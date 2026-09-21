//! The second phase. Collectors are independent by design and know nothing
//! of each other, so every fact that needs more than one of them lives here:
//! package provenance, whether a target exists, which unit shadows which, and
//! the LD_PRELOAD assignments that turn up in six different kinds of file.
//!
//! This is also where a rule engine would eventually go. The Entry record
//! carries the raw facts precisely so that it could.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::entry::{Entry, Flag, Integrity, Kind, Provenance};
use crate::provenance;
use crate::root::{Root, is_hidden_path};
use crate::scan::Scan;

pub fn enrich(root: &Root, scan: &mut Scan) {
    normalise_targets(root, &mut scan.entries);

    let wanted = paths_to_resolve(root, &scan.entries);
    let answers = provenance::resolve(root, &wanted);

    for entry in &mut scan.entries {
        apply_provenance(root, entry, &answers);
        apply_target(root, entry);
        apply_location(root, entry);
    }

    apply_shadowing(&mut scan.entries);
    cross_reference_suid(&mut scan.entries);

    let preloads = preload_entries(root, &scan.entries);
    scan.entries.extend(preloads);
    scan.entries.sort_by(|a, b| (a.kind, &a.source, &a.name).cmp(&(b.kind, &b.source, &b.name)));
}

/// Collectors disagree about whether a target path is the literal string from
/// the file or a path in the scan root's coordinates. Both are made to mean
/// the same thing here, once, so nothing downstream has to know which
/// collector produced an entry.
fn normalise_targets(root: &Root, entries: &mut [Entry]) {
    for e in entries {
        if let Some(target) = e.target_path.take() {
            e.target_path = Some(root.abs(root.rel(&target)));
        }
    }
}

fn paths_to_resolve(root: &Root, entries: &[Entry]) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    for e in entries {
        out.insert(root.rel(&e.source));
        if let Some(t) = &e.target_path {
            out.insert(root.rel(t));
        }
    }
    out
}

fn apply_provenance(root: &Root, entry: &mut Entry, answers: &provenance::Answers) {
    let source_rel = root.rel(&entry.source);
    let verdict = answers.get(&source_rel).cloned().unwrap_or(Provenance::Unknown);

    match &verdict {
        Provenance::Unpackaged => entry.flag(Flag::Unpackaged),
        Provenance::Packaged { integrity: Integrity::Modified, .. } => entry.flag(Flag::PackagedModified),
        Provenance::Packaged { integrity: Integrity::ConffileModified, .. } => {
            entry.flag(Flag::ConffileModified)
        }
        _ => {}
    }
    entry.provenance = verdict;

    // The target is a separate file with a separate verdict, and an entry
    // whose backing file is packaged can still point at something that is
    // not — which is the whole shape of a hijacked ExecStart.
    if let Some(target) = entry.target_path.clone() {
        let target_rel = root.rel(&target);
        if target_rel != source_rel {
            match answers.get(&target_rel) {
                Some(Provenance::Unpackaged) => {
                    entry.note("target_provenance", "unpackaged");
                    entry.flag(Flag::Unpackaged);
                }
                Some(Provenance::Packaged { package, integrity, .. }) => {
                    entry.note("target_provenance", format!("{package} ({integrity})"));
                    if *integrity == Integrity::Modified {
                        entry.flag(Flag::PackagedModified);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Directories a bare command name is looked up in. Same list systemd uses,
/// and close enough to any shell's default PATH for the purpose.
const BIN_DIRS: [&str; 6] =
    ["usr/local/sbin", "usr/local/bin", "usr/sbin", "usr/bin", "sbin", "bin"];

/// A command that is not an absolute path is not automatically unresolvable.
/// systemd has allowed bare executable names for years, and `ExecStart=
/// systemctl ...` appears in a hundred vendor units on an ordinary host.
fn resolve_bare_command(root: &Root, kind: Kind, command: &[u8]) -> Option<PathBuf> {
    let text = String::from_utf8_lossy(command);
    let first = text.split_whitespace().next()?;
    // systemd's argument prefixes, and a quoted first token.
    let first = first.trim_start_matches(['-', '@', '+', '!', ':']).trim_matches(['"', '\'']);
    if first.is_empty() || first.contains('/') {
        return None;
    }
    // udev resolves its helper names against its own directory, which is why
    // `IMPORT{program}=ata_id` appears bare in dozens of vendor rules.
    let extra: &[&str] = match kind {
        Kind::Udev => &["usr/lib/udev", "lib/udev"],
        _ => &[],
    };
    extra
        .iter()
        .chain(BIN_DIRS.iter())
        .map(|d| format!("{d}/{first}"))
        .find(|p| root.exists(p))
        .map(|p| root.abs(p))
}

/// Why a target path cannot be checked against the filesystem at all.
fn unverifiable(target: &Path) -> Option<&'static str> {
    let text = target.to_string_lossy();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        // A systemd specifier: %i, %f, %H. `%%` is a literal percent.
        if c == '%' {
            match chars.peek() {
                Some('%') => {
                    chars.next();
                }
                Some(n) if n.is_ascii_alphabetic() => return Some("unexpanded specifier"),
                _ => {}
            }
        }
    }
    if text.contains(['*', '?']) || (text.contains('[') && text.contains(']')) {
        return Some("glob pattern");
    }
    None
}

/// The reported digest, and whether the thing the entry runs is actually
/// there. An entry pointing at a path that does not exist is Autoruns' orphan
/// highlighting: cheap to check, impossible to fake.
fn apply_target(root: &Root, entry: &mut Entry) {
    if entry.target_path.is_none() {
        if let Some(command) = entry.command.clone() {
            if let Some(found) = resolve_bare_command(root, entry.kind, &command) {
                entry.note("target_resolved_from", "search path");
                entry.target_path = Some(found);
            }
        }
    }

    let hashed = match &entry.target_path {
        Some(target) => {
            // A path holding a specifier or a glob names a set, not a file.
            // Reporting it missing would be a false finding on every
            // template unit and every sshd Include line.
            if let Some(why) = unverifiable(target) {
                entry.note("target_unverifiable", why);
                return;
            }
            let rel = root.rel(target);
            if !root.exists(&rel) {
                entry.flag(Flag::TargetMissing);
            }
            rel
        }
        None => {
            // No resolvable target. Where the entry is itself the script,
            // the source is what runs; where a command was parsed but no
            // path could be got out of it, that is a finding of its own —
            // unless the mechanism runs it inside its own process, as udev
            // does with its builtins, in which case there is no file to find.
            let builtin = entry.raw.get("key").is_some_and(|k| k.contains("{builtin}"));
            if builtin {
                entry.note("target_unverifiable", "runs inside udev, not a program");
            } else if entry.command.is_some() {
                entry.flag(Flag::TargetUnresolvable);
            }
            root.rel(&entry.source)
        }
    };

    if entry.target_sha256.is_none() {
        if let Some(d) = provenance::digests(root, &hashed) {
            entry.target_sha256 = Some(d.sha256);
        }
    }
}

/// Where a mechanism's files are supposed to live. A unit or rule outside its
/// own search path — usually reached by a symlink from inside one — is worth
/// saying out loud.
fn standard_roots(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::SystemdUnit | Kind::SystemdTimer | Kind::SystemdGenerator => &[
            "/etc/systemd/",
            "/run/systemd/",
            "/usr/lib/systemd/",
            "/lib/systemd/",
            "/usr/local/lib/systemd/",
        ],
        Kind::Udev => &["/etc/udev/", "/run/udev/", "/usr/lib/udev/", "/lib/udev/"],
        Kind::KernelModule => &[
            "/etc/modules",
            "/etc/modules-load.d/",
            "/etc/modprobe.d/",
            "/run/modules-load.d/",
            "/usr/lib/modprobe.d/",
            "/lib/modprobe.d/",
            "/usr/lib/modules-load.d/",
            "/proc/modules",
        ],
        Kind::XdgAutostart => &["/etc/xdg/autostart/", "/.config/autostart/"],
        Kind::Cron => &["/etc/crontab", "/etc/cron", "/etc/anacrontab", "/var/spool/cron"],
        _ => &[],
    }
}

fn apply_location(root: &Root, entry: &mut Entry) {
    let roots = standard_roots(entry.kind);
    if roots.is_empty() {
        return;
    }
    let inside = |p: &Path| {
        let text = p.to_string_lossy().into_owned();
        roots.iter().any(|r| text.contains(r))
    };
    // Paths are judged as they sit inside the scan root, so an offline image
    // does not inherit the analyst's own directory names.
    let in_root = |p: &Path| Path::new("/").join(root.rel(p));

    // The source is always inside a search path, because that is where the
    // collector looked. What matters is where a symlink from inside one
    // actually leads: `systemctl link /tmp/evil.service` leaves a perfectly
    // ordinary-looking unit name in /etc.
    if let Some(target) = entry.raw.get("symlink_target") {
        let resolved = in_root(&resolve_link(root, &entry.source, Path::new(target)));
        if !inside(&resolved) {
            entry.flag(Flag::NonStandardLocation);
        }
        if is_hidden_path(&resolved) {
            entry.flag(Flag::HiddenPath);
        }
    } else if !inside(&in_root(&entry.source)) {
        entry.flag(Flag::NonStandardLocation);
    }
}

fn resolve_link(root: &Root, source: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        return root.abs(root.rel(target));
    }
    match source.parent() {
        Some(dir) => root.abs(root.rel(&dir.join(target))),
        None => target.to_path_buf(),
    }
}

/// Collectors record which file shadows which; deciding that the relationship
/// is worth a flag needs the whole set, so it happens here.
fn apply_shadowing(entries: &mut [Entry]) {
    for e in entries {
        if e.raw.contains_key("shadows") {
            e.flag(Flag::ShadowsVendorUnit);
        }
    }
}

/// A cron job or unit whose target is an unpackaged setuid binary is a
/// different proposition from one that merely runs an unpackaged script. The
/// fact needs two collectors, so it is recorded here.
fn cross_reference_suid(entries: &mut [Entry]) {
    let suspicious: BTreeSet<PathBuf> = entries
        .iter()
        .filter(|e| e.kind == Kind::SuidBinary && matches!(e.provenance, Provenance::Unpackaged))
        .map(|e| e.source.clone())
        .collect();
    if suspicious.is_empty() {
        return;
    }
    for e in entries {
        if e.kind == Kind::SuidBinary {
            continue;
        }
        if let Some(target) = &e.target_path {
            if suspicious.contains(target) {
                e.note("target_is_unpackaged_suid", "true");
            }
        }
    }
}

/// §5 promises an ld_preload entry for every LD_PRELOAD assignment found by
/// the shell and systemd collectors, and §14.4 forbids a collector from
/// knowing about another's output. Both hold if the collectors record the
/// assignment as ordinary data and the entries are made here — which also
/// catches the assignments in PAM environment files, crontabs and udev rules
/// that neither section thought to list.
fn preload_entries(root: &Root, entries: &[Entry]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<(PathBuf, String)> = BTreeSet::new();

    for carrier in entries {
        if carrier.kind == Kind::LdPreload {
            continue;
        }
        for (key, value) in &carrier.raw {
            if !matches!(key.as_str(), "env.LD_PRELOAD" | "env.LD_AUDIT" | "env.LD_LIBRARY_PATH") {
                continue;
            }
            let variable = key.trim_start_matches("env.");
            for library in value.split([' ', ':', '\n']).filter(|s| !s.is_empty()) {
                if !seen.insert((carrier.source.clone(), library.to_string())) {
                    continue;
                }
                let mut e = Entry::new(Kind::LdPreload, &carrier.source, library);
                e.command = Some(format!("{variable}={library}").into_bytes());
                e.target_path = Some(root.abs(root.rel(Path::new(library))));
                e.trigger = carrier.trigger;
                e.principal = carrier.principal.clone();
                e.owner_uid = carrier.owner_uid;
                e.mode = carrier.mode;
                e.mtime = carrier.mtime;
                e.enabled = carrier.enabled;
                e.note("variable", variable);
                e.note("declared_in", carrier.source.to_string_lossy());
                e.note("declared_by_entry", &carrier.id);
                out.push(e);
            }
        }
    }
    out
}

/// A synthesised preload entry is built after provenance has run, so it needs
/// its own pass over the same machinery.
pub fn enrich_late(root: &Root, scan: &mut Scan) {
    let wanted: BTreeSet<PathBuf> = scan
        .entries
        .iter()
        .filter(|e| e.kind == Kind::LdPreload && e.target_sha256.is_none())
        .filter_map(|e| e.target_path.as_ref().map(|t| root.rel(t)))
        .collect();
    if wanted.is_empty() {
        return;
    }
    let answers = provenance::resolve(root, &wanted);
    for e in &mut scan.entries {
        if e.kind == Kind::LdPreload && e.target_sha256.is_none() {
            apply_provenance(root, e, &answers);
            apply_target(root, e);
        }
    }
}

/// Counts for the run summary, kept here so the renderer stays a renderer.
pub fn flag_counts(scan: &Scan) -> BTreeMap<Flag, usize> {
    let mut out = BTreeMap::new();
    for e in &scan.entries {
        for f in &e.flags {
            *out.entry(*f).or_insert(0) += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Trigger;
    use crate::scan::{self, Collector, Ctx, Options};

    struct Planted;

    impl Collector for Planted {
        fn name(&self) -> &'static str {
            "planted"
        }

        fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
            let mut out = Vec::new();

            let mut e = cx.entry(Kind::SystemdUnit, "etc/systemd/system/evil.service", "evil.service");
            e.command = Some(b"/opt/backdoor --quiet".to_vec());
            e.target_path = Some(PathBuf::from("/opt/backdoor"));
            out.push(e);

            let mut e = cx.entry(Kind::SystemdUnit, "etc/systemd/system/ghost.service", "ghost.service");
            e.command = Some(b"/usr/bin/vanished".to_vec());
            e.target_path = Some(PathBuf::from("/usr/bin/vanished"));
            out.push(e);

            let mut e = cx.entry(Kind::ShellProfile, "etc/profile", "profile");
            e.note("env.LD_PRELOAD", "/tmp/hook.so");
            e.trigger = Trigger::Login;
            out.push(e);

            let mut e = cx.entry(Kind::SystemdUnit, "etc/systemd/system/linked.service", "linked.service");
            e.command = Some(b"/tmp/staging/run.sh".to_vec());
            out.push(e);

            let mut e = cx.entry(Kind::Cron, "etc/cron.d/job", "abc123");
            e.command = Some(b"do-something-unparseable".to_vec());
            out.push(e);

            out
        }
    }

    fn scanned(dir: &Path) -> (Root, Scan) {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Planted)];
        let mut scan = scan::run(&root, &Options { deep: false }, &collectors);
        enrich(&root, &mut scan);
        enrich_late(&root, &mut scan);
        (Root::at(dir).unwrap(), scan)
    }

    fn find<'a>(scan: &'a Scan, name: &str) -> &'a Entry {
        scan.entries.iter().find(|e| e.name == name).unwrap_or_else(|| panic!("no entry named {name}"))
    }

    #[test]
    fn enrichment_resolves_provenance_targets_links_and_preloads() {
        let dir = std::env::temp_dir().join(format!("unbidden-enrich-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["etc/systemd/system", "etc/cron.d", "opt", "tmp/staging", "var/lib/dpkg/info"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(dir.join("opt/backdoor"), b"payload").unwrap();
        std::fs::write(dir.join("tmp/staging/run.sh"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.join("etc/profile"), b"export LD_PRELOAD=/tmp/hook.so\n").unwrap();
        std::fs::write(dir.join("etc/systemd/system/evil.service"), b"[Service]\n").unwrap();
        std::fs::write(dir.join("etc/systemd/system/ghost.service"), b"[Service]\n").unwrap();
        std::fs::write(dir.join("etc/cron.d/job"), b"* * * * * root x\n").unwrap();
        std::os::unix::fs::symlink("/tmp/staging/run.sh", dir.join("etc/systemd/system/linked.service")).unwrap();
        // A package database must exist, or every verdict is Unknown rather
        // than Unpackaged.
        std::fs::write(dir.join("var/lib/dpkg/status"), b"Package: base-files\nVersion: 13\n\n").unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/base-files.list"), b"/etc/profile\n").unwrap();
        let shipped = {
            use md5::Digest as _;
            let mut h = md5::Md5::new();
            h.update(b"export LD_PRELOAD=/tmp/hook.so\n");
            crate::entry::hex(&h.finalize())
        };
        std::fs::write(
            dir.join("var/lib/dpkg/info/base-files.md5sums"),
            format!("{shipped}  etc/profile\n"),
        )
        .unwrap();

        let (_root, scan) = scanned(&dir);

        let evil = find(&scan, "evil.service");
        assert!(evil.has_flag(Flag::Unpackaged));
        assert!(!evil.has_flag(Flag::TargetMissing), "the target is present");
        assert!(evil.target_sha256.is_some(), "the reported digest is of the target");

        let ghost = find(&scan, "ghost.service");
        assert!(ghost.has_flag(Flag::TargetMissing), "an orphaned entry is the cheapest real finding");

        let linked = find(&scan, "linked.service");
        assert!(linked.has_flag(Flag::NonStandardLocation), "a unit linked out of the search path");
        assert!(linked.has_flag(Flag::HiddenPath), "and into a world-writable directory");

        let unparseable = find(&scan, "abc123");
        assert!(unparseable.has_flag(Flag::TargetUnresolvable));

        let preload = scan.entries.iter().find(|e| e.kind == Kind::LdPreload).expect("preload entry");
        assert_eq!(preload.name, "/tmp/hook.so");
        assert_eq!(preload.trigger, Trigger::Login);
        assert_eq!(preload.raw["declared_in"], dir.join("etc/profile").to_string_lossy());
        assert!(preload.has_flag(Flag::TargetMissing), "the library itself is not even there");
        assert_eq!(preload.command.as_deref(), Some(b"LD_PRELOAD=/tmp/hook.so".as_slice()));

        // The profile file is packaged and untouched, so it is exactly the
        // sort of row the default view hides — while the preload entry it
        // spawned is not.
        let profile = find(&scan, "profile");
        assert!(profile.provenance.is_packaged_intact());
        assert!(crate::render::suppressed(profile));
        assert!(!crate::render::suppressed(preload));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
