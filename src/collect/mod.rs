//! Collectors, one module per group of mechanism classes.
//!
//! Grouping is by shared source material, not by kind: the cron collector
//! reads six spool layouts and emits two kinds, and splitting it would mean
//! parsing crontab syntax twice.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::scan::{Collector, Ctx};

pub mod agents;
pub mod auth;
pub mod browsers;
pub mod cloudinit;
pub mod cron;
pub mod deep;
pub mod desktop;
pub mod dm;
pub mod editors;
pub mod events;
pub mod fail2ban;
pub mod inetd;
pub mod initramfs;
pub mod inittab;
pub mod initscripts;
pub mod integrity;
pub mod kernel;
pub mod logrotate;
pub mod pkg;
pub mod plugins;
pub mod polkit;
pub mod python;
pub mod shell;
pub mod sources;
pub mod systemd;
pub mod vcs;

/// The command word of shell text, cut where the shell cuts it. A `;`, `|`,
/// `&`, `<`, `>` or parenthesis ends a word as surely as a space does, so
/// `/opt/a.sh; /tmp/x` runs /opt/a.sh and not a file named `a.sh;`, and the
/// rest of the line is left for enrichment to split into its own commands.
pub(crate) fn shell_word(word: &[u8]) -> &[u8] {
    let end = word.iter().position(|b| b";|&<>()".contains(b)).unwrap_or(word.len());
    &word[..end]
}

/// A shell-style glob with `*` and `?`, as sudoers includes and systemd
/// preset patterns use it.
pub(crate) fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0, 0);
    let (mut star, mut mark) = (usize::MAX, 0);
    while i < s.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == s[i]) {
            p += 1;
            i += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = p;
            p += 1;
            mark = i;
        } else if star != usize::MAX {
            p = star + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// An include path resolved root-relative: absolute means relative to the scan
/// root, bare means relative to `base`.
pub(crate) fn include_rel(base: &Path, spec: &[u8]) -> PathBuf {
    let p = Path::new(OsStr::from_bytes(spec));
    match p.strip_prefix("/") {
        Ok(stripped) => stripped.to_path_buf(),
        Err(_) => base.join(p),
    }
}

/// The files a glob in the last path component matches, sorted as glob(3)
/// returns them; a path with no glob is itself.
pub(crate) fn expand_glob(cx: &mut Ctx, rel: &Path) -> Vec<PathBuf> {
    let name = rel.file_name().map(|n| n.as_encoded_bytes().to_vec()).unwrap_or_default();
    if !name.contains(&b'*') && !name.contains(&b'?') {
        return vec![rel.to_path_buf()];
    }
    let dir = rel.parent().unwrap_or(Path::new("")).to_path_buf();
    let mut out = Vec::new();
    for ent in cx.dir(&dir) {
        if !ent.is_dir && glob_match(&name, ent.name.as_encoded_bytes()) {
            out.push(dir.join(&ent.name));
        }
    }
    out.sort();
    out
}

/// Which run-parts a host has: debianutils' binary, the shell script
/// Fedora's crontabs package installs, or BusyBox's applet. They pick
/// scripts by different rules.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum RunParts {
    Debian,
    /// debianutils' run-parts given `--lsbsysinit`, as pam_motd runs it over
    /// update-motd.d: LSB's namespaces instead of letters, digits, `_` and `-`.
    DebianLsb,
    Script,
    BusyBox,
}

/// Read whole and directly: a binary is not configuration, and a capped read
/// of one is not a limited read the operator should hear about.
pub(crate) fn run_parts_flavour(cx: &mut Ctx) -> RunParts {
    for p in ["usr/bin/run-parts", "bin/run-parts"] {
        let Ok(resolved) = cx.root.resolve(Path::new(p)) else { continue };
        let Ok((bytes, _)) = cx.root.read_capped(&resolved, 16 << 20) else { continue };
        if bytes.starts_with(b"#!") {
            return RunParts::Script;
        }
        if bytes.windows(7).any(|w| w == b"BusyBox") {
            return RunParts::BusyBox;
        }
        return RunParts::Debian;
    }
    RunParts::Debian
}

/// Why run-parts would not run the file `name` in `dir`, or `None` where it
/// would. debianutils' run-parts runs names of letters, digits, `_` and `-`
/// only, so `backup.sh` never runs. Fedora's script runs any name but a
/// dotfile, one ending in `~` or `,`, or `.cfsaved`, `.rpmsave`, `.rpmorig`,
/// `.rpmnew`, `.swp` or `,v`, and honours `jobs.deny` and `jobs.allow` in the
/// directory. BusyBox's allows a dot too, anywhere but first, so there
/// `backup.sh` does run. All three then need the execute bit, checked by
/// the caller.
pub(crate) fn run_parts_skips(cx: &mut Ctx, flavour: RunParts, dir: &Path, name: &[u8]) -> Option<&'static str> {
    match flavour {
        RunParts::Debian => {
            let ok = !name.is_empty() && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-');
            (!ok).then_some("run-parts runs only names of letters, digits, _ and -")
        }
        RunParts::DebianLsb => {
            (!lsb_name(name)).then_some("run-parts --lsbsysinit runs only lower-case names in LSB's namespaces")
        }
        RunParts::BusyBox => {
            let ok = !name.is_empty()
                && name[0] != b'.'
                && name.iter().all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(b));
            (!ok).then_some("run-parts runs only names of letters, digits, _, - and dots after the first character")
        }
        RunParts::Script => {
            const SKIP: [&[u8]; 6] = [b".cfsaved", b".rpmsave", b".rpmorig", b".rpmnew", b".swp", b",v"];
            if name.starts_with(b".") || name.ends_with(b"~") || name.ends_with(b",") || SKIP.iter().any(|s| name.ends_with(s)) {
                return Some("run-parts skips a hidden, backup or package-manager copy");
            }
            let listed = |cx: &mut Ctx, file: &str| {
                cx.read_capped(dir.join(file), 64 * 1024).map(|b| b.split(|c| *c == b'\n').any(|l| l == name))
            };
            if listed(cx, "jobs.deny") == Some(true) {
                return Some("named in jobs.deny");
            }
            if listed(cx, "jobs.allow") == Some(false) {
                return Some("not named in jobs.allow");
            }
            None
        }
    }
}

/// A name in a run-parts directory, and why run-parts would not run it, if it
/// would not.
pub(crate) struct RunPartsFile {
    pub rel: PathBuf,
    pub name: OsString,
    pub not_run: Option<&'static str>,
}

/// Every name in a directory run-parts is pointed at, in the order it runs
/// them, each judged as run-parts judges it: by the name rule of the run-parts
/// the host has, then by the file the name leads to. The execute test follows
/// a link, so a link to nothing, to a directory or to a file that is not
/// executable runs nothing. Such a name is still reported, off: a script that
/// was there and is not is evidence.
pub(crate) fn run_parts_dir(cx: &mut Ctx, flavour: RunParts, dir: &Path) -> Vec<RunPartsFile> {
    let mut ents = cx.dir(dir);
    ents.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = Vec::new();
    for ent in ents {
        if ent.is_dir {
            continue;
        }
        let rel = dir.join(&ent.name);
        let not_run = run_parts_skips(cx, flavour, dir, ent.name.as_encoded_bytes()).or_else(|| match cx.root.stat_follow(&rel) {
            Ok(m) if m.is_file && m.mode & 0o111 != 0 => None,
            Ok(m) if m.is_file => Some("not executable"),
            Ok(_) => Some("not a regular file"),
            Err(_) => Some("a link to nothing"),
        });
        out.push(RunPartsFile { rel, name: ent.name, not_run });
    }
    out
}

/// The names debianutils' `run-parts --lsbsysinit` accepts, worked out from
/// what the real binary ran over a table of names: a lower-case letter or
/// digit then any of those, `_` and `-`; or hyphen-separated parts of
/// lower-case letters, digits, `_` and `.`, the last of only letters and
/// digits. Whatever the rule, names with a `.dpkg-` in them, a `~`, or a
/// package-manager or editor suffix are dropped first.
fn lsb_name(name: &[u8]) -> bool {
    const SKIP_SUFFIX: [&[u8]; 6] = [b"~", b".rpmsave", b".rpmorig", b".rpmnew", b".swp", b",v"];
    if name.windows(6).any(|w| w == b".dpkg-") || SKIP_SUFFIX.iter().any(|s| name.ends_with(s)) || name.ends_with(b".cfsaved") {
        return false;
    }
    let lower = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if name.first().is_some_and(lower) && name.iter().all(|b| lower(b) || matches!(b, b'_' | b'-')) {
        return true;
    }
    let mut parts = name.split(|b| *b == b'-').collect::<Vec<_>>();
    let Some(last) = parts.pop() else { return false };
    !parts.is_empty()
        && parts.iter().all(|p| !p.is_empty() && p.iter().all(|b| lower(b) || matches!(b, b'_' | b'.')))
        && !last.is_empty()
        && last.iter().all(lower)
}

/// The directories ldconfig puts in the loader's cache, read from
/// /etc/ld.so.conf as ldconfig reads it: `#` starts a comment anywhere, an
/// `include` line names whitespace-separated patterns relative to the file
/// it is in, a `hwcap` line is ignored, and any other line is one directory.
/// A file that is not included is never read, whatever directory it sits in.
/// Each directory comes with the file that first named it.
pub(crate) fn ld_so_conf_dirs(cx: &mut Ctx) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    ld_so_conf(cx, Path::new("etc/ld.so.conf"), 0, &mut out);
    out
}

fn ld_so_conf(cx: &mut Ctx, rel: &Path, depth: usize, out: &mut Vec<(String, PathBuf)>) {
    // An include loop ends here rather than in the stack.
    if depth > 8 {
        return;
    }
    let Some(bytes) = cx.read_capped(rel, 64 * 1024) else { return };
    let base = rel.parent().unwrap_or(Path::new("")).to_path_buf();
    for raw in bytes.split(|b| *b == b'\n') {
        let line = raw.split(|b| *b == b'#').next().unwrap_or_default().trim_ascii();
        let (word, rest) = line.split_at(line.iter().position(u8::is_ascii_whitespace).unwrap_or(line.len()));
        if line.is_empty() || word.eq_ignore_ascii_case(b"hwcap") {
            continue;
        }
        if word == b"include" && !rest.is_empty() {
            for pat in rest.split(u8::is_ascii_whitespace).filter(|p| !p.is_empty()) {
                for f in expand_glob(cx, &include_rel(&base, pat)) {
                    ld_so_conf(cx, &f, depth + 1, out);
                }
            }
            continue;
        }
        // ldconfig strips trailing slashes, and an old `dir=TYPE` suffix.
        let dir = line.split(|b| *b == b'=').next().unwrap_or_default().trim_ascii();
        let mut d = String::from_utf8_lossy(dir).into_owned();
        while d.len() > 1 && d.ends_with('/') {
            d.pop();
        }
        if !d.is_empty() && !out.iter().any(|(seen, _)| *seen == d) {
            out.push((d, rel.to_path_buf()));
        }
    }
}

/// The files in `dirs` in the order systemd and polkit read them, by file
/// name, each with the file that replaces it: a same-named file in an
/// earlier directory is read instead, and a link to /dev/null there masks it.
pub(crate) fn replaceable(cx: &mut Ctx, dirs: &[&str], suffix: &str) -> Vec<(PathBuf, Option<PathBuf>)> {
    let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut first: BTreeMap<OsString, PathBuf> = BTreeMap::new();
    let mut found = Vec::new();
    for dir in dirs {
        match cx.root.dir_identity(dir) {
            Ok(id) if seen.insert(id) => {}
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                cx.note_failed(dir, &e);
                continue;
            }
        }
        for ent in cx.dir(dir) {
            if ent.is_dir || !ent.name.as_encoded_bytes().ends_with(suffix.as_bytes()) {
                continue;
            }
            let rel = Path::new(dir).join(&ent.name);
            let by = first.get(&ent.name).cloned();
            first.entry(ent.name.clone()).or_insert_with(|| rel.clone());
            found.push((ent.name, rel, by));
        }
    }
    // Stable, so the copy that is read comes before the ones it replaces.
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found.into_iter().map(|(_, rel, by)| (rel, by)).collect()
}

pub fn all() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(systemd::Systemd),
        Box::new(cron::Cron),
        Box::new(desktop::Desktop),
        Box::new(dm::DisplayManager),
        Box::new(shell::Shell),
        Box::new(initscripts::InitScripts),
        Box::new(inittab::Inittab),
        Box::new(auth::Auth),
        Box::new(polkit::Polkit),
        Box::new(inetd::Inetd),
        Box::new(kernel::Kernel),
        Box::new(initramfs::Initramfs),
        Box::new(logrotate::Logrotate),
        Box::new(events::Events),
        Box::new(agents::Agents),
        Box::new(fail2ban::Fail2ban),
        Box::new(plugins::Plugins),
        Box::new(vcs::Vcs),
        Box::new(browsers::Browsers),
        Box::new(editors::Editors),
        Box::new(pkg::PkgHooks),
        Box::new(sources::Sources),
        Box::new(cloudinit::CloudInit),
        Box::new(python::Python),
        Box::new(deep::GitConfig),
        Box::new(deep::Deep),
        Box::new(integrity::Integrity),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name here was run through `run-parts --test --lsbsysinit` of the
    /// debianutils on Ubuntu 24.04, in a directory of executable files, and
    /// is listed as that binary answered.
    #[test]
    fn the_lsb_name_rule_matches_what_run_parts_did() {
        let accepted = "00-header 10-help-text 10-x.y-z 1-a 1_-a a a- a-1 a_1-b_2 a1-b2 _a-b a--b a-b a_b ab1 _a.b-c a.b-c a_b-c a-b-c-d a-b.c-d";
        let rejected = "A _a a-B a.b a-b.c -a 10-x. 50-landscape-sysinfo.sh x.dpkg-old x~ A-b .a";
        for n in accepted.split(' ') {
            assert!(lsb_name(n.as_bytes()), "{n} is run");
        }
        for n in rejected.split(' ') {
            assert!(!lsb_name(n.as_bytes()), "{n} is not run");
        }
    }

    #[test]
    fn glob_matching_is_not_a_prefix_check() {
        assert!(glob_match(b"*.conf", b"10-evil.conf"));
        assert!(!glob_match(b"*.conf", b"notes.txt"));
        assert!(glob_match(b"sshd_config_?", b"sshd_config_1"));
        assert!(glob_match(b"*", b"anything"));
        assert!(!glob_match(b"a*b", b"ab_"));
        assert!(glob_match(b"a*b*c", b"axxbxxc"));
    }
}
