//! Programs daemons run as root when something happens to the machine: an
//! ACPI event, a ZFS event, a failing disk, a crash, a certificate update.
//! Each is read only where its daemon or tool is installed, by the rule it
//! uses to choose what to run.
//!
//! acpid (acpid(8)): regular files in /etc/acpi/events named with letters,
//! digits, `_` and `-` only, not starting `.` nor ending `~`; each rule's
//! `action=` line (the key without regard to case, whitespace significant)
//! runs through /bin/sh. ZFS's zed (zed_conf.c, 2.2): files in
//! /etc/zfs/zed.d not starting `.`, regular, owned by root, executable by
//! their owner and writable by neither group nor other. smartd (Debian's
//! smartd-runner): what run-parts selects in /etc/smartmontools/run.d, on a
//! disk warning. update-ca-certificates: what run-parts selects in
//! /etc/ca-certificates/update.d, on every certificate change. apport: the
//! Python in /usr/share/apport/general-hooks, loaded for every crash report,
//! and in package-hooks, for a crash in that package.

use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger, hex};
use crate::scan::{Collector, Ctx};

pub struct Events;

impl Collector for Events {
    fn name(&self) -> &'static str {
        "events"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        acpid(cx, &mut out);
        if cx.root.exists("usr/sbin/zed") {
            zed(cx, &mut out);
        }
        let flavour = super::run_parts_flavour(cx);
        for (dir, tool, trigger, installed) in [
            ("etc/smartmontools/run.d", "smartd", Trigger::DeviceEvent, "usr/sbin/smartd"),
            ("etc/ca-certificates/update.d", "update-ca-certificates", Trigger::PackageOp, "usr/sbin/update-ca-certificates"),
        ] {
            if cx.root.exists(installed) {
                run_parts(cx, &mut out, Path::new(dir), tool, trigger, flavour);
            }
        }
        if cx.root.exists("usr/share/apport/apport") {
            apport(cx, &mut out);
        }
        rsyslog(cx, &mut out);
        cups(cx, &mut out);
        out
    }
}

fn sorted(cx: &mut Ctx, dir: &Path) -> Vec<PathBuf> {
    let mut names: Vec<_> = cx.dir(dir).into_iter().filter(|e| !e.is_dir).map(|e| e.name).collect();
    names.sort();
    names.into_iter().map(|n| dir.join(n)).collect()
}

fn entry(cx: &mut Ctx, rel: &Path, name: String, tool: &str, trigger: Trigger) -> Entry {
    let mut e = cx.entry(Kind::EventHandler, rel, name);
    e.trigger = trigger;
    e.principal = Some("root".into());
    e.enabled = Enablement::Enabled;
    e.note("run_by", tool);
    e
}

fn file_name(rel: &Path) -> String {
    rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Read whether or not acpid is installed, and off where it is not.
fn acpid(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/sbin/acpid");
    for rel in sorted(cx, Path::new("etc/acpi/events")) {
        let name = file_name(&rel);
        let n = name.as_bytes();
        let chosen = !n.is_empty() && n.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-');
        let Some(bytes) = cx.read_capped(&rel, 64 * 1024) else { continue };
        let (mut event, mut action) = (None, None);
        for line in bytes.split(|b| *b == b'\n') {
            if line.first() == Some(&b'#') {
                continue;
            }
            let Some(eq) = line.iter().position(|b| *b == b'=') else { continue };
            let key = String::from_utf8_lossy(&line[..eq]).to_ascii_lowercase();
            let value = line[eq + 1..].to_vec();
            match key.as_str() {
                "event" => event = Some(value),
                "action" => action = Some(value),
                _ => {}
            }
        }
        let Some(action) = action else { continue };
        let mut e = entry(cx, &rel, format!("acpid:{name}"), "acpid", Trigger::DeviceEvent);
        if let Some(ev) = event {
            e.note("event", String::from_utf8_lossy(&ev).into_owned());
        }
        e.command = Some(action);
        if !chosen {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "acpid reads only names of letters, digits, _ and -");
        } else if !installed {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "acpid is not installed");
        }
        out.push(e);
    }
}

fn zed(cx: &mut Ctx, out: &mut Vec<Entry>) {
    for rel in sorted(cx, Path::new("etc/zfs/zed.d")) {
        let name = file_name(&rel);
        if name.starts_with('.') {
            continue;
        }
        let Ok(meta) = cx.root.stat_follow(&rel) else { continue };
        // zed.rc and zed-functions.sh beside the zedlets are sourced, not
        // run, and are not executable.
        if !meta.is_file || meta.mode & 0o111 == 0 {
            continue;
        }
        let mut e = entry(cx, &rel, format!("zed:{name}"), "zed", Trigger::DeviceEvent);
        e.target_path = Some(cx.root.abs(&rel));
        e.note("event_class", name.split('-').next().unwrap_or_default());
        let why = if meta.uid != 0 {
            Some("zed runs only zedlets owned by root")
        } else if meta.mode & 0o100 == 0 {
            Some("zed needs its owner's execute bit")
        } else if meta.mode & 0o022 != 0 {
            Some("zed runs no zedlet writable by group or other")
        } else {
            None
        };
        if let Some(why) = why {
            e.enabled = Enablement::Disabled;
            e.note("not_run", why);
        }
        out.push(e);
    }
}

fn run_parts(cx: &mut Ctx, out: &mut Vec<Entry>, dir: &Path, tool: &str, trigger: Trigger, flavour: super::RunParts) {
    for rel in sorted(cx, dir) {
        let name = file_name(&rel);
        let mut e = entry(cx, &rel, format!("{tool}:{name}"), tool, trigger);
        e.target_path = Some(cx.root.abs(&rel));
        if e.mode & 0o111 == 0 {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "not executable");
        }
        if let Some(why) = super::run_parts_skips(cx, flavour, dir, name.as_bytes()) {
            e.enabled = Enablement::Disabled;
            e.note("not_run", why);
        }
        out.push(e);
    }
}

fn apport(cx: &mut Ctx, out: &mut Vec<Entry>) {
    for (dir, scope) in [("usr/share/apport/general-hooks", "every crash report"), ("usr/share/apport/package-hooks", "crashes in its package")] {
        for rel in sorted(cx, Path::new(dir)) {
            let name = file_name(&rel);
            if !name.ends_with(".py") {
                continue;
            }
            let mut e = entry(cx, &rel, format!("apport:{name}"), "apport", Trigger::Always);
            e.target_path = Some(cx.root.abs(&rel));
            e.note("loaded_for", scope);
            out.push(e);
        }
    }
}


// ------------------------------------------------------------- rsyslog ----

/// rsyslog (8.2312): programs it feeds log messages to, from
/// /etc/rsyslog.conf and what its `$IncludeConfig` and `include(file=...)`
/// lines name: each `action(type="omprog" binary="...")`, and each legacy
/// `^program` action. They run as the user `$PrivDropToUser` or
/// `global(privdrop.user.name=...)` names, root where none is named (Ubuntu
/// drops to syslog). Off where rsyslogd is not installed.
fn rsyslog(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let mut texts: Vec<(PathBuf, String)> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    rsyslog_file(cx, Path::new("etc/rsyslog.conf"), 0, &mut seen, &mut texts);
    let mut user = None;
    for (_, t) in &texts {
        for line in t.lines() {
            let l = line.trim();
            if let Some(u) = l.strip_prefix("$PrivDropToUser ") {
                user = Some(u.trim().to_string());
            }
            if let Some(i) = l.find("privdrop.user.name") {
                if let Some(v) = quoted_after(&l[i..]) {
                    user = Some(v);
                }
            }
        }
    }
    let installed = cx.root.exists("usr/sbin/rsyslogd");
    for (rel, text) in texts {
        let mut actions: Vec<String> = Vec::new();
        // action( ... ) blocks, which may span lines; quotes may hold `)`.
        let bytes = text.as_bytes();
        let mut i = 0;
        while let Some(at) = text[i..].find("action(").map(|n| i + n) {
            let (mut j, mut quote) = (at + 7, None);
            while j < bytes.len() {
                match (bytes[j], quote) {
                    (b'"' | b'\'', None) => quote = Some(bytes[j]),
                    (c, Some(q)) if c == q => quote = None,
                    (b')', None) => break,
                    _ => {}
                }
                j += 1;
            }
            let params = &text[at + 7..j.min(text.len())];
            if param(params, "type").is_some_and(|t| t.eq_ignore_ascii_case("omprog")) {
                if let Some(b) = param(params, "binary") {
                    actions.push(b);
                }
            }
            i = j.min(text.len());
            if i <= at {
                break;
            }
        }
        // A legacy selector line whose action is `^program;template`.
        for line in text.lines() {
            let l = line.trim();
            if l.starts_with('#') || l.starts_with('$') {
                continue;
            }
            if let Some(action) = l.split_whitespace().nth(1).and_then(|a| a.strip_prefix('^')) {
                actions.push(action.split(';').next().unwrap_or(action).to_string());
            }
        }
        for binary in actions {
            let mut e = entry(cx, &rel, format!("rsyslog:{}", hex(&blake3::hash(binary.as_bytes()).as_bytes()[..6])), "rsyslog", Trigger::Always);
            e.principal = Some(user.clone().unwrap_or_else(|| "root".into()));
            e.note("runs", "for every log message its selector matches");
            if let Some(first) = binary.split_whitespace().next().filter(|w| w.starts_with('/')) {
                e.target_path = Some(PathBuf::from(first));
            }
            e.command = Some(binary.into_bytes());
            if !installed {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "rsyslogd is not installed");
            }
            out.push(e);
        }
    }
    crate::entry::dedup_ids(out);
}

fn rsyslog_file(cx: &mut Ctx, rel: &Path, depth: usize, seen: &mut std::collections::BTreeSet<PathBuf>, out: &mut Vec<(PathBuf, String)>) {
    if depth > 8 || !seen.insert(rel.to_path_buf()) {
        return;
    }
    let Some(bytes) = cx.read_capped(rel, 256 * 1024) else { return };
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let mut includes = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(g) = l.strip_prefix("$IncludeConfig ") {
            includes.push(g.trim().to_string());
        } else if let Some(args) = l.strip_prefix("include(") {
            if let Some(f) = param(args, "file") {
                includes.push(f);
            }
        }
    }
    out.push((rel.to_path_buf(), text));
    for g in includes {
        let target = super::include_rel(Path::new("etc"), g.as_bytes());
        for f in super::expand_glob(cx, &target) {
            rsyslog_file(cx, &f, depth + 1, seen, out);
        }
    }
}

/// `name="value"` in RainerScript parameters, the name without regard to
/// case.
fn param(params: &str, name: &str) -> Option<String> {
    let lower = params.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find(name).map(|n| from + n) {
        let before_ok = at == 0 || !lower.as_bytes()[at - 1].is_ascii_alphanumeric() && lower.as_bytes()[at - 1] != b'.';
        let rest = params[at + name.len()..].trim_start();
        if before_ok && rest.starts_with('=') {
            return quoted_after(rest);
        }
        from = at + name.len();
    }
    None
}

fn quoted_after(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let end = s[start..].find('"')? + start;
    Some(s[start..end].to_string())
}

// ---------------------------------------------------------------- cups ----

/// CUPS backends (backend(7)): the scheduler runs a backend as root when its
/// file grants nothing to group or other, and otherwise as its unprivileged
/// user, whenever a job goes to a queue using it.
fn cups(cx: &mut Ctx, out: &mut Vec<Entry>) {
    if !cx.root.exists("usr/sbin/cupsd") {
        return;
    }
    for rel in sorted(cx, Path::new("usr/lib/cups/backend")) {
        let Ok(meta) = cx.root.stat_follow(&rel) else { continue };
        if !meta.is_file || meta.mode & 0o111 == 0 {
            continue;
        }
        let name = file_name(&rel);
        let mut e = entry(cx, &rel, format!("cups:{name}"), "cupsd", Trigger::Always);
        e.target_path = Some(cx.root.abs(&rel));
        e.note("runs", "for each print job sent to a queue using it");
        e.principal = Some(if meta.mode & 0o077 == 0 { "root" } else { "lp" }.into());
        out.push(e);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan};

    fn put(dir: &Path, rel: &str, body: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Events)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    #[test]
    fn event_handlers_are_read_by_each_daemons_rule() {
        let d = std::env::temp_dir().join(format!("unbidden-events-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "usr/sbin/acpid", b"", 0o755);
        put(&d, "etc/acpi/events/powerbtn", b"# power\nevent=button/power.*\nAction=/opt/on-power %e\n", 0o644);
        put(&d, "etc/acpi/events/lid.bak", b"event=button/lid\naction=/opt/never\n", 0o644);
        put(&d, "usr/sbin/zed", b"", 0o755);
        put(&d, "etc/zfs/zed.d/all-beacon.sh", b"#!/bin/sh\n", 0o755);
        put(&d, "etc/zfs/zed.d/zed.rc", b"ZED_EMAIL_ADDR=root\n", 0o644);
        put(&d, "usr/sbin/update-ca-certificates", b"", 0o755);
        put(&d, "etc/ca-certificates/update.d/jks-keystore", b"#!/bin/sh\n", 0o755);
        put(&d, "usr/share/apport/apport", b"", 0o755);
        put(&d, "usr/share/apport/general-hooks/evil.py", b"import os\n", 0o644);
        let s = scan(&d);
        let by = |n: &str| s.entries.iter().find(|e| e.name == n).unwrap_or_else(|| panic!("no {n}"));
        let power = by("acpid:powerbtn");
        assert_eq!((power.command.as_deref(), power.enabled), (Some(&b"/opt/on-power %e"[..]), Enablement::Enabled), "the key is case-insensitive");
        assert_eq!(by("acpid:lid.bak").enabled, Enablement::Disabled);
        let zedlet = by("zed:all-beacon.sh");
        // Owned by whoever runs the test: root only when root does.
        let root_run = rustix::process::geteuid().is_root();
        assert_eq!(zedlet.enabled, if root_run { Enablement::Enabled } else { Enablement::Disabled });
        assert!(!s.entries.iter().any(|e| e.name == "zed:zed.rc"), "zed.rc is configuration");
        assert_eq!(by("update-ca-certificates:jks-keystore").trigger, Trigger::PackageOp);
        assert_eq!(by("apport:evil.py").raw["loaded_for"], "every crash report");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rsyslog_programs_and_root_cups_backends_are_found() {
        let d = std::env::temp_dir().join(format!("unbidden-rsyslog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "usr/sbin/rsyslogd", b"", 0o755);
        put(&d, "etc/rsyslog.conf", b"module(load=\"omprog\")\n$PrivDropToUser syslog\n$IncludeConfig /etc/rsyslog.d/*.conf\n", 0o644);
        put(
            &d,
            "etc/rsyslog.d/50-exfil.conf",
            b"*.* action(type=\"omprog\"\n  binary=\"/usr/local/bin/ship --to x\" template=\"t\")\nauth.* ^/opt/legacy;fmt\n",
            0o644,
        );
        put(&d, "usr/sbin/cupsd", b"", 0o755);
        put(&d, "usr/lib/cups/backend/rootly", b"#!/bin/sh\n", 0o700);
        put(&d, "usr/lib/cups/backend/ipp", b"", 0o755);
        let s = scan(&d);
        let cmds: Vec<(&str, Option<&str>)> = s
            .entries
            .iter()
            .filter(|e| e.raw.get("run_by").is_some_and(|r| r == "rsyslog"))
            .map(|e| (std::str::from_utf8(e.command.as_deref().unwrap()).unwrap(), e.principal.as_deref()))
            .collect();
        assert_eq!(cmds.len(), 2);
        assert!(cmds.contains(&("/usr/local/bin/ship --to x", Some("syslog"))), "{cmds:?}");
        assert!(cmds.contains(&("/opt/legacy", Some("syslog"))));
        let by = |n: &str| s.entries.iter().find(|e| e.name == n).unwrap();
        assert_eq!(by("cups:rootly").principal.as_deref(), Some("root"));
        assert_eq!(by("cups:ipp").principal.as_deref(), Some("lp"));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
