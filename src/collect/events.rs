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
//!
//! molly-guard: what run-parts selects in /etc/molly-guard/run.d, before a
//! shutdown or reboot command goes ahead. netfilter-persistent: what
//! run-parts selects in /usr/share/netfilter-persistent/plugins.d, at boot.
//! schroot 1.6 (sbuild-run-parts.cc, sbuild-util.cc): each file in
//! /etc/schroot/setup.d whose name is all `[a-z0-9]`, LSB-style
//! `_?([a-z0-9_.]+-)+[a-z0-9]+`, or cron-style `[a-z0-9][a-z0-9-]*`, and not
//! ending `dpkg-old`, `-dist`, `-new` or `-tmp`, in name order, as root when
//! a chroot session starts or ends. ModemManager 1.20 (mm-dispatcher*.c):
//! from /etc/ModemManager and its library directory, the `connection.d`
//! scripts on every connect and disconnect, and the `fcc-unlock.d` script
//! named for a modem's `vid:pid`, when that modem needs unlocking; a script
//! runs only if, links followed, it is regular, non-empty, owned by root,
//! executable by its owner, not writable by group or other, not setuid, and
//! not a link to /dev/null. cron-apt: /etc/cron-apt/config and, for each
//! action, config.d/<action>, sourced as shell, and each line of each action
//! in action.d (regular files named `[[:alnum:]_-]` alone) run as the
//! arguments of apt-get; all as root, on cron-apt's schedule.

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
            ("etc/molly-guard/run.d", "molly-guard", Trigger::PowerEvent, "usr/lib/molly-guard/molly-guard"),
            ("usr/share/netfilter-persistent/plugins.d", "netfilter-persistent", Trigger::Boot, "usr/sbin/netfilter-persistent"),
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
        if cx.root.exists("usr/bin/schroot") {
            schroot(cx, &mut out);
        }
        if cx.root.exists("usr/sbin/ModemManager") {
            modem_manager(cx, &mut out);
        }
        if cx.root.exists("usr/sbin/cron-apt") {
            cron_apt(cx, &mut out);
        }
        out
    }
}

/// schroot's own run-parts, always in its LSB mode.
fn schroot(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let lanana = |n: &str| !n.is_empty() && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let cron = |n: &str| {
        n.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    // `_?([a-z0-9_.]+-)+[a-z0-9]+`: past an optional `_`, a last part of
    // [a-z0-9] after the final `-`, and before it only [a-z0-9_.-] with no
    // empty part.
    let lsb = |n: &str| {
        let n = n.strip_prefix('_').unwrap_or(n);
        let Some((head, last)) = n.rsplit_once('-') else { return false };
        lanana(last)
            && !head.is_empty()
            && head.split('-').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.'))
    };
    let cruft = |n: &str| ["dpkg-old", "dpkg-dist", "dpkg-new", "dpkg-tmp"].iter().any(|c| n.ends_with(c));
    for rel in sorted(cx, Path::new("etc/schroot/setup.d")) {
        let name = file_name(&rel);
        if !(lanana(&name) || lsb(&name) || cron(&name)) || cruft(&name) {
            continue;
        }
        let mut e = entry(cx, &rel, format!("schroot:{name}"), "schroot", Trigger::Login);
        e.target_path = Some(cx.root.abs(&rel));
        if e.mode & 0o111 == 0 {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "not executable");
        }
        out.push(e);
    }
}

fn modem_manager(cx: &mut Ctx, out: &mut Vec<Entry>) {
    // The library directory: /usr/lib64, a multiarch one, or /usr/lib.
    let mut libdirs: Vec<PathBuf> = vec!["usr/lib64/ModemManager".into(), "usr/lib/ModemManager".into()];
    for ent in cx.dir(Path::new("usr/lib")) {
        if ent.is_dir && ent.name.to_string_lossy().contains("-linux-") {
            libdirs.push(Path::new("usr/lib").join(&ent.name).join("ModemManager"));
        }
    }
    let dirs: Vec<PathBuf> = std::iter::once(PathBuf::from("etc/ModemManager")).chain(libdirs).collect();
    for (sub, trigger, what) in [("connection.d", Trigger::NetworkEvent, "a modem connects or disconnects"), ("fcc-unlock.d", Trigger::DeviceEvent, "a modem with that vid:pid needs FCC unlock")] {
        for dir in &dirs {
            for rel in sorted(cx, &dir.join(sub)) {
                let name = file_name(&rel);
                let file = cx.root.resolve(&rel).unwrap_or_else(|_| rel.clone());
                let mut e = entry(cx, &file, format!("ModemManager:{sub}:{name}"), "ModemManager", trigger);
                e.target_path = Some(cx.root.abs(&file));
                e.note("dispatcher", cx.root.abs(&rel).display().to_string());
                e.note("runs_when", what);
                let meta = cx.root.stat_follow(&rel).ok();
                let why = if cx.root.read_link(&rel).is_ok_and(|t| t == Path::new("/dev/null")) {
                    Some("a link to /dev/null masks it")
                } else if let Some(m) = meta {
                    if !m.is_file {
                        Some("not a regular file")
                    } else if m.size == 0 {
                        Some("empty")
                    } else if m.uid != 0 {
                        Some("not owned by root")
                    } else if m.mode & 0o022 != 0 {
                        Some("writable by group or other")
                    } else if m.mode & 0o4000 != 0 {
                        Some("setuid")
                    } else if m.mode & 0o100 == 0 {
                        Some("not executable by its owner")
                    } else {
                        None
                    }
                } else {
                    Some("cannot be read")
                };
                let why = why.or_else(|| {
                    let vid_pid = name.len() == 9
                        && name.as_bytes()[4] == b':'
                        && name.bytes().enumerate().all(|(i, b)| i == 4 || matches!(b, b'0'..=b'9' | b'a'..=b'f'));
                    (sub == "fcc-unlock.d" && !vid_pid).then_some("ModemManager looks up only a lowercase vid:pid name")
                });
                if let Some(why) = why {
                    e.enabled = Enablement::Disabled;
                    e.note("not_run", why);
                }
                out.push(e);
            }
        }
    }
}

fn cron_apt(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let shell = |cx: &mut Ctx, out: &mut Vec<Entry>, rel: &Path, name: String| {
        if !cx.root.stat_follow(rel).is_ok_and(|m| m.is_file) {
            return;
        }
        let mut e = entry(cx, rel, name, "cron-apt", Trigger::Schedule);
        e.target_path = Some(cx.root.abs(rel));
        e.note("sourced_by", "cron-apt");
        out.push(e);
    };
    shell(cx, out, Path::new("etc/cron-apt/config"), "cron-apt:config".into());
    let action_dir = Path::new("etc/cron-apt/action.d");
    for rel in sorted(cx, action_dir) {
        let name = file_name(&rel);
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            continue;
        }
        if !cx.root.stat_follow(&rel).is_ok_and(|m| m.is_file) {
            continue;
        }
        shell(cx, out, &Path::new("etc/cron-apt/config.d").join(&name), format!("cron-apt:config.d:{name}"));
        let Some(bytes) = cx.read_capped(&rel, 64 * 1024) else { continue };
        for (n, line) in bytes.split(|b| *b == b'\n').enumerate() {
            // `sed -e "s/#.*$//"`, then blank lines dropped.
            let line = &line[..line.iter().position(|b| *b == b'#').unwrap_or(line.len())];
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let mut e = entry(cx, &rel, format!("cron-apt:{name}:{}", n + 1), "cron-apt", Trigger::Schedule);
            e.command = Some([b"/usr/bin/apt-get ".as_slice(), line.trim_ascii()].concat());
            out.push(e);
        }
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
    fn package_hook_directories_run_as_their_tools_choose() {
        let d = std::env::temp_dir().join(format!("unbidden-hookdirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "usr/bin/schroot", b"", 0o755);
        for name in ["00check", "15binfmt", "_x.y-z1", "a-", "Upper", "05file.dpkg-old", "x_y"] {
            put(&d, &format!("etc/schroot/setup.d/{name}"), b"#!/bin/sh\n", 0o755);
        }
        put(&d, "usr/sbin/ModemManager", b"", 0o755);
        put(&d, "etc/ModemManager/connection.d/10-beacon", b"#!/bin/sh\n", 0o755);
        put(&d, "usr/lib/x86_64-linux-gnu/ModemManager/fcc-unlock.d/105b:e0ab", b"#!/bin/sh\n", 0o755);
        put(&d, "etc/ModemManager/fcc-unlock.d/NOTVIDPID", b"#!/bin/sh\n", 0o755);
        put(&d, "usr/sbin/cron-apt", b"", 0o755);
        put(&d, "etc/cron-apt/config", b"MAILON=error\n", 0o644);
        put(&d, "etc/cron-apt/action.d/3-download", b"# comment\ndist-upgrade -d -y # trailing\n\n-o APT::Update::Pre-Invoke::=/opt/x update\n", 0o644);
        put(&d, "etc/cron-apt/action.d/9.bak", b"install evil\n", 0o644);
        put(&d, "etc/cron-apt/config.d/3-download", b"OPTIONS=-q\n", 0o644);
        let s = scan(&d);
        let names = |p: &str| s.entries.iter().filter(|e| e.name.starts_with(p)).map(|e| e.name.clone()).collect::<Vec<_>>();
        assert_eq!(names("schroot:"), ["schroot:00check", "schroot:15binfmt", "schroot:_x.y-z1", "schroot:a-"], "schroot's LSB names only");
        let mm: Vec<(&str, Enablement)> = s.entries.iter().filter(|e| e.name.starts_with("ModemManager:")).map(|e| (e.name.as_str(), e.enabled)).collect();
        assert_eq!(mm.len(), 3);
        assert!(mm.iter().all(|(_, en)| *en == Enablement::Disabled), "fixture files are not root's: {mm:?}");
        let fcc = s.entries.iter().find(|e| e.name.ends_with("NOTVIDPID")).unwrap();
        assert_eq!(fcc.raw["not_run"], "not owned by root");
        let apt: Vec<(&str, &str)> = s
            .entries
            .iter()
            .filter(|e| e.name.starts_with("cron-apt:"))
            .map(|e| (e.name.as_str(), e.command.as_deref().map(|c| std::str::from_utf8(c).unwrap()).unwrap_or("-")))
            .collect();
        assert_eq!(
            apt,
            [
                ("cron-apt:3-download:2", "/usr/bin/apt-get dist-upgrade -d -y"),
                ("cron-apt:3-download:4", "/usr/bin/apt-get -o APT::Update::Pre-Invoke::=/opt/x update"),
                ("cron-apt:config", "-"),
                ("cron-apt:config.d:3-download", "-"),
            ]
        );
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
