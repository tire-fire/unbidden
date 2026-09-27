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

use crate::entry::{Enablement, Entry, Kind, Trigger};
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
}
