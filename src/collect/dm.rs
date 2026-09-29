//! Display managers: the scripts GDM, LightDM and SDDM run, most as root,
//! around the greeter and every graphical login.
//!
//! Each runs its hooks only while it is the display manager, which systemd
//! records as the target of display-manager.service; where that link is
//! absent the hooks are unknown.
//!
//! GDM (42 through 47, read from its source): PostLogin, PreSession and
//! PostSession for every login, X11 or Wayland, and Init when it starts an
//! X server, all as root, from /etc/gdm3 on the Debian family and /etc/gdm
//! elsewhere. From each directory it runs the first regular, executable file
//! named after the display, then after the host, then `Default`. Ubuntu's
//! gdm3 adds Prime and PrimeOff.
//!
//! LightDM (1.32): keys in its `[Seat:*]` section, the last file to set one
//! winning. Files: `lightdm.conf.d/*.conf` under /usr/share, /usr/local/share
//! and /etc/xdg (each directory sorted), then /etc/lightdm/lightdm.conf.d,
//! then /etc/lightdm/lightdm.conf.
//!
//! SDDM (0.21): the `[X11]` and `[Wayland]` commands, from
//! /usr/lib/sddm/sddm.conf.d, /etc/sddm.conf.d and /etc/sddm.conf, the last
//! to set one winning, or their built-in defaults.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct DisplayManager;

const CAP: usize = 256 * 1024;

impl Collector for DisplayManager {
    fn name(&self) -> &'static str {
        "display_manager"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let active = active(cx);
        let mut out = Vec::new();
        gdm(cx, &mut out, active.as_deref());
        lightdm(cx, &mut out, active.as_deref());
        sddm(cx, &mut out, active.as_deref());
        out
    }
}

/// The display manager systemd starts: the unit display-manager.service
/// links to, as `gdm3`, `gdm`, `lightdm` or `sddm`.
fn active(cx: &mut Ctx) -> Option<String> {
    let link = cx.root.read_link("etc/systemd/system/display-manager.service").ok()?;
    let unit = link.file_name()?.to_str()?;
    Some(unit.strip_suffix(".service").unwrap_or(unit).to_string())
}

/// On or unknown, by whether `dm` is the display manager.
fn gate(e: &mut Entry, dm: &[&str], active: Option<&str>) {
    match active {
        Some(a) if dm.contains(&a) => {}
        Some(a) => {
            e.enabled = Enablement::Disabled;
            e.note("inactive", format!("the display manager is {a}"));
        }
        None => {
            if e.enabled == Enablement::Enabled {
                e.enabled = Enablement::Unknown;
            }
            e.note("depends_on", "being the display manager; display-manager.service names none");
        }
    }
}

fn entry(cx: &mut Ctx, rel: &Path, name: String, trigger: Trigger, principal: Option<&str>) -> Entry {
    let mut e = cx.entry(Kind::DisplayManager, rel, name);
    e.trigger = trigger;
    e.enabled = Enablement::Enabled;
    e.principal = principal.map(str::to_string);
    e
}

// ------------------------------------------------------------------ gdm ----

const GDM_DIRS: [(&str, Trigger); 6] = [
    ("Init", Trigger::Boot),
    ("PostLogin", Trigger::Login),
    ("PreSession", Trigger::Login),
    ("PostSession", Trigger::Login),
    ("Prime", Trigger::Boot),
    ("PrimeOff", Trigger::Boot),
];

fn gdm(cx: &mut Ctx, out: &mut Vec<Entry>, active: Option<&str>) {
    for conf in ["etc/gdm3", "etc/gdm"] {
        for (dir, trigger) in GDM_DIRS {
            let d = Path::new(conf).join(dir);
            let ents = cx.dir(&d);
            for ent in ents {
                let rel = d.join(&ent.name);
                let Ok(meta) = cx.root.stat_follow(&rel) else { continue };
                if !meta.is_file {
                    continue;
                }
                let name = ent.name.to_string_lossy().into_owned();
                let mut e = entry(cx, &rel, format!("gdm:{dir}/{name}"), trigger, Some("root"));
                e.target_path = Some(cx.root.abs(&rel));
                e.note("hook", dir);
                if meta.mode & 0o111 == 0 {
                    e.enabled = Enablement::Disabled;
                    e.note("not_run", "not executable");
                } else if name != "Default" {
                    e.note("runs_for", format!("the display or host named {name}, before Default"));
                }
                if matches!(dir, "Prime" | "PrimeOff") {
                    e.note("added_by", "Ubuntu's gdm3");
                }
                gate(&mut e, &["gdm3", "gdm"], active);
                out.push(e);
            }
        }
    }
}

// ---------------------------------------------------------------- ini ------

/// The files of a `.conf` directory, sorted.
fn conf_dir(cx: &mut Ctx, dir: &str) -> Vec<PathBuf> {
    let names: Vec<_> =
        cx.dir(dir).into_iter().filter(|e| !e.is_dir && e.name.as_encoded_bytes().ends_with(b".conf")).map(|e| e.name).collect();
    names.into_iter().map(|n| Path::new(dir).join(n)).collect()
}

/// Each key's final value across `files`, read in order, with the file that
/// set it: only the sections `wanted` says are read.
fn merged(cx: &mut Ctx, files: &[PathBuf], wanted: impl Fn(&str) -> bool) -> BTreeMap<(String, String), (String, PathBuf)> {
    let mut out = BTreeMap::new();
    for f in files {
        let Some(bytes) = cx.read_capped(f, CAP) else { continue };
        for crate::text::IniLine { section, key, value, .. } in crate::text::ini(&bytes) {
            let value = crate::text::lossy(&value);
            if wanted(&section) {
                out.insert((section, key), (value, f.clone()));
            }
        }
    }
    out
}

fn command_entry(
    cx: &mut Ctx,
    dm: &str,
    rel: &Path,
    key: &str,
    value: &str,
    trigger: Trigger,
    principal: Option<&str>,
) -> Entry {
    let mut e = entry(cx, rel, format!("{dm}:{key}"), trigger, principal);
    e.note("key", key);
    e.command = Some(value.as_bytes().to_vec());
    if let Some(first) = value.split_whitespace().next().filter(|w| w.starts_with('/')) {
        e.target_path = Some(PathBuf::from(first));
    }
    e
}

// -------------------------------------------------------------- lightdm ----

/// What LightDM runs, and as whom: the scripts as root, the wrappers as the
/// account whose session or greeter they start.
const LIGHTDM_KEYS: [(&str, Trigger, Option<&str>); 8] = [
    ("display-setup-script", Trigger::Boot, Some("root")),
    ("display-stopped-script", Trigger::Boot, Some("root")),
    ("greeter-setup-script", Trigger::Boot, Some("root")),
    ("session-setup-script", Trigger::Login, Some("root")),
    ("session-cleanup-script", Trigger::Login, Some("root")),
    ("session-wrapper", Trigger::Login, None),
    ("greeter-wrapper", Trigger::Boot, Some("lightdm")),
    ("guest-wrapper", Trigger::Login, None),
];

fn lightdm(cx: &mut Ctx, out: &mut Vec<Entry>, active: Option<&str>) {
    let mut files = Vec::new();
    for dir in [
        "usr/share/lightdm/lightdm.conf.d",
        "usr/local/share/lightdm/lightdm.conf.d",
        "etc/xdg/lightdm/lightdm.conf.d",
        "etc/lightdm/lightdm.conf.d",
    ] {
        files.extend(conf_dir(cx, dir));
    }
    files.push(PathBuf::from("etc/lightdm/lightdm.conf"));
    // [SeatDefaults] is the old name for [Seat:*]; a named seat's section
    // applies to that seat only, and is noted.
    let values = merged(cx, &files, |s| s == "Seat:*" || s == "SeatDefaults" || s.starts_with("Seat:"));
    for ((section, key), (value, rel)) in values {
        let Some(&(_, trigger, principal)) = LIGHTDM_KEYS.iter().find(|(k, _, _)| *k == key) else { continue };
        if value.is_empty() {
            continue;
        }
        let mut e = command_entry(cx, "lightdm", &rel, &key, &value, trigger, principal);
        if section != "Seat:*" && section != "SeatDefaults" {
            e.note("seat", section.trim_start_matches("Seat:"));
        }
        gate(&mut e, &["lightdm"], active);
        out.push(e);
    }
}

// ----------------------------------------------------------------- sddm ----

const SDDM_KEYS: [(&str, &str, &str, Trigger, Option<&str>); 4] = [
    ("X11", "DisplayCommand", "usr/share/sddm/scripts/Xsetup", Trigger::Boot, Some("root")),
    ("X11", "DisplayStopCommand", "usr/share/sddm/scripts/Xstop", Trigger::Boot, Some("root")),
    ("X11", "SessionCommand", "etc/sddm/Xsession", Trigger::Login, None),
    ("Wayland", "SessionCommand", "etc/sddm/wayland-session", Trigger::Login, None),
];

fn sddm(cx: &mut Ctx, out: &mut Vec<Entry>, active: Option<&str>) {
    if !["usr/bin/sddm", "usr/sbin/sddm"].iter().any(|p| cx.root.exists(p)) {
        return;
    }
    let mut files = conf_dir(cx, "usr/lib/sddm/sddm.conf.d");
    files.extend(conf_dir(cx, "etc/sddm.conf.d"));
    files.push(PathBuf::from("etc/sddm.conf"));
    let values = merged(cx, &files, |s| s == "X11" || s == "Wayland");
    for (section, key, default, trigger, principal) in SDDM_KEYS {
        let (value, rel) = match values.get(&(section.to_string(), key.to_string())) {
            Some((v, rel)) => (v.clone(), rel.clone()),
            // The built-in default, reported where the file it names is.
            None => {
                if !cx.root.exists(default) {
                    continue;
                }
                (format!("/{default}"), PathBuf::from(default))
            }
        };
        if value.is_empty() {
            continue;
        }
        let mut e = command_entry(cx, "sddm", &rel, &format!("{section}/{key}"), &value, trigger, principal);
        gate(&mut e, &["sddm"], active);
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
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(DisplayManager)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    fn by<'a>(s: &'a Scan, name: &str) -> &'a Entry {
        s.entries.iter().find(|e| e.name == name).unwrap_or_else(|| panic!("no {name}"))
    }

    #[test]
    fn each_display_managers_hooks_are_read_its_way_and_gated_on_being_active() {
        let d = crate::testing::Tree::new("dm");
        put(&d, "etc/gdm3/PostLogin/Default.sample", b"#!/bin/sh\n", 0o644);
        put(&d, "etc/gdm3/PreSession/Default", b"#!/bin/sh\n", 0o755);
        put(&d, "etc/gdm3/PostSession/:0", b"#!/bin/sh\n", 0o755);
        put(&d, "usr/share/lightdm/lightdm.conf.d/50-a.conf", b"[Seat:*]\nsession-setup-script=/usr/share/x\ngreeter-wrapper=/usr/lib/lightdm/greeter-wrap\n", 0o644);
        put(&d, "etc/lightdm/lightdm.conf.d/90-b.conf", b"[Seat:*]\n# display-setup-script=/commented\nsession-setup-script = /opt/evil --now\n", 0o644);
        put(&d, "etc/lightdm/lightdm.conf", b"[SeatDefaults]\nsession-cleanup-script=/opt/cleanup\n[Seat:seat1]\ndisplay-setup-script=/opt/seat1\n", 0o644);
        put(&d, "usr/bin/sddm", b"", 0o755);
        put(&d, "usr/share/sddm/scripts/Xsetup", b"#!/bin/sh\n", 0o755);
        put(&d, "etc/sddm.conf.d/10-x.conf", b"[X11]\nDisplayStopCommand=/opt/stop\n", 0o644);
        std::fs::create_dir_all(d.join("etc/systemd/system")).unwrap();
        std::os::unix::fs::symlink("/lib/systemd/system/lightdm.service", d.join("etc/systemd/system/display-manager.service")).unwrap();
        let s = scan(&d);

        let setup = by(&s, "lightdm:session-setup-script");
        assert_eq!(setup.command.as_deref(), Some(&b"/opt/evil --now"[..]), "the later file wins");
        assert_eq!((setup.enabled, setup.principal.as_deref(), setup.trigger), (Enablement::Enabled, Some("root"), Trigger::Login));
        assert_eq!(setup.source, d.join("etc/lightdm/lightdm.conf.d/90-b.conf"));
        assert_eq!(by(&s, "lightdm:session-cleanup-script").enabled, Enablement::Enabled);
        assert_eq!(by(&s, "lightdm:display-setup-script").raw["seat"], "seat1");
        assert_eq!(by(&s, "lightdm:greeter-wrapper").principal.as_deref(), Some("lightdm"));
        assert!(!s.entries.iter().any(|e| e.command.as_deref() == Some(&b"/commented"[..])));

        let pre = by(&s, "gdm:PreSession/Default");
        assert_eq!((pre.enabled, pre.raw["inactive"].as_str()), (Enablement::Disabled, "the display manager is lightdm"));
        assert_eq!(by(&s, "gdm:PostLogin/Default.sample").raw["not_run"], "not executable");
        assert!(by(&s, "gdm:PostSession/:0").raw["runs_for"].contains(":0"));

        assert_eq!(by(&s, "sddm:X11/DisplayCommand").target_path, Some(PathBuf::from("/usr/share/sddm/scripts/Xsetup")));
        assert_eq!(by(&s, "sddm:X11/DisplayStopCommand").command.as_deref(), Some(&b"/opt/stop"[..]));
        assert_eq!(by(&s, "sddm:X11/DisplayCommand").enabled, Enablement::Disabled);

        std::fs::remove_file(d.join("etc/systemd/system/display-manager.service")).unwrap();
        assert_eq!(by(&scan(&d), "gdm:PreSession/Default").enabled, Enablement::Unknown);
    }
}
