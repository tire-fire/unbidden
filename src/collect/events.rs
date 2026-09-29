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
//!
//! ClamAV 1.0 (optparser.c, clamd_others.c, freshclam.c): clamd.conf's
//! `VirusEvent`, run through `/bin/sh -c` as clamd's `User` (root when
//! unset) on each detection; freshclam.conf's `OnUpdateExecute`,
//! `OnErrorExecute` and `OnOutdatedExecute`, run through a shell as
//! `DatabaseOwner` (clamav). Lines are `Name value`, the value trimmed and
//! a leading `"` quoting to the last; a line of two characters or fewer or
//! starting `#` is skipped, and an `Example` line stops the daemon.
//!
//! SpamAssassin: each `loadplugin Name [file]` in /etc/spamassassin's
//! `.pre` and `.cf` files loads Perl into spamd, from the file (relative to
//! the configuration's directory) or else from Perl's @INC; and Debian's
//! daily sa-update job runs what `run-parts --lsbsysinit` selects in
//! /etc/spamassassin/sa-update-hooks.d. Kea: each `"library"` of a
//! `"hooks-libraries"` list in the kea-dhcp4, kea-dhcp6, kea-dhcp-ddns and
//! kea-ctrl-agent configurations, loaded into that daemon; Kea's JSON takes
//! `#`, `//` and `/* */` comments and `<?include "file"?>`. X2Go: every
//! readable file in /etc/x2go/x2go_logout.d, which x2go_logout sources from
//! x2goruncommand, as the session's user, when an X2Go session ends.
//! libreport (event_config.c): each `EVENT=name [conditions]` rule in
//! /etc/libreport/events.d/*.conf, whose indented lines that follow are the
//! shell abrt-handle-event runs, as root under abrtd, when that event fires
//! for a crash; `#` comments to the end of the line.

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
        clamav(cx, &mut out);
        if cx.root.exists("usr/sbin/spamd") || cx.root.exists("usr/bin/spamassassin") {
            spamassassin(cx, &mut out);
        }
        kea(cx, &mut out);
        if cx.root.exists("usr/bin/x2goruncommand") {
            x2go(cx, &mut out);
        }
        libreport(cx, &mut out);
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

/// A ClamAV configuration's options, the last of each name winning, and
/// whether an `Example` line leaves the daemon refusing to start.
fn clamav_options(bytes: &[u8]) -> (std::collections::BTreeMap<String, String>, bool) {
    let mut opts = std::collections::BTreeMap::new();
    for line in String::from_utf8_lossy(bytes).lines() {
        let line = line.trim_start_matches([' ', '\t']);
        // fgets keeps the newline, so "two characters" is one and a break.
        if line.len() <= 1 || line.starts_with('#') {
            continue;
        }
        if line.starts_with("Example") {
            return (opts, true);
        }
        let Some((name, value)) = line.split_once([' ', '\t']) else { continue };
        let value = value.trim_matches([' ', '\t']);
        let value = match value.strip_prefix('"') {
            Some(v) => &v[..v.rfind('"').unwrap_or(v.len())],
            None => value,
        };
        if !value.is_empty() {
            opts.insert(name.to_string(), value.to_string());
        }
    }
    (opts, false)
}

fn clamav(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let daemons: [(&str, &[&str], &[&str], &str); 2] = [
        ("clamd", &["etc/clamav/clamd.conf", "etc/clamd.d/scan.conf"], &["VirusEvent"], "usr/sbin/clamd"),
        ("freshclam", &["etc/clamav/freshclam.conf", "etc/freshclam.conf"], &["OnUpdateExecute", "OnErrorExecute", "OnOutdatedExecute"], "usr/bin/freshclam"),
    ];
    for (daemon, confs, keys, bin) in daemons {
        let installed = cx.root.exists(bin);
        for conf in confs {
            let rel = Path::new(conf);
            let Some(bytes) = cx.read_capped(rel, 256 * 1024) else { continue };
            let (opts, example) = clamav_options(&bytes);
            let principal = match daemon {
                "clamd" => opts.get("User").cloned().unwrap_or_else(|| "root".into()),
                _ => opts.get("DatabaseOwner").cloned().unwrap_or_else(|| "clamav".into()),
            };
            for key in keys {
                let Some(cmd) = opts.get(*key) else { continue };
                let trigger = if daemon == "clamd" { Trigger::Always } else { Trigger::Schedule };
                let mut e = entry(cx, rel, format!("{daemon}:{key}"), daemon, trigger);
                e.principal = Some(principal.clone());
                e.command = Some(cmd.as_bytes().to_vec());
                if example {
                    e.enabled = Enablement::Disabled;
                    e.note("not_run", "an Example line stops the daemon starting");
                } else if !installed {
                    e.enabled = Enablement::Disabled;
                    e.note("not_run", format!("{daemon} is not installed"));
                }
                out.push(e);
            }
        }
    }
}

fn spamassassin(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let dir = Path::new("etc/spamassassin");
    for rel in sorted(cx, dir) {
        let name = file_name(&rel);
        if !(name.ends_with(".pre") || name.ends_with(".cf")) {
            continue;
        }
        let Some(bytes) = cx.read_capped(&rel, 256 * 1024) else { continue };
        for line in String::from_utf8_lossy(&bytes).lines() {
            let line = line.split('#').next().unwrap_or_default();
            let mut words = line.split_whitespace();
            if words.next() != Some("loadplugin") {
                continue;
            }
            let Some(module) = words.next() else { continue };
            let mut e = entry(cx, &rel, format!("spamassassin:{module}"), "spamd", Trigger::Always);
            e.command = Some(module.as_bytes().to_vec());
            match words.next() {
                Some(file) if file.starts_with('/') => e.target_path = Some(PathBuf::from(file)),
                Some(file) => e.target_path = Some(cx.root.abs(dir.join(file))),
                None => e.note("target_unverifiable", "a Perl module found on @INC"),
            }
            out.push(e);
        }
    }
    // run-parts --lsbsysinit: LANANA, LSB hierarchical, or Debian cron
    // names, and no dpkg leftovers.
    if cx.root.exists("usr/bin/sa-update") {
        let lanana = |n: &str| !n.is_empty() && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let lsb = |n: &str| {
            let n = n.strip_prefix('_').unwrap_or(n);
            n.rsplit_once('-').is_some_and(|(head, last)| {
                lanana(last) && head.split('-').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.'))
            })
        };
        let cron = |n: &str| !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        for rel in sorted(cx, &dir.join("sa-update-hooks.d")) {
            let name = file_name(&rel);
            let cruft = [".dpkg-old", ".dpkg-dist", ".dpkg-new", ".dpkg-tmp"].iter().any(|c| name.ends_with(c));
            if !(lanana(&name) || lsb(&name) || cron(&name)) || cruft {
                continue;
            }
            let mut e = entry(cx, &rel, format!("sa-update:{name}"), "sa-update", Trigger::Schedule);
            e.target_path = Some(cx.root.abs(&rel));
            if e.mode & 0o111 == 0 {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "not executable");
            }
            out.push(e);
        }
    }
}

/// Kea's JSON with its comments blanked out, strings kept whole.
fn kea_uncomment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                out.push(c);
                while let Some(c) = chars.next() {
                    out.push(c);
                    if c == '\\' {
                        out.extend(chars.next());
                    } else if c == '"' {
                        break;
                    }
                }
            }
            '#' => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'/') => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut last = ' ';
                for c in chars.by_ref() {
                    if last == '*' && c == '/' {
                        break;
                    }
                    last = c;
                }
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    out
}

/// The quoted string after `"key"` and a colon, wherever they appear.
fn json_strings<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    let needle = format!("\"{key}\"");
    let mut out = Vec::new();
    for (i, _) in text.match_indices(&needle) {
        let rest = text[i + needle.len()..].trim_start();
        let Some(rest) = rest.strip_prefix(':') else { continue };
        let Some(rest) = rest.trim_start().strip_prefix('"') else { continue };
        if let Some(end) = rest.find('"') {
            out.push(&rest[..end]);
        }
    }
    out
}

fn kea(cx: &mut Ctx, out: &mut Vec<Entry>) {
    for (conf, daemon) in [
        ("etc/kea/kea-dhcp4.conf", "kea-dhcp4"),
        ("etc/kea/kea-dhcp6.conf", "kea-dhcp6"),
        ("etc/kea/kea-dhcp-ddns.conf", "kea-dhcp-ddns"),
        ("etc/kea/kea-ctrl-agent.conf", "kea-ctrl-agent"),
    ] {
        let installed = cx.root.exists(format!("usr/sbin/{daemon}"));
        let mut files = vec![PathBuf::from(conf)];
        let mut i = 0;
        while i < files.len() && i < 16 {
            let rel = files[i].clone();
            i += 1;
            let Some(bytes) = cx.read_capped(&rel, 1024 * 1024) else { continue };
            let text = kea_uncomment(&String::from_utf8_lossy(&bytes));
            for (at, _) in text.match_indices("<?include") {
                if let Some(q) = text[at..].split('"').nth(1) {
                    files.push(super::include_rel(rel.parent().unwrap_or(Path::new("")), q.as_bytes()));
                }
            }
            for lib in json_strings(&text, "library") {
                let mut e = entry(cx, &rel, format!("{daemon}:{lib}"), daemon, Trigger::NetworkEvent);
                e.principal = None;
                e.command = Some(lib.as_bytes().to_vec());
                if lib.starts_with('/') {
                    e.target_path = Some(PathBuf::from(lib));
                } else {
                    e.note("target_unverifiable", "a hooks library found in Kea's hooks directory");
                }
                if !installed {
                    e.enabled = Enablement::Disabled;
                    e.note("not_run", format!("{daemon} is not installed"));
                }
                out.push(e);
            }
        }
    }
}

fn libreport(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/libexec/abrt-handle-event");
    for rel in sorted(cx, Path::new("etc/libreport/events.d")) {
        let file = file_name(&rel);
        if !file.ends_with(".conf") {
            continue;
        }
        let Some(bytes) = cx.read_capped(&rel, 256 * 1024) else { continue };
        let mut rules: Vec<(String, Vec<String>)> = Vec::new();
        for line in String::from_utf8_lossy(&bytes).lines() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            if let Some(head) = line.strip_prefix("EVENT=") {
                rules.push((head.trim().to_string(), Vec::new()));
            } else if line.starts_with([' ', '\t']) && !line.trim().is_empty() {
                if let Some((_, body)) = rules.last_mut() {
                    body.push(line.trim().to_string());
                }
            }
        }
        for (i, (head, body)) in rules.into_iter().enumerate() {
            if body.is_empty() {
                continue;
            }
            let event = head.split_whitespace().next().unwrap_or_default().to_string();
            let mut e = entry(cx, &rel, format!("abrt:{file}:{event}:{}", i + 1), "abrt-handle-event", Trigger::Always);
            e.note("event", head);
            e.note("runs_when", "a crash reaches this event, as root under abrtd");
            e.command = Some(body.join("\n").into_bytes());
            if !installed {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "abrt is not installed");
            }
            out.push(e);
        }
    }
}

fn x2go(cx: &mut Ctx, out: &mut Vec<Entry>) {
    for rel in sorted(cx, Path::new("etc/x2go/x2go_logout.d")) {
        let name = file_name(&rel);
        let mut e = entry(cx, &rel, format!("x2go:logout:{name}"), "x2goruncommand", Trigger::Login);
        e.principal = None;
        e.note("runs_when", "an X2Go session ends, sourced as the session's user");
        e.target_path = Some(cx.root.abs(&rel));
        out.push(e);
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
    let names: Vec<_> = cx.dir(dir).into_iter().filter(|e| !e.is_dir).map(|e| e.name).collect();
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
    for f in super::run_parts_dir(cx, flavour, dir) {
        let mut e = entry(cx, &f.rel, format!("{tool}:{}", f.name.to_string_lossy()), tool, trigger);
        e.target_path = Some(cx.root.abs(&f.rel));
        if let Some(why) = f.not_run {
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
        put(&d, "usr/bin/x2goruncommand", b"", 0o755);
        put(&d, "etc/x2go/x2go_logout.d/010_userscripts.sh", b"echo bye\n", 0o644);
        put(&d, "usr/libexec/abrt-handle-event", b"", 0o755);
        put(&d, "etc/libreport/events.d/evil_event.conf", b"# c\nEVENT=post-create analyzer=CCpp\n    /opt/beacon --crash \\\n        \"$DUMP_DIR\"\nEVENT=notify\n\nEVENT=report_x\n   reporter-x\n", 0o644);
        let s = scan(&d);
        let abrt: Vec<(&str, &str)> = s.entries.iter().filter(|e| e.name.starts_with("abrt:")).map(|e| (e.name.as_str(), std::str::from_utf8(e.command.as_deref().unwrap()).unwrap())).collect();
        assert_eq!(abrt, [("abrt:evil_event.conf:post-create:1", "/opt/beacon --crash \\\n\"$DUMP_DIR\""), ("abrt:evil_event.conf:report_x:3", "reporter-x")], "an event with no command runs nothing");
        assert!(s.entries.iter().any(|e| e.name == "x2go:logout:010_userscripts.sh" && e.principal.is_none()));
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
    fn clamav_runs_its_event_commands() {
        let d = std::env::temp_dir().join(format!("unbidden-clamav-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "usr/sbin/clamd", b"", 0o755);
        put(&d, "etc/clamav/clamd.conf", b"# VirusEvent /never\nUser clamav\nVirusEvent   \"/opt/alert %v\"  \n", 0o644);
        put(&d, "etc/clamav/freshclam.conf", b"OnUpdateExecute /opt/updated\n", 0o644);
        put(&d, "etc/clamd.d/scan.conf", b"Example\nVirusEvent /opt/example\n", 0o644);
        let s = scan(&d);
        let got: Vec<(&str, &str, &str, Enablement)> = s
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.principal.as_deref().unwrap(), std::str::from_utf8(e.command.as_deref().unwrap()).unwrap(), e.enabled))
            .collect();
        assert_eq!(
            got,
            [
                ("clamd:VirusEvent", "clamav", "/opt/alert %v", Enablement::Enabled),
                ("freshclam:OnUpdateExecute", "clamav", "/opt/updated", Enablement::Disabled),
            ]
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn spamassassin_and_kea_load_what_their_configurations_name() {
        let d = std::env::temp_dir().join(format!("unbidden-plugins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "usr/sbin/spamd", b"", 0o755);
        put(&d, "etc/spamassassin/v310.pre", b"# loadplugin Mail::SpamAssassin::Plugin::Never\nloadplugin Mail::SpamAssassin::Plugin::SPF\n", 0o644);
        put(&d, "etc/spamassassin/local.cf", b"loadplugin Evil evil.pm # here\n", 0o644);
        put(&d, "etc/spamassassin/notes.txt", b"loadplugin Never\n", 0o644);
        put(&d, "usr/sbin/kea-dhcp4", b"", 0o755);
        put(
            &d,
            "etc/kea/kea-dhcp4.conf",
            b"{ \"Dhcp4\": {\n // \"library\": \"/never.so\"\n /* \"library\": \"/nor.so\" */\n \"hooks-libraries\": [ { \"library\" : \"/opt/hook.so\", \"parameters\": { \"x\": \"# not a comment\" } } ],\n<?include \"extra.json\"?>\n} }\n",
            0o644,
        );
        put(&d, "etc/kea/extra.json", b"\"hooks-libraries\": [ { \"library\": \"libdhcp_lease_cmds.so\" } ]\n", 0o644);
        let s = scan(&d);
        let got: Vec<(&str, Option<&Path>)> = s.entries.iter().map(|e| (e.name.as_str(), e.target_path.as_deref())).collect();
        assert_eq!(
            got,
            [
                ("kea-dhcp4:libdhcp_lease_cmds.so", None),
                ("kea-dhcp4:/opt/hook.so", Some(Path::new("/opt/hook.so"))),
                ("spamassassin:Evil", Some(d.join("etc/spamassassin/evil.pm").as_path())),
                ("spamassassin:Mail::SpamAssassin::Plugin::SPF", None),
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
