//! What init itself runs: /etc/inittab, by the rule of the init that reads it
//! (§5). Two inits do. sysvinit's init — Debian's and Ubuntu's sysvinit-core —
//! reads it in 255-byte fgets pieces, four colon-separated fields, an action
//! table matched without regard to case, and /etc/inittab.d/*.tab beside it;
//! BusyBox's init, Alpine's PID 1, reads it through its config parser, the
//! same four fields by a different rule and a different table. Both hand a
//! process holding a shell metacharacter to /bin/sh -c "exec …" and split
//! anything else on blanks themselves. systemd reads none of it, so on a
//! host that boots with systemd every line here is inert, and reported as
//! inert rather than not at all: an inittab on such a host is a leftover or
//! a plant, and either is worth a row.
//!
//! Which init a host has is read from /sbin/init: what it resolves to, and
//! whether that binary carries the strings it would need to do the reading.

use crate::entry::key;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger, name_from_os};
use crate::scan::{Collector, Ctx};

pub struct Inittab;

const INIT: &str = "sbin/init";
const INITTAB: &str = "etc/inittab";
const INITTAB_D: &str = "etc/inittab.d";
const INITSCRIPT: &str = "etc/initscript";
/// Debian's sysvinit-core installs /etc/inittab by copying this in its
/// postinst, so dpkg owns the template and never the file.
const TEMPLATE: &str = "usr/share/sysvinit/inittab";

/// The characters that make either init give a process to /bin/sh.
const SHELL_CHARS: &[u8] = b"~`!$^&*()=|\\{}[];\"'<>?";

/// An init binary is read whole to learn what it reads. systemd's is never
/// read, and the cap sits far above the size of BusyBox or sysvinit.
const INIT_CAP: usize = 16 << 20;

/// sysvinit's action table (init.c) and what each fires on.
const SYSV_ACTIONS: &[(&str, Trigger)] = &[
    ("respawn", Trigger::Boot),
    ("wait", Trigger::Boot),
    ("once", Trigger::Boot),
    ("boot", Trigger::Boot),
    ("bootwait", Trigger::Boot),
    ("powerfail", Trigger::PowerEvent),
    ("powerfailnow", Trigger::PowerEvent),
    ("powerwait", Trigger::PowerEvent),
    ("powerokwait", Trigger::PowerEvent),
    ("ctrlaltdel", Trigger::DeviceEvent),
    ("off", Trigger::Boot),
    ("ondemand", Trigger::Always),
    ("initdefault", Trigger::Boot),
    ("sysinit", Trigger::Boot),
    ("kbrequest", Trigger::DeviceEvent),
];

/// BusyBox's, in its own order and matched exactly.
const BUSYBOX_ACTIONS: &[(&str, Trigger)] = &[
    ("sysinit", Trigger::Boot),
    ("wait", Trigger::Boot),
    ("once", Trigger::Boot),
    ("respawn", Trigger::Boot),
    ("askfirst", Trigger::Boot),
    ("ctrlaltdel", Trigger::DeviceEvent),
    ("shutdown", Trigger::PowerEvent),
    ("restart", Trigger::Always),
];

#[derive(Clone, Copy, PartialEq, Debug)]
enum Init {
    SysV { inittab_d: bool },
    BusyBox,
    Systemd,
    /// Something at /sbin/init that never opens /etc/inittab.
    Other,
    Missing,
}

impl Collector for Inittab {
    fn name(&self) -> &'static str {
        "inittab"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let (init, shown) = which_init(cx);
        let mut out = Vec::new();
        match init {
            Init::BusyBox => busybox(cx, &shown, &mut out),
            // Anything else reads the file by sysvinit's rule, or not at all,
            // and the enablement says which.
            _ => sysv(cx, init, &shown, &mut out),
        }
        out
    }
}

/// What /sbin/init is: by name for systemd, and by the strings in the binary
/// for the two that read inittab, since BusyBox may sit behind any name and
/// sysvinit's binary is simply `init`, as Upstart's was.
fn which_init(cx: &mut Ctx) -> (Init, String) {
    let Ok(resolved) = cx.root.resolve(Path::new(INIT)) else { return (Init::Missing, "none".to_string()) };
    let shown = cx.root.abs(&resolved).display().to_string();
    if resolved.file_name().is_some_and(|n| n == "systemd") {
        return (Init::Systemd, shown);
    }
    let Some(bytes) = cx.read_capped(&resolved, INIT_CAP) else { return (Init::Other, shown) };
    let has = |s: &[u8]| bytes.windows(s.len()).any(|w| w == s);
    let init = if !has(b"/etc/inittab") {
        Init::Other
    } else if has(b"BusyBox") {
        Init::BusyBox
    } else {
        Init::SysV { inittab_d: has(b"inittab.d") }
    };
    (init, shown)
}

/// Enablement from which init this is. A line's own action can still turn
/// it off afterwards.
fn gate(e: &mut Entry, init: Init, shown: &str) {
    e.note("init", shown);
    e.enabled = match init {
        Init::SysV { .. } | Init::BusyBox => Enablement::Enabled,
        Init::Systemd => {
            e.note("not_run", "init is systemd, which ignores inittab");
            Enablement::Disabled
        }
        Init::Other => {
            e.note("not_run", format!("{shown} does not read inittab"));
            Enablement::Disabled
        }
        Init::Missing => {
            e.note("not_run", "no /sbin/init on this root");
            Enablement::Unknown
        }
    };
}

// ------------------------------------------------------------- sysvinit ----

/// The line buffer is 256 bytes and fgets stops at a newline: a longer line
/// arrives as 255-byte pieces, each read as a line of its own.
fn fgets_pieces(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        let mut rest = line;
        while rest.len() > 254 {
            let (piece, more) = rest.split_at(255);
            out.push(piece);
            rest = more;
        }
        out.push(rest);
    }
    out
}

/// What one line said, once read_inittab accepted it.
struct SysvLine<'a> {
    id: &'a [u8],
    runlevels: String,
    action: &'static str,
    trigger: Trigger,
    process: &'a [u8],
}

/// read_inittab's checks, in its order; `ids` is every id accepted so far,
/// which a later line may not repeat unless it is `~~`.
fn sysv_line<'a>(piece: &'a [u8], ids: &mut BTreeSet<Vec<u8>>) -> Option<SysvLine<'a>> {
    let start = piece.iter().position(|b| *b != b' ' && *b != b'\t').unwrap_or(piece.len());
    let p = &piece[start..];
    if p.is_empty() || p[0] == b'#' {
        return None;
    }
    let mut fields = p.splitn(4, |b| *b == b':');
    let id = fields.next()?;
    let (rlevel, action, process) = (fields.next()?, fields.next()?, fields.next()?);
    if id.is_empty() || action.is_empty() || id.len() > 4 || rlevel.len() > 11 || process.len() > 127 || action.len() > 32 {
        return None;
    }
    let (name, trigger) = SYSV_ACTIONS.iter().find(|(n, _)| n.as_bytes().eq_ignore_ascii_case(action))?;
    if id != b"~~" && !ids.insert(id.to_vec()) {
        return None;
    }
    let power = matches!(*name, "powerwait" | "powerfail" | "powerokwait" | "powerfailnow" | "ctrlaltdel");
    let runlevels = match *name {
        "sysinit" => "#".to_string(),
        "boot" | "bootwait" => "*".to_string(),
        _ if rlevel.is_empty() && power => "S0123456789".to_string(),
        _ if rlevel.is_empty() => "0123456789".to_string(),
        _ => String::from_utf8_lossy(rlevel).into_owned(),
    };
    Some(SysvLine { id, runlevels, action: name, trigger: *trigger, process })
}

fn sysv(cx: &mut Ctx, init: Init, shown: &str, out: &mut Vec<Entry>) {
    let template: BTreeSet<Vec<u8>> = match cx.root.stat(TEMPLATE) {
        Ok(m) if m.is_file => cx
            .read(TEMPLATE)
            .map(|b| b.split(|c| *c == b'\n').map(<[u8]>::to_vec).collect())
            .unwrap_or_default(),
        _ => BTreeSet::new(),
    };
    let initscript = cx.root.stat_follow(INITSCRIPT).is_ok_and(|m| m.is_file);
    let inittab_d = matches!(init, Init::SysV { inittab_d: true });

    let mut ids = BTreeSet::new();
    let mut used: BTreeMap<String, u32> = BTreeMap::new();
    let mut default_runlevel: Option<String> = None;
    let mut lines: Vec<Entry> = Vec::new();

    let mut take = |cx: &mut Ctx, rel: &Path, piece: &[u8], from_d: bool, lines: &mut Vec<Entry>| {
        let Some(line) = sysv_line(piece, &mut ids) else { return };
        if line.action == "initdefault" {
            // The highest character names the level; anything outside
            // 0-9 and S makes init ask on the console.
            let lvl = line.runlevels.bytes().max().map(|b| b.to_ascii_uppercase());
            default_runlevel = Some(match lvl {
                Some(b) if b"0123456789S".contains(&b) => (b as char).to_string(),
                _ => "asked on the console".to_string(),
            });
            return;
        }
        let base = String::from_utf8_lossy(line.id).into_owned();
        let n = used.entry(base.clone()).or_insert(0);
        *n += 1;
        let name = if *n == 1 { base } else { format!("{base}-{n}") };
        let mut e = cx.entry(Kind::Inittab, rel, &name);
        name_from_os(&mut e, OsStr::from_bytes(line.id));
        e.trigger = line.trigger;
        e.principal = Some("root".to_string());
        e.note("action", line.action);
        e.note("runlevels", line.runlevels.clone());
        let mut text = line.process;
        if let Some(rest) = text.strip_prefix(b"+") {
            // No utmp/wtmp record for this process; nothing else changes.
            e.note("utmp", "not recorded");
            text = rest;
        }
        command(cx, &mut e, text, true);
        if line.action == "off" {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "action off does nothing");
        }
        if from_d {
            e.note("inittab_d", "one entry per file, the first line that is not a comment");
            if !inittab_d {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "this init does not read inittab.d");
            }
        }
        if template.contains(piece) {
            e.note(key::MATCHES_TEMPLATE, cx.root.abs(TEMPLATE).display().to_string());
        }
        lines.push(e);
    };

    if let Some(bytes) = cx.read(INITTAB) {
        let crlf = bytes.contains(&b'\r');
        for piece in fgets_pieces(&bytes) {
            let before = lines.len();
            take(cx, Path::new(INITTAB), piece, false, &mut lines);
            if crlf && lines.len() > before {
                lines.last_mut().unwrap().note("line_ending", "crlf");
            }
        }
    }

    // Every *.tab in inittab.d, one entry each: the first line that is not
    // blank or a comment, read after everything in inittab.
    let mut tabs: Vec<Vec<u8>> = cx
        .dir(INITTAB_D)
        .into_iter()
        .filter(|e| !e.is_dir && e.name.len() >= 5 && e.name.as_bytes().ends_with(b".tab"))
        .map(|e| e.name.as_bytes().to_vec())
        .collect();
    tabs.sort();
    for name in tabs {
        let rel = Path::new(INITTAB_D).join(OsStr::from_bytes(&name));
        let Some(bytes) = cx.read(&rel) else { continue };
        let first = fgets_pieces(&bytes).into_iter().find(|p| {
            let t = p.iter().position(|b| *b != b' ' && *b != b'\t').unwrap_or(p.len());
            p.len() > t && p[t] != b'#'
        });
        if let Some(piece) = first {
            take(cx, &rel, piece, true, &mut lines);
        }
    }

    for mut e in lines {
        let off = e.enabled == Enablement::Disabled;
        gate(&mut e, init, shown);
        if off {
            e.enabled = Enablement::Disabled;
        }
        if let Some(lvl) = &default_runlevel {
            e.note("default_runlevel", lvl.clone());
        }
        if initscript {
            e.note("initscript", cx.root.abs(INITSCRIPT).display().to_string());
        }
        out.push(e);
    }

    // sysvinit runs /etc/initscript, when it can read one, around every
    // process outside runlevel S: `/bin/sh /etc/initscript <id> <runlevels>
    // <action> <process>`. It is the process, and the file is an entry.
    if initscript {
        let rel = Path::new(INITSCRIPT);
        let mut e = cx.entry(Kind::Inittab, rel, "initscript");
        e.trigger = Trigger::Boot;
        e.principal = Some("root".to_string());
        e.target_path = Some(cx.root.abs(rel));
        e.note("runs_for", "every process init starts outside runlevel S, as /bin/sh /etc/initscript id runlevels action process");
        gate(&mut e, init, shown);
        out.push(e);
    }
}

// -------------------------------------------------------------- BusyBox ----

/// A line ending in a backslash continues on the next, backslash dropped:
/// BusyBox's get_line_with_continuation, which its init and crond share.
pub(crate) fn continued_lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut open = false;
    for line in bytes.split(|b| *b == b'\n') {
        let (body, continues) = match line.strip_suffix(b"\\") {
            Some(b) => (b, true),
            None => (line, false),
        };
        if open {
            out.last_mut().unwrap().extend_from_slice(body);
        } else {
            out.push(body.to_vec());
        }
        open = continues;
    }
    out
}

/// config_read with delimiters `#:`, four tokens, the last greedy, comments
/// anywhere, nothing trimmed or collapsed: `tty:ignored:action:command`.
fn busybox_fields(line: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    if line.is_empty() || line[0] == b'#' {
        return None;
    }
    let mut rest = line;
    let mut tokens: Vec<&[u8]> = Vec::new();
    loop {
        if tokens.len() < 3 {
            let i = rest.iter().position(|b| *b == b'#' || *b == b':').unwrap_or(rest.len());
            tokens.push(&rest[..i]);
            // A comment character ends the line; a colon ends the token.
            rest = if i < rest.len() && rest[i] == b':' { &rest[i + 1..] } else { &[] };
        } else {
            let i = rest.iter().position(|b| *b == b'#').unwrap_or(rest.len());
            tokens.push(&rest[..i]);
            rest = &[];
        }
        if rest.is_empty() || rest[0] == b'#' || tokens.len() >= 4 {
            break;
        }
    }
    if tokens.len() < 4 {
        return None;
    }
    Some((tokens[0], tokens[2], tokens[3]))
}

fn busybox(cx: &mut Ctx, shown: &str, out: &mut Vec<Entry>) {
    let Some(bytes) = cx.read(INITTAB) else { return };
    let crlf = bytes.contains(&b'\r');
    // new_init_action: a line repeating an earlier one's tty and command is
    // the same action, moved and given the later action.
    let mut seen: BTreeMap<(Vec<u8>, Vec<u8>), usize> = BTreeMap::new();
    let mut entries: Vec<Entry> = Vec::new();
    for line in continued_lines(&bytes) {
        let Some((tty, action, process)) = busybox_fields(&line) else { continue };
        let Some((name, trigger)) = BUSYBOX_ACTIONS.iter().find(|(n, _)| n.as_bytes() == action) else { continue };
        if process.is_empty() {
            continue;
        }
        let tty = tty.strip_prefix(b"/dev/").unwrap_or(tty);
        let key = (tty.to_vec(), process.to_vec());
        if let Some(&i) = seen.get(&key) {
            let e = &mut entries[i];
            e.note("action", *name);
            e.trigger = *trigger;
            let n = e.raw.get("duplicate_line").and_then(|v| v.parse::<u32>().ok()).unwrap_or(1) + 1;
            e.note("duplicate_line", n.to_string());
            continue;
        }
        let console = if tty.is_empty() { "console".to_string() } else { String::from_utf8_lossy(tty).into_owned() };
        let mut e = cx.entry(Kind::Inittab, INITTAB, format!("{console}:{}", String::from_utf8_lossy(process)));
        e.trigger = *trigger;
        e.principal = Some("root".to_string());
        e.note("action", *name);
        e.note("tty", if tty.is_empty() { "console".to_string() } else { format!("/dev/{}", String::from_utf8_lossy(tty)) });
        let mut text = process;
        if let Some(rest) = text.strip_prefix(b"-") {
            // Started as a login shell, with a controlling terminal.
            e.note("login_shell", "true");
            text = rest;
        }
        command(cx, &mut e, text, false);
        gate(&mut e, Init::BusyBox, shown);
        if crlf {
            e.note("line_ending", "crlf");
        }
        seen.insert(key, entries.len());
        entries.push(e);
    }
    out.extend(entries);
}

// --------------------------------------------------------------- shared ----

/// What init does with a process field, in both inits: a shell
/// metacharacter anywhere hands the whole text to `/bin/sh -c "exec …"`;
/// otherwise init splits it on blanks itself. sysvinit's splitter also ends
/// the argument list at the first `#`, wherever it falls, and keeps
/// fourteen words.
fn command(cx: &Ctx, e: &mut Entry, text: &[u8], sysv: bool) {
    if text.is_empty() {
        e.note("not_run", "empty process field");
        return;
    }
    let first_word = |t: &[u8]| -> Option<PathBuf> {
        let word = t.split(|b| *b == b' ' || *b == b'\t').find(|w| !w.is_empty())?;
        let word = super::shell_word(word);
        word.starts_with(b"/").then(|| cx.root.abs(Path::new(OsStr::from_bytes(word))))
    };
    if text.iter().any(|b| SHELL_CHARS.contains(b)) {
        e.note("runs_via", "/bin/sh -c \"exec …\"");
        super::cron::set_command(e, text);
        e.target_path = first_word(text);
        return;
    }
    let text = if sysv { text.split(|b| *b == b'#').next().unwrap_or(text) } else { text };
    let words: Vec<&[u8]> = text.split(|b| *b == b' ' || *b == b'\t').filter(|w| !w.is_empty()).collect();
    let kept = if sysv && words.len() > 14 {
        e.note("argv_truncated", format!("init passes fourteen words; the line has {}", words.len()));
        &words[..14]
    } else {
        &words[..]
    };
    if kept.is_empty() {
        e.note("not_run", "empty process field");
        return;
    }
    e.note("argv", "split on blanks by init, no shell");
    super::cron::set_command(e, &kept.join(&b' '));
    e.target_path = first_word(kept[0]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{Options, Scan, run};
    use crate::root::Root;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn tree(tag: &str) -> crate::testing::Tree {
        crate::testing::Tree::new(&format!("inittab-{tag}"))
    }
    fn put(root: &Path, rel: &str, bytes: &[u8]) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, PermissionsExt::from_mode(0o755)).unwrap();
    }
    fn link(root: &Path, target: &str, at: &str) {
        let p = root.join(at);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, p).unwrap();
    }
    /// An init binary that reads inittab, by its strings alone.
    fn sysvinit(root: &Path, inittab_d: bool) {
        let mut body = b"\x7fELF init /etc/inittab ".to_vec();
        if inittab_d {
            body.extend_from_slice(b"/etc/inittab.d ");
        }
        put(root, "sbin/init", &body);
    }
    fn busybox_init(root: &Path) {
        put(root, "bin/busybox", b"\x7fELF BusyBox v1.37.0 multi-call binary /etc/inittab");
        link(root, "/bin/busybox", "sbin/init");
    }
    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Inittab)];
        run(&root, &Options { deep: false }, &collectors)
    }
    fn one<'a>(s: &'a Scan, name: &str) -> &'a Entry {
        let found: Vec<&Entry> = s.entries.iter().filter(|e| e.name == name).collect();
        assert_eq!(found.len(), 1, "expected one entry named {name}: {:?}", s.entries.iter().map(|e| &e.name).collect::<Vec<_>>());
        found[0]
    }
    fn text(e: &Entry) -> String {
        String::from_utf8_lossy(e.command.as_deref().unwrap_or(b"")).into_owned()
    }

    const DEBIAN: &[u8] = b"# /etc/inittab: init(8) configuration.\nid:2:initdefault:\nsi::sysinit:/etc/init.d/rcS\n~~:S:wait:/sbin/sulogin --force\nl2:2:wait:/etc/init.d/rc 2\nz6:6:respawn:/sbin/sulogin --force\nca:12345:ctrlaltdel:/sbin/shutdown -t1 -a -r now\npf::powerwait:/etc/init.d/powerfail start\n1:2345:respawn:/sbin/getty --noclear 38400 tty1\n";

    #[test]
    fn sysvinit_reads_the_file_by_read_inittabs_rule() {
        let d = tree("sysv");
        sysvinit(&d, true);
        put(&d, "sbin/getty", b"#!/bin/sh\n");
        let mut tab = DEBIAN.to_vec();
        tab.extend_from_slice(b"  ev:2:respawn:+/opt/agent -d $HOME  # trailing\n");
        tab.extend_from_slice(b"ar:2:once:/opt/x a b c #d e\n");
        tab.extend_from_slice(b"1:3:respawn:/sbin/getty tty1 # duplicate id\n");
        tab.extend_from_slice(b"xx:2:RESPAWN:/opt/upper\n");
        tab.extend_from_slice(b"of:2:off:/opt/off\n");
        tab.extend_from_slice(b"toolong:2:once:/opt/x\n");
        tab.extend_from_slice(b"nc:2:once\n");
        tab.extend_from_slice(b"bad:2:frobnicate:/opt/x\n");
        tab.extend_from_slice(b"mt:2:once:\n");
        put(&d, "etc/inittab", &tab);
        let s = scan(&d);
        let names: Vec<&str> = s.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(!names.contains(&"id"), "initdefault is not an entry: {names:?}");
        for absent in ["toolong", "nc", "bad"] {
            assert!(!names.contains(&absent), "{absent} was accepted: {names:?}");
        }
        assert_eq!(names.iter().filter(|n| **n == "1").count(), 1, "a duplicate id is skipped");

        let getty = one(&s, "1");
        assert_eq!((getty.enabled, getty.trigger), (Enablement::Enabled, Trigger::Boot));
        assert_eq!(text(getty), "/sbin/getty --noclear 38400 tty1");
        assert_eq!(getty.raw["argv"], "split on blanks by init, no shell");
        assert_eq!(getty.raw["runlevels"], "2345");
        assert_eq!(getty.raw["default_runlevel"], "2");
        assert_eq!(getty.raw["action"], "respawn");
        assert_eq!(getty.target_path, Some(d.join("sbin/getty")));

        let ev = one(&s, "ev");
        assert_eq!(text(ev), "/opt/agent -d $HOME  # trailing", "a $ hands the whole text to sh -c, comment and all");
        assert_eq!(ev.raw["runs_via"], "/bin/sh -c \"exec …\"");
        assert_eq!(ev.raw["utmp"], "not recorded");
        assert_eq!(one(&s, "ar").command.as_deref(), Some(b"/opt/x a b c".as_slice()), "# ends the argument list");
        assert_eq!(one(&s, "xx").raw["action"], "respawn", "actions match without regard to case");
        assert_eq!(one(&s, "of").enabled, Enablement::Disabled);
        assert!(one(&s, "mt").command.is_none());
        assert_eq!(one(&s, "mt").raw["not_run"], "empty process field");

        assert_eq!(one(&s, "si").raw["runlevels"], "#");
        assert_eq!(one(&s, "pf").raw["runlevels"], "S0123456789", "a power action with no runlevels gets S too");
        assert_eq!(one(&s, "pf").trigger, Trigger::PowerEvent);
        assert_eq!(one(&s, "ca").trigger, Trigger::DeviceEvent);
        assert_eq!(one(&s, "~~").raw["runlevels"], "S");
    }

    #[test]
    fn a_long_line_arrives_in_fgets_pieces() {
        let d = tree("fgets");
        sysvinit(&d, false);
        // 255 bytes of id, then the rest of the line reads as a line of its
        // own, and that one parses.
        let mut tab = vec![b'x'; 255];
        tab.extend_from_slice(b"ok:2:once:/opt/second-piece\n");
        put(&d, "etc/inittab", &tab);
        let s = scan(&d);
        assert_eq!(s.entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["ok"]);
    }

    #[test]
    fn inittab_d_holds_one_entry_per_file_when_this_init_reads_it() {
        let d = tree("inittab-d");
        sysvinit(&d, true);
        put(&d, "etc/inittab", b"id:2:initdefault:\nag:2:respawn:/opt/agent\n");
        put(&d, "etc/inittab.d/10-first.tab", b"# comment\n\n  \nsv:2:respawn:/opt/sv\nignored:2:once:/opt/ignored\n");
        put(&d, "etc/inittab.d/20-dup.tab", b"ag:2:once:/opt/other\n");
        put(&d, "etc/inittab.d/notes.txt", b"nt:2:once:/opt/notes\n");
        put(&d, "etc/inittab.d/.tab", b"ht:2:once:/opt/hidden\n");
        let s = scan(&d);
        let names: Vec<&str> = s.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["ag", "sv"], "{names:?}");
        let sv = one(&s, "sv");
        assert_eq!(sv.enabled, Enablement::Enabled);
        assert!(sv.raw.contains_key("inittab_d"));
        assert!(sv.source.ends_with("etc/inittab.d/10-first.tab"));

        sysvinit(&d, false);
        let s = scan(&d);
        assert_eq!(one(&s, "sv").enabled, Enablement::Disabled, "an older init never opens the directory");
        assert_eq!(one(&s, "ag").enabled, Enablement::Enabled);
    }

    #[test]
    fn initscript_wraps_every_process_and_is_an_entry() {
        let d = tree("initscript");
        sysvinit(&d, false);
        put(&d, "etc/inittab", b"1:2345:respawn:/sbin/getty 38400 tty1\n");
        put(&d, "etc/initscript", b"#!/bin/sh\numask 022\neval exec \"$4\"\n");
        let s = scan(&d);
        let script = one(&s, "initscript");
        assert_eq!((script.enabled, script.target_path.clone()), (Enablement::Enabled, Some(d.join("etc/initscript"))));
        assert_eq!(one(&s, "1").raw["initscript"], d.join("etc/initscript").display().to_string());
    }

    #[test]
    fn a_line_the_packaged_template_holds_is_noted() {
        let d = tree("template");
        sysvinit(&d, false);
        put(&d, "usr/share/sysvinit/inittab", DEBIAN);
        let mut tab = DEBIAN.to_vec();
        tab.extend_from_slice(b"bd:2345:respawn:/sbin/getty 38400 tty9\n");
        put(&d, "etc/inittab", &tab);
        let s = scan(&d);
        assert_eq!(one(&s, "1").raw["matches_template"], d.join("usr/share/sysvinit/inittab").display().to_string());
        assert!(!one(&s, "bd").raw.contains_key("matches_template"));
    }

    #[test]
    fn on_a_systemd_host_every_line_is_inert_and_visible() {
        let d = tree("systemd");
        put(&d, "lib/systemd/systemd", b"\x7fELF systemd");
        link(&d, "/lib/systemd/systemd", "sbin/init");
        put(&d, "etc/inittab", b"ev:2:respawn:/opt/agent\n");
        let s = scan(&d);
        let ev = one(&s, "ev");
        assert_eq!(ev.enabled, Enablement::Disabled);
        assert_eq!(ev.raw["not_run"], "init is systemd, which ignores inittab");
        assert!(ev.raw["init"].ends_with("lib/systemd/systemd"));

        put(&d, "sbin/runit-init", b"\x7fELF runit");
        fs::remove_file(d.join("sbin/init")).unwrap();
        link(&d, "runit-init", "sbin/init");
        let s = scan(&d);
        assert_eq!(one(&s, "ev").enabled, Enablement::Disabled);
        assert!(one(&s, "ev").raw["not_run"].ends_with("does not read inittab"));

        fs::remove_file(d.join("sbin/init")).unwrap();
        let s = scan(&d);
        assert_eq!(one(&s, "ev").enabled, Enablement::Unknown);
    }

    #[test]
    fn busybox_reads_the_file_through_config_read() {
        let d = tree("busybox");
        busybox_init(&d);
        put(&d, "sbin/openrc", b"#!/bin/sh\n");
        let tab = b"# /etc/inittab\n\n::sysinit:/sbin/openrc sysinit\n::sysinit:/sbin/openrc boot\n::wait:/sbin/openrc default\ntty1::respawn:/sbin/getty 38400 tty1\n/dev/ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100 # serial\n::ctrlaltdel:/sbin/reboot\n::shutdown:/sbin/openrc shutdown\n::restart:/sbin/init\ntty2::askfirst:-/bin/sh\n::once:/opt/long \\\n  --continued\n::SYSINIT:/opt/upper\n::once:\n::respawn:/opt/wrapped | logger\nbad#tty::respawn:/opt/x\n::once:/opt/three:fields:kept\n::wait:/sbin/openrc default\n";
        put(&d, "etc/inittab", tab);
        let s = scan(&d);
        let names: Vec<&str> = s.entries.iter().map(|e| e.name.as_str()).collect();
        for absent in ["console:/opt/upper", "console:"] {
            assert!(!names.contains(&absent), "{absent} was accepted: {names:?}");
        }
        assert!(!names.iter().any(|n| n.starts_with("bad")), "a # in the tty field ends the line: {names:?}");
        let sysinit = one(&s, "console:/sbin/openrc sysinit");
        assert_eq!((sysinit.enabled, sysinit.trigger), (Enablement::Enabled, Trigger::Boot));
        assert_eq!(sysinit.target_path, Some(d.join("sbin/openrc")));
        assert_eq!(sysinit.raw["tty"], "console");
        let serial = one(&s, "ttyS0:/sbin/getty -L 115200 ttyS0 vt100 ");
        assert_eq!(serial.raw["tty"], "/dev/ttyS0");
        assert_eq!(text(serial), "/sbin/getty -L 115200 ttyS0 vt100", "a # ends the line; blanks are split by init");
        assert_eq!(one(&s, "tty2:-/bin/sh").raw["login_shell"], "true");
        assert_eq!(text(one(&s, "tty2:-/bin/sh")), "/bin/sh");
        assert_eq!(text(one(&s, "console:/opt/long   --continued")), "/opt/long --continued", "a backslash joins the lines");
        assert_eq!(one(&s, "console:/opt/wrapped | logger").raw["runs_via"], "/bin/sh -c \"exec …\"");
        assert_eq!(text(one(&s, "console:/opt/three:fields:kept")), "/opt/three:fields:kept", "the command keeps its colons");
        let default = one(&s, "console:/sbin/openrc default");
        assert_eq!(default.raw["duplicate_line"], "2", "a repeated tty and command is one action");
        assert_eq!(one(&s, "console:/sbin/reboot").trigger, Trigger::DeviceEvent);
        assert_eq!(one(&s, "console:/sbin/openrc shutdown").trigger, Trigger::PowerEvent);
        assert_eq!(one(&s, "console:/sbin/init").trigger, Trigger::Always);
    }

    #[test]
    fn hostile_files_leave_the_collector_complete() {
        let d = tree("hostile");
        sysvinit(&d, true);
        put(&d, "etc/inittab", b":::\n::::::\n\xff\xfe:2:once:/opt/\xff\n\x00:2:once:/opt/nul\n~~:S:wait:/a\n~~:S:wait:/b\n");
        fs::create_dir_all(d.join("etc/inittab.d/dir.tab")).unwrap();
        put(&d, "etc/inittab.d/empty.tab", b"");
        put(&d, "etc/inittab.d/comments.tab", b"# only\n   # this\n");
        let s = scan(&d);
        let status = &s.header.collectors.iter().find(|c| c.name == "inittab").unwrap().status;
        assert!(matches!(status, crate::scan::Status::Complete), "{status:?}");
        assert_eq!(s.entries.iter().filter(|e| e.name.starts_with("~~")).count(), 2, "~~ may repeat");
    }
}
