//! systemd: unit files, their drop-ins, and generators.
//!
//! Three things make this collector different from a directory walk.
//!
//! The search path is walked by directory identity, not by name. On every
//! supported distro /lib is a symlink to /usr/lib, so `lib/systemd/system` and
//! `usr/lib/systemd/system` name one directory; walking both would give every
//! vendor unit two ids that never reconcile in a diff.
//!
//! Presence is not enablement (§6). Without D-Bus the answer comes from
//! resolving the `.wants/` and `.requires/` symlink farms, which is an
//! inference, so every unit carries DegradedEnablement to say so. The D-Bus
//! enrichment pass overwrites both on a live host.
//!
//! Precedence is recorded, not resolved. A unit present in /etc and in
//! /usr/lib is two entries plus the rank and the path of its neighbour, so
//! enrichment can decide which shadows which; the collector does not.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Flag, Kind, Trigger, name_from_os};
use crate::scan::{Collector, Ctx};

pub struct Systemd;

/// The system unit search path with its precedence rank: /etc shadows /run
/// shadows the vendor directories. `lib` and `usr/lib` share rank because on a
/// merged-usr host they are the same directory.
const SYSTEM_PATHS: [(&str, u8); 4] = [
    ("etc/systemd/system", 0),
    ("run/systemd/system", 1),
    ("usr/lib/systemd/system", 2),
    ("lib/systemd/system", 2),
];

const USER_PATHS: [(&str, u8); 4] = [
    ("etc/systemd/user", 0),
    ("run/systemd/user", 1),
    ("usr/lib/systemd/user", 2),
    ("lib/systemd/user", 2),
];

const GENERATOR_PATHS: [&str; 6] = [
    "etc/systemd/system-generators",
    "usr/lib/systemd/system-generators",
    "lib/systemd/system-generators",
    "etc/systemd/user-generators",
    "usr/lib/systemd/user-generators",
    "lib/systemd/user-generators",
];

const UNIT_SUFFIXES: [&str; 4] = [".service", ".timer", ".socket", ".path"];

const EXEC_KEYS: [&str; 6] =
    ["ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload"];

const TIMER_KEYS: [&str; 4] = ["OnCalendar", "OnBootSec", "OnUnitActiveSec", "Persistent"];

/// Sections in which an Exec= line is one systemd would actually run. A line
/// outside them is still reported, annotated, because it is evidence of intent
/// even where the manager ignores it.
const EXEC_SECTIONS: [&str; 5] = ["Service", "Socket", "Mount", "Swap", "Scope"];

/// Units in one scope shadow each other; units in different scopes never do.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Scope {
    System,
    User,
    Home(String),
}

impl Scope {
    fn label(&self) -> String {
        match self {
            Scope::System => "system".to_string(),
            Scope::User => "user".to_string(),
            Scope::Home(who) => format!("user:{who}"),
        }
    }
}

/// A unit file or a drop-in conf located on the search path.
struct Found {
    scope: Scope,
    rank: u8,
    rel: PathBuf,
    file_name: OsString,
    /// The unit this is — or, for a drop-in, the unit it modifies.
    unit: String,
}

/// A symlink inside a `.wants/` or `.requires/` directory.
struct Link {
    scope: Scope,
    rank: u8,
    name: String,
    rel: PathBuf,
}

#[derive(Default)]
struct Walk {
    units: Vec<Found>,
    dropins: Vec<Found>,
    /// Unit name to the symlinks that pull it in, including the template name
    /// an instance symlink resolves to.
    links: BTreeMap<(Scope, String), Vec<PathBuf>>,
    wants: Vec<Link>,
}

impl Collector for Systemd {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();
        let mut w = Walk::default();

        for (p, rank) in SYSTEM_PATHS {
            w.scan(cx, &mut seen, &Scope::System, Path::new(p), rank);
        }
        for (p, rank) in USER_PATHS {
            w.scan(cx, &mut seen, &Scope::User, Path::new(p), rank);
        }
        let homes: Vec<(String, PathBuf)> = cx
            .users
            .iter()
            .map(|u| (u.name.clone(), u.in_home(".config/systemd/user")))
            .collect();
        for (who, dir) in &homes {
            w.scan(cx, &mut seen, &Scope::Home(who.clone()), dir, 0);
        }

        let mut out = w.entries(cx);
        out.extend(generators(cx, &mut seen));
        out
    }
}

impl Walk {
    fn scan(&mut self, cx: &mut Ctx, seen: &mut BTreeSet<(u64, u64)>, scope: &Scope, dir: &Path, rank: u8) {
        match cx.root.dir_identity(dir) {
            Ok(id) => {
                if !seen.insert(id) {
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                cx.note_unreadable(format!("{}: {e}", dir.display()));
                return;
            }
        }

        for ent in cx.dir(dir) {
            let name = ent.name.to_string_lossy().into_owned();
            let rel = dir.join(&ent.name);
            let walkable = ent.is_dir || ent.is_symlink;

            if name.ends_with(".wants") || name.ends_with(".requires") {
                if walkable {
                    self.scan_links(cx, scope, &rel, rank);
                }
            } else if let Some(parent) = name.strip_suffix(".d") {
                if walkable {
                    self.scan_dropins(cx, scope, &rel, parent, rank);
                }
            } else if !ent.is_dir && unit_suffix(&name).is_some() {
                self.units.push(Found { scope: scope.clone(), rank, rel, file_name: ent.name, unit: name });
            }
        }
    }

    /// `multi-user.target.wants/foo.service` is how a unit is enabled on disk.
    fn scan_links(&mut self, cx: &mut Ctx, scope: &Scope, dir: &Path, rank: u8) {
        for ent in cx.dir(dir) {
            let name = ent.name.to_string_lossy().into_owned();
            if unit_suffix(&name).is_none() {
                continue;
            }
            let rel = dir.join(&ent.name);
            let abs = cx.root.abs(&rel);
            let target_base = cx
                .root
                .read_link(&rel)
                .ok()
                .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()));
            self.links.entry((scope.clone(), name.clone())).or_default().push(abs.clone());
            // An instance symlink enables the template it points at, so the
            // template file is reported enabled too.
            if let Some(tb) = &target_base {
                if *tb != name {
                    self.links.entry((scope.clone(), tb.clone())).or_default().push(abs);
                }
            }
            self.wants.push(Link { scope: scope.clone(), rank, name, rel });
        }
    }

    fn scan_dropins(&mut self, cx: &mut Ctx, scope: &Scope, dir: &Path, parent: &str, rank: u8) {
        for ent in cx.dir(dir) {
            let name = ent.name.to_string_lossy().into_owned();
            if ent.is_dir || !name.ends_with(".conf") {
                continue;
            }
            self.dropins.push(Found {
                scope: scope.clone(),
                rank,
                rel: dir.join(&ent.name),
                file_name: ent.name,
                unit: parent.to_string(),
            });
        }
    }

    fn entries(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out: Vec<Entry> = Vec::with_capacity(self.units.len() + self.dropins.len());
        for f in &self.units {
            out.push(self.unit_entry(cx, f));
        }
        self.note_shadowing(&mut out);

        for f in &self.dropins {
            out.push(dropin_entry(cx, f));
        }

        // A name that only a .wants symlink carries is still a unit that runs:
        // an instance of a template, an alias, or a `systemctl link` pointing
        // at a unit file the attacker left outside the search path. The unit
        // file it resolves to is reported separately and is not this entry.
        let present: BTreeSet<(&Scope, &str)> =
            self.units.iter().map(|f| (&f.scope, f.unit.as_str())).collect();
        for l in &self.wants {
            if !present.contains(&(&l.scope, l.name.as_str())) {
                out.push(linked_entry(cx, l));
            }
        }
        out
    }

    /// The search path is walked in precedence order, so each group is already
    /// ordered highest-precedence first.
    fn note_shadowing(&self, out: &mut [Entry]) {
        let mut groups: BTreeMap<(&Scope, &str), Vec<usize>> = BTreeMap::new();
        for (i, f) in self.units.iter().enumerate() {
            groups.entry((&f.scope, f.unit.as_str())).or_default().push(i);
        }
        for idx in groups.into_values().filter(|g| g.len() > 1) {
            for n in 0..idx.len() {
                if n > 0 {
                    let above = out[idx[n - 1]].source.to_string_lossy().into_owned();
                    out[idx[n]].note("shadowed_by", above);
                }
                if n + 1 < idx.len() {
                    let below = out[idx[n + 1]].source.to_string_lossy().into_owned();
                    out[idx[n]].note("shadows", below);
                }
            }
        }
    }

    fn unit_entry(&self, cx: &mut Ctx, f: &Found) -> Entry {
        let suffix = unit_suffix(&f.unit);
        let mut e = cx.entry(kind_for(suffix), &f.rel, f.unit.clone());
        name_from_os(&mut e, &f.file_name);
        e.trigger = trigger_for(suffix);
        e.note("scope", f.scope.label());
        e.note("search_path_rank", f.rank.to_string());
        if let Some(s) = suffix {
            e.note("unit_type", s.trim_start_matches('.'));
        }
        note_template(&mut e, &f.unit, suffix);

        let target = cx
            .root
            .stat(&f.rel)
            .ok()
            .filter(|m| m.is_symlink)
            .and_then(|_| cx.root.read_link(&f.rel).ok());
        let masked = target.as_deref() == Some(Path::new("/dev/null"));

        let facts = if masked { Facts::default() } else { parse_into_facts(cx, &f.rel) };
        fill(cx, &mut e, &facts, &f.scope);

        e.enabled = if masked {
            Enablement::Masked
        } else if let Some(links) = self.enabling_links(f, suffix) {
            let paths: Vec<String> = links.iter().map(|p| p.to_string_lossy().into_owned()).collect();
            e.note("enabled_by", paths.join(", "));
            Enablement::Enabled
        } else if !facts.has_install {
            Enablement::Static
        } else {
            Enablement::Disabled
        };
        e.flag(Flag::DegradedEnablement);
        e
    }

    fn enabling_links(&self, f: &Found, suffix: Option<&str>) -> Option<&Vec<PathBuf>> {
        if let Some(l) = self.links.get(&(f.scope.clone(), f.unit.clone())) {
            return Some(l);
        }
        // An instance is enabled by a link naming its template.
        let (template, instance) = suffix.and_then(|s| template_of(&f.unit, s))?;
        if instance.is_empty() {
            return None;
        }
        self.links.get(&(f.scope.clone(), template))
    }
}

fn dropin_entry(cx: &mut Ctx, f: &Found) -> Entry {
    let suffix = unit_suffix(&f.unit);
    let conf = f.file_name.to_string_lossy().into_owned();
    let mut e = cx.entry(kind_for(suffix), &f.rel, format!("{}.d/{conf}", f.unit));
    name_from_os(&mut e, &f.file_name);
    e.trigger = trigger_for(suffix);
    // A drop-in has no enablement of its own: it applies whenever its unit
    // runs. Its ExecStartPre= runs all the same, which is the point.
    e.enabled = Enablement::NotApplicable;
    e.note("dropin_for", f.unit.clone());
    e.note("scope", f.scope.label());
    e.note("search_path_rank", f.rank.to_string());
    note_template(&mut e, &f.unit, suffix);

    let facts = parse_into_facts(cx, &f.rel);
    fill(cx, &mut e, &facts, &f.scope);
    e
}

fn linked_entry(cx: &mut Ctx, l: &Link) -> Entry {
    let suffix = unit_suffix(&l.name);
    let mut e = cx.entry(kind_for(suffix), &l.rel, l.name.clone());
    e.trigger = trigger_for(suffix);
    e.note("scope", l.scope.label());
    e.note("search_path_rank", l.rank.to_string());
    e.note("enabled_by", cx.root.abs(&l.rel).to_string_lossy().into_owned());
    e.note("from_wants_link", "true");
    note_template(&mut e, &l.name, suffix);

    let facts = parse_into_facts(cx, &l.rel);
    fill(cx, &mut e, &facts, &l.scope);
    e.enabled = Enablement::Enabled;
    e.flag(Flag::DegradedEnablement);
    e
}

fn generators(cx: &mut Ctx, seen: &mut BTreeSet<(u64, u64)>) -> Vec<Entry> {
    let mut out = Vec::new();
    for dir in GENERATOR_PATHS {
        match cx.root.dir_identity(dir) {
            Ok(id) => {
                if !seen.insert(id) {
                    continue;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                cx.note_unreadable(format!("{dir}: {e}"));
                continue;
            }
        }
        let scope = if dir.ends_with("user-generators") { "user" } else { "system" };
        for ent in cx.dir(dir) {
            if ent.is_dir {
                continue;
            }
            let rel = Path::new(dir).join(&ent.name);
            // A generator runs only if it is executable. A dangling link is
            // kept: what it points at is enrichment's problem, not a reason to
            // drop the evidence that something is wired in here.
            let runnable = match cx.root.stat_follow(&rel) {
                Ok(m) => m.mode & 0o111 != 0,
                Err(_) => true,
            };
            if !runnable {
                continue;
            }
            let name = ent.name.to_string_lossy().into_owned();
            let abs = cx.root.abs(&rel);
            let mut e = cx.entry(Kind::SystemdGenerator, &rel, name);
            name_from_os(&mut e, &ent.name);
            e.trigger = Trigger::Boot;
            // Every executable in the directory runs on every manager start;
            // there is nothing to enable or disable.
            e.enabled = Enablement::NotApplicable;
            e.command = Some(abs.clone().into_os_string().into_vec());
            e.target_path = Some(abs);
            e.note("scope", scope);
            out.push(e);
        }
    }
    out
}

// ---------------------------------------------------------------- unit files

struct Directive {
    section: String,
    /// Empty for the record marking a section header.
    key: String,
    value: Vec<u8>,
}

/// Unit files look like INI and are not. Keys repeat and the repetition is
/// meaningful, an empty assignment resets the list, values may contain `=`,
/// and a line ending in a backslash continues into the next. Values stay
/// bytes: an ExecStart= that is not UTF-8 is evidence.
fn parse_unit(bytes: &[u8]) -> Vec<Directive> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut lines = bytes.split(|b| *b == b'\n').peekable();

    while let Some(raw) = lines.next() {
        let mut line = raw;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if !pending.is_empty() {
            line = trim_start(line);
        }
        let t = trim_end(line);
        if t.last() == Some(&b'\\') && lines.peek().is_some() {
            pending.extend_from_slice(trim_end(&t[..t.len() - 1]));
            pending.push(b' ');
            continue;
        }
        pending.extend_from_slice(line);
        let logical = std::mem::take(&mut pending);
        push_directive(&mut out, &mut section, &logical);
    }
    if !pending.is_empty() {
        let logical = std::mem::take(&mut pending);
        push_directive(&mut out, &mut section, &logical);
    }
    out
}

fn push_directive(out: &mut Vec<Directive>, section: &mut String, logical: &[u8]) {
    let t = trim(logical);
    if t.is_empty() || t[0] == b'#' || t[0] == b';' {
        return;
    }
    if t[0] == b'[' && t.len() > 1 && t[t.len() - 1] == b']' {
        *section = String::from_utf8_lossy(&t[1..t.len() - 1]).into_owned();
        out.push(Directive { section: section.clone(), key: String::new(), value: Vec::new() });
        return;
    }
    let Some(eq) = t.iter().position(|b| *b == b'=') else { return };
    let key = trim(&t[..eq]);
    if key.is_empty() {
        return;
    }
    out.push(Directive {
        section: section.clone(),
        key: String::from_utf8_lossy(key).into_owned(),
        value: trim(&t[eq + 1..]).to_vec(),
    });
}

#[derive(Default)]
struct Facts {
    exec: BTreeMap<&'static str, Vec<Vec<u8>>>,
    timer: BTreeMap<&'static str, Vec<Vec<u8>>>,
    env: Vec<(String, String)>,
    env_files: Vec<Vec<u8>>,
    user: Option<Vec<u8>>,
    group: Option<Vec<u8>>,
    unit_type: Option<Vec<u8>>,
    wanted_by: Vec<Vec<u8>>,
    required_by: Vec<Vec<u8>>,
    has_install: bool,
    /// Set when ExecStart= sits in a section where systemd would ignore it.
    exec_section: Option<String>,
}

fn parse_into_facts(cx: &mut Ctx, rel: &Path) -> Facts {
    match read_regular(cx, rel, crate::root::READ_CAP) {
        Some(bytes) => facts(&parse_unit(&bytes)),
        None => Facts::default(),
    }
}

fn facts(ds: &[Directive]) -> Facts {
    let mut f = Facts::default();
    for d in ds {
        if d.section == "Install" {
            f.has_install = true;
        }
        if d.key.is_empty() {
            continue;
        }
        if let Some(k) = EXEC_KEYS.iter().find(|k| **k == d.key) {
            accumulate(f.exec.entry(k).or_default(), &d.value);
            if *k == "ExecStart" && f.exec_section.is_none() && !EXEC_SECTIONS.contains(&d.section.as_str()) {
                f.exec_section = Some(d.section.clone());
            }
            continue;
        }
        if let Some(k) = TIMER_KEYS.iter().find(|k| **k == d.key) {
            accumulate(f.timer.entry(k).or_default(), &d.value);
            continue;
        }
        match d.key.as_str() {
            "User" => f.user = non_empty(&d.value),
            "Group" => f.group = non_empty(&d.value),
            "Type" => f.unit_type = non_empty(&d.value),
            "Environment" => {
                if d.value.is_empty() {
                    f.env.clear();
                } else {
                    f.env.extend(split_env(&d.value));
                }
            }
            "EnvironmentFile" => accumulate(&mut f.env_files, &d.value),
            "WantedBy" if d.section == "Install" => accumulate(&mut f.wanted_by, &d.value),
            "RequiredBy" if d.section == "Install" => accumulate(&mut f.required_by, &d.value),
            _ => {}
        }
    }
    f
}

/// `ExecStart=` with nothing after it resets the list systemd has built so
/// far; a drop-in clearing the parent's command relies on exactly this.
fn accumulate(slot: &mut Vec<Vec<u8>>, value: &[u8]) {
    if value.is_empty() {
        slot.clear();
    } else {
        slot.push(value.to_vec());
    }
}

fn fill(cx: &mut Ctx, e: &mut Entry, f: &Facts, scope: &Scope) {
    for (key, values) in &f.exec {
        for (i, v) in values.iter().enumerate() {
            note_bytes(e, &indexed(&format!("exec.{key}"), i), v);
        }
    }
    if let Some(first) = f.exec.get("ExecStart").and_then(|v| v.first()) {
        if std::str::from_utf8(first).is_err() {
            e.flag(Flag::EncodingAnomaly);
        }
        e.target_path = exec_target(first);
        e.command = Some(first.clone());
    }
    if let Some(s) = &f.exec_section {
        e.note("exec_section", s.clone());
    }

    for (key, values) in &f.timer {
        for (i, v) in values.iter().enumerate() {
            note_bytes(e, &indexed(&format!("timer.{key}"), i), v);
        }
    }
    for (i, v) in f.wanted_by.iter().enumerate() {
        note_bytes(e, &indexed("wanted_by", i), v);
    }
    for (i, v) in f.required_by.iter().enumerate() {
        note_bytes(e, &indexed("required_by", i), v);
    }
    if let Some(t) = &f.unit_type {
        note_bytes(e, "type", t);
    }
    if let Some(g) = &f.group {
        note_bytes(e, "group", g);
    }
    if let Some(u) = &f.user {
        note_bytes(e, "user", u);
        e.principal = Some(String::from_utf8_lossy(u).into_owned());
    } else if let Scope::Home(who) = scope {
        e.principal = Some(who.clone());
    }

    for (k, v) in &f.env {
        e.note(&format!("env.{k}"), v.clone());
    }
    for (i, spec) in f.env_files.iter().enumerate() {
        note_bytes(e, &indexed("env_file", i), spec);
        // A leading `-` means tolerate absence; the path is what follows.
        let path = spec.strip_prefix(b"-").unwrap_or(spec);
        let path = PathBuf::from(OsString::from_vec(path.to_vec()));
        let Some(bytes) = read_regular(cx, &path, 256 * 1024) else { continue };
        for (k, v) in parse_env_file(&bytes) {
            e.note(&format!("env.{k}"), v);
        }
    }
}

/// An `EnvironmentFile=` is shell-ish `KEY=VALUE` lines. It is read because
/// LD_PRELOAD hides there as readily as in an `Environment=` line.
fn parse_env_file(bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' || line[0] == b';' {
            continue;
        }
        let line = line.strip_prefix(b"export ").map(trim_start).unwrap_or(line);
        let Some(eq) = line.iter().position(|b| *b == b'=') else { continue };
        let key = trim(&line[..eq]);
        if key.is_empty() {
            continue;
        }
        let mut value = trim(&line[eq + 1..]);
        if value.len() >= 2 {
            let (first, last) = (value[0], value[value.len() - 1]);
            if (first == b'"' || first == b'\'') && first == last {
                value = &value[1..value.len() - 1];
            }
        }
        out.push((
            String::from_utf8_lossy(key).into_owned(),
            String::from_utf8_lossy(value).into_owned(),
        ));
    }
    out
}

/// `Environment=` carries several assignments on one line, quoted or not.
fn split_env(v: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < v.len() {
        while i < v.len() && v[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= v.len() {
            break;
        }
        let mut tok: Vec<u8> = Vec::new();
        let mut quote = 0u8;
        while i < v.len() {
            let c = v[i];
            if quote != 0 {
                if c == quote {
                    quote = 0;
                } else {
                    tok.push(c);
                }
            } else if c == b'"' || c == b'\'' {
                quote = c;
            } else if c.is_ascii_whitespace() {
                break;
            } else {
                tok.push(c);
            }
            i += 1;
        }
        let Some(eq) = tok.iter().position(|b| *b == b'=') else { continue };
        if eq == 0 {
            continue;
        }
        out.push((
            String::from_utf8_lossy(&tok[..eq]).into_owned(),
            String::from_utf8_lossy(&tok[eq + 1..]).into_owned(),
        ));
    }
    out
}

/// The executable an Exec= line names, where it names one syntactically.
/// systemd allows `-`, `@`, `+`, `!` and `:` prefixes before the path.
fn exec_target(v: &[u8]) -> Option<PathBuf> {
    let mut i = 0;
    while i < v.len() && matches!(v[i], b'-' | b'@' | b'+' | b'!' | b':') {
        i += 1;
    }
    while i < v.len() && v[i].is_ascii_whitespace() {
        i += 1;
    }
    let rest = &v[i..];
    let token: &[u8] = match rest.first() {
        Some(&q @ (b'"' | b'\'')) => {
            let end = rest[1..].iter().position(|b| *b == q)?;
            &rest[1..1 + end]
        }
        _ => {
            let end = rest.iter().position(|b| b.is_ascii_whitespace()).unwrap_or(rest.len());
            &rest[..end]
        }
    };
    if token.first() == Some(&b'/') {
        Some(PathBuf::from(OsString::from_vec(token.to_vec())))
    } else {
        None
    }
}

/// Opening a FIFO blocks, and a unit path can be one. Only regular files, and
/// only through the root's confined resolution, are read.
fn read_regular(cx: &mut Ctx, rel: &Path, cap: usize) -> Option<Vec<u8>> {
    match cx.root.stat_follow(rel) {
        Ok(m) if m.is_file => cx.read_capped(rel, cap),
        _ => None,
    }
}

// ------------------------------------------------------------------- helpers

fn unit_suffix(name: &str) -> Option<&'static str> {
    UNIT_SUFFIXES.iter().copied().find(|s| name.len() > s.len() && name.ends_with(s))
}

fn kind_for(suffix: Option<&str>) -> Kind {
    if suffix == Some(".timer") { Kind::SystemdTimer } else { Kind::SystemdUnit }
}

fn trigger_for(suffix: Option<&str>) -> Trigger {
    if suffix == Some(".timer") { Trigger::Schedule } else { Trigger::Boot }
}

/// `foo@.service` is a template; `foo@bar.service` is an instance of it. The
/// difference is whether anything sits between the `@` and the suffix.
fn template_of(unit: &str, suffix: &str) -> Option<(String, String)> {
    let stem = unit.strip_suffix(suffix)?;
    let at = stem.find('@')?;
    Some((format!("{}@{suffix}", &stem[..at]), stem[at + 1..].to_string()))
}

fn note_template(e: &mut Entry, unit: &str, suffix: Option<&str>) {
    let Some((template, instance)) = suffix.and_then(|s| template_of(unit, s)) else { return };
    if instance.is_empty() {
        e.note("template", "true");
    } else {
        e.note("template_unit", template);
        e.note("instance", instance);
    }
}

fn note_bytes(e: &mut Entry, key: &str, v: &[u8]) {
    if std::str::from_utf8(v).is_err() {
        e.flag(Flag::EncodingAnomaly);
    }
    e.note(key, String::from_utf8_lossy(v));
}

fn indexed(base: &str, i: usize) -> String {
    if i == 0 { base.to_string() } else { format!("{base}.{i}") }
}

fn non_empty(v: &[u8]) -> Option<Vec<u8>> {
    if v.is_empty() { None } else { Some(v.to_vec()) }
}

fn trim(b: &[u8]) -> &[u8] {
    trim_end(trim_start(b))
}

fn trim_start(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    &b[i..]
}

fn trim_end(b: &[u8]) -> &[u8] {
    let i = b.iter().rposition(|c| !c.is_ascii_whitespace()).map_or(0, |i| i + 1);
    &b[..i]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan, Status};

    fn tree(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("unbidden-systemd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write(dir: &Path, rel: &str, body: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
    }

    fn link(dir: &Path, target: &str, rel: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, &p).unwrap();
    }

    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Systemd)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    fn named<'a>(s: &'a Scan, name: &str) -> Vec<&'a Entry> {
        s.entries.iter().filter(|e| e.name == name).collect()
    }

    fn one<'a>(s: &'a Scan, name: &str) -> &'a Entry {
        let found = named(s, name);
        assert_eq!(found.len(), 1, "expected one entry named {name}, got {}", found.len());
        found[0]
    }

    const VENDOR: &[u8] = b"[Unit]\nDescription=v\n[Service]\nExecStart=/usr/sbin/sshd -D\n[Install]\nWantedBy=multi-user.target\n";

    #[test]
    fn merged_usr_reports_each_vendor_unit_once() {
        let dir = tree("merged");
        std::fs::create_dir_all(dir.join("usr/lib/systemd/system")).unwrap();
        // What every supported distro looks like: /lib is /usr/lib.
        std::os::unix::fs::symlink("usr/lib", dir.join("lib")).unwrap();
        write(&dir, "usr/lib/systemd/system/vendor.service", VENDOR);

        let s = scan(&dir);
        let e = one(&s, "vendor.service");
        assert_eq!(e.source, dir.join("usr/lib/systemd/system/vendor.service"));
        assert_eq!(e.command.as_deref(), Some(&b"/usr/sbin/sshd -D"[..]));
        assert_eq!(e.target_path, Some(PathBuf::from("/usr/sbin/sshd")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_split_usr_keeps_two_genuinely_different_directories() {
        let dir = tree("split");
        write(&dir, "lib/systemd/system/old.service", VENDOR);
        write(&dir, "usr/lib/systemd/system/new.service", VENDOR);

        let s = scan(&dir);
        assert_eq!(named(&s, "old.service").len(), 1);
        assert_eq!(named(&s, "new.service").len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn enablement_comes_from_the_symlink_farm_and_says_it_is_inferred() {
        let dir = tree("wants");
        write(&dir, "etc/systemd/system/linked.service", VENDOR);
        write(&dir, "etc/systemd/system/present.service", VENDOR);
        write(&dir, "etc/systemd/system/plumbing.service", b"[Service]\nExecStart=/bin/true\n");
        link(&dir, "../linked.service", "etc/systemd/system/multi-user.target.wants/linked.service");

        let s = scan(&dir);
        let on = one(&s, "linked.service");
        assert_eq!(on.enabled, Enablement::Enabled);
        assert!(on.raw["enabled_by"].ends_with("multi-user.target.wants/linked.service"));
        assert!(on.has_flag(Flag::DegradedEnablement), "inference must be declared as such");

        assert_eq!(one(&s, "present.service").enabled, Enablement::Disabled, "presence is not enablement");
        assert_eq!(one(&s, "plumbing.service").enabled, Enablement::Static, "no [Install] is static");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_unit_linked_to_dev_null_is_masked() {
        let dir = tree("masked");
        std::fs::create_dir_all(dir.join("etc/systemd/system")).unwrap();
        link(&dir, "/dev/null", "etc/systemd/system/telemetry.service");
        // Still masked even if something also wants it.
        link(&dir, "../telemetry.service", "etc/systemd/system/multi-user.target.wants/telemetry.service");

        let s = scan(&dir);
        let e = one(&s, "telemetry.service");
        assert_eq!(e.enabled, Enablement::Masked);
        assert_eq!(e.raw["symlink_target"], "/dev/null");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_unit_in_etc_shadowing_a_vendor_unit_yields_both_entries() {
        let dir = tree("shadow");
        write(&dir, "usr/lib/systemd/system/sshd.service", VENDOR);
        write(&dir, "run/systemd/system/sshd.service", b"[Service]\nExecStart=/tmp/runtime\n");
        write(&dir, "etc/systemd/system/sshd.service", b"[Service]\nExecStart=/tmp/backdoor\n[Install]\nWantedBy=multi-user.target\n");

        let s = scan(&dir);
        let all = named(&s, "sshd.service");
        assert_eq!(all.len(), 3, "every rank is reported, none is resolved away");

        let by_rank: BTreeMap<&str, &Entry> =
            all.iter().map(|e| (e.raw["search_path_rank"].as_str(), *e)).collect();
        assert_eq!(by_rank["0"].source, dir.join("etc/systemd/system/sshd.service"));
        assert_eq!(by_rank["2"].source, dir.join("usr/lib/systemd/system/sshd.service"));
        assert_eq!(by_rank["0"].raw["shadows"], by_rank["1"].source.to_string_lossy());
        assert_eq!(by_rank["1"].raw["shadowed_by"], by_rank["0"].source.to_string_lossy());
        assert_eq!(by_rank["2"].raw["shadowed_by"], by_rank["1"].source.to_string_lossy());
        assert!(!by_rank["2"].raw.contains_key("shadows"));
        // The flag itself belongs to the enrichment pass.
        assert!(all.iter().all(|e| !e.has_flag(Flag::ShadowsVendorUnit)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_drop_in_is_its_own_entry() {
        let dir = tree("dropin");
        write(&dir, "usr/lib/systemd/system/cups.service", VENDOR);
        write(
            &dir,
            "etc/systemd/system/cups.service.d/10-hardening.conf",
            b"[Service]\nExecStartPre=/opt/pwn/stage2\nEnvironment=\"LD_PRELOAD=/dev/shm/x.so\" TZ=UTC\n",
        );

        let s = scan(&dir);
        let e = one(&s, "cups.service.d/10-hardening.conf");
        assert_eq!(e.kind, Kind::SystemdUnit);
        assert_eq!(e.raw["dropin_for"], "cups.service");
        assert_eq!(e.raw["exec.ExecStartPre"], "/opt/pwn/stage2");
        assert_eq!(e.raw["env.LD_PRELOAD"], "/dev/shm/x.so");
        assert_eq!(e.raw["env.TZ"], "UTC");
        assert_eq!(e.enabled, Enablement::NotApplicable);
        // The parent is still reported, unchanged.
        assert_eq!(one(&s, "cups.service").command.as_deref(), Some(&b"/usr/sbin/sshd -D"[..]));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn templates_and_their_instances_are_not_confused() {
        let dir = tree("template");
        write(
            &dir,
            "usr/lib/systemd/system/getty@.service",
            b"[Service]\nExecStart=/sbin/agetty %I\n[Install]\nWantedBy=getty.target\n",
        );
        link(&dir, "/usr/lib/systemd/system/getty@.service", "etc/systemd/system/getty.target.wants/getty@tty1.service");
        write(&dir, "etc/systemd/system/pwn@.service", b"[Service]\nExecStart=/tmp/x %i\n[Install]\nWantedBy=multi-user.target\n");
        link(&dir, "pwn@.service", "etc/systemd/system/pwn@one.service");

        let s = scan(&dir);

        let tmpl = one(&s, "getty@.service");
        assert_eq!(tmpl.raw["template"], "true");
        assert!(!tmpl.raw.contains_key("instance"));
        assert_eq!(tmpl.enabled, Enablement::Enabled, "an instance link enables the template");

        // The instance has no unit file of its own: only the .wants link names it.
        let inst = one(&s, "getty@tty1.service");
        assert_eq!(inst.raw["instance"], "tty1");
        assert_eq!(inst.raw["template_unit"], "getty@.service");
        assert_eq!(inst.raw["from_wants_link"], "true");
        assert_eq!(inst.raw["symlink_target"], "/usr/lib/systemd/system/getty@.service");
        assert_eq!(inst.enabled, Enablement::Enabled);

        // An instantiated symlink sitting in the search path is a unit file,
        // and reading it yields the template's body.
        let sym = one(&s, "pwn@one.service");
        assert_eq!(sym.raw["instance"], "one");
        assert_eq!(sym.command.as_deref(), Some(&b"/tmp/x %i"[..]));
        assert_eq!(one(&s, "pwn@.service").raw["template"], "true");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hostile_unit_files_yield_entries_rather_than_a_panic() {
        let dir = tree("hostile");
        let mut huge = b"[Service]\nExecStart=/bin/sh -c '".to_vec();
        huge.extend(std::iter::repeat_n(b'A', 10 * 1024 * 1024));
        huge.extend_from_slice(b"'\n");
        write(&dir, "etc/systemd/system/huge.service", &huge);

        write(&dir, "etc/systemd/system/mojibake.service", b"[Service]\nExecStart=/usr/bin/\xff\xfe\x00run --go\n");
        // Continuation, repetition and reset, comments, '=' in values, no
        // trailing newline, a section header that never closes.
        write(
            &dir,
            "etc/systemd/system/awkward.service",
            b"# leading comment\n; another\n[Service]\nExecStart=/bin/first\nExecStart=\nExecStart=/bin/second \\\n    --flag=value=with=equals\nEnvironment=A=1\n[Unopened\nUser = daemon \nExecStop=/bin/stop",
        );
        // Neither a unit file nor a directory tree systemd would load.
        write(&dir, "etc/systemd/system/notaunit.txt", b"whatever");
        write(&dir, "etc/systemd/system/.service", b"[Service]\nExecStart=/x\n");

        let s = scan(&dir);
        let status = &s.header.collectors[0];
        assert!(
            !matches!(status.status, Status::Failed { .. }),
            "hostile input must not fail the collector: {:?}",
            status.status
        );

        let huge = one(&s, "huge.service");
        let cmd = huge.command.as_ref().expect("a capped read still yields a command");
        assert!(cmd.len() > 1000 && cmd.len() <= crate::root::READ_CAP);

        let moji = one(&s, "mojibake.service");
        assert!(moji.has_flag(Flag::EncodingAnomaly));
        assert_eq!(moji.command.as_deref(), Some(&b"/usr/bin/\xff\xfe\x00run --go"[..]));
        assert_eq!(moji.target_path, Some(PathBuf::from(OsString::from_vec(b"/usr/bin/\xff\xfe\x00run".to_vec()))));

        let a = one(&s, "awkward.service");
        assert_eq!(a.command.as_deref(), Some(&b"/bin/second --flag=value=with=equals"[..]));
        assert!(!a.raw.contains_key("exec.ExecStart.1"), "an empty ExecStart= resets the list");
        assert_eq!(a.raw["exec.ExecStop"], "/bin/stop", "a file with no final newline still parses");
        assert_eq!(a.principal.as_deref(), Some("daemon"));
        assert_eq!(a.raw["env.A"], "1");

        assert!(named(&s, "notaunit.txt").is_empty());
        assert!(named(&s, ".service").is_empty(), "a bare suffix is not a unit name");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn timers_generators_and_user_units_carry_their_own_facts() {
        let dir = tree("misc");
        write(
            &dir,
            "etc/systemd/system/beacon.timer",
            b"[Timer]\nOnCalendar=*-*-* *:00/5:00\nOnBootSec=30\nOnUnitActiveSec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n",
        );
        write(&dir, "usr/lib/systemd/system-generators/zz-evil", b"#!/bin/sh\n");
        std::fs::set_permissions(
            dir.join("usr/lib/systemd/system-generators/zz-evil"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        write(&dir, "usr/lib/systemd/system-generators/README", b"not executable\n");
        // Merged-usr applies to the generator directories too.
        std::os::unix::fs::symlink("usr/lib", dir.join("lib")).unwrap();

        write(&dir, "etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/bash\n");
        write(
            &dir,
            "home/alice/.config/systemd/user/agent.service",
            b"[Service]\nExecStart=/home/alice/.cache/agent\nEnvironmentFile=/home/alice/.env\n",
        );
        write(&dir, "home/alice/.env", b"# comment\nexport LD_PRELOAD=\"/home/alice/.cache/hook.so\"\nEMPTY=\n");

        let s = scan(&dir);

        let t = one(&s, "beacon.timer");
        assert_eq!(t.kind, Kind::SystemdTimer);
        assert_eq!(t.trigger, Trigger::Schedule);
        assert_eq!(t.raw["timer.OnCalendar"], "*-*-* *:00/5:00");
        assert_eq!(t.raw["timer.Persistent"], "true");
        assert_eq!(t.raw["wanted_by"], "timers.target");

        let g = one(&s, "zz-evil");
        assert_eq!(g.kind, Kind::SystemdGenerator);
        assert_eq!(g.enabled, Enablement::NotApplicable);
        assert_eq!(g.target_path, Some(dir.join("usr/lib/systemd/system-generators/zz-evil")));
        assert!(named(&s, "README").is_empty(), "only executables are generators");

        let u = one(&s, "agent.service");
        assert_eq!(u.raw["scope"], "user:alice");
        assert_eq!(u.principal.as_deref(), Some("alice"), "a user unit runs as its owner");
        assert_eq!(u.raw["env.LD_PRELOAD"], "/home/alice/.cache/hook.so");
        assert!(u.has_flag(Flag::HiddenPath));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
