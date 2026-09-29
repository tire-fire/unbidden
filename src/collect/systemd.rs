//! systemd: unit files, their drop-ins, generators, and the two boot-time
//! configurations beside them: tmpfiles.d, which writes files, and presets,
//! which decide what a package install enables.
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
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use super::{glob_match, replaceable};
use crate::entry::{Enablement, Entry, Flag, Kind, Trigger, name_from_os};
use crate::scan::{Collector, Ctx};

pub struct Systemd;

/// One directory on a unit search path.
struct SearchDir {
    path: &'static str,
    /// Position on the search path, lower first. A unit here shadows a
    /// same-named unit at any higher rank. `lib` and `usr/lib` share one
    /// because on a merged-usr host they are the same directory.
    rank: u8,
    /// Whether a `.wants/` link or an alias here is someone enabling a unit,
    /// as opposed to a package declaring a dependency. systemd reports a
    /// unit wanted only from a vendor directory as static, not enabled.
    admin: bool,
}

const fn dir(path: &'static str, rank: u8, admin: bool) -> SearchDir {
    SearchDir { path, rank, admin }
}

/// The system manager's unit search path, in the order systemd.unit(5) gives
/// it. Generator output is part of it: systemd loads those units like any
/// other, and a generator is itself a persistence mechanism, so what it wrote
/// is enumerated rather than inferred from the generator alone. Note where
/// the three generator directories fall — `generator.early` outranks /etc,
/// and `generator.late` sits below every vendor directory.
const SYSTEM_PATHS: [SearchDir; 13] = [
    dir("etc/systemd/system.control", 0, true),
    dir("run/systemd/system.control", 1, true),
    dir("run/systemd/transient", 2, true),
    dir("run/systemd/generator.early", 3, true),
    dir("etc/systemd/system", 4, true),
    dir("etc/systemd/system.attached", 5, true),
    dir("run/systemd/system", 6, true),
    dir("run/systemd/system.attached", 7, true),
    dir("run/systemd/generator", 8, true),
    dir("usr/local/lib/systemd/system", 9, false),
    dir("usr/lib/systemd/system", 10, false),
    dir("lib/systemd/system", 10, false),
    dir("run/systemd/generator.late", 11, true),
];

/// The user manager's search path outside any home, ranked on the same
/// scale as `HOME_USER_PATHS` so the two can be compared: each account's user
/// manager reads both, interleaved.
const USER_PATHS: [SearchDir; 8] = [
    dir("etc/xdg/systemd/user", 5, true),
    dir("etc/systemd/user", 6, true),
    dir("run/systemd/user", 8, true),
    dir("usr/local/share/systemd/user", 11, false),
    dir("usr/share/systemd/user", 12, false),
    dir("usr/local/lib/systemd/user", 13, false),
    dir("usr/lib/systemd/user", 14, false),
    dir("lib/systemd/user", 14, false),
];

/// The per-account part of the user search path, relative to the home.
/// `~/.config/systemd/user` is where `systemctl --user enable` writes, and
/// `~/.local/share/systemd/user` is where applications install their own
/// units — both writable by the account alone, which is what makes them
/// worth an attacker's attention.
const HOME_USER_PATHS: [SearchDir; 3] = [
    dir(".config/systemd/user.control", 0, true),
    dir(".config/systemd/user", 4, true),
    dir(".local/share/systemd/user", 10, false),
];

/// Every directory systemd.generator(7) says generators are loaded from.
/// Environment generators too (systemd.environment-generator(7)): their
/// output is the environment of everything the manager starts, LD_PRELOAD
/// included.
const GENERATOR_PATHS: [&str; 20] = [
    "run/systemd/system-generators",
    "etc/systemd/system-generators",
    "usr/local/lib/systemd/system-generators",
    "usr/lib/systemd/system-generators",
    "lib/systemd/system-generators",
    "run/systemd/user-generators",
    "etc/systemd/user-generators",
    "usr/local/lib/systemd/user-generators",
    "usr/lib/systemd/user-generators",
    "lib/systemd/user-generators",
    "run/systemd/system-environment-generators",
    "etc/systemd/system-environment-generators",
    "usr/local/lib/systemd/system-environment-generators",
    "usr/lib/systemd/system-environment-generators",
    "lib/systemd/system-environment-generators",
    "run/systemd/user-environment-generators",
    "etc/systemd/user-environment-generators",
    "usr/local/lib/systemd/user-environment-generators",
    "usr/lib/systemd/user-environment-generators",
    "lib/systemd/user-environment-generators",
];

/// tmpfiles.d(5), in the order a same-named file replaces another.
const TMPFILES_PATHS: [&str; 5] =
    ["etc/tmpfiles.d", "run/tmpfiles.d", "usr/local/lib/tmpfiles.d", "usr/lib/tmpfiles.d", "lib/tmpfiles.d"];
const USER_TMPFILES_PATHS: [&str; 2] = ["usr/local/share/user-tmpfiles.d", "usr/share/user-tmpfiles.d"];
const HOME_TMPFILES_PATHS: [&str; 2] = [".config/user-tmpfiles.d", ".local/share/user-tmpfiles.d"];

/// systemd.preset(5).
const PRESET_PATHS: [&str; 5] = [
    "etc/systemd/system-preset",
    "run/systemd/system-preset",
    "usr/local/lib/systemd/system-preset",
    "usr/lib/systemd/system-preset",
    "lib/systemd/system-preset",
];
const USER_PRESET_PATHS: [&str; 5] = [
    "etc/systemd/user-preset",
    "run/systemd/user-preset",
    "usr/local/lib/systemd/user-preset",
    "usr/lib/systemd/user-preset",
    "lib/systemd/user-preset",
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
    /// Found where an administrator, not a package, puts units.
    admin: bool,
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
    /// an instance symlink resolves to, each with whether it sits where an
    /// administrator enables things.
    links: BTreeMap<(Scope, String), Vec<(bool, PathBuf)>>,
    wants: Vec<Link>,
}

impl Collector for Systemd {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();
        let mut w = Walk::default();

        for d in &SYSTEM_PATHS {
            w.scan(cx, &mut seen, &Scope::System, Path::new(d.path), d);
        }
        for d in &USER_PATHS {
            w.scan(cx, &mut seen, &Scope::User, Path::new(d.path), d);
        }
        let homes: Vec<(String, PathBuf, &SearchDir)> = cx
            .users
            .iter()
            .flat_map(|u| HOME_USER_PATHS.iter().map(move |d| (u.name.clone(), u.in_home(d.path), d)))
            .collect();
        for (who, dir, d) in &homes {
            w.scan(cx, &mut seen, &Scope::Home(who.clone()), dir, d);
        }

        let mut out = w.entries(cx);
        out.extend(generators(cx, &mut seen));
        out.extend(power_hooks(cx));
        out.extend(manager_environment(cx));
        out.extend(tmpfiles(cx));
        out.extend(presets(cx, &PRESET_PATHS, &SYSTEM_PATHS, "system"));
        out.extend(presets(cx, &USER_PRESET_PATHS, &USER_PATHS, "user"));
        out
    }
}

impl Walk {
    fn scan(&mut self, cx: &mut Ctx, seen: &mut BTreeSet<(u64, u64)>, scope: &Scope, dir: &Path, at: &SearchDir) {
        let (rank, admin) = (at.rank, at.admin);
        // A search-path directory that is a link is walked under the name it
        // resolves to. Debian ships /etc/xdg/systemd/user as a link to
        // /etc/systemd/user and merged-usr makes /lib one to /usr/lib;
        // walking the link's name would report every unit under a path no
        // administrator uses, and re-key them all in the process (§5).
        // Not for a directory a home links out of it: its account could
        // point ~/.config/systemd/user at /root's, and the walk would then
        // read root's units as theirs (§3).
        if let Some(target) = cx.root.escaping_link(dir) {
            cx.note_left_home(dir, &target);
            return;
        }
        let canonical = match cx.root.stat(dir) {
            Ok(m) if m.is_symlink => cx.root.resolve(dir).ok(),
            _ => None,
        };
        let dir = canonical.as_deref().unwrap_or(dir);
        match cx.root.dir_identity(dir) {
            Ok(id) => {
                if !seen.insert(id) {
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                cx.note_failed(&dir, &e);
                return;
            }
        }

        for ent in cx.dir(dir) {
            let name = ent.name.to_string_lossy().into_owned();
            let rel = dir.join(&ent.name);
            let walkable = ent.is_dir || ent.is_symlink;

            if name.ends_with(".wants") || name.ends_with(".requires") {
                if walkable {
                    self.scan_links(cx, scope, &rel, rank, admin);
                }
            } else if let Some(parent) = name.strip_suffix(".d") {
                if walkable {
                    self.scan_dropins(cx, scope, &rel, parent, rank);
                }
            } else if !ent.is_dir && unit_suffix(&name).is_some() {
                // A unit file in /etc or /run that is a symlink to another
                // unit is an Alias=, and systemd treats the aliased unit as
                // enabled. `systemctl enable gdm` works exactly this way:
                // it writes /etc/systemd/system/display-manager.service.
                if ent.is_symlink && admin {
                    if let Ok(target) = cx.root.read_link(&rel) {
                        if let Some(base) = target.file_name().map(|n| n.to_string_lossy().into_owned()) {
                            if base != name && unit_suffix(&base).is_some() {
                                let abs = cx.root.abs(&rel);
                                self.links.entry((scope.clone(), base)).or_default().push((admin, abs));
                            }
                        }
                    }
                }
                self.units.push(Found { scope: scope.clone(), rank, rel, file_name: ent.name, unit: name, admin });
            }
        }
    }

    /// `multi-user.target.wants/foo.service` is how a unit is enabled on disk.
    fn scan_links(&mut self, cx: &mut Ctx, scope: &Scope, dir: &Path, rank: u8, admin: bool) {
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
            self.links.entry((scope.clone(), name.clone())).or_default().push((admin, abs.clone()));
            // An instance symlink enables the template it points at, so the
            // template file is reported enabled too.
            if let Some(tb) = &target_base {
                if *tb != name {
                    self.links.entry((scope.clone(), tb.clone())).or_default().push((admin, abs));
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
                admin: false,
            });
        }
    }

    fn entries(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out: Vec<Entry> = Vec::with_capacity(self.units.len() + self.dropins.len());
        for f in &self.units {
            out.push(self.unit_entry(cx, f));
        }
        self.note_shadowing(&mut out);
        self.fold_aliases(cx, &mut out);

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

    /// A unit file an administrator's directory holds that is a symlink to
    /// a unit file of another name, itself found in the search path, is
    /// that unit under a second name: the Alias= `systemctl enable` writes,
    /// such as sshd.service for ssh.service. An alias a package ships in the
    /// vendor directories is the package's own file and stays. Its enablement is already on the unit it names; the
    /// link becomes a note there rather than an entry judged as a file no
    /// package owns. An alias to anything else stays an entry of its own.
    fn fold_aliases(&self, cx: &mut Ctx, out: &mut Vec<Entry>) {
        let files: BTreeMap<&Path, usize> = self
            .units
            .iter()
            .enumerate()
            .filter(|(_, f)| !cx.root.stat(&f.rel).is_ok_and(|m| m.is_symlink))
            .map(|(i, f)| (f.rel.as_path(), i))
            .collect();
        let mut folded: BTreeMap<usize, usize> = BTreeMap::new();
        for (i, f) in self.units.iter().enumerate() {
            if !f.admin || !cx.root.stat(&f.rel).is_ok_and(|m| m.is_symlink) {
                continue;
            }
            let Ok(resolved) = cx.root.resolve(&f.rel) else { continue };
            // A link to a template from one of its instances is that
            // instance, a unit of its own, not an alias.
            let template = |u: &str| u.contains("@.");
            if let Some(&j) = files.get(resolved.as_path())
                && self.units[j].unit != f.unit
                && self.units[j].scope == f.scope
                && template(&self.units[j].unit) == template(&f.unit)
            {
                folded.insert(i, j);
            }
        }
        for (&i, &j) in &folded {
            let alias = out[i].source.to_string_lossy().into_owned();
            let merged = match out[j].raw.get("aliases") {
                Some(prev) => format!("{prev}, {alias}"),
                None => alias,
            };
            out[j].note("aliases", merged);
        }
        for i in folded.into_keys().rev() {
            out.remove(i);
        }
    }

    /// Orders each unit name's files by search-path rank and records who
    /// shadows whom. An account's user manager reads its own directories and
    /// the global user ones interleaved, so a unit in a home competes with
    /// the global user units of the same name; the global ones never compete
    /// with each other across accounts.
    fn note_shadowing(&self, out: &mut [Entry]) {
        let mut groups: BTreeMap<(Scope, &str), Vec<usize>> = BTreeMap::new();
        for (i, f) in self.units.iter().enumerate() {
            groups.entry((f.scope.clone(), f.unit.as_str())).or_default().push(i);
        }
        let global_user: BTreeMap<&str, Vec<usize>> = groups
            .iter()
            .filter(|((scope, _), _)| *scope == Scope::User)
            .map(|((_, unit), idx)| (*unit, idx.clone()))
            .collect();
        for ((scope, unit), idx) in groups.iter_mut() {
            if matches!(scope, Scope::Home(_)) {
                if let Some(global) = global_user.get(unit) {
                    idx.extend(global);
                }
            }
        }

        let mut shadows: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
        let mut shadowed_by: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
        for mut idx in groups.into_values().filter(|g| g.len() > 1) {
            idx.sort_by_key(|&i| self.units[i].rank);
            for pair in idx.windows(2) {
                let (above, below) = (pair[0], pair[1]);
                // Two names for one directory share a rank; neither shadows.
                if self.units[above].rank == self.units[below].rank {
                    continue;
                }
                shadows.entry(above).or_default().insert(out[below].source.to_string_lossy().into_owned());
                shadowed_by.entry(below).or_default().insert(out[above].source.to_string_lossy().into_owned());
            }
        }
        for (i, paths) in shadows {
            out[i].note("shadows", paths.into_iter().collect::<Vec<_>>().join(", "));
        }
        for (i, paths) in shadowed_by {
            out[i].note("shadowed_by", paths.into_iter().collect::<Vec<_>>().join(", "));
        }
    }

    fn unit_entry(&self, cx: &mut Ctx, f: &Found) -> Entry {
        let suffix = unit_suffix(&f.unit);
        let mut e = cx.entry(kind_for(suffix), &f.rel, f.unit.clone());
        name_from_os(&mut e, &f.file_name);
        e.trigger = trigger_for(suffix);
        note_scope(cx, &mut e, &f.scope);
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
        // systemd masks a unit with a link to /dev/null and, just the same,
        // with an empty file (`null_or_empty_path`).
        let empty = cx.root.stat_follow(&f.rel).is_ok_and(|m| m.is_file && m.size == 0);
        let masked = empty || target.as_deref() == Some(Path::new("/dev/null"));
        if empty {
            e.note("masked_by", "an empty file");
        }

        let facts = if masked { Facts::default() } else { parse_into_facts(cx, &f.rel) };
        fill(cx, &mut e, &facts, &f.scope);

        e.enabled = if masked {
            Enablement::Masked
        } else {
            let links = self.enabling_links(f, suffix);
            let describe = |want: bool| -> Option<String> {
                let paths: Vec<String> = links?
                    .iter()
                    .filter(|(admin, _)| *admin == want)
                    .map(|(_, p)| p.to_string_lossy().into_owned())
                    .collect();
                (!paths.is_empty()).then(|| paths.join(", "))
            };
            // A .wants link under /usr/lib is a vendor dependency, not an
            // administrator enabling something: systemd reports those units
            // as static. Only a link in /etc or /run is an admin action.
            if let Some(vendor) = describe(false) {
                e.note("pulled_in_by", vendor);
            }
            match describe(true) {
                Some(admin) => {
                    e.note("enabled_by", admin);
                    Enablement::Enabled
                }
                None if !facts.has_install => Enablement::Static,
                None => Enablement::Disabled,
            }
        };
        e.flag(Flag::DegradedEnablement);
        e
    }

    fn enabling_links(&self, f: &Found, suffix: Option<&str>) -> Option<&Vec<(bool, PathBuf)>> {
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
    note_scope(cx, &mut e, &f.scope);
    e.note("search_path_rank", f.rank.to_string());
    note_template(&mut e, &f.unit, suffix);

    let facts = parse_into_facts(cx, &f.rel);
    fill(cx, &mut e, &facts, &f.scope);
    e
}

/// The scope, and for a unit in someone's home the uid whose user manager is
/// entitled to speak for it. D-Bus enrichment believes that manager and no
/// other about the unit, so the uid comes from the account database here
/// rather than from anything the unit file or its owner could set.
fn note_scope(cx: &Ctx, e: &mut Entry, scope: &Scope) {
    e.note("scope", scope.label());
    if let Scope::Home(who) = scope {
        if let Some(uid) = cx.users.iter().find(|u| &u.name == who).and_then(|u| u.uid) {
            e.note("scope_uid", uid.to_string());
        }
    }
}

fn linked_entry(cx: &mut Ctx, l: &Link) -> Entry {
    let suffix = unit_suffix(&l.name);
    let mut e = cx.entry(kind_for(suffix), &l.rel, l.name.clone());
    e.trigger = trigger_for(suffix);
    note_scope(cx, &mut e, &l.scope);
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
                cx.note_failed(&dir, &e);
                continue;
            }
        }
        let scope = if dir.contains("/user-") { "user" } else { "system" };
        for ent in cx.dir(dir) {
            if ent.is_dir {
                continue;
            }
            if hidden_or_backup(&ent.name) {
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
            if dir.ends_with("environment-generators") {
                e.note("generator_type", "environment");
            }
            out.push(e);
        }
    }
    out
}

/// systemd's hidden_or_backup_file: a name it never runs or reads from a
/// directory of executables or drop-ins.
fn hidden_or_backup(name: &std::ffi::OsStr) -> bool {
    let name = name.as_encoded_bytes();
    const SUFFIXES: [&[u8]; 17] = [
        b"rpmnew", b"rpmsave", b"rpmorig", b"dpkg-old", b"dpkg-new", b"dpkg-tmp", b"dpkg-dist", b"dpkg-bak",
        b"dpkg-backup", b"dpkg-remove", b"ucf-new", b"ucf-old", b"ucf-dist", b"swp", b"bak", b"old", b"new",
    ];
    name.starts_with(b".")
        || matches!(name, b"lost+found" | b"aquota.user" | b"aquota.group")
        || name.ends_with(b"~")
        || name.iter().rposition(|b| *b == b'.').is_some_and(|dot| SUFFIXES.contains(&&name[dot + 1..]))
}

/// The one directory each of systemd-sleep and systemd-shutdown runs every
/// executable in, as root: before suspend or hibernation and after resume,
/// with `pre` or `post`; and at the very end of shutdown, after every
/// service has stopped, with `poweroff`, `reboot`, `halt` or `kexec`. The
/// same in systemd 249 through 257. An empty file or a link to /dev/null is
/// masked; a name systemd treats as hidden or a backup is never run.
const POWER_HOOK_DIRS: [(&str, &str); 4] = [
    ("usr/lib/systemd/system-sleep", "sleep"),
    ("lib/systemd/system-sleep", "sleep"),
    ("usr/lib/systemd/system-shutdown", "shutdown"),
    ("lib/systemd/system-shutdown", "shutdown"),
];

fn power_hooks(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();
    for (dir, hook) in POWER_HOOK_DIRS {
        match cx.root.dir_identity(dir) {
            Ok(id) if seen.insert(id) => {}
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                cx.note_failed(dir, &e);
                continue;
            }
        }
        let mut ents = cx.dir(dir);
        ents.sort_by(|a, b| a.name.cmp(&b.name));
        for ent in ents {
            if ent.is_dir || hidden_or_backup(&ent.name) {
                continue;
            }
            let rel = Path::new(dir).join(&ent.name);
            let meta = cx.root.stat_follow(&rel).ok();
            if meta.as_ref().is_some_and(|m| !m.is_file) && !cx.root.read_link(&rel).is_ok_and(|t| t == Path::new("/dev/null")) {
                continue;
            }
            let abs = cx.root.abs(&rel);
            let mut e = cx.entry(Kind::SystemdHook, &rel, format!("{hook}:{}", ent.name.to_string_lossy()));
            name_from_os(&mut e, &ent.name);
            e.trigger = Trigger::PowerEvent;
            e.principal = Some("root".into());
            e.note("hook", hook);
            e.command = Some(abs.clone().into_os_string().into_vec());
            e.target_path = Some(abs);
            e.enabled = match &meta {
                _ if cx.root.read_link(&rel).is_ok_and(|t| t == Path::new("/dev/null")) => Enablement::Masked,
                Some(m) if m.size == 0 => Enablement::Masked,
                Some(m) if m.mode & 0o111 == 0 => {
                    e.note("not_run", "not executable");
                    Enablement::Disabled
                }
                _ => Enablement::Enabled,
            };
            out.push(e);
        }
    }
    out
}

/// The system manager's configuration: `DefaultEnvironment=` sets variables
/// for every service it starts, and `ManagerEnvironment=` for the manager
/// itself and its generators, so an LD_PRELOAD there reaches all of them.
/// Read from system.conf and its drop-ins the way systemd reads them: the
/// drop-ins in system.conf.d under /etc, /run, /usr/local/lib and /usr/lib,
/// a same-named one in an earlier directory replacing a later one, applied
/// after the main file. The main file is /etc/systemd/system.conf up to
/// systemd 255; from 256 the first of the four directories to hold one. The
/// user manager reads user.conf the same way, and then the account's own
/// ~/.config/systemd/user.conf and user.conf.d/*.conf. One entry per
/// assignment line.
fn manager_environment(cx: &mut Ctx) -> Vec<Entry> {
    const CONF_DIRS: [&str; 4] = ["etc/systemd", "run/systemd", "usr/local/lib/systemd", "usr/lib/systemd"];
    let version = systemd_version(cx);
    let mut out = Vec::new();
    for (file, scope) in [("system.conf", "system"), ("user.conf", "user")] {
        // The main files in search order, and whether systemd reads each.
        let mut main_read = false;
        let mut files: Vec<(PathBuf, Option<String>)> = Vec::new();
        for (i, dir) in CONF_DIRS.iter().enumerate() {
            let rel = Path::new(dir).join(file);
            if !cx.root.exists(&rel) {
                continue;
            }
            let why_not = if main_read {
                Some("an earlier main file is read instead".to_string())
            } else if i > 0 {
                match version {
                    Some(v) if v >= 256 => None,
                    Some(v) => Some(format!("systemd {v} reads only /etc/systemd/{file}")),
                    None => Some("read from systemd 256 on; the version here is unknown".to_string()),
                }
            } else {
                None
            };
            main_read |= why_not.is_none();
            files.push((rel, why_not));
        }
        let dropin_dirs: Vec<String> = CONF_DIRS.iter().map(|d| format!("{d}/{file}.d")).collect();
        let dirs: Vec<&str> = dropin_dirs.iter().map(String::as_str).collect();
        for (rel, shadowed_by) in replaceable(cx, &dirs, ".conf") {
            let why = shadowed_by.map(|by| format!("replaced by /{}", by.display()));
            files.push((rel, why));
        }
        let mut files: Vec<(PathBuf, Option<String>, Option<String>)> = files.into_iter().map(|(r, w)| (r, w, None)).collect();
        if scope == "user" {
            for u in cx.users {
                files.push((u.in_home(".config/systemd/user.conf"), None, Some(u.name.clone())));
                let dir = u.in_home(".config/systemd/user.conf.d");
                let mut names: Vec<_> = cx.dir(&dir).into_iter().filter(|e| !e.is_dir && e.name.to_string_lossy().ends_with(".conf")).map(|e| e.name).collect();
                names.sort();
                files.extend(names.into_iter().map(|n| (dir.join(n), None, Some(u.name.clone()))));
            }
        }
        for (rel, why_not, account) in files {
            let Some(bytes) = cx.read_capped(&rel, crate::root::READ_CAP) else { continue };
            for d in parse_unit(&bytes) {
                if d.section != "Manager" || !matches!(d.key.as_str(), "DefaultEnvironment" | "ManagerEnvironment") {
                    continue;
                }
                let name = format!("{}:{}", d.key, String::from_utf8_lossy(&d.value));
                let mut e = cx.entry(Kind::SystemdHook, &rel, name);
                e.trigger = Trigger::Boot;
                e.note("hook", d.key.clone());
                e.note("scope", scope);
                if scope == "system" {
                    e.principal = Some("root".into());
                }
                if let Some(a) = &account {
                    e.principal = Some(a.clone());
                    e.note("scope", "the account's own user manager");
                }
                for (k, v) in split_env(&d.value) {
                    e.note(&format!("env.{k}"), v);
                }
                e.enabled = Enablement::Enabled;
                if let Some(why) = &why_not {
                    e.enabled = Enablement::Disabled;
                    e.note("not_read", why.clone());
                }
                out.push(e);
            }
        }
    }
    out
}

/// systemd's major version, from the name of the shared library every one
/// of its binaries links: libsystemd-shared-252.so, or on Fedora
/// libsystemd-shared-257.9-1.fc42.so.
fn systemd_version(cx: &mut Ctx) -> Option<u32> {
    ["usr/lib/systemd", "usr/lib64/systemd", "lib/systemd"].iter().find_map(|dir| {
        cx.dir(dir).into_iter().find_map(|e| {
            let name = e.name.to_str()?.strip_prefix("libsystemd-shared-")?;
            let digits: String = name.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
    })
}

// ---------------------------------------------------------------- unit files

/// Whitespace-separated fields, at most `n`, and what follows them.
fn fields(line: &[u8], n: usize) -> (Vec<&[u8]>, &[u8]) {
    let mut out = Vec::new();
    let mut rest = line;
    while out.len() < n {
        let s = rest.trim_ascii_start();
        if s.is_empty() {
            rest = s;
            break;
        }
        let end = s.iter().position(u8::is_ascii_whitespace).unwrap_or(s.len());
        out.push(&s[..end]);
        rest = &s[end..];
    }
    (out, rest.trim_ascii())
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn tmpfiles(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    for (rel, by) in replaceable(cx, &TMPFILES_PATHS, ".conf") {
        tmpfiles_file(cx, &rel, by.as_deref(), None, &mut out);
    }
    for (rel, by) in replaceable(cx, &USER_TMPFILES_PATHS, ".conf") {
        tmpfiles_file(cx, &rel, by.as_deref(), None, &mut out);
    }
    // ponytail: an account's own files are reported, but not matched against
    // the global user ones they replace.
    let dirs: Vec<(String, PathBuf)> = cx
        .users
        .iter()
        .flat_map(|u| HOME_TMPFILES_PATHS.iter().map(move |d| (u.name.clone(), u.in_home(d))))
        .collect();
    let mut walked = BTreeSet::new();
    for (who, dir) in dirs {
        if !walked.insert(dir.clone()) {
            continue;
        }
        for ent in cx.dir(&dir) {
            if !ent.is_dir && ent.name.as_encoded_bytes().ends_with(b".conf") {
                tmpfiles_file(cx, &dir.join(&ent.name), None, Some(&who), &mut out);
            }
        }
    }
    out
}

/// One entry per line that puts content somewhere at boot: `w` writes a
/// file (a value under /proc/sys among them), `C` copies one, `L` makes a
/// link, and `f` with an argument, or with `^` from a credential, creates a
/// file with that content. Lines that only make directories, set modes or
/// clean up run nothing and are not listed.
fn tmpfiles_file(cx: &mut Ctx, rel: &Path, shadowed_by: Option<&Path>, principal: Option<&str>, out: &mut Vec<Entry>) {
    let Some(bytes) = cx.read(rel) else { return };
    let mut used: BTreeMap<String, usize> = BTreeMap::new();
    for line in bytes.split(|b| *b == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        // Type, path, mode, user, group, age; the argument is the rest.
        // ponytail: a quoted path holding spaces is split at them; the line
        // is still reported whole under `line`.
        let (f, argument) = fields(line, 6);
        let (Some(ty), Some(path)) = (f.first(), f.get(1)) else { continue };
        let writes = match ty[0] {
            b'w' | b'C' | b'L' => true,
            b'f' | b'F' => !argument.is_empty() || ty.contains(&b'^'),
            _ => false,
        };
        if !writes {
            continue;
        }
        let base = format!("{} {}", lossy(ty), lossy(path));
        let seen = used.entry(base.clone()).or_insert(0);
        *seen += 1;
        let name = if *seen == 1 { base } else { format!("{base}#{seen}") };
        let mut e = cx.entry(Kind::Tmpfiles, rel, name);
        e.trigger = Trigger::Boot;
        e.principal = principal.map(str::to_string);
        e.enabled = if shadowed_by.is_some() { Enablement::Disabled } else { Enablement::Enabled };
        e.note("type", lossy(ty));
        e.note("path", lossy(path));
        if !argument.is_empty() {
            e.note("argument", lossy(argument));
        }
        e.note("line", lossy(line));
        if let Some(by) = shadowed_by {
            e.note("shadowed_by", cx.root.abs(by).display().to_string());
        }
        if std::str::from_utf8(line).is_err() {
            e.flag(Flag::EncodingAnomaly);
        }
        out.push(e);
    }
}

/// One entry per `enable` line, the units a package install or `systemctl
/// preset` would switch on. A named unit found on the search path is the
/// target, so an unpackaged one flags the line through its provenance. The
/// first line whose pattern matches a unit decides it, so an `enable` of one
/// unit after a matching `disable` or `ignore` never applies and is reported
/// off. An `enable` glob is left on: which units it decides depends on what
/// is installed when it is applied.
fn presets(cx: &mut Ctx, dirs: &[&str], units: &[SearchDir], scope: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut decided: Vec<(Vec<u8>, String)> = Vec::new();
    let mut by_rank: Vec<&SearchDir> = units.iter().collect();
    by_rank.sort_by_key(|d| d.rank);
    for (rel, shadowed_by) in replaceable(cx, dirs, ".preset") {
        let Some(bytes) = cx.read(&rel) else { continue };
        let mut used: BTreeMap<String, usize> = BTreeMap::new();
        for line in bytes.split(|b| *b == b'\n') {
            let line = line.trim_ascii();
            if line.is_empty() || line[0] == b'#' || line[0] == b';' {
                continue;
            }
            let (f, instances) = fields(line, 2);
            let (Some(&directive), Some(&pattern)) = (f.first(), f.get(1)) else { continue };
            if !matches!(directive, b"enable" | b"disable" | b"ignore") {
                continue;
            }
            let literal = !pattern.iter().any(|b| b"*?[".contains(b));
            let before = if literal {
                decided.iter().find(|(p, _)| glob_match(p, pattern)).map(|(_, at)| at.clone())
            } else {
                None
            };
            if shadowed_by.is_none() {
                decided.push((pattern.to_vec(), format!("{}: {}", cx.root.abs(&rel).display(), lossy(line))));
            }
            if directive != b"enable" {
                continue;
            }
            let base = format!("enable {}", lossy(pattern));
            let seen = used.entry(base.clone()).or_insert(0);
            *seen += 1;
            let name = if *seen == 1 { base } else { format!("{base}#{seen}") };
            let mut e = cx.entry(Kind::SystemdPreset, &rel, name);
            e.trigger = Trigger::PackageOp;
            e.enabled =
                if shadowed_by.is_some() || before.is_some() { Enablement::Disabled } else { Enablement::Enabled };
            e.note("scope", scope);
            e.note("pattern", lossy(pattern));
            if !instances.is_empty() {
                e.note("instances", lossy(instances));
            }
            if let Some(by) = &shadowed_by {
                e.note("shadowed_by", cx.root.abs(by).display().to_string());
            }
            if let Some(at) = before {
                e.note("decided_by", at);
            }
            if literal {
                let name = std::ffi::OsStr::from_bytes(pattern);
                if let Some(found) = by_rank.iter().map(|d| Path::new(d.path).join(name)).find(|p| cx.root.exists(p)) {
                    e.target_path = Some(cx.root.abs(found));
                }
            }
            if std::str::from_utf8(line).is_err() {
                e.flag(Flag::EncodingAnomaly);
            }
            out.push(e);
        }
    }
    out
}

struct Directive {
    section: String,
    /// Empty for the record marking a section header.
    key: String,
    value: Vec<u8>,
}

/// Unit files look like INI and are not. Keys repeat and the repetition is
/// meaningful, an empty assignment resets the list, values may contain `=`,
/// and a line ending in a backslash continues into the next, past any comment
/// lines between. Values stay
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
        // A comment line is skipped whole, before any continuation is looked
        // for: it neither ends a continued line nor continues into the next
        // (checked with `systemd-analyze verify`).
        if matches!(trim_start(line).first(), Some(b'#' | b';')) {
            continue;
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
    /// Every Condition*= and Assert*= line, key and value as written. An
    /// empty value clears the whole list it belongs to, Condition or Assert
    /// as the case may be, whatever the key: that is how systemd resets them.
    /// Only the path ones can be tested here, but a `|` on one that cannot
    /// still decides whether the triggering ones matter.
    conditions: Vec<(String, Vec<u8>)>,
}

/// Which of a unit's two lists a key belongs to: systemd keeps Conditions,
/// which skip the unit, apart from Asserts, which fail it.
fn condition_list(key: &str) -> &str {
    if key.starts_with("Assert") { "Assert" } else { "Condition" }
}

fn parse_into_facts(cx: &mut Ctx, rel: &Path) -> Facts {
    match cx.read_capped(rel, crate::root::READ_CAP) {
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
            k if k.starts_with("Condition") || k.starts_with("Assert") => {
                if d.value.is_empty() {
                    let list = condition_list(k);
                    f.conditions.retain(|(key, _)| condition_list(key) != list);
                } else {
                    f.conditions.push((k.to_string(), d.value.clone()));
                }
            }
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
    // A unit whose condition does not hold is skipped by systemd however it
    // is enabled: rc-local.service runs only if /etc/rc.local is executable,
    // quotaon.service only if /sbin/quotaon exists. Evaluated here the way
    // systemd evaluates them — `|` marks a triggering condition and `!`
    // negates — so an absent target the unit itself tests for is not an
    // orphan. A `|` line is not required by itself: one of them must hold.
    // Each list is a conjunction of its plain conditions, and of one
    // disjunction: if any are marked `|`, at least one of those must hold too.
    let mut fails = Vec::new();
    for list in ["Condition", "Assert"] {
        let (mut triggers, mut any_holds, mut unknown) = (Vec::new(), false, false);
        for (key, raw) in f.conditions.iter().filter(|(k, _)| condition_list(k) == list) {
            let mut spec = raw.as_slice();
            let triggering = spec.first() == Some(&b'|');
            if triggering {
                spec = &spec[1..];
            }
            let negate = spec.first() == Some(&b'!');
            let path = PathBuf::from(OsString::from_vec(if negate { spec[1..].to_vec() } else { spec.to_vec() }));
            let test = key.trim_start_matches("Condition").trim_start_matches("Assert");
            // The keys whose value is a path this pass can test without running
            // anything: existence, kind, the execute bit, a non-empty file. A
            // glob, a mount point or an encrypted path is left to systemd.
            let holds = match test {
                "PathExists" => cx.root.stat_follow(&path).is_ok(),
                "PathIsDirectory" => cx.root.stat_follow(&path).is_ok_and(|m| m.is_dir),
                "PathIsSymbolicLink" => cx.root.stat(&path).is_ok_and(|m| m.is_symlink),
                "FileNotEmpty" => cx.root.stat_follow(&path).is_ok_and(|m| m.is_file && m.size > 0),
                "FileIsExecutable" => cx.root.stat_follow(&path).is_ok_and(|m| m.is_file && m.mode & 0o111 != 0),
                // Not testable here: it may hold, so nothing is claimed of
                // the unit it sits in unless it is a plain one that fails.
                _ => {
                    unknown |= triggering;
                    continue;
                }
            };
            let ok = holds != negate;
            let shown = format!("{key}={}", String::from_utf8_lossy(raw));
            if triggering {
                any_holds |= ok;
                triggers.push(shown);
            } else if !ok {
                fails.push(shown);
            }
        }
        if !triggers.is_empty() && !any_holds && !unknown {
            fails.push(format!("none of the {} lines marked `|` holds: {}", list, triggers.join(", ")));
        }
    }
    if !fails.is_empty() {
        e.note("condition_fails", fails.join("; "));
        e.note("not_run", format!("a condition of the unit does not hold: {}", fails[0]));
    }
    for (i, spec) in f.env_files.iter().enumerate() {
        note_bytes(e, &indexed("env_file", i), spec);
        // A leading `-` means tolerate absence; the path is what follows.
        let path = spec.strip_prefix(b"-").unwrap_or(spec);
        let path = PathBuf::from(OsString::from_vec(path.to_vec()));
        // A unit in a home belongs to its account, whose user manager reads
        // what that account can read. Root reading whatever path it names
        // would read it on the account's behalf: `EnvironmentFile=` at
        // /etc/mysql/debian.cnf would put root's secrets in the report. Only
        // what lies inside the account's own home is read; the root applies
        // its rule to links and `..` from there.
        if let Scope::Home(who) = scope {
            let inside = cx.users.iter().find(|u| &u.name == who).is_some_and(|u| path.starts_with(&u.home));
            if !inside {
                e.note(&indexed("env_file_skipped", i), "outside the account's home; not read on its behalf");
                continue;
            }
        }
        let Some(bytes) = cx.read_capped(&path, 256 * 1024) else { continue };
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
    fn a_unit_conditioned_on_its_own_absent_target_says_so() {
        let dir = tree("conditions");
        write(&dir, "usr/lib/systemd/system/quotaon.service", b"[Unit]\nConditionPathExists=/sbin/quotaon\n[Service]\nExecStart=/sbin/quotaon -aug\n");
        write(&dir, "usr/lib/systemd/system/rc-local.service", b"[Unit]\nConditionFileIsExecutable=/etc/rc.local\n[Service]\nExecStart=/etc/rc.local start\n");
        write(&dir, "etc/rc.local", b"#!/bin/sh\n");
        write(&dir, "usr/lib/systemd/system/held.service", b"[Unit]\nConditionPathExists=|!/etc/absent\nConditionPathIsDirectory=/etc\nAssertPathExists=/etc/rc.local\n[Service]\nExecStart=/opt/held\n");
        write(&dir, "usr/lib/systemd/system/reset.service", b"[Unit]\nConditionPathExists=/nowhere\nConditionPathExists=\n[Service]\nExecStart=/opt/reset\n");
        let s = scan(&dir);
        let quotaon = one(&s, "quotaon.service");
        assert_eq!(quotaon.raw["condition_fails"], "ConditionPathExists=/sbin/quotaon");
        assert!(quotaon.raw["not_run"].starts_with("a condition of the unit does not hold"));
        let rc_local = one(&s, "rc-local.service");
        assert_eq!(rc_local.raw["condition_fails"], "ConditionFileIsExecutable=/etc/rc.local", "present but not executable");
        assert!(!one(&s, "held.service").raw.contains_key("condition_fails"), "a negated absent path, a directory and a present file all hold");
        assert!(!one(&s, "reset.service").raw.contains_key("condition_fails"), "an empty assignment clears the list");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_comment_neither_ends_nor_continues_a_continued_line() {
        let d = parse_unit(b"[Service]\nExecStart=\\\n# a comment\n; another\n/tmp/evil --x\n# trailing slash \\\nRestart=always\n");
        let get = |k: &str| d.iter().find(|x| x.key == k).map(|x| String::from_utf8_lossy(&x.value).into_owned());
        assert_eq!(get("ExecStart").as_deref(), Some("/tmp/evil --x"));
        assert_eq!(get("Restart").as_deref(), Some("always"), "a comment ending in a backslash swallows nothing");
    }

    #[test]
    fn a_triggering_condition_needs_only_one_of_its_kind_to_hold() {
        let dir = tree("triggers");
        let unit = |lines: &str| format!("[Unit]\n{lines}[Service]\nExecStart=/opt/x\n").into_bytes();
        let w = |name: &str, lines: &str| write(&dir, &format!("usr/lib/systemd/system/{name}.service"), &unit(lines));
        w("none-holds", "ConditionPathExists=|/nowhere\nConditionPathExists=|/nowhere2\n");
        w("one-holds", "ConditionPathExists=|/nowhere\nConditionPathIsDirectory=|/usr\n");
        // A `|` line this pass cannot test may be the one that holds.
        w("untestable", "ConditionPathExists=|/nowhere\nConditionVirtualization=|container\n");
        w("plain-and-trigger", "ConditionPathExists=/nowhere\nConditionPathIsDirectory=|/usr\n");
        // Empty assignment clears the whole Condition list, whatever the key,
        // and leaves the Assert list alone.
        w("reset-all", "ConditionPathExists=/nowhere\nConditionPathIsDirectory=/nowhere2\nConditionVirtualization=\n");
        w("reset-not-asserts", "AssertPathExists=/nowhere\nConditionVirtualization=\n");
        let s = scan(&dir);
        assert!(one(&s, "none-holds.service").raw["condition_fails"].starts_with("none of the Condition lines marked `|` holds"));
        assert!(!one(&s, "one-holds.service").raw.contains_key("condition_fails"));
        assert!(!one(&s, "untestable.service").raw.contains_key("condition_fails"));
        assert_eq!(one(&s, "plain-and-trigger.service").raw["condition_fails"], "ConditionPathExists=/nowhere");
        assert!(!one(&s, "reset-all.service").raw.contains_key("condition_fails"));
        assert_eq!(one(&s, "reset-not-asserts.service").raw["condition_fails"], "AssertPathExists=/nowhere");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_home_cannot_make_root_read_units_it_may_not_or_break_the_scan() {
        let dir = tree("home-escape");
        write(&dir, "etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n");
        std::fs::create_dir_all(dir.join("home/alice/.config/systemd")).unwrap();
        std::fs::create_dir_all(dir.join("home/bob/.config/systemd")).unwrap();
        write(&dir, "srv/secret/user/private.service", b"[Service]\nExecStart=/usr/bin/tool --token=ROOTSECRET\n");
        write(&dir, "srv/secret/file", b"not a directory");
        link(&dir, "/srv/secret/user", "home/alice/.config/systemd/user");
        link(&dir, "/srv/secret/file", "home/bob/.config/systemd/user");
        let s = scan(&dir);
        assert!(s.entries.iter().all(|e| !e.name.contains("private")), "root's unit is not alice's");
        assert!(
            !serde_json::to_string(&s.entries).unwrap().contains("ROOTSECRET"),
            "and its command is not in the report"
        );
        let status = &s.header.collectors[0].status;
        assert!(matches!(status, crate::scan::Status::Complete), "a link out of a home is a limit, not a failure: {status:?}");
        assert!(s.header.collectors[0].truncated.iter().any(|t| t.contains("alice") && t.contains("not followed")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_home_unit_reads_only_environment_files_inside_its_home() {
        let dir = tree("env-file");
        write(&dir, "etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/sh\n");
        write(&dir, "etc/mysql/debian.cnf", b"password=ROOTSECRET\n");
        write(&dir, "home/alice/env", b"LD_PRELOAD=/tmp/x.so\n");
        let unit = |env: &str| format!("[Service]\nEnvironmentFile={env}\nExecStart=/usr/bin/tool\n");
        write(&dir, "home/alice/.config/systemd/user/theirs.service", unit("/etc/mysql/debian.cnf").as_bytes());
        write(&dir, "home/alice/.config/systemd/user/mine.service", unit("/home/alice/env").as_bytes());
        write(&dir, "home/alice/.config/systemd/user/dots.service", unit("/home/alice/../../etc/mysql/debian.cnf").as_bytes());
        write(&dir, "etc/systemd/system/admin.service", unit("/etc/mysql/debian.cnf").as_bytes());
        let s = scan(&dir);
        let theirs = one(&s, "theirs.service");
        assert!(!theirs.raw.keys().any(|k| k.starts_with("env.")), "{:?}", theirs.raw);
        assert!(theirs.raw.keys().any(|k| k.starts_with("env_file_skipped")), "the skip is on the entry: {:?}", theirs.raw);
        assert_eq!(one(&s, "mine.service").raw["env.LD_PRELOAD"], "/tmp/x.so");
        assert!(!one(&s, "dots.service").raw.keys().any(|k| k.starts_with("env.")), "`..` out of the home is refused too");
        assert_eq!(one(&s, "admin.service").raw["env.password"], "ROOTSECRET", "an administrator's unit reads what it names");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sleep_and_shutdown_hooks_run_as_systemd_runs_them() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tree("power");
        let exe = |dir: &Path, rel: &str, body: &[u8], mode: u32| {
            write(dir, rel, body);
            std::fs::set_permissions(dir.join(rel), std::fs::Permissions::from_mode(mode)).unwrap();
        };
        exe(&dir, "usr/lib/systemd/system-sleep/50-beacon", b"#!/bin/sh\n", 0o755);
        exe(&dir, "usr/lib/systemd/system-sleep/inert", b"#!/bin/sh\n", 0o644);
        exe(&dir, "usr/lib/systemd/system-sleep/old.dpkg-old", b"#!/bin/sh\n", 0o755);
        exe(&dir, "usr/lib/systemd/system-sleep/.hidden", b"#!/bin/sh\n", 0o755);
        exe(&dir, "usr/lib/systemd/system-sleep/emptied", b"", 0o755);
        exe(&dir, "usr/lib/systemd/system-shutdown/wipe", b"#!/bin/sh\n", 0o755);
        link(&dir, "/dev/null", "usr/lib/systemd/system-shutdown/masked");
        std::os::unix::fs::symlink("usr/lib", dir.join("lib")).unwrap();
        let s = scan(&dir);
        let mut names: Vec<(&str, Enablement)> =
            s.entries.iter().filter(|e| e.kind == Kind::SystemdHook).map(|e| (e.name.as_str(), e.enabled)).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                ("shutdown:masked", Enablement::Masked),
                ("shutdown:wipe", Enablement::Enabled),
                ("sleep:50-beacon", Enablement::Enabled),
                ("sleep:emptied", Enablement::Masked),
                ("sleep:inert", Enablement::Disabled),
            ],
            "hidden and backup names never run; /lib is /usr/lib, walked once"
        );
        let beacon = one(&s, "sleep:50-beacon");
        assert_eq!((beacon.trigger, beacon.principal.as_deref()), (Trigger::PowerEvent, Some("root")));
        assert_eq!(beacon.target_path, Some(dir.join("usr/lib/systemd/system-sleep/50-beacon")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn default_environment_is_read_from_the_files_systemd_reads() {
        let dir = tree("manager-env");
        write(&dir, "usr/lib/systemd/libsystemd-shared-255.so", b"");
        write(&dir, "etc/systemd/system.conf", b"[Manager]\n#DefaultEnvironment=A=commented\nDefaultEnvironment=\"LD_PRELOAD=/tmp/x.so\" LANG=C\n");
        write(&dir, "usr/lib/systemd/system.conf", b"[Manager]\nDefaultEnvironment=VENDOR=1\n");
        write(&dir, "etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/sh\n");
        write(&dir, "home/alice/.config/systemd/user.conf", b"[Manager]\nDefaultEnvironment=LD_PRELOAD=/tmp/u.so\n");
        write(&dir, "home/alice/.config/systemd/user.conf.d/10.conf", b"[Manager]\nManagerEnvironment=NODE_OPTIONS=-r/tmp/n\n");
        write(&dir, "usr/lib/systemd/system.conf.d/10-v.conf", b"[Manager]\nManagerEnvironment=V=1\n");
        write(&dir, "etc/systemd/system.conf.d/10-v.conf", b"[Manager]\nDefaultEnvironment=E=1\n");
        write(&dir, "etc/systemd/user.conf", b"[Manager]\nDefaultEnvironment=PERL5OPT=-Mhook\n[Other]\nDefaultEnvironment=NOT=1\n");
        let s = scan(&dir);
        let hooks: Vec<&Entry> = s.entries.iter().filter(|e| e.kind == Kind::SystemdHook).collect();
        let by = |name: &str| *hooks.iter().find(|e| e.name == name).unwrap_or_else(|| panic!("no {name}"));
        let main = by("DefaultEnvironment:\"LD_PRELOAD=/tmp/x.so\" LANG=C");
        assert_eq!((main.enabled, main.raw["env.LD_PRELOAD"].as_str(), main.raw["env.LANG"].as_str()), (Enablement::Enabled, "/tmp/x.so", "C"));
        let vendor = by("DefaultEnvironment:VENDOR=1");
        assert_eq!(vendor.enabled, Enablement::Disabled);
        assert_eq!(vendor.raw["not_read"], "an earlier main file is read instead");
        assert_eq!(by("ManagerEnvironment:V=1").raw["not_read"], "replaced by /etc/systemd/system.conf.d/10-v.conf");
        assert_eq!(by("DefaultEnvironment:E=1").enabled, Enablement::Enabled);
        assert_eq!(by("DefaultEnvironment:PERL5OPT=-Mhook").raw["scope"], "user");
        let mine = by("DefaultEnvironment:LD_PRELOAD=/tmp/u.so");
        assert_eq!((mine.principal.as_deref(), mine.raw["scope"].as_str()), (Some("alice"), "the account's own user manager"));
        assert_eq!(by("ManagerEnvironment:NODE_OPTIONS=-r/tmp/n").principal.as_deref(), Some("alice"), "the account's drop-ins too");
        assert_eq!(hooks.len(), 7, "a commented line and another section are not settings");

        // Before 256 a main file outside /etc is never read, earlier one or not.
        std::fs::remove_file(dir.join("etc/systemd/system.conf")).unwrap();
        let s = scan(&dir);
        let vendor = s.entries.iter().find(|e| e.name == "DefaultEnvironment:VENDOR=1").unwrap();
        assert_eq!(vendor.raw["not_read"], "systemd 255 reads only /etc/systemd/system.conf");
        std::fs::remove_file(dir.join("usr/lib/systemd/libsystemd-shared-255.so")).unwrap();
        write(&dir, "usr/lib/systemd/libsystemd-shared-257.9-1.fc42.so", b"");
        let s = scan(&dir);
        assert_eq!(s.entries.iter().find(|e| e.name == "DefaultEnvironment:VENDOR=1").unwrap().enabled, Enablement::Enabled);
        std::fs::remove_dir_all(&dir).unwrap();
    }

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
    fn an_alias_is_a_second_name_for_the_unit_not_a_file_of_its_own() {
        let dir = tree("alias");
        write(&dir, "usr/lib/systemd/system/ssh.service", b"[Service]\nExecStart=/usr/sbin/sshd -D\n[Install]\nWantedBy=multi-user.target\nAlias=sshd.service\n");
        link(&dir, "/usr/lib/systemd/system/ssh.service", "etc/systemd/system/sshd.service");
        // A link of another name to a unit outside the search path is not an
        // alias of anything reported, and stays.
        write(&dir, "opt/elsewhere/beacon.service", b"[Service]\nExecStart=/opt/b\n");
        link(&dir, "/opt/elsewhere/beacon.service", "etc/systemd/system/innocent.service");
        // A packaged alias in the vendor directory is the package's file.
        write(&dir, "usr/lib/systemd/system/getty@.service", b"[Service]\nExecStart=/sbin/agetty %I\n");
        link(&dir, "getty@.service", "usr/lib/systemd/system/autovt@.service");

        let s = scan(&dir);
        assert!(s.entries.iter().all(|e| e.name != "sshd.service"), "the alias folds into ssh.service");
        let ssh = one(&s, "ssh.service");
        assert!(ssh.raw["aliases"].ends_with("etc/systemd/system/sshd.service"));
        assert_eq!(ssh.enabled, Enablement::Enabled, "an alias enables the unit it names");
        one(&s, "innocent.service");
        one(&s, "autovt@.service");
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
    fn an_empty_unit_file_masks_like_a_link_to_dev_null() {
        let dir = tree("masked-empty");
        write(&dir, "usr/lib/systemd/system/telemetry.service", b"[Service]\nExecStart=/usr/bin/telemetry\n[Install]\nWantedBy=multi-user.target\n");
        write(&dir, "etc/systemd/system/telemetry.service", b"");
        let s = scan(&dir);
        let by_path: BTreeMap<bool, &Entry> = named(&s, "telemetry.service").into_iter().map(|e| (e.source.starts_with(dir.join("etc")), e)).collect();
        assert_eq!(by_path[&true].enabled, Enablement::Masked);
        assert_eq!(by_path[&true].raw["masked_by"], "an empty file");
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
        let (etc, run, vendor) = (by_rank["4"], by_rank["6"], by_rank["10"]);
        assert_eq!(etc.source, dir.join("etc/systemd/system/sshd.service"));
        assert_eq!(run.source, dir.join("run/systemd/system/sshd.service"));
        assert_eq!(vendor.source, dir.join("usr/lib/systemd/system/sshd.service"));
        assert_eq!(etc.raw["shadows"], run.source.to_string_lossy());
        assert_eq!(run.raw["shadowed_by"], etc.source.to_string_lossy());
        assert_eq!(vendor.raw["shadowed_by"], run.source.to_string_lossy());
        assert!(!vendor.raw.contains_key("shadows"));
        // The flag itself belongs to the enrichment pass.
        assert!(all.iter().all(|e| !e.has_flag(Flag::ShadowsVendorUnit)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn precedence_follows_the_search_path_systemd_actually_uses() {
        // generator.early outranks /etc, generator.late sits below every
        // vendor directory, and /usr/local/lib is a search-path directory in
        // its own right between /run and /usr/lib.
        let dir = tree("order");
        write(&dir, "run/systemd/generator.early/a.service", b"[Service]\nExecStart=/bin/early\n");
        write(&dir, "etc/systemd/system/a.service", b"[Service]\nExecStart=/bin/etc\n");
        write(&dir, "usr/lib/systemd/system/b.service", VENDOR);
        write(&dir, "run/systemd/generator.late/b.service", b"[Service]\nExecStart=/bin/late\n");
        write(&dir, "usr/local/lib/systemd/system/c.service", b"[Service]\nExecStart=/opt/c\n[Install]\nWantedBy=multi-user.target\n");
        write(&dir, "usr/lib/systemd/system/c.service", VENDOR);

        let s = scan(&dir);
        let src = |e: &Entry| e.source.strip_prefix(&dir).unwrap().to_string_lossy().into_owned();
        let find = |name: &str, at: &str| {
            named(&s, name).into_iter().find(|e| src(e) == at).unwrap_or_else(|| panic!("{at} not reported"))
        };

        let early = find("a.service", "run/systemd/generator.early/a.service");
        assert!(early.raw["shadows"].ends_with("etc/systemd/system/a.service"), "{:?}", early.raw);
        let late = find("b.service", "run/systemd/generator.late/b.service");
        assert!(late.raw["shadowed_by"].ends_with("usr/lib/systemd/system/b.service"), "{:?}", late.raw);
        assert!(!late.raw.contains_key("shadows"));

        let local = find("c.service", "usr/local/lib/systemd/system/c.service");
        assert!(local.raw["shadows"].ends_with("usr/lib/systemd/system/c.service"));
        assert_eq!(local.command.as_deref(), Some(&b"/opt/c"[..]));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_unit_in_a_home_overrides_the_global_user_unit_of_the_same_name() {
        // Each account's user manager reads ~/.config/systemd/user before
        // /etc/systemd/user and /usr/lib/systemd/user, so dropping a unit
        // there replaces the packaged one for that account.
        let dir = tree("homeorder");
        write(&dir, "etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n");
        write(&dir, "usr/lib/systemd/user/pipewire.service", VENDOR);
        write(&dir, "home/alice/.config/systemd/user/pipewire.service", b"[Service]\nExecStart=/tmp/x\n");
        write(&dir, "home/bob/.local/share/systemd/user/pipewire.service", b"[Service]\nExecStart=/tmp/y\n");
        write(&dir, "etc/systemd/user/pipewire.service", b"[Service]\nExecStart=/opt/admin\n");

        let s = scan(&dir);
        let all = named(&s, "pipewire.service");
        assert_eq!(all.len(), 4);
        let at = |p: &str| *all.iter().find(|e| e.source.ends_with(p)).unwrap();

        let alice = at("home/alice/.config/systemd/user/pipewire.service");
        assert!(alice.raw["shadows"].ends_with("etc/systemd/user/pipewire.service"), "{:?}", alice.raw);
        // The only manager D-Bus enrichment may believe about this file.
        assert_eq!(alice.raw["scope_uid"], "1000");
        assert!(!at("etc/systemd/user/pipewire.service").raw.contains_key("scope_uid"));
        // ~/.local/share ranks below /etc/systemd/user: bob's copy is itself
        // overridden, and overrides only the vendor one.
        let bob = at("home/bob/.local/share/systemd/user/pipewire.service");
        assert!(bob.raw["shadowed_by"].ends_with("etc/systemd/user/pipewire.service"), "{:?}", bob.raw);
        assert!(bob.raw["shadows"].ends_with("usr/lib/systemd/user/pipewire.service"));
        let admin = at("etc/systemd/user/pipewire.service");
        assert!(admin.raw["shadowed_by"].contains("home/alice"), "{:?}", admin.raw);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_search_directory_that_is_a_link_is_walked_under_the_name_it_resolves_to() {
        // Debian ships /etc/xdg/systemd/user -> ../../systemd/user. Walked
        // under the link's name, every /etc/systemd/user unit was reported
        // somewhere no administrator looks, took a new id, and read as
        // world-writable because a symlink's own mode is 0777.
        let dir = tree("xdglink");
        write(&dir, "etc/systemd/user/pipewire.service", VENDOR);
        std::fs::create_dir_all(dir.join("etc/xdg/systemd")).unwrap();
        link(&dir, "../../systemd/user", "etc/xdg/systemd/user");

        let s = scan(&dir);
        let e = one(&s, "pipewire.service");
        assert_eq!(e.source, dir.join("etc/systemd/user/pipewire.service"));
        assert_eq!(e.id, crate::entry::entry_id(Kind::SystemdUnit, Path::new("etc/systemd/user/pipewire.service"), "pipewire.service"));
        assert!(!e.has_flag(Flag::WorldWritable));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_unit_in_a_home_search_directory_is_where_units_belong() {
        // Both per-account directories are on the user manager's search
        // path. Flagging every unit found there as non-standard would bury
        // the one that is actually out of place.
        let dir = tree("homeloc");
        write(&dir, "etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/sh\n");
        write(&dir, "home/alice/.config/systemd/user/sync.service", b"[Service]\nExecStart=/usr/bin/true\n");
        write(&dir, "home/alice/.local/share/systemd/user/app.service", b"[Service]\nExecStart=/usr/bin/true\n");
        write(&dir, "home/alice/elsewhere/rogue.service", b"[Service]\nExecStart=/usr/bin/true\n");
        link(&dir, "/home/alice/elsewhere/rogue.service", "home/alice/.config/systemd/user/rogue.service");

        let root = Root::at(&dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Systemd)];
        let mut s = crate::scan::run(&root, &Options { deep: false }, &collectors);
        crate::enrich::enrich(&root, &mut s);
        for name in ["sync.service", "app.service"] {
            assert!(!one(&s, name).has_flag(Flag::NonStandardLocation), "{name}");
        }
        assert!(one(&s, "rogue.service").has_flag(Flag::NonStandardLocation));
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
        // ~/.config/systemd/user is the documented location for user units.
        assert!(!u.has_flag(Flag::HiddenPath));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_environment_generator_is_a_generator_that_says_so() {
        let dir = tree("envgen");
        write(&dir, "etc/systemd/system-environment-generators/10-preload", b"#!/bin/sh\necho LD_PRELOAD=/tmp/x.so\n");
        write(&dir, "usr/local/lib/systemd/user-environment-generators/20-x", b"#!/bin/sh\n");
        for f in ["etc/systemd/system-environment-generators/10-preload", "usr/local/lib/systemd/user-environment-generators/20-x"] {
            std::fs::set_permissions(dir.join(f), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        }
        let s = scan(&dir);
        let sys = one(&s, "10-preload");
        assert_eq!(sys.kind, Kind::SystemdGenerator);
        assert_eq!(sys.raw["generator_type"], "environment");
        assert_eq!(sys.raw["scope"], "system");
        assert_eq!(one(&s, "20-x").raw["scope"], "user");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tmpfiles_lines_that_write_are_listed_and_a_replaced_file_is_off() {
        let dir = tree("tmpfiles");
        write(
            &dir,
            "etc/tmpfiles.d/evil.conf",
            b"# comment\n\
              w /proc/sys/kernel/core_pattern - - - - |/tmp/x %p\n\
              L+ /etc/systemd/system/multi-user.target.wants/x.service - - - - /tmp/x.service\n\
              d /run/x 0755 root root -\n\
              f /var/log/empty 0644 root root -\n\
              f^ /root/.ssh/authorized_keys 0600 root root - ssh.authorized_keys.root\n",
        );
        write(&dir, "etc/tmpfiles.d/same.conf", b"C /root/.bashrc - - - - /etc/skel/.bashrc\n");
        write(&dir, "usr/lib/tmpfiles.d/same.conf", b"C /root/.profile - - - - /usr/share/x\n");
        let s = scan(&dir);
        let kinds: Vec<_> = s.entries.iter().filter(|e| e.kind == Kind::Tmpfiles).map(|e| e.name.as_str()).collect();
        assert_eq!(kinds.len(), 5, "{kinds:?}");
        let core = one(&s, "w /proc/sys/kernel/core_pattern");
        assert_eq!(core.raw["argument"], "|/tmp/x %p");
        assert_eq!(core.trigger, Trigger::Boot);
        assert_eq!(one(&s, "L+ /etc/systemd/system/multi-user.target.wants/x.service").raw["argument"], "/tmp/x.service");
        one(&s, "f^ /root/.ssh/authorized_keys");
        assert!(named(&s, "f /var/log/empty").is_empty(), "an empty file writes nothing");
        assert!(named(&s, "d /run/x").is_empty());
        assert_eq!(one(&s, "C /root/.bashrc").enabled, Enablement::Enabled);
        let vendor = one(&s, "C /root/.profile");
        assert_eq!(vendor.enabled, Enablement::Disabled, "tmpfiles never reads the replaced file");
        assert!(vendor.raw["shadowed_by"].ends_with("etc/tmpfiles.d/same.conf"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_preset_enable_names_its_unit_and_the_first_matching_line_decides() {
        let dir = tree("preset");
        write(&dir, "etc/systemd/system/evil.service", VENDOR);
        write(&dir, "usr/lib/systemd/system/sshd.service", VENDOR);
        write(&dir, "usr/lib/systemd/system/getty@.service", VENDOR);
        write(&dir, "etc/systemd/system-preset/10-x.preset", b"enable evil.service\ndisable sshd.service\n");
        write(
            &dir,
            "usr/lib/systemd/system-preset/90-default.preset",
            b"# vendor\nenable sshd.service\nenable getty@.service tty1 tty2\nenable foo-*.service\ndisable *\n",
        );
        write(&dir, "usr/lib/systemd/system-preset/10-x.preset", b"enable replaced.service\n");
        let s = scan(&dir);
        let evil = one(&s, "enable evil.service");
        assert_eq!(evil.kind, Kind::SystemdPreset);
        assert_eq!(evil.trigger, Trigger::PackageOp);
        assert_eq!(evil.enabled, Enablement::Enabled);
        assert_eq!(evil.target_path, Some(dir.join("etc/systemd/system/evil.service")));
        let sshd = one(&s, "enable sshd.service");
        assert_eq!(sshd.enabled, Enablement::Disabled, "an earlier disable decided it");
        assert!(sshd.raw["decided_by"].ends_with("10-x.preset: disable sshd.service"));
        assert_eq!(sshd.target_path, Some(dir.join("usr/lib/systemd/system/sshd.service")));
        let getty = one(&s, "enable getty@.service");
        assert_eq!(getty.raw["instances"], "tty1 tty2");
        assert_eq!(getty.target_path, Some(dir.join("usr/lib/systemd/system/getty@.service")));
        let glob = one(&s, "enable foo-*.service");
        assert_eq!((glob.enabled, glob.target_path.clone()), (Enablement::Enabled, None));
        let replaced = one(&s, "enable replaced.service");
        assert_eq!(replaced.enabled, Enablement::Disabled);
        assert!(replaced.raw["shadowed_by"].ends_with("etc/systemd/system-preset/10-x.preset"));
        assert!(named(&s, "disable *").is_empty(), "disable lines run nothing");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
