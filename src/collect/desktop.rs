//! XDG autostart, plus the desktop-session code GNOME Shell and Cinnamon load
//! into their own process at login.
//!
//! The second half is why this collector is not just a directory lister. An
//! extension, applet or desklet present on disk runs only if dconf says so, so
//! enablement means reading dconf's binary GVDB databases directly — §3 bars
//! asking `gsettings` or `dconf`, which are binaries on the host under
//! examination. Both layers matter: a key the account never changed is absent
//! from the user database entirely, and its value comes from the compiled
//! schema defaults instead.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use gvdb::read::File as Gvdb;

use crate::entry::{Enablement, Entry, Flag, Kind, Trigger, hex, name_from_os};
use crate::scan::{Collector, Ctx};
use crate::users::User;

pub struct Desktop;

impl Collector for Desktop {
    fn name(&self) -> &'static str {
        "desktop"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = autostart(cx);
        out.append(&mut extensions(cx));
        out
    }
}

/// A .desktop file is a few hundred bytes; anything past this is not one.
const DESKTOP_CAP: usize = 256 * 1024;
/// A GVDB database is read whole or not at all — a half-read one parses and
/// answers with silently missing keys.
const DCONF_CAP: usize = 8 << 20;
const METADATA_CAP: usize = 256 * 1024;

const SYSTEM_AUTOSTART: &str = "etc/xdg/autostart";
const SCHEMAS: &str = "usr/share/glib-2.0/schemas/gschemas.compiled";

// ---------------------------------------------------------------- autostart

fn autostart(cx: &mut Ctx) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    let mut system: BTreeMap<OsString, usize> = BTreeMap::new();

    for ent in cx.dir(SYSTEM_AUTOSTART) {
        if !is_desktop(&ent.name) {
            continue;
        }
        let rel = Path::new(SYSTEM_AUTOSTART).join(&ent.name);
        if let Some(e) = desktop_file(cx, &rel, &ent.name, None) {
            system.insert(ent.name.clone(), out.len());
            out.push(e);
        }
    }

    let users = cx.users;
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for u in users {
        let dir = u.in_home(".config/autostart");
        if !seen.insert(dir.clone()) {
            continue;
        }
        for ent in cx.dir(&dir) {
            if !is_desktop(&ent.name) {
                continue;
            }
            let rel = dir.join(&ent.name);
            let Some(mut e) = desktop_file(cx, &rel, &ent.name, Some(u.name.as_str())) else { continue };
            if let Some(&ix) = system.get(&ent.name) {
                let vendor = out[ix].source.to_string_lossy().into_owned();
                e.note("overrides", vendor);
                let mine = e.source.to_string_lossy().into_owned();
                append_note(&mut out[ix], "overridden_by", &mine);
            }
            out.push(e);
        }
    }
    out
}

fn is_desktop(name: &OsStr) -> bool {
    name.as_bytes().ends_with(b".desktop")
}

fn append_note(e: &mut Entry, key: &str, value: &str) {
    let merged = match e.raw.get(key) {
        Some(prev) => format!("{prev}, {value}"),
        None => value.to_string(),
    };
    e.note(key, merged);
}

fn desktop_file(cx: &mut Ctx, rel: &Path, file: &OsStr, principal: Option<&str>) -> Option<Entry> {
    let bytes = cx.read_capped(rel, DESKTOP_CAP)?;
    let mut e = cx.entry(Kind::XdgAutostart, rel, file.to_string_lossy().into_owned());
    name_from_os(&mut e, file);
    e.trigger = Trigger::Login;
    e.principal = principal.map(str::to_string);
    // An autostart file runs unless it says otherwise; the keys below are the
    // only things that stop it.
    e.enabled = Enablement::Enabled;

    let pairs = desktop_entry_group(&bytes);
    if pairs.is_empty() {
        e.note("parse", "no [Desktop Entry] group, or it is empty");
    }

    let mut keys: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (key, value) in pairs {
        match split_locale(&key) {
            (base, Some(locale)) => {
                if base == "Exec" || base == "TryExec" {
                    // Not executed by any conforming implementation, but a key
                    // spelled Exec[..] is worth showing to whoever is reading.
                    e.note(&format!("{}_locale.{locale}", base.to_lowercase()), lossy(&value));
                }
            }
            (base, None) => {
                if let Some(prev) = keys.get(base) {
                    if prev != &value {
                        e.note(&format!("duplicate_key.{base}"), lossy(prev));
                    }
                }
                keys.insert(base.to_string(), value);
            }
        }
    }

    if let Some(exec) = keys.get("Exec") {
        read_exec(&mut e, exec, cx.root);
    } else {
        e.note("exec", "absent");
    }
    if let Some(v) = keys.get("TryExec") {
        e.note("tryexec", lossy(v));
    }
    for (key, note) in [("Type", "desktop_type"), ("Name", "desktop_name"), ("NoDisplay", "nodisplay")] {
        if let Some(v) = keys.get(key) {
            e.note(note, lossy(v));
        }
    }
    // Conditional on the running desktop, which the scan cannot know, so they
    // are recorded rather than folded into enablement.
    for key in ["OnlyShowIn", "NotShowIn"] {
        if let Some(v) = keys.get(key) {
            e.note(&key.to_lowercase(), lossy(v));
        }
    }
    if let Some(v) = keys.get("Hidden") {
        if as_bool(v) == Some(true) {
            e.enabled = Enablement::Disabled;
            e.note("hidden", "true");
        }
    }
    if let Some(v) = keys.get("X-GNOME-Autostart-enabled") {
        e.note("x_gnome_autostart_enabled", lossy(v));
        if as_bool(v) == Some(false) {
            e.enabled = Enablement::Disabled;
        }
    }
    Some(e)
}

fn read_exec(e: &mut Entry, exec: &[u8], root: &crate::root::Root) {
    e.command = Some(exec.to_vec());
    if std::str::from_utf8(exec).is_err() {
        e.flag(Flag::EncodingAnomaly);
        e.note("exec_hex", hex(exec));
    }

    let codes = field_codes(exec);
    if !codes.is_empty() {
        e.note("exec_field_codes", codes.join(" "));
    }

    // The raw bytes are the evidence; this is the argv a launcher would build
    // from them, before field-code substitution.
    let argv = argv_of(&unescape(exec));
    let rendered: Vec<String> = argv.iter().map(|a| lossy(a)).collect();
    if let Ok(json) = serde_json::to_string(&rendered) {
        e.note("exec_argv", json);
    }

    let mut ix = 0;
    while let Some(tok) = argv.get(ix) {
        if tok == b"env" || tok == b"/usr/bin/env" || tok == b"/bin/env" {
            ix += 1;
            continue;
        }
        match env_assignment(tok) {
            Some((k, v)) => {
                e.note(&format!("env.{k}"), lossy(v));
                ix += 1;
            }
            None => break,
        }
    }
    if let Some(prog) = argv.get(ix) {
        if prog.starts_with(b"/") {
            // Reported in the same coordinates as `source`: inside the scan
            // root, not on the analyst's own filesystem.
            e.target_path = Some(root.abs(PathBuf::from(OsString::from_vec(prog.clone()))));
        }
    }
}

/// The key/value lines of the `[Desktop Entry]` group, values undecoded.
fn desktop_entry_group(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in bytes.split(|b| *b == b'\n') {
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if line[0] == b'[' {
            inside = line == b"[Desktop Entry]".as_slice();
            continue;
        }
        if !inside {
            continue;
        }
        let Some(eq) = line.iter().position(|b| *b == b'=') else { continue };
        let key = lossy(trim(&line[..eq]));
        if key.is_empty() {
            continue;
        }
        out.push((key, trim(&line[eq + 1..]).to_vec()));
    }
    out
}

/// `Name[de]` splits into `Name` and `de`; everything else keeps its name.
fn split_locale(key: &str) -> (&str, Option<&str>) {
    match (key.find('['), key.strip_suffix(']')) {
        (Some(open), Some(body)) if open + 1 <= body.len() => (&key[..open], Some(&body[open + 1..])),
        _ => (key, None),
    }
}

fn as_bool(v: &[u8]) -> Option<bool> {
    match v {
        b"true" | b"True" | b"1" => Some(true),
        b"false" | b"False" | b"0" => Some(false),
        _ => None,
    }
}

/// `\s \n \t \r \\` as the desktop entry spec defines them.
fn unescape(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len());
    let mut i = 0;
    while i < v.len() {
        if v[i] == b'\\' && i + 1 < v.len() {
            let (byte, step) = match v[i + 1] {
                b's' => (b' ', 2),
                b'n' => (b'\n', 2),
                b't' => (b'\t', 2),
                b'r' => (b'\r', 2),
                b'\\' => (b'\\', 2),
                _ => (v[i], 1),
            };
            out.push(byte);
            i += step;
        } else {
            out.push(v[i]);
            i += 1;
        }
    }
    out
}

fn argv_of(v: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut open = false;
    let mut started = false;
    let mut i = 0;
    while i < v.len() {
        let b = v[i];
        if open {
            if b == b'\\' && i + 1 < v.len() {
                cur.push(v[i + 1]);
                i += 2;
                continue;
            }
            if b == b'"' {
                open = false;
            } else {
                cur.push(b);
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => {
                open = true;
                started = true;
            }
            b' ' | b'\t' => {
                if started {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            _ => {
                cur.push(b);
                started = true;
            }
        }
        i += 1;
    }
    if started {
        out.push(cur);
    }
    out
}

fn field_codes(v: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < v.len() {
        if v[i] == b'%' {
            if v[i + 1] == b'%' {
                i += 2;
                continue;
            }
            if v[i + 1].is_ascii_alphabetic() {
                let code = format!("%{}", v[i + 1] as char);
                if !out.contains(&code) {
                    out.push(code);
                }
            }
        }
        i += 1;
    }
    out
}

fn env_assignment(tok: &[u8]) -> Option<(String, &[u8])> {
    let eq = tok.iter().position(|b| *b == b'=')?;
    let (key, value) = tok.split_at(eq);
    if key.is_empty() || key[0].is_ascii_digit() {
        return None;
    }
    if !key.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_') {
        return None;
    }
    Some((lossy(key), &value[1..]))
}

// --------------------------------------------------------------- extensions

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flavour {
    GnomeExtension,
    CinnamonApplet,
    CinnamonDesklet,
    CinnamonExtension,
}

use Flavour::{CinnamonApplet, CinnamonDesklet, CinnamonExtension, GnomeExtension};

impl Flavour {
    fn entry_file(self) -> &'static str {
        match self {
            GnomeExtension | CinnamonExtension => "extension.js",
            CinnamonApplet => "applet.js",
            CinnamonDesklet => "desklet.js",
        }
    }

    /// The dconf key holding the enabled list for this flavour.
    fn key(self) -> &'static str {
        match self {
            GnomeExtension => "/org/gnome/shell/enabled-extensions",
            CinnamonApplet => "/org/cinnamon/enabled-applets",
            CinnamonDesklet => "/org/cinnamon/enabled-desklets",
            CinnamonExtension => "/org/cinnamon/enabled-extensions",
        }
    }

    fn label(self) -> &'static str {
        match self {
            GnomeExtension => "gnome-shell-extension",
            CinnamonApplet => "cinnamon-applet",
            CinnamonDesklet => "cinnamon-desklet",
            CinnamonExtension => "cinnamon-extension",
        }
    }
}

const SYSTEM_EXT_DIRS: &[(&str, Flavour)] = &[
    ("usr/share/gnome-shell/extensions", GnomeExtension),
    ("usr/share/cinnamon/applets", CinnamonApplet),
    ("usr/share/cinnamon/desklets", CinnamonDesklet),
    ("usr/share/cinnamon/extensions", CinnamonExtension),
];

const USER_EXT_DIRS: &[(&str, Flavour)] = &[
    (".local/share/gnome-shell/extensions", GnomeExtension),
    (".local/share/cinnamon/applets", CinnamonApplet),
    (".local/share/cinnamon/desklets", CinnamonDesklet),
    (".local/share/cinnamon/extensions", CinnamonExtension),
];

fn extensions(cx: &mut Ctx) -> Vec<Entry> {
    let schemas = read_gvdb(cx, Path::new(SCHEMAS));
    let users = cx.users;

    let mut stacks: Vec<(String, Stack)> = Vec::new();
    let mut homes: BTreeSet<PathBuf> = BTreeSet::new();
    for u in users {
        if homes.insert(u.home.clone()) {
            stacks.push((u.name.clone(), dconf_stack(cx, u)));
        }
    }

    let mut out = Vec::new();
    for (dir, flavour) in SYSTEM_EXT_DIRS {
        let dir = Path::new(dir);
        for uuid in ext_dirs(cx, dir) {
            let rel = dir.join(&uuid);
            let mut e = extension_entry(cx, &rel, &uuid, *flavour, None);
            let name = e.name.clone();
            verdict(*flavour, &name, false, &stacks, schemas.as_ref(), None).apply(&mut e);
            out.push(e);
        }
    }

    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for u in users {
        for (suffix, flavour) in USER_EXT_DIRS {
            let dir = u.in_home(suffix);
            if !seen.insert(dir.clone()) {
                continue;
            }
            for uuid in ext_dirs(cx, &dir) {
                let rel = dir.join(&uuid);
                let mut e = extension_entry(cx, &rel, &uuid, *flavour, Some(u.name.as_str()));
                let name = e.name.clone();
                verdict(*flavour, &name, true, &stacks, schemas.as_ref(), Some(u.name.as_str()))
                    .apply(&mut e);
                out.push(e);
            }
        }
    }
    out
}

fn ext_dirs(cx: &mut Ctx, dir: &Path) -> Vec<OsString> {
    cx.dir(dir)
        .into_iter()
        .filter(|ent| ent.is_dir || ent.is_symlink)
        .map(|ent| ent.name)
        .collect()
}

fn extension_entry(
    cx: &mut Ctx,
    rel: &Path,
    dirname: &OsStr,
    flavour: Flavour,
    principal: Option<&str>,
) -> Entry {
    // GNOME Shell and Cinnamon both key an extension by its directory name,
    // not by the uuid inside metadata.json; a disagreement between the two is
    // itself worth recording.
    let uuid = dirname.to_string_lossy().into_owned();
    let mut e = cx.entry(Kind::DesktopExtension, rel, uuid.clone());
    name_from_os(&mut e, dirname);
    e.trigger = Trigger::Login;
    e.principal = principal.map(str::to_string);
    e.note("uuid", uuid.clone());
    e.note("extension_kind", flavour.label());

    if let Some(bytes) = cx.read_capped(rel.join("metadata.json"), METADATA_CAP) {
        match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(meta) => {
                for (key, note) in [
                    ("name", "metadata_name"),
                    ("description", "metadata_description"),
                    ("version", "metadata_version"),
                ] {
                    if let Some(s) = meta.get(key).and_then(|v| v.as_str()) {
                        e.note(note, s);
                    }
                }
                for key in ["shell-version", "cinnamon-version"] {
                    if let Some(list) = meta.get(key).and_then(|v| v.as_array()) {
                        let versions: Vec<String> =
                            list.iter().map(|v| v.to_string().trim_matches('"').to_string()).collect();
                        e.note(&key.replace('-', "_"), versions.join(","));
                    }
                }
                match meta.get("uuid").and_then(|v| v.as_str()) {
                    Some(m) if m != uuid => e.note("metadata_uuid_mismatch", m),
                    _ => {}
                }
            }
            Err(err) => e.note("metadata_json", format!("unparseable: {err}")),
        }
    } else {
        e.note("metadata_json", "absent");
    }

    match entry_point(cx, rel, flavour.entry_file()) {
        Some(found) => {
            e.target_path = Some(cx.root.abs(&found));
            e.note("entry_point", flavour.entry_file());
        }
        None => e.note("entry_point", format!("{} not found", flavour.entry_file())),
    }
    e
}

/// The code file itself, either directly in the uuid directory or under one of
/// the per-Cinnamon-version subdirectories that Mint's applets ship.
fn entry_point(cx: &mut Ctx, dir: &Path, file: &str) -> Option<PathBuf> {
    let direct = dir.join(file);
    if cx.root.stat(&direct).is_ok() {
        return Some(direct);
    }
    cx.dir(dir)
        .into_iter()
        .filter(|ent| ent.is_dir)
        .map(|ent| dir.join(&ent.name).join(file))
        .find(|candidate| cx.root.stat(candidate).is_ok())
}

// -------------------------------------------------------------------- dconf

struct Db {
    label: String,
    file: Gvdb<'static>,
    locks: Vec<String>,
}

/// One account's dconf database stack, highest priority first.
struct Stack {
    dbs: Vec<Db>,
    notes: Vec<(String, String)>,
}

fn read_gvdb(cx: &mut Ctx, rel: &Path) -> Option<Gvdb<'static>> {
    let bytes = cx.read_capped(rel, DCONF_CAP)?;
    if bytes.len() >= DCONF_CAP {
        cx.note_unreadable(format!("{}: larger than {DCONF_CAP} bytes, not parsed", rel.display()));
        return None;
    }
    match Gvdb::from_bytes(Cow::Owned(bytes)) {
        Ok(f) => Some(f),
        Err(e) => {
            cx.note_unreadable(format!("{}: {e}", rel.display()));
            None
        }
    }
}

fn dconf_stack(cx: &mut Ctx, u: &User) -> Stack {
    let mut stack = Stack { dbs: Vec::new(), notes: Vec::new() };

    let profile = cx.read_capped("etc/dconf/profile/user", 64 * 1024);
    let mut specs: Vec<String> = Vec::new();
    if let Some(bytes) = &profile {
        for line in String::from_utf8_lossy(bytes).lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                specs.push(line.to_string());
            }
        }
    }
    if specs.is_empty() {
        // The documented default when no profile file names a stack.
        specs.push("user-db:user".to_string());
        if profile.is_some() {
            stack.notes.push(("dconf_profile".into(), "present but named no database".into()));
        }
    } else {
        stack.notes.push(("dconf_profile".into(), specs.join(", ")));
    }

    for spec in specs {
        let Some((kind, name)) = spec.split_once(':') else {
            stack.notes.push(("dconf_profile_unparsed".into(), spec));
            continue;
        };
        // A profile is root-writable configuration, but a name carrying a path
        // separator would walk the stack out of the directory it names.
        if name.is_empty() || name.contains('/') || name.contains("..") {
            stack.notes.push(("dconf_profile_rejected".into(), spec.clone()));
            continue;
        }
        let rel = match kind {
            "user-db" => u.in_home(&format!(".config/dconf/{name}")),
            "system-db" => PathBuf::from("etc/dconf/db").join(name),
            _ => {
                stack.notes.push(("dconf_profile_unsupported".into(), spec.clone()));
                continue;
            }
        };
        // /run/user/<uid>/dconf/user is deliberately not consulted: it is a
        // two-byte change counter, not a database.
        if let Some(file) = read_gvdb(cx, &rel) {
            let locks = locks_of(&file);
            stack.dbs.push(Db { label: spec.clone(), file, locks });
        }
    }
    stack
}

fn locks_of(file: &Gvdb<'static>) -> Vec<String> {
    let Ok(root) = file.hash_table() else { return Vec::new() };
    let Ok(locks) = root.get_hash_table(".locks") else { return Vec::new() };
    locks
        .keys()
        .filter_map(|k| k.ok())
        // Path components of a locked key appear in the same table as
        // containers; only the ones carrying a value are locks.
        .filter(|k| locks.get_value(k).is_ok())
        .collect()
}

impl Stack {
    fn strings(&self, path: &str, schemas: Option<&Gvdb<'static>>) -> Option<(Vec<String>, String)> {
        for db in &self.dbs {
            if let Ok(table) = db.file.hash_table() {
                if let Ok(v) = table.get::<Vec<String>>(path) {
                    return Some((v, db.label.clone()));
                }
            }
        }
        schema_default(schemas, path, |t, key| t.get::<(Vec<String>,)>(key).ok().map(|v| v.0))
    }

    fn flag(&self, path: &str, schemas: Option<&Gvdb<'static>>) -> Option<(bool, String)> {
        for db in &self.dbs {
            if let Ok(table) = db.file.hash_table() {
                if let Ok(v) = table.get::<bool>(path) {
                    return Some((v, db.label.clone()));
                }
            }
        }
        schema_default(schemas, path, |t, key| t.get::<(bool,)>(key).ok().map(|v| v.0))
    }

    fn lock_on(&self, path: &str) -> Option<String> {
        for db in &self.dbs {
            for lock in &db.locks {
                if lock == path || (lock.ends_with('/') && path.starts_with(lock.as_str())) {
                    return Some(format!("{} ({})", lock, db.label));
                }
            }
        }
        None
    }
}

/// The compiled schema default for a dconf path. Defaults live in a nested
/// table per schema id, each value wrapped in a one-tuple, and the schema's
/// own `.path` key is what ties the id back to the dconf path.
fn schema_default<T>(
    schemas: Option<&Gvdb<'static>>,
    path: &str,
    get: impl Fn(&gvdb::read::HashTable<'_, '_>, &str) -> Option<T>,
) -> Option<(T, String)> {
    let file = schemas?;
    let (prefix, key) = path.rsplit_once('/')?;
    if key.is_empty() {
        return None;
    }
    let prefix = format!("{prefix}/");
    let schema = prefix.trim_matches('/').replace('/', ".");
    let root = file.hash_table().ok()?;
    let table = root.get_hash_table(&schema).ok()?;
    // Relocatable schemas have no .path and cannot be mapped to a dconf path.
    if table.get::<String>(".path").ok()? != prefix {
        return None;
    }
    get(&table, key).map(|v| (v, format!("schema:{schema}")))
}

/// What dconf says about one extension, across the accounts that could enable
/// it.
struct Verdict {
    enabled: Enablement,
    degraded: bool,
    notes: Vec<(String, String)>,
}

impl Verdict {
    fn apply(self, e: &mut Entry) {
        e.enabled = self.enabled;
        if self.degraded {
            e.flag(Flag::DegradedEnablement);
        }
        for (k, v) in self.notes {
            e.note(&k, v);
        }
    }
}

fn verdict(
    flavour: Flavour,
    uuid: &str,
    user_scope: bool,
    stacks: &[(String, Stack)],
    schemas: Option<&Gvdb<'static>>,
    only: Option<&str>,
) -> Verdict {
    let key = flavour.key();
    let mut notes: Vec<(String, String)> = Vec::new();
    let mut answered = false;
    let mut enabled_for: Vec<String> = Vec::new();
    let mut matched: Option<String> = None;
    let mut source: Option<String> = None;

    for (user, stack) in stacks {
        if only.is_some_and(|u| u != user) {
            continue;
        }
        if let Some(lock) = stack.lock_on(key) {
            notes.push(("dconf_lock".into(), lock));
        }
        notes.extend(stack.notes.iter().cloned());
        let Some((list, from)) = stack.strings(key, schemas) else { continue };
        answered = true;

        let hit = list.iter().find(|s| colon_fields_contain(s, uuid)).cloned();
        let mut on = hit.is_some();

        if flavour == GnomeExtension {
            if let Some((disabled, from)) = stack.strings("/org/gnome/shell/disabled-extensions", schemas) {
                if disabled.iter().any(|s| s == uuid) {
                    on = false;
                    notes.push(("dconf_disabled_extensions".into(), from));
                }
            }
            if user_scope {
                if let Some((true, from)) =
                    stack.flag("/org/gnome/shell/disable-user-extensions", schemas)
                {
                    on = false;
                    notes.push(("dconf_disable_user_extensions".into(), from));
                }
            }
        }

        if on {
            enabled_for.push(user.clone());
            matched = hit;
            source = Some(from);
        }
    }

    // A compiled schema default is the same answer for everyone, so naming
    // the accounts it applied to says nothing and says it at length: on a
    // real desktop that is every account with a home, on every shipped
    // applet. Accounts are worth listing only when a particular user's own
    // database is what turned the thing on.
    let from_schema = source.as_deref().is_some_and(|s| s.starts_with("schema:"));
    let who = (!enabled_for.is_empty() && !from_schema).then(|| enabled_for.join(", "));

    for (note, value) in [
        ("dconf_key", Some(key.to_string())),
        ("enabled_for", who),
        ("enabled_by", matched),
        ("enablement_source", source),
    ] {
        if let Some(value) = value {
            notes.push((note.to_string(), value));
        }
    }

    let (enabled, degraded) = if !enabled_for.is_empty() {
        (Enablement::Enabled, false)
    } else if answered {
        (Enablement::Disabled, false)
    } else {
        // No database and no schema default could be read, so presence on disk
        // is all that is known — which is exactly what must not be mistaken
        // for enablement.
        notes.push(("enablement".into(), "no dconf database or schema default could be read".into()));
        (Enablement::Unknown, true)
    };

    Verdict { enabled, degraded, notes }
}

/// Cinnamon stores an applet as `panel1:right:0:calendar@cinnamon.org:12` and
/// an extension as the bare uuid, so the uuid is a field of the value rather
/// than the whole of it.
fn colon_fields_contain(value: &str, uuid: &str) -> bool {
    value == uuid || value.split(':').any(|f| f == uuid)
}

// -------------------------------------------------------------------- bytes

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn trim(mut line: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = line {
        if first.is_ascii_whitespace() {
            line = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = line {
        if last.is_ascii_whitespace() {
            line = rest;
        } else {
            break;
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Status};
    use gvdb::write::{FileWriter, HashTableBuilder};

    fn tree(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("unbidden-desktop-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        put(&dir, "etc/passwd", b"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh\n");
        std::fs::create_dir_all(dir.join("home/alice")).unwrap();
        dir
    }

    fn put(dir: &Path, rel: &str, bytes: &[u8]) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn run(dir: &Path) -> (Vec<Entry>, Status) {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Desktop)];
        let scan = crate::scan::run(&root, &Options { deep: false }, &collectors);
        let status = scan.header.collectors[0].status.clone();
        (scan.entries, status)
    }

    fn by_name<'a>(entries: &'a [Entry], kind: Kind, name: &str) -> Vec<&'a Entry> {
        entries.iter().filter(|e| e.kind == kind && e.name == name).collect()
    }

    /// A dconf database in the real on-disk format, written by gvdb itself.
    fn dconf_db(strings: &[(&str, &[&str])], flags: &[(&str, bool)], locks: &[&str]) -> Vec<u8> {
        let mut t = HashTableBuilder::new();
        for (key, value) in strings {
            let v: Vec<String> = value.iter().map(|s| s.to_string()).collect();
            t.insert(key, v).unwrap();
        }
        for (key, value) in flags {
            t.insert(key, *value).unwrap();
        }
        if !locks.is_empty() {
            let mut l = HashTableBuilder::new();
            for key in locks {
                l.insert_string(key, "").unwrap();
            }
            t.insert_table(".locks", l).unwrap();
        }
        FileWriter::new().write_to_vec_with_table(t).unwrap()
    }

    /// gschemas.compiled: a table per schema id, defaults in one-tuples.
    fn schemas_db(schema: &str, path: &str, strings: &[(&str, &[&str])]) -> Vec<u8> {
        let mut inner = HashTableBuilder::with_path_separator(None);
        inner.insert_string(".path", path).unwrap();
        for (key, value) in strings {
            let v: Vec<String> = value.iter().map(|s| s.to_string()).collect();
            inner.insert(key, (v,)).unwrap();
        }
        let mut root = HashTableBuilder::with_path_separator(None);
        root.insert_table(schema, inner).unwrap();
        FileWriter::new().write_to_vec_with_table(root).unwrap()
    }

    fn extension(dir: &Path, base: &str, uuid: &str, file: &str) {
        put(dir, &format!("{base}/{uuid}/{file}"), b"// session code\n");
        put(
            dir,
            &format!("{base}/{uuid}/metadata.json"),
            format!(r#"{{"uuid":"{uuid}","name":"T","description":"d","shell-version":["45"]}}"#).as_bytes(),
        );
    }

    #[test]
    fn hidden_true_disables_without_hiding_the_entry() {
        let dir = tree("hidden");
        put(
            &dir,
            "etc/xdg/autostart/spice-vdagent.desktop",
            b"[Desktop Entry]\nType=Application\nName=Agent\nExec=/usr/bin/spice-vdagent\nHidden=true\n",
        );
        let (entries, status) = run(&dir);
        let e = by_name(&entries, Kind::XdgAutostart, "spice-vdagent.desktop");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].enabled, Enablement::Disabled);
        assert_eq!(e[0].trigger, Trigger::Login);
        assert_eq!(e[0].command.as_deref(), Some(b"/usr/bin/spice-vdagent".as_slice()));
        assert_eq!(e[0].target_path, Some(dir.join("usr/bin/spice-vdagent")));
        assert_eq!(status, Status::Complete);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_user_file_shadowing_a_system_one_emits_both_and_says_so() {
        let dir = tree("override");
        put(
            &dir,
            "etc/xdg/autostart/nm-applet.desktop",
            b"[Desktop Entry]\nExec=/usr/bin/nm-applet\n",
        );
        put(
            &dir,
            "home/alice/.config/autostart/nm-applet.desktop",
            b"[Desktop Entry]\nExec=env LD_PRELOAD=/tmp/evil.so /usr/bin/nm-applet %u\n",
        );
        let (entries, _) = run(&dir);
        let both = by_name(&entries, Kind::XdgAutostart, "nm-applet.desktop");
        assert_eq!(both.len(), 2, "both files are evidence, not one winner");

        let user = both.iter().find(|e| e.principal.as_deref() == Some("alice")).unwrap();
        let system = both.iter().find(|e| e.principal.is_none()).unwrap();
        assert_eq!(user.raw.get("overrides"), Some(&system.source.to_string_lossy().into_owned()));
        assert_eq!(system.raw.get("overridden_by"), Some(&user.source.to_string_lossy().into_owned()));
        assert_eq!(user.raw.get("env.LD_PRELOAD").map(String::as_str), Some("/tmp/evil.so"));
        assert_eq!(user.target_path, Some(dir.join("usr/bin/nm-applet")));
        assert_eq!(user.raw.get("exec_field_codes").map(String::as_str), Some("%u"));
        // ~/.config/autostart is where per-user autostart is supposed to
        // live, so being under a dot-directory says nothing about it.
        assert!(!user.has_flag(Flag::HiddenPath));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn invalid_utf8_in_exec_is_kept_as_bytes_and_flagged() {
        let dir = tree("utf8");
        let mut file = b"[Desktop Entry]\nExec=/usr/bin/".to_vec();
        file.extend_from_slice(&[0xff, 0xfe, 0x80]);
        file.extend_from_slice(b" --daemon\n");
        put(&dir, "etc/xdg/autostart/bad.desktop", &file);

        let (entries, _) = run(&dir);
        let e = by_name(&entries, Kind::XdgAutostart, "bad.desktop");
        assert_eq!(e.len(), 1);
        let command = e[0].command.clone().unwrap();
        assert!(command.ends_with(b" --daemon"));
        assert!(command.windows(3).any(|w| w == [0xff, 0xfe, 0x80]), "raw bytes survive");
        assert!(e[0].has_flag(Flag::EncodingAnomaly));
        assert!(e[0].raw.contains_key("exec_hex"));
        assert_eq!(e[0].enabled, Enablement::Enabled);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_extension_on_disk_but_absent_from_enabled_extensions_is_reported_disabled() {
        let dir = tree("notenabled");
        extension(&dir, "home/alice/.local/share/gnome-shell/extensions", "lurker@x.com", "extension.js");
        put(
            &dir,
            "home/alice/.config/dconf/user",
            &dconf_db(&[("/org/gnome/shell/enabled-extensions", &["something-else@x.com"])], &[], &[]),
        );

        let (entries, status) = run(&dir);
        let e = by_name(&entries, Kind::DesktopExtension, "lurker@x.com");
        assert_eq!(e.len(), 1, "an extension that is not enabled is still reported");
        assert_eq!(e[0].enabled, Enablement::Disabled);
        assert_eq!(e[0].principal.as_deref(), Some("alice"));
        assert_eq!(e[0].command, None);
        assert_eq!(
            e[0].target_path,
            Some(dir.join("home/alice/.local/share/gnome-shell/extensions/lurker@x.com/extension.js"))
        );
        assert_eq!(e[0].raw.get("uuid").map(String::as_str), Some("lurker@x.com"));
        assert_eq!(e[0].raw.get("shell_version").map(String::as_str), Some("45"));
        assert!(!e[0].has_flag(Flag::DegradedEnablement));
        assert_eq!(status, Status::Complete);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_extension_enabled_only_by_the_schema_default_is_found() {
        let dir = tree("schema");
        extension(&dir, "usr/share/gnome-shell/extensions", "ding@rastersoft.com", "extension.js");
        // The account never touched the key, so it is absent from the user
        // database and only the compiled default answers.
        put(
            &dir,
            "home/alice/.config/dconf/user",
            &dconf_db(&[("/org/gnome/shell/favorite-apps", &["firefox.desktop"])], &[], &[]),
        );
        put(
            &dir,
            SCHEMAS,
            &schemas_db(
                "org.gnome.shell",
                "/org/gnome/shell/",
                &[("enabled-extensions", &["ding@rastersoft.com"])],
            ),
        );

        let (entries, _) = run(&dir);
        let e = by_name(&entries, Kind::DesktopExtension, "ding@rastersoft.com");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].enabled, Enablement::Enabled);
        assert_eq!(
            e[0].raw.get("enablement_source").map(String::as_str),
            Some("schema:org.gnome.shell")
        );
        // A compiled default applies to every account, not just the one whose
        // database was read.
        // The schema default is user-independent, so the accounts it covers
        // are not worth listing — the source note already says so.
        assert!(e[0].raw.get("enabled_for").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_cinnamon_applet_is_matched_on_the_uuid_field_not_the_whole_string() {
        let dir = tree("applet");
        extension(&dir, "home/alice/.local/share/cinnamon/applets", "calendar@cinnamon.org", "applet.js");
        extension(&dir, "usr/share/cinnamon/desklets", "clock@cinnamon.org", "desklet.js");
        put(
            &dir,
            "home/alice/.config/dconf/user",
            &dconf_db(
                &[
                    ("/org/cinnamon/enabled-applets", &["panel1:right:0:calendar@cinnamon.org:12"]),
                    ("/org/cinnamon/enabled-desklets", &["clock@cinnamon.org:0:100:100"]),
                ],
                &[],
                &["/org/cinnamon/enabled-applets"],
            ),
        );

        let (entries, _) = run(&dir);
        let applet = by_name(&entries, Kind::DesktopExtension, "calendar@cinnamon.org");
        assert_eq!(applet.len(), 1);
        assert_eq!(applet[0].enabled, Enablement::Enabled);
        assert_eq!(
            applet[0].raw.get("enabled_by").map(String::as_str),
            Some("panel1:right:0:calendar@cinnamon.org:12")
        );
        assert_eq!(applet[0].raw.get("extension_kind").map(String::as_str), Some("cinnamon-applet"));
        assert!(applet[0].raw.contains_key("dconf_lock"), "a locked key is recorded");

        let desklet = by_name(&entries, Kind::DesktopExtension, "clock@cinnamon.org");
        assert_eq!(desklet.len(), 1);
        assert_eq!(desklet[0].enabled, Enablement::Enabled, "system desklet, enabled by alice");
        assert_eq!(desklet[0].principal, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_truncated_dconf_database_neither_panics_nor_fails_the_collector() {
        let dir = tree("corrupt");
        extension(&dir, "home/alice/.local/share/gnome-shell/extensions", "x@y.z", "extension.js");
        let good = dconf_db(&[("/org/gnome/shell/enabled-extensions", &["x@y.z"])], &[], &[]);

        for cut in [0, 8, 24, 31, good.len() / 3, good.len() / 2, good.len() - 1] {
            put(&dir, "home/alice/.config/dconf/user", &good[..cut]);
            let (entries, status) = run(&dir);
            let e = by_name(&entries, Kind::DesktopExtension, "x@y.z");
            assert_eq!(e.len(), 1, "the extension is reported whatever the database does");
            assert!(
                !matches!(status, Status::Failed { .. }),
                "a corrupt database must not fail the collector (cut {cut}): {status:?}"
            );
            if cut < 32 {
                // Too short to carry a valid header, so nothing is known.
                assert_eq!(e[0].enabled, Enablement::Unknown, "cut {cut}");
                assert!(e[0].has_flag(Flag::DegradedEnablement), "cut {cut}");
            }
        }

        // Header-valid but with the body replaced by noise.
        let mut noise = good.clone();
        for b in noise.iter_mut().skip(32) {
            *b = 0xa5;
        }
        put(&dir, "home/alice/.config/dconf/user", &noise);
        let (entries, status) = run(&dir);
        assert_eq!(by_name(&entries, Kind::DesktopExtension, "x@y.z").len(), 1);
        assert!(!matches!(status, Status::Failed { .. }), "{status:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_system_db_named_by_the_profile_answers_for_every_account() {
        let dir = tree("profile");
        extension(&dir, "usr/share/gnome-shell/extensions", "site@corp", "extension.js");
        put(&dir, "etc/dconf/profile/user", b"user-db:user\nsystem-db:local\n");
        put(
            &dir,
            "home/alice/.config/dconf/user",
            &dconf_db(&[("/org/gnome/shell/favorite-apps", &["firefox.desktop"])], &[], &[]),
        );
        put(
            &dir,
            "etc/dconf/db/local",
            &dconf_db(&[("/org/gnome/shell/enabled-extensions", &["site@corp"])], &[], &[]),
        );

        let (entries, _) = run(&dir);
        let e = by_name(&entries, Kind::DesktopExtension, "site@corp");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].enabled, Enablement::Enabled);
        assert_eq!(e[0].raw.get("enablement_source").map(String::as_str), Some("system-db:local"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn with_no_dconf_at_all_presence_is_not_reported_as_enablement() {
        let dir = tree("nodconf");
        extension(&dir, "usr/share/gnome-shell/extensions", "orphan@x", "extension.js");
        let (entries, _) = run(&dir);
        let e = by_name(&entries, Kind::DesktopExtension, "orphan@x");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].enabled, Enablement::Unknown);
        assert!(e[0].has_flag(Flag::DegradedEnablement));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn malformed_desktop_files_do_not_panic() {
        let dir = tree("malformed");
        let cases: &[(&str, &[u8])] = &[
            ("empty.desktop", b""),
            ("nogroup.desktop", b"Exec=/bin/sh\n"),
            ("nul.desktop", b"[Desktop Entry]\nExec=/bin/sh\x00-c\x00id\n"),
            ("trailing.desktop", b"[Desktop Entry]\nExec=\\"),
            ("bracket.desktop", b"[Desktop Entry\nExec=/bin/sh\n"),
            ("equals.desktop", b"[Desktop Entry]\n=novalue\nExec\n"),
            ("locale.desktop", b"[Desktop Entry]\nName[de]=x\nExec[de]=/bin/evil\nHidden[x]=true\n"),
            ("dupes.desktop", b"[Desktop Entry]\nHidden=true\nHidden=false\nExec=/bin/a\nExec=/bin/b\n"),
            ("quotes.desktop", b"[Desktop Entry]\nExec=\"/opt/my app/run\" \\s --x \"unclosed\n"),
        ];
        for (name, body) in cases {
            put(&dir, &format!("etc/xdg/autostart/{name}"), body);
        }
        let (entries, status) = run(&dir);
        assert_eq!(by_name(&entries, Kind::XdgAutostart, "empty.desktop").len(), 1);
        assert!(!matches!(status, Status::Failed { .. }), "{status:?}");

        // A localised Exec is not what runs, so it must not become the command.
        let locale = by_name(&entries, Kind::XdgAutostart, "locale.desktop");
        assert_eq!(locale[0].command, None);
        assert_eq!(locale[0].raw.get("exec_locale.de").map(String::as_str), Some("/bin/evil"));
        assert_eq!(locale[0].enabled, Enablement::Enabled, "Hidden[x] is not Hidden");

        // glib keeps the last of a repeated key; the earlier one is recorded.
        let dupes = by_name(&entries, Kind::XdgAutostart, "dupes.desktop");
        assert_eq!(dupes[0].command.as_deref(), Some(b"/bin/b".as_slice()));
        assert_eq!(dupes[0].enabled, Enablement::Enabled);
        assert_eq!(dupes[0].raw.get("duplicate_key.Hidden").map(String::as_str), Some("true"));

        let quotes = by_name(&entries, Kind::XdgAutostart, "quotes.desktop");
        assert_eq!(quotes[0].target_path, Some(dir.join("opt/my app/run")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_versioned_cinnamon_applet_directory_still_yields_its_entry_point() {
        let dir = tree("versioned");
        put(&dir, "usr/share/cinnamon/applets/menu@cinnamon.org/5.4/applet.js", b"// code\n");
        put(
            &dir,
            "usr/share/cinnamon/applets/menu@cinnamon.org/metadata.json",
            br#"{"uuid":"other@x","name":"Menu"}"#,
        );
        let (entries, _) = run(&dir);
        let e = by_name(&entries, Kind::DesktopExtension, "menu@cinnamon.org");
        assert_eq!(e.len(), 1);
        assert_eq!(
            e[0].target_path,
            Some(dir.join("usr/share/cinnamon/applets/menu@cinnamon.org/5.4/applet.js"))
        );
        assert_eq!(e[0].raw.get("metadata_uuid_mismatch").map(String::as_str), Some("other@x"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
