//! The apk backend: Alpine's installed-package database, one plain-text
//! file, read as apk-tools 2.14 and 3.0 read it (`apk_db_index_read`).
//!
//! /lib/apk/db/installed is a sequence of blank-line-separated records, one
//! per package, each a list of `X:value` lines: `P:` and `V:` name and
//! version, then the files, as `F:` directory lines each followed by the
//! `R:` names inside it, with `a:` (owner and mode) and `Z:` (digest) lines
//! after the `R:` they describe. The digest is the whole integrity story:
//! apk records no size or mtime, and a symlink's digest is of its target
//! string rather than of anything the link leads to.
//!
//! What a difference means is apk's protected-paths rule. A file under a
//! protected path (`+etc` by default) is kept when its package upgrades, so
//! a change there is what configuration is for; under a symlinks-only path
//! (`@etc/init.d`) or an unprotected one the package's copy comes back on
//! the next upgrade, so a change is a modified package file. `apk audit`
//! itself skips a changed regular file under `@etc/init.d` in both of its
//! modes, which makes this the one place on an Alpine host where the check
//! sees what the package manager does not.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::entry::{Integrity, Provenance};
use crate::root::Root;

use super::{Answers, Outcome, spellings};

const INSTALLED: &str = "lib/apk/db/installed";
const PROTECTED_D: &str = "etc/apk/protected_paths.d";

/// A full host's database is a few megabytes; the cap is a backstop.
const DB_CAP: usize = 64 << 20;

/// apk's compiled-in protected paths (database.c), read before anything in
/// protected_paths.d: /etc is kept on upgrade, /etc/init.d only its links,
/// and /etc/apk is apk's own.
const DEFAULT_PROTECTED: &str = "+etc\n@etc/init.d\n!etc/apk\n";

pub fn present(root: &Root) -> bool {
    root.exists(INSTALLED)
}

/// Every path the database claims, files and directories alike,
/// root-relative.
pub fn packaged_files(root: &Root) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    let Ok((bytes, _)) = root.read_capped(INSTALLED, DB_CAP) else { return out };
    each_path(&bytes, |_, path, _| {
        out.insert(PathBuf::from(OsStr::from_bytes(path)));
    });
    out
}

pub fn resolve(root: &Root, wanted: &BTreeSet<PathBuf>) -> Outcome {
    if !present(root) {
        return Outcome::Absent;
    }
    // A database that is there but cannot be read, or not all of it, answers
    // for nobody it does not name: Unknown for every other path, not
    // Unpackaged.
    let (bytes, truncated) = match root.read_capped(INSTALLED, DB_CAP) {
        Ok(read) => read,
        Err(e) => return Outcome::Incomplete(Answers::new(), format!("{INSTALLED} could not be read: {e}")),
    };

    let mut alias_to_wanted: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    for w in wanted {
        for alias in spellings(root, w) {
            alias_to_wanted.entry(alias).or_default().push(w.clone());
        }
    }

    let protected = protected_paths(root);
    let mut out = Answers::new();
    each_path(&bytes, |pkg, path, facts| {
        let Some(ws) = alias_to_wanted.get(Path::new(OsStr::from_bytes(path))) else { return };
        for w in ws {
            let integrity = verify(root, w, &facts, &protected);
            out.insert(
                w.clone(),
                Provenance::Packaged {
                    package: String::from_utf8_lossy(pkg.name).into_owned(),
                    version: String::from_utf8_lossy(pkg.version).into_owned(),
                    integrity,
                },
            );
        }
    });
    if truncated {
        return Outcome::Incomplete(out, format!("{INSTALLED} is larger than the read cap"));
    }
    Outcome::Complete(out)
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Alg {
    Md5,
    Sha1,
    Sha256,
}

/// What the database says about one path.
#[derive(Default, Clone, Debug, PartialEq)]
struct Facts {
    is_dir: bool,
    /// Lower-case hex, in the algorithm the record was written with.
    digest: Option<(Alg, String)>,
    /// From the `a:` line, octal as apk writes it.
    mode: Option<u32>,
}

struct Pkg<'a> {
    name: &'a [u8],
    version: &'a [u8],
}

/// Streams the database once, calling `f` for every directory and file it
/// claims with the package that claims it. Lines apk would refuse the whole
/// database over — a field without its colon, an `a:` before any `R:` — are
/// skipped here instead: the rest of the file is still evidence.
fn each_path(bytes: &[u8], mut f: impl FnMut(&Pkg<'_>, &[u8], Facts)) {
    let mut name: &[u8] = b"";
    let mut version: &[u8] = b"";
    let mut dir: Vec<u8> = Vec::new();
    // The file whose `a:` and `Z:` lines may still follow.
    let mut pending: Option<(Vec<u8>, Facts)> = None;

    let flush = |pending: &mut Option<(Vec<u8>, Facts)>, name: &[u8], version: &[u8], f: &mut dyn FnMut(&Pkg<'_>, &[u8], Facts)| {
        if let Some((path, facts)) = pending.take() {
            f(&Pkg { name, version }, &path, facts);
        }
    };

    for line in bytes.split(|b| *b == b'\n') {
        // A record ends at a line shorter than two bytes; apk_db_index_read
        // treats that as the blank line between packages.
        if line.len() < 2 {
            flush(&mut pending, name, version, &mut f);
            name = b"";
            version = b"";
            dir.clear();
            continue;
        }
        if line[1] != b':' {
            continue;
        }
        let value = &line[2..];
        match line[0] {
            b'P' => name = value,
            b'V' => version = value,
            b'F' => {
                flush(&mut pending, name, version, &mut f);
                dir = value.strip_suffix(b"/").unwrap_or(value).to_vec();
                if !dir.is_empty() {
                    f(&Pkg { name, version }, &dir, Facts { is_dir: true, ..Facts::default() });
                }
            }
            b'R' => {
                flush(&mut pending, name, version, &mut f);
                let mut path = dir.clone();
                if !path.is_empty() {
                    path.push(b'/');
                }
                path.extend_from_slice(value);
                pending = Some((path, Facts::default()));
            }
            b'a' => {
                if let Some((_, facts)) = pending.as_mut() {
                    facts.mode = acl_mode(value);
                }
            }
            b'Z' => {
                if let Some((_, facts)) = pending.as_mut() {
                    facts.digest = digest(value);
                }
            }
            _ => {}
        }
    }
    flush(&mut pending, name, version, &mut f);
}

/// `uid:gid:mode[:xattr-digest]`, the mode in octal.
fn acl_mode(value: &[u8]) -> Option<u32> {
    let mut fields = value.split(|b| *b == b':');
    let (_uid, _gid, mode) = (fields.next()?, fields.next()?, fields.next()?);
    let text = std::str::from_utf8(mode).ok()?;
    u32::from_str_radix(text, 8).ok()
}

/// A `Z:` value as apk_blob_pull_csum (2.14) and apk_blob_pull_digest (3.0)
/// read it: `Q` for base64 or `X` for hex, then `1` for SHA-1 or `2` for
/// SHA-256; a value starting with a hex digit is an MD5 hexdump from before
/// the prefix existed. apk 3 writes a SHA-256 in an old database as a
/// SHA-1-length prefix with the remaining twelve bytes appended, and reads
/// it back as SHA-256.
fn digest(value: &[u8]) -> Option<(Alg, String)> {
    if value.first().is_some_and(u8::is_ascii_hexdigit) {
        let bytes = unhex(value)?;
        return (bytes.len() == 16).then(|| (Alg::Md5, crate::entry::hex(&bytes)));
    }
    let [encoding, alg, rest @ ..] = value else { return None };
    let decode = |chunk: &[u8]| match encoding {
        b'Q' => crate::text::base64_decode(chunk, crate::text::Padding::Required),
        b'X' => unhex(chunk),
        _ => None,
    };
    let bytes = match alg {
        b'1' => {
            let head = if *encoding == b'Q' { 28 } else { 40 };
            let (first, more) = rest.split_at_checked(head)?;
            let mut bytes = decode(first)?;
            if bytes.len() != 20 {
                return None;
            }
            if !more.is_empty() {
                let tail = decode(more)?;
                if tail.len() != 12 {
                    return None;
                }
                bytes.extend(tail);
            }
            bytes
        }
        b'2' => {
            let bytes = decode(rest)?;
            if bytes.len() != 32 {
                return None;
            }
            bytes
        }
        _ => return None,
    };
    match bytes.len() {
        20 => Some((Alg::Sha1, crate::entry::hex(&bytes))),
        32 => Some((Alg::Sha256, crate::entry::hex(&bytes))),
        _ => None,
    }
}

fn unhex(text: &[u8]) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let nibble = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    text.chunks(2).map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?)).collect()
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Protect {
    /// Not protected: the package's copy replaces a change on upgrade.
    None,
    /// `-`: explicitly not protected.
    Ignore,
    /// `+`: a changed file is kept, the package's copy written beside it.
    Changed,
    /// `@`: symlinks are kept; a changed regular file is replaced.
    SymlinksOnly,
    /// `!`: everything is kept, and apk never audits it.
    All,
}

/// The compiled-in defaults, then every `*.list` in protected_paths.d, in
/// name order; a line is a mode character then a path, `#` a comment, and a
/// path with no mode character is `+`.
fn protected_paths(root: &Root) -> Vec<(Vec<u8>, Protect)> {
    let mut out = Vec::new();
    let mut add = |text: &[u8]| {
        for line in text.split(|b| *b == b'\n') {
            let (mode, path) = match line.first() {
                None | Some(b'#') => continue,
                Some(b'-') => (Protect::Ignore, &line[1..]),
                Some(b'+') => (Protect::Changed, &line[1..]),
                Some(b'@') => (Protect::SymlinksOnly, &line[1..]),
                Some(b'!') => (Protect::All, &line[1..]),
                Some(_) => (Protect::Changed, line),
            };
            let start = path.iter().position(|b| *b != b'/').unwrap_or(path.len());
            let end = path.iter().rposition(|b| *b != b'/').map_or(0, |i| i + 1);
            if start < end {
                out.push((path[start..end].to_vec(), mode));
            }
        }
    };
    add(DEFAULT_PROTECTED.as_bytes());
    let mut lists: Vec<Vec<u8>> = root
        .read_dir_optional(PROTECTED_D)
        .unwrap_or_default()
        .into_iter()
        .filter(|e| !e.is_dir && e.name.as_bytes().ends_with(b".list"))
        .map(|e| e.name.as_bytes().to_vec())
        .collect();
    lists.sort();
    for name in lists {
        let rel = Path::new(PROTECTED_D).join(OsStr::from_bytes(&name));
        if let Ok((bytes, _)) = root.read_capped(rel, 1 << 20) {
            add(&bytes);
        }
    }
    out
}

/// apk's mode for a path, as apk_db_dir_get and determine_file_protect_mode
/// work it out: a pattern is matched component by component from the root,
/// a pattern that still has a slash descending with the directory it
/// matched, one that has none setting the mode of the directory or file it
/// matches, a later pattern overriding an earlier one, and a directory's
/// mode inherited by everything under it. Patterns are `*` and `?` globs;
/// fnmatch's bracket expressions are not read.
fn protect_mode(patterns: &[(Vec<u8>, Protect)], rel: &Path) -> Protect {
    let comps: Vec<&[u8]> = rel.iter().map(OsStr::as_bytes).collect();
    let Some((name, dirs)) = comps.split_last() else { return Protect::None };
    let mut mode = Protect::None;
    let mut level: Vec<(&[u8], Protect)> = patterns.iter().map(|(p, m)| (p.as_slice(), *m)).collect();
    for c in dirs {
        let mut next = Vec::new();
        for (pat, m) in &level {
            match pat.iter().position(|b| *b == b'/') {
                Some(i) => {
                    if crate::text::glob_match(&pat[..i], c) {
                        next.push((&pat[i + 1..], *m));
                    }
                }
                None => {
                    if crate::text::glob_match(pat, c) {
                        mode = *m;
                    }
                }
            }
        }
        level = next;
    }
    for (pat, m) in &level {
        if !pat.contains(&b'/') && crate::text::glob_match(pat, name) {
            mode = *m;
        }
    }
    mode
}

fn verify(root: &Root, rel: &Path, facts: &Facts, protected: &[(Vec<u8>, Protect)]) -> Integrity {
    if facts.is_dir {
        return Integrity::Unknown;
    }
    // No digest recorded — a directory, or a record apk 3 wrote for a file
    // it did not hash — is genuinely unknown, never intact.
    let Some((alg, expected)) = &facts.digest else { return Integrity::Unknown };
    let Ok(meta) = root.stat(rel) else { return Integrity::Unknown };
    let actual = if meta.is_symlink {
        root.read_link(rel).ok().map(|t| hash(*alg, t.as_os_str().as_bytes()))
    } else {
        super::digests(root, rel).map(|d| match alg {
            Alg::Md5 => d.md5,
            Alg::Sha1 => d.sha1,
            Alg::Sha256 => d.sha256,
        })
    };
    let Some(actual) = actual else { return Integrity::Unknown };
    if actual.eq_ignore_ascii_case(expected) {
        // Contents match; a setuid or setgid bit the package did not ship
        // is the rpm backend's ModeModified.
        let privilege = |m: u32| m & 0o6000;
        return match facts.mode {
            Some(shipped) if privilege(shipped) != privilege(meta.mode) => Integrity::ModeModified,
            _ => Integrity::Intact,
        };
    }
    match protect_mode(protected, rel) {
        Protect::Changed | Protect::All => Integrity::ConffileModified,
        Protect::SymlinksOnly if meta.is_symlink => Integrity::ConffileModified,
        Protect::SymlinksOnly | Protect::Ignore | Protect::None => Integrity::Modified,
    }
}

fn hash(alg: Alg, bytes: &[u8]) -> String {
    use md5::Digest as _;
    crate::entry::hex(&match alg {
        Alg::Md5 => md5::Md5::digest(bytes).to_vec(),
        Alg::Sha1 => sha1::Sha1::digest(bytes).to_vec(),
        Alg::Sha256 => sha2::Sha256::digest(bytes).to_vec(),
    })
}


// ------------------------------------------------- scripts and triggers ----

const SCRIPTS_GZ: &str = "lib/apk/db/scripts.tar.gz";
const SCRIPTS_TAR: &str = "lib/apk/db/scripts.tar";
const TRIGGERS: &str = "lib/apk/db/triggers";

/// The phases apk runs a package's scripts at (apk_script_types).
const PHASES: [&str; 7] =
    ["pre-install", "post-install", "pre-deinstall", "post-deinstall", "pre-upgrade", "post-upgrade", "trigger"];

/// One script apk keeps for an installed package: `<name>-<version>.<package
/// digest>.<phase>` in the archive, run as root at that phase of the
/// package's own transactions, or, for `trigger`, whenever any transaction
/// touches a directory the triggers file lists for it.
pub struct Script {
    pub package: String,
    pub version: String,
    /// The package's own checksum, lower-case hex, as `C:` records it.
    pub digest: String,
    pub phase: String,
    pub body: Vec<u8>,
}

/// The scripts archive: apk 3 writes scripts.tar.gz, apk 2 scripts.tar,
/// both ustar written by apk itself. The path read is returned with them.
pub fn scripts(root: &Root) -> Option<(&'static str, Vec<Script>)> {
    let (path, bytes) = if let Ok((b, _)) = root.read_capped(SCRIPTS_GZ, DB_CAP) {
        (SCRIPTS_GZ, gunzip(&b)?)
    } else if let Ok((b, _)) = root.read_capped(SCRIPTS_TAR, DB_CAP) {
        (SCRIPTS_TAR, b)
    } else {
        return None;
    };
    let mut out = Vec::new();
    for (name, body) in tar_entries(&bytes) {
        let Some((stem, phase)) = name.rsplit_once('.') else { continue };
        if !PHASES.contains(&phase) {
            continue;
        }
        let Some((pkg_ver, digest)) = stem.rsplit_once('.') else { continue };
        let Some(alg_digest) = digest_text(digest) else { continue };
        let Some(dash) = pkg_ver.rfind('-') else { continue };
        let Some(dash2) = pkg_ver[..dash].rfind('-') else { continue };
        out.push(Script {
            package: pkg_ver[..dash2].to_string(),
            version: pkg_ver[dash2 + 1..].to_string(),
            digest: alg_digest,
            phase: phase.to_string(),
            body,
        });
    }
    Some((path, out))
}

/// One line of the triggers file: a package's checksum and the directory
/// patterns whose change runs its trigger script.
pub struct Trigger {
    pub digest: String,
    pub dirs: Vec<String>,
    pub package: Option<(String, String)>,
}

/// The triggers file, each line's digest resolved to the installed package
/// whose `C:` it is.
pub fn triggers(root: &Root) -> Option<(&'static str, Vec<Trigger>)> {
    let (bytes, _) = root.read_capped(TRIGGERS, DB_CAP).ok()?;
    let packages = packages_by_checksum(root);
    let mut out = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        let mut fields = line.split(|b| b.is_ascii_whitespace()).filter(|f| !f.is_empty());
        let Some(first) = fields.next() else { continue };
        let Some(digest) = digest_text(&String::from_utf8_lossy(first)) else { continue };
        let package = packages.get(&digest).cloned();
        out.push(Trigger { package, digest, dirs: fields.map(|f| String::from_utf8_lossy(f).into_owned()).collect() });
    }
    Some((TRIGGERS, out))
}

/// Every installed package by its `C:` checksum, lower-case hex.
fn packages_by_checksum(root: &Root) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    let Ok((bytes, _)) = root.read_capped(INSTALLED, DB_CAP) else { return out };
    let (mut checksum, mut name, mut version) = (None, String::new(), String::new());
    for line in bytes.split(|b| *b == b'\n') {
        if line.len() < 2 {
            if let Some(c) = checksum.take() {
                out.insert(c, (std::mem::take(&mut name), std::mem::take(&mut version)));
            }
            name.clear();
            version.clear();
            continue;
        }
        if line[1] != b':' {
            continue;
        }
        let value = String::from_utf8_lossy(&line[2..]).into_owned();
        match line[0] {
            b'C' => checksum = digest_text(&value),
            b'P' => name = value,
            b'V' => version = value,
            _ => {}
        }
    }
    if let Some(c) = checksum {
        out.insert(c, (name, version));
    }
    out
}

/// A digest in either of apk's spellings, as hex, so a `Q1` in the
/// triggers file matches the `X1` in an apk 3 script name.
fn digest_text(text: &str) -> Option<String> {
    digest(text.as_bytes()).map(|(_, hex)| hex)
}

/// RFC 1952: the fixed header, the optional fields the flags announce, then
/// a raw deflate stream; the trailer is not consulted.
fn gunzip(bytes: &[u8]) -> Option<Vec<u8>> {
    let [0x1f, 0x8b, 8, flags, rest @ ..] = bytes else { return None };
    let mut i = 6usize.min(rest.len());
    if flags & 4 != 0 {
        let len = usize::from(u16::from_le_bytes([*rest.get(i)?, *rest.get(i + 1)?]));
        i = i.checked_add(2 + len)?;
    }
    for bit in [8u8, 16] {
        if flags & bit != 0 {
            let end = rest.get(i..)?.iter().position(|b| *b == 0)?;
            i += end + 1;
        }
    }
    if flags & 2 != 0 {
        i = i.checked_add(2)?;
    }
    miniz_oxide::inflate::decompress_to_vec_with_limit(rest.get(i..)?, DB_CAP).ok()
}

/// The regular files of a ustar archive, in order: name (with the prefix
/// field, or a GNU `././@LongLink` entry before it) and contents. Stops at
/// the first zero block, a short block, or a header without ustar's magic.
fn tar_entries(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut long_name: Option<String> = None;
    while at + 512 <= bytes.len() {
        let header = &bytes[at..at + 512];
        if header.iter().all(|b| *b == 0) {
            break;
        }
        if &header[257..262] != b"ustar" {
            break;
        }
        let field = |range: std::ops::Range<usize>| -> String {
            let raw = &header[range];
            let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            String::from_utf8_lossy(&raw[..end]).into_owned()
        };
        let size = {
            let raw = &header[124..136];
            let text: String = raw.iter().take_while(|b| b.is_ascii_digit()).map(|b| *b as char).collect();
            usize::from_str_radix(&text, 8).unwrap_or(0)
        };
        let typeflag = header[156];
        let data_end = at.saturating_add(512).saturating_add(size).min(bytes.len());
        let data = &bytes[(at + 512).min(bytes.len())..data_end];
        let name = match long_name.take() {
            Some(n) => n,
            None => {
                let prefix = field(345..500);
                let name = field(0..100);
                if prefix.is_empty() { name } else { format!("{prefix}/{name}") }
            }
        };
        match typeflag {
            b'L' => long_name = Some(field(0..0).clone() + &String::from_utf8_lossy(data).trim_end_matches('\0')),
            b'0' | 0 => out.push((name, data.to_vec())),
            _ => {}
        }
        let padded = size.div_ceil(512) * 512;
        let Some(next) = at.checked_add(512).and_then(|n| n.checked_add(padded)) else { break };
        at = next;
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) struct Fixture(pub PathBuf);

    impl Fixture {
        pub(crate) fn new(tag: &str) -> Fixture {
            let dir = std::env::temp_dir().join(format!("unbidden-apk-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("lib/apk/db")).unwrap();
            Fixture(dir)
        }
        pub(crate) fn write(&self, rel: &str, content: &[u8]) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        }
        pub(crate) fn link(&self, target: &str, rel: &str) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(target, p).unwrap();
        }
        pub(crate) fn root(&self) -> Root {
            Root::at(&self.0).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `Q1<base64 sha1>`, as apk writes a digest.
    pub(crate) fn q1(content: &[u8]) -> String {
        use md5::Digest as _;
        format!("Q1{}", b64(&sha1::Sha1::digest(content)))
    }

    fn b64(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut acc = 0u32;
            for (i, b) in chunk.iter().enumerate() {
                acc |= u32::from(*b) << (16 - 8 * i);
            }
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(T[((acc >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn ask(root: &Root, paths: &[&str]) -> Answers {
        let wanted: BTreeSet<PathBuf> = paths.iter().map(PathBuf::from).collect();
        resolve(root, &wanted).unwrap()
    }

    #[test]
    fn an_installed_database_that_cannot_be_read_is_incomplete_not_unpackaged() {
        let f = Fixture::new("unreadable");
        // Present, and not a file that can be read.
        std::fs::create_dir_all(f.0.join(INSTALLED)).unwrap();
        let wanted: BTreeSet<PathBuf> = [PathBuf::from("usr/bin/x")].into_iter().collect();
        assert!(matches!(resolve(&f.root(), &wanted), Outcome::Incomplete(a, why) if a.is_empty() && why.contains("could not be read")));
    }

    fn integrity(answers: &Answers, path: &str) -> Integrity {
        match &answers[Path::new(path)] {
            Provenance::Packaged { integrity, .. } => *integrity,
            other => panic!("{path}: {other:?}"),
        }
    }

    /// One package record in the database's own layout.
    fn record(name: &str, version: &str, files: &[(&str, &str)]) -> String {
        let mut out = format!("C:Q1abc=\nP:{name}\nV:{version}\nA:x86_64\nT:test\n");
        let mut dir = "";
        for (path, digest) in files {
            let (d, f) = path.rsplit_once('/').unwrap_or(("", path));
            if d != dir {
                dir = d;
                out.push_str(&format!("F:{d}\n"));
            }
            out.push_str(&format!("R:{f}\na:0:0:755\n"));
            if !digest.is_empty() {
                out.push_str(&format!("Z:{digest}\n"));
            }
        }
        out.push('\n');
        out
    }

    #[test]
    fn a_file_is_owned_and_intact_when_its_digest_matches() {
        let f = Fixture::new("intact");
        let getty = b"#!/bin/sh\nexec /bin/busybox getty \"$@\"\n";
        f.write("sbin/getty", getty);
        f.write("etc/inittab", b"::sysinit:/sbin/openrc sysinit\n");
        f.write(
            INSTALLED,
            format!(
                "{}{}",
                record("busybox", "1.37.0-r31", &[("sbin/getty", &q1(getty))]),
                record("alpine-baselayout-data", "3.7.2-r1", &[("etc/inittab", &q1(b"::sysinit:/sbin/openrc sysinit\n"))]),
            )
            .as_bytes(),
        );
        let answers = ask(&f.root(), &["sbin/getty", "etc/inittab", "usr/bin/nothing"]);
        match &answers[Path::new("sbin/getty")] {
            Provenance::Packaged { package, version, integrity } => {
                assert_eq!((package.as_str(), version.as_str(), *integrity), ("busybox", "1.37.0-r31", Integrity::Intact));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(integrity(&answers, "etc/inittab"), Integrity::Intact);
        assert!(!answers.contains_key(Path::new("usr/bin/nothing")), "an unclaimed path is the caller's to judge");
    }

    #[test]
    fn a_changed_file_is_configuration_under_etc_and_a_finding_elsewhere() {
        let f = Fixture::new("protected");
        let shipped = b"shipped\n";
        for p in ["etc/motd", "usr/bin/tool", "etc/init.d/crond", "etc/apk/keys/k.rsa.pub", "etc/conf.d/crond"] {
            f.write(p, b"changed\n");
        }
        let d = q1(shipped);
        let files: Vec<(&str, &str)> = ["etc/motd", "usr/bin/tool", "etc/init.d/crond", "etc/apk/keys/k.rsa.pub", "etc/conf.d/crond"]
            .into_iter()
            .map(|p| (p, d.as_str()))
            .collect();
        f.write(INSTALLED, record("pkg", "1-r0", &files).as_bytes());
        let a = ask(&f.root(), &["etc/motd", "usr/bin/tool", "etc/init.d/crond", "etc/apk/keys/k.rsa.pub", "etc/conf.d/crond"]);
        assert_eq!(integrity(&a, "etc/motd"), Integrity::ConffileModified, "+etc keeps the change");
        assert_eq!(integrity(&a, "etc/conf.d/crond"), Integrity::ConffileModified);
        assert_eq!(integrity(&a, "usr/bin/tool"), Integrity::Modified);
        assert_eq!(integrity(&a, "etc/init.d/crond"), Integrity::Modified, "@etc/init.d protects links only");
        assert_eq!(integrity(&a, "etc/apk/keys/k.rsa.pub"), Integrity::ConffileModified, "!etc/apk is never overwritten");
    }

    #[test]
    fn a_symlink_is_judged_by_its_target_string() {
        let f = Fixture::new("links");
        f.write("bin/busybox", b"ELF");
        f.link("/bin/busybox", "bin/sh");
        f.link("/tmp/evil", "usr/bin/rbash");
        f.link("/tmp/evil", "etc/init.d/sshd");
        let d = q1(b"/bin/busybox");
        f.write(
            INSTALLED,
            record("busybox-binsh", "1.37.0-r31", &[("bin/sh", &d), ("usr/bin/rbash", &d), ("etc/init.d/sshd", &d)]).as_bytes(),
        );
        let a = ask(&f.root(), &["bin/sh", "usr/bin/rbash", "etc/init.d/sshd"]);
        assert_eq!(integrity(&a, "bin/sh"), Integrity::Intact);
        assert_eq!(integrity(&a, "usr/bin/rbash"), Integrity::Modified, "repointed");
        assert_eq!(integrity(&a, "etc/init.d/sshd"), Integrity::ConffileModified, "a link under @etc/init.d is kept on upgrade");
    }

    #[test]
    fn a_setuid_bit_the_package_did_not_ship_is_mode_modified() {
        let f = Fixture::new("modes");
        let body = b"#!/bin/sh\n";
        f.write("usr/bin/find", body);
        f.write("usr/bin/su", body);
        std::fs::set_permissions(f.0.join("usr/bin/find"), std::fs::Permissions::from_mode(0o4755)).unwrap();
        std::fs::set_permissions(f.0.join("usr/bin/su"), std::fs::Permissions::from_mode(0o4755)).unwrap();
        let d = q1(body);
        f.write(
            INSTALLED,
            format!("C:Q1x=\nP:findutils\nV:4.10.0-r0\nF:usr/bin\nR:find\na:0:0:755\nZ:{d}\nR:su\na:0:0:4755\nZ:{d}\n\n").as_bytes(),
        );
        let a = ask(&f.root(), &["usr/bin/find", "usr/bin/su"]);
        assert_eq!(integrity(&a, "usr/bin/find"), Integrity::ModeModified);
        assert_eq!(integrity(&a, "usr/bin/su"), Integrity::Intact);
    }

    #[test]
    fn no_digest_and_a_directory_are_unknown_never_intact() {
        let f = Fixture::new("nodigest");
        f.write("usr/lib/x.so", b"x");
        f.write(INSTALLED, record("p", "1", &[("usr/lib/x.so", "")]).as_bytes());
        let a = ask(&f.root(), &["usr/lib/x.so", "usr/lib"]);
        assert_eq!(integrity(&a, "usr/lib/x.so"), Integrity::Unknown);
        assert_eq!(integrity(&a, "usr/lib"), Integrity::Unknown, "a directory is owned, and has no digest");
    }

    #[test]
    fn every_digest_encoding_apk_has_written_is_read() {
        use md5::Digest as _;
        let f = Fixture::new("encodings");
        let body = b"payload\n";
        for p in ["a", "b", "c", "d", "e"] {
            f.write(&format!("usr/share/{p}"), body);
        }
        let sha1 = sha1::Sha1::digest(body);
        let sha256 = sha2::Sha256::digest(body);
        let md5 = md5::Md5::digest(body);
        let x1 = format!("X1{}", crate::entry::hex(&sha1));
        let q2 = format!("Q2{}", b64(&sha256));
        // apk 3 in an apk 2 database: the SHA-1-length prefix, then the rest.
        let q1_extended = format!("Q1{}{}", b64(&sha256[..20]), b64(&sha256[20..]));
        let legacy = crate::entry::hex(&md5);
        f.write(
            INSTALLED,
            record("p", "1", &[("usr/share/a", &q1(body)), ("usr/share/b", &x1), ("usr/share/c", &q2), ("usr/share/d", &q1_extended), ("usr/share/e", &legacy)]).as_bytes(),
        );
        let a = ask(&f.root(), &["usr/share/a", "usr/share/b", "usr/share/c", "usr/share/d", "usr/share/e"]);
        for p in ["a", "b", "c", "d", "e"] {
            assert_eq!(integrity(&a, &format!("usr/share/{p}")), Integrity::Intact, "{p}");
        }
    }

    #[test]
    fn protected_paths_d_overrides_the_defaults_in_name_order() {
        let f = Fixture::new("lists");
        let shipped = b"shipped\n";
        for p in ["etc/foo/x", "usr/local/bin/x", "etc/bar/y", "var/lib/z"] {
            f.write(p, b"changed\n");
        }
        f.write(&format!("{PROTECTED_D}/10-site.list"), b"# site policy\n-etc/foo\n+usr/local\n/var/lib/\n");
        f.write(&format!("{PROTECTED_D}/20-later.list"), b"+etc/foo/x\n");
        f.write(&format!("{PROTECTED_D}/ignored.conf"), b"-etc\n");
        let d = q1(shipped);
        f.write(
            INSTALLED,
            record("p", "1", &[("etc/foo/x", &d), ("usr/local/bin/x", &d), ("etc/bar/y", &d), ("var/lib/z", &d)]).as_bytes(),
        );
        let a = ask(&f.root(), &["etc/foo/x", "usr/local/bin/x", "etc/bar/y", "var/lib/z"]);
        assert_eq!(integrity(&a, "etc/foo/x"), Integrity::ConffileModified, "20-later's + outranks 10-site's -");
        assert_eq!(integrity(&a, "usr/local/bin/x"), Integrity::ConffileModified, "+usr/local");
        assert_eq!(integrity(&a, "etc/bar/y"), Integrity::ConffileModified, "still under +etc");
        assert_eq!(integrity(&a, "var/lib/z"), Integrity::ConffileModified, "no mode character is +");
        f.write(&format!("{PROTECTED_D}/20-later.list"), b"");
        let a = ask(&f.root(), &["etc/foo/x"]);
        assert_eq!(integrity(&a, "etc/foo/x"), Integrity::Modified, "-etc/foo unprotects what +etc protected");
    }

    #[test]
    fn a_hostile_database_is_read_as_far_as_it_goes() {
        let f = Fixture::new("hostile");
        f.write("usr/bin/ok", b"ok\n");
        f.write("usr/bin/bad", b"bad\n");
        let db = format!(
            "garbage line\nP\n:x\nZ:Q1before-any-file\na:1:2:3\nP:p\nV:1\nF:usr/bin\nR:ok\nZ:{}\nR:bad\nZ:Q1!!!!\nR:worse\nZ:Q1{}\nR:odd\na:0:0:notoctal\nZ:X1zz\n\nP:q\nF:\nR:rootfile\n",
            q1(b"ok\n"),
            "A".repeat(28)
        );
        f.write(INSTALLED, db.as_bytes());
        let a = ask(&f.root(), &["usr/bin/ok", "usr/bin/bad", "usr/bin/worse", "usr/bin/odd", "rootfile"]);
        assert_eq!(integrity(&a, "usr/bin/ok"), Integrity::Intact);
        assert_eq!(integrity(&a, "usr/bin/bad"), Integrity::Unknown, "an undecodable digest verifies nothing");
        assert_eq!(integrity(&a, "usr/bin/worse"), Integrity::Unknown, "a decodable digest of a missing file");
        assert_eq!(integrity(&a, "usr/bin/odd"), Integrity::Unknown);
        assert!(matches!(&a[Path::new("rootfile")], Provenance::Packaged { package, .. } if package == "q"));
        assert!(packaged_files(&f.root()).contains(Path::new("usr/bin")));
    }

    #[test]
    fn the_digest_decoder_matches_apk() {
        assert_eq!(unhex(b"0aFF"), Some(vec![10, 255]));
        assert_eq!(unhex(b"0a0"), None);
        assert_eq!(digest(b"Q1"), None);
        assert_eq!(digest(b"Q3AAAA"), None);
        assert_eq!(digest(b"Y1AAAA"), None);
        assert_eq!(digest(&b"0".repeat(32)).map(|d| d.0), Some(Alg::Md5));
        assert_eq!(digest(&b"0".repeat(30)), None);
        assert_eq!(digest(&[b"X1".as_slice(), &b"0".repeat(40)].concat()).map(|d| d.0), Some(Alg::Sha1));
        assert_eq!(digest(&[b"X1".as_slice(), &b"0".repeat(64)].concat()).map(|d| d.0), Some(Alg::Sha256));
        assert_eq!(digest(&[b"X2".as_slice(), &b"0".repeat(64)].concat()).map(|d| d.0), Some(Alg::Sha256));
        assert_eq!(digest(&[b"X2".as_slice(), &b"0".repeat(40)].concat()), None);
    }

    /// A ustar archive as apk writes one, a GNU long-name entry ahead of any
    /// name over a hundred bytes.
    pub(crate) fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        fn header(name: &str, size: usize, typeflag: u8) -> Vec<u8> {
            let mut h = vec![0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..108].copy_from_slice(b"0000644\0");
            h[108..116].copy_from_slice(b"0000000\0");
            h[116..124].copy_from_slice(b"0000000\0");
            h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
            h[136..148].copy_from_slice(b"00000000000\0");
            h[148..156].copy_from_slice(b"        ");
            h[156] = typeflag;
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
            let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
            h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            h
        }
        let mut out = Vec::new();
        for (name, body) in entries {
            let short = if name.len() > 100 {
                out.extend(header("././@LongLink", name.len() + 1, b'L'));
                let mut data = name.as_bytes().to_vec();
                data.push(0);
                data.resize(data.len().div_ceil(512) * 512, 0);
                out.extend(data);
                &name[..100]
            } else {
                name
            };
            out.extend(header(short, body.len(), b'0'));
            let mut data = body.to_vec();
            data.resize(data.len().div_ceil(512) * 512, 0);
            out.extend(data);
        }
        out.extend(vec![0u8; 1024]);
        out
    }

    /// The bytes gzip would write: a header naming the file, a raw deflate
    /// stream, and a trailer nobody here reads.
    pub(crate) fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 3];
        out.extend_from_slice(b"scripts.tar\0");
        out.extend(miniz_oxide::deflate::compress_to_vec(bytes, 6));
        out.extend_from_slice(&[0u8; 8]);
        out
    }

    #[test]
    fn the_scripts_archive_is_read_gzipped_or_not() {
        let f = Fixture::new("scripts");
        let long = format!("{}-1.0-r0.Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=.post-install", "x".repeat(120));
        let archive = tar(&[
            ("busybox-1.37.0-r31.X1b5405ebc02f7dd8be95b6265c54b243d5456ab8f.trigger", b"#!/bin/busybox sh\n/bin/busybox --install -s\n"),
            ("busybox-1.37.0-r31.X1b5405ebc02f7dd8be95b6265c54b243d5456ab8f.post-install", b"#!/bin/sh\nexit 0\n"),
            ("alpine-baselayout-3.7.2-r1.Q1tUBevAL33YvpW2JlxUskPVRWq48=.pre-upgrade", b"#!/bin/sh\n"),
            ("notes.txt", b"not a script"),
            ("odd-1.0-r0.Q1garbage.post-install", b"#!/bin/sh\n"),
            (long.as_str(), b"#!/bin/sh\n"),
        ]);
        f.write(SCRIPTS_GZ, &gzip(&archive));
        let (path, scripts) = scripts(&f.root()).unwrap();
        assert_eq!(path, SCRIPTS_GZ);
        let names: Vec<(String, String, String)> = scripts.iter().map(|s| (s.package.clone(), s.version.clone(), s.phase.clone())).collect();
        assert_eq!(
            names,
            [
                ("busybox".to_string(), "1.37.0-r31".to_string(), "trigger".to_string()),
                ("busybox".to_string(), "1.37.0-r31".to_string(), "post-install".to_string()),
                ("alpine-baselayout".to_string(), "3.7.2-r1".to_string(), "pre-upgrade".to_string()),
                ("x".repeat(120), "1.0-r0".to_string(), "post-install".to_string()),
            ]
        );
        assert_eq!(scripts[0].digest, "b5405ebc02f7dd8be95b6265c54b243d5456ab8f");
        assert_eq!(scripts[2].digest, "b5405ebc02f7dd8be95b6265c54b243d5456ab8f", "Q1 and X1 spell one digest");
        assert_eq!(scripts[0].body, b"#!/bin/busybox sh\n/bin/busybox --install -s\n");

        std::fs::remove_file(f.0.join(SCRIPTS_GZ)).unwrap();
        f.write(SCRIPTS_TAR, &archive);
        let (path, plain) = super::scripts(&f.root()).unwrap();
        assert_eq!((path, plain.len()), (SCRIPTS_TAR, 4), "apk 2 keeps it uncompressed");
    }

    #[test]
    fn triggers_resolve_to_the_package_whose_checksum_they_carry() {
        let f = Fixture::new("triggers");
        f.write(
            INSTALLED,
            b"C:Q1tUBevAL33YvpW2JlxUskPVRWq48=\nP:busybox\nV:1.37.0-r31\n\nC:Q1xvm97RfYRLbxsLtXZtLDXA1chQg=\nP:kmod\nV:33-r0\n",
        );
        f.write(TRIGGERS, b"Q1tUBevAL33YvpW2JlxUskPVRWq48= /bin /usr/bin /lib/modules/*\nX1ffffffffffffffffffffffffffffffffffffffff /etc/x\nnot-a-digest /y\n\n");
        let (_, triggers) = triggers(&f.root()).unwrap();
        assert_eq!(triggers.len(), 2);
        assert_eq!(triggers[0].package, Some(("busybox".to_string(), "1.37.0-r31".to_string())));
        assert_eq!(triggers[0].dirs, ["/bin", "/usr/bin", "/lib/modules/*"]);
        assert_eq!(triggers[1].package, None);
    }

    #[test]
    fn hostile_archives_and_headers_yield_nothing_rather_than_a_panic() {
        let f = Fixture::new("hostile-archive");
        for (i, bytes) in [
            vec![0x1f, 0x8b],
            vec![0x1f, 0x8b, 8, 0xff, 0, 0, 0, 0, 0, 3, 0xff, 0xff],
            vec![0x1f, 0x8b, 8, 0x04, 0, 0, 0, 0, 0, 3, 0xff, 0xff, 1],
            vec![0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 3, b'n', b'o', b'n', b'u', b'l'],
            gzip(b"not a tar"),
            gzip(&{
                let mut t = tar(&[("a-1-r0.Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=.trigger", b"x")]);
                t[124..136].copy_from_slice(b"77777777777\0");
                t
            }),
            gzip(&tar(&[("a-1-r0.Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=.trigger", b"x")])[..600].to_vec()),
        ]
        .into_iter()
        .enumerate()
        {
            f.write(SCRIPTS_GZ, &bytes);
            let got = super::scripts(&f.root()).map(|(_, s)| s.len());
            assert!(got.is_none() || got == Some(0) || i >= 5, "case {i}: {got:?}");
        }
        assert_eq!(tar_entries(&[0u8; 511]).len(), 0);
        assert_eq!(tar_entries(b"\x00".repeat(1024).as_slice()).len(), 0);
        assert!(gunzip(&[]).is_none());
    }
}
