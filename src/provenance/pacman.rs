//! pacman's local database, for Arch Linux and its derivatives.
//!
//! `/var/lib/pacman/local` holds one directory per installed package, named
//! `<name>-<version>-<release>`. Its `files` lists every path the package
//! owns (directories end in `/`) and, under `%BACKUP%`, the configuration
//! files with the md5 of the copy shipped. Its `mtree` is a gzip of the
//! build's manifest: a sha256 for every file, the mode, and the target of
//! every link. Together they answer the question this module exists for: who
//! owns this path, and are its bytes still what the package installed?
//!
//! Like the other backends it streams the database once and answers only
//! the paths asked for; an `mtree` is read only for a package that owns one.
//! A package directory that cannot be read leaves the answer incomplete, so
//! what it might have owned is Unknown rather than Unpackaged.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::entry::{Integrity, Provenance};
use crate::root::Root;

use super::{Answers, Outcome, spellings};

const LOCAL: &str = "var/lib/pacman/local";

/// A package's `files`. The largest on a full desktop is a few hundred
/// kilobytes; the cap is a backstop.
const FILES_CAP: usize = 16 << 20;

/// A package's `mtree`, compressed and unpacked. Firmware packages run to
/// megabytes of text.
const MTREE_CAP: usize = 64 << 20;

/// Packages one database may hold before it is read as truncated: a desktop
/// carries a couple of thousand.
const MAX_PACKAGES: usize = 100_000;

pub fn present(root: &Root) -> bool {
    root.exists(LOCAL)
}

/// `name-version-release` split into the name and `version-release`. The
/// name may hold hyphens, the version may hold an epoch (`1:2.3-1`) but not
/// a hyphen of its own, so the last two hyphens divide them.
fn split_dir_name(dir: &str) -> Option<(&str, &str)> {
    let release = dir.rfind('-')?;
    let version = dir[..release].rfind('-')?;
    (version > 0).then(|| (&dir[..version], &dir[version + 1..]))
}

struct Pkg {
    dir: String,
    name: String,
    version: String,
}

/// The packages the database lists, or why it could not be listed.
fn packages(root: &Root) -> Result<Vec<Pkg>, String> {
    let entries = root.read_dir(LOCAL).map_err(|e| format!("{LOCAL} could not be listed: {e}"))?;
    let mut out = Vec::new();
    for ent in entries {
        let dir = ent.name.to_string_lossy().into_owned();
        if !ent.is_dir || ent.is_symlink {
            continue;
        }
        let Some((name, version)) = split_dir_name(&dir) else { continue };
        if out.len() >= MAX_PACKAGES {
            return Err(format!("{LOCAL} lists more than {MAX_PACKAGES} packages"));
        }
        out.push(Pkg { name: name.to_string(), version: version.to_string(), dir });
    }
    Ok(out)
}

/// What a `files` list holds.
#[derive(Default)]
struct Files {
    /// Every path, directories without their trailing slash.
    paths: Vec<Vec<u8>>,
    /// Configuration files and the md5 of the copy shipped.
    backups: BTreeMap<Vec<u8>, String>,
}

fn parse_files(bytes: &[u8]) -> Files {
    let mut out = Files::default();
    let mut section: &[u8] = b"";
    for line in bytes.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line.len() > 2 && line[0] == b'%' && line[line.len() - 1] == b'%' {
            section = line;
            continue;
        }
        match section {
            b"%FILES%" => {
                let path = line.strip_suffix(b"/").unwrap_or(line);
                if !path.is_empty() {
                    out.paths.push(path.to_vec());
                }
            }
            b"%BACKUP%" => {
                if let Some(tab) = line.iter().position(|b| *b == b'\t') {
                    let md5 = String::from_utf8_lossy(&line[tab + 1..]).to_ascii_lowercase();
                    out.backups.insert(line[..tab].to_vec(), md5);
                }
            }
            _ => {}
        }
    }
    out
}

/// Every path the database claims, files and directories alike,
/// root-relative.
pub fn packaged_files(root: &Root) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    let Ok(pkgs) = packages(root) else { return out };
    for pkg in pkgs {
        let Ok((bytes, _)) = root.read_capped(Path::new(LOCAL).join(&pkg.dir).join("files"), FILES_CAP) else { continue };
        for path in parse_files(&bytes).paths {
            out.insert(PathBuf::from(OsStr::from_bytes(&path)));
        }
    }
    out
}

/// What the manifest says about one path.
#[derive(Default, Clone, Debug, PartialEq)]
struct Facts {
    is_dir: bool,
    sha256: Option<String>,
    link: Option<Vec<u8>>,
    mode: Option<u32>,
}

/// mtree writes a space, a tab, a backslash and the like as `\NNN`, octal.
fn unescape(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'\\'
            && i + 4 <= text.len()
            && text[i + 1..i + 4].iter().all(|b| (b'0'..=b'7').contains(b))
        {
            let value = text[i + 1..i + 4].iter().fold(0u32, |n, b| n * 8 + u32::from(b - b'0'));
            out.push(value as u8);
            i += 4;
        } else {
            out.push(text[i]);
            i += 1;
        }
    }
    out
}

/// The manifest's entries for `wanted` (root-relative, no `./`), in one pass.
fn mtree_facts(gz: &[u8], wanted: &BTreeSet<Vec<u8>>) -> BTreeMap<Vec<u8>, Facts> {
    let mut out = BTreeMap::new();
    let Some(text) = super::apk::gunzip(gz) else { return out };
    let mut default_mode: Option<u32> = None;
    let mut default_type_dir = false;
    for line in text.split(|b| *b == b'\n') {
        let mut words = line.split(|b| *b == b' ').filter(|w| !w.is_empty());
        let Some(first) = words.next() else { continue };
        if first == b"/set" {
            for w in words {
                if let Some(v) = w.strip_prefix(b"mode=") {
                    default_mode = std::str::from_utf8(v).ok().and_then(|v| u32::from_str_radix(v, 8).ok());
                } else if let Some(v) = w.strip_prefix(b"type=") {
                    default_type_dir = v == b"dir";
                }
            }
            continue;
        }
        if first == b"/unset" {
            continue;
        }
        let name = unescape(first.strip_prefix(b"./").unwrap_or(first));
        if !wanted.contains(&name) {
            continue;
        }
        let mut facts = Facts { is_dir: default_type_dir, mode: default_mode, ..Facts::default() };
        for w in words {
            if let Some(v) = w.strip_prefix(b"type=") {
                facts.is_dir = v == b"dir";
                if v == b"link" {
                    facts.is_dir = false;
                }
            } else if let Some(v) = w.strip_prefix(b"mode=") {
                facts.mode = std::str::from_utf8(v).ok().and_then(|v| u32::from_str_radix(v, 8).ok());
            } else if let Some(v) = w.strip_prefix(b"sha256digest=") {
                facts.sha256 = Some(String::from_utf8_lossy(v).to_ascii_lowercase());
            } else if let Some(v) = w.strip_prefix(b"link=") {
                facts.link = Some(unescape(v));
            }
        }
        out.insert(name, facts);
    }
    out
}

pub fn resolve(root: &Root, wanted: &BTreeSet<PathBuf>) -> Outcome {
    if !present(root) {
        return Outcome::Absent;
    }
    let pkgs = match packages(root) {
        Ok(p) => p,
        Err(why) => return Outcome::Incomplete(Answers::new(), why),
    };

    let mut alias_to_wanted: BTreeMap<Vec<u8>, Vec<PathBuf>> = BTreeMap::new();
    for w in wanted {
        for alias in spellings(root, w) {
            alias_to_wanted.entry(alias.as_os_str().as_bytes().to_vec()).or_default().push(w.clone());
        }
    }

    let mut out = Answers::new();
    let mut unread = Vec::new();
    for pkg in &pkgs {
        let dir = Path::new(LOCAL).join(&pkg.dir);
        let (bytes, truncated) = match root.read_capped(dir.join("files"), FILES_CAP) {
            Ok(read) => read,
            Err(e) => {
                unread.push(format!("{}: {e}", pkg.dir));
                continue;
            }
        };
        if truncated {
            unread.push(format!("{}: files is larger than the read cap", pkg.dir));
        }
        let files = parse_files(&bytes);
        let owned: Vec<&Vec<u8>> = files.paths.iter().filter(|p| alias_to_wanted.contains_key(p.as_slice())).collect();
        if owned.is_empty() {
            continue;
        }
        let facts = match root.read_capped(dir.join("mtree"), MTREE_CAP) {
            Ok((gz, _)) => mtree_facts(&gz, &owned.iter().map(|p| (*p).clone()).collect()),
            Err(_) => BTreeMap::new(),
        };
        for path in owned {
            let f = facts.get(path).cloned().unwrap_or_default();
            for w in &alias_to_wanted[path.as_slice()] {
                let integrity = verify(root, w, &f, files.backups.get(path.as_slice()));
                out.insert(
                    w.clone(),
                    Provenance::Packaged { package: pkg.name.clone(), version: pkg.version.clone(), integrity },
                );
            }
        }
    }
    if !unread.is_empty() {
        let shown = unread.iter().take(3).cloned().collect::<Vec<_>>().join("; ");
        return Outcome::Incomplete(out, format!("{} package records could not be read: {shown}", unread.len()));
    }
    Outcome::Complete(out)
}

fn verify(root: &Root, rel: &Path, facts: &Facts, backup: Option<&String>) -> Integrity {
    if facts.is_dir {
        return Integrity::Unknown;
    }
    let Ok(meta) = root.stat(rel) else { return Integrity::Unknown };
    let conffile = backup.is_some();
    if let Some(shipped) = &facts.link {
        if !meta.is_symlink {
            return if conffile { Integrity::ConffileModified } else { Integrity::Modified };
        }
        return match root.read_link(rel) {
            Ok(t) if t.as_os_str().as_bytes() == shipped.as_slice() => Integrity::Intact,
            Ok(_) => Integrity::Modified,
            Err(_) => Integrity::Unknown,
        };
    }
    let Some(expected) = &facts.sha256 else { return Integrity::Unknown };
    let Some(actual) = super::digests(root, rel).map(|d| d.sha256) else { return Integrity::Unknown };
    if actual.eq_ignore_ascii_case(expected) {
        // Contents match; a setuid or setgid bit the package did not ship is
        // the rpm backend's ModeModified.
        let privilege = |m: u32| m & 0o6000;
        return match facts.mode {
            Some(shipped) if privilege(shipped) != privilege(meta.mode) => Integrity::ModeModified,
            _ => Integrity::Intact,
        };
    }
    if conffile { Integrity::ConffileModified } else { Integrity::Modified }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::apk::tests::gzip;

    fn sha256(content: &[u8]) -> String {
        crate::entry::hex(&<sha2::Sha256 as sha2::Digest>::digest(content))
    }

    struct Db(crate::testing::Tree);

    impl Db {
        fn new(tag: &str) -> Db {
            let tree = crate::testing::Tree::new(&format!("pacman-{tag}"));
            std::fs::create_dir_all(tree.join(LOCAL)).unwrap();
            Db(tree)
        }
        fn put(&self, rel: &str, content: &[u8]) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        }
        /// A package whose manifest holds `(path, sha256 or link)` and whose
        /// list names the same paths; `backup` are the config files.
        fn package(&self, dir: &str, files: &[(&str, &str)], backup: &[&str]) {
            let mut list = String::from("%FILES%\n");
            let mut mtree = String::from("#mtree\n/set type=file uid=0 gid=0 mode=644\n");
            for (path, attr) in files {
                list.push_str(&format!("{path}\n"));
                mtree.push_str(&format!("./{} time=1.0 {attr}\n", path.replace(' ', "\\040")));
            }
            if !backup.is_empty() {
                list.push_str("\n%BACKUP%\n");
                for b in backup {
                    list.push_str(&format!("{b}\t00000000000000000000000000000000\n"));
                }
            }
            self.put(&format!("{LOCAL}/{dir}/files"), list.as_bytes());
            self.put(&format!("{LOCAL}/{dir}/mtree"), &gzip(mtree.as_bytes()));
        }
        fn root(&self) -> Root {
            Root::at(&self.0).unwrap()
        }
    }

    fn wanted(paths: &[&str]) -> BTreeSet<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    fn integrity(a: &Answers, path: &str) -> Integrity {
        match &a[Path::new(path)] {
            Provenance::Packaged { integrity, .. } => *integrity,
            other => panic!("{path}: {other:?}"),
        }
    }

    #[test]
    fn a_package_directory_name_splits_at_its_last_two_hyphens() {
        assert_eq!(split_dir_name("bash-5.3.20-1"), Some(("bash", "5.3.20-1")));
        assert_eq!(split_dir_name("gtk-update-icon-cache-1:4.0-2"), Some(("gtk-update-icon-cache", "1:4.0-2")));
        assert_eq!(split_dir_name("nohyphens"), None);
        assert_eq!(split_dir_name("one-hyphen"), None);
    }

    #[test]
    fn owned_paths_are_judged_by_the_manifest() {
        let db = Db::new("judge");
        db.put("usr/bin/tool", b"binary");
        db.put("usr/bin/edited", b"changed after");
        db.put("etc/tool.conf", b"local settings");
        db.put("usr/bin/setuid", b"binary");
        db.put("usr/share/with space", b"x");
        std::os::unix::fs::symlink("tool", db.0.join("usr/bin/alias")).unwrap();
        std::os::unix::fs::symlink("elsewhere", db.0.join("usr/bin/moved")).unwrap();
        db.package(
            "tool-1.0-1",
            &[
                ("usr/bin/tool", &format!("size=6 sha256digest={}", sha256(b"binary"))),
                ("usr/bin/edited", &format!("size=7 sha256digest={}", sha256(b"original"))),
                ("etc/tool.conf", &format!("size=3 sha256digest={}", sha256(b"shipped settings"))),
                ("usr/bin/setuid", &format!("size=6 mode=755 sha256digest={}", sha256(b"binary"))),
                ("usr/share/with space", &format!("size=1 sha256digest={}", sha256(b"x"))),
                ("usr/bin/alias", "type=link link=tool"),
                ("usr/bin/moved", "type=link link=original"),
            ],
            &["etc/tool.conf"],
        );
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(db.0.join("usr/bin/setuid"), std::fs::Permissions::from_mode(0o4755)).unwrap();
        let root = db.root();
        let a = resolve(
            &root,
            &wanted(&["usr/bin/tool", "usr/bin/edited", "etc/tool.conf", "usr/bin/setuid", "usr/share/with space", "usr/bin/alias", "usr/bin/moved", "usr/bin/stranger"]),
        )
        .unwrap();
        assert_eq!(integrity(&a, "usr/bin/tool"), Integrity::Intact);
        assert_eq!(integrity(&a, "usr/bin/edited"), Integrity::Modified);
        assert_eq!(integrity(&a, "etc/tool.conf"), Integrity::ConffileModified, "a config file the admin edited is expected");
        assert_eq!(integrity(&a, "usr/bin/setuid"), Integrity::ModeModified);
        assert_eq!(integrity(&a, "usr/share/with space"), Integrity::Intact, "mtree escapes a space as \\040");
        assert_eq!(integrity(&a, "usr/bin/alias"), Integrity::Intact);
        assert_eq!(integrity(&a, "usr/bin/moved"), Integrity::Modified);
        assert!(!a.contains_key(Path::new("usr/bin/stranger")), "nobody's file is left to the caller to call unpackaged");
        match &a[Path::new("usr/bin/tool")] {
            Provenance::Packaged { package, version, .. } => assert_eq!((package.as_str(), version.as_str()), ("tool", "1.0-1")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_record_that_cannot_be_read_leaves_the_rest_unknown_not_unpackaged() {
        let db = Db::new("incomplete");
        db.package("tool-1.0-1", &[("usr/bin/tool", &format!("size=6 sha256digest={}", sha256(b"binary")))], &[]);
        std::fs::create_dir_all(db.0.join(LOCAL).join("broken-2.0-1")).unwrap();
        db.put("usr/bin/tool", b"binary");
        match resolve(&db.root(), &wanted(&["usr/bin/tool", "usr/bin/other"])) {
            Outcome::Incomplete(answers, why) => {
                assert!(answers.contains_key(Path::new("usr/bin/tool")));
                assert!(why.contains("broken-2.0-1"), "{why}");
            }
            _ => panic!("a package with no files list must make the answer incomplete"),
        }
    }

    #[test]
    fn no_database_is_absent() {
        let tree = crate::testing::Tree::new("pacman-none");
        assert!(matches!(resolve(&Root::at(&tree).unwrap(), &wanted(&["usr/bin/x"])), Outcome::Absent));
    }

    #[test]
    fn the_whole_claim_includes_directories() {
        let db = Db::new("claims");
        db.put(&format!("{LOCAL}/tool-1.0-1/files"), b"%FILES%\nusr/\nusr/bin/\nusr/bin/tool\n");
        let claimed = packaged_files(&db.root());
        assert!(claimed.contains(Path::new("usr/bin")) && claimed.contains(Path::new("usr/bin/tool")));
    }
}
