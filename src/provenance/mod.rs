//! Which package shipped this file, and does it still match?
//!
//! This is the Linux answer to Autoruns' signature check, and a stronger
//! signal: instead of asking whether a binary is signed, it asks whether any
//! package claims the file and whether its bytes still match what was
//! installed. "Is this supposed to be here?" stops being a judgement call.
//!
//! Resolution is targeted rather than exhaustive. A desktop carries half a
//! million packaged files and a scan asks about a few thousand, so the
//! backends stream their databases once and answer only the paths asked for.
//! Building a full path index would be the most expensive part of a scan.

pub mod dpkg;
pub mod generated;
pub mod rpm;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::entry::Provenance;
use crate::root::Root;

pub type Answers = BTreeMap<PathBuf, Provenance>;

/// What the provenance pass learned, and which backends it could not ask.
pub struct Resolution {
    pub answers: Answers,
    /// Backends that panicked on their database. §3 treats every parsed file
    /// as hostile, and a package database is a file.
    pub failures: Vec<String>,
}

/// Paths are root-relative throughout, matching every other filesystem
/// operation in the tool.
///
/// The package databases answer first, for every path. A runtime producer is
/// only ever asked about a path no package claims: the GeneratedBy verdict
/// takes Unpackaged away, and a file a package ships must be checked against
/// that package whatever it happens to be called.
pub fn resolve(root: &Root, wanted: &BTreeSet<PathBuf>) -> Resolution {
    resolve_with(root, wanted, &[("dpkg", dpkg::resolve), ("rpm", rpm::resolve)])
}

type Backend = fn(&Root, &BTreeSet<PathBuf>) -> Option<Answers>;

fn resolve_with(root: &Root, wanted: &BTreeSet<PathBuf>, backends: &[(&str, Backend)]) -> Resolution {
    let mut out = Answers::new();
    let mut failures = Vec::new();

    // A backend returns None when its database is not on this root, which is
    // a different fact from "the database says nothing owns that path". One
    // that panics is a third fact: its database is there, and what it would
    // have said is unknown.
    let mut backend_ran = false;
    let mut backend_failed = false;
    for (name, backend) in backends {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| backend(root, wanted))) {
            Ok(Some(answers)) => {
                out.extend(answers);
                backend_ran = true;
            }
            Ok(None) => {}
            Err(payload) => {
                failures.push(format!("{name} database: {}", crate::scan::panic_message(payload)));
                backend_failed = true;
            }
        }
    }

    let unclaimed: BTreeSet<PathBuf> = wanted.iter().filter(|p| !out.contains_key(*p)).cloned().collect();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| generated::classify(root, &unclaimed))) {
        Ok(answers) => out.extend(answers),
        Err(payload) => failures.push(format!("runtime producers: {}", crate::scan::panic_message(payload))),
    }

    // A path no backend claimed is Unpackaged only if a backend actually ran
    // and none failed. Without a package database the honest answer is
    // Unknown — silently calling every file unpackaged would flag the whole
    // system — and the same holds when a database was there but could not be
    // read to the end: any of these paths might have been in it.
    let verdict = if backend_ran && !backend_failed { Provenance::Unpackaged } else { Provenance::Unknown };
    for p in wanted {
        out.entry(p.clone()).or_insert_with(|| verdict.clone());
    }
    Resolution { answers: out, failures }
}

/// Aliased paths under merged /usr. Every supported distribution ships
/// /lib as a symlink to /usr/lib, and package databases are inconsistent
/// about which spelling they record, so a lookup must try both.
pub fn usr_aliases(rel: &Path) -> Vec<PathBuf> {
    const ALIASED: [&str; 4] = ["bin", "sbin", "lib", "lib64"];
    let mut out = vec![rel.to_path_buf()];
    let text = rel.to_string_lossy();
    for dir in ALIASED {
        if let Some(rest) = text.strip_prefix(&format!("usr/{dir}/")) {
            out.push(PathBuf::from(format!("{dir}/{rest}")));
        } else if let Some(rest) = text.strip_prefix(&format!("{dir}/")) {
            out.push(PathBuf::from(format!("usr/{dir}/{rest}")));
        }
    }
    out
}

pub struct FileDigests {
    pub sha256: String,
    pub md5: String,
    pub size: u64,
}

/// A file large enough that hashing it is not worth an incident responder's
/// wall clock. Reported as an unknown digest rather than silently skipped.
pub const HASH_SIZE_LIMIT: u64 = 256 << 20;

/// One read, both digests: the reported sha256 of §4 and the md5 that dpkg
/// manifests are written in.
pub fn digests(root: &Root, rel: &Path) -> Option<FileDigests> {
    use md5::Digest as _;

    let meta = root.stat_follow(rel).ok()?;
    if !meta.is_file || meta.size > HASH_SIZE_LIMIT {
        return None;
    }
    let mut file = root.open(rel).ok()?;
    let mut sha = <sha2::Sha256 as sha2::Digest>::new();
    let mut md5 = md5::Md5::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                sha2::Digest::update(&mut sha, &buf[..n]);
                md5.update(&buf[..n]);
                size += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(FileDigests {
        sha256: crate::entry::hex(&sha2::Digest::finalize(sha)),
        md5: crate::entry::hex(&md5.finalize()),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merged_usr_lookups_try_both_spellings() {
        let both = usr_aliases(Path::new("usr/lib/systemd/system/ssh.service"));
        assert!(both.contains(&PathBuf::from("usr/lib/systemd/system/ssh.service")));
        assert!(both.contains(&PathBuf::from("lib/systemd/system/ssh.service")));

        let both = usr_aliases(Path::new("bin/sh"));
        assert!(both.contains(&PathBuf::from("usr/bin/sh")));

        assert_eq!(usr_aliases(Path::new("etc/crontab")), vec![PathBuf::from("etc/crontab")]);
    }

    #[test]
    fn no_package_database_means_unknown_not_unpackaged() {
        let dir = std::env::temp_dir().join(format!("unbidden-prov-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/crontab"), b"x").unwrap();
        let root = Root::at(&dir).unwrap();

        let wanted: BTreeSet<PathBuf> = [PathBuf::from("etc/crontab")].into_iter().collect();
        assert_eq!(resolve(&root, &wanted).answers[Path::new("etc/crontab")], Provenance::Unknown);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_packaged_file_is_checked_against_its_package_whatever_it_is_called() {
        // snap-confine is setuid root and shipped by the snapd package. A
        // name rule that ran first used to call it snapd's and skip the
        // integrity check, so a trojaned copy read as nothing at all.
        let dir = std::env::temp_dir().join(format!("unbidden-prov-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["usr/lib/snapd", "var/lib/dpkg/info", "etc/systemd/system"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(dir.join("usr/lib/snapd/snap-confine"), b"trojaned").unwrap();
        std::fs::write(dir.join("etc/systemd/system/snap.evil.x.service"), b"[Service]\nExecStart=/tmp/x\n").unwrap();
        std::fs::write(
            dir.join("var/lib/dpkg/status"),
            b"Package: snapd\nStatus: install ok installed\nVersion: 2.66\n\n",
        )
        .unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/snapd.list"), b"/usr/lib/snapd/snap-confine\n").unwrap();
        std::fs::write(
            dir.join("var/lib/dpkg/info/snapd.md5sums"),
            b"0123456789abcdef0123456789abcdef  usr/lib/snapd/snap-confine\n",
        )
        .unwrap();

        let root = Root::at(&dir).unwrap();
        let wanted: BTreeSet<PathBuf> =
            ["usr/lib/snapd/snap-confine", "etc/systemd/system/snap.evil.x.service"].iter().map(PathBuf::from).collect();
        let answers = resolve(&root, &wanted).answers;
        assert!(matches!(
            &answers[Path::new("usr/lib/snapd/snap-confine")],
            Provenance::Packaged { integrity: crate::entry::Integrity::Modified, .. }
        ));
        assert_eq!(answers[Path::new("etc/systemd/system/snap.evil.x.service")], Provenance::Unpackaged);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_backend_that_panics_leaves_its_paths_unknown_not_unpackaged() {
        // A package database is a file an attacker can write. If reading it
        // panics, every path it might have claimed is unknown; calling them
        // unpackaged would flag the whole system on the attacker's say-so.
        fn owns_one(_: &Root, _: &BTreeSet<PathBuf>) -> Option<Answers> {
            let mut a = Answers::new();
            a.insert(PathBuf::from("usr/bin/ok"), Provenance::Unpackaged);
            Some(a)
        }
        fn explodes(_: &Root, _: &BTreeSet<PathBuf>) -> Option<Answers> {
            panic!("header index 4294967295 out of range")
        }
        let dir = std::env::temp_dir().join(format!("unbidden-prov-panic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = Root::at(&dir).unwrap();
        let wanted: BTreeSet<PathBuf> = ["usr/bin/ok", "etc/other"].iter().map(PathBuf::from).collect();

        let r = resolve_with(&root, &wanted, &[("dpkg", owns_one), ("rpm", explodes)]);
        assert_eq!(r.failures.len(), 1);
        assert!(r.failures[0].starts_with("rpm database: header index"), "{:?}", r.failures);
        assert_eq!(r.answers[Path::new("usr/bin/ok")], Provenance::Unpackaged, "what dpkg said stands");
        assert_eq!(r.answers[Path::new("etc/other")], Provenance::Unknown);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_read_yields_both_digests() {
        let dir = std::env::temp_dir().join(format!("unbidden-dig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f"), b"abc").unwrap();
        let root = Root::at(&dir).unwrap();
        let d = digests(&root, Path::new("f")).unwrap();
        assert_eq!(d.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(d.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(d.size, 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
