//! The dpkg backend: plain text throughout, so no dependency and no shelling
//! out to `dpkg -S`, which on a compromised host is a wrapper that lies.
//!
//! Three files answer the question. `info/*.list` says which package owns a
//! path, `status` gives the version and the conffile manifest, and
//! `info/*.md5sums` gives the digest the package shipped.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::entry::{Integrity, Provenance};
use crate::root::Root;

use super::{Answers, usr_aliases};

const INFO: &str = "var/lib/dpkg/info";
const STATUS: &str = "var/lib/dpkg/status";

/// File lists and the status database are large on a full desktop but are
/// root-owned system files; the cap is a backstop, not a parsing limit.
const DB_CAP: usize = 64 << 20;

pub fn present(root: &Root) -> bool {
    root.exists(STATUS)
}

pub fn resolve(root: &Root, wanted: &BTreeSet<PathBuf>) -> Option<Answers> {
    if !present(root) {
        return None;
    }

    // Every spelling of every wanted path, mapped back to the one the caller
    // asked about, so a /lib vs /usr/lib mismatch cannot lose an answer.
    // One spelling can be the alias of several wanted paths: the moment a
    // scan asks about both `bin/sh` and `usr/bin/sh` — which it does as soon
    // as anything names /bin/sh — they alias to each other, and a map of one
    // value silently dropped whichever was inserted first. The path that lost
    // was then answered by nobody and reported Unpackaged.
    let mut alias_to_wanted: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    for w in wanted {
        for alias in usr_aliases(w) {
            alias_to_wanted.entry(alias).or_default().push(w.clone());
        }
    }

    let mut owner: BTreeMap<PathBuf, String> = BTreeMap::new();
    for ent in root.read_dir_optional(INFO).unwrap_or_default() {
        let name = ent.name.to_string_lossy().into_owned();
        let Some(pkg) = name.strip_suffix(".list") else { continue };
        let Ok((bytes, _)) = root.read_capped(format!("{INFO}/{name}"), DB_CAP) else { continue };
        for line in bytes.split(|b| *b == b'\n') {
            let listed = strip_slash(line);
            if listed.is_empty() {
                continue;
            }
            if let Some(ws) = alias_to_wanted.get(Path::new(&String::from_utf8_lossy(listed).into_owned())) {
                for w in ws {
                    owner.insert(w.clone(), pkg.to_string());
                }
            }
        }
    }

    if owner.is_empty() {
        return Some(Answers::new());
    }

    let needed: BTreeSet<String> = owner.values().cloned().collect();
    let status = read_status(root, &needed);

    let mut out = Answers::new();
    for (path, pkg) in &owner {
        let Some(info) = status.get(pkg) else { continue };
        let integrity = verify(root, path, pkg, info);
        out.insert(path.clone(), Provenance::Packaged {
            package: base_name(pkg).to_string(),
            version: info.version.clone(),
            integrity,
        });
    }
    Some(out)
}

#[derive(Default)]
struct PkgInfo {
    version: String,
    /// Path (no leading slash) to the digest dpkg shipped. A conffile is
    /// expected to differ from it; that is what a conffile is for.
    conffiles: BTreeMap<String, String>,
}

/// Streams the status file once, keeping only the packages that own
/// something the scan asked about.
fn read_status(root: &Root, needed: &BTreeSet<String>) -> BTreeMap<String, PkgInfo> {
    let mut out = BTreeMap::new();
    let Ok((bytes, _)) = root.read_capped(STATUS, DB_CAP) else { return out };
    let text = String::from_utf8_lossy(&bytes);

    let mut package = String::new();
    let mut arch = String::new();
    let mut info = PkgInfo::default();
    let mut in_conffiles = false;

    let flush = |package: &mut String, arch: &mut String, info: &mut PkgInfo, out: &mut BTreeMap<String, PkgInfo>| {
        if package.is_empty() {
            return;
        }
        let taken = std::mem::take(info);
        let qualified = format!("{package}:{arch}");
        for key in [package.clone(), qualified] {
            if needed.contains(&key) {
                out.insert(key, PkgInfo { version: taken.version.clone(), conffiles: taken.conffiles.clone() });
            }
        }
        package.clear();
        arch.clear();
    };

    for line in text.lines() {
        if line.is_empty() {
            flush(&mut package, &mut arch, &mut info, &mut out);
            in_conffiles = false;
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if in_conffiles {
                // " /etc/ssh/sshd_config 0fd9... [obsolete]"
                let mut parts = line.split_whitespace();
                if let (Some(path), Some(digest)) = (parts.next(), parts.next()) {
                    info.conffiles.insert(strip_slash_str(path).to_string(), digest.to_string());
                }
            }
            continue;
        }
        in_conffiles = false;
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match key {
            "Package" => package = value.to_string(),
            "Architecture" => arch = value.to_string(),
            "Version" => info.version = value.to_string(),
            "Conffiles" => in_conffiles = true,
            _ => {}
        }
    }
    flush(&mut package, &mut arch, &mut info, &mut out);
    out
}

fn verify(root: &Root, path: &Path, pkg: &str, info: &PkgInfo) -> Integrity {
    let Some(actual) = super::digests(root, path) else {
        return Integrity::Unknown;
    };

    // A conffile is checked against the digest dpkg recorded for it, and a
    // difference is expected rather than alarming. Without this, every host
    // with an edited sshd_config lights up.
    for spelling in usr_aliases(path) {
        let key = spelling.to_string_lossy().into_owned();
        if let Some(expected) = info.conffiles.get(&key) {
            return if expected.eq_ignore_ascii_case(&actual.md5) {
                Integrity::Intact
            } else {
                Integrity::ConffileModified
            };
        }
    }

    match shipped_digest(root, pkg, path) {
        // Not every package ships md5sums, and a path may be absent from one
        // that does. Integrity is then genuinely unknown; calling it intact
        // would give false assurance about exactly the file an attacker
        // replaced.
        None => Integrity::Unknown,
        Some(expected) if expected.eq_ignore_ascii_case(&actual.md5) => Integrity::Intact,
        Some(_) => Integrity::Modified,
    }
}

fn shipped_digest(root: &Root, pkg: &str, path: &Path) -> Option<String> {
    let (bytes, _) = root.read_capped(format!("{INFO}/{pkg}.md5sums"), DB_CAP).ok()?;
    let aliases: Vec<String> =
        usr_aliases(path).iter().map(|p| p.to_string_lossy().into_owned()).collect();
    for line in bytes.split(|b| *b == b'\n') {
        let line = String::from_utf8_lossy(line);
        let Some((digest, listed)) = line.split_once(char::is_whitespace) else { continue };
        let listed = strip_slash_str(listed.trim());
        if aliases.iter().any(|a| a == listed) {
            return Some(digest.to_string());
        }
    }
    None
}

fn base_name(pkg: &str) -> &str {
    pkg.split(':').next().unwrap_or(pkg)
}

fn strip_slash(line: &[u8]) -> &[u8] {
    let line = match line.strip_suffix(b"\r") {
        Some(l) => l,
        None => line,
    };
    line.strip_prefix(b"/").unwrap_or(line)
}

fn strip_slash_str(s: &str) -> &str {
    s.strip_prefix('/').unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(tag: &str) -> Fixture {
            let dir = std::env::temp_dir().join(format!("unbidden-dpkg-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join(INFO)).unwrap();
            Fixture(dir)
        }
        fn write(&self, rel: &str, content: &[u8]) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        }
        fn root(&self) -> Root {
            Root::at(&self.0).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn md5_of(content: &[u8]) -> String {
        use md5::Digest as _;
        let mut h = md5::Md5::new();
        h.update(content);
        crate::entry::hex(&h.finalize())
    }

    fn ask(root: &Root, paths: &[&str]) -> Answers {
        let wanted: BTreeSet<PathBuf> = paths.iter().map(PathBuf::from).collect();
        resolve(root, &wanted).unwrap()
    }

    #[test]
    fn an_edited_conffile_is_not_a_modified_package_file() {
        let f = Fixture::new("conffile");
        let shipped = b"PermitRootLogin no\n";
        f.write("etc/ssh/sshd_config", b"PermitRootLogin yes\n");
        f.write("usr/lib/systemd/system/ssh.service", b"[Service]\nExecStart=/usr/sbin/sshd\n");
        f.write(
            STATUS,
            format!(
                "Package: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.6p1-3\nConffiles:\n /etc/ssh/sshd_config {}\nDescription: x\n\n",
                md5_of(shipped)
            )
            .as_bytes(),
        );
        f.write(
            &format!("{INFO}/openssh-server.list"),
            b"/etc/ssh/sshd_config\n/usr/lib/systemd/system/ssh.service\n",
        );
        f.write(
            &format!("{INFO}/openssh-server.md5sums"),
            format!(
                "{}  usr/lib/systemd/system/ssh.service\n",
                md5_of(b"[Service]\nExecStart=/usr/sbin/sshd\n")
            )
            .as_bytes(),
        );

        let root = f.root();
        let answers = ask(&root, &["etc/ssh/sshd_config", "usr/lib/systemd/system/ssh.service"]);

        match &answers[Path::new("etc/ssh/sshd_config")] {
            Provenance::Packaged { package, version, integrity } => {
                assert_eq!(package, "openssh-server");
                assert_eq!(version, "1:9.6p1-3");
                assert_eq!(*integrity, Integrity::ConffileModified);
            }
            other => panic!("expected a packaged conffile, got {other:?}"),
        }
        assert!(matches!(
            answers[Path::new("usr/lib/systemd/system/ssh.service")],
            Provenance::Packaged { integrity: Integrity::Intact, .. }
        ));
    }

    #[test]
    fn a_trojaned_unit_file_reads_as_modified() {
        let f = Fixture::new("modified");
        f.write("usr/lib/systemd/system/cron.service", b"[Service]\nExecStart=/tmp/evil\n");
        f.write(STATUS, b"Package: cron\nArchitecture: amd64\nVersion: 3.0pl1\n\n");
        f.write(&format!("{INFO}/cron.list"), b"/usr/lib/systemd/system/cron.service\n");
        f.write(
            &format!("{INFO}/cron.md5sums"),
            format!("{}  usr/lib/systemd/system/cron.service\n", md5_of(b"[Service]\nExecStart=/usr/sbin/cron\n")).as_bytes(),
        );

        let root = f.root();
        let answers = ask(&root, &["usr/lib/systemd/system/cron.service"]);
        assert!(matches!(
            answers[Path::new("usr/lib/systemd/system/cron.service")],
            Provenance::Packaged { integrity: Integrity::Modified, .. }
        ));
    }

    #[test]
    fn a_package_with_no_md5sums_reports_unknown_never_intact() {
        let f = Fixture::new("nomd5");
        f.write("usr/bin/thing", b"binary");
        f.write(STATUS, b"Package: thing\nArchitecture: amd64\nVersion: 1.0\n\n");
        f.write(&format!("{INFO}/thing.list"), b"/usr/bin/thing\n");

        let root = f.root();
        let answers = ask(&root, &["usr/bin/thing"]);
        assert!(matches!(
            answers[Path::new("usr/bin/thing")],
            Provenance::Packaged { integrity: Integrity::Unknown, .. }
        ));
    }

    #[test]
    fn merged_usr_spellings_resolve_to_the_same_package() {
        let f = Fixture::new("merged");
        let body = b"[Service]\nExecStart=/usr/sbin/rsyslogd\n";
        f.write("usr/lib/systemd/system/rsyslog.service", body);
        f.write(STATUS, b"Package: rsyslog\nArchitecture: amd64\nVersion: 8.2\n\n");
        // The database records the pre-merge spelling; the scan found the
        // post-merge one.
        f.write(&format!("{INFO}/rsyslog.list"), b"/lib/systemd/system/rsyslog.service\n");
        f.write(
            &format!("{INFO}/rsyslog.md5sums"),
            format!("{}  lib/systemd/system/rsyslog.service\n", md5_of(body)).as_bytes(),
        );

        let root = f.root();
        let answers = ask(&root, &["usr/lib/systemd/system/rsyslog.service"]);
        assert!(
            matches!(
                answers[Path::new("usr/lib/systemd/system/rsyslog.service")],
                Provenance::Packaged { integrity: Integrity::Intact, .. }
            ),
            "got {:?}",
            answers[Path::new("usr/lib/systemd/system/rsyslog.service")]
        );
    }

    #[test]
    fn an_architecture_qualified_package_is_found_by_either_name() {
        let f = Fixture::new("archqual");
        f.write("usr/lib/x/libfoo.so", b"so");
        f.write(STATUS, b"Package: libfoo\nArchitecture: amd64\nVersion: 2.1\n\n");
        f.write(&format!("{INFO}/libfoo:amd64.list"), b"/usr/lib/x/libfoo.so\n");

        let root = f.root();
        let answers = ask(&root, &["usr/lib/x/libfoo.so"]);
        match &answers[Path::new("usr/lib/x/libfoo.so")] {
            Provenance::Packaged { package, version, .. } => {
                assert_eq!(package, "libfoo");
                assert_eq!(version, "2.1");
            }
            other => panic!("expected the arch-qualified package to resolve, got {other:?}"),
        }
    }

    #[test]
    fn both_spellings_of_one_merged_usr_path_are_answered() {
        // A scan that asks about /bin/sh and /usr/bin/sh together must get an
        // answer for both. They are aliases of each other, so a lookup table
        // holding one owner per spelling loses one of them and reports a
        // perfectly ordinary shell as unpackaged.
        let f = Fixture::new("aliasboth");
        let body = b"#!/bin/dash\n";
        f.write("bin/sh", body);
        f.write(STATUS, b"Package: dash\nArchitecture: amd64\nVersion: 0.5.12\n\n");
        f.write(&format!("{INFO}/dash.list"), b"/bin/sh\n");
        f.write(&format!("{INFO}/dash.md5sums"), format!("{}  bin/sh\n", md5_of(body)).as_bytes());

        let root = f.root();
        let answers = ask(&root, &["bin/sh", "usr/bin/sh"]);
        for spelling in ["bin/sh", "usr/bin/sh"] {
            assert!(
                matches!(answers.get(Path::new(spelling)), Some(Provenance::Packaged { .. })),
                "{spelling} went unanswered: {:?}",
                answers.get(Path::new(spelling))
            );
        }
    }

    #[test]
    fn an_attacker_authored_unit_is_claimed_by_nobody() {
        let f = Fixture::new("unowned");
        f.write("etc/systemd/system/evil.service", b"[Service]\nExecStart=/tmp/x\n");
        f.write(STATUS, b"Package: cron\nArchitecture: amd64\nVersion: 3.0\n\n");
        f.write(&format!("{INFO}/cron.list"), b"/usr/sbin/cron\n");

        let root = f.root();
        let answers = ask(&root, &["etc/systemd/system/evil.service"]);
        assert!(answers.is_empty(), "the backend reports only what it can claim");

        let wanted: BTreeSet<PathBuf> = [PathBuf::from("etc/systemd/system/evil.service")].into_iter().collect();
        assert_eq!(super::super::resolve(&root, &wanted)[Path::new("etc/systemd/system/evil.service")], Provenance::Unpackaged);
    }
}
