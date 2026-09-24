//! Files that are neither packaged nor attacker-authored: something on the
//! system produced them at runtime.
//!
//! Without this, every snap on an Ubuntu or Mint host reports Unpackaged —
//! the same verdict an attacker's unit gets, and the flag the tool leads
//! with. That is the largest false-positive source in the supported set.
//!
//! The verdict takes Unpackaged away, so it has to be earned rather than
//! claimed by a file name. Two rules keep it honest. It is only ever asked
//! about a path no package database claims: a file a package ships is
//! checked against the package, whatever it is called, so a trojaned
//! `snap-confine` or `cloud-init` binary still reads as modified. And a snap
//! verdict needs the snap to be installed and the file to have the shape
//! snapd gives it — `snap.evil.service` running `/tmp/x` is not a snap unit
//! because of its name.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::entry::Provenance;
use crate::root::Root;

use super::Answers;

/// The snapd unit files are a few hundred bytes; anything much bigger is not
/// one of them.
const UNIT_CAP: usize = 64 * 1024;

/// Paths no package claims, classified where something on the host provably
/// produced them. Anything else is left out and stays Unpackaged.
pub fn classify(root: &Root, unclaimed: &BTreeSet<PathBuf>) -> Answers {
    let snaps = Snaps::installed(root);
    let mut out = Answers::new();
    for path in unclaimed {
        if let Some(by) = producer(root, &snaps, path) {
            out.insert(path.clone(), Provenance::GeneratedBy { by: by.to_string() });
        }
    }
    out
}

/// Installed snaps and their revisions, from the squashfs images snapd keeps
/// in /var/lib/snapd/snaps as `<name>_<revision>.snap`. Every revision of an
/// installed snap has one; a name with no image is not installed.
struct Snaps(BTreeMap<String, BTreeSet<String>>);

impl Snaps {
    fn installed(root: &Root) -> Snaps {
        let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for ent in root.read_dir_optional("var/lib/snapd/snaps").unwrap_or_default() {
            let name = ent.name.to_string_lossy();
            let Some(stem) = name.strip_suffix(".snap") else { continue };
            let Some((snap, rev)) = stem.rsplit_once('_') else { continue };
            if snap.is_empty() || rev.is_empty() || ent.is_dir || ent.is_symlink {
                continue;
            }
            out.entry(snap.to_string()).or_default().insert(rev.to_string());
        }
        Snaps(out)
    }

    fn has(&self, snap: &str) -> bool {
        self.0.contains_key(snap)
    }

    fn has_revision(&self, snap: &str, rev: &str) -> bool {
        self.0.get(snap).is_some_and(|r| r.contains(rev))
    }
}

fn producer(root: &Root, snaps: &Snaps, rel: &Path) -> Option<&'static str> {
    let text = rel.to_string_lossy();

    // The contents of a mounted snap: a read-only squashfs image of an
    // installed revision.
    if let Some(rest) = text.strip_prefix("snap/") {
        let mut parts = rest.splitn(3, '/');
        let (snap, rev) = (parts.next()?, parts.next()?);
        return snaps.has_revision(snap, rev).then_some("snapd");
    }

    // Written by systemd itself, into directories only root can write.
    // Each is a different writer, and the name says which.
    if text.starts_with("run/systemd/generator") {
        return Some("systemd-generator");
    }
    if text.starts_with("run/systemd/transient/") {
        return Some("systemd-transient");
    }
    if text.starts_with("run/systemd/system.control/") || text.starts_with("etc/systemd/system.control/") {
        return Some("systemctl-set-property");
    }

    // cloud-init's runtime state; its units and binaries are packaged and so
    // never reach this function.
    if text.starts_with("run/cloud-init/") {
        return Some("cloud-init");
    }

    let unit_dir = ["etc/systemd/system/", "etc/systemd/user/"].iter().any(|d| {
        text.strip_prefix(d).is_some_and(|rest| !rest.contains('/'))
    });
    if unit_dir && snap_unit(root, snaps, rel) {
        return Some("snapd");
    }
    None
}

/// Does this unit file look the way snapd writes it, for a snap that is
/// installed? A service must say `X-Snappy=yes` and run nothing but
/// `/usr/bin/snap run`; a mount unit must mount an installed revision's
/// image at its own directory.
fn snap_unit(root: &Root, snaps: &Snaps, rel: &Path) -> bool {
    let Some(name) = rel.file_name().map(|n| n.to_string_lossy().into_owned()) else { return false };
    let Ok((bytes, truncated)) = root.read_capped(rel, UNIT_CAP) else { return false };
    if truncated {
        return false;
    }
    let text = String::from_utf8_lossy(&bytes);
    let values = |key: &str| -> Vec<&str> {
        text.lines()
            .filter_map(|l| l.trim().strip_prefix(key)?.trim_start().strip_prefix('='))
            .map(str::trim)
            .collect()
    };

    if name.starts_with("snap-") && name.ends_with(".mount") {
        let (what, where_) = (values("What"), values("Where"));
        let ([what], [where_]) = (&what[..], &where_[..]) else { return false };
        let Some(image) = what.strip_prefix("/var/lib/snapd/snaps/").and_then(|i| i.strip_suffix(".snap")) else {
            return false;
        };
        let Some((snap, rev)) = image.rsplit_once('_') else { return false };
        return snaps.has_revision(snap, rev) && *where_ == format!("/snap/{snap}/{rev}");
    }

    // snap.<snap>.<app>.service, snap.<snap>.<app>.timer, snap.<snap>.hook.*
    let Some(rest) = name.strip_prefix("snap.") else { return false };
    let Some((snap, _)) = rest.split_once('.') else { return false };
    if !snaps.has(snap) || !values("X-Snappy").contains(&"yes") {
        return false;
    }
    let execs: Vec<&str> = text
        .lines()
        .filter_map(|l| {
            let (k, v) = l.trim().split_once('=')?;
            k.trim().starts_with("Exec").then_some(v.trim())
        })
        .collect();
    // Every command must go through snap run, for this snap: that is what
    // confines it, and a unit that runs anything else is not snapd's.
    execs.iter().all(|v| {
        let v = v.trim_start_matches(['-', '@', '+', '!', ':']);
        v.strip_prefix("/usr/bin/snap run ").is_some_and(|args| {
            args.split_whitespace().filter(|a| !a.starts_with("--")).next().is_some_and(|app| {
                app == snap || app.strip_prefix(snap).is_some_and(|r| r.starts_with('.'))
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: &str = "[Unit]\n# Auto-generated, DO NOT EDIT\nDescription=Service for snap application lxd.daemon\n\
        Requires=snap-lxd-24322.mount\nX-Snappy=yes\n\n[Service]\nEnvironmentFile=-/etc/environment\n\
        ExecStart=/usr/bin/snap run lxd.daemon\nExecStop=/usr/bin/snap run --command=stop lxd.daemon\n";
    const MOUNT: &str = "[Unit]\nDescription=Mount unit for lxd, revision 24322\n\n[Mount]\n\
        What=/var/lib/snapd/snaps/lxd_24322.snap\nWhere=/snap/lxd/24322\nType=squashfs\n";

    fn tree(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("unbidden-generated-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["etc/systemd/system", "var/lib/snapd/snaps", "snap/lxd/24322/bin", "tmp"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(dir.join("var/lib/snapd/snaps/lxd_24322.snap"), b"hsqs").unwrap();
        dir
    }

    fn verdict(dir: &Path, rel: &str) -> Option<Provenance> {
        let root = Root::at(dir).unwrap();
        let wanted: BTreeSet<PathBuf> = [PathBuf::from(rel)].into_iter().collect();
        classify(&root, &wanted).remove(Path::new(rel))
    }

    fn snapd() -> Option<Provenance> {
        Some(Provenance::GeneratedBy { by: "snapd".into() })
    }

    #[test]
    fn a_unit_snapd_wrote_for_an_installed_snap_is_attributed_to_snapd() {
        let dir = tree("real");
        std::fs::write(dir.join("etc/systemd/system/snap.lxd.daemon.service"), SERVICE).unwrap();
        std::fs::write(dir.join("etc/systemd/system/snap-lxd-24322.mount"), MOUNT).unwrap();
        std::fs::write(dir.join("snap/lxd/24322/bin/lxd"), b"elf").unwrap();

        assert_eq!(verdict(&dir, "etc/systemd/system/snap.lxd.daemon.service"), snapd());
        assert_eq!(verdict(&dir, "etc/systemd/system/snap-lxd-24322.mount"), snapd());
        assert_eq!(verdict(&dir, "snap/lxd/24322/bin/lxd"), snapd());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_snap_name_alone_earns_nothing() {
        let dir = tree("forged");
        let put = |rel: &str, body: &str| std::fs::write(dir.join(rel), body).unwrap();
        // Named like a snap unit, for no installed snap.
        put("etc/systemd/system/snap.evil.daemon.service", &SERVICE.replace("lxd", "evil"));
        // For an installed snap, but running something other than snap run.
        put(
            "etc/systemd/system/snap.lxd.backdoor.service",
            &SERVICE.replace("ExecStart=/usr/bin/snap run lxd.daemon", "ExecStart=/tmp/x"),
        );
        // A second command smuggled in beside a genuine one.
        put("etc/systemd/system/snap.lxd.extra.service", &format!("{SERVICE}ExecStartPre=/tmp/x\n"));
        // snap run, but of a different snap.
        put("etc/systemd/system/snap.lxd.other.service", &SERVICE.replace("run lxd.daemon", "run evil.daemon"));
        // Without snapd's marker.
        put("etc/systemd/system/snap.lxd.plain.service", &SERVICE.replace("X-Snappy=yes\n", ""));
        // A mount unit mounting something that is not an installed image.
        put("etc/systemd/system/snap-lxd-1.mount", &MOUNT.replace("24322", "1"));
        put("etc/systemd/system/snap-lxd-24322b.mount", &MOUNT.replace("Where=/snap/lxd/24322", "Where=/usr/bin"));
        // Named like snapd's files but somewhere else entirely.
        put("tmp/snap.lxd.daemon.service", SERVICE);
        std::fs::create_dir_all(dir.join("snap/evil/1")).unwrap();
        put("snap/evil/1/x", "x");

        for rel in [
            "etc/systemd/system/snap.evil.daemon.service",
            "etc/systemd/system/snap.lxd.backdoor.service",
            "etc/systemd/system/snap.lxd.extra.service",
            "etc/systemd/system/snap.lxd.other.service",
            "etc/systemd/system/snap.lxd.plain.service",
            "etc/systemd/system/snap-lxd-1.mount",
            "etc/systemd/system/snap-lxd-24322b.mount",
            "tmp/snap.lxd.daemon.service",
            "snap/evil/1/x",
            "var/lib/snapd/anything",
            "usr/lib/snapd/snap-confine",
            "usr/bin/cloud-init",
            "etc/systemd/system/cloud-init-local.service",
        ] {
            assert_eq!(verdict(&dir, rel), None, "{rel}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn systemd_runtime_output_names_its_writer() {
        let dir = tree("runtime");
        let v = |rel| verdict(&dir, rel).map(|p| match p {
            Provenance::GeneratedBy { by } => by,
            other => panic!("{other:?}"),
        });
        assert_eq!(v("run/systemd/generator/foo.service").as_deref(), Some("systemd-generator"));
        assert_eq!(v("run/systemd/generator.late/foo.service").as_deref(), Some("systemd-generator"));
        assert_eq!(v("run/systemd/transient/run-u1.service").as_deref(), Some("systemd-transient"));
        assert_eq!(v("run/systemd/system.control/ssh.service.d/50-CPUQuota.conf").as_deref(), Some("systemctl-set-property"));
        assert_eq!(v("etc/systemd/system/evil.service"), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
