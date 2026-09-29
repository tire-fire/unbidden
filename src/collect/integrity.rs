//! `--deep` integrity: every packaged program and library on the host
//! checked against its package's manifest, and the ones that differ
//! reported. No entry names them — that is the point. A trojaned `ls` or a
//! patched libc is persistence that runs whenever anything does, and only a
//! walk of every manifest finds it.
//!
//! What is checked: each path a package claims (dpkg's file lists, rpm's
//! headers, ghosts left out) that is a regular file with an execute bit or a
//! shared object by name. That is what runs; a modified data file is not
//! code. Each is judged by the package backends exactly as an entry's own
//! file is (§7): a conffile edited is expected and not reported, a file its
//! package records no digest for is unknown and not reported, and a file
//! whose digest differs is reported as a package_file entry.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::entry::{Enablement, Entry, Integrity as Verdict, Kind, Provenance, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Integrity;

/// A host has some tens of thousands of packaged programs; past this the
/// collector says it stopped.
const MAX_FILES: usize = 500_000;

impl Collector for Integrity {
    fn name(&self) -> &'static str {
        "integrity"
    }

    fn deep_only(&self) -> bool {
        true
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut wanted: BTreeSet<PathBuf> = BTreeSet::new();
        let mut looked = 0usize;
        for rel in crate::provenance::packaged_files(cx.root) {
            looked += 1;
            if looked > MAX_FILES {
                cx.note_limited(format!("stopped after {MAX_FILES} packaged files"));
                break;
            }
            let Ok(meta) = cx.root.stat(&rel) else { continue };
            if !meta.is_file {
                continue;
            }
            let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let code = meta.mode & 0o111 != 0 || name.contains(".so");
            if code {
                wanted.insert(rel);
            }
        }
        let resolution = crate::provenance::resolve(cx.root, &wanted);
        let mut out = Vec::new();
        for (rel, prov) in resolution.answers {
            let Provenance::Packaged { package, version, integrity: Verdict::Modified } = prov else { continue };
            // Named by its path within the root, not as reported: the mount
            // prefix would give one file two ids, and the same host scanned live
            // and as an image could never be diffed.
            let mut e = cx.entry(Kind::PackageFile, &rel, format!("/{}", rel.display()));
            e.trigger = Trigger::Always;
            e.enabled = Enablement::NotApplicable;
            e.target_path = Some(cx.root.abs(&rel));
            e.note("package", package);
            e.note("package_version", version);
            e.note("differs_from", "the digest its package recorded");
            out.push(e);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::Options;
    use std::path::Path;

    fn md5_of(content: &[u8]) -> String {
        use md5::Digest as _;
        let mut h = md5::Md5::new();
        h.update(content);
        crate::entry::hex(&h.finalize())
    }

    /// A host with a trojaned `ls`, a patched libc, an intact `cat`, an edited
    /// conffile and a changed data file, all of one package.
    fn host(tag: &str) -> crate::testing::Tree {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::testing::Tree::new(&format!("integrity-{tag}"));
        let put = |rel: &str, body: &[u8], mode: u32| {
            let p = d.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        put("usr/bin/ls", b"trojan", 0o755);
        put("usr/bin/cat", b"cat", 0o755);
        put("usr/lib/libc.so.6", b"patched", 0o644);
        put("usr/share/doc/README", b"changed docs", 0o644);
        put("etc/coreutils.conf", b"edited", 0o644);
        put("var/lib/dpkg/status", b"Package: coreutils\nStatus: install ok installed\nVersion: 9.1\nConffiles:\n /etc/coreutils.conf 0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f\n\n", 0o644);
        put("var/lib/dpkg/info/coreutils.list", b"/usr/bin/ls\n/usr/bin/cat\n/usr/lib/libc.so.6\n/usr/share/doc/README\n/etc/coreutils.conf\n", 0o644);
        put(
            "var/lib/dpkg/info/coreutils.md5sums",
            format!("{}  usr/bin/ls\n{}  usr/bin/cat\n{}  usr/lib/libc.so.6\n{}  usr/share/doc/README\n", md5_of(b"ls"), md5_of(b"cat"), md5_of(b"libc"), md5_of(b"docs")).as_bytes(),
            0o644,
        );
        d
    }

    #[test]
    fn the_same_host_at_two_mount_points_has_the_same_ids() {
        let scan = |d: &Path| {
            let root = Root::at(d).unwrap();
            let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Integrity)];
            let s = crate::scan::run(&root, &Options { deep: true }, &collectors);
            let mut ids: Vec<(String, String)> = s.entries.iter().map(|e| (e.name.clone(), e.id.clone())).collect();
            ids.sort();
            ids
        };
        let (a, b) = (host("mount-a"), host("mount-b"));
        let (ids_a, ids_b) = (scan(&a), scan(&b));
        assert_eq!(ids_a.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["/usr/bin/ls", "/usr/lib/libc.so.6"]);
        assert_eq!(ids_a, ids_b);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn a_packaged_program_that_differs_from_its_manifest_is_reported() {
        let d = host("reported");
        let root = Root::at(&d).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Integrity)];
        let shallow = crate::scan::run(&root, &Options { deep: false }, &collectors);
        assert!(shallow.entries.is_empty(), "a shallow scan does not walk the manifests");
        let s = crate::scan::run(&root, &Options { deep: true }, &collectors);
        let mut got: Vec<&Path> = s.entries.iter().map(|e| e.source.strip_prefix(&d).unwrap()).collect();
        got.sort();
        assert_eq!(got, [Path::new("usr/bin/ls"), Path::new("usr/lib/libc.so.6")], "a trojaned program and a patched library; not an intact program, an edited conffile or a data file");
        assert_eq!(s.entries[0].raw["package"], "coreutils");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
