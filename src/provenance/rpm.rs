//! The rpm backend.
//!
//! rpm keeps a per-file digest in each package's header, so integrity
//! checking needs no `rpm -V` — which is fortunate, because executing a host
//! binary to learn whether host binaries have been tampered with is circular.
//!
//! Only the sqlite backend is read. Fedora switched to it in 33 and dropped
//! BerkeleyDB to read-only in 34, so no supported release carries a bdb or
//! ndb database; those formats are a best-effort platform's problem and are
//! deliberately not handled.
//!
//! The header format is parsed here rather than through a crate. The one
//! available crate drops empty strings from string arrays, and the
//! `filesystem` package owns `/`, whose basename is the empty string — which
//! shifts every basename in the largest package by one against its directory
//! index and silently misattributes thousands of paths. Wrong provenance is
//! worse than none, and the format is small enough to own.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::entry::{Integrity, Provenance};
use crate::root::Root;

use super::{Answers, usr_aliases};

const DB: &str = "var/lib/rpm/rpmdb.sqlite";

/// An rpm database on a large workstation runs to tens of megabytes. The cap
/// is a backstop against a corrupt or hostile size, not a working limit.
const DB_CAP: u64 = 512 << 20;

// Header tags. The names are rpm's own.
const TAG_NAME: u32 = 1000;
const TAG_VERSION: u32 = 1001;
const TAG_RELEASE: u32 = 1002;
const TAG_EPOCH: u32 = 1003;
const TAG_ARCH: u32 = 1022;
const TAG_FILEDIGESTS: u32 = 1035;
const TAG_FILEFLAGS: u32 = 1037;
const TAG_DIRINDEXES: u32 = 1116;
const TAG_BASENAMES: u32 = 1117;
const TAG_DIRNAMES: u32 = 1118;
const TAG_FILEDIGESTALGO: u32 = 5011;

// Region tags carry structure, not values.
const TAG_HEADERIMAGE: u32 = 61;
const TAG_HEADERSIGNATURES: u32 = 62;
const TAG_HEADERIMMUTABLE: u32 = 63;

const TYPE_INT16: u32 = 3;
const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_STRING_ARRAY: u32 = 8;
const TYPE_I18NSTRING: u32 = 9;

/// `%config` — expected to differ from what the package shipped, the rpm
/// analogue of a dpkg conffile.
const RPMFILE_CONFIG: u32 = 1 << 0;
/// `%ghost` — a path the package declares but does not ship: an alternatives
/// symlink, a log file, a generated config. It carries no digest, so its
/// integrity is unknowable, but the package does own it. Reporting one as
/// Unpackaged would flag `/usr/bin/java` on every Fedora host.
const RPMFILE_GHOST: u32 = 1 << 6;

/// Sanity bounds on a header before any arithmetic is done with its counts.
const MAX_INDEX_ENTRIES: u64 = 1 << 20;
const MAX_STORE: u64 = 256 << 20;

/// Offsets in the SQLite file header of the write and read format versions.
const SQLITE_WRITE_VERSION: usize = 18;
const SQLITE_READ_VERSION: usize = 19;
const SQLITE_HEADER: usize = 100;

pub fn present(root: &Root) -> bool {
    root.exists(DB)
}

pub fn resolve(root: &Root, wanted: &BTreeSet<PathBuf>) -> Option<Answers> {
    if !present(root) {
        return None;
    }

    let mut alias_to_wanted: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();
    for w in wanted {
        for alias in usr_aliases(w) {
            alias_to_wanted.insert(alias, w.clone());
        }
    }

    let mut claims: BTreeMap<PathBuf, Vec<Claim>> = BTreeMap::new();
    for blob in read_blobs(root)? {
        let Some(header) = Header::parse(&blob) else { continue };
        collect_claims(&header, &alias_to_wanted, &mut claims);
    }

    let mut out = Answers::new();
    for (path, candidates) in claims {
        let verdict = verify(root, &path, &candidates);
        out.insert(path, verdict);
    }
    Some(out)
}

/// The package headers, read through the Root like everything else.
///
/// SQLite is handed the bytes rather than a path. That keeps the scan inside
/// its root, and it also sidesteps a failure that would otherwise make a
/// mounted image unreadable: opening an rpm database read-write makes SQLite
/// try to create its -wal and -shm sidecars, which fails on read-only media.
///
/// The consequence, accepted deliberately: a transaction sitting in a live
/// -wal during a concurrent dnf run is not seen. A scanner reads a snapshot.
fn read_blobs(root: &Root) -> Option<Vec<Vec<u8>>> {
    let meta = root.stat_follow(DB).ok()?;
    if meta.size == 0 || meta.size > DB_CAP {
        return None;
    }
    let (mut bytes, truncated) = root.read_capped(DB, DB_CAP as usize).ok()?;
    if truncated || bytes.len() < SQLITE_HEADER {
        return None;
    }

    // rpm keeps its database in WAL mode, and SQLite refuses to open a WAL
    // image that has no -shm to go with it — which an in-memory copy never
    // has. The main file is a complete database as of the last checkpoint, so
    // the read and write format versions are set back to the rollback-journal
    // value and the snapshot is read directly.
    //
    // The accepted consequence is the one above: a transaction sitting in a
    // live -wal during a concurrent dnf run is not seen. A scanner reads a
    // snapshot, and the alternative — opening the real file read-write so
    // SQLite can recover the WAL — fails outright on a mounted image and
    // writes to the host under examination.
    bytes[SQLITE_WRITE_VERSION] = 1;
    bytes[SQLITE_READ_VERSION] = 1;

    let size = bytes.len();
    let mut conn = rusqlite::Connection::open_in_memory().ok()?;
    conn.deserialize_read_exact("main", bytes.as_slice(), size, true).ok()?;

    let mut stmt = conn.prepare("SELECT blob FROM Packages").ok()?;
    let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)).ok()?;
    Some(rows.filter_map(|r| r.ok()).collect())
}

struct Claim {
    package: String,
    version: String,
    digest: String,
    algo: u32,
    config: bool,
    ghost: bool,
}

fn collect_claims(
    header: &Header,
    alias_to_wanted: &BTreeMap<PathBuf, PathBuf>,
    claims: &mut BTreeMap<PathBuf, Vec<Claim>>,
) {
    let basenames = header.string_array(TAG_BASENAMES);
    if basenames.is_empty() {
        return;
    }
    let dirnames = header.string_array(TAG_DIRNAMES);
    let dirindexes = header.int_array(TAG_DIRINDEXES);
    let digests = header.string_array(TAG_FILEDIGESTS);
    let flags = header.int_array(TAG_FILEFLAGS);
    let algo = header.int(TAG_FILEDIGESTALGO).unwrap_or(0);

    let name = header.string(TAG_NAME).unwrap_or_default();
    let version = nevr(header);

    for (i, base) in basenames.iter().enumerate() {
        let Some(dir) = dirindexes.get(i).and_then(|d| dirnames.get(*d as usize)) else { continue };
        let file_flags = flags.get(i).copied().unwrap_or(0) as u32;
        // rpm stores absolute paths; every other path in the tool is
        // root-relative.
        let mut path = String::with_capacity(dir.len() + base.len());
        path.push_str(dir.trim_start_matches('/'));
        path.push_str(base);
        let Some(wanted) = alias_to_wanted.get(Path::new(&path)) else { continue };

        claims.entry(wanted.clone()).or_default().push(Claim {
            package: name.clone(),
            version: version.clone(),
            digest: digests.get(i).cloned().unwrap_or_default(),
            algo,
            config: file_flags & RPMFILE_CONFIG != 0,
            ghost: file_flags & RPMFILE_GHOST != 0,
        });
    }
}

fn nevr(header: &Header) -> String {
    let version = header.string(TAG_VERSION).unwrap_or_default();
    let release = header.string(TAG_RELEASE).unwrap_or_default();
    let arch = header.string(TAG_ARCH).unwrap_or_default();
    let base = match header.int(TAG_EPOCH) {
        Some(e) if e > 0 => format!("{e}:{version}-{release}"),
        _ => format!("{version}-{release}"),
    };
    if arch.is_empty() { base } else { format!("{base}.{arch}") }
}

/// A directory can be co-owned by several packages, so a path may carry more
/// than one claim. Prefer the one that actually matches the bytes on disk.
fn verify(root: &Root, path: &Path, candidates: &[Claim]) -> Provenance {
    let actual = super::digests(root, path);

    let mut best: Option<(&Claim, Integrity)> = None;
    for claim in candidates {
        let integrity = match (&actual, digest_of(&actual, claim.algo)) {
            _ if claim.ghost => Integrity::Unknown,
            (Some(_), Some(actual_digest)) if !claim.digest.is_empty() => {
                if claim.digest.eq_ignore_ascii_case(actual_digest) {
                    Integrity::Intact
                } else if claim.config {
                    Integrity::ConffileModified
                } else {
                    Integrity::Modified
                }
            }
            _ => Integrity::Unknown,
        };
        let better = match &best {
            None => true,
            Some((_, current)) => rank(integrity) > rank(*current),
        };
        if better {
            best = Some((claim, integrity));
        }
    }

    match best {
        Some((claim, integrity)) => Provenance::Packaged {
            package: claim.package.clone(),
            version: claim.version.clone(),
            integrity,
        },
        None => Provenance::Unpackaged,
    }
}

/// rpm names its digest algorithm per package. An absent tag means MD5, which
/// is what pre-sqlite-era packages carry; treating it as unknown would report
/// every old package's integrity as unverifiable.
fn digest_of(actual: &Option<super::FileDigests>, algo: u32) -> Option<&str> {
    let actual = actual.as_ref()?;
    match algo {
        0 | 1 => Some(&actual.md5),
        8 => Some(&actual.sha256),
        _ => None,
    }
}

/// Which answer wins when a path is claimed twice: a package that matches the
/// file beats one that does not, and any real answer beats an unknown one.
fn rank(i: Integrity) -> u8 {
    match i {
        Integrity::Intact => 3,
        Integrity::ConffileModified => 2,
        Integrity::Modified => 1,
        Integrity::Unknown => 0,
    }
}

/// An rpm header: a count of index entries, a data store, and entries that
/// point into it.
struct Header<'a> {
    fields: BTreeMap<u32, Field<'a>>,
}

struct Field<'a> {
    ty: u32,
    count: usize,
    /// The data store from this field's offset onwards. String arrays have no
    /// stored length, so the end is found by counting terminators.
    data: &'a [u8],
}

impl<'a> Header<'a> {
    fn parse(blob: &'a [u8]) -> Option<Header<'a>> {
        // A header written to a package file carries an 8-byte lead; one
        // stored in the database usually does not.
        let blob = match blob.strip_prefix(&[0x8e, 0xad, 0xe8, 0x01]) {
            Some(rest) => rest.get(4..)?,
            None => blob,
        };

        let il = be32(blob, 0)? as u64;
        let dl = be32(blob, 4)? as u64;
        if il > MAX_INDEX_ENTRIES || dl > MAX_STORE {
            return None;
        }
        let index_end = 8u64.checked_add(il.checked_mul(16)?)?;
        let store_end = index_end.checked_add(dl)?;
        if store_end > blob.len() as u64 {
            return None;
        }
        let store = &blob[index_end as usize..store_end as usize];

        let mut fields = BTreeMap::new();
        for i in 0..il as usize {
            let at = 8 + i * 16;
            let tag = be32(blob, at)?;
            let ty = be32(blob, at + 4)?;
            let offset = be32(blob, at + 8)? as i32;
            let count = be32(blob, at + 12)? as usize;

            if matches!(tag, TAG_HEADERIMAGE | TAG_HEADERSIGNATURES | TAG_HEADERIMMUTABLE) {
                continue;
            }
            if offset < 0 || offset as usize > store.len() {
                continue;
            }
            fields.insert(tag, Field { ty, count, data: &store[offset as usize..] });
        }
        Some(Header { fields })
    }

    fn string(&self, tag: u32) -> Option<String> {
        let f = self.fields.get(&tag)?;
        if f.ty != TYPE_STRING && f.ty != TYPE_I18NSTRING {
            return None;
        }
        let end = f.data.iter().position(|b| *b == 0).unwrap_or(f.data.len());
        Some(String::from_utf8_lossy(&f.data[..end]).into_owned())
    }

    /// Every element, empty ones included. Dropping an empty string here is
    /// the bug that misattributes the `filesystem` package, whose basename
    /// for `/` is exactly that.
    fn string_array(&self, tag: u32) -> Vec<String> {
        let Some(f) = self.fields.get(&tag) else { return Vec::new() };
        if f.ty != TYPE_STRING_ARRAY && f.ty != TYPE_I18NSTRING {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(f.count.min(1 << 16));
        let mut rest = f.data;
        for _ in 0..f.count {
            let end = match rest.iter().position(|b| *b == 0) {
                Some(e) => e,
                None => break,
            };
            out.push(String::from_utf8_lossy(&rest[..end]).into_owned());
            rest = &rest[end + 1..];
        }
        out
    }

    fn int_array(&self, tag: u32) -> Vec<i64> {
        let Some(f) = self.fields.get(&tag) else { return Vec::new() };
        let width = match f.ty {
            TYPE_INT16 => 2,
            TYPE_INT32 => 4,
            _ => return Vec::new(),
        };
        let mut out = Vec::with_capacity(f.count.min(1 << 16));
        for i in 0..f.count {
            let at = i * width;
            let Some(slice) = f.data.get(at..at + width) else { break };
            out.push(match width {
                2 => i16::from_be_bytes([slice[0], slice[1]]) as i64,
                _ => i32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as i64,
            });
        }
        out
    }

    fn int(&self, tag: u32) -> Option<u32> {
        self.int_array(tag).first().map(|v| *v as u32)
    }
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let s = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a header the way rpm writes one, so the parser is tested
    /// against the real layout rather than against its own assumptions.
    #[derive(Default)]
    struct HeaderBuilder {
        index: Vec<(u32, u32, u32, usize)>,
        store: Vec<u8>,
    }

    impl HeaderBuilder {
        fn string(&mut self, tag: u32, value: &str) -> &mut Self {
            let offset = self.store.len() as u32;
            self.store.extend_from_slice(value.as_bytes());
            self.store.push(0);
            self.index.push((tag, TYPE_STRING, offset, 1));
            self
        }

        fn string_array(&mut self, tag: u32, values: &[&str]) -> &mut Self {
            let offset = self.store.len() as u32;
            for v in values {
                self.store.extend_from_slice(v.as_bytes());
                self.store.push(0);
            }
            self.index.push((tag, TYPE_STRING_ARRAY, offset, values.len()));
            self
        }

        fn ints(&mut self, tag: u32, values: &[i32]) -> &mut Self {
            let offset = self.store.len() as u32;
            for v in values {
                self.store.extend_from_slice(&v.to_be_bytes());
            }
            self.index.push((tag, TYPE_INT32, offset, values.len()));
            self
        }

        fn build(&self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&(self.index.len() as u32).to_be_bytes());
            out.extend_from_slice(&(self.store.len() as u32).to_be_bytes());
            for (tag, ty, offset, count) in &self.index {
                out.extend_from_slice(&tag.to_be_bytes());
                out.extend_from_slice(&ty.to_be_bytes());
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(&(*count as u32).to_be_bytes());
            }
            out.extend_from_slice(&self.store);
            out
        }
    }

    fn sha256_of(content: &[u8]) -> String {
        crate::entry::hex(&<sha2::Sha256 as sha2::Digest>::digest(content))
    }

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(tag: &str) -> Fixture {
            let dir = std::env::temp_dir().join(format!("unbidden-rpm-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Fixture(dir)
        }

        fn write(&self, rel: &str, content: &[u8]) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        }

        /// Writes a real sqlite database in rpm's schema, so the sqlite read
        /// path and the deserialize-from-Root path are both exercised.
        fn rpmdb(&self, headers: &[Vec<u8>]) {
            let path = self.0.join(DB);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)", []).unwrap();
            for (i, h) in headers.iter().enumerate() {
                conn.execute("INSERT INTO Packages (hnum, blob) VALUES (?1, ?2)", rusqlite::params![i as i64 + 1, h]).unwrap();
            }
            conn.close().unwrap();
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

    fn ask(root: &Root, paths: &[&str]) -> Answers {
        let wanted: BTreeSet<PathBuf> = paths.iter().map(PathBuf::from).collect();
        resolve(root, &wanted).unwrap()
    }

    #[test]
    fn an_empty_basename_does_not_shift_every_path_after_it() {
        // The `filesystem` package owns "/", whose basename is the empty
        // string. Dropping it slides every later basename onto the wrong
        // directory index and silently misattributes thousands of files.
        let mut b = HeaderBuilder::default();
        b.string(TAG_NAME, "filesystem")
            .string(TAG_VERSION, "3.18")
            .string(TAG_RELEASE, "12.fc44")
            .string(TAG_ARCH, "x86_64")
            .string_array(TAG_DIRNAMES, &["/", "/usr/lib/systemd/system/"])
            .string_array(TAG_BASENAMES, &["", "target.service"])
            .ints(TAG_DIRINDEXES, &[0, 1])
            .string_array(TAG_FILEDIGESTS, &["", ""])
            .ints(TAG_FILEFLAGS, &[0, 0]);

        let blob = b.build();
        let header = Header::parse(&blob).unwrap();
        assert_eq!(header.string_array(TAG_BASENAMES), vec!["".to_string(), "target.service".to_string()]);

        let mut claims = BTreeMap::new();
        let wanted = PathBuf::from("usr/lib/systemd/system/target.service");
        let aliases: BTreeMap<PathBuf, PathBuf> =
            usr_aliases(&wanted).into_iter().map(|a| (a, wanted.clone())).collect();
        collect_claims(&header, &aliases, &mut claims);

        assert_eq!(claims.len(), 1, "the path after the empty basename must still resolve");
        assert_eq!(claims[&wanted][0].package, "filesystem");
    }

    #[test]
    fn a_trojaned_binary_reads_as_modified_and_an_untouched_one_as_intact() {
        let f = Fixture::new("integrity");
        let shipped = b"#!/bin/sh\nexec /usr/sbin/crond\n";
        f.write("usr/lib/systemd/system/crond.service", b"[Service]\nExecStart=/tmp/evil\n");
        f.write("usr/bin/clean", shipped);

        let mut b = HeaderBuilder::default();
        b.string(TAG_NAME, "cronie")
            .string(TAG_VERSION, "1.7.2")
            .string(TAG_RELEASE, "16.fc44")
            .string(TAG_ARCH, "x86_64")
            .string_array(TAG_DIRNAMES, &["/usr/lib/systemd/system/", "/usr/bin/"])
            .string_array(TAG_BASENAMES, &["crond.service", "clean"])
            .ints(TAG_DIRINDEXES, &[0, 1])
            .string_array(TAG_FILEDIGESTS, &[&sha256_of(b"[Service]\nExecStart=/usr/sbin/crond\n"), &sha256_of(shipped)])
            .ints(TAG_FILEFLAGS, &[0, 0])
            .ints(TAG_FILEDIGESTALGO, &[8]);
        f.rpmdb(&[b.build()]);

        let root = f.root();
        let answers = ask(&root, &["usr/lib/systemd/system/crond.service", "usr/bin/clean"]);

        match &answers[Path::new("usr/lib/systemd/system/crond.service")] {
            Provenance::Packaged { package, version, integrity } => {
                assert_eq!(package, "cronie");
                assert_eq!(version, "1.7.2-16.fc44.x86_64");
                assert_eq!(*integrity, Integrity::Modified);
            }
            other => panic!("expected a modified packaged file, got {other:?}"),
        }
        assert!(matches!(
            answers[Path::new("usr/bin/clean")],
            Provenance::Packaged { integrity: Integrity::Intact, .. }
        ));
    }

    #[test]
    fn an_edited_config_file_is_not_a_modified_package_file() {
        let f = Fixture::new("config");
        f.write("etc/crontab", b"SHELL=/bin/bash\n*/5 * * * * root /tmp/x\n");

        let mut b = HeaderBuilder::default();
        b.string(TAG_NAME, "crontabs")
            .string(TAG_VERSION, "1.11")
            .string(TAG_RELEASE, "10.fc44")
            .string_array(TAG_DIRNAMES, &["/etc/"])
            .string_array(TAG_BASENAMES, &["crontab"])
            .ints(TAG_DIRINDEXES, &[0])
            .string_array(TAG_FILEDIGESTS, &[&sha256_of(b"SHELL=/bin/bash\n")])
            .ints(TAG_FILEFLAGS, &[(RPMFILE_CONFIG | (1 << 4)) as i32])
            .ints(TAG_FILEDIGESTALGO, &[8]);
        f.rpmdb(&[b.build()]);

        let root = f.root();
        assert!(matches!(
            ask(&root, &["etc/crontab"])[Path::new("etc/crontab")],
            Provenance::Packaged { integrity: Integrity::ConffileModified, .. }
        ));
    }

    #[test]
    fn a_ghost_path_is_owned_but_never_verifiable() {
        let f = Fixture::new("ghost");
        f.write("var/log/evil", b"whatever");

        let mut b = HeaderBuilder::default();
        b.string(TAG_NAME, "somepkg")
            .string(TAG_VERSION, "1")
            .string(TAG_RELEASE, "1")
            .string_array(TAG_DIRNAMES, &["/var/log/"])
            .string_array(TAG_BASENAMES, &["evil"])
            .ints(TAG_DIRINDEXES, &[0])
            .string_array(TAG_FILEDIGESTS, &[""])
            .ints(TAG_FILEFLAGS, &[RPMFILE_GHOST as i32]);
        f.rpmdb(&[b.build()]);

        let root = f.root();
        // The package owns the path, so it is not attacker-authored, but it
        // shipped no bytes, so nothing can be verified. Integrity Unknown is
        // never suppressed, so the entry still reaches the operator.
        assert!(matches!(
            ask(&root, &["var/log/evil"])[Path::new("var/log/evil")],
            Provenance::Packaged { integrity: Integrity::Unknown, .. }
        ));
    }

    #[test]
    fn an_absent_digest_algorithm_means_md5_not_unverifiable() {
        let f = Fixture::new("md5algo");
        let body = b"old package contents\n";
        f.write("usr/bin/old", body);
        let md5 = {
            use md5::Digest as _;
            let mut h = md5::Md5::new();
            h.update(body);
            crate::entry::hex(&h.finalize())
        };

        let mut b = HeaderBuilder::default();
        b.string(TAG_NAME, "old")
            .string(TAG_VERSION, "0.1")
            .string(TAG_RELEASE, "1")
            .string_array(TAG_DIRNAMES, &["/usr/bin/"])
            .string_array(TAG_BASENAMES, &["old"])
            .ints(TAG_DIRINDEXES, &[0])
            .string_array(TAG_FILEDIGESTS, &[&md5])
            .ints(TAG_FILEFLAGS, &[0]);
        f.rpmdb(&[b.build()]);

        let root = f.root();
        assert!(matches!(
            ask(&root, &["usr/bin/old"])[Path::new("usr/bin/old")],
            Provenance::Packaged { integrity: Integrity::Intact, .. }
        ));
    }

    #[test]
    fn a_co_owned_path_reports_the_package_whose_bytes_match() {
        let f = Fixture::new("coowned");
        let body = b"shared\n";
        f.write("etc/pki/tls/openssl.cnf", body);

        let mut wrong = HeaderBuilder::default();
        wrong
            .string(TAG_NAME, "other")
            .string(TAG_VERSION, "1")
            .string(TAG_RELEASE, "1")
            .string_array(TAG_DIRNAMES, &["/etc/pki/tls/"])
            .string_array(TAG_BASENAMES, &["openssl.cnf"])
            .ints(TAG_DIRINDEXES, &[0])
            .string_array(TAG_FILEDIGESTS, &[&sha256_of(b"different\n")])
            .ints(TAG_FILEFLAGS, &[0])
            .ints(TAG_FILEDIGESTALGO, &[8]);

        let mut right = HeaderBuilder::default();
        right
            .string(TAG_NAME, "openssl")
            .string(TAG_VERSION, "3.2")
            .string(TAG_RELEASE, "1")
            .string_array(TAG_DIRNAMES, &["/etc/pki/tls/"])
            .string_array(TAG_BASENAMES, &["openssl.cnf"])
            .ints(TAG_DIRINDEXES, &[0])
            .string_array(TAG_FILEDIGESTS, &[&sha256_of(body)])
            .ints(TAG_FILEFLAGS, &[0])
            .ints(TAG_FILEDIGESTALGO, &[8]);

        f.rpmdb(&[wrong.build(), right.build()]);

        let root = f.root();
        match &ask(&root, &["etc/pki/tls/openssl.cnf"])[Path::new("etc/pki/tls/openssl.cnf")] {
            Provenance::Packaged { package, integrity, .. } => {
                assert_eq!(package, "openssl");
                assert_eq!(*integrity, Integrity::Intact);
            }
            other => panic!("expected the matching owner to win, got {other:?}"),
        }
    }

    /// Differential check against a genuine rpm database.
    ///
    /// Point UNBIDDEN_RPMDB at a directory holding `rpmdb.sqlite` and a
    /// `gt_filemap.txt` of `path\tname\tversion\trelease\tarch` lines taken
    /// from `rpm -qa --qf`. This is the check the upstream crate never had:
    /// its path reconstruction was wrong for thousands of files and no test
    /// ever compared a rebuilt path against reality.
    #[test]
    fn matches_rpm_on_a_real_database() {
        let Ok(dir) = std::env::var("UNBIDDEN_RPMDB") else { return };
        let dir = PathBuf::from(dir);

        let f = Fixture::new("differential");
        std::fs::create_dir_all(f.0.join("var/lib/rpm")).unwrap();
        let src = dir.join("rpmdb.sqlite");
        // A hard link where the temp directory shares a filesystem with the
        // database, which keeps a multi-gigabyte matrix run off the disk.
        if std::fs::hard_link(&src, f.0.join(DB)).is_err() {
            std::fs::copy(&src, f.0.join(DB)).unwrap();
        }

        let truth = std::fs::read_to_string(dir.join("gt_filemap.txt")).unwrap();
        let mut owners: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
        for line in truth.lines() {
            let mut cols = line.split('\t');
            let (Some(path), Some(name)) = (cols.next(), cols.next()) else { continue };
            owners
                .entry(PathBuf::from(path.trim_start_matches('/')))
                .or_default()
                .insert(name.to_string());
        }
        assert!(owners.len() > 1000, "ground truth looks empty");

        let wanted: BTreeSet<PathBuf> = owners.keys().cloned().collect();
        let answers = resolve(&f.root(), &wanted).unwrap();

        let mut missing = Vec::new();
        let mut wrong = Vec::new();
        for (path, expected) in &owners {
            match answers.get(path) {
                Some(Provenance::Packaged { package, .. }) if expected.contains(package) => {}
                Some(Provenance::Packaged { package, .. }) => wrong.push((path.clone(), package.clone())),
                _ => missing.push(path.clone()),
            }
        }
        assert!(
            missing.is_empty() && wrong.is_empty(),
            "{} paths unattributed, {} misattributed, out of {}. first missing: {:?}, first wrong: {:?}",
            missing.len(),
            wrong.len(),
            owners.len(),
            missing.first(),
            wrong.first()
        );

        // Attribution alone is not enough: integrity rests on the digest and
        // the config flag, so compare those against rpm too where the
        // ground truth carries them.
        let attrs = dir.join("gt_fileattrs.txt");
        if !attrs.exists() {
            return;
        }
        let mut expected: BTreeMap<PathBuf, BTreeSet<(String, bool)>> = BTreeMap::new();
        for line in std::fs::read_to_string(&attrs).unwrap().lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 5 {
                continue;
            }
            let flags: u32 = cols[4].parse().unwrap_or(0);
            expected
                .entry(PathBuf::from(cols[0].trim_start_matches('/')))
                .or_default()
                .insert((cols[1].to_ascii_lowercase(), flags & RPMFILE_CONFIG != 0));
        }

        let mut claims: BTreeMap<PathBuf, Vec<Claim>> = BTreeMap::new();
        let aliases: BTreeMap<PathBuf, PathBuf> =
            wanted.iter().map(|w| (w.clone(), w.clone())).collect();
        for blob in read_blobs(&f.root()).unwrap() {
            let Some(header) = Header::parse(&blob) else { continue };
            collect_claims(&header, &aliases, &mut claims);
        }

        let mut bad = Vec::new();
        for (path, got) in &claims {
            let Some(want) = expected.get(path) else { continue };
            for claim in got {
                let pair = (claim.digest.to_ascii_lowercase(), claim.config);
                if !want.contains(&pair) {
                    bad.push((path.clone(), pair, want.clone()));
                }
            }
        }
        assert!(bad.is_empty(), "{} digest or config-flag mismatches, first: {:?}", bad.len(), bad.first());
    }

    #[test]
    fn malformed_headers_are_rejected_rather_than_trusted() {
        assert!(Header::parse(&[]).is_none());
        assert!(Header::parse(&[0; 7]).is_none());

        let mut b = HeaderBuilder::default();
        b.string(TAG_NAME, "x").string_array(TAG_BASENAMES, &["a", "b"]);
        let good = b.build();

        // Truncation anywhere must be refused or parsed without panicking.
        for cut in 0..good.len() {
            let h = Header::parse(&good[..cut]);
            if let Some(h) = h {
                let _ = h.string_array(TAG_BASENAMES);
                let _ = h.string(TAG_NAME);
                let _ = h.int_array(TAG_DIRINDEXES);
            }
        }

        // A count far larger than the store must not be believed.
        let mut lying = good.clone();
        lying[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        if let Some(h) = Header::parse(&lying) {
            assert!(h.string_array(TAG_BASENAMES).len() < 1 << 20);
        }

        // An index-entry count that would overflow the slice.
        let mut huge = good.clone();
        huge[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Header::parse(&huge).is_none());
    }
}
