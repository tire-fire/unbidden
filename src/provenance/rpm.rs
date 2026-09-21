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

/// Where the database lives. Fedora 36 moved it under /usr and left
/// /var/lib/rpm as a symlink to it; rpm 4.16-era systems keep the real
/// directory in /var. The real file is looked for first so that an entry
/// naming the database as its source names the path rpm's own manifest owns
/// — through the compatibility symlink, that path is nobody's file.
const DBS: [&str; 2] = ["usr/lib/sysimage/rpm/rpmdb.sqlite", DB];

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

/// The scripts rpm runs as root around a transaction: the body, then the
/// program it is handed to. Taken from rpm's own rpmtag.h and checked against
/// three real databases — a wrong number here reads the wrong bytes silently.
///
/// `%verifyscript` is deliberately absent: it runs only when an operator asks
/// for `rpm -V`, not when a package is installed. `%preuntrans` and
/// `%postuntrans` arrived in rpm 4.20 and are simply missing from an older
/// header, which a tag-driven read handles by finding nothing.
const SCRIPTLETS: &[(&str, u32, u32)] = &[
    ("%pre", 1023, 1085),
    ("%post", 1024, 1086),
    ("%preun", 1025, 1087),
    ("%postun", 1026, 1088),
    ("%pretrans", 1151, 1153),
    ("%posttrans", 1152, 1154),
    ("%preuntrans", 5103, 5105),
    ("%postuntrans", 5104, 5106),
];

/// One family of triggers. A package holds several scripts per family, and
/// each script has a set of names that fire it: for `%trigger*` a package
/// name, for the file families a path prefix. `index` says which script each
/// name belongs to, `flags` carries which half of the transaction it runs in.
struct TriggerTags {
    label: &'static str,
    scripts: u32,
    prog: u32,
    names: u32,
    versions: u32,
    index: u32,
    flags: u32,
    /// Ordering within the transaction, one per script. Absent for the
    /// dependency triggers, which rpm does not order.
    priorities: Option<u32>,
}

const TRIGGERS: &[TriggerTags] = &[
    // Fires when a *named package* is installed or removed.
    TriggerTags {
        label: "%trigger",
        scripts: 1065,
        prog: 1092,
        names: 1066,
        versions: 1067,
        index: 1069,
        flags: 1068,
        priorities: None,
    },
    // Fires when the package being installed carries a matching path.
    TriggerTags {
        label: "%filetrigger",
        scripts: 5066,
        prog: 5067,
        names: 5069,
        versions: 5071,
        index: 5070,
        flags: 5072,
        priorities: Some(5084),
    },
    // Fires once per transaction if any package in it carries a matching
    // path — `%transfiletriggerin -- /usr/bin` runs whenever anything at all
    // is installed into /usr/bin.
    TriggerTags {
        label: "%transfiletrigger",
        scripts: 5076,
        prog: 5077,
        names: 5079,
        versions: 5081,
        index: 5080,
        flags: 5082,
        priorities: Some(5085),
    },
];

// Dependency flags, from rpm's rpmds.h.
const RPMSENSE_LESS: i64 = 1 << 1;
const RPMSENSE_GREATER: i64 = 1 << 2;
const RPMSENSE_EQUAL: i64 = 1 << 3;
const RPMSENSE_TRIGGERIN: i64 = 1 << 16;
const RPMSENSE_TRIGGERUN: i64 = 1 << 17;
const RPMSENSE_TRIGGERPOSTUN: i64 = 1 << 18;
const RPMSENSE_TRIGGERPREIN: i64 = 1 << 25;

/// A scriptlet body is bounded like every other read. The largest on a stock
/// Fedora 44 is the `filesystem` package's 84 KB lua file trigger, so this is
/// a backstop against a crafted header rather than a working limit.
const SCRIPT_CAP: usize = 1 << 20;

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
    db_path(root).is_some()
}

fn db_path(root: &Root) -> Option<&'static str> {
    DBS.into_iter().find(|p| root.exists(p))
}

pub fn resolve(root: &Root, wanted: &BTreeSet<PathBuf>) -> Option<Answers> {
    if !present(root) {
        return None;
    }

    // One alias can stand for more than one wanted path: a scan that asks
    // about /bin/sh and /usr/bin/sh asks about one file under two names, and
    // both spellings alias to the same key. Keyed one-to-one, the second
    // insert replaces the first, and whichever lost is answered by nobody —
    // which reads as Unpackaged, the flag the tool leads with.
    let mut alias_to_wanted: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    for w in wanted {
        for alias in usr_aliases(w) {
            alias_to_wanted.entry(alias).or_default().push(w.clone());
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
    let db = db_path(root)?;
    let meta = root.stat_follow(db).ok()?;
    if meta.size == 0 || meta.size > DB_CAP {
        return None;
    }
    let (mut bytes, truncated) = root.read_capped(db, DB_CAP as usize).ok()?;
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

#[derive(Clone)]
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
    alias_to_wanted: &BTreeMap<PathBuf, Vec<PathBuf>>,
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

        let claim = Claim {
            package: name.clone(),
            version: version.clone(),
            digest: digests.get(i).cloned().unwrap_or_default(),
            algo,
            config: file_flags & RPMFILE_CONFIG != 0,
            ghost: file_flags & RPMFILE_GHOST != 0,
        };
        for w in wanted {
            claims.entry(w.clone()).or_default().push(claim.clone());
        }
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

/// A script rpm keeps inside a package header and runs as root during a
/// transaction. No file under /etc or /usr/lib/rpm names these — the
/// configuration a collector can read shows transaction plugins only — so
/// the database is the only place they can be seen without running `rpm`.
pub struct Scriptlet {
    pub package: String,
    pub arch: String,
    pub version: String,
    /// rpm's own spelling: `%post`, `%transfiletriggerin`, `%triggerun`.
    pub kind: String,
    /// The program the body is handed to. `<lua>` means rpm's own embedded
    /// interpreter, which runs it inside the rpm process.
    pub prog: String,
    /// What makes this fire: path prefixes for a file trigger, a package
    /// dependency for a `%trigger*`. Empty for an install scriptlet, which
    /// fires on transactions of its own package.
    pub fires_on: Vec<String>,
    /// Ordering within the transaction, where the family has one.
    pub priority: Option<i64>,
    pub body: Vec<u8>,
    pub truncated: bool,
}

/// Every scriptlet and trigger the database holds, and the path it was read
/// from. `None` where this root carries no rpm database.
///
/// Deliberately not part of `resolve`: a scan pays for the database once for
/// file provenance and once for this, and only if something asks.
pub fn scriptlets(root: &Root) -> Option<(&'static str, Vec<Scriptlet>)> {
    let db = db_path(root)?;
    let mut out = Vec::new();
    for blob in read_blobs(root)? {
        let Some(header) = Header::parse(&blob) else { continue };
        collect_scriptlets(&header, &mut out);
    }
    Some((db, out))
}

fn collect_scriptlets(header: &Header, out: &mut Vec<Scriptlet>) {
    let package = header.string(TAG_NAME).unwrap_or_default();
    if package.is_empty() {
        return;
    }
    let arch = header.string(TAG_ARCH).unwrap_or_default();
    let version = nevr(header);
    let mut push = |kind: String, prog: String, fires_on: Vec<String>, priority, body: &[u8]| {
        let end = body.len().min(SCRIPT_CAP);
        out.push(Scriptlet {
            package: package.clone(),
            arch: arch.clone(),
            version: version.clone(),
            kind,
            prog,
            fires_on,
            priority,
            body: body[..end].to_vec(),
            truncated: end < body.len(),
        });
    };

    for (kind, body_tag, prog_tag) in SCRIPTLETS {
        let Some(body) = header.bytes_array(*body_tag).first().copied() else { continue };
        // A program with arguments — `%post -p "/usr/bin/perl -w"` — is one
        // element per word.
        let prog: Vec<String> = header.bytes_array(*prog_tag).into_iter().map(lossy).collect();
        push(kind.to_string(), prog.join(" "), Vec::new(), None, body);
    }

    for t in TRIGGERS {
        let scripts = header.bytes_array(t.scripts);
        if scripts.is_empty() {
            continue;
        }
        let progs = header.bytes_array(t.prog);
        let names = header.string_array(t.names);
        let versions = header.string_array(t.versions);
        let index = header.int_array(t.index);
        let flags = header.int_array(t.flags);
        // One priority per script, not per name.
        let priorities = t.priorities.map(|tag| header.int_array(tag)).unwrap_or_default();

        for (i, body) in scripts.iter().enumerate() {
            let mut fires_on = Vec::new();
            let mut when = 0;
            for (j, at) in index.iter().enumerate() {
                if *at != i as i64 {
                    continue;
                }
                let Some(name) = names.get(j) else { continue };
                let flag = flags.get(j).copied().unwrap_or(0);
                when |= flag;
                fires_on.push(condition(name, versions.get(j).map_or("", String::as_str), flag));
            }
            push(
                format!("{}{}", t.label, when_label(when)),
                progs.get(i).map_or_else(String::new, |p| lossy(p)),
                fires_on,
                priorities.get(i).copied(),
                body,
            );
        }
    }
}

/// `systemd < 256`, the way rpm itself renders a trigger's condition. A
/// version with no comparison in its flags is printed without one rather
/// than guessed at.
fn condition(name: &str, version: &str, flags: i64) -> String {
    if version.is_empty() {
        return name.to_string();
    }
    let op = match (
        flags & RPMSENSE_LESS != 0,
        flags & RPMSENSE_GREATER != 0,
        flags & RPMSENSE_EQUAL != 0,
    ) {
        (true, false, false) => "<",
        (true, false, true) => "<=",
        (false, true, false) => ">",
        (false, true, true) => ">=",
        (false, false, true) => "=",
        _ => return format!("{name} {version}"),
    };
    format!("{name} {op} {version}")
}

/// Which half of a transaction a trigger runs in, from the dependency flags
/// rpm stores with each name.
fn when_label(flags: i64) -> &'static str {
    if flags & RPMSENSE_TRIGGERPREIN != 0 {
        "prein"
    } else if flags & RPMSENSE_TRIGGERIN != 0 {
        "in"
    } else if flags & RPMSENSE_TRIGGERUN != 0 {
        "un"
    } else if flags & RPMSENSE_TRIGGERPOSTUN != 0 {
        "postun"
    } else {
        ""
    }
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
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
    ///
    /// A field stored as a plain string is not read as a one-element array:
    /// this reads file lists, and a file list is always written as an array.
    fn string_array(&self, tag: u32) -> Vec<String> {
        match self.fields.get(&tag) {
            Some(f) if f.ty == TYPE_STRING_ARRAY || f.ty == TYPE_I18NSTRING => {
                self.bytes_array(tag).into_iter().map(lossy).collect()
            }
            _ => Vec::new(),
        }
    }

    /// Every element of a string or string-array field, as the bytes rpm
    /// stored. A scriptlet body is a program, not text: it may be lua, and it
    /// may not be valid UTF-8.
    ///
    /// A plain string reads as a one-element array here, because rpm writes
    /// one that way even where its tag table declares an array. Every
    /// `%post -p /bin/sh` in the three databases this was checked against is
    /// stored as a string, so requiring the declared type finds nothing.
    fn bytes_array(&self, tag: u32) -> Vec<&'a [u8]> {
        let Some(f) = self.fields.get(&tag) else { return Vec::new() };
        let count = match f.ty {
            TYPE_STRING => 1,
            TYPE_STRING_ARRAY | TYPE_I18NSTRING => f.count,
            _ => return Vec::new(),
        };
        let mut out = Vec::with_capacity(count.min(1 << 16));
        let mut rest = f.data;
        for _ in 0..count {
            let end = match rest.iter().position(|b| *b == 0) {
                Some(e) => e,
                None => break,
            };
            out.push(&rest[..end]);
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
pub(crate) mod tests {
    use super::*;

    /// Builds a header the way rpm writes one, so the parser is tested
    /// against the real layout rather than against its own assumptions.
    ///
    /// Shared with the pkg collector's tests, which need a database to read
    /// scriptlets out of and have no other way to write one.
    #[derive(Default)]
    pub(crate) struct HeaderBuilder {
        index: Vec<(u32, u32, u32, usize)>,
        store: Vec<u8>,
    }

    impl HeaderBuilder {
        pub(crate) fn string(&mut self, tag: u32, value: &str) -> &mut Self {
            self.bytes(tag, value.as_bytes())
        }

        /// A scriptlet body is not required to be text.
        pub(crate) fn bytes(&mut self, tag: u32, value: &[u8]) -> &mut Self {
            let offset = self.store.len() as u32;
            self.store.extend_from_slice(value);
            self.store.push(0);
            self.index.push((tag, TYPE_STRING, offset, 1));
            self
        }

        pub(crate) fn string_array(&mut self, tag: u32, values: &[&str]) -> &mut Self {
            let offset = self.store.len() as u32;
            for v in values {
                self.store.extend_from_slice(v.as_bytes());
                self.store.push(0);
            }
            self.index.push((tag, TYPE_STRING_ARRAY, offset, values.len()));
            self
        }

        pub(crate) fn ints(&mut self, tag: u32, values: &[i32]) -> &mut Self {
            let offset = self.store.len() as u32;
            for v in values {
                self.store.extend_from_slice(&v.to_be_bytes());
            }
            self.index.push((tag, TYPE_INT32, offset, values.len()));
            self
        }

        pub(crate) fn build(&self) -> Vec<u8> {
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

    /// Writes a real sqlite database in rpm's schema, so the sqlite read path
    /// and the deserialize-from-Root path are both exercised. `path` is the
    /// database file, inside a tree the caller owns.
    pub(crate) fn write_rpmdb(path: &Path, headers: &[Vec<u8>]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)", [])
            .unwrap();
        for (i, h) in headers.iter().enumerate() {
            conn.execute(
                "INSERT INTO Packages (hnum, blob) VALUES (?1, ?2)",
                rusqlite::params![i as i64 + 1, h],
            )
            .unwrap();
        }
        conn.close().unwrap();
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

        fn rpmdb(&self, headers: &[Vec<u8>]) {
            write_rpmdb(&self.0.join(DB), headers);
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
        let aliases: BTreeMap<PathBuf, Vec<PathBuf>> =
            usr_aliases(&wanted).into_iter().map(|a| (a, vec![wanted.clone()])).collect();
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

    #[test]
    fn both_spellings_of_one_merged_usr_path_are_answered() {
        // /bin/sh and /usr/bin/sh are one file under two names, and a scan
        // asks about both: a scriptlet's interpreter is written /bin/sh, a
        // shell entry's source is /usr/bin/sh. Both alias to the same key, so
        // an alias keyed to a single wanted path answers only whichever was
        // inserted last, and the other reads as Unpackaged.
        let f = Fixture::new("aliases");
        f.write("usr/bin/sh", b"#!/bin/sh\n");

        let mut b = HeaderBuilder::default();
        b.string(TAG_NAME, "bash")
            .string(TAG_VERSION, "5.3.9")
            .string(TAG_RELEASE, "3.fc44")
            .string(TAG_ARCH, "x86_64")
            .string_array(TAG_DIRNAMES, &["/usr/bin/"])
            .string_array(TAG_BASENAMES, &["sh"])
            .ints(TAG_DIRINDEXES, &[0])
            .string_array(TAG_FILEDIGESTS, &[&sha256_of(b"#!/bin/sh\n")])
            .ints(TAG_FILEFLAGS, &[0])
            .ints(TAG_FILEDIGESTALGO, &[8]);
        f.rpmdb(&[b.build()]);

        let root = f.root();
        let answers = ask(&root, &["bin/sh", "usr/bin/sh"]);
        for path in ["bin/sh", "usr/bin/sh"] {
            assert!(
                matches!(answers.get(Path::new(path)), Some(Provenance::Packaged { .. })),
                "{path} went unanswered: {:?}",
                answers.get(Path::new(path))
            );
        }
    }

    #[test]
    fn a_scriptlet_program_stored_as_a_plain_string_is_still_read() {
        // rpm's tag table types every *PROG tag as a string array, and every
        // database writes the one-word case as a plain string. Requiring the
        // declared type finds no interpreter for any scriptlet on any host.
        let mut b = HeaderBuilder::default();
        b.string(TAG_NAME, "cronie")
            .string(TAG_VERSION, "1.7.2")
            .string(TAG_RELEASE, "16.fc44")
            .string(TAG_ARCH, "x86_64")
            .bytes(1024, b"/bin/systemctl daemon-reload\n") // RPMTAG_POSTIN
            .string(1086, "/bin/sh"); // RPMTAG_POSTINPROG

        let blob = b.build();
        let mut out = Vec::new();
        collect_scriptlets(&Header::parse(&blob).unwrap(), &mut out);

        assert_eq!(out.len(), 1, "one body tag, one scriptlet");
        assert_eq!(out[0].kind, "%post");
        assert_eq!(out[0].prog, "/bin/sh");
        assert_eq!(out[0].package, "cronie");
        assert_eq!(out[0].version, "1.7.2-16.fc44.x86_64");
        assert_eq!(out[0].body, b"/bin/systemctl daemon-reload\n");
        assert!(out[0].fires_on.is_empty(), "an install scriptlet fires on its own package");
    }

    #[test]
    fn a_trigger_carries_the_paths_and_packages_that_fire_it() {
        let mut b = HeaderBuilder::default();
        b.string(TAG_NAME, "systemd")
            .string(TAG_VERSION, "259")
            .string(TAG_RELEASE, "1.fc44")
            .string(TAG_ARCH, "x86_64")
            // RPMTAG_TRANSFILETRIGGER{SCRIPTS,SCRIPTPROG,NAME,INDEX,FLAGS,PRIORITIES}
            .string_array(5076, &["systemctl daemon-reload || :", "systemd-tmpfiles --create || :"])
            .string_array(5077, &["/bin/sh", "/bin/sh"])
            .string_array(5079, &["/etc/systemd/system/", "/usr/lib/systemd/system/", "/usr/lib/tmpfiles.d/"])
            .ints(5080, &[0, 0, 1])
            .ints(5082, &[1 << 16, 1 << 16, 1 << 18])
            .ints(5085, &[900900, 1000700])
            // RPMTAG_TRIGGER{SCRIPTS,SCRIPTPROG,NAME,VERSION,INDEX,FLAGS}
            .string_array(1065, &["systemctl daemon-reexec || :"])
            .string_array(1092, &["/bin/sh"])
            .string_array(1066, &["systemd"])
            .string_array(1067, &["256"])
            .ints(1069, &[0])
            .ints(1068, &[(1 << 17) | 2]);

        let blob = b.build();
        let mut out = Vec::new();
        collect_scriptlets(&Header::parse(&blob).unwrap(), &mut out);

        let by_kind = |k: &str| out.iter().find(|s| s.kind == k).unwrap_or_else(|| panic!("no {k}"));

        let installed = by_kind("%transfiletriggerin");
        assert_eq!(
            installed.fires_on,
            vec!["/etc/systemd/system/".to_string(), "/usr/lib/systemd/system/".to_string()],
            "a trigger's identity is the set of paths that fire it"
        );
        assert_eq!(installed.priority, Some(900900), "priorities are per script, not per path");
        assert_eq!(installed.body, b"systemctl daemon-reload || :");

        let removed = by_kind("%transfiletriggerpostun");
        assert_eq!(removed.fires_on, vec!["/usr/lib/tmpfiles.d/".to_string()]);
        assert_eq!(removed.priority, Some(1000700));

        // A dependency trigger fires on a package, with a version comparison
        // that lives in the same flags as the trigger type.
        let dep = by_kind("%triggerun");
        assert_eq!(dep.fires_on, vec!["systemd < 256".to_string()]);
        assert_eq!(dep.priority, None);
    }

    #[test]
    fn a_hostile_scriptlet_header_yields_fewer_facts_rather_than_a_panic() {
        let huge = vec![b'a'; SCRIPT_CAP + 4096];
        let mut b = HeaderBuilder::default();
        b.string(TAG_NAME, "evil")
            .string(TAG_VERSION, "1")
            .string(TAG_RELEASE, "1")
            .bytes(1024, &huge) // RPMTAG_POSTIN, past the cap
            .bytes(1023, b"/tmp/\xff\xfe") // RPMTAG_PREIN, not UTF-8
            .string_array(5076, &["a", "b"])
            // Indexes naming a script that does not exist, one negative, and
            // more flags than names.
            .string_array(5079, &["/usr/bin"])
            .ints(5080, &[7, -1, 0])
            .ints(5082, &[1 << 16]);

        let blob = b.build();
        let mut out = Vec::new();
        collect_scriptlets(&Header::parse(&blob).unwrap(), &mut out);

        let post = out.iter().find(|s| s.kind == "%post").unwrap();
        assert_eq!(post.body.len(), SCRIPT_CAP, "a crafted body is read to the cap");
        assert!(post.truncated);

        let pre = out.iter().find(|s| s.kind == "%pre").unwrap();
        assert_eq!(pre.body, b"/tmp/\xff\xfe", "a body is bytes, not text");

        // Both trigger scripts are still reported; the one whose names are
        // unreadable simply lists none.
        assert_eq!(out.iter().filter(|s| s.kind.starts_with("%transfiletrigger")).count(), 2);
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
        let aliases: BTreeMap<PathBuf, Vec<PathBuf>> =
            wanted.iter().map(|w| (w.clone(), vec![w.clone()])).collect();
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

    /// The same differential check for what only the header holds.
    ///
    /// `gt_scriptlets.txt` is `package\tkind\tprogram\tsha256\tlength` and
    /// `gt_filetriggers.txt` is
    /// `package\tfamily\ttype\tprogram\tconditions\tsha256\tlength`, both
    /// written from rpm's own library — `type` and `conditions` through its
    /// TYPE and CONDS extensions, so a misread flag bit or a mis-grouped
    /// index shows up as a mismatched row rather than as silence.
    #[test]
    fn matches_rpm_scriptlets_on_a_real_database() {
        let Ok(dir) = std::env::var("UNBIDDEN_RPMDB") else { return };
        let dir = PathBuf::from(dir);
        let Ok(scripts) = std::fs::read_to_string(dir.join("gt_scriptlets.txt")) else { return };

        let f = Fixture::new("scriptlets");
        std::fs::create_dir_all(f.0.join("var/lib/rpm")).unwrap();
        let src = dir.join("rpmdb.sqlite");
        if std::fs::hard_link(&src, f.0.join(DB)).is_err() {
            std::fs::copy(&src, f.0.join(DB)).unwrap();
        }

        let mut want: Vec<String> = Vec::new();
        for line in scripts.lines() {
            let c: Vec<&str> = line.split('\t').collect();
            if c.len() < 5 {
                continue;
            }
            want.push(format!("{}|%{}|{}||{}|{}", c[0], c[1], c[2], c[3], c[4]));
        }
        let triggers = std::fs::read_to_string(dir.join("gt_filetriggers.txt")).unwrap_or_default();
        for line in triggers.lines() {
            let c: Vec<&str> = line.split('\t').collect();
            if c.len() < 7 {
                continue;
            }
            want.push(format!("{}|%{}{}|{}|{}|{}|{}", c[0], c[1], c[2], c[3], c[4], c[5], c[6]));
        }
        assert!(want.len() > 10, "ground truth looks empty");

        let (db, found) = scriptlets(&f.root()).unwrap();
        assert_eq!(db, DB);
        let mut ours: Vec<String> = found
            .iter()
            .map(|s| {
                format!(
                    "{}|{}|{}|{}|{}|{}",
                    s.package,
                    s.kind,
                    s.prog,
                    s.fires_on.join(", "),
                    sha256_of(&s.body),
                    s.body.len()
                )
            })
            .collect();

        ours.sort();
        want.sort();
        let missing: Vec<&String> = want.iter().filter(|w| !ours.contains(w)).collect();
        let extra: Vec<&String> = ours.iter().filter(|o| !want.contains(o)).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{} of rpm's {} scripts not reported, {} reported that rpm does not have.\n missing: {:?}\n extra: {:?}",
            missing.len(),
            want.len(),
            extra.len(),
            missing.first(),
            extra.first()
        );
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

