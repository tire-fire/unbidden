//! One harness for every target.
//!
//! The parsers are private to their collector modules, and §3's property is
//! about what a collector does with a hostile file rather than about any one
//! function's return value — so the input is delivered the way the adversary
//! delivers it: as a file on the scan root, read back through `Ctx::read`
//! with its cap, its symlink rule and its not-a-regular-file check intact.
//! Nothing in the crate is made public for the fuzzer's benefit.
//!
//! The cost of going through the filesystem is one `write` and one scan per
//! iteration, measured at 9-12k iterations per second uninstrumented, which
//! is well clear of the rate at which libFuzzer stops being useful.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use unbidden::root::Root;
use unbidden::scan::{self, Collector, Options, Status};

/// The scan root, built once per process and reused. `Root` holds an open
/// directory fd and a write-once home list, so a second one per iteration
/// would buy nothing but syscalls.
static ROOT: OnceLock<(PathBuf, Root)> = OnceLock::new();

/// Plants `data` at `rel` and runs `collector` over it.
///
/// Asserts §3's property and only that: no panic, no hang, no unbounded
/// memory. Arbitrary bytes have no correct parse, so nothing here checks
/// what came out — only that the collector came back.
pub fn feed(rel: &str, collector: Box<dyn Collector>, data: &[u8]) {
    feed_with(rel, &[], collector, false, data);
}

/// As `feed`, with fixed files planted beside the fuzzed one and, where
/// `enrich` is set, the enrichment pass run afterwards.
///
/// Some parsers only run on a file another file points them at — a dpkg
/// status file is read only for the packages that claim a path an entry
/// named — and some parse in enrichment rather than in a collector: package
/// databases, script interpreter lines. `setup` supplies the pointing files;
/// `enrich` reaches the second group.
pub fn feed_with(rel: &str, setup: &[(&str, &[u8])], collector: Box<dyn Collector>, enrich: bool, data: &[u8]) {
    let (dir, root) = ROOT.get_or_init(|| plant(rel, setup));
    std::fs::write(dir.join(rel), data).expect("fuzz root is writable");
    run(root, collector, enrich);
}

/// As `feed_with`, for a parser whose input is not a file's bytes but a
/// record inside one: `write` turns the fuzzed bytes into what goes on disk.
pub fn feed_encoded(
    rel: &str,
    setup: &[(&str, &[u8])],
    collector: Box<dyn Collector>,
    enrich: bool,
    data: &[u8],
    write: impl FnOnce(&Path, &[u8]),
) {
    let (dir, root) = ROOT.get_or_init(|| plant(rel, setup));
    write(&dir.join(rel), data);
    run(root, collector, enrich);
}

fn run(root: &Root, collector: Box<dyn Collector>, enrich: bool) {
    let mut scan = scan::run(root, &Options { deep: false }, std::slice::from_ref(&collector));
    if enrich {
        unbidden::enrich::enrich(root, &mut scan);
        unbidden::enrich::enrich_late(root, &mut scan);
    }

    // libfuzzer-sys aborts from its panic hook before unwinding, so a panic
    // inside the collector is a crash the fuzzer reports with a stack trace
    // and never reaches the `catch_unwind` in `scan::run`. This is the
    // fallback for the case where it does: a swallowed panic is still the
    // operator losing a whole mechanism class, which is the defect §3 names.
    for c in &scan.header.collectors {
        if let Status::Failed { error } = &c.status {
            panic!("collector {} failed on fuzzed input: {error}", c.name);
        }
    }
    // The same holds for an enrichment stage: isolated, it costs the
    // operator a provenance verdict rather than the scan, but it is still a
    // panic on hostile input.
    if let Some(f) = scan.header.enrichment_failures.first() {
        panic!("enrichment failed on fuzzed input: {f}");
    }
}

fn plant(rel: &str, setup: &[(&str, &[u8])]) -> (PathBuf, Root) {
    // ponytail: never removed. The process is the fuzzer's, the directory is
    // a handful of files, and a Drop that ran on abort is not a thing.
    let dir = std::env::temp_dir().join(format!("unbidden-fuzz-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("etc")).expect("fuzz root is writable");

    // Distro detection reads the root, not the host (§11), and an empty
    // answer would send every collector down its "unknown distro" path for
    // every iteration.
    std::fs::write(dir.join("etc/os-release"), b"ID=debian\nVERSION_ID=\"12\"\n").unwrap();

    for (path, bytes) in setup {
        let p = dir.join(path);
        std::fs::create_dir_all(p.parent().unwrap_or(Path::new("."))).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    let target = dir.join(rel);
    std::fs::create_dir_all(target.parent().unwrap_or(Path::new("."))).unwrap();

    let root = Root::at(&dir).expect("the fuzz tree is a directory this process just created");
    (dir, root)
}
