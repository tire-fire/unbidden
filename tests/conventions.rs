//! The conventions §3 and §11 state as rules, enforced rather than trusted.
//!
//! §11 asks for this directly — "a lint or a #[deny]-style convention should
//! enforce this, because one collector reaching for an absolute path silently
//! breaks offline mode for everyone". The same applies to shelling out: it is
//! the one thing the threat model forbids outright, and it is one careless
//! line away at all times.
//!
//! A line that genuinely must break a rule says so with a trailing
//! `// convention-exempt: <reason>`, which keeps the exceptions countable and
//! makes adding one a deliberate act.

use std::path::{Path, PathBuf};

const EXEMPT: &str = "convention-exempt:";

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Lines of real code, with test modules and their fixtures excluded: a test
/// builds trees with std::fs and names absolute paths on purpose.
fn production_lines(path: &Path) -> Vec<(usize, String)> {
    let text = std::fs::read_to_string(path).unwrap();
    let mut out = Vec::new();
    let mut in_tests = false;
    for (n, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            in_tests = true;
        }
        if in_tests || line.contains(EXEMPT) {
            continue;
        }
        let code = line.split("//").next().unwrap_or("");
        if !code.trim().is_empty() {
            out.push((n + 1, code.to_string()));
        }
    }
    out
}

fn all_sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    files.sort();
    assert!(files.len() > 15, "found almost no source files; the walk is wrong");
    files
}

#[test]
fn nothing_executes_a_binary_on_the_host_being_examined() {
    // rpm, dpkg, systemctl, crontab and ls are all binaries on the host
    // under examination, and wrapping one so it filters itself out of the
    // output is a standard persistence technique. Anything this tool learned
    // by running a host binary would be worthless.
    let mut bad = Vec::new();
    for file in all_sources() {
        for (n, code) in production_lines(&file) {
            for banned in ["Command::new", "process::Command", "std::process::exit"] {
                if code.contains(banned) {
                    bad.push(format!("{}:{n}: {banned}", file.display()));
                }
            }
        }
    }
    assert!(bad.is_empty(), "the threat model forbids these:\n  {}", bad.join("\n  "));
}

#[test]
fn collectors_reach_the_filesystem_only_through_the_scan_root() {
    // A collector that opens a path itself works perfectly on a live host and
    // silently reads the analyst's own machine when the root is a mounted
    // image. The failure is invisible until it matters.
    let mut bad = Vec::new();
    for file in all_sources() {
        if !file.to_string_lossy().contains("/collect/") {
            continue;
        }
        for (n, code) in production_lines(&file) {
            for banned in ["std::fs::", "File::open", "File::create", "rustix::fs::", "read_to_string("] {
                if code.contains(banned) {
                    bad.push(format!("{}:{n}: {banned} — use cx.read/cx.dir/cx.root", file.display()));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "collectors must go through Root:\n  {}\n\nIf a line genuinely cannot, append `// {EXEMPT} <reason>`.",
        bad.join("\n  ")
    );
}

#[test]
fn the_exemptions_stay_countable() {
    // Not zero — one exists and is justified in place. The point is that the
    // number moves only when somebody means it to.
    let mut found = Vec::new();
    for file in all_sources() {
        let text = std::fs::read_to_string(&file).unwrap();
        for (n, line) in text.lines().enumerate() {
            if line.contains(EXEMPT) {
                found.push(format!("{}:{}", file.display(), n + 1));
            }
        }
    }
    assert!(
        found.len() <= 2,
        "{} conventions exemptions, which is more than this project has agreed to:\n  {}",
        found.len(),
        found.join("\n  ")
    );
}
