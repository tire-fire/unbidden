//! Collectors, one module per group of mechanism classes.
//!
//! Grouping is by shared source material, not by kind: the cron collector
//! reads six spool layouts and emits two kinds, and splitting it would mean
//! parsing crontab syntax twice.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::scan::{Collector, Ctx};

pub mod auth;
pub mod cron;
pub mod deep;
pub mod desktop;
pub mod inetd;
pub mod initscripts;
pub mod kernel;
pub mod pkg;
pub mod polkit;
pub mod shell;
pub mod systemd;

/// The command word of shell text, cut where the shell cuts it. A `;`, `|`,
/// `&`, `<`, `>` or parenthesis ends a word as surely as a space does, so
/// `/opt/a.sh; /tmp/x` runs /opt/a.sh and not a file named `a.sh;`, and the
/// rest of the line is left for enrichment to split into its own commands.
pub(crate) fn shell_word(word: &[u8]) -> &[u8] {
    let end = word.iter().position(|b| b";|&<>()".contains(b)).unwrap_or(word.len());
    &word[..end]
}

/// A shell-style glob with `*` and `?`, as sudoers includes and systemd
/// preset patterns use it.
pub(crate) fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0, 0);
    let (mut star, mut mark) = (usize::MAX, 0);
    while i < s.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == s[i]) {
            p += 1;
            i += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = p;
            p += 1;
            mark = i;
        } else if star != usize::MAX {
            p = star + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// An include path resolved root-relative: absolute means relative to the scan
/// root, bare means relative to `base`.
pub(crate) fn include_rel(base: &Path, spec: &[u8]) -> PathBuf {
    let p = Path::new(OsStr::from_bytes(spec));
    match p.strip_prefix("/") {
        Ok(stripped) => stripped.to_path_buf(),
        Err(_) => base.join(p),
    }
}

/// The files a glob in the last path component matches, sorted as glob(3)
/// returns them; a path with no glob is itself.
pub(crate) fn expand_glob(cx: &mut Ctx, rel: &Path) -> Vec<PathBuf> {
    let name = rel.file_name().map(|n| n.as_encoded_bytes().to_vec()).unwrap_or_default();
    if !name.contains(&b'*') && !name.contains(&b'?') {
        return vec![rel.to_path_buf()];
    }
    let dir = rel.parent().unwrap_or(Path::new("")).to_path_buf();
    let mut out = Vec::new();
    for ent in cx.dir(&dir) {
        if !ent.is_dir && glob_match(&name, ent.name.as_encoded_bytes()) {
            out.push(dir.join(&ent.name));
        }
    }
    out.sort();
    out
}

/// The directories ldconfig puts in the loader's cache, read from
/// /etc/ld.so.conf as ldconfig reads it: `#` starts a comment anywhere, an
/// `include` line names whitespace-separated patterns relative to the file
/// it is in, a `hwcap` line is ignored, and any other line is one directory.
/// A file that is not included is never read, whatever directory it sits in.
pub(crate) fn ld_so_conf_dirs(cx: &mut Ctx) -> Vec<String> {
    let mut out = Vec::new();
    ld_so_conf(cx, Path::new("etc/ld.so.conf"), 0, &mut out);
    out
}

fn ld_so_conf(cx: &mut Ctx, rel: &Path, depth: usize, out: &mut Vec<String>) {
    // An include loop ends here rather than in the stack.
    if depth > 8 {
        return;
    }
    let Some(bytes) = cx.read_capped(rel, 64 * 1024) else { return };
    let base = rel.parent().unwrap_or(Path::new("")).to_path_buf();
    for raw in bytes.split(|b| *b == b'\n') {
        let line = raw.split(|b| *b == b'#').next().unwrap_or_default().trim_ascii();
        let (word, rest) = line.split_at(line.iter().position(u8::is_ascii_whitespace).unwrap_or(line.len()));
        if line.is_empty() || word.eq_ignore_ascii_case(b"hwcap") {
            continue;
        }
        if word == b"include" && !rest.is_empty() {
            for pat in rest.split(u8::is_ascii_whitespace).filter(|p| !p.is_empty()) {
                for f in expand_glob(cx, &include_rel(&base, pat)) {
                    ld_so_conf(cx, &f, depth + 1, out);
                }
            }
            continue;
        }
        // ldconfig strips trailing slashes, and an old `dir=TYPE` suffix.
        let dir = line.split(|b| *b == b'=').next().unwrap_or_default().trim_ascii();
        let mut d = String::from_utf8_lossy(dir).into_owned();
        while d.len() > 1 && d.ends_with('/') {
            d.pop();
        }
        if !d.is_empty() && !out.contains(&d) {
            out.push(d);
        }
    }
}

/// The files in `dirs` in the order systemd and polkit read them, by file
/// name, each with the file that replaces it: a same-named file in an
/// earlier directory is read instead, and a link to /dev/null there masks it.
pub(crate) fn replaceable(cx: &mut Ctx, dirs: &[&str], suffix: &str) -> Vec<(PathBuf, Option<PathBuf>)> {
    let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut first: BTreeMap<OsString, PathBuf> = BTreeMap::new();
    let mut found = Vec::new();
    for dir in dirs {
        match cx.root.dir_identity(dir) {
            Ok(id) if seen.insert(id) => {}
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                cx.note_failed(dir, &e);
                continue;
            }
        }
        for ent in cx.dir(dir) {
            if ent.is_dir || !ent.name.as_encoded_bytes().ends_with(suffix.as_bytes()) {
                continue;
            }
            let rel = Path::new(dir).join(&ent.name);
            let by = first.get(&ent.name).cloned();
            first.entry(ent.name.clone()).or_insert_with(|| rel.clone());
            found.push((ent.name, rel, by));
        }
    }
    // Stable, so the copy that is read comes before the ones it replaces.
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found.into_iter().map(|(_, rel, by)| (rel, by)).collect()
}

pub fn all() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(systemd::Systemd),
        Box::new(cron::Cron),
        Box::new(desktop::Desktop),
        Box::new(shell::Shell),
        Box::new(initscripts::InitScripts),
        Box::new(auth::Auth),
        Box::new(polkit::Polkit),
        Box::new(inetd::Inetd),
        Box::new(kernel::Kernel),
        Box::new(pkg::PkgHooks),
        Box::new(deep::GitConfig),
        Box::new(deep::Deep),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matching_is_not_a_prefix_check() {
        assert!(glob_match(b"*.conf", b"10-evil.conf"));
        assert!(!glob_match(b"*.conf", b"notes.txt"));
        assert!(glob_match(b"sshd_config_?", b"sshd_config_1"));
        assert!(glob_match(b"*", b"anything"));
        assert!(!glob_match(b"a*b", b"ab_"));
        assert!(glob_match(b"a*b*c", b"axxbxxc"));
    }
}
