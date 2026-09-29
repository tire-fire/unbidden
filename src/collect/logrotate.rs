//! logrotate's scripts: shell run as root by the daily rotation, on nearly
//! every host, from `prerotate`, `postrotate`, `firstaction`, `lastaction`
//! and `preremove` blocks.
//!
//! Read as logrotate 3.21 reads its configuration (config.c): from
//! /etc/logrotate.conf, following `include` into a file or a directory,
//! whose entries are read in strcmp order, skipping `.`, `..` and any name
//! ending in one of its taboo extensions (a dotfile is read). A script runs
//! from the line after its keyword to the line whose first word is
//! `endscript`. `tabooext` changes to the taboo list are not followed.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Logrotate;

const CAP: usize = 256 * 1024;
/// How deep `include` may nest. A loop is ended by the set of files already
/// read; this bounds the nesting of a chain that is not one.
const MAX_DEPTH: usize = 8;
const SCRIPTS: [&str; 5] = ["prerotate", "postrotate", "firstaction", "lastaction", "preremove"];
/// logrotate's default taboo extensions; `.rhn-cfg-tmp-*` is a pattern.
const TABOO: [&str; 18] = [
    ",v", ".bak", ".cfsaved", ".disabled", ".dpkg-bak", ".dpkg-del", ".dpkg-dist", ".dpkg-new", ".dpkg-old", ".dpkg-tmp",
    ".rpmnew", ".rpmorig", ".rpmsave", ".swp", ".ucf-dist", ".ucf-new", ".ucf-old", "~",
];

impl Collector for Logrotate {
    fn name(&self) -> &'static str {
        "logrotate"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let installed = ["usr/sbin/logrotate", "sbin/logrotate"].iter().any(|p| cx.root.exists(p));
        let mut out = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        read(cx, Path::new("etc/logrotate.conf"), 0, &mut seen, &mut out);
        for e in &mut out {
            if !installed {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "logrotate is not installed");
            }
        }
        out
    }
}

fn taboo(name: &[u8]) -> bool {
    name.windows(b".rhn-cfg-tmp-".len()).any(|w| w == b".rhn-cfg-tmp-") || TABOO.iter().any(|t| name.ends_with(t.as_bytes()))
}

fn include(cx: &mut Ctx, rel: &Path, depth: usize, seen: &mut std::collections::BTreeSet<PathBuf>, out: &mut Vec<Entry>) {
    match cx.root.stat_follow(rel) {
        Ok(m) if m.is_dir => {
            let names: Vec<_> = cx.dir(rel).into_iter().filter(|e| !e.is_dir && !taboo(e.name.as_encoded_bytes())).map(|e| e.name).collect();
            for n in names {
                read(cx, &rel.join(n), depth, seen, out);
            }
        }
        Ok(_) => read(cx, rel, depth, seen, out),
        Err(_) => {}
    }
}

fn read(cx: &mut Ctx, rel: &Path, depth: usize, seen: &mut std::collections::BTreeSet<PathBuf>, out: &mut Vec<Entry>) {
    if depth > MAX_DEPTH || !seen.insert(rel.to_path_buf()) {
        return;
    }
    let Some(bytes) = cx.read_capped(rel, CAP) else { return };
    let mut logs: Option<String> = None;
    // Log names may run over several lines before the `{`.
    let mut pending: Vec<&[u8]> = Vec::new();
    let mut script: Option<(&str, Vec<&[u8]>)> = None;
    for line in bytes.split(|b| *b == b'\n') {
        let t = line.trim_ascii();
        let first = t.split(|b| b.is_ascii_whitespace()).next().unwrap_or_default();
        if let Some((kw, lines)) = &mut script {
            if first == b"endscript" {
                let kw = *kw;
                let body = lines.join(&b'\n');
                push(cx, out, rel, logs.as_deref().unwrap_or("(global)"), kw, body);
                script = None;
            } else {
                lines.push(line);
            }
            continue;
        }
        if t.is_empty() || t[0] == b'#' {
            continue;
        }
        if let Some(kw) = SCRIPTS.iter().find(|k| first == k.as_bytes()) {
            script = Some((kw, Vec::new()));
        } else if first == b"include" {
            let arg = t[first.len()..].trim_ascii();
            let target = arg.strip_prefix(b"/").unwrap_or(arg);
            include(cx, &PathBuf::from(std::ffi::OsStr::from_bytes(target)), depth + 1, seen, out);
        } else if t.ends_with(b"{") {
            pending.push(t[..t.len() - 1].trim_ascii());
            let names: Vec<&[u8]> = pending.drain(..).filter(|p| !p.is_empty()).collect();
            logs = Some(String::from_utf8_lossy(&names.join(&b' ')).into_owned());
        } else if t == b"}" {
            logs = None;
        } else if logs.is_none() && matches!(t[0], b'/' | b'"' | b'~') {
            pending.push(t);
        }
    }
}

fn push(cx: &mut Ctx, out: &mut Vec<Entry>, rel: &Path, logs: &str, kw: &str, body: Vec<u8>) {
    let first_log = logs.split_whitespace().next().unwrap_or(logs);
    let mut e = cx.entry(Kind::Logrotate, rel, format!("{first_log}:{kw}"));
    e.trigger = Trigger::Schedule;
    e.principal = Some("root".into());
    e.enabled = Enablement::Enabled;
    e.note("script", kw);
    e.note("logs", logs);
    if std::str::from_utf8(&body).is_err() {
        e.flag(crate::entry::Flag::EncodingAnomaly);
    }
    e.command = Some(body);
    out.push(e);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan};

    fn put(dir: &Path, rel: &str, body: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Logrotate)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    #[test]
    fn scripts_are_read_from_the_files_logrotate_includes() {
        let d = crate::testing::Tree::new("logrotate");
        put(&d, "etc/logrotate.conf", b"weekly\ninclude /etc/logrotate.d\n");
        put(
            &d,
            "etc/logrotate.d/nginx",
            b"/var/log/nginx/*.log\n/var/log/nginx/x.log\n{\n  daily\n  postrotate\n    invoke-rc.d nginx rotate >/dev/null 2>&1\n    /opt/beacon &\n  endscript\n  # prerotate\n}\n",
        );
        put(&d, "etc/logrotate.d/.hidden", b"/x {\n firstaction\n  /tmp/h\n endscript\n}\n");
        put(&d, "etc/logrotate.d/old.dpkg-old", b"/y {\n postrotate\n  /tmp/never\n endscript\n}\n");
        let s = scan(&d);
        let mut got: Vec<(String, String)> =
            s.entries.iter().map(|e| (e.name.clone(), String::from_utf8_lossy(e.command.as_deref().unwrap()).into_owned())).collect();
        got.sort();
        assert_eq!(
            got,
            [
                ("/var/log/nginx/*.log:postrotate".to_string(), "    invoke-rc.d nginx rotate >/dev/null 2>&1\n    /opt/beacon &".to_string()),
                ("/x:firstaction".to_string(), "  /tmp/h".to_string()),
            ],
            "a dotfile is read, a taboo extension is not"
        );
        assert!(s.entries.iter().all(|e| e.enabled == Enablement::Disabled), "logrotate is not installed here");
        put(&d, "usr/sbin/logrotate", b"");
        let s = scan(&d);
        assert!(s.entries.iter().all(|e| e.enabled == Enablement::Enabled && e.trigger == Trigger::Schedule));
    }
}
