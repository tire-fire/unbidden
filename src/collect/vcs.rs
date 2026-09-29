//! Mercurial's hooks: shell commands hg runs, as whoever runs hg, when an
//! event fires in any repository, from the `[hooks]` section of
//! /etc/mercurial/hgrc, /etc/mercurial/hgrc.d/*.rc in name order, and each
//! account's ~/.hgrc, as hg reads them (rcutil.py). A key is the event or
//! `event.name`; a value beginning `python:` names a Python function loaded
//! into hg instead of a command. Git's hooks are the deep collector's.

use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Vcs;

const CAP: usize = 256 * 1024;

impl Collector for Vcs {
    fn name(&self) -> &'static str {
        "vcs"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        let installed = cx.root.exists("usr/bin/hg");
        let mut files: Vec<(PathBuf, Option<String>)> = vec![(PathBuf::from("etc/mercurial/hgrc"), None)];
        let mut rcs: Vec<PathBuf> = cx
            .dir(Path::new("etc/mercurial/hgrc.d"))
            .into_iter()
            .filter(|e| !e.is_dir && e.name.to_string_lossy().ends_with(".rc"))
            .map(|e| Path::new("etc/mercurial/hgrc.d").join(e.name))
            .collect();
        rcs.sort();
        files.extend(rcs.into_iter().map(|f| (f, None)));
        for u in crate::users::one_per_home(cx.users) {
            files.push((u.in_home(".hgrc"), Some(u.name.clone())));
        }
        for (rel, principal) in files {
            let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
            for (key, value) in hooks_section(&String::from_utf8_lossy(&bytes)) {
                let mut e = cx.entry(Kind::MercurialHook, &rel, format!("hg:{key}"));
                e.trigger = Trigger::Always;
                e.enabled = Enablement::Enabled;
                e.principal = principal.clone();
                e.note("event", key.split('.').next().unwrap_or_default());
                if let Some(py) = value.strip_prefix("python:") {
                    e.note("python", py.trim());
                    e.note("target_unverifiable", "a Python function loaded into hg");
                } else {
                    e.command = Some(value.as_bytes().to_vec());
                    if let Some(first) = value.split_whitespace().next().filter(|w| w.starts_with('/')) {
                        e.target_path = Some(PathBuf::from(first));
                    }
                }
                if !installed {
                    e.enabled = Enablement::Disabled;
                    e.note("not_run", "hg is not installed");
                }
                out.push(e);
            }
        }
        out
    }
}

/// The `[hooks]` section's settings, as hg's config parser reads them: `#`
/// and `;` comment lines, `key = value`, an indented line continuing the
/// value, a later key replacing an earlier one in the same file.
fn hooks_section(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut in_hooks = false;
    for line in text.lines() {
        let t = line.trim_end();
        if t.trim_start().starts_with(['#', ';']) || t.trim().is_empty() {
            continue;
        }
        if let Some(name) = t.trim().strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            in_hooks = name.trim() == "hooks";
            continue;
        }
        if !in_hooks {
            continue;
        }
        if t.starts_with([' ', '\t']) {
            if let Some((_, v)) = out.last_mut() {
                v.push(' ');
                v.push_str(t.trim());
            }
            continue;
        }
        let Some((k, v)) = t.split_once(['=', ':']) else { continue };
        let (k, v) = (k.trim().to_string(), v.trim().to_string());
        if let Some(prev) = out.iter_mut().find(|(pk, _)| *pk == k) {
            prev.1 = v;
        } else {
            out.push((k, v));
        }
    }
    out
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
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Vcs)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    #[test]
    fn mercurial_hooks_are_commands_hg_runs_on_its_events() {
        let d = crate::testing::Tree::new("hg");
        put(&d, "usr/bin/hg", b"");
        put(&d, "etc/passwd", b"root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n");
        put(&d, "etc/mercurial/hgrc", b"[ui]\nusername = x\n[hooks]\n# c\npretxncommit.lint = /opt/lint\n  --strict\nupdate = python:mod.fn\n[paths]\ndefault = x\n");
        put(&d, "etc/mercurial/hgrc.d/10-site.rc", b"[hooks]\nchangegroup = /usr/local/bin/notify\n");
        put(&d, "home/alice/.hgrc", b"[hooks]\npost-pull = ~/.local/bin/beacon\n");
        let s = scan(&d);
        let mut got: Vec<(&str, Option<&str>, Option<&str>)> = s
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.command.as_deref().map(|c| std::str::from_utf8(c).unwrap()), e.principal.as_deref()))
            .collect();
        got.sort();
        assert_eq!(
            got,
            [
                ("hg:changegroup", Some("/usr/local/bin/notify"), None),
                ("hg:post-pull", Some("~/.local/bin/beacon"), Some("alice")),
                ("hg:pretxncommit.lint", Some("/opt/lint --strict"), None),
                ("hg:update", None, None),
            ]
        );
        let py = s.entries.iter().find(|e| e.name == "hg:update").unwrap();
        assert_eq!(py.raw["python"], "mod.fn");
    }

    #[test]
    fn two_accounts_sharing_a_home_report_its_hgrc_once() {
        let d = crate::testing::Tree::new("hg-shared");
        put(&d, "usr/bin/hg", b"");
        put(&d, "etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/sh\nalias:x:1001:1001::/home/alice:/bin/sh\n");
        put(&d, "home/alice/.hgrc", b"[hooks]\npost-pull = /opt/beacon\n");
        let s = scan(&d);
        let names: Vec<&str> = s.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["hg:post-pull"], "not also hg:post-pull#2 for the second account");
    }
}
