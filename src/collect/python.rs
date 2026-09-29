//! Python's startup hooks: code every Python process runs before its own.
//!
//! The site module, which every interpreter imports at start unless told not
//! to (`-S`), reads each `.pth` file in each site-packages directory and
//! executes any line starting `import ` or `import\t`, then imports
//! `sitecustomize` and `usercustomize` if they can be found. A root cron job,
//! a package manager hook or an administrator's script written in Python
//! runs them all, as whoever runs it.
//!
//! Read as CPython 3.10 through 3.14 read them (Lib/site.py, unchanged in
//! this across those versions): `.pth` files whose names do not start with a
//! dot, in sorted order; `#` lines and blank lines skipped. The directories
//! are the ones `site.getsitepackages()` returns on each distribution: the
//! Debian family's `dist-packages` (checked on Ubuntu 24.04), elsewhere
//! `site-packages` under lib64 and lib for /usr/local and /usr (checked on
//! Fedora 44). The user site, `~/.local/lib/pythonX.Y/site-packages`, is
//! read for every account.

use std::collections::BTreeSet;
use std::path::Path;

use crate::entry::{Enablement, Entry, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Python;

const CAP: usize = 256 * 1024;

impl Collector for Python {
    fn name(&self) -> &'static str {
        "python"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let versions = versions(cx);
        let debian = cx.root.exists("usr/lib/python3/dist-packages");
        let mut out = Vec::new();
        let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();
        for v in &versions {
            let (dirs, stdlib): (Vec<String>, Vec<String>) = if debian {
                (
                    vec![
                        format!("usr/local/lib/{v}/dist-packages"),
                        "usr/lib/python3/dist-packages".to_string(),
                        format!("usr/lib/{v}/dist-packages"),
                    ],
                    vec![format!("usr/lib/{v}")],
                )
            } else {
                (
                    vec![
                        format!("usr/local/lib64/{v}/site-packages"),
                        format!("usr/local/lib/{v}/site-packages"),
                        format!("usr/lib64/{v}/site-packages"),
                        format!("usr/lib/{v}/site-packages"),
                    ],
                    vec![format!("usr/lib64/{v}"), format!("usr/lib/{v}")],
                )
            };
            // sitecustomize is looked for on the whole path, the standard
            // library's directory first.
            for dir in stdlib.iter().chain(&dirs) {
                if cx.first_visit(dir, &mut seen).is_some() {
                    site_dir(cx, &mut out, Path::new(dir), None, dir.ends_with("-packages"));
                }
            }
        }
        let users = cx.users;
        for u in crate::users::one_per_home(users) {
            for v in &versions {
                let dir = u.in_home(&format!(".local/lib/{v}/site-packages"));
                if cx.first_visit(&dir, &mut seen).is_some() {
                    site_dir(cx, &mut out, &dir, Some(&u.name), true);
                }
            }
        }
        out
    }
}

/// The installed Python 3 versions, as the `python3.N` directory names under
/// /usr/lib and /usr/lib64.
fn versions(cx: &mut Ctx) -> Vec<String> {
    let mut out = BTreeSet::new();
    for dir in ["usr/lib", "usr/lib64"] {
        for e in cx.dir(dir) {
            let Some(name) = e.name.to_str() else { continue };
            let minor = name.strip_prefix("python3.").unwrap_or_default();
            if e.is_dir && !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit()) {
                out.insert(name.to_string());
            }
        }
    }
    out.into_iter().collect()
}

fn site_dir(cx: &mut Ctx, out: &mut Vec<Entry>, dir: &Path, user: Option<&str>, site: bool) {
    let mut names: Vec<_> = cx.dir(dir).into_iter().filter(|e| !e.is_dir).map(|e| e.name).collect();
    names.sort();
    for name in names {
        let Some(n) = name.to_str() else { continue };
        let rel = dir.join(&name);
        if site && n.ends_with(".pth") && !n.starts_with('.') {
            pth(cx, out, &rel, user);
        } else if matches!(n, "sitecustomize.py" | "usercustomize.py") {
            let module = n.trim_end_matches(".py");
            let mut e = entry(cx, &rel, module.to_string(), user);
            e.target_path = Some(cx.root.abs(&rel));
            e.note("hook", module);
            out.push(e);
        }
    }
}

fn entry(cx: &mut Ctx, rel: &Path, name: String, user: Option<&str>) -> Entry {
    let mut e = cx.entry(Kind::PythonStartup, rel, name);
    e.trigger = Trigger::Always;
    e.enabled = Enablement::Enabled;
    e.principal = user.map(str::to_string);
    e
}

/// One entry per `.pth` file that executes something: its import lines are
/// the command. A file of paths only adds directories to the module path
/// and runs nothing itself.
fn pth(cx: &mut Ctx, out: &mut Vec<Entry>, rel: &Path, user: Option<&str>) {
    let Some(bytes) = cx.read_capped(rel, CAP) else { return };
    let mut imports: Vec<&[u8]> = Vec::new();
    let mut paths = 0;
    // Python splits on every line ending it knows; \n and \r cover what a
    // file on Linux holds.
    for line in bytes.split(|b| *b == b'\n' || *b == b'\r') {
        if line.starts_with(b"#") || line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if line.starts_with(b"import ") || line.starts_with(b"import\t") {
            imports.push(line);
        } else {
            paths += 1;
        }
    }
    if imports.is_empty() {
        return;
    }
    let file = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut e = entry(cx, rel, file, user);
    e.note("hook", "pth");
    e.note("import_lines", imports.len().to_string());
    if paths > 0 {
        e.note("path_lines", paths.to_string());
    }
    e.command = Some(imports.join(&b'\n'));
    // Python, not shell: there is no program in it for enrichment to find.
    e.note("target_unverifiable", "Python code run inside the interpreter");
    if std::str::from_utf8(&bytes).is_err() {
        e.flag(crate::entry::Flag::EncodingAnomaly);
    }
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
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Python)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    fn names(s: &Scan) -> Vec<(String, Option<String>)> {
        let mut v: Vec<_> = s.entries.iter().map(|e| (e.source.to_string_lossy().into_owned(), e.principal.clone())).collect();
        v.sort();
        v
    }

    #[test]
    fn debian_reads_dist_packages_and_every_user_site() {
        let d = std::env::temp_dir().join(format!("unbidden-python-deb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "etc/passwd", b"root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n");
        std::fs::create_dir_all(d.join("usr/lib/python3.12")).unwrap();
        put(&d, "usr/lib/python3/dist-packages/distutils-precedence.pth", b"import os; os.environ.get('X')\n");
        put(&d, "usr/lib/python3/dist-packages/paths.pth", b"# only paths\n/opt/lib\n\n");
        put(&d, "usr/lib/python3/dist-packages/.hidden.pth", b"import evil\n");
        put(&d, "usr/local/lib/python3.12/dist-packages/zz.pth", b"/x\r\nimport\tbeacon\r\n");
        put(&d, "usr/local/lib/python3.12/site-packages/ignored.pth", b"import never\n");
        put(&d, "usr/lib/python3.12/sitecustomize.py", b"import os\n");
        put(&d, "home/alice/.local/lib/python3.12/site-packages/usercustomize.py", b"x=1\n");
        put(&d, "home/alice/.local/lib/python3.12/site-packages/a.pth", b"import hook\n");
        let s = scan(&d);
        let r = d.to_string_lossy().into_owned();
        let want: Vec<(String, Option<String>)> = [
            ("home/alice/.local/lib/python3.12/site-packages/a.pth", Some("alice")),
            ("home/alice/.local/lib/python3.12/site-packages/usercustomize.py", Some("alice")),
            ("usr/lib/python3.12/sitecustomize.py", None),
            ("usr/lib/python3/dist-packages/distutils-precedence.pth", None),
            ("usr/local/lib/python3.12/dist-packages/zz.pth", None),
        ]
        .iter()
        .map(|(p, u)| (format!("{r}/{p}"), u.map(str::to_string)))
        .collect();
        assert_eq!(names(&s), want, "Debian never reads site-packages; a dotted .pth and a paths-only one run nothing");
        let zz = s.entries.iter().find(|e| e.name == "zz.pth").unwrap();
        assert_eq!((zz.command.as_deref(), zz.raw["path_lines"].as_str()), (Some(&b"import\tbeacon"[..]), "1"));
        assert_eq!(zz.trigger, Trigger::Always);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn elsewhere_reads_site_packages_under_lib64_and_lib() {
        let d = std::env::temp_dir().join(format!("unbidden-python-fed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "etc/passwd", b"root:x:0:0::/root:/bin/sh\n");
        put(&d, "usr/lib64/python3.14/site-packages/a.pth", b"import a\n");
        put(&d, "usr/lib/python3.14/site-packages/b.pth", b"import b\n");
        put(&d, "usr/local/lib64/python3.14/site-packages/c.pth", b"import c\n");
        put(&d, "usr/local/lib/python3.14/dist-packages/d.pth", b"import d\n");
        let s = scan(&d);
        let mut got: Vec<&str> = s.entries.iter().map(|e| e.name.as_str()).collect();
        got.sort_unstable();
        assert_eq!(got, ["a.pth", "b.pth", "c.pth"]);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
