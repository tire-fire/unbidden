//! Package sources and the keys that vouch for them. They run nothing, but a
//! repository and a key trusted to sign it let the next upgrade, which is
//! unattended on many hosts, install anything as root.
//!
//! apt (2.7): /etc/apt/sources.list, and in sources.list.d the one-line
//! `.list` and deb822 `.sources` files apt reads: no dotfile, only letters,
//! digits, `_`, `-`, `:` and `.` in the name, not ending in a dot. One entry
//! per repository line or stanza. `trusted=yes` turns signature checking
//! off; `Signed-By` limits a repository to the keys it names. The keys:
//! /etc/apt/trusted.gpg, the `.gpg` and `.asc` files in trusted.gpg.d (every
//! repository without Signed-By trusts them), and the files Signed-By names.
//!
//! dnf (5.4): the `.repo` files in /etc/yum.repos.d, /etc/distro.repos.d and
//! /usr/share/dnf5/repos.d, one entry per repository, with the key files its
//! `gpgkey` names; `gpgcheck=0` turns package signature checking off.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger, hex};
use crate::scan::{Collector, Ctx};

pub struct Sources;

const CAP: usize = 256 * 1024;

impl Collector for Sources {
    fn name(&self) -> &'static str {
        "sources"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        let mut keys: BTreeSet<PathBuf> = BTreeSet::new();
        let apt_installed = ["usr/bin/apt-get", "bin/apt-get"].iter().any(|p| cx.root.exists(p));
        let dnf_installed = ["usr/bin/dnf", "usr/bin/dnf5", "usr/bin/yum"].iter().any(|p| cx.root.exists(p));
        {
            // What a repository without Signed-By trusts.
            let mut store: Vec<PathBuf> = vec![PathBuf::from("etc/apt/trusted.gpg")];
            store.extend(apt_dir(cx, Path::new("etc/apt/trusted.gpg.d"), &["gpg", "asc"]));
            store.retain(|k| cx.root.exists(k));
            apt(cx, &mut out, &mut keys, &store);
            keys.extend(store);
            keys.extend(apt_dir(cx, Path::new("etc/apt/keyrings"), &["gpg", "asc"]));
        }
        dnf(cx, &mut out, &mut keys);
        // Read either way, and off where the tool that would use them is not
        // installed.
        for e in &mut out {
            let tool = e.raw.get("source_type").cloned().unwrap_or_default();
            let missing = (tool == "apt repository" && !apt_installed) || (tool == "dnf repository" && !dnf_installed);
            if missing {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "its package manager is not installed");
            }
        }
        for rel in keys {
            if !cx.root.stat_follow(&rel).is_ok_and(|m| m.is_file) {
                continue;
            }
            let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let mut e = entry(cx, &rel, format!("key:{name}"));
            e.note("source_type", "signing key");
            e.target_path = Some(cx.root.abs(&rel));
            out.push(e);
        }
        crate::entry::dedup_ids(&mut out);
        out
    }
}

fn entry(cx: &mut Ctx, rel: &Path, name: String) -> Entry {
    let mut e = cx.entry(Kind::PkgSource, rel, name);
    e.trigger = Trigger::PackageOp;
    e.principal = Some("root".into());
    e.enabled = Enablement::Enabled;
    e
}

/// The files apt reads from a parts directory.
fn apt_dir(cx: &mut Ctx, dir: &Path, exts: &[&str]) -> Vec<PathBuf> {
    let mut names: Vec<_> = cx
        .dir(dir)
        .into_iter()
        .filter(|e| {
            let n = e.name.as_encoded_bytes();
            let ext_ok = exts.iter().any(|x| n.len() > x.len() + 1 && n.ends_with(x.as_bytes()) && n[n.len() - x.len() - 1] == b'.');
            !e.is_dir
                && !n.is_empty()
                && n[0] != b'.'
                && ext_ok
                && n.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'.'))
        })
        .map(|e| e.name)
        .collect();
    names.sort();
    names.into_iter().map(|n| dir.join(n)).collect()
}

/// A path apt or dnf names, root-relative: `file://` stripped, absolute.
fn key_path(spec: &str) -> Option<PathBuf> {
    let p = spec.strip_prefix("file://").unwrap_or(spec);
    p.strip_prefix('/').map(PathBuf::from)
}

fn apt(cx: &mut Ctx, out: &mut Vec<Entry>, keys: &mut BTreeSet<PathBuf>, store: &[PathBuf]) {
    let mut files = vec![PathBuf::from("etc/apt/sources.list")];
    files.extend(apt_dir(cx, Path::new("etc/apt/sources.list.d"), &["list", "sources"]));
    for rel in files {
        let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        let deb822 = rel.extension().is_some_and(|x| x == "sources");
        let repos = if deb822 { deb822_stanzas(&text) } else { one_line(&text) };
        for r in repos {
            let digest = hex(&blake3::hash(format!("{}|{}|{}", r.types, r.uris, r.suites).as_bytes()).as_bytes()[..6]);
            let mut e = entry(cx, &rel, format!("apt:{}:{digest}", r.uris.split_whitespace().next().unwrap_or("")));
            e.note("source_type", "apt repository");
            e.note("types", r.types.clone());
            e.note("uris", r.uris.clone());
            e.note("suites", r.suites.clone());
            if !r.components.is_empty() {
                e.note("components", r.components.clone());
            }
            if r.trusted {
                e.note("signature_checking", "off (trusted=yes)");
            }
            // The key files this repository trusts, which enrichment checks.
            let trusts: Vec<PathBuf> = match &r.signed_by {
                Some(s) if s.contains("BEGIN PGP") => {
                    e.note("signed_by", "a key given inline");
                    Vec::new()
                }
                Some(s) => {
                    e.note("signed_by", s.clone());
                    s.split([',', ' ']).filter_map(key_path).collect()
                }
                None => {
                    e.note("signed_by", "every key in trusted.gpg and trusted.gpg.d");
                    store.to_vec()
                }
            };
            if !trusts.is_empty() && !r.trusted {
                let abs: Vec<String> = trusts.iter().map(|k| cx.root.abs(k).display().to_string()).collect();
                e.note("trusts", abs.join(", "));
            }
            keys.extend(trusts);
            if !r.enabled {
                e.enabled = Enablement::Disabled;
            }
            out.push(e);
        }
    }
}

#[derive(Default)]
struct Repo {
    types: String,
    uris: String,
    suites: String,
    components: String,
    signed_by: Option<String>,
    trusted: bool,
    enabled: bool,
}

/// `deb [opt=value ...] uri suite [component ...]`, `#` comments.
fn one_line(text: &str) -> Vec<Repo> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let mut rest = line;
        let Some(ty) = rest.split_whitespace().next().filter(|t| matches!(*t, "deb" | "deb-src")) else { continue };
        rest = rest[ty.len()..].trim_start();
        let mut r = Repo { types: ty.to_string(), enabled: true, ..Default::default() };
        if let Some(opts) = rest.strip_prefix('[') {
            let Some(end) = opts.find(']') else { continue };
            for o in opts[..end].split_whitespace() {
                let (k, v) = o.split_once('=').unwrap_or((o, ""));
                match k.to_ascii_lowercase().as_str() {
                    "signed-by" => r.signed_by = Some(v.to_string()),
                    "trusted" => r.trusted = v.eq_ignore_ascii_case("yes"),
                    _ => {}
                }
            }
            rest = opts[end + 1..].trim_start();
        }
        let words: Vec<&str> = rest.split_whitespace().collect();
        let [uri, suite, components @ ..] = words.as_slice() else { continue };
        (r.uris, r.suites, r.components) = (uri.to_string(), suite.to_string(), components.join(" "));
        out.push(r);
    }
    out
}

/// deb822 stanzas: `Field: value` with continuation lines, stanzas
/// separated by blank lines, `#` lines comments.
fn deb822_stanzas(text: &str) -> Vec<Repo> {
    let mut out = Vec::new();
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut flush = |fields: &mut Vec<(String, String)>| {
        if fields.is_empty() {
            return;
        }
        let get = |k: &str| fields.iter().rev().find(|(f, _)| f.eq_ignore_ascii_case(k)).map(|(_, v)| v.trim().to_string());
        let mut r = Repo { enabled: true, ..Default::default() };
        r.types = get("Types").unwrap_or_default();
        r.uris = get("URIs").unwrap_or_default();
        r.suites = get("Suites").unwrap_or_default();
        r.components = get("Components").unwrap_or_default();
        r.signed_by = get("Signed-By");
        r.trusted = get("Trusted").is_some_and(|v| v.eq_ignore_ascii_case("yes"));
        r.enabled = !get("Enabled").is_some_and(|v| v.eq_ignore_ascii_case("no"));
        if !r.uris.is_empty() {
            out.push(r);
        }
        fields.clear();
    };
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        if line.trim().is_empty() {
            flush(&mut fields);
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = fields.last_mut() {
                v.push('\n');
                v.push_str(line.trim());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            fields.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    flush(&mut fields);
    out
}

fn dnf(cx: &mut Ctx, out: &mut Vec<Entry>, keys: &mut BTreeSet<PathBuf>) {
    for dir in ["etc/yum.repos.d", "etc/distro.repos.d", "usr/share/dnf5/repos.d"] {
        let mut names: Vec<_> =
            cx.dir(dir).into_iter().filter(|e| !e.is_dir && e.name.as_encoded_bytes().ends_with(b".repo")).map(|e| e.name).collect();
        names.sort();
        for n in names {
            let rel = Path::new(dir).join(n);
            let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
            let text = String::from_utf8_lossy(&bytes);
            let mut sections: Vec<(String, Vec<(String, String)>)> = Vec::new();
            for line in text.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with(['#', ';']) {
                    continue;
                }
                if let Some(id) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                    sections.push((id.to_string(), Vec::new()));
                } else if let (Some((k, v)), Some((_, kv))) = (t.split_once('='), sections.last_mut()) {
                    kv.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
                }
            }
            for (id, kv) in sections {
                if id == "main" {
                    continue;
                }
                let get = |k: &str| kv.iter().rev().find(|(f, _)| f == k).map(|(_, v)| v.clone());
                let mut e = entry(cx, &rel, format!("dnf:{id}"));
                e.note("source_type", "dnf repository");
                for k in ["baseurl", "metalink", "mirrorlist", "gpgkey"] {
                    if let Some(v) = get(k) {
                        e.note(k, v);
                    }
                }
                let off = |k: &str| get(k).is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no"));
                if off("gpgcheck") {
                    e.note("signature_checking", "off (gpgcheck=0)");
                }
                if off("enabled") {
                    e.enabled = Enablement::Disabled;
                }
                if let Some(g) = get("gpgkey") {
                    for k in g.split([',', ' ', '\n']).filter_map(key_path) {
                        // A key named with dnf's own variables is not one file.
                        if !k.to_string_lossy().contains('$') {
                            keys.insert(k);
                        }
                    }
                }
                out.push(e);
            }
        }
    }
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
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Sources)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    #[test]
    fn apt_and_dnf_sources_and_their_keys_are_read_as_each_tool_reads_them() {
        let d = std::env::temp_dir().join(format!("unbidden-sources-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "usr/bin/apt-get", b"");
        put(&d, "etc/apt/sources.list", b"# old style\ndeb http://deb.debian.org/debian bookworm main\n");
        put(
            &d,
            "etc/apt/sources.list.d/evil.list",
            b"deb [trusted=yes arch=amd64] http://203.0.113.9/repo stable main # planted\n",
        );
        put(
            &d,
            "etc/apt/sources.list.d/vendor.sources",
            b"Types: deb\nURIs: https://pkg.example/apt\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/keyrings/example.gpg\n\nTypes: deb-src\nURIs: https://pkg.example/apt\nSuites: stable\nEnabled: no\n",
        );
        put(&d, "etc/apt/sources.list.d/.hidden.list", b"deb http://x/ y z\n");
        put(&d, "etc/apt/sources.list.d/backup.list.save", b"deb http://x/ y z\n");
        put(&d, "etc/apt/keyrings/example.gpg", b"key");
        put(&d, "etc/apt/trusted.gpg.d/planted.asc", b"key");
        put(&d, "usr/bin/dnf5", b"");
        put(&d, "etc/yum.repos.d/x.repo", b"[x]\nname=X\nbaseurl=http://203.0.113.9/x\ngpgcheck=0\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-x\n[y]\nbaseurl=http://y/\nenabled=0\n");
        put(&d, "etc/pki/rpm-gpg/RPM-GPG-KEY-x", b"key");
        let s = scan(&d);
        let with = |k: &str, v: &str| s.entries.iter().filter(|e| e.raw.get(k).is_some_and(|x| x == v)).count();
        assert_eq!(with("source_type", "apt repository"), 4, "a dotfile and a .save file are not read");
        let evil = s.entries.iter().find(|e| e.raw.get("uris").is_some_and(|u| u.contains("203.0.113.9"))).unwrap();
        assert_eq!(evil.raw["signature_checking"], "off (trusted=yes)");
        let src = s.entries.iter().find(|e| e.raw.get("types").is_some_and(|t| t == "deb-src")).unwrap();
        assert_eq!(src.enabled, Enablement::Disabled);
        let mut keys: Vec<&str> = s.entries.iter().filter(|e| e.name.starts_with("key:")).map(|e| e.name.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["key:RPM-GPG-KEY-x", "key:example.gpg", "key:planted.asc"]);
        let x = s.entries.iter().find(|e| e.name == "dnf:x").unwrap();
        assert_eq!((x.raw["signature_checking"].as_str(), x.trigger), ("off (gpgcheck=0)", Trigger::PackageOp));
        assert_eq!(s.entries.iter().find(|e| e.name == "dnf:y").unwrap().enabled, Enablement::Disabled);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
