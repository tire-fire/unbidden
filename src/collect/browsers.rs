//! Browser policy that puts code in every user's browser: extensions the
//! administrator forces installed, and Firefox's autoconfig, a JavaScript
//! file run with the browser's own privileges at every start.
//!
//! Chromium and Chrome (the Linux policy loader): each `*.json` in
//! /etc/chromium/policies/managed, /etc/chromium-browser/policies/managed
//! and /etc/opt/chrome/policies/managed; `ExtensionInstallForcelist` lists
//! `id;update_url`, and `ExtensionSettings` maps an id to an
//! `installation_mode` of `force_installed` or `normal_installed` with an
//! `update_url`. Firefox (Enterprise Policies): `policies.json` in the
//! install's `distribution` directory and in /etc/firefox/policies;
//! `Extensions.Install` lists URLs or paths, and `ExtensionSettings` maps
//! an id to `installation_mode` and `install_url`. Autoconfig: a
//! `general.config.filename` pref in the install's `defaults/pref/*.js`, or
//! in the distribution's /etc pref files, names a `.cfg` in the install
//! directory that Firefox evaluates at startup.

use crate::entry::key;
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Browsers;

const CAP: usize = 1 << 20;

impl Collector for Browsers {
    fn name(&self) -> &'static str {
        "browsers"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        chromium(cx, &mut out);
        firefox(cx, &mut out);
        out
    }
}

fn entry(cx: &mut Ctx, rel: &Path, name: String, browser: &str, installed: bool) -> Entry {
    let mut e = cx.entry(Kind::BrowserPolicy, rel, name);
    e.trigger = Trigger::Login;
    e.enabled = Enablement::Enabled;
    e.note("browser", browser);
    if !installed {
        e.enabled = Enablement::Disabled;
        e.note("not_run", format!("{browser} is not installed"));
    }
    e
}

fn sorted_json(cx: &mut Ctx, dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> =
        cx.dir(dir).into_iter().filter(|e| !e.is_dir && e.name.to_string_lossy().ends_with(".json")).map(|e| dir.join(e.name)).collect();
    v.sort();
    v
}

/// An extension a policy installs: its id, how, and from where.
fn extension(cx: &mut Ctx, rel: &Path, browser: &str, installed: bool, id: &str, mode: &str, url: Option<&str>) -> Entry {
    let mut e = entry(cx, rel, format!("{browser}:extension:{id}"), browser, installed);
    e.note("installation_mode", mode);
    e.note("extension_id", id);
    match url {
        Some(u) if u.starts_with('/') => e.target_path = Some(PathBuf::from(u)),
        Some(u) => {
            e.note("install_url", u);
            e.note(key::TARGET_UNVERIFIABLE, "code fetched from a URL");
        }
        None => e.note(key::TARGET_UNVERIFIABLE, "code fetched from the browser's web store"),
    }
    e
}

fn chromium(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let dirs: [(&str, &str, &[&str]); 3] = [
        ("etc/chromium/policies/managed", "chromium", &["usr/bin/chromium", "usr/lib/chromium/chromium", "usr/lib64/chromium-browser/chromium-browser"]),
        ("etc/chromium-browser/policies/managed", "chromium", &["usr/bin/chromium-browser", "usr/lib/chromium-browser/chromium-browser"]),
        ("etc/opt/chrome/policies/managed", "google-chrome", &["opt/google/chrome/chrome"]),
    ];
    for (dir, browser, bins) in dirs {
        let installed = bins.iter().any(|b| cx.root.exists(b));
        for rel in sorted_json(cx, Path::new(dir)) {
            let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else { continue };
            if let Some(list) = v.get("ExtensionInstallForcelist").and_then(|l| l.as_array()) {
                for item in list.iter().filter_map(|i| i.as_str()) {
                    let (id, url) = item.split_once(';').map(|(i, u)| (i, Some(u))).unwrap_or((item, None));
                    out.push(extension(cx, &rel, browser, installed, id, "force_installed", url));
                }
            }
            if let Some(settings) = v.get("ExtensionSettings").and_then(|s| s.as_object()) {
                for (id, cfg) in settings {
                    let mode = cfg.get("installation_mode").and_then(|m| m.as_str()).unwrap_or("");
                    if !matches!(mode, "force_installed" | "normal_installed") {
                        continue;
                    }
                    let url = cfg.get("update_url").and_then(|u| u.as_str());
                    out.push(extension(cx, &rel, browser, installed, id, mode, url));
                }
            }
        }
    }
}

/// Firefox install directories that exist, each with its name.
fn firefox_installs(cx: &mut Ctx) -> Vec<(PathBuf, &'static str)> {
    let mut out = Vec::new();
    for (dir, browser) in [
        ("usr/lib/firefox-esr", "firefox-esr"),
        ("usr/lib/firefox", "firefox"),
        ("usr/lib64/firefox", "firefox"),
        ("usr/lib64/firefox-esr", "firefox-esr"),
        ("opt/firefox", "firefox"),
    ] {
        if cx.root.exists(dir) {
            out.push((PathBuf::from(dir), browser));
        }
    }
    out
}

fn firefox(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installs = firefox_installs(cx);
    let any = !installs.is_empty();
    let mut policy_files: Vec<(PathBuf, &str, bool)> = installs.iter().map(|(d, b)| (d.join("distribution/policies.json"), *b, true)).collect();
    policy_files.push((PathBuf::from("etc/firefox/policies/policies.json"), "firefox", any));
    for (rel, browser, installed) in policy_files {
        let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else { continue };
        let Some(p) = v.get("policies") else { continue };
        if let Some(list) = p.get("Extensions").and_then(|e| e.get("Install")).and_then(|l| l.as_array()) {
            for item in list.iter().filter_map(|i| i.as_str()) {
                let id = item.rsplit('/').next().unwrap_or(item);
                out.push(extension(cx, &rel, browser, installed, id, "force_installed", Some(item)));
            }
        }
        if let Some(settings) = p.get("ExtensionSettings").and_then(|s| s.as_object()) {
            for (id, cfg) in settings {
                let mode = cfg.get("installation_mode").and_then(|m| m.as_str()).unwrap_or("");
                if !matches!(mode, "force_installed" | "normal_installed") {
                    continue;
                }
                let url = cfg.get("install_url").and_then(|u| u.as_str());
                out.push(extension(cx, &rel, browser, installed, id, mode, url));
            }
        }
    }
    // Autoconfig: the pref names a file in the install directory.
    let mut pref_files: Vec<(PathBuf, PathBuf, &str)> = Vec::new();
    for (dir, browser) in &installs {
        for sub in ["defaults/pref", "browser/defaults/preferences"] {
            let mut js: Vec<PathBuf> =
                cx.dir(dir.join(sub)).into_iter().filter(|e| !e.is_dir && e.name.to_string_lossy().ends_with(".js")).map(|e| dir.join(sub).join(e.name)).collect();
            js.sort();
            pref_files.extend(js.into_iter().map(|f| (f, dir.clone(), *browser)));
        }
        for etc in ["etc/firefox-esr", "etc/firefox/pref", "etc/firefox"] {
            let mut js: Vec<PathBuf> =
                cx.dir(Path::new(etc)).into_iter().filter(|e| !e.is_dir && e.name.to_string_lossy().ends_with(".js")).map(|e| Path::new(etc).join(e.name)).collect();
            js.sort();
            pref_files.extend(js.into_iter().map(|f| (f, dir.clone(), *browser)));
        }
    }
    for (rel, install, browser) in pref_files {
        let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
        for line in String::from_utf8_lossy(&bytes).lines() {
            let Some(name) = pref_string(line, "general.config.filename") else { continue };
            let mut e = entry(cx, &rel, format!("{browser}:autoconfig:{name}"), browser, true);
            e.note("config_file", name.clone());
            e.note("runs_when", "Firefox starts, as the browser, with chrome privileges");
            let target = if name.starts_with('/') { PathBuf::from(&name) } else { install.join(&name) };
            e.target_path = Some(if name.starts_with('/') { target } else { cx.root.abs(&target) });
            out.push(e);
        }
    }
}

/// The string a `pref("name", "value")`, `lockPref` or `defaultPref` line
/// sets for `key`, if this line sets it.
fn pref_string(line: &str, key: &str) -> Option<String> {
    let t = line.trim();
    let body = t.strip_prefix("pref(").or_else(|| t.strip_prefix("lockPref(")).or_else(|| t.strip_prefix("defaultPref("))?;
    let body = body.trim_start().strip_prefix('"')?;
    let (name, rest) = body.split_once('"')?;
    if name != key {
        return None;
    }
    let rest = rest.trim_start().strip_prefix(',')?.trim_start().strip_prefix('"')?;
    let (value, _) = rest.split_once('"')?;
    (!value.is_empty()).then(|| value.to_string())
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
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Browsers)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    #[test]
    fn forced_extensions_and_autoconfig_are_code_in_every_browser() {
        let d = crate::testing::Tree::new("browsers");
        put(&d, "usr/bin/chromium", b"");
        put(&d, "etc/chromium/policies/managed/site.json", b"{\"ExtensionInstallForcelist\": [\"abcdefghijklmnopabcdefghijklmnop;https://x.example/u.xml\"], \"ExtensionSettings\": {\"*\": {\"installation_mode\": \"blocked\"}, \"ponmlkjihgfedcbaponmlkjihgfedcba\": {\"installation_mode\": \"normal_installed\", \"update_url\": \"https://y.example/u\"}}}");
        put(&d, "usr/lib/firefox-esr/firefox-esr", b"");
        put(&d, "usr/lib/firefox-esr/distribution/policies.json", b"{\"policies\": {\"Extensions\": {\"Install\": [\"/opt/ext/beacon.xpi\"]}, \"ExtensionSettings\": {\"uBlock0@raymondhill.net\": {\"installation_mode\": \"force_installed\", \"install_url\": \"https://addons.mozilla.org/x.xpi\"}}}}");
        put(&d, "usr/lib/firefox-esr/defaults/pref/channel-prefs.js", b"pref(\"app.update.channel\", \"esr\");\n");
        put(&d, "etc/firefox-esr/syspref.js", b"// x\npref(\"general.config.filename\", \"mozilla.cfg\");\npref(\"general.config.obscure_value\", 0);\n");
        put(&d, "etc/opt/chrome/policies/managed/x.json", b"{\"ExtensionInstallForcelist\": [\"chromeidchromeidchromeidchromeid\"]}");
        let s = scan(&d);
        let mut got: Vec<(&str, &str, Option<&str>, Enablement)> = s
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.raw.get("installation_mode").map(String::as_str).unwrap_or("-"), e.target_path.as_deref().and_then(|p| p.to_str()), e.enabled))
            .collect();
        got.sort();
        let cfg = d.join("usr/lib/firefox-esr/mozilla.cfg");
        assert_eq!(
            got,
            [
                ("chromium:extension:abcdefghijklmnopabcdefghijklmnop", "force_installed", None, Enablement::Enabled),
                ("chromium:extension:ponmlkjihgfedcbaponmlkjihgfedcba", "normal_installed", None, Enablement::Enabled),
                ("firefox-esr:autoconfig:mozilla.cfg", "-", Some(cfg.to_str().unwrap()), Enablement::Enabled),
                ("firefox-esr:extension:beacon.xpi", "force_installed", Some("/opt/ext/beacon.xpi"), Enablement::Enabled),
                ("firefox-esr:extension:uBlock0@raymondhill.net", "force_installed", None, Enablement::Enabled),
                ("google-chrome:extension:chromeidchromeidchromeidchromeid", "force_installed", None, Enablement::Disabled),
            ]
        );
    }
}
