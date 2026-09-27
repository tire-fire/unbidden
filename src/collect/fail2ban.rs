//! fail2ban's actions: shell commands fail2ban-server runs as root when a
//! jail starts, stops, bans and unbans, and Python actions it loads.
//!
//! Read as fail2ban 1.0 reads them (client/configreader.py,
//! configparserinc.py, jailreader.py, helpers.py). A configuration name is
//! read as `<name>.conf`, `<name>.d/*.conf`, `<name>.local`, then
//! `<name>.d/*.local`, each file's `[INCLUDES]` `before` and `after` read
//! around it; INI as Python's ConfigParser reads it, keys lowercased, `;`
//! after a blank starting an inline comment, indented lines continuing a
//! value, a later file replacing an earlier value. A jail is enabled by
//! `enabled`; its `action`, `%(name)s` interpolated from the jail and then
//! `[DEFAULT]`, is a list of `name[options]`, split on blanks outside the
//! brackets. `name.py` is Python loaded from action.d; any other name reads
//! action.d/`name`, whose `[Definition]` `action*` keys are the commands,
//! their `<tags>` filled from the action's `[Init]` and `[Definition]`.
//! Only actions an enabled jail reaches, directly or through an include,
//! are reported: the rest never run, and the jail that would name one is
//! what a change would show.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Fail2ban;

const CAP: usize = 256 * 1024;
const BASE: &str = "etc/fail2ban";
/// Includes nest; a loop ends here, as interpolation does past its depth.
const MAX_DEPTH: usize = 10;

/// Section, then key, then the value and the file that set it.
type Ini = BTreeMap<String, BTreeMap<String, (String, PathBuf)>>;

impl Collector for Fail2ban {
    fn name(&self) -> &'static str {
        "fail2ban"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        let installed = cx.root.exists("usr/bin/fail2ban-server");
        let jails = read_config(cx, "jail");
        let mut used: BTreeSet<String> = BTreeSet::new();
        for (section, keys) in &jails {
            if section == "DEFAULT" || section == "INCLUDES" {
                continue;
            }
            let get = |k: &str| lookup(&jails, section, k);
            let enabled = get("enabled").is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "yes" | "1" | "on"));
            if !enabled {
                continue;
            }
            let _ = keys;
            if let Some(action) = get("action") {
                used.extend(split_actions(&interpolate(&jails, section, &action, 0)));
            }
        }
        // What the used actions include is used too.
        let mut reach: BTreeSet<String> = BTreeSet::new();
        let mut queue: Vec<String> = used.iter().cloned().collect();
        while let Some(n) = queue.pop() {
            if !reach.insert(n.clone()) || n.ends_with(".py") {
                continue;
            }
            for inc in includes_of(cx, &format!("action.d/{n}")) {
                queue.push(inc);
            }
        }
        for name in reach {
            if name.ends_with(".py") {
                let rel = Path::new(BASE).join("action.d").join(&name);
                if !cx.root.exists(&rel) {
                    continue;
                }
                let mut e = entry(cx, &rel, format!("fail2ban:{name}"));
                e.target_path = Some(cx.root.abs(&rel));
                e.note("loaded_by", "fail2ban-server");
                gate(&mut e, installed);
                out.push(e);
                continue;
            }
            let own = layers(cx, &format!("action.d/{name}"));
            let action = read_config(cx, &format!("action.d/{name}"));
            let Some(def) = action.get("Definition") else { continue };
            for (key, (value, file)) in def {
                // A command an include defines is reported under the action
                // whose file it is.
                if !key.starts_with("action") || key.contains("_on_") || value.trim().is_empty() || !own.contains(file) {
                    continue;
                }
                let mut e = entry(cx, file, format!("fail2ban:{name}:{key}"));
                e.command = Some(tags(&action, &interpolate(&action, "Definition", value, 0), 0).into_bytes());
                e.note("run_when", key.trim_start_matches("action"));
                gate(&mut e, installed);
                out.push(e);
            }
        }
        crate::entry::dedup_ids(&mut out);
        out
    }
}

fn entry(cx: &mut Ctx, rel: &Path, name: String) -> Entry {
    let mut e = cx.entry(Kind::EventHandler, rel, name);
    e.trigger = Trigger::Always;
    e.principal = Some("root".into());
    e.enabled = Enablement::Enabled;
    e.note("run_by", "fail2ban");
    e
}

fn gate(e: &mut Entry, installed: bool) {
    if !installed {
        e.enabled = Enablement::Disabled;
        e.note("not_run", "fail2ban is not installed");
    }
}

/// The files fail2ban reads for a configuration name, in order.
fn layers(cx: &mut Ctx, name: &str) -> Vec<PathBuf> {
    let base = Path::new(BASE);
    let mut files = vec![base.join(format!("{name}.conf"))];
    let dir = base.join(format!("{name}.d"));
    let mut in_dir = |suffix: &str, files: &mut Vec<PathBuf>| {
        let mut v: Vec<PathBuf> = cx
            .dir(&dir)
            .into_iter()
            .filter(|e| !e.is_dir && e.name.to_string_lossy().ends_with(suffix))
            .map(|e| dir.join(e.name))
            .collect();
        v.sort();
        files.extend(v);
    };
    in_dir(".conf", &mut files);
    files.push(base.join(format!("{name}.local")));
    in_dir(".local", &mut files);
    files
}

fn read_config(cx: &mut Ctx, name: &str) -> Ini {
    let mut ini = Ini::new();
    let mut seen = BTreeSet::new();
    for f in layers(cx, name) {
        read_with_includes(cx, &f, 0, &mut seen, &mut ini);
    }
    ini
}

/// A file's `before` includes, the file, then its `after` ones.
fn read_with_includes(cx: &mut Ctx, rel: &Path, depth: usize, seen: &mut BTreeSet<PathBuf>, ini: &mut Ini) {
    if depth > MAX_DEPTH || !seen.insert(rel.to_path_buf()) {
        return;
    }
    let Some(bytes) = cx.read_capped(rel, CAP) else { return };
    let own = parse(&String::from_utf8_lossy(&bytes), rel);
    let dir = rel.parent().unwrap_or(Path::new("")).to_path_buf();
    let inc = |k: &str| {
        own.get("INCLUDES").and_then(|s| s.get(k)).map(|(v, _)| v.split_whitespace().map(|p| dir.join(p)).collect::<Vec<_>>()).unwrap_or_default()
    };
    let (before, after) = (inc("before"), inc("after"));
    for b in before {
        read_with_includes(cx, &b, depth + 1, seen, ini);
    }
    for (section, keys) in own {
        ini.entry(section).or_default().extend(keys);
    }
    for a in after {
        read_with_includes(cx, &a, depth + 1, seen, ini);
    }
}

/// The action names an action file's `[INCLUDES]` pulls in, from any of
/// its layers.
fn includes_of(cx: &mut Ctx, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for f in layers(cx, name) {
        let Some(bytes) = cx.read_capped(&f, CAP) else { continue };
        let ini = parse(&String::from_utf8_lossy(&bytes), &f);
        for k in ["before", "after"] {
            if let Some((v, _)) = ini.get("INCLUDES").and_then(|s| s.get(k)) {
                for p in v.split_whitespace() {
                    let stem = p.strip_suffix(".conf").or_else(|| p.strip_suffix(".local")).unwrap_or(p);
                    out.push(stem.to_string());
                }
            }
        }
    }
    out
}

/// ConfigParser's reading of one file.
fn parse(text: &str, file: &Path) -> Ini {
    let mut ini = Ini::new();
    let mut section: Option<String> = None;
    let mut key: Option<String> = None;
    for raw in text.lines() {
        let stripped = raw.trim();
        if stripped.starts_with('#') || stripped.starts_with(';') {
            continue;
        }
        // Inline comments: `;` after white space.
        let line = match raw.find(" ;").or_else(|| raw.find("\t;")) {
            Some(i) => &raw[..i],
            None => raw,
        };
        if line.trim().is_empty() {
            key = None;
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if let (Some(s), Some(k)) = (&section, &key) {
                if let Some((v, _)) = ini.get_mut(s).and_then(|m| m.get_mut(k)) {
                    v.push('\n');
                    v.push_str(line.trim());
                }
            }
            continue;
        }
        let t = line.trim();
        if let Some(name) = t.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            section = Some(name.to_string());
            ini.entry(name.to_string()).or_default();
            key = None;
            continue;
        }
        let Some(s) = &section else { continue };
        let Some(i) = t.find(['=', ':']) else { continue };
        let k = t[..i].trim().to_lowercase();
        let v = t[i + 1..].trim().to_string();
        ini.entry(s.clone()).or_default().insert(k.clone(), (v, file.to_path_buf()));
        key = Some(k);
    }
    ini
}

/// A key's value in a section, or failing that in `[DEFAULT]`.
fn lookup(ini: &Ini, section: &str, key: &str) -> Option<String> {
    ini.get(section).and_then(|s| s.get(key)).or_else(|| ini.get("DEFAULT").and_then(|s| s.get(key))).map(|(v, _)| v.clone())
}

/// `%(name)s` replaced, from the section, `[DEFAULT]`, or `section/name`.
fn interpolate(ini: &Ini, section: &str, value: &str, depth: usize) -> String {
    if depth > MAX_DEPTH {
        return value.to_string();
    }
    let mut out = String::new();
    let mut rest = value;
    while let Some(i) = rest.find("%(") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let Some(end) = after.find(")s") else {
            out.push_str(&rest[i..]);
            return out;
        };
        let name = after[..end].to_lowercase();
        let found = match name.split_once('/') {
            Some((sec, key)) => lookup(ini, sec, key),
            None => lookup(ini, section, &name),
        };
        match found {
            Some(v) => out.push_str(&interpolate(ini, section, &v, depth + 1)),
            None => out.push_str(&rest[i..i + 2 + end + 2]),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// `<tag>` replaced as fail2ban replaces it from the action's own settings,
/// `[Init]` first, then `[Definition]`; tags only a ban supplies, `<ip>` and
/// the like, stay as written.
fn tags(ini: &Ini, value: &str, depth: usize) -> String {
    if depth > MAX_DEPTH {
        return value.to_string();
    }
    let mut out = String::new();
    let mut rest = value;
    while let Some(i) = rest.find('<') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let end = after.find('>').filter(|&e| e > 0 && after[..e].chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-'));
        let Some(end) = end else {
            out.push('<');
            rest = after;
            continue;
        };
        let name = after[..end].to_lowercase();
        let found = ["Init", "Definition"].iter().find_map(|s| ini.get(*s).and_then(|m| m.get(&name))).map(|(v, _)| v.clone());
        match found {
            Some(v) => out.push_str(&tags(ini, &interpolate(ini, "Definition", &v, 0), depth + 1)),
            None => out.push_str(&rest[i..i + end + 2]),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// `splitWithOptions` and `extractOptions`: the names in an action list.
fn split_actions(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (mut depth, mut quote) = (0usize, None::<char>);
    let mut current = String::new();
    for c in value.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') if depth > 0 => quote = Some(c),
            (None, '[') => depth += 1,
            (None, ']') => depth = depth.saturating_sub(1),
            (None, c) if c.is_whitespace() && depth == 0 => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    if !current.is_empty() {
        out.push(current);
    }
    out.into_iter().map(|a| a.split('[').next().unwrap_or_default().trim().to_string()).filter(|n| !n.is_empty()).collect()
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
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Fail2ban)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    #[test]
    fn actions_enabled_jails_name_run_and_others_are_off() {
        let d = std::env::temp_dir().join(format!("unbidden-fail2ban-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "usr/bin/fail2ban-server", b"");
        put(
            &d,
            "etc/fail2ban/jail.conf",
            b"[DEFAULT]\nenabled = false\nbanaction = iptables-multiport\naction_ = %(banaction)s[port=\"%(port)s\", chain=\"<chain>\"]\naction = %(action_)s\nport = 0:65535\n\n[sshd]\nport = ssh\n\n[apache]\naction = beacon[x=1]\n         %(action_)s\n",
        );
        put(&d, "etc/fail2ban/jail.d/defaults.conf", b"[sshd]\nenabled = true\n");
        put(&d, "etc/fail2ban/jail.local", b"[sshd]\naction = %(action_)s\n  hook.py[a=1]\n");
        put(&d, "etc/fail2ban/action.d/iptables-multiport.conf", b"[INCLUDES]\nbefore = iptables.conf\n[Definition]\nactionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>\n");
        put(&d, "etc/fail2ban/action.d/iptables.conf", b"[Definition]\nactionstart = <iptables> -N f2b-<name>\nactionstart_on_demand = false\n[Init]\niptables = iptables <lockingopt>\nlockingopt = -w\nblocktype = REJECT\n");
        put(&d, "etc/fail2ban/action.d/iptables-multiport.local", b"[Definition]\nactionunban = /opt/beacon <ip> ; inline\n  --more\n");
        put(&d, "etc/fail2ban/action.d/beacon.conf", b"[Definition]\nactionban = /opt/never\n");
        put(&d, "etc/fail2ban/action.d/hook.py", b"import os\n");
        let s = scan(&d);
        let got: Vec<(&str, Enablement)> = s.entries.iter().map(|e| (e.name.as_str(), e.enabled)).collect();
        assert_eq!(
            got,
            [
                ("fail2ban:hook.py", Enablement::Enabled),
                ("fail2ban:iptables-multiport:actionban", Enablement::Enabled),
                ("fail2ban:iptables-multiport:actionunban", Enablement::Enabled),
                ("fail2ban:iptables:actionstart", Enablement::Enabled),
            ]
        );
        let unban = s.entries.iter().find(|e| e.name.ends_with("actionunban")).unwrap();
        assert_eq!(unban.command.as_deref(), Some(b"/opt/beacon <ip>\n--more".as_slice()));
        assert!(unban.source.ends_with("iptables-multiport.local"));
        let ban = s.entries.iter().find(|e| e.name == "fail2ban:iptables-multiport:actionban").unwrap();
        assert_eq!(ban.command.as_deref(), Some(b"iptables -w -I f2b-<name> 1 -s <ip> -j REJECT".as_slice()), "tags from the action and its includes, not the ban's");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
