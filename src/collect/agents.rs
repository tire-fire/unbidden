//! Programs that auditing, monitoring and configuration-management agents
//! run, each read only by the rule its agent uses to choose them.
//!
//! auditd (audit-userspace 3.0 to 4.x, audispd.c and audispd-pconfig.c):
//! every file in `plugin_dir` (auditd.conf; /etc/audit/plugins.d by
//! default) not starting `.` and with at most one `.` is a plugin
//! configuration, of `key = value` lines split on spaces, keys and `yes`
//! without regard to case. A plugin with `active = yes` has its `path`
//! executed with `args`, as root, for as long as auditd runs. The ownership
//! and mode checks auditd adds differ between releases and are not applied:
//! a plugin one release refuses, the next may run. `path = builtin_*` ran
//! inside auditd until 3.1 and runs /sbin/audisp-af_unix since; whichever
//! the host has is what is reported.
//!
//! collectd (configfile.c, liboconfig): /etc/collectd/collectd.conf
//! (Debian) or /etc/collectd.conf (Fedora), with each top-level `Include`,
//! or `<Include>` with a `Filter` fnmatch on file names, read in its place:
//! a directory is read whole, its entries sorted and dotfiles skipped, eight
//! levels deep. Paths and program names are quoted strings, `\` escaping the
//! next character. The exec plugin's `Exec` and `NotificationExec` run a
//! program, never as root (it refuses), as the user they name; the python,
//! perl and lua plugins load code into collectd itself. A plugin runs only
//! once `LoadPlugin` names it, or with `AutoLoadPlugin true`.
//!
//! incron 0.5.12 (icd-main.cpp, incrontab.cpp, usertable.cpp): tables in
//! `system_table_dir` (/etc/incron.d) and `user_table_dir`
//! (/var/spool/incron), as /etc/incron.conf sets them. Only regular files
//! are loaded, never a symlink; a system table not starting `.` runs as
//! root, a user table named after an account in passwd runs as that account
//! if incron.allow lists it or, with no allow file, incron.deny does not.
//! Debian creates both files empty, so no user table runs there by default.
//! A line is a path and an event mask, split on blanks with `\\` escaping,
//! and the rest of the line, raw, is the command, run through a shell on
//! each event. There is no comment syntax: a line lacking three fields is
//! skipped, and one whose path is not absolute watches nothing.
//!
//! facter 4 external facts (custom_facts/util/config.rb, parser.rb,
//! directory_loader.rb): every facter run, and so every puppet agent run,
//! executes as root each regular file with an execute bit in its external
//! fact directories, not starting `.`, whose extension is none of `yaml`,
//! `txt` and `json` (read as data) or `bat`, `cmd`, `com` and `exe`
//! (ignored). The directories are /etc/facter/facts.d and, except for
//! Debian's patched facter, /etc/puppetlabs/facter/facts.d and
//! /opt/puppetlabs/facter/facts.d; `external-dir` in facter.conf
//! (/etc/facter or /etc/puppetlabs/facter) replaces them, and
//! `no-external-facts = true` turns them off. facter.conf is HOCON; only
//! those two keys are looked for, not parsed as HOCON would. Facts a puppet
//! server syncs down are not read: pluginsync replaces them every run.
//!
//! munin-node 2.0 (Munin::Node::Service, Munin::Node::Config): on each poll
//! it runs every regular executable file in /etc/munin/plugins not starting
//! `.`, not ending `.conf`, named from `[-\w@.:]` alone and matching no
//! `ignore_file` regex of munin-node.conf. A plugin runs as the `user` its
//! /etc/munin/plugin-conf.d section gives, or failing that a `name*` or
//! `*name` wildcard section's, or `default_plugin_user` (nobody); `command`
//! replaces what runs, `%c` standing for the plugin. Configuration files
//! are read in order, a later setting replacing an earlier; `#` starts a
//! comment unless escaped. A pattern the regex crate cannot compile ignores
//! nothing. Plugins are enabled by linking them into the directory, as
//! systemd units are, so an entry is the file the link leads to, the link a
//! note; where `command` replaces the plugin, it is the file that says so.
//!
//! monit (l.l): /etc/monit/monitrc (Debian) or /etc/monitrc (Fedora), each
//! `include` a glob whose matches are read in its place, less directories
//! and names ending `~`. `#` comments to the end of the line. The programs
//! it runs, as root unless `as uid` names another: `check program` `path`,
//! and `start`, `stop`, `restart` and `exec`, each a quoted string split on
//! white space and executed without a shell. The grammar is read loosely,
//! by those keywords alone.
//!
//! Zabbix agent and agent 2 (6.0 to 7.4; cfg.c, agent_conf.c, the Go conf
//! package): /etc/zabbix/zabbix_agentd.conf and zabbix_agent2.conf, of
//! `Parameter=value` lines, `#` comment lines, each `Include` read in its
//! place: a file, every regular file of a directory, or a directory's files
//! matching a pattern in the last component; a relative path is taken from
//! the including file's directory, ten levels deep. `UserParameter=key,cmd`
//! runs `cmd` through `/bin/sh -c`, as `User` (zabbix) unless `AllowRoot`,
//! whenever the server asks for `key`. `AllowKey=system.run[...]` (and the
//! older `EnableRemoteCommands=1`) lets the server send any command to run;
//! a `DenyKey` for it earlier in the file refuses it. Agent 2 starts every
//! `Plugins.<name>.System.Path` as an external plugin.
//!
//! NRPE 4.1 (nrpe.c): /etc/nagios/nrpe.cfg, lines of `name=value`, `#`
//! comments; `include` and `include_file` read a file, `include_dir` every
//! regular `*.cfg` file in a directory and its subdirectories not starting
//! `.`. `command[name]=line` runs `line`, after any `command_prefix`,
//! through popen as `nrpe_user`, when a client asks for `name`; with
//! `dont_blame_nrpe=1` the client supplies its `$ARGn$` values.
//!
//! Salt minion (3007): the `schedule:` of /etc/salt/minion and of the files
//! its default include names, minion.d/*.conf, each job a function the
//! minion runs on its schedule as root. For cmd.run, cmd.shell and
//! cmd.script the arguments are the command; any other function's payload
//! is the module's own or comes from the master, and is not read.

use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Agents;

const CAP: usize = 64 * 1024;
/// What `path = builtin_af_unix` and its kin run where auditd no longer
/// holds them itself.
const AUDIT_BUILTIN: &str = "/sbin/audisp-af_unix";

impl Collector for Agents {
    fn name(&self) -> &'static str {
        "agents"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        audit_plugins(cx, &mut out);
        collectd(cx, &mut out);
        incron(cx, &mut out);
        facter(cx, &mut out);
        munin(cx, &mut out);
        monit(cx, &mut out);
        zabbix(cx, &mut out);
        nrpe(cx, &mut out);
        salt(cx, &mut out);
        crate::entry::dedup_ids(&mut out);
        out
    }
}

/// The plugin a `Plugins.<name>.System.Path` key names, if it names one.
fn plugin_name(key: &str) -> Option<&str> {
    key.strip_prefix("Plugins.")?.strip_suffix(".System.Path").filter(|n| !n.is_empty())
}

fn sorted(cx: &mut Ctx, dir: &Path) -> Vec<PathBuf> {
    let mut names: Vec<_> = cx.dir(dir).into_iter().filter(|e| !e.is_dir).map(|e| e.name).collect();
    names.sort();
    names.into_iter().map(|n| dir.join(n)).collect()
}

/// auditd's `key = value` lines: tokens split on spaces alone, the second
/// of them `=`.
fn audit_pairs(bytes: &[u8]) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        let mut tokens = line.split(|b| *b == b' ').filter(|t| !t.is_empty());
        let Some(name) = tokens.next() else { continue };
        if name[0] == b'#' || tokens.next() != Some(b"=".as_slice()) {
            continue;
        }
        let values = tokens.map(|t| String::from_utf8_lossy(t).into_owned()).collect();
        out.push((String::from_utf8_lossy(name).to_ascii_lowercase(), values));
    }
    out
}

fn audit_plugins(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = ["usr/sbin/auditd", "sbin/auditd"].iter().any(|p| cx.root.exists(p));
    let conf = cx.read_capped(Path::new("etc/audit/auditd.conf"), CAP).unwrap_or_default();
    let dir = audit_pairs(&conf)
        .into_iter()
        .rev()
        .find(|(k, v)| k == "plugin_dir" && !v.is_empty())
        .map(|(_, v)| v[0].trim_start_matches('/').to_string())
        .unwrap_or_else(|| "etc/audit/plugins.d".into());
    for rel in sorted(cx, Path::new(&dir)) {
        let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
        let (mut active, mut path, mut args) = (false, None, Vec::new());
        for (k, v) in audit_pairs(&bytes) {
            match k.as_str() {
                "active" => active = v.first().is_some_and(|a| a.eq_ignore_ascii_case("yes")),
                "path" => path = v.first().cloned(),
                "args" => args = v,
                _ => {}
            }
        }
        let Some(path) = path else { continue };
        let builtin = path.len() >= 8 && path.as_bytes()[..8].eq_ignore_ascii_case(b"builtin_");
        let path = if builtin && cx.root.exists(&AUDIT_BUILTIN[1..]) { AUDIT_BUILTIN.to_string() } else { path };
        let mut e = cx.entry(Kind::AuditPlugin, &rel, format!("auditd:{name}"));
        e.trigger = Trigger::Always;
        e.principal = Some("root".into());
        e.enabled = Enablement::Enabled;
        e.note("run_by", "auditd");
        e.command = Some([path.as_str()].into_iter().chain(args.iter().map(String::as_str)).collect::<Vec<_>>().join(" ").into_bytes());
        if path.starts_with('/') {
            e.target_path = Some(PathBuf::from(&path));
        } else {
            e.note("target_unverifiable", "runs inside auditd, not a program");
        }
        let why = if name.starts_with('.') || name.matches('.').count() > 1 {
            Some("auditd skips hidden names and names with more than one dot")
        } else if !active {
            Some("the plugin is not active = yes")
        } else if !installed {
            Some("auditd is not installed")
        } else {
            None
        };
        if let Some(why) = why {
            e.enabled = Enablement::Disabled;
            e.note("not_run", why);
        }
        out.push(e);
    }
}

/// incron's `key = value` configuration, defaults filled in.
fn incron_conf(cx: &mut Ctx) -> impl Fn(&str, &str) -> String + use<> {
    let bytes = cx.read_capped(Path::new("etc/incron.conf"), CAP).unwrap_or_default();
    let mut conf = std::collections::BTreeMap::new();
    for line in String::from_utf8_lossy(&bytes).lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            conf.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    move |k: &str, default: &str| conf.get(k).cloned().unwrap_or_else(|| default.to_string()).trim_start_matches('/').to_string()
}

/// A path and a mask, each ending at unescaped white space, and the raw rest.
fn incron_line(line: &[u8]) -> Option<(String, String, Vec<u8>)> {
    let mut fields = Vec::new();
    let mut i = 0;
    while fields.len() < 2 {
        while i < line.len() && matches!(line[i], b' ' | b'\t') {
            i += 1;
        }
        if i == line.len() {
            return None;
        }
        let mut f = Vec::new();
        while i < line.len() && !matches!(line[i], b' ' | b'\t') {
            if line[i] == b'\\' && i + 1 < line.len() {
                i += 1;
            }
            f.push(line[i]);
            i += 1;
        }
        fields.push(String::from_utf8_lossy(&f).into_owned());
    }
    let rest = line[i..].trim_ascii();
    if rest.is_empty() {
        return None;
    }
    let mask = fields.pop()?;
    Some((fields.pop()?, mask, rest.to_vec()))
}

fn incron(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/sbin/incrond");
    let conf = incron_conf(cx);
    let (system, spool) = (conf("system_table_dir", "/etc/incron.d"), conf("user_table_dir", "/var/spool/incron"));
    let (allow_rel, deny_rel) = (conf("allowed_users", "/etc/incron.allow"), conf("denied_users", "/etc/incron.deny"));
    let listed = |cx: &mut Ctx, rel: &str| {
        cx.read_capped(Path::new(rel), CAP).map(|b| {
            String::from_utf8_lossy(&b).lines().filter_map(|l| l.split_whitespace().next().map(str::to_string)).collect::<Vec<_>>()
        })
    };
    let (allow, deny) = (listed(cx, &allow_rel), listed(cx, &deny_rel));
    let accounts: Vec<String> = cx.users.iter().filter(|u| u.source == "passwd").map(|u| u.name.clone()).collect();
    for (dir, user_tables) in [(system, false), (spool, true)] {
        let mut names: Vec<_> = cx.dir(Path::new(&dir)).into_iter().map(|e| e.name).collect();
        names.sort();
        for n in names {
            let rel = Path::new(&dir).join(&n);
            let name = n.to_string_lossy().into_owned();
            if !cx.root.stat(&rel).is_ok_and(|m| m.is_file) {
                continue;
            }
            let (principal, why) = if !user_tables {
                if name.starts_with('.') {
                    continue;
                }
                ("root".to_string(), None)
            } else {
                if !accounts.contains(&name) {
                    continue;
                }
                let why = match (&allow, &deny) {
                    (Some(a), _) if !a.contains(&name) => Some("incron.allow does not list the account"),
                    (None, Some(d)) if d.contains(&name) => Some("incron.deny lists the account"),
                    _ => None,
                };
                (name.clone(), why)
            };
            let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
            for line in bytes.split(|b| *b == b'\n') {
                let Some((path, mask, command)) = incron_line(line) else { continue };
                if !path.starts_with('/') {
                    continue;
                }
                let mut e = cx.entry(Kind::Incron, &rel, format!("{path}:{mask}"));
                e.trigger = Trigger::FileEvent;
                e.principal = Some(principal.clone());
                e.enabled = Enablement::Enabled;
                e.note("watch", path);
                e.note("mask", mask);
                e.command = Some(command);
                if let Some(why) = why.or((!installed).then_some("incron is not installed")) {
                    e.enabled = Enablement::Disabled;
                    e.note("not_run", why);
                }
                out.push(e);
            }
        }
    }
}

/// `key = value`, `key: value` or `key value` in HOCON, the value a quoted
/// or bare string or a list of them.
fn hocon_values(text: &str, key: &str) -> Option<Vec<String>> {
    let at = text.match_indices(key).find(|(i, _)| {
        let before = text[..*i].chars().next_back();
        before.is_none_or(|c| c.is_whitespace() || c == '{' || c == ',' || c == '.')
    })?;
    let rest = text[at.0 + key.len()..].trim_start();
    let rest = rest.strip_prefix(['=', ':']).unwrap_or(rest).trim_start();
    let (list, body) = match rest.strip_prefix('[') {
        Some(r) => (true, &r[..r.find(']').unwrap_or(r.len())]),
        None => (false, rest.lines().next().unwrap_or_default()),
    };
    let mut out = Vec::new();
    for item in body.split([',', '\n']) {
        let item = item.trim();
        let v = match item.strip_prefix('"') {
            Some(q) => q.split('"').next().unwrap_or_default(),
            None => item.split(|c: char| c.is_whitespace() || c == '#' || c == '}').next().unwrap_or_default(),
        };
        if !v.is_empty() {
            out.push(v.to_string());
        }
        if !list {
            break;
        }
    }
    Some(out)
}

fn facter(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let aio = cx.root.exists("opt/puppetlabs/puppet/bin/facter");
    let installed = aio || cx.root.exists("usr/bin/facter");
    let debian = cx.root.exists("etc/debian_version");
    let mut dirs: Vec<String> = vec!["etc/facter/facts.d".into()];
    if aio || !debian {
        dirs.extend(["etc/puppetlabs/facter/facts.d".into(), "opt/puppetlabs/facter/facts.d".into()]);
    }
    let mut off = None;
    for conf in ["etc/facter/facter.conf", "etc/puppetlabs/facter/facter.conf"] {
        let Some(bytes) = cx.read_capped(Path::new(conf), CAP) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        if let Some(ext) = hocon_values(&text, "external-dir") {
            dirs = ext.iter().map(|d| d.trim_start_matches('/').to_string()).collect();
        }
        if hocon_values(&text, "no-external-facts").is_some_and(|v| v.first().is_some_and(|b| b == "true")) {
            off = Some(format!("no-external-facts is set in /{conf}"));
        }
        break;
    }
    for dir in dirs {
        let mut names: Vec<_> = cx.dir(Path::new(&dir)).into_iter().map(|e| e.name).collect();
        names.sort();
        for n in names {
            let name = n.to_string_lossy().into_owned();
            let ext = name.rsplit_once('.').map(|(_, x)| x).unwrap_or_default();
            if name.starts_with('.') || ["yaml", "txt", "json", "bat", "cmd", "com", "exe"].contains(&ext) {
                continue;
            }
            let rel = Path::new(&dir).join(&n);
            let Ok(meta) = cx.root.stat_follow(&rel) else { continue };
            if !meta.is_file || meta.mode & 0o111 == 0 {
                continue;
            }
            let mut e = cx.entry(Kind::ExternalFact, &rel, format!("facter:{name}"));
            e.trigger = Trigger::Schedule;
            e.principal = Some("root".into());
            e.enabled = Enablement::Enabled;
            e.note("run_by", "facter");
            e.target_path = Some(cx.root.abs(&rel));
            if let Some(why) = off.clone().or((!installed).then(|| "facter is not installed".to_string())) {
                e.enabled = Enablement::Disabled;
                e.note("not_run", why);
            }
            out.push(e);
        }
    }
}

/// A munin configuration line without its comment, trimmed.
fn munin_line(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'#') => {
                out.push('#');
                chars.next();
            }
            '#' => break,
            _ => out.push(c),
        }
    }
    out.trim().to_string()
}

fn munin(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/sbin/munin-node");
    let conf = cx.read_capped(Path::new("etc/munin/munin-node.conf"), CAP).unwrap_or_default();
    let (mut ignores, mut default_user) = (Vec::new(), "nobody".to_string());
    for line in String::from_utf8_lossy(&conf).lines().map(munin_line) {
        let Some((k, v)) = line.split_once(char::is_whitespace) else { continue };
        match k {
            "ignore_file" => ignores.extend(regex::Regex::new(v.trim()).ok()),
            "default_plugin_user" | "default_client_user" => default_user = v.trim().to_string(),
            _ => {}
        }
    }
    let plain = |n: &str| !n.is_empty() && n.chars().all(|c| c.is_alphanumeric() || "-_@.:".contains(c));
    // Section name to its settings, later files and lines replacing earlier.
    // Section name to its settings and the file each came from, later files
    // and lines replacing earlier.
    let mut sections: std::collections::BTreeMap<String, std::collections::BTreeMap<String, (String, PathBuf)>> = Default::default();
    let confdir = Path::new("etc/munin/plugin-conf.d");
    let mut files: Vec<_> = cx.dir(confdir).into_iter().map(|e| e.name.to_string_lossy().into_owned()).collect();
    files.sort();
    for f in files {
        if f.starts_with('.') || !plain(&f) || f.contains('@') || ignores.iter().any(|r| r.is_match(&f)) {
            continue;
        }
        let rel = confdir.join(&f);
        if !cx.root.stat_follow(&rel).is_ok_and(|m| m.is_file) {
            continue;
        }
        let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
        let mut section = None;
        for line in String::from_utf8_lossy(&bytes).lines().map(munin_line) {
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = Some(name.to_string());
            } else if let (Some(s), Some((k, v))) = (&section, line.split_once(char::is_whitespace)) {
                if k == "user" || k == "command" {
                    sections.entry(s.clone()).or_default().insert(k.to_string(), (v.trim().to_string(), rel.clone()));
                }
            }
        }
    }
    let setting = |service: &str, key: &str| -> Option<(String, PathBuf)> {
        if let Some(v) = sections.get(service).and_then(|s| s.get(key)) {
            return Some(v.clone());
        }
        // Wildcards, most specific first: munin applies them in reverse
        // sorted order and never over a value already set.
        sections.iter().rev().find_map(|(name, s)| {
            let hit = match (name.strip_suffix('*'), name.strip_prefix('*')) {
                (Some(prefix), _) => service.starts_with(prefix),
                (None, Some(suffix)) => service.ends_with(suffix),
                _ => false,
            };
            if hit { s.get(key).cloned() } else { None }
        })
    };
    let dir = Path::new("etc/munin/plugins");
    let mut names: Vec<_> = cx.dir(dir).into_iter().map(|e| e.name.to_string_lossy().into_owned()).collect();
    names.sort();
    for name in names {
        if name.starts_with('.') || name.ends_with(".conf") || !plain(&name) || ignores.iter().any(|r| r.is_match(&name)) {
            continue;
        }
        let rel = dir.join(&name);
        let Ok(meta) = cx.root.stat_follow(&rel) else { continue };
        if !meta.is_file || meta.mode & 0o111 == 0 {
            continue;
        }
        let plugin = format!("/{}", rel.display());
        let mut e = match setting(&name, "command") {
            Some((command, conf)) => {
                let mut e = cx.entry(Kind::MonitorPlugin, &conf, format!("munin:{name}"));
                e.command = Some(command.split_whitespace().map(|t| if t == "%c" { plugin.as_str() } else { t }).collect::<Vec<_>>().join(" ").into_bytes());
                e
            }
            None => {
                let file = cx.root.resolve(&rel).unwrap_or_else(|_| rel.clone());
                let mut e = cx.entry(Kind::MonitorPlugin, &file, format!("munin:{name}"));
                e.target_path = Some(cx.root.abs(&file));
                e
            }
        };
        e.note("plugin", plugin.clone());
        e.trigger = Trigger::Schedule;
        e.enabled = Enablement::Enabled;
        e.note("run_by", "munin-node");
        e.principal = Some(setting(&name, "user").map(|(u, _)| u).unwrap_or_else(|| default_user.clone()));
        if !installed {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "munin-node is not installed");
        }
        out.push(e);
    }
}

/// monit's words and quoted strings (quoted: true), comments dropped and
/// `=` a word of its own.
fn monit_tokens(bytes: &[u8]) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            q @ (b'"' | b'\'') => {
                let start = i + 1;
                i = start;
                while i < bytes.len() && bytes[i] != q {
                    i += 1;
                }
                out.push((String::from_utf8_lossy(&bytes[start..i.min(bytes.len())]).into_owned(), true));
            }
            b'=' => out.push(("=".into(), false)),
            b if b.is_ascii_whitespace() => {}
            _ => {
                let start = i;
                while i + 1 < bytes.len() && !bytes[i + 1].is_ascii_whitespace() && !b"#\"'=".contains(&bytes[i + 1]) {
                    i += 1;
                }
                out.push((String::from_utf8_lossy(&bytes[start..=i]).into_owned(), false));
            }
        }
        i += 1;
    }
    out
}

const MONIT_DEPTH: usize = 10;

fn monit_read(cx: &mut Ctx, rel: &Path, depth: usize, out: &mut Vec<(PathBuf, String, bool)>) {
    if depth > MONIT_DEPTH {
        return;
    }
    let Some(bytes) = cx.read_capped(rel, CAP) else { return };
    let mut toks = monit_tokens(&bytes).into_iter();
    while let Some((t, quoted)) = toks.next() {
        if !quoted && t.eq_ignore_ascii_case("include") {
            let Some((pattern, _)) = toks.next() else { break };
            for target in super::expand_glob(cx, &super::include_rel(Path::new("etc"), pattern.as_bytes())) {
                if target.as_os_str().as_encoded_bytes().ends_with(b"~") || cx.root.stat_follow(&target).is_ok_and(|m| m.is_dir) {
                    continue;
                }
                monit_read(cx, &target, depth + 1, out);
            }
            continue;
        }
        out.push((rel.to_path_buf(), t, quoted));
    }
}

fn monit(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/bin/monit");
    let mut toks = Vec::new();
    for main in ["etc/monit/monitrc", "etc/monitrc"] {
        monit_read(cx, Path::new(main), 0, &mut toks);
    }
    let word = |i: usize| toks.get(i).filter(|t| !t.2).map(|t| t.1.to_ascii_lowercase());
    let mut service = String::new();
    let mut i = 0;
    while i < toks.len() {
        let w = word(i).unwrap_or_default();
        if w == "check" && toks.len() > i + 2 {
            service = toks[i + 2].1.clone();
        }
        let action = match w.as_str() {
            "start" | "stop" | "restart" | "exec" | "execute" => w.trim_end_matches("ute").to_string(),
            "path" if i >= 3 && word(i - 3).as_deref() == Some("check") && word(i - 2).as_deref() == Some("program") => "program".into(),
            "path" if i >= 4 && word(i - 4).as_deref() == Some("check") && word(i - 3).as_deref() == Some("program") => "program".into(),
            _ => {
                i += 1;
                continue;
            }
        };
        // The program string follows, after `program` and `=` for start,
        // stop and restart.
        let mut j = i + 1;
        while matches!(word(j).as_deref(), Some("program" | "=")) {
            j += 1;
        }
        let Some((rel, cmd, true)) = toks.get(j).cloned() else {
            i += 1;
            continue;
        };
        let argv: Vec<&str> = cmd.split_whitespace().collect();
        let mut principal = "root".to_string();
        if word(j + 1).as_deref() == Some("as") && word(j + 2).as_deref() == Some("uid") {
            principal = toks.get(j + 3).map(|t| t.1.clone()).unwrap_or(principal);
        }
        let mut e = cx.entry(Kind::MonitorPlugin, &rel, format!("monit:{service}:{action}"));
        e.trigger = Trigger::Schedule;
        e.enabled = Enablement::Enabled;
        e.principal = Some(principal);
        e.note("run_by", "monit");
        e.command = Some(argv.join(" ").into_bytes());
        if let Some(p) = argv.first().filter(|p| p.starts_with('/')) {
            e.target_path = Some(PathBuf::from(p));
        }
        if !installed {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "monit is not installed");
        }
        out.push(e);
        i = j + 1;
    }
}

/// A configuration's `name=value` lines, each include read in its place,
/// with the file each came from; `include` says which names include what.
fn eq_lines(
    cx: &mut Ctx,
    rel: &Path,
    depth: usize,
    include: &dyn Fn(&mut Ctx, &Path, &str, &str) -> Option<Vec<PathBuf>>,
    out: &mut Vec<(PathBuf, String, String)>,
) {
    if depth > 10 {
        return;
    }
    let Some(bytes) = cx.read_capped(rel, CAP) else { return };
    for line in String::from_utf8_lossy(&bytes).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim_end(), v.trim_start());
        match include(cx, rel, k, v) {
            Some(targets) => {
                for t in targets {
                    eq_lines(cx, &t, depth + 1, include, out);
                }
            }
            None => out.push((rel.to_path_buf(), k.to_string(), v.to_string())),
        }
    }
}

/// What a Zabbix `Include` names: a file, a directory's regular files, or
/// those matching the pattern in its last component.
fn zabbix_include(cx: &mut Ctx, from: &Path, key: &str, value: &str) -> Option<Vec<PathBuf>> {
    if key != "Include" {
        return None;
    }
    let base = from.parent().unwrap_or(Path::new(""));
    let rel = super::include_rel(base, value.trim_end_matches('/').as_bytes());
    let mut files = if cx.root.stat_follow(&rel).is_ok_and(|m| m.is_dir) {
        let mut names: Vec<_> = cx.dir(&rel).into_iter().map(|e| rel.join(e.name)).collect();
        names.sort();
        names
    } else {
        super::expand_glob(cx, &rel)
    };
    files.retain(|f| cx.root.stat_follow(f).is_ok_and(|m| m.is_file));
    Some(files)
}

fn zabbix(cx: &mut Ctx, out: &mut Vec<Entry>) {
    for (agent, conf, bin) in [("agentd", "etc/zabbix/zabbix_agentd.conf", "usr/sbin/zabbix_agentd"), ("agent2", "etc/zabbix/zabbix_agent2.conf", "usr/sbin/zabbix_agent2")] {
        let installed = cx.root.exists(bin);
        let mut lines = Vec::new();
        eq_lines(cx, Path::new(conf), 0, &zabbix_include, &mut lines);
        let last = |k: &str| lines.iter().rev().find(|l| l.1 == k).map(|l| l.2.clone());
        let user = last("User").unwrap_or_else(|| "zabbix".into());
        let allow_root = last("AllowRoot").is_some_and(|v| v == "1");
        let dir = last("UserParameterDir");
        let mut denied = false;
        for (rel, k, v) in &lines {
            let mut e = match k.as_str() {
                "UserParameter" => {
                    let Some((key, cmd)) = v.split_once(',') else { continue };
                    let mut e = cx.entry(Kind::MonitorPlugin, rel, format!("zabbix:{agent}:{key}"));
                    e.trigger = Trigger::Schedule;
                    e.command = Some(cmd.as_bytes().to_vec());
                    e.note("item_key", key);
                    if let Some(d) = &dir {
                        e.note("working_directory", d.clone());
                    }
                    e
                }
                "DenyKey" if v.starts_with("system.run") => {
                    denied = true;
                    continue;
                }
                "AllowKey" if v.starts_with("system.run") => remote(cx, rel, agent, v, denied),
                "EnableRemoteCommands" if v == "1" => remote(cx, rel, agent, v, denied),
                // `Plugins.System.Path` passes both an affix test and is too
                // short to hold a name between them, so the two are stripped
                // in turn, never by adding their lengths up.
                _ if agent == "agent2" && plugin_name(k).is_some() => {
                    let name = plugin_name(k).unwrap_or_default();
                    let mut e = cx.entry(Kind::MonitorPlugin, rel, format!("zabbix:agent2:plugin:{name}"));
                    e.trigger = Trigger::Always;
                    e.command = Some(v.as_bytes().to_vec());
                    e.target_path = Some(PathBuf::from(v));
                    if !v.starts_with('/') {
                        e.enabled = Enablement::Disabled;
                        e.note("not_run", "agent 2 refuses a plugin path that is not absolute");
                    }
                    e
                }
                _ => continue,
            };
            e.principal = Some(user.clone());
            e.note("run_by", format!("zabbix_{agent}"));
            if allow_root {
                e.note("allow_root", "1: runs as root when the agent is started as root");
            }
            if e.enabled == Enablement::Unknown {
                e.enabled = Enablement::Enabled;
            }
            if e.enabled == Enablement::Enabled && !installed {
                e.enabled = Enablement::Disabled;
                e.note("not_run", format!("zabbix_{agent} is not installed"));
            }
            out.push(e);
        }
    }
}

/// The server's licence to send any command.
fn remote(cx: &mut Ctx, rel: &Path, agent: &str, value: &str, denied: bool) -> Entry {
    let mut e = cx.entry(Kind::MonitorPlugin, rel, format!("zabbix:{agent}:system.run"));
    e.trigger = Trigger::Schedule;
    e.note("allows", value);
    e.note("target_unverifiable", "whatever command the Zabbix server sends");
    if denied {
        e.enabled = Enablement::Disabled;
        e.note("not_run", "an earlier DenyKey refuses system.run");
    }
    e
}

/// What an NRPE include names: `include_dir` recursively, its regular
/// `*.cfg` files and its subdirectories not starting `.`.
fn nrpe_include(cx: &mut Ctx, _from: &Path, key: &str, value: &str) -> Option<Vec<PathBuf>> {
    fn walk(cx: &mut Ctx, dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
        if depth > 10 {
            return;
        }
        let mut names: Vec<_> = cx.dir(dir).into_iter().map(|e| e.name).collect();
        names.sort();
        for n in names {
            let p = dir.join(&n);
            let name = n.as_encoded_bytes();
            match cx.root.stat_follow(&p) {
                Ok(m) if m.is_file && name.len() > 4 && name.ends_with(b".cfg") => out.push(p),
                Ok(m) if m.is_dir && !name.starts_with(b".") => walk(cx, &p, depth + 1, out),
                _ => {}
            }
        }
    }
    let rel = super::include_rel(Path::new(""), value.trim_end_matches('/').as_bytes());
    match key {
        "include" | "include_file" => Some(vec![rel]),
        "include_dir" => {
            let mut out = Vec::new();
            walk(cx, &rel, 0, &mut out);
            Some(out)
        }
        _ => None,
    }
}

fn nrpe(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/sbin/nrpe");
    let mut lines = Vec::new();
    eq_lines(cx, Path::new("etc/nagios/nrpe.cfg"), 0, &nrpe_include, &mut lines);
    let last = |k: &str| lines.iter().rev().find(|l| l.1 == k).map(|l| l.2.clone());
    let user = last("nrpe_user").unwrap_or_else(|| "nagios".into());
    let prefix = last("command_prefix");
    let arguments = last("dont_blame_nrpe").is_some_and(|v| v.trim().parse::<i64>() == Ok(1));
    for (rel, k, v) in &lines {
        let Some(name) = k.split_once('[').and_then(|(_, r)| r.split(']').next()).filter(|_| k.contains("command[")) else { continue };
        // strtok on `=` skips a run of them.
        let line = v.trim_start_matches('=');
        let mut e = cx.entry(Kind::MonitorPlugin, rel, format!("nrpe:{name}"));
        e.trigger = Trigger::Schedule;
        e.enabled = Enablement::Enabled;
        e.principal = Some(user.clone());
        e.note("run_by", "nrpe");
        e.command = Some(match &prefix {
            Some(p) => format!("{p} {line}"),
            None => line.to_string(),
        }.into_bytes());
        if arguments {
            e.note("arguments", "dont_blame_nrpe=1: the client supplies $ARGn$");
        }
        if !installed {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "nrpe is not installed");
        }
        out.push(e);
    }
}

fn salt(cx: &mut Ctx, out: &mut Vec<Entry>) {
    use crate::yaml::Value;
    let installed = cx.root.exists("usr/bin/salt-minion");
    let mut files = vec![PathBuf::from("etc/salt/minion")];
    files.extend(sorted(cx, Path::new("etc/salt/minion.d")).into_iter().filter(|f| f.to_string_lossy().ends_with(".conf")));
    for rel in files {
        let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
        let Ok(Some(doc)) = crate::yaml::parse(&String::from_utf8_lossy(&bytes)) else { continue };
        let Some(Value::Map(jobs)) = doc.get("schedule") else { continue };
        for (name, job) in jobs {
            let (Some(name), Value::Map(_)) = (name.python_str(), job) else { continue };
            let function = job.get("function").and_then(Value::python_str).unwrap_or_default();
            let mut e = cx.entry(Kind::SaltSchedule, &rel, format!("salt:{name}"));
            e.trigger = Trigger::Schedule;
            e.principal = Some("root".into());
            e.enabled = Enablement::Enabled;
            e.note("run_by", "salt-minion");
            e.note("function", function.clone());
            let mut args: Vec<String> = match job.get("args") {
                Some(Value::Seq(a)) => a.iter().filter_map(Value::python_str).collect(),
                Some(v) => v.python_str().into_iter().collect(),
                None => Vec::new(),
            };
            if let Some(cmd) = job.get("kwargs").and_then(|k| k.get("cmd")).and_then(Value::python_str) {
                args.insert(0, cmd);
            }
            if matches!(function.as_str(), "cmd.run" | "cmd.shell" | "cmd.script" | "cmd.run_all") && !args.is_empty() {
                e.command = Some(args.join(" ").into_bytes());
                if function == "cmd.script" {
                    e.note("target_unverifiable", "a script the minion fetches from the master or a URL");
                }
            } else {
                e.note("target_unverifiable", "a salt execution module, its payload not in this file");
                if !args.is_empty() {
                    e.note("args", args.join(" "));
                }
            }
            if job.get("enabled").is_some_and(|v| matches!(v, Value::Bool(false))) {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "enabled: false");
            } else if !installed {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "salt-minion is not installed");
            }
            out.push(e);
        }
    }
}

/// One collectd statement: `Key values`, `<Key values>` or `</Key>`.
#[derive(Debug, PartialEq)]
enum Stmt {
    Item(String, Vec<String>),
    Open(String, Vec<String>),
    Close(String),
}

/// collectd's configuration grammar, leniently: what it would reject is
/// read as far as it goes.
fn oconfig(bytes: &[u8]) -> Vec<Stmt> {
    #[derive(PartialEq)]
    enum Tok {
        Word(String),
        Lt,
        Gt,
        Slash,
    }
    fn statement(toks: &mut Vec<Tok>, out: &mut Vec<Stmt>) {
        let word = |t: &Tok| match t {
            Tok::Word(w) => Some(w.clone()),
            _ => None,
        };
        let stmt = match toks.as_slice() {
            [Tok::Lt, Tok::Slash, Tok::Word(k), ..] => Some(Stmt::Close(k.clone())),
            [Tok::Lt, Tok::Word(k), rest @ ..] => Some(Stmt::Open(k.clone(), rest.iter().map_while(word).collect())),
            [Tok::Word(k), rest @ ..] => Some(Stmt::Item(k.clone(), rest.iter().filter_map(word).collect())),
            _ => None,
        };
        out.extend(stmt);
        toks.clear();
    }
    let (mut out, mut toks) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\n' => statement(&mut toks, &mut out),
            b'#' => {
                while i + 1 < bytes.len() && bytes[i + 1] != b'\n' {
                    i += 1;
                }
            }
            b'\\' if bytes.get(i + 1) == Some(&b'\n') => i += 1,
            b'\\' if bytes[i + 1..].starts_with(b"\r\n") => i += 2,
            b'<' => toks.push(Tok::Lt),
            b'>' => toks.push(Tok::Gt),
            b'/' => toks.push(Tok::Slash),
            b'"' => {
                let mut v = Vec::new();
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 1;
                        // A backslash ending the line continues the string on
                        // the next, less its leading white space.
                        if bytes[i] == b'\n' || bytes[i..].starts_with(b"\r\n") {
                            i += if bytes[i] == b'\r' { 2 } else { 1 };
                            while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | 8) {
                                i += 1;
                            }
                            continue;
                        }
                    }
                    v.push(bytes[i]);
                    i += 1;
                }
                toks.push(Tok::Word(String::from_utf8_lossy(&v).into_owned()));
            }
            b' ' | b'\t' | b'\r' | 8 => {}
            _ => {
                let start = i;
                while i + 1 < bytes.len() && !b" \t\r\n\x08\"<>/#\\".contains(&bytes[i + 1]) {
                    i += 1;
                }
                toks.push(Tok::Word(String::from_utf8_lossy(&bytes[start..=i]).into_owned()));
            }
        }
        i += 1;
    }
    statement(&mut toks, &mut out);
    out
}

const COLLECTD_DEPTH: usize = 8;

/// A configuration file's statements, each top-level Include replaced by
/// what it names, and the file each statement came from.
fn collectd_read(cx: &mut Ctx, rel: &Path, filter: Option<&str>, depth: usize, out: &mut Vec<(PathBuf, Stmt)>) {
    if depth >= COLLECTD_DEPTH {
        return;
    }
    let Ok(meta) = cx.root.stat_follow(rel) else { return };
    if meta.is_dir {
        let mut names: Vec<_> = cx.dir(rel).into_iter().map(|e| e.name).filter(|n| !n.as_encoded_bytes().starts_with(b".")).collect();
        names.sort();
        for n in names {
            collectd_read(cx, &rel.join(n), filter, depth, out);
        }
        return;
    }
    let name = rel.file_name().map(|n| n.as_encoded_bytes().to_vec()).unwrap_or_default();
    if filter.is_some_and(|f| !super::glob_match(f.as_bytes(), &name)) {
        return;
    }
    let Some(bytes) = cx.read_capped(rel, CAP) else { return };
    let stmts = oconfig(&bytes);
    let mut level = 0usize;
    let mut it = stmts.into_iter().peekable();
    while let Some(st) = it.next() {
        let include = match &st {
            Stmt::Item(k, v) if level == 0 && k.eq_ignore_ascii_case("Include") => Some((v.first().cloned(), None)),
            Stmt::Open(k, v) if level == 0 && k.eq_ignore_ascii_case("Include") => {
                let mut filter = None;
                for inner in it.by_ref() {
                    match inner {
                        Stmt::Item(k, v) if k.eq_ignore_ascii_case("Filter") => filter = v.first().cloned(),
                        Stmt::Close(_) => break,
                        _ => {}
                    }
                }
                Some((v.first().cloned(), filter))
            }
            _ => None,
        };
        if let Some((path, inner_filter)) = include {
            let Some(path) = path else { continue };
            for target in super::expand_glob(cx, &super::include_rel(Path::new("etc"), path.as_bytes())) {
                collectd_read(cx, &target, inner_filter.as_deref(), depth + 1, out);
            }
            continue;
        }
        match &st {
            Stmt::Open(..) => level += 1,
            Stmt::Close(_) => level = level.saturating_sub(1),
            Stmt::Item(..) => {}
        }
        out.push((rel.to_path_buf(), st));
    }
}

fn collectd(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/sbin/collectd");
    let mut stmts = Vec::new();
    for main in ["etc/collectd/collectd.conf", "etc/collectd.conf"] {
        collectd_read(cx, Path::new(main), None, 0, &mut stmts);
    }
    let mut loaded = std::collections::BTreeSet::new();
    let mut autoload = false;
    let mut level = 0usize;
    for (_, st) in &stmts {
        match st {
            Stmt::Item(k, v) | Stmt::Open(k, v) if level == 0 && k.eq_ignore_ascii_case("LoadPlugin") => {
                loaded.extend(v.first().map(|p| p.to_ascii_lowercase()));
            }
            Stmt::Item(k, v) if level == 0 && k.eq_ignore_ascii_case("AutoLoadPlugin") => {
                autoload = v.first().is_some_and(|b| matches!(b.to_ascii_lowercase().as_str(), "true" | "yes" | "on"));
            }
            _ => {}
        }
        match st {
            Stmt::Open(..) => level += 1,
            Stmt::Close(_) => level = level.saturating_sub(1),
            Stmt::Item(..) => {}
        }
    }
    // The block each statement sits in, as `<Plugin name>` names it.
    let mut plugin: Option<String> = None;
    let mut depth = 0usize;
    let (mut module_paths, mut include_dirs, mut base_path) = (Vec::new(), Vec::new(), None);
    for (rel, st) in &stmts {
        match st {
            Stmt::Open(k, v) => {
                depth += 1;
                if depth == 1 && k.eq_ignore_ascii_case("Plugin") {
                    plugin = v.first().map(|p| p.to_ascii_lowercase());
                }
                continue;
            }
            Stmt::Close(_) => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    plugin = None;
                }
                continue;
            }
            Stmt::Item(..) if depth != 1 => continue,
            Stmt::Item(k, v) => {
                let Some(p) = plugin.as_deref() else { continue };
                let key = k.to_ascii_lowercase();
                let first = v.first().cloned().unwrap_or_default();
                let e = match (p, key.as_str()) {
                    ("exec", "exec" | "notificationexec") if v.len() >= 2 => {
                        let user = first.split(':').next().unwrap_or_default().to_string();
                        let mut e = cx.entry(Kind::MonitorPlugin, rel, format!("collectd:{k}:{}", v[1]));
                        e.command = Some(v[1..].join(" ").into_bytes());
                        e.target_path = Some(PathBuf::from(&v[1]));
                        e.principal = Some(user.clone());
                        if user == "root" {
                            e.enabled = Enablement::Disabled;
                            e.note("not_run", "collectd refuses to run a program as root");
                        }
                        Some(e)
                    }
                    ("python", "modulepath") => {
                        module_paths.push(first);
                        None
                    }
                    ("perl", "includedir") => {
                        include_dirs.push(first);
                        None
                    }
                    ("lua", "basepath") => {
                        base_path = Some(first);
                        None
                    }
                    ("python", "import") => {
                        let file = module_paths.iter().rev().flat_map(|d| [format!("{d}/{first}.py"), format!("{d}/{first}/__init__.py")]).find(|f| cx.root.exists(f.trim_start_matches('/')));
                        Some(code_entry(cx, rel, "python", &first, file))
                    }
                    ("perl", "loadplugin") => {
                        let tail = first.replace("::", "/");
                        let file = include_dirs.iter().rev().map(|d| format!("{d}/{tail}.pm")).find(|f| cx.root.exists(f.trim_start_matches('/')));
                        Some(code_entry(cx, rel, "perl", &first, file))
                    }
                    ("lua", "script") => {
                        let file = if first.starts_with('/') { first.clone() } else { format!("{}/{first}", base_path.as_deref().unwrap_or("")) };
                        Some(code_entry(cx, rel, "lua", &first, Some(file)))
                    }
                    _ => None,
                };
                let Some(mut e) = e else { continue };
                e.trigger = Trigger::Always;
                e.note("run_by", "collectd");
                if e.enabled != Enablement::Disabled {
                    e.enabled = Enablement::Enabled;
                    if !loaded.contains(p) && !autoload {
                        e.enabled = Enablement::Disabled;
                        e.note("not_run", format!("no LoadPlugin {p}"));
                    } else if !installed {
                        e.enabled = Enablement::Disabled;
                        e.note("not_run", "collectd is not installed");
                    }
                }
                out.push(e);
            }
        }
    }
}

/// Code a collectd language plugin loads into collectd, as root.
fn code_entry(cx: &mut Ctx, rel: &Path, lang: &str, name: &str, file: Option<String>) -> Entry {
    let mut e = cx.entry(Kind::MonitorPlugin, rel, format!("collectd:{lang}:{name}"));
    e.principal = Some("root".into());
    e.note("language", lang);
    e.command = Some(name.as_bytes().to_vec());
    match file {
        Some(f) => e.target_path = Some(PathBuf::from(f)),
        None => e.note("target_unverifiable", format!("a {lang} module found on the interpreter's own path")),
    }
    e
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
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Agents)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    fn fixture(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("unbidden-agents-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn plugin_key_names_are_cut_by_stripping_not_by_index() {
        assert_eq!(plugin_name("Plugins.Foo.System.Path"), Some("Foo"));
        assert_eq!(plugin_name("Plugins.System.Path"), None, "the two affixes overlap");
        assert_eq!(plugin_name("Plugins..System.Path"), None);
        assert_eq!(plugin_name("Plugins.Foo.Bar.System.Path"), Some("Foo.Bar"));
        assert_eq!(plugin_name("Plugin.Foo.System.Path"), None);
    }

    #[test]
    fn a_zabbix_key_that_overlaps_its_own_affixes_cannot_fail_the_collector() {
        let d = fixture("zabbix-overlap");
        put(&d, "usr/sbin/zabbix_agent2", b"");
        put(&d, "etc/zabbix/zabbix_agent2.conf", b"Plugins.System.Path=/x\nPlugins.Real.System.Path=/opt/real\n");
        let s = scan(&d);
        let status = &s.header.collectors[0].status;
        assert!(matches!(status, crate::scan::Status::Complete), "{status:?}");
        assert!(s.entries.iter().any(|e| e.name == "zabbix:agent2:plugin:Real"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn an_active_audit_plugin_is_what_auditd_runs() {
        let d = fixture("audit");
        put(&d, "usr/sbin/auditd", b"");
        put(&d, "etc/audit/auditd.conf", b"log_file = /var/log/audit/audit.log\nplugin_dir = /etc/audit/p.d\n");
        put(&d, "etc/audit/p.d/remote.conf", b"# x\nACTIVE = Yes\ndirection = out\npath = /opt/beacon\ntype = always\nargs = -q  -x\n");
        put(&d, "etc/audit/p.d/af_unix.conf", b"active = no\npath = builtin_af_unix\n");
        put(&d, "etc/audit/p.d/remote.conf.bak", b"active = yes\npath = /tmp/old\n");
        put(&d, "etc/audit/p.d/tab.conf", b"active\t=\tyes\npath = /tmp/tab\n");
        put(&d, "etc/audit/plugins.d/ignored.conf", b"active = yes\npath = /tmp/elsewhere\n");
        let s = scan(&d);
        let got: Vec<(&str, &str, Enablement)> = s
            .entries
            .iter()
            .map(|e| (e.name.as_str(), std::str::from_utf8(e.command.as_deref().unwrap()).unwrap(), e.enabled))
            .collect();
        assert_eq!(
            got,
            [
                ("auditd:af_unix.conf", "builtin_af_unix", Enablement::Disabled),
                ("auditd:remote.conf", "/opt/beacon -q -x", Enablement::Enabled),
                ("auditd:remote.conf.bak", "/tmp/old", Enablement::Disabled),
                ("auditd:tab.conf", "/tmp/tab", Enablement::Disabled),
            ]
        );
        assert_eq!(s.entries[1].target_path.as_deref(), Some(Path::new("/opt/beacon")));
        assert!(s.entries[0].target_path.is_none(), "audit 3.0 runs its builtins itself");
        put(&d, "sbin/audisp-af_unix", b"");
        let s = scan(&d);
        assert_eq!(s.entries[0].command.as_deref(), Some(b"/sbin/audisp-af_unix".as_slice()), "later releases execute it");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn incron_tables_run_as_incrond_chooses() {
        let d = fixture("incron");
        put(&d, "usr/sbin/incrond", b"");
        put(&d, "etc/passwd", b"root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n");
        put(&d, "etc/incron.d/web", b"# /never IN_CREATE /tmp/no\n/var/www/a\\ b IN_CLOSE_WRITE,IN_CREATE   /opt/sync $@/$# # not a comment\nrel IN_CREATE /x\n/two fields\n");
        put(&d, "etc/incron.d/.hidden", b"/h IN_CREATE /tmp/h\n");
        put(&d, "etc/incron.d/web~", b"/b IN_MODIFY /tmp/backup\n");
        put(&d, "var/spool/incron/alice", b"/home/alice IN_CREATE /tmp/a\n");
        put(&d, "var/spool/incron/bob", b"/home/bob IN_CREATE /tmp/b\n");
        put(&d, "var/spool/incron/nosuch", b"/n IN_CREATE /tmp/n\n");
        put(&d, "etc/incron.deny", b"bob\n");
        std::os::unix::fs::symlink("web", d.join("etc/incron.d/link")).unwrap();
        let s = scan(&d);
        let got: Vec<(&str, &str, &str, Enablement)> = s
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.principal.as_deref().unwrap(), std::str::from_utf8(e.command.as_deref().unwrap()).unwrap(), e.enabled))
            .collect();
        assert_eq!(
            got,
            [
                ("/var/www/a b:IN_CLOSE_WRITE,IN_CREATE", "root", "/opt/sync $@/$# # not a comment", Enablement::Enabled),
                ("/b:IN_MODIFY", "root", "/tmp/backup", Enablement::Enabled),
                ("/home/alice:IN_CREATE", "alice", "/tmp/a", Enablement::Enabled),
                ("/home/bob:IN_CREATE", "bob", "/tmp/b", Enablement::Disabled),
            ]
        );
        put(&d, "etc/incron.allow", b"");
        let s = scan(&d);
        assert!(s.entries.iter().filter(|e| e.principal.as_deref() != Some("root")).all(|e| e.enabled == Enablement::Disabled), "an empty allow file admits nobody");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn facter_executes_what_it_does_not_read_as_data() {
        use std::os::unix::fs::PermissionsExt;
        let d = fixture("facter");
        let exe = |rel: &str| {
            put(&d, rel, b"#!/bin/sh\necho a=b\n");
            std::fs::set_permissions(d.join(rel), std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        put(&d, "usr/bin/facter", b"");
        exe("etc/facter/facts.d/run");
        exe("etc/facter/facts.d/data.yaml");
        exe("etc/facter/facts.d/also.yml");
        exe("etc/facter/facts.d/win.bat");
        exe("etc/facter/facts.d/.hidden");
        put(&d, "etc/facter/facts.d/plain", b"x");
        exe("etc/puppetlabs/facter/facts.d/aio");
        exe("opt/custom/f");
        let names = |d: &Path| scan(d).entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>();
        assert_eq!(names(&d), ["facter:also.yml", "facter:run", "facter:aio"]);
        put(&d, "etc/debian_version", b"12\n");
        assert_eq!(names(&d), ["facter:also.yml", "facter:run"], "Debian's facter reads only /etc/facter/facts.d");
        put(&d, "etc/facter/facter.conf", b"global : {\n  external-dir : [ \"/opt/custom\" ]\n}\n");
        assert_eq!(names(&d), ["facter:f"], "external-dir replaces the defaults");
        put(&d, "etc/facter/facter.conf", b"global {\n  no-external-facts = true\n}\n");
        assert!(scan(&d).entries.iter().all(|e| e.enabled == Enablement::Disabled));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn munin_runs_its_plugins_as_their_sections_say() {
        use std::os::unix::fs::PermissionsExt;
        let d = fixture("munin");
        let exe = |rel: &str| {
            put(&d, rel, b"#!/bin/sh\n");
            std::fs::set_permissions(d.join(rel), std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        put(&d, "usr/sbin/munin-node", b"");
        put(&d, "etc/munin/munin-node.conf", b"user root\nignore_file [\\#~]$ # comment\nignore_file \\.bak$\nignore_file (?<=x)y\n");
        put(&d, "etc/munin/plugin-conf.d/munin-node", b"[df*]\nuser root\n[df_inode]\nuser nobody2\n[cpu]\nuser daemon\n");
        put(&d, "etc/munin/plugin-conf.d/zz", b"# later\n[cpu]\ncommand /usr/bin/sudo %c\nuser root\n");
        exe("etc/munin/plugins/cpu");
        exe("usr/share/munin/plugins/df_");
        std::os::unix::fs::symlink("/usr/share/munin/plugins/df_", d.join("etc/munin/plugins/df")).unwrap();
        exe("etc/munin/plugins/df_inode");
        exe("etc/munin/plugins/load");
        exe("etc/munin/plugins/load~");
        exe("etc/munin/plugins/x.bak");
        exe("etc/munin/plugins/x.conf");
        exe("etc/munin/plugins/we ird");
        put(&d, "etc/munin/plugins/noexec", b"");
        let s = scan(&d);
        let got: Vec<(&str, &str)> = s.entries.iter().map(|e| (e.name.as_str(), e.principal.as_deref().unwrap())).collect();
        assert_eq!(got, [("munin:cpu", "root"), ("munin:df_inode", "nobody2"), ("munin:load", "nobody"), ("munin:df", "root")]);
        assert_eq!(s.entries[0].command.as_deref(), Some(b"/usr/bin/sudo /etc/munin/plugins/cpu".as_slice()));
        assert!(s.entries[0].source.ends_with("etc/munin/plugin-conf.d/zz"), "a command is judged by the file that sets it");
        assert!(s.entries[3].source.ends_with("usr/share/munin/plugins/df_"), "a linked plugin is judged by what it links to");
        assert_eq!(s.entries[3].raw["plugin"], "/etc/munin/plugins/df");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn monit_runs_the_programs_its_control_file_names() {
        let d = fixture("monit");
        put(&d, "usr/bin/monit", b"");
        put(&d, "etc/monit/monitrc", b"set daemon 120 # start program = \"/never\"\ninclude /etc/monit/conf.d/*\n");
        put(
            &d,
            "etc/monit/conf.d/web",
            b"check process nginx with pidfile /run/nginx.pid\n  start program = \"/usr/sbin/service nginx start\" with timeout 60 seconds\n  stop program \"/usr/sbin/service  nginx stop\" as uid www and gid www\n  if failed port 80 then exec '/opt/alert --now'\ncheck program beacon with path \"/opt/beacon -q\"\n  if status != 0 then alert\n",
        );
        put(&d, "etc/monit/conf.d/web~", b"check program old with path \"/tmp/old\"\n");
        let s = scan(&d);
        let got: Vec<(&str, &str, &str)> = s
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.principal.as_deref().unwrap(), std::str::from_utf8(e.command.as_deref().unwrap()).unwrap()))
            .collect();
        assert_eq!(
            got,
            [
                ("monit:beacon:program", "root", "/opt/beacon -q"),
                ("monit:nginx:exec", "root", "/opt/alert --now"),
                ("monit:nginx:start", "root", "/usr/sbin/service nginx start"),
                ("monit:nginx:stop", "www", "/usr/sbin/service nginx stop"),
            ]
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn zabbix_runs_user_parameters_and_what_the_server_may_send() {
        let d = fixture("zabbix");
        put(&d, "usr/sbin/zabbix_agentd", b"");
        put(&d, "etc/zabbix/zabbix_agentd.conf", b"# UserParameter=never,/tmp/x\nUser=zbx\nInclude=/etc/zabbix/zabbix_agentd.conf.d/*.conf\nInclude=extra\n");
        put(&d, "etc/zabbix/zabbix_agentd.conf.d/a.conf", b"UserParameter=mysql.ping[*],  mysqladmin -u$1 ping | grep -c alive\nDenyKey=system.run[rm *]\nAllowKey=system.run[*]\n");
        put(&d, "etc/zabbix/zabbix_agentd.conf.d/b.txt", b"UserParameter=no,/tmp/no\n");
        put(&d, "etc/zabbix/extra/one", b"UserParameter = x , /opt/x\n");
        put(&d, "etc/zabbix/zabbix_agent2.conf", b"Include=./zabbix_agent2.d/plugins.d/*.conf\n");
        put(&d, "etc/zabbix/zabbix_agent2.d/plugins.d/m.conf", b"Plugins.Beacon.System.Path=/opt/beacon\nPlugins.Rel.System.Path=rel\n");
        let s = scan(&d);
        let got: Vec<(&str, &str, Enablement)> = s
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.command.as_deref().map(|c| std::str::from_utf8(c).unwrap()).unwrap_or("-"), e.enabled))
            .collect();
        assert_eq!(
            got,
            [
                ("zabbix:agentd:x ", " /opt/x", Enablement::Enabled),
                ("zabbix:agent2:plugin:Beacon", "/opt/beacon", Enablement::Disabled),
                ("zabbix:agent2:plugin:Rel", "rel", Enablement::Disabled),
                ("zabbix:agentd:mysql.ping[*]", "  mysqladmin -u$1 ping | grep -c alive", Enablement::Enabled),
                ("zabbix:agentd:system.run", "-", Enablement::Disabled),
            ]
        );
        assert!(s.entries.iter().filter(|e| e.name.starts_with("zabbix:agentd")).all(|e| e.principal.as_deref() == Some("zbx")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn nrpe_runs_the_commands_its_configuration_names() {
        let d = fixture("nrpe");
        put(&d, "usr/sbin/nrpe", b"");
        put(&d, "etc/nagios/nrpe.cfg", b"nrpe_user=nagios\ncommand_prefix=/usr/bin/sudo\ncommand[check_users]=/usr/lib/nagios/plugins/check_users -w 5\ninclude_dir=/etc/nagios/nrpe.d/\n");
        put(&d, "etc/nagios/nrpe.d/local.cfg", b"# command[x]=/tmp/x\ncommand[beacon]==/opt/beacon $ARG1$\ndont_blame_nrpe=1\n");
        put(&d, "etc/nagios/nrpe.d/sub/deep.cfg", b"command[deep]=/opt/deep\n");
        put(&d, "etc/nagios/nrpe.d/.hid/h.cfg", b"command[hid]=/opt/h\n");
        put(&d, "etc/nagios/nrpe.d/notes.txt", b"command[txt]=/opt/t\n");
        let s = scan(&d);
        let got: Vec<(&str, &str)> =
            s.entries.iter().map(|e| (e.name.as_str(), std::str::from_utf8(e.command.as_deref().unwrap()).unwrap())).collect();
        assert_eq!(
            got,
            [
                ("nrpe:check_users", "/usr/bin/sudo /usr/lib/nagios/plugins/check_users -w 5"),
                ("nrpe:beacon", "/usr/bin/sudo /opt/beacon $ARG1$"),
                ("nrpe:deep", "/usr/bin/sudo /opt/deep"),
            ]
        );
        assert!(s.entries.iter().all(|e| e.raw.contains_key("arguments") && e.principal.as_deref() == Some("nagios")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn salt_schedules_run_what_their_jobs_name() {
        let d = fixture("salt");
        put(&d, "usr/bin/salt-minion", b"");
        put(&d, "etc/salt/minion", b"master: salt\nschedule:\n  beacon:\n    function: cmd.run\n    args: ['/opt/b --quiet']\n    minutes: 5\n  states:\n    function: state.apply\n    hours: 1\n");
        put(&d, "etc/salt/minion.d/extra.conf", b"schedule:\n  paused:\n    function: cmd.shell\n    kwargs: {cmd: /tmp/x}\n    enabled: false\n");
        put(&d, "etc/salt/minion.d/notes.txt", b"schedule:\n  never:\n    function: cmd.run\n    args: [/never]\n");
        let s = scan(&d);
        let mut got: Vec<(&str, &str, Enablement)> = s
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.command.as_deref().map(|c| std::str::from_utf8(c).unwrap()).unwrap_or("-"), e.enabled))
            .collect();
        got.sort();
        assert_eq!(
            got,
            [("salt:beacon", "/opt/b --quiet", Enablement::Enabled), ("salt:paused", "/tmp/x", Enablement::Disabled), ("salt:states", "-", Enablement::Enabled)]
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn collectd_grammar_is_read_as_its_scanner_reads_it() {
        use Stmt::*;
        let got = oconfig(b"LoadPlugin exec # x\n<Plugin \"exec\">\n  Exec \"nobody:nogroup\" \"/opt/a b\" \"-x\" 5 \\\n true\n  Exec \"u\" \"/p\\\"q\" \"multi\\\n     line\"\n</Plugin>\n");
        assert_eq!(
            got,
            [
                Item("LoadPlugin".into(), vec!["exec".into()]),
                Open("Plugin".into(), vec!["exec".into()]),
                Item("Exec".into(), vec!["nobody:nogroup".into(), "/opt/a b".into(), "-x".into(), "5".into(), "true".into()]),
                Item("Exec".into(), vec!["u".into(), "/p\"q".into(), "multiline".into()]),
                Close("Plugin".into()),
            ]
        );
    }

    #[test]
    fn collectd_runs_what_its_loaded_plugins_name() {
        let d = fixture("collectd");
        put(&d, "usr/sbin/collectd", b"");
        put(
            &d,
            "etc/collectd/collectd.conf",
            b"LoadPlugin exec\nLoadPlugin python\n<Include \"/etc/collectd/collectd.conf.d\">\n  Filter \"*.conf\"\n</Include>\n",
        );
        put(&d, "etc/collectd/collectd.conf.d/a.conf", b"<Plugin exec>\n  Exec \"nobody\" \"/opt/poll\" \"-v\"\n  NotificationExec \"root\" \"/opt/n\"\n</Plugin>\n");
        put(&d, "etc/collectd/collectd.conf.d/b.conf", b"<Plugin python>\n  ModulePath \"/opt/py\"\n  Import \"spy\"\n  Import \"os\"\n  <Module spy>\n    Import \"no\"\n  </Module>\n</Plugin>\n<Plugin perl>\n  LoadPlugin \"Collectd::Plugins::X\"\n</Plugin>\n");
        put(&d, "etc/collectd/collectd.conf.d/c.txt", b"<Plugin exec>\n Exec \"u\" \"/never\"\n</Plugin>\n");
        put(&d, "etc/collectd/collectd.conf.d/.h.conf", b"<Plugin exec>\n Exec \"u\" \"/never\"\n</Plugin>\n");
        put(&d, "opt/py/spy.py", b"");
        let s = scan(&d);
        let got: Vec<(&str, Option<&str>, Enablement)> =
            s.entries.iter().map(|e| (e.name.as_str(), e.principal.as_deref(), e.enabled)).collect();
        assert_eq!(
            got,
            [
                ("collectd:Exec:/opt/poll", Some("nobody"), Enablement::Enabled),
                ("collectd:NotificationExec:/opt/n", Some("root"), Enablement::Disabled),
                ("collectd:perl:Collectd::Plugins::X", Some("root"), Enablement::Disabled),
                ("collectd:python:os", Some("root"), Enablement::Enabled),
                ("collectd:python:spy", Some("root"), Enablement::Enabled),
            ]
        );
        assert_eq!(s.entries[0].command.as_deref(), Some(b"/opt/poll -v".as_slice()));
        assert_eq!(s.entries[4].target_path.as_deref(), Some(Path::new("/opt/py/spy.py")));
        assert!(s.entries[3].raw.contains_key("target_unverifiable"));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
