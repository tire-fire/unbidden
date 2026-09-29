//! cloud-init: the commands its configuration runs and the scripts it runs
//! from its own directories, each boot or once per instance, as root.
//!
//! Read the way cloud-init 26.2 reads them. The configuration is YAML,
//! loaded as PyYAML loads it (see `crate::yaml`), from sources merged
//! highest first: the instance's cloud-config.txt (user data), its vendor
//! data, /run/cloud-init/cloud.cfg, cloud.cfg.d/*.cfg with the name that
//! sorts last first, then /etc/cloud/cloud.cfg. The default merge keeps a
//! list from the first source that has it, so of several `bootcmd` lists
//! one runs; a source that sets `merge_how` may append instead, and what it
//! loses is left unknown. The datasource's own configuration and the kernel
//! command line's are not read.
//!
//! Whether each module runs, and how often, comes from the module lists in
//! the merged configuration and the semaphores cloud-init leaves: a module
//! run once per instance has run for this one when its semaphore exists, and
//! runs again only for a new instance id.

use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger};
use crate::scan::{Collector, Ctx};
use crate::yaml::{self, Value};

pub struct CloudInit;

impl Collector for CloudInit {
    fn name(&self) -> &'static str {
        "cloud_init"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        if !cx.root.exists("etc/cloud") && !cx.root.exists("var/lib/cloud") {
            return Vec::new();
        }
        let gate = gate(cx);
        let sources = sources(cx);
        let merged = |key: &str| sources.iter().position(|s| s.cfg.get(key).is_some());
        let modules = Modules::read(&sources, merged);

        let mut out = Vec::new();
        for (key, module) in [("bootcmd", "bootcmd"), ("runcmd", "runcmd")] {
            let winner = merged(key);
            for (i, s) in sources.iter().enumerate() {
                let Some(list) = s.cfg.get(key) else { continue };
                commands(cx, &mut out, s, key, list, winner, i, &sources, &modules, module, &gate);
            }
        }
        scripts(cx, &mut out, &modules, &gate);
        hooks(cx, &mut out, &gate);
        out
    }
}

/// What decides whether cloud-init runs at all.
struct Gate {
    /// A reason it does not, or `None` where it may.
    off: Option<String>,
    /// Whether it does on this boot is known: a live root whose generator
    /// has recorded its decision.
    known: bool,
}

impl Gate {
    /// An entry that would run is unknown where cloud-init's own decision
    /// is, and off where cloud-init is.
    fn apply(&self, e: &mut Entry) {
        if e.enabled == Enablement::Enabled && !self.known {
            e.enabled = Enablement::Unknown;
        }
        if let Some(why) = &self.off {
            e.enabled = Enablement::Disabled;
            e.note("cloud_init_off", why.clone());
        }
    }
}

fn gate(cx: &mut Ctx) -> Gate {
    let installed = ["usr/bin/cloud-init", "bin/cloud-init", "usr/local/bin/cloud-init"].iter().any(|p| cx.root.exists(p));
    let off = if !installed {
        Some("cloud-init is not installed".to_string())
    } else if cx.root.exists("etc/cloud/cloud-init.disabled") {
        Some("/etc/cloud/cloud-init.disabled exists".to_string())
    } else if cx.root.is_live()
        && cx.read("proc/cmdline").is_some_and(|c| c.split(|b| b.is_ascii_whitespace()).any(|w| w == b"cloud-init=disabled"))
    {
        Some("cloud-init=disabled on the kernel command line".to_string())
    } else if cx.root.is_live() && cx.root.exists("run/cloud-init/disabled") {
        Some("the generator disabled it for this boot (no datasource found)".to_string())
    } else {
        None
    };
    let known = off.is_some() || (cx.root.is_live() && cx.root.exists("run/cloud-init/enabled"));
    Gate { off, known }
}

/// One configuration source, in merge order.
struct Source {
    rel: PathBuf,
    cfg: Value,
    /// It sets merge_how or merge_type, so it may extend a higher source's
    /// list instead of losing to it.
    custom_merge: bool,
    /// Its first line marks it a Jinja template, rendered before loading.
    jinja: bool,
}

const INSTANCE: &str = "var/lib/cloud/instance";

fn sources(cx: &mut Ctx) -> Vec<Source> {
    let mut rels: Vec<PathBuf> = ["cloud-config.txt", "vendor2-cloud-config.txt", "vendor-cloud-config.txt"]
        .iter()
        .map(|f| Path::new(INSTANCE).join(f))
        .collect();
    rels.push(PathBuf::from("run/cloud-init/cloud.cfg"));

    let base = load(cx, Path::new("etc/cloud/cloud.cfg"));
    // cloud.cfg may name its own drop-in directory.
    let confd = match base.as_ref().and_then(|s| s.cfg.get("conf_d")) {
        Some(Value::Str(d)) => {
            let d = d.trim();
            PathBuf::from(d.strip_prefix('/').unwrap_or(d))
        }
        Some(_) => PathBuf::new(),
        None => PathBuf::from("etc/cloud/cloud.cfg.d"),
    };
    let names: Vec<_> = if confd.as_os_str().is_empty() {
        Vec::new()
    } else {
        cx.dir(&confd).into_iter().filter(|e| !e.is_dir && e.name.as_encoded_bytes().ends_with(b".cfg")).map(|e| e.name).collect()
    };
    rels.extend(names.into_iter().rev().map(|n| confd.join(n)));

    let mut out: Vec<Source> = rels.iter().filter_map(|r| load(cx, r)).collect();
    out.extend(base);
    out
}

/// A source as cloud-init loads it: nothing where the file is absent, is
/// not UTF-8, is not YAML or is not a mapping, since cloud-init then reads
/// it as empty.
fn load(cx: &mut Ctx, rel: &Path) -> Option<Source> {
    let bytes = cx.read(rel)?;
    let problem = |cx: &mut Ctx, why: &str| cx.note_limited(format!("{}: {why}; cloud-init reads it as empty", rel.display()));
    let Ok(text) = std::str::from_utf8(&bytes) else {
        problem(cx, "not UTF-8");
        return None;
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let cfg = match yaml::parse(text) {
        Ok(Some(v @ Value::Map(_))) => v,
        Ok(None) => return None,
        Ok(Some(_)) => {
            problem(cx, "not a YAML mapping");
            return None;
        }
        Err(e) => {
            problem(cx, &format!("not YAML cloud-init can load ({e})"));
            return None;
        }
    };
    let custom_merge = cfg.get("merge_how").is_some() || cfg.get("merge_type").is_some();
    let jinja = text.lines().next().is_some_and(|l| l.trim().eq_ignore_ascii_case("## template: jinja"));
    Some(Source { rel: rel.to_path_buf(), cfg, custom_merge, jinja })
}

const PER_ALWAYS: &str = "always";
const PER_INSTANCE: &str = "once-per-instance";
const PER_ONCE: &str = "once";

/// The modules the merged configuration lists, with the frequency each
/// runs at.
struct Modules(Vec<(String, Option<String>)>);

impl Modules {
    fn read(sources: &[Source], merged: impl Fn(&str) -> Option<usize>) -> Modules {
        let mut out = Vec::new();
        for list in ["cloud_init_modules", "cloud_config_modules", "cloud_final_modules"] {
            let Some(i) = merged(list) else { continue };
            let Some(Value::Seq(items)) = sources[i].cfg.get(list) else { continue };
            for item in items {
                // A name, [name, frequency, args...] or {name, frequency}.
                let (name, freq) = match item {
                    Value::Str(n) => (Some(n.as_str()), None),
                    Value::Seq(v) => (v.first().and_then(Value::as_str), v.get(1).and_then(Value::as_str)),
                    Value::Map(_) => (item.get("name").and_then(Value::as_str), item.get("frequency").and_then(Value::as_str)),
                    _ => (None, None),
                };
                if let Some(name) = name.and_then(canonical) {
                    out.push((name, freq.map(|f| f.trim().to_string())));
                }
            }
        }
        Modules(out)
    }

    /// Whether `module` is listed, and at what frequency; its own default
    /// where the list names none.
    fn frequency(&self, module: &str, default: &str) -> Option<String> {
        self.0.iter().find(|(n, _)| n == module).map(|(_, f)| f.clone().unwrap_or_else(|| default.to_string()))
    }
}

/// A module name as cloud-init's form_module_name makes it, without the
/// `cc_` it then prefixes.
fn canonical(name: &str) -> Option<String> {
    let mut n = name.replace('-', "_");
    if n.to_ascii_lowercase().ends_with(".py") {
        n.truncate(n.len() - 3);
    }
    let n = n.trim();
    let n = n.strip_prefix("cc_").unwrap_or(n);
    (!n.is_empty()).then(|| n.to_string())
}

/// Whether a module will run on the next boot, and why not.
fn runs(cx: &Ctx, modules: &Modules, module: &str, default: &str) -> Result<String, String> {
    let Some(freq) = modules.frequency(module, default) else {
        return Err(format!("{module} is in no module list"));
    };
    let sem = match freq.as_str() {
        PER_ALWAYS => None,
        PER_ONCE => Some(format!("var/lib/cloud/sem/config_{module}.once")),
        _ => Some(format!("{INSTANCE}/sem/config_{module}")),
    };
    match sem {
        Some(s) if cx.root.exists(&s) => Err(format!("{module} has run ({freq}); runs again only for a new instance")),
        _ => Ok(freq),
    }
}

/// A command as cloud-init's shellify writes it: a string as it is, a list
/// with each member single-quoted.
fn shellify(v: &Value) -> Option<String> {
    match v {
        Value::Str(s) => Some(s.clone()),
        Value::Seq(args) => {
            let quoted: Option<Vec<String>> = args.iter().map(|a| a.python_str().map(|s| format!("'{}'", s.replace('\'', "'\\''")))).collect();
            quoted.map(|q| q.join(" "))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn commands(
    cx: &mut Ctx,
    out: &mut Vec<Entry>,
    s: &Source,
    key: &str,
    list: &Value,
    winner: Option<usize>,
    i: usize,
    sources: &[Source],
    modules: &Modules,
    module: &str,
    gate: &Gate,
) {
    let Value::Seq(items) = list else {
        cx.note_limited(format!("{}: {key} is not a list; cloud-init fails the module", s.rel.display()));
        return;
    };
    // shellify raises on the first item that is neither a string, a list
    // nor empty, and the module then runs none of them.
    let broken = items.iter().any(|v| !matches!(v, Value::Null) && shellify(v).is_none());
    let run = match key {
        // runcmd writes the script; scripts_user runs it.
        "runcmd" => runs(cx, modules, "runcmd", PER_INSTANCE).and_then(|_| runs(cx, modules, "scripts_user", PER_INSTANCE)),
        _ => runs(cx, modules, module, PER_ALWAYS),
    };
    for item in items {
        let Some(command) = shellify(item) else { continue };
        let id = blake3::hash(command.as_bytes()).to_hex();
        let mut e = cx.entry(Kind::CloudInit, &s.rel, format!("{key}:{}", &id[..12]));
        e.trigger = Trigger::Boot;
        e.principal = Some("root".into());
        e.note("key", key);
        e.note("module", module);
        if let Some(w) = command.split_whitespace().next().map(|w| w.trim_matches('\''))
            && w.starts_with('/')
        {
            e.target_path = Some(PathBuf::from(w));
        }
        e.command = Some(command.into_bytes());
        e.enabled = Enablement::Enabled;
        if s.jinja {
            e.note("jinja", "a template cloud-init renders first; read as written");
        }
        match &run {
            Ok(freq) => e.note("frequency", freq.clone()),
            Err(why) => {
                e.enabled = Enablement::Disabled;
                e.note("not_run", why.clone());
            }
        }
        if broken {
            e.enabled = Enablement::Disabled;
            e.note("not_run", format!("an item in this {key} is neither a string nor a list, which fails the module"));
        }
        if let Some(w) = winner
            && w != i
        {
            let by = format!("/{}", sources[w].rel.display());
            if s.custom_merge {
                // Not knowing whether it merges is no reason to say it runs: an
                // item the module will not run, or that fails it, stays off.
                if e.enabled == Enablement::Enabled {
                    e.enabled = Enablement::Unknown;
                }
                e.note("merge", format!("sets merge_how; may add to {by}"));
            } else {
                e.enabled = Enablement::Disabled;
                e.note("superseded", format!("{by} sets {key} first"));
            }
        }
        gate.apply(&mut e);
        out.push(e);
    }
}

/// The directories cloud-init runs every executable file of, in name order,
/// with the module that runs each.
const SCRIPT_DIRS: [(&str, &str, &str); 5] = [
    ("var/lib/cloud/scripts/per-boot", "scripts_per_boot", PER_ALWAYS),
    ("var/lib/cloud/scripts/per-instance", "scripts_per_instance", PER_INSTANCE),
    ("var/lib/cloud/scripts/per-once", "scripts_per_once", PER_ONCE),
    ("var/lib/cloud/instance/scripts", "scripts_user", PER_INSTANCE),
    ("var/lib/cloud/instance/scripts/vendor", "scripts_vendor", PER_INSTANCE),
];

fn scripts(cx: &mut Ctx, out: &mut Vec<Entry>, modules: &Modules, gate: &Gate) {
    for (dir, module, default) in SCRIPT_DIRS {
        let run = runs(cx, modules, module, default);
        let ents = cx.dir(dir);
        for ent in ents {
            let rel = Path::new(dir).join(&ent.name);
            let Ok(meta) = cx.root.stat_follow(&rel) else { continue };
            // runparts runs a regular file it may execute and skips the rest.
            if !meta.is_file {
                continue;
            }
            let mut e = cx.entry(Kind::CloudInit, &rel, ent.name.to_string_lossy());
            e.trigger = Trigger::Boot;
            e.principal = Some("root".into());
            e.target_path = Some(cx.root.abs(&rel));
            e.note("module", module);
            e.enabled = Enablement::Enabled;
            match &run {
                Ok(freq) => e.note("frequency", freq.clone()),
                Err(why) => {
                    e.enabled = Enablement::Disabled;
                    e.note("not_run", why.clone());
                }
            }
            if meta.mode & 0o111 == 0 {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "not executable; runparts skips it");
            }
            gate.apply(&mut e);
            out.push(e);
        }
    }
}

/// What cloud-init runs from user data on every boot, before any module:
/// user data is consumed each boot, and in doing so cloud-init imports every
/// `*.py` in its handlers directory as a part handler (the import runs the
/// file, handler or not), writes each part handler and boothook the user
/// data holds and runs it. Both handler directories go on the front of
/// Python's module path, so a file there can also stand in for a module
/// cloud-init imports later. The seed directory holds user data a NoCloud
/// datasource reads from disk, rather than from a cloud, on each boot.
fn hooks(cx: &mut Ctx, out: &mut Vec<Entry>, gate: &Gate) {
    const DIRS: [(&str, &str, &str); 3] = [
        ("var/lib/cloud/handlers", "handler", "imported by cloud-init on every boot"),
        ("var/lib/cloud/instance/handlers", "part-handler", "written from user data and imported on every boot"),
        ("var/lib/cloud/instance/boothooks", "boothook", "written from user data and run on every boot"),
    ];
    for (dir, what, how) in DIRS {
        let ents = cx.dir(dir);
        for ent in ents {
            let name = ent.name.to_string_lossy().into_owned();
            let rel = Path::new(dir).join(&ent.name);
            let Ok(meta) = cx.root.stat_follow(&rel) else { continue };
            if !meta.is_file {
                continue;
            }
            // Python imports `name.py` by module name, so a name with a
            // dot of its own, or not ending in .py, is never loaded.
            let module = name.strip_suffix(".py").map(str::trim).filter(|m| !m.is_empty() && !m.contains('.'));
            if what != "boothook" && module.is_none() {
                continue;
            }
            let mut e = cx.entry(Kind::CloudInit, &rel, format!("{what}:{name}"));
            e.trigger = Trigger::Boot;
            e.principal = Some("root".into());
            e.target_path = Some(cx.root.abs(&rel));
            e.note("hook", what);
            e.note("frequency", PER_ALWAYS);
            e.note("runs", how);
            if let Some(m) = module {
                e.note("python_module", m);
            }
            e.enabled = Enablement::Enabled;
            gate.apply(&mut e);
            out.push(e);
        }
    }

    for seed in cx.dir("var/lib/cloud/seed") {
        if !seed.is_dir {
            continue;
        }
        let dir = Path::new("var/lib/cloud/seed").join(&seed.name);
        for file in ["user-data", "vendor-data"] {
            let rel = dir.join(file);
            let Some(bytes) = cx.read_capped(&rel, 4096) else { continue };
            let mut e = cx.entry(Kind::CloudInit, &rel, format!("seed:{}:{file}", seed.name.to_string_lossy()));
            e.trigger = Trigger::Boot;
            e.principal = Some("root".into());
            e.target_path = Some(cx.root.abs(&rel));
            e.note("hook", "seed");
            e.note("datasource", seed.name.to_string_lossy());
            // What cloud-init makes of it depends on how it starts.
            let first = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
            e.note("format", String::from_utf8_lossy(&first[..first.len().min(80)]).trim().to_string());
            e.enabled = Enablement::Enabled;
            gate.apply(&mut e);
            out.push(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan};

    fn put(dir: &Path, rel: &str, content: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, PermissionsExt::from_mode(mode)).unwrap();
    }

    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(CloudInit)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    fn by_command<'a>(s: &'a Scan, command: &str) -> &'a Entry {
        s.entries
            .iter()
            .find(|e| e.command.as_deref() == Some(command.as_bytes()))
            .unwrap_or_else(|| panic!("no entry runs {command}"))
    }

    #[test]
    fn a_merge_that_may_add_does_not_turn_a_module_that_never_runs_into_a_maybe() {
        let d = std::env::temp_dir().join(format!("unbidden-cloudinit-merge-off-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "usr/bin/cloud-init", "#!/usr/bin/python3\n", 0o755);
        // runcmd is in no module list, so nothing runs it whatever merges.
        put(&d, "etc/cloud/cloud.cfg", "cloud_init_modules: [bootcmd]\nruncmd: [echo base]\n", 0o644);
        put(&d, "etc/cloud/cloud.cfg.d/10-m.cfg", "merge_how: list(append)+dict()\nruncmd: [echo appended]\n", 0o644);
        put(&d, "etc/cloud/cloud.cfg.d/90-z.cfg", "runcmd: [echo winner]\n", 0o644);
        let s = scan(&d);
        let appended = by_command(&s, "echo appended");
        assert_eq!(appended.enabled, Enablement::Disabled);
        assert_eq!(appended.raw["not_run"], "runcmd is in no module list");
        assert!(appended.raw["merge"].starts_with("sets merge_how"), "the merge is still said");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn commands_and_scripts_are_read_as_cloud_init_merges_and_runs_them() {
        let d = std::env::temp_dir().join(format!("unbidden-cloudinit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "usr/bin/cloud-init", "#!/usr/bin/python3\n", 0o755);
        put(
            &d,
            "etc/cloud/cloud.cfg",
            "cloud_init_modules: [bootcmd]\ncloud_config_modules: [runcmd]\n\
             cloud_final_modules: [scripts_per_boot, scripts_per_instance, [scripts_user, always]]\n\
             bootcmd: [echo base]\nruncmd: [\"echo run\"]\n",
            0o644,
        );
        put(&d, "etc/cloud/cloud.cfg.d/50-a.cfg", "bootcmd:\n  - echo fifty\n", 0o644);
        put(&d, "etc/cloud/cloud.cfg.d/90-z.cfg", "bootcmd:\n  - [/opt/x, \"a'b\", yes]\n  -\n", 0o644);
        put(&d, "etc/cloud/cloud.cfg.d/10-m.cfg", "merge_how: list(append)+dict()\nbootcmd: [echo appended]\n", 0o644);
        put(&d, "etc/cloud/cloud.cfg.d/20-bad.cfg", "bootcmd: [echo never\n", 0o644);
        put(&d, "etc/cloud/cloud.cfg.d/30.cfg.bak", "bootcmd: [echo ignored]\n", 0o644);
        put(&d, "var/lib/cloud/scripts/per-boot/10-beacon", "#!/bin/sh\n", 0o755);
        put(&d, "var/lib/cloud/scripts/per-boot/20-inert", "#!/bin/sh\n", 0o644);
        put(&d, "var/lib/cloud/scripts/per-instance/once", "#!/bin/sh\n", 0o755);
        put(&d, "var/lib/cloud/instance/sem/config_scripts_per_instance", "", 0o644);
        put(&d, "var/lib/cloud/instance/scripts/runcmd", "#!/bin/sh\necho run\n", 0o700);
        let s = scan(&d);

        let won = by_command(&s, "'/opt/x' 'a'\\''b' 'True'");
        assert_eq!(won.enabled, Enablement::Unknown, "offline, cloud-init's own decision is unknown");
        assert_eq!((won.trigger, won.raw["frequency"].as_str()), (Trigger::Boot, "always"));
        assert_eq!(won.target_path, Some(PathBuf::from("/opt/x")));
        let lost = by_command(&s, "echo fifty");
        assert_eq!(lost.enabled, Enablement::Disabled);
        assert_eq!(lost.raw["superseded"], "/etc/cloud/cloud.cfg.d/90-z.cfg sets bootcmd first");
        assert_eq!(by_command(&s, "echo base").enabled, Enablement::Disabled);
        let appended = by_command(&s, "echo appended");
        assert_eq!(appended.enabled, Enablement::Unknown);
        assert!(appended.raw["merge"].starts_with("sets merge_how"));
        assert!(s.entries.iter().all(|e| e.command.as_deref() != Some(b"echo ignored".as_slice())), "only .cfg files are read");
        assert!(s.header.collectors[0].truncated.iter().any(|t| t.contains("20-bad.cfg")), "a file that is not YAML is noted");

        // scripts_user runs always here, so the runcmd script runs every boot.
        let script = s.entries.iter().find(|e| e.name == "runcmd" && e.raw["module"] == "scripts_user").unwrap();
        assert_eq!(script.raw["frequency"], "always");
        let beacon = s.entries.iter().find(|e| e.name == "10-beacon").unwrap();
        assert_eq!((beacon.enabled, beacon.raw["frequency"].as_str()), (Enablement::Unknown, "always"));
        assert_eq!(s.entries.iter().find(|e| e.name == "20-inert").unwrap().enabled, Enablement::Disabled);
        let once = s.entries.iter().find(|e| e.name == "once").unwrap();
        assert_eq!(once.enabled, Enablement::Disabled);
        assert!(once.raw["not_run"].contains("runs again only for a new instance"));

        // A bad item fails the whole module; a missing module runs nothing.
        put(&d, "etc/cloud/cloud.cfg.d/90-z.cfg", "bootcmd: [echo ok, 5]\nruncmd: [echo r]\ncloud_config_modules: [ntp]\n", 0o644);
        let s = scan(&d);
        assert!(by_command(&s, "echo ok").raw["not_run"].contains("fails the module"));
        assert_eq!(by_command(&s, "echo r").raw["not_run"], "runcmd is in no module list");

        put(&d, "etc/cloud/cloud-init.disabled", "", 0o644);
        let s = scan(&d);
        assert!(s.entries.iter().all(|e| e.enabled == Enablement::Disabled && e.raw.contains_key("cloud_init_off")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn module_names_are_canonicalised_as_cloud_init_does() {
        assert_eq!(canonical("cc_scripts-user.py").as_deref(), Some("scripts_user"));
        assert_eq!(canonical(" bootcmd ").as_deref(), Some("bootcmd"));
        assert_eq!(canonical("  "), None);
    }

    #[test]
    fn handlers_boothooks_and_seed_user_data_run_every_boot() {
        let d = std::env::temp_dir().join(format!("unbidden-cloudinit-hooks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "usr/bin/cloud-init", "#!/usr/bin/python3\n", 0o755);
        put(&d, "var/lib/cloud/handlers/evil.py", "import os\n", 0o644);
        put(&d, "var/lib/cloud/handlers/not.a.module.py", "", 0o644);
        put(&d, "var/lib/cloud/handlers/README", "", 0o644);
        put(&d, "var/lib/cloud/instance/handlers/part-handler-000.py", "def handle_part(*a): pass\n", 0o600);
        put(&d, "var/lib/cloud/instance/boothooks/part-001", "#!/bin/sh\necho hi\n", 0o700);
        put(&d, "var/lib/cloud/seed/nocloud/user-data", "#cloud-config\nruncmd: [id]\n", 0o600);
        put(&d, "var/lib/cloud/seed/nocloud/meta-data", "instance-id: x\n", 0o600);
        let s = scan(&d);
        let mut names: Vec<&str> = s.entries.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["boothook:part-001", "handler:evil.py", "part-handler:part-handler-000.py", "seed:nocloud:user-data"],
            "a dotted module name, a non-Python file and meta-data run nothing"
        );
        let evil = s.entries.iter().find(|e| e.name == "handler:evil.py").unwrap();
        assert_eq!((evil.trigger, evil.enabled, evil.raw["python_module"].as_str()), (Trigger::Boot, Enablement::Unknown, "evil"));
        assert_eq!(s.entries.iter().find(|e| e.name.starts_with("seed")).unwrap().raw["format"], "#cloud-config");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
