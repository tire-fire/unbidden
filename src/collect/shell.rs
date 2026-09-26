//! Shell startup files, and the dynamic loader's preload list.
//!
//! One entry per file, never per line. A .bashrc is hundreds of lines and an
//! entry per line is a wall nobody reads; what the file *does* is lifted into
//! `raw` instead — environment assignments, sourced paths, and the lines that
//! run something — because that is what an operator greps and what the
//! enrichment pass of §14.4 correlates.
//!
//! The extraction is a line-oriented scan, not a shell parser. Shell cannot be
//! parsed without evaluating it, and evaluating attacker-authored shell is the
//! one thing this tool must never do. The blind spots are listed on
//! `scan_shell` and are deliberate.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Flag, Kind, Trigger, name_from_os};
use crate::root::READ_CAP;
use crate::scan::{Collector, Ctx};
use crate::users::User;

pub struct Shell;

/// System-wide startup files. Both zsh layouts are listed: most distributions
/// put zsh's files in /etc/zsh, some put them straight in /etc, and a file in
/// the layout the running zsh does not use is still a file worth reporting.
const SYSTEM_PROFILES: &[&str] = &[
    "etc/profile",
    "etc/bash.bashrc",
    "etc/bashrc",
    "etc/environment",
    "etc/zsh/zshenv",
    "etc/zsh/zprofile",
    "etc/zsh/zshrc",
    "etc/zsh/zlogin",
    "etc/zsh/zlogout",
    "etc/zshenv",
    "etc/zprofile",
    "etc/zshrc",
    "etc/zlogin",
    "etc/zlogout",
];

const USER_PROFILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
];

/// The one system file in the list above that is not shell (§ PAM reads it).
const PAM_ENV: &str = "etc/environment";

/// pam_env's own configuration, which sets variables for every PAM session —
/// every login, every su, every cron job that goes through PAM. Its syntax is
/// not the `KEY=value` of /etc/environment but
/// `VARIABLE [DEFAULT=value] [OVERRIDE=value]`, so it needs its own reading.
const PAM_ENV_CONF: &str = "etc/security/pam_env.conf";

/// systemd's environment drop-ins, which apply to every user session it
/// starts. Plain `KEY=value`, like /etc/environment.
const ENVIRONMENT_D: &[&str] = &[
    "etc/environment.d",
    "run/environment.d",
    "usr/local/lib/environment.d",
    "usr/lib/environment.d",
    "lib/environment.d",
];

/// How a file that carries environment assignments spells them.
#[derive(Clone, Copy, PartialEq)]
enum Syntax {
    /// A shell script: `export NAME=value`, and it may run commands.
    Shell,
    /// `NAME=value` only, no expansion, no commands. /etc/environment and
    /// systemd's environment.d drop-ins.
    KeyValue,
    /// `VARIABLE DEFAULT=value OVERRIDE=value`.
    PamEnvConf,
}

/// Library directories every distribution already searches. A directory
/// outside these is what makes an ld.so.conf drop-in worth mentioning.
const STANDARD_LIB_DIRS: &[&str] =
    &["/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64"];

/// How much of one extracted value is kept.
const VALUE_CAP: usize = 2048;
/// How much of one executing line is kept, and how many of them.
const EXEC_LINE_CAP: usize = 512;
const EXEC_KEEP: usize = 32;
/// Words per line. A megabyte of single-character words is not a profile.
const MAX_WORDS: usize = 1024;

impl Collector for Shell {
    fn name(&self) -> &'static str {
        "shell"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();

        for p in SYSTEM_PROFILES {
            let syntax = if *p == PAM_ENV { Syntax::KeyValue } else { Syntax::Shell };
            profile(cx, Path::new(p), None, syntax, &mut seen, &mut out);
        }
        // §5 says /etc/zsh/*, not a list of names: a distribution can ship
        // anything there and an attacker can add to it, and a file zsh reads
        // that this walk does not is the whole failure mode.
        for dir in ["etc/zsh", "etc/profile.d"] {
            for ent in cx.dir(dir) {
                if ent.is_dir {
                    continue;
                }
                let rel = Path::new(dir).join(&ent.name);
                profile(cx, &rel, None, Syntax::Shell, &mut seen, &mut out);
            }
        }

        // Environment set for every PAM session and every systemd user
        // session. Neither runs a command itself, which is exactly why an
        // LD_PRELOAD parked here is quiet.
        profile(cx, Path::new(PAM_ENV_CONF), None, Syntax::PamEnvConf, &mut seen, &mut out);
        // /lib/environment.d and /usr/lib/environment.d are one directory on
        // a merged-usr host. Walked by name, every drop-in in it was reported
        // twice, once under the alias (§5).
        let mut walked: BTreeSet<(u64, u64)> = BTreeSet::new();
        for dir in ENVIRONMENT_D {
            match cx.root.dir_identity(dir) {
                Ok(id) if walked.insert(id) => {}
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    cx.note_failed(dir, &e);
                    continue;
                }
            }
            for ent in cx.dir(dir) {
                if ent.is_dir || !ent.name.to_string_lossy().ends_with(".conf") {
                    continue;
                }
                let rel = Path::new(dir).join(&ent.name);
                profile(cx, &rel, None, Syntax::KeyValue, &mut seen, &mut out);
            }
        }

        let users = cx.users;
        for u in users {
            // A home named in passwd that does not exist is not an error and
            // not a finding; it is most of /etc/passwd on a server.
            let Ok(home) = cx.root.stat(&u.home) else { continue };
            let home_link =
                if home.is_symlink { cx.root.read_link(&u.home).ok() } else { None };
            for f in USER_PROFILES {
                let rel = u.in_home(f);
                let at = out.len();
                profile(cx, &rel, Some(u), Syntax::Shell, &mut seen, &mut out);
                if let (Some(t), Some(e)) = (&home_link, out.get_mut(at)) {
                    e.note("home_symlink_target", t.to_string_lossy());
                }
            }
            // The user manager reads the account's own drop-ins ahead of the
            // system ones.
            let dir = u.in_home(".config/environment.d");
            for ent in cx.dir(&dir) {
                if ent.is_dir || !ent.name.to_string_lossy().ends_with(".conf") {
                    continue;
                }
                profile(cx, &dir.join(&ent.name), Some(u), Syntax::KeyValue, &mut seen, &mut out);
            }
        }

        preload(cx, &mut out);
        library_dirs(cx, &mut out);
        out
    }
}

fn profile(
    cx: &mut Ctx,
    rel: &Path,
    user: Option<&User>,
    syntax: Syntax,
    seen: &mut BTreeSet<PathBuf>,
    out: &mut Vec<Entry>,
) {
    // Two accounts can share a home, and /etc/zshrc can be reached twice on a
    // merged layout. Same path, same entry id, so read it once.
    if !seen.insert(cx.root.abs(rel)) {
        return;
    }
    let Ok(meta) = cx.root.stat(rel) else { return };
    if meta.is_dir {
        return;
    }

    let file_name = rel.file_name().unwrap_or(OsStr::new(""));
    let mut e = cx.entry(
        Kind::ShellProfile,
        rel,
        file_name.to_string_lossy().into_owned(),
    );
    name_from_os(&mut e, file_name);
    e.trigger = Trigger::Login;
    e.enabled = Enablement::NotApplicable;
    e.target_path = Some(cx.root.abs(rel));
    if let Some(u) = user {
        e.principal = Some(u.name.clone());
        if let Some(sh) = &u.shell {
            e.note("login_shell", sh.clone());
        }
    }

    // Opening a fifo blocks until a writer appears, which on a hostile host is
    // a free hang. A dangling symlink is evidence in its own right. Either
    // way the file's presence is reported without reading it.
    let regular = if meta.is_symlink {
        cx.root.stat_follow(rel).map(|m| m.is_file).unwrap_or(false)
    } else {
        meta.is_file
    };
    if !regular {
        e.note("not_regular_file", if meta.is_symlink { "link resolves to nothing readable" } else { "not a regular file" });
        out.push(e);
        return;
    }

    // A profile linked out of its owner's home is reported as the link it
    // is and not read: following it is how `~/.bashrc -> /etc/shadow` would
    // put another account's secrets in the report. That is the policy
    // working, so it is noted rather than counted as a failed read, which any
    // user could otherwise use to make every later baseline incomparable.
    if let Some(target) = cx.root.escaping_link(rel) {
        e.note("not_followed", format!("leads out of its owner's home to {}", target.display()));
        cx.note_limited(format!(
            "{}: leads out of its owner's home to {}, not followed",
            cx.root.abs(rel).display(),
            target.display()
        ));
        out.push(e);
        return;
    }

    let (bytes, truncated) = match cx.root.read_capped(rel, READ_CAP) {
        Ok(v) => v,
        Err(err) => {
            cx.note_failed(cx.root.abs(rel), &err);
            e.note("unreadable", err.to_string());
            out.push(e);
            return;
        }
    };
    if truncated {
        cx.note_limited(format!(
            "{} (truncated at {READ_CAP} bytes)",
            cx.root.abs(rel).display()
        ));
        e.note("truncated", format!("read capped at {READ_CAP} bytes"));
    }
    if std::str::from_utf8(&bytes).is_err() {
        e.flag(Flag::EncodingAnomaly);
    }
    let nul = bytes.iter().filter(|b| **b == 0).count();
    if nul > 0 {
        e.note("nul_bytes", nul.to_string());
    }
    match syntax {
        Syntax::Shell => {}
        Syntax::KeyValue => e.note("syntax", "pam-environment"),
        Syntax::PamEnvConf => e.note("syntax", "pam_env.conf"),
    }

    apply(&mut e, match syntax {
        Syntax::Shell => scan_shell(&bytes),
        Syntax::KeyValue => scan_pam_env(&bytes),
        Syntax::PamEnvConf => scan_pam_env_conf(&bytes),
    });
    out.push(e);
}

/// `/etc/ld.so.preload`: the mechanism static linking exists to defend against
/// (§3). One entry per library, because each named object is its own payload.
fn preload(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let rel = Path::new("etc/ld.so.preload");
    let Ok(meta) = cx.root.stat(rel) else { return };
    if !meta.is_file && !(meta.is_symlink && cx.root.stat_follow(rel).map(|m| m.is_file).unwrap_or(false)) {
        return;
    }
    let Ok((bytes, truncated)) = cx.root.read_capped(rel, 64 * 1024) else {
        cx.note_unreadable(format!("{} unreadable", cx.root.abs(rel).display()));
        return;
    };
    if truncated {
        cx.note_limited(format!("{} (truncated at 65536 bytes)", cx.root.abs(rel).display()));
    }

    let mut libs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut listed = BTreeSet::new();
    for raw in bytes.split(|b| *b == b'\n') {
        let line = strip_cr(raw);
        // glibc skips a leading '#' and splits the rest on whitespace.
        let body = match line.iter().position(|b| *b == b'#') {
            Some(0) => continue,
            Some(_) if line.trim_ascii().first() == Some(&b'#') => continue,
            _ => line,
        };
        for lib in body.split(|b| *b == b' ' || *b == b'\t') {
            if lib.is_empty() || lib.starts_with(b"#") {
                break;
            }
            if listed.insert(lib.to_vec()) {
                libs.push((lib.to_vec(), line.to_vec()));
            }
        }
    }
    if libs.is_empty() {
        return;
    }

    let nonstandard = nonstandard_lib_dirs(cx);
    for (lib, line) in libs {
        let mut e = cx.entry(Kind::LdPreload, rel, String::from_utf8_lossy(&lib).into_owned());
        name_from_os(&mut e, OsStr::from_bytes(&lib));
        e.command = Some(line);
        e.target_path = Some(PathBuf::from(OsString::from_vec(lib)));
        e.trigger = Trigger::Always;
        // A library listed here is loaded into every dynamically linked
        // process on the system; there is no state in which it is not.
        e.enabled = Enablement::Enabled;
        if !nonstandard.is_empty() {
            e.note("ld_so_conf.nonstandard", nonstandard.join("\n"));
        }
        out.push(e);
    }
}

/// Search directories configured outside the set every distribution already
/// has. Recorded as a note on the preload entries, never as entries of their
/// own — a configured directory is not itself something that runs.
fn nonstandard_lib_dirs(cx: &mut Ctx) -> Vec<String> {
    super::ld_so_conf_dirs(cx).into_iter().map(|(d, _)| d).filter(|d| !is_standard_lib_dir(d)).collect()
}

/// A directory ld.so.conf adds to the loader's search outside the set every
/// distribution already has. Every dynamically linked program looks there,
/// so a library dropped into it under a common soname is loaded in place of
/// the real one. The file that names it is the source; a vendor's packaged
/// drop-in is hidden like any other packaged file.
fn library_dirs(cx: &mut Ctx, out: &mut Vec<Entry>) {
    for (dir, rel) in super::ld_so_conf_dirs(cx) {
        if is_standard_lib_dir(&dir) {
            continue;
        }
        let mut e = cx.entry(Kind::LibraryDir, &rel, dir.clone());
        e.trigger = Trigger::Always;
        e.enabled = Enablement::Enabled;
        e.target_path = Some(PathBuf::from(&dir));
        out.push(e);
    }
}

fn is_standard_lib_dir(d: &str) -> bool {
    STANDARD_LIB_DIRS
        .iter()
        .any(|s| d.strip_prefix(s).is_some_and(|rest| rest.is_empty() || rest.starts_with('/')))
}

#[derive(Default)]
struct Scanned {
    env: Vec<(String, String)>,
    sourced: Vec<String>,
    exec: Vec<String>,
    exec_total: usize,
    crlf: bool,
}

/// A line-oriented scan of shell-ish text. It is honest about being a scan.
///
/// What it finds: `NAME=value`, `export NAME=value`, `typeset -x NAME=value`
/// and the `declare`/`readonly`/`local` spellings; csh's `setenv NAME value`,
/// because /etc/profile.d carries both dialects; `source X` and `. X`,
/// including after a `&&`, `||`, `;` or `|`; and lines whose first word is
/// neither an assignment nor a shell keyword, which are the lines that run
/// something.
///
/// What it misses, deliberately, because closing any of these means evaluating
/// the file:
/// - Command substitution. `$(...)` and backticks are not tracked, so
///   `eval "$(curl x|sh)"` is reported as an executing line but nothing inside
///   it is extracted; `[ -n "$(curl x)" ]` is not reported at all, because the
///   first word is `[`; and an unquoted `|` inside a substitution splits the
///   line, which reports a line as executing that may not be. The error runs
///   towards reporting too much, which is the right direction.
/// - Parameter expansion. `$VAR`, `${VAR:=default}` and `${!ref}` are taken
///   literally, so `LD_PRELOAD=$HOME/x.so` is recorded with the `$HOME` still
///   in it and `export $NAME=$VAL` yields no assignment at all.
/// - Here-documents. The body is scanned as if it were code, so a heredoc
///   containing commands produces spurious executing lines.
/// - Multi-line constructs. A trailing backslash continuation, a quote left
///   open at end of line, and a `for`/`case` body are each scanned one line at
///   a time; a quote never spans lines here.
/// - Arrays, `$'...'` quoting, process substitution `<(...)`, and arithmetic.
/// - Conditional execution. A line inside `if false; then ... fi` is recorded
///   exactly like one that always runs; so is a function body that is never
///   called.
fn scan_shell(bytes: &[u8]) -> Scanned {
    let mut s = Scanned::default();
    for raw in bytes.split(|b| *b == b'\n') {
        let line = match raw.split_last() {
            Some((b'\r', rest)) => {
                s.crlf = true;
                rest
            }
            _ => raw,
        };
        let words = words(line);
        if words.is_empty() {
            continue;
        }
        let mut executes = false;
        for seg in words.split(|w| w.op) {
            executes |= scan_segment(seg, &mut s);
        }
        if executes {
            s.exec_total += 1;
            if s.exec.len() < EXEC_KEEP {
                s.exec.push(clip(line.trim_ascii(), EXEC_LINE_CAP));
            }
        }
    }
    s
}

/// Returns true when the segment runs something.
fn scan_segment(seg: &[Word], s: &mut Scanned) -> bool {
    let mut i = 0;
    while i < seg.len() && push_assign(&seg[i].text, s) {
        i += 1;
    }
    let Some(cmd) = seg.get(i) else { return false };
    match cmd.text.as_slice() {
        b"export" | b"declare" | b"typeset" | b"readonly" | b"local" => {
            for w in &seg[i + 1..] {
                push_assign(&w.text, s);
            }
            false
        }
        b"setenv" => {
            // csh and tcsh: `setenv NAME value`, no `=`. /etc/profile.d holds
            // both dialects side by side, and reading a .csh file as sh turns
            // every one of these into a phantom executing line.
            if let Some(n) = seg.get(i + 1).filter(|n| is_name(&n.text)) {
                let v = seg.get(i + 2).map(|w| clip(&w.text, VALUE_CAP)).unwrap_or_default();
                s.env.push((String::from_utf8_lossy(&n.text).into_owned(), v));
            }
            false
        }
        b"source" | b"." => {
            if let Some(a) = seg.get(i + 1) {
                s.sourced.push(clip(&a.text, VALUE_CAP));
            }
            false
        }
        w => !is_shell_word(w),
    }
}

/// `/etc/environment` is read by pam_env, not by a shell: plain `KEY=value`
/// lines, no `export`, no expansion, no commands. Parsing it as shell would
/// invent findings that cannot happen.
/// `VARIABLE DEFAULT=value OVERRIDE=value`, where OVERRIDE wins when both are
/// present. Either may be quoted, and either may be absent.
fn scan_pam_env_conf(bytes: &[u8]) -> Scanned {
    let mut s = Scanned::default();
    for raw in bytes.split(|b| *b == b'\n') {
        let line = match raw.split_last() {
            Some((b'\r', rest)) => {
                s.crlf = true;
                rest
            }
            _ => raw,
        };
        let line = line.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let mut words = line.split(|b| *b == b' ' || *b == b'\t').filter(|w| !w.is_empty());
        let Some(name) = words.next() else { continue };
        if !is_name(name) {
            continue;
        }
        let (mut default, mut over) = (None, None);
        for w in words {
            if let Some(v) = w.strip_prefix(b"DEFAULT=") {
                default = Some(v.to_vec());
            } else if let Some(v) = w.strip_prefix(b"OVERRIDE=") {
                over = Some(v.to_vec());
            }
        }
        // OVERRIDE wins where both are given, which is what pam_env does.
        let Some(value) = over.or(default) else { continue };
        s.env.push((
            String::from_utf8_lossy(name).into_owned(),
            clip(unquote(&value), VALUE_CAP),
        ));
    }
    s
}

fn scan_pam_env(bytes: &[u8]) -> Scanned {
    let mut s = Scanned::default();
    for raw in bytes.split(|b| *b == b'\n') {
        let line = match raw.split_last() {
            Some((b'\r', rest)) => {
                s.crlf = true;
                rest
            }
            _ => raw,
        };
        let line = line.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let Some(eq) = line.iter().position(|b| *b == b'=') else { continue };
        let (name, value) = line.split_at(eq);
        if !is_name(name) {
            continue;
        }
        s.env.push((
            String::from_utf8_lossy(name).into_owned(),
            clip(unquote(&value[1..]), VALUE_CAP),
        ));
    }
    s
}

fn apply(e: &mut Entry, s: Scanned) {
    let mut env: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in s.env {
        let slot = env.entry(k).or_default();
        if !slot.contains(&v) {
            slot.push(v);
        }
    }
    // One name assigned twice keeps both values, newline separated: the first
    // may be the one that survives, and dropping either loses the evidence.
    for (k, v) in env {
        e.note(&format!("env.{k}"), v.join("\n"));
    }
    if !s.sourced.is_empty() {
        e.note("sourced_count", s.sourced.len().to_string());
        e.note("sourced", s.sourced.join("\n"));
    }
    if s.exec_total > 0 {
        e.note("exec_count", s.exec_total.to_string());
        e.note("exec", s.exec.join("\n"));
        if s.exec_total > s.exec.len() {
            e.note(
                "exec_capped",
                format!(
                    "first {} of {} executing lines kept, each clipped to {EXEC_LINE_CAP} bytes",
                    s.exec.len(),
                    s.exec_total
                ),
            );
        }
    }
    if s.crlf {
        e.note("line_endings", "crlf");
    }
}

struct Word {
    text: Vec<u8>,
    /// A `;`, `|`, `&`, `&&` or `||` that was not inside quotes.
    op: bool,
}

/// Splits a line into words, honouring quoting only far enough to keep a
/// quoted value in one piece and to stop an operator inside quotes from
/// splitting the line. Nothing is expanded.
fn words(line: &[u8]) -> Vec<Word> {
    let mut out: Vec<Word> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut started = false;
    let mut i = 0;
    while i < line.len() && out.len() < MAX_WORDS {
        let c = line[i];
        match c {
            b' ' | b'\t' => {
                if started {
                    out.push(Word { text: std::mem::take(&mut cur), op: false });
                    started = false;
                }
                i += 1;
            }
            b'#' if !started => break,
            b';' | b'|' | b'&' => {
                if started {
                    out.push(Word { text: std::mem::take(&mut cur), op: false });
                    started = false;
                }
                let mut op = vec![c];
                if line.get(i + 1) == Some(&c) {
                    op.push(c);
                    i += 1;
                }
                out.push(Word { text: op, op: true });
                i += 1;
            }
            b'\'' => {
                started = true;
                i += 1;
                while i < line.len() && line[i] != b'\'' {
                    cur.push(line[i]);
                    i += 1;
                }
                i += 1;
            }
            b'"' => {
                started = true;
                i += 1;
                while i < line.len() && line[i] != b'"' {
                    if line[i] == b'\\' && i + 1 < line.len() {
                        i += 1;
                    }
                    cur.push(line[i]);
                    i += 1;
                }
                i += 1;
            }
            b'\\' => {
                started = true;
                i += 1;
                if i < line.len() {
                    cur.push(line[i]);
                    i += 1;
                }
            }
            _ => {
                started = true;
                cur.push(c);
                i += 1;
            }
        }
    }
    if started && out.len() < MAX_WORDS {
        out.push(Word { text: cur, op: false });
    }
    out
}

fn push_assign(w: &[u8], s: &mut Scanned) -> bool {
    let Some(eq) = w.iter().position(|b| *b == b'=') else { return false };
    let (mut name, value) = w.split_at(eq);
    // `PATH+=:/tmp` appends; the appended text is what matters here.
    if let Some((b'+', rest)) = name.split_last() {
        name = rest;
    }
    if !is_name(name) {
        return false;
    }
    s.env.push((
        String::from_utf8_lossy(name).into_owned(),
        clip(&value[1..], VALUE_CAP),
    ));
    true
}

fn is_name(n: &[u8]) -> bool {
    !n.is_empty()
        && (n[0].is_ascii_alphabetic() || n[0] == b'_')
        && n.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// Keywords and builtins that change the shell's own state without running a
/// program. Anything not in here is treated as executing something.
fn is_shell_word(w: &[u8]) -> bool {
    matches!(
        w,
        b"if" | b"then"
            | b"else"
            | b"elif"
            | b"fi"
            | b"for"
            | b"while"
            | b"until"
            | b"do"
            | b"done"
            | b"case"
            | b"esac"
            | b"in"
            | b"select"
            | b"function"
            | b"{"
            | b"}"
            | b"!"
            | b";;"
            | b"return"
            | b"break"
            | b"continue"
            | b"shift"
            | b"exit"
            | b"alias"
            | b"unalias"
            | b"unset"
            | b"umask"
            | b"ulimit"
            | b"set"
            | b"shopt"
            | b"setopt"
            | b"unsetopt"
            | b"bind"
            | b"bindkey"
            | b"complete"
            | b"compdef"
            | b"autoload"
            | b"zstyle"
            | b"zmodload"
            | b"emulate"
            | b"test"
            | b"["
            | b"]"
            | b"[["
            | b"]]"
            | b"fc"
            | b"history"
            | b"cd"
            | b"pushd"
            | b"popd"
            | b"unsetenv"
            | b"endif"
            | b"foreach"
            | b"end"
            | b"switch"
            | b"breaksw"
            | b"endsw"
    )
}

fn strip_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((b'\r', rest)) => rest,
        _ => line,
    }
}

/// Strips one matched pair of surrounding quotes, which is what pam_env does.
fn unquote(v: &[u8]) -> &[u8] {
    if v.len() >= 2 && (v[0] == b'"' || v[0] == b'\'') && v[v.len() - 1] == v[0] {
        &v[1..v.len() - 1]
    } else {
        v
    }
}

fn clip(b: &[u8], cap: usize) -> String {
    let mut s = String::from_utf8_lossy(&b[..cap.min(b.len())]).into_owned();
    if b.len() > cap {
        s.push_str("…[clipped]");
    }
    s
}


#[cfg(test)]
mod pam_env_tests {
    use super::*;
    use crate::scan::{self, Collector, Options};

    #[test]
    fn an_ld_preload_parked_in_a_pam_or_systemd_environment_file_is_found() {
        let dir = std::env::temp_dir().join(format!("unbidden-pamenv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let put = |rel: &str, body: &[u8]| {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        put("etc/os-release", b"ID=debian\n");
        // OVERRIDE beats DEFAULT, which is what pam_env does.
        put(
            "etc/security/pam_env.conf",
            b"# comment\nLANG DEFAULT=C\nLD_PRELOAD DEFAULT=/usr/lib/ok.so OVERRIDE=/tmp/evil.so\nBROKEN\n",
        );
        put("etc/environment.d/99-x.conf", b"LD_AUDIT=/tmp/audit.so\n");

        let root = crate::root::Root::at(&dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Shell)];
        let s = scan::run(&root, &Options { deep: false }, &collectors);

        let conf = s.entries.iter().find(|e| e.name == "pam_env.conf").expect("pam_env.conf");
        assert_eq!(conf.raw["syntax"], "pam_env.conf");
        assert_eq!(conf.raw["env.LD_PRELOAD"], "/tmp/evil.so", "OVERRIDE wins over DEFAULT");
        assert_eq!(conf.raw["env.LANG"], "C");
        assert!(!conf.raw.contains_key("env.BROKEN"), "a line with no value sets nothing");

        let dropin = s.entries.iter().find(|e| e.name == "99-x.conf").expect("environment.d drop-in");
        assert_eq!(dropin.raw["env.LD_AUDIT"], "/tmp/audit.so");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan, Status};
    use std::fs;
    use std::os::unix::fs::symlink;

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("unbidden-shell-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn run(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        crate::scan::run(&root, &Options { deep: false }, &[Box::new(Shell)])
    }

    fn by_name<'a>(s: &'a Scan, kind: Kind, name: &str) -> &'a Entry {
        s.entries
            .iter()
            .find(|e| e.kind == kind && e.name == name)
            .unwrap_or_else(|| panic!("no {kind} entry named {name} in {:?}",
                s.entries.iter().map(|e| (e.kind, e.name.as_str())).collect::<Vec<_>>()))
    }

    #[test]
    fn one_entry_per_file_carrying_what_the_file_does() {
        let dir = tmpdir("normal");
        fs::create_dir_all(dir.join("etc/profile.d")).unwrap();
        fs::create_dir_all(dir.join("home/alice")).unwrap();
        fs::write(
            dir.join("etc/passwd"),
            "root:x:0:0::/root:/bin/bash\n\
             alice:x:1000:1000::/home/alice:/bin/zsh\n\
             ghost:x:1001:1001::/home/ghost:/bin/sh\n",
        )
        .unwrap();
        fs::write(
            dir.join("etc/profile"),
            "export PATH=/usr/bin:/bin\n\
             LD_PRELOAD=/tmp/evil.so\n\
             . /etc/profile.d/lang.sh\n\
             [ -f /tmp/hook ] && . /tmp/hook\n\
             /usr/local/bin/beacon &\n\
             if [ -n \"$X\" ]; then\n\
             \x20 eval \"$(/tmp/x)\"\n\
             fi\n\
             alias ll='ls -l'\n",
        )
        .unwrap();
        fs::write(dir.join("etc/profile.d/lang.sh"), "export LANG=C.UTF-8\n").unwrap();
        fs::write(dir.join("etc/profile.d/java.csh"), "setenv JAVA_HOME /usr/lib/jvm\n").unwrap();
        fs::write(dir.join("home/alice/.bashrc"), "typeset -x TERM=xterm HISTFILE=/dev/null\n").unwrap();

        let scan = run(&dir);
        assert!(matches!(scan.header.collectors[0].status, Status::Complete));

        let p = by_name(&scan, Kind::ShellProfile, "profile");
        assert_eq!(p.trigger, Trigger::Login);
        assert_eq!(p.enabled, Enablement::NotApplicable);
        assert_eq!(p.command, None, "a profile has no single command");
        assert_eq!(p.target_path.as_deref(), Some(dir.join("etc/profile").as_path()));
        assert_eq!(p.principal, None);
        assert_eq!(p.raw["env.LD_PRELOAD"], "/tmp/evil.so");
        assert_eq!(p.raw["env.PATH"], "/usr/bin:/bin");
        assert_eq!(p.raw["sourced"], "/etc/profile.d/lang.sh\n/tmp/hook");
        assert_eq!(p.raw["sourced_count"], "2");
        assert_eq!(p.raw["exec_count"], "2", "beacon and eval, not the alias or the if");
        assert!(p.raw["exec"].contains("/usr/local/bin/beacon &"));
        assert!(p.raw["exec"].contains("eval"));
        assert!(!p.raw["exec"].contains("alias"));

        // §14.4: the LD_PRELOAD above is this collector's data, not a second
        // collector's entry. Correlation belongs to enrichment.
        assert!(
            !scan.entries.iter().any(|e| e.kind == Kind::LdPreload),
            "a profile assignment must not manufacture an ld_preload entry"
        );

        let a = by_name(&scan, Kind::ShellProfile, ".bashrc");
        assert_eq!(a.principal.as_deref(), Some("alice"));
        assert_eq!(a.raw["login_shell"], "/bin/zsh");
        assert_eq!(a.raw["env.TERM"], "xterm");
        assert_eq!(a.raw["env.HISTFILE"], "/dev/null", "zsh typeset -x is an assignment");
        assert!(by_name(&scan, Kind::ShellProfile, "lang.sh").raw.contains_key("env.LANG"));

        // A csh drop-in read as sh would report setenv as an executing line
        // and lose the assignment; /etc/profile.d holds both dialects.
        let csh = by_name(&scan, Kind::ShellProfile, "java.csh");
        assert_eq!(csh.raw["env.JAVA_HOME"], "/usr/lib/jvm");
        assert!(!csh.raw.contains_key("exec"));

        // ghost is in passwd with no home on disk: nothing, and no complaint.
        assert!(!scan.entries.iter().any(|e| e.source.starts_with(dir.join("home/ghost"))));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn etc_environment_is_not_parsed_as_shell() {
        let dir = tmpdir("pamenv");
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(
            dir.join("etc/environment"),
            "# comment\n\
             PATH=\"/usr/bin:/bin\"\n\
             LD_PRELOAD=/tmp/evil.so\n\
             export FOO=bar\n\
             . /tmp/sourced\n\
             /tmp/beacon\n",
        )
        .unwrap();

        let e = &run(&dir).entries[0];
        assert_eq!(e.raw["syntax"], "pam-environment");
        assert_eq!(e.raw["env.PATH"], "/usr/bin:/bin");
        assert_eq!(e.raw["env.LD_PRELOAD"], "/tmp/evil.so");
        assert!(!e.raw.contains_key("env.FOO"), "pam_env has no export keyword");
        assert!(!e.raw.contains_key("sourced"), "pam_env does not source");
        assert!(!e.raw.contains_key("exec"), "pam_env runs nothing");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hostile_files_yield_entries_rather_than_a_panic() {
        let dir = tmpdir("hostile");
        fs::create_dir_all(dir.join("home/alice")).unwrap();
        fs::create_dir_all(dir.join("home/bob")).unwrap();
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(
            dir.join("etc/passwd"),
            "alice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n",
        )
        .unwrap();

        let mut huge = b"export EVIL=".to_vec();
        huge.extend(std::iter::repeat_n(b'A', 10 * 1024 * 1024));
        fs::write(dir.join("home/alice/.bashrc"), &huge).unwrap();

        let mut nasty = b"export LD_PRELOAD=/tmp/\xff\xfe.so\r\n".to_vec();
        nasty.extend_from_slice(b"PS1=\x00\x00broken\r\n");
        nasty.extend_from_slice(b"'unterminated\r\n");
        fs::write(dir.join("home/bob/.zshrc"), &nasty).unwrap();

        let scan = run(&dir);
        // A file past the cap is the cap doing its job. Recording it as a
        // failed read would let any user make every baseline incomparable by
        // growing their own .bashrc.
        let st = &scan.header.collectors[0];
        assert!(matches!(st.status, Status::Complete), "a capped read is not a failed one: {st:?}");
        assert!(st.truncated.iter().any(|u| u.contains(".bashrc") && u.contains("truncated")));

        let a = by_name(&scan, Kind::ShellProfile, ".bashrc");
        assert!(a.raw.contains_key("truncated"));
        assert_eq!(a.raw["env.EVIL"].len(), VALUE_CAP + "…[clipped]".len());

        let b = by_name(&scan, Kind::ShellProfile, ".zshrc");
        assert!(b.has_flag(Flag::EncodingAnomaly), "invalid UTF-8 is evidence");
        assert_eq!(b.raw["line_endings"], "crlf");
        assert_eq!(b.raw["nul_bytes"], "2");
        assert!(b.raw["env.LD_PRELOAD"].starts_with("/tmp/"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_home_or_a_profile_that_is_a_link_is_recorded_as_one() {
        let dir = tmpdir("links");
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::create_dir_all(dir.join("home")).unwrap();
        fs::create_dir_all(dir.join("srv/carol")).unwrap();
        fs::create_dir_all(dir.join("tmp")).unwrap();
        fs::write(dir.join("etc/passwd"), "carol:x:1000:1000::/home/carol:/bin/bash\n").unwrap();
        symlink("../srv/carol", dir.join("home/carol")).unwrap();
        fs::write(dir.join("tmp/payload"), "export LD_PRELOAD=/tmp/x.so\n").unwrap();
        symlink("/tmp/payload", dir.join("srv/carol/.bashrc")).unwrap();
        symlink("/tmp/gone", dir.join("srv/carol/.profile")).unwrap();

        let scan = run(&dir);
        let b = by_name(&scan, Kind::ShellProfile, ".bashrc");
        assert_eq!(b.raw["symlink_target"], "/tmp/payload", "the link is the finding");
        assert_eq!(b.raw["home_symlink_target"], "../srv/carol");
        // The link leaves the home, so it is recorded and not followed. An
        // account that can write this link need not be able to read what it
        // points at; following it would let the report carry the contents of
        // any file on the host.
        assert!(!b.raw.contains_key("env.LD_PRELOAD"), "a link out of the home is not read through");
        assert!(b.raw["not_followed"].contains("leads out of its owner's home"));
        assert!(!b.raw.contains_key("unreadable"), "a refused link is not a failed read");

        let p = by_name(&scan, Kind::ShellProfile, ".profile");
        assert_eq!(p.raw["symlink_target"], "/tmp/gone");
        assert!(p.raw.contains_key("not_regular_file"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ld_so_preload_is_one_entry_per_library() {
        let dir = tmpdir("preload");
        fs::create_dir_all(dir.join("etc/ld.so.conf.d")).unwrap();
        fs::write(
            dir.join("etc/ld.so.preload"),
            "# injected\n/usr/lib/libnss.so\t/tmp/evil.so\n\n/opt/weird/lib.so\n/tmp/evil.so\n",
        )
        .unwrap();
        fs::write(dir.join("etc/ld.so.conf"), "include /etc/ld.so.conf.d/*.conf\n/usr/lib/x86_64-linux-gnu\n").unwrap();
        fs::write(dir.join("etc/ld.so.conf.d/weird.conf"), "/opt/weird/lib/ # trailing\ninclude nested/*.conf\n").unwrap();
        // ldconfig reads only what an include names.
        fs::write(dir.join("etc/ld.so.conf.d/skipped.txt"), "/opt/never\n").unwrap();
        fs::create_dir_all(dir.join("etc/ld.so.conf.d/nested")).unwrap();
        fs::write(dir.join("etc/ld.so.conf.d/nested/a.conf"), "/opt/nested/lib\n").unwrap();

        let scan = run(&dir);
        let pre: Vec<_> = scan.entries.iter().filter(|e| e.kind == Kind::LdPreload).collect();
        assert_eq!(pre.len(), 3, "three distinct libraries, the repeat folded");

        let evil = by_name(&scan, Kind::LdPreload, "/tmp/evil.so");
        assert_eq!(evil.trigger, Trigger::Always);
        assert_eq!(evil.enabled, Enablement::Enabled);
        assert_eq!(evil.target_path.as_deref(), Some(Path::new("/tmp/evil.so")));
        assert_eq!(evil.command.as_deref(), Some(&b"/usr/lib/libnss.so\t/tmp/evil.so"[..]));
        assert_eq!(evil.raw["ld_so_conf.nonstandard"], "/opt/weird/lib\n/opt/nested/lib");
        assert!(by_name(&scan, Kind::LdPreload, "/opt/weird/lib.so").command.is_some());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_profile_linked_out_of_its_home_is_recorded_without_making_the_scan_partial() {
        // Any user can do this to their own home. Were the refusal counted as
        // an unreadable path, the collector would turn Partial and every
        // later --against would refuse to run.
        let dir = tmpdir("escape");
        fs::create_dir_all(dir.join("home/alice")).unwrap();
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("etc/passwd"), "alice:x:1000:1000::/home/alice:/bin/bash\n").unwrap();
        fs::write(dir.join("etc/shadow"), "root:$6$secret:19000::::::\n").unwrap();
        symlink("/etc/shadow", dir.join("home/alice/.bashrc")).unwrap();
        symlink("../../etc/shadow", dir.join("home/alice/.profile")).unwrap();

        let scan = run(&dir);
        let st = &scan.header.collectors[0];
        assert!(matches!(st.status, Status::Complete), "{st:?}");
        assert_eq!(st.truncated.iter().filter(|t| t.contains("not followed")).count(), 2, "{st:?}");

        for name in [".bashrc", ".profile"] {
            let e = by_name(&scan, Kind::ShellProfile, name);
            assert!(e.raw["not_followed"].contains("etc/shadow"), "{:?}", e.raw);
            assert!(e.raw.keys().all(|k| !k.starts_with("env.")), "the target was not read");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_environment_drop_in_reached_through_merged_usr_is_reported_once() {
        let dir = tmpdir("envd");
        fs::create_dir_all(dir.join("usr/lib/environment.d")).unwrap();
        fs::write(dir.join("usr/lib/environment.d/99-environment.conf"), "PATH=/usr/bin\n").unwrap();
        symlink("usr/lib", dir.join("lib")).unwrap();

        let scan = run(&dir);
        let found: Vec<_> = scan.entries.iter().filter(|e| e.name == "99-environment.conf").collect();
        assert_eq!(found.len(), 1, "{:?}", found.iter().map(|e| &e.source).collect::<Vec<_>>());
        assert_eq!(found[0].source, dir.join("usr/lib/environment.d/99-environment.conf"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn environment_drop_ins_in_usr_local_and_the_home_are_read() {
        let dir = tmpdir("envd-more");
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("etc/passwd"), "alice:x:1000:1000::/home/alice:/bin/sh\n").unwrap();
        fs::create_dir_all(dir.join("usr/local/lib/environment.d")).unwrap();
        fs::write(dir.join("usr/local/lib/environment.d/10-local.conf"), "LD_PRELOAD=/opt/a.so\n").unwrap();
        fs::create_dir_all(dir.join("home/alice/.config/environment.d")).unwrap();
        fs::write(dir.join("home/alice/.config/environment.d/20-mine.conf"), "LD_PRELOAD=/opt/b.so\n").unwrap();

        let scan = run(&dir);
        by_name(&scan, Kind::ShellProfile, "10-local.conf");
        let mine = by_name(&scan, Kind::ShellProfile, "20-mine.conf");
        assert_eq!(mine.principal.as_deref(), Some("alice"));
        assert_eq!(mine.raw.get("env.LD_PRELOAD").map(String::as_str), Some("/opt/b.so"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_nonstandard_library_directory_is_an_entry_of_the_file_that_names_it() {
        let dir = tmpdir("libdir");
        fs::create_dir_all(dir.join("etc/ld.so.conf.d")).unwrap();
        fs::write(dir.join("etc/ld.so.conf"), "include /etc/ld.so.conf.d/*.conf\n").unwrap();
        fs::write(dir.join("etc/ld.so.conf.d/x86_64-linux-gnu.conf"), "/usr/lib/x86_64-linux-gnu\n/usr/local/lib\n").unwrap();
        fs::write(dir.join("etc/ld.so.conf.d/zz-evil.conf"), "/var/tmp/.lib\n").unwrap();
        let scan = run(&dir);
        let dirs: Vec<_> = scan.entries.iter().filter(|e| e.kind == Kind::LibraryDir).collect();
        assert_eq!(dirs.len(), 1, "{:?}", dirs.iter().map(|e| &e.name).collect::<Vec<_>>());
        assert_eq!(dirs[0].name, "/var/tmp/.lib");
        assert_eq!(dirs[0].source, dir.join("etc/ld.so.conf.d/zz-evil.conf"));
        assert_eq!(dirs[0].trigger, Trigger::Always);
        fs::remove_dir_all(&dir).unwrap();
    }
}
