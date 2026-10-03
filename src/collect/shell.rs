//! Shell startup files, and the dynamic loader's preload list.
//!
//! One entry per file, never per line. A .bashrc is hundreds of lines and an
//! entry per line is a wall nobody reads; what the file *does* is lifted into
//! `raw` instead — environment assignments, sourced paths, and the lines that
//! run something — because that is what an operator greps and what the
//! enrichment pass of §14.4 correlates.
//!
//! The extraction is a line-oriented scan, not a shell interpreter. Shell
//! cannot be understood without evaluating it (expansion, sourcing and
//! conditionals decide what runs), and evaluating attacker-authored shell is
//! the one thing this tool must never do. The blind spots are listed on
//! `scan_shell` and are deliberate.

use crate::text::unquote;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Flag, Kind, Trigger, name_from_os};
use crate::root::READ_CAP;
use crate::scan::{Collector, Ctx, Read};
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

/// The one system file in the list above that is not shell: pam_env reads it.
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
    /// Another shell's language, reported but not read: sh rules would
    /// misread it.
    Opaque(&'static str),
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
            if cx.first_visit(dir, &mut walked).is_none() {
                continue;
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

        x_session(cx, &mut seen, &mut out);
        plasma_env(cx, &mut seen, &mut out);
        other_shells(cx, &mut seen, &mut out);
        preload(cx, &mut out);
        library_dirs(cx, &mut out);
        out
    }
}

/// The shell an X11 login sources on its way to the desktop. Wayland
/// sessions, the default on every supported distribution but Mint, source
/// none of it, which is noted on each entry.
///
/// Debian family (/etc/X11/Xsession, used by LightDM and by GDM's X
/// sessions): every file in /etc/X11/Xsession.d that `run-parts --list`
/// selects, then ~/.xsessionrc, which one of those sources, then ~/.xsession
/// or ~/.Xsession as the session itself where Xsession.options allows it.
/// Fedora (/etc/X11/xinit/Xsession and xinitrc-common): every file in
/// /etc/X11/xinit/xinitrc.d but a dotfile, and ~/.xsession or ~/.Xclients as
/// the session when executable. And the display managers' own session
/// scripts (GDM, LightDM, SDDM) source /etc/xprofile and ~/.xprofile.
fn x_session(cx: &mut Ctx, seen: &mut BTreeSet<PathBuf>, out: &mut Vec<Entry>) {
    const X11_ONLY: &str = "X11 logins; a Wayland session sources none of it";
    let mut add = |cx: &mut Ctx, rel: &Path, user: Option<&User>, by: &str, off: Option<&str>, out: &mut Vec<Entry>| {
        let at = out.len();
        profile(cx, rel, user, Syntax::Shell, seen, out);
        if let Some(e) = out.get_mut(at) {
            e.note("sourced_by", by);
            e.note("session", X11_ONLY);
            if let Some(why) = off {
                e.enabled = Enablement::Disabled;
                e.note("not_run", why);
            }
        }
    };
    let xsession_d = Path::new("etc/X11/Xsession.d");
    let names: Vec<_> = cx.dir(xsession_d).into_iter().filter(|e| !e.is_dir).map(|e| e.name).collect();
    for name in names {
        let why = super::run_parts_skips(cx, super::RunParts::Debian, xsession_d, name.as_encoded_bytes());
        add(cx, &xsession_d.join(&name), None, "/etc/X11/Xsession", why, out);
    }
    let xinitrc_d = Path::new("etc/X11/xinit/xinitrc.d");
    let names: Vec<_> =
        cx.dir(xinitrc_d).into_iter().filter(|e| !e.is_dir && !e.name.as_encoded_bytes().starts_with(b".")).map(|e| e.name).collect();
    for name in names {
        add(cx, &xinitrc_d.join(&name), None, "/etc/X11/xinit/xinitrc-common", None, out);
    }
    add(cx, Path::new("etc/xprofile"), None, "the display manager's X session script", None, out);

    // Debian runs the user's own session file only with this option set,
    // in Xsession.options or a .conf in Xsession.options.d.
    let mut options = cx.read_capped("etc/X11/Xsession.options", 64 * 1024).unwrap_or_default();
    for e in cx.dir("etc/X11/Xsession.options.d") {
        if e.name.as_encoded_bytes().ends_with(b".conf") {
            options.extend(cx.read_capped(Path::new("etc/X11/Xsession.options.d").join(&e.name), 64 * 1024).unwrap_or_default());
            options.push(b'\n');
        }
    }
    let allow = options.split(|b| *b == b'\n').map(|l| l.trim_ascii()).any(|l| l == b"allow-user-xsession");
    let debian = cx.root.exists("etc/X11/Xsession");
    let users = cx.users;
    for u in users {
        if debian {
            add(cx, &u.in_home(".xsessionrc"), Some(u), "/etc/X11/Xsession.d/40x11-common_xsessionrc", None, out);
        }
        add(cx, &u.in_home(".xprofile"), Some(u), "the display manager's X session script", None, out);
        // The first found becomes the session. Debian's Xsession runs a
        // non-executable one through the shell; Fedora's only an executable.
        let has_xsession = cx.root.exists(u.in_home(".xsession"));
        for f in [".xsession", ".Xsession", ".Xclients"] {
            let rel = u.in_home(f);
            let exec = cx.root.stat_follow(&rel).is_ok_and(|m| m.mode & 0o111 != 0);
            let off = match (debian, f) {
                (true, ".Xclients") => Some("only Fedora's Xsession runs .Xclients"),
                (true, _) if !allow => Some("Xsession.options does not allow-user-xsession"),
                (true, ".Xsession") if has_xsession => Some(".xsession is found first"),
                (true, _) => None,
                (false, ".Xsession") => Some("only the Debian family's Xsession runs .Xsession"),
                (false, _) if !exec => Some("run only when executable"),
                (false, ".Xclients") if has_xsession && cx.root.stat_follow(u.in_home(".xsession")).is_ok_and(|m| m.mode & 0o111 != 0) => {
                    Some(".xsession is found first")
                }
                (false, _) => None,
            };
            add(cx, &rel, Some(u), "the X session, as the session itself", off, out);
        }
    }
}

/// What bash, csh/tcsh, fish and ksh read beyond the profiles above, each
/// only where that shell is installed, as their packages ship them.
///
/// bash: /etc/bash.bash_logout at a login shell's exit; ~/.bash_aliases,
/// which the skeleton ~/.bashrc sources; and with bash-completion, every
/// file in /etc/bash_completion.d but its backup names and Makefiles, and
/// ~/.bash_completion and ~/.config/bash_completion, in every interactive
/// shell. csh and tcsh (Debian's tcsh): /etc/csh.cshrc, /etc/csh.login,
/// /etc/csh.logout, every file in /etc/csh/cshrc.d and /etc/csh/login.d,
/// and ~/.tcshrc, ~/.cshrc, ~/.login and ~/.logout. fish (3.7): config.fish
/// in /etc/fish and ~/.config/fish, and `*.fish` in the conf.d directories,
/// the user's, then /etc's, then the vendor ones, the first of a name
/// winning. ksh93: ~/.kshrc, its default $ENV.
fn other_shells(cx: &mut Ctx, seen: &mut BTreeSet<PathBuf>, out: &mut Vec<Entry>) {
    let installed = |cx: &mut Ctx, names: &[&str]| {
        names.iter().any(|n| ["bin", "usr/bin"].iter().any(|d| cx.root.exists(Path::new(d).join(n))))
    };
    let mut files: Vec<(PathBuf, Option<&User>, Syntax, &str)> = Vec::new();
    let users = cx.users;
    let sorted = |cx: &mut Ctx, dir: &Path, keep: &dyn Fn(&[u8]) -> bool| -> Vec<PathBuf> {
        let names: Vec<_> = cx.dir(dir).into_iter().filter(|e| !e.is_dir && keep(e.name.as_encoded_bytes())).map(|e| e.name).collect();
        names.into_iter().map(|n| dir.join(n)).collect()
    };

    files.push((PathBuf::from("etc/bash.bash_logout"), None, Syntax::Shell, "bash, at a login shell's exit"));
    for u in users {
        files.push((u.in_home(".bash_aliases"), Some(u), Syntax::Shell, "the skeleton ~/.bashrc"));
    }
    if cx.root.exists("usr/share/bash-completion/bash_completion") {
        // bash-completion's _backup_glob, and its Makefile* exclusion.
        let keep = |n: &[u8]| {
            let backup = (n.starts_with(b"#") && n.ends_with(b"#"))
                || n.ends_with(b"~")
                || [b".bak".as_slice(), b".orig", b".rej", b".swp", b".rpmorig", b".rpmnew", b".rpmsave"].iter().any(|s| n.ends_with(s))
                || n.windows(5).any(|w| w == b".dpkg");
            !backup && !n.starts_with(b"Makefile")
        };
        for f in sorted(cx, Path::new("etc/bash_completion.d"), &keep) {
            files.push((f, None, Syntax::Shell, "bash-completion, in every interactive bash"));
        }
        for u in users {
            for f in [".bash_completion", ".config/bash_completion"] {
                files.push((u.in_home(f), Some(u), Syntax::Shell, "bash-completion, in every interactive bash"));
            }
        }
    }
    if installed(cx, &["csh", "tcsh", "bsd-csh"]) {
        for f in ["etc/csh.cshrc", "etc/csh.login", "etc/csh.logout"] {
            files.push((PathBuf::from(f), None, Syntax::Opaque("csh"), "csh and tcsh"));
        }
        for dir in ["etc/csh/cshrc.d", "etc/csh/login.d"] {
            for f in sorted(cx, Path::new(dir), &|n: &[u8]| !n.starts_with(b".")) {
                files.push((f, None, Syntax::Opaque("csh"), "/etc/csh.cshrc or /etc/csh.login"));
            }
        }
        for u in users {
            for f in [".tcshrc", ".cshrc", ".login", ".logout"] {
                files.push((u.in_home(f), Some(u), Syntax::Opaque("csh"), "csh and tcsh"));
            }
        }
    }
    if installed(cx, &["fish"]) {
        let fish = |n: &[u8]| n.ends_with(b".fish");
        files.push((PathBuf::from("etc/fish/config.fish"), None, Syntax::Opaque("fish"), "fish, at every start"));
        // The system snippets, reported once; the first of a name wins. A
        // user's own snippet of the same name replaces it for that user.
        let mut taken: BTreeSet<Vec<u8>> = BTreeSet::new();
        for d in ["etc/fish/conf.d", "usr/local/share/fish/vendor_conf.d", "usr/share/fish/vendor_conf.d"] {
            for f in sorted(cx, Path::new(d), &fish) {
                let name = f.file_name().map(|n| n.as_encoded_bytes().to_vec()).unwrap_or_default();
                let by = if taken.insert(name) { "fish, at every start" } else { "fish, but replaced by a same-named snippet earlier in its order" };
                files.push((f, None, Syntax::Opaque("fish"), by));
            }
        }
        for u in users {
            files.push((u.in_home(".config/fish/config.fish"), Some(u), Syntax::Opaque("fish"), "fish, at every start"));
            for d in [".config/fish/conf.d", ".local/share/fish/vendor_conf.d"] {
                for f in sorted(cx, &u.in_home(d), &fish) {
                    files.push((f, Some(u), Syntax::Opaque("fish"), "fish, at every start"));
                }
            }
        }
    }
    if installed(cx, &["ksh", "ksh93"]) {
        for u in users {
            files.push((u.in_home(".kshrc"), Some(u), Syntax::Opaque("ksh"), "ksh93, as its default $ENV"));
        }
    }

    for (rel, user, syntax, by) in files {
        let at = out.len();
        profile(cx, &rel, user, syntax, seen, out);
        if let Some(e) = out.get_mut(at) {
            e.note("sourced_by", by);
            if by.contains("replaced by") {
                e.enabled = Enablement::Disabled;
            }
        }
    }
}

/// Plasma (5.27 and 6, startplasma.cpp) sources every config location's
/// plasma-workspace/env/*.sh at the start of each session, X11 or Wayland:
/// /etc/xdg's first, the user's last, each directory in name order.
fn plasma_env(cx: &mut Ctx, seen: &mut BTreeSet<PathBuf>, out: &mut Vec<Entry>) {
    let mut dirs: Vec<(PathBuf, Option<&User>)> = vec![(PathBuf::from("etc/xdg/plasma-workspace/env"), None)];
    let users = cx.users;
    dirs.extend(users.iter().map(|u| (u.in_home(".config/plasma-workspace/env"), Some(u))));
    for (dir, user) in dirs {
        let names: Vec<_> =
            cx.dir(&dir).into_iter().filter(|e| !e.is_dir && e.name.as_encoded_bytes().ends_with(b".sh")).map(|e| e.name).collect();
        for n in names {
            let at = out.len();
            profile(cx, &dir.join(n), user, Syntax::Shell, seen, out);
            if let Some(e) = out.get_mut(at) {
                e.note("sourced_by", "startplasma, at every Plasma login");
            }
        }
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

    // A profile that is not a regular file, a dangling link, or a link out
    // of its owner's home (`~/.bashrc -> /etc/shadow`) is reported as what it
    // is and not read. Which of them it is, is the root's answer to the one
    // read. The scan records the first and the last as limits, never a
    // failure, since any user could otherwise use them to make every baseline
    // incomparable; a dangling link is simply absent.
    let outcome = cx.read_outcome(rel, READ_CAP);
    cx.record(rel, READ_CAP, &outcome);
    let bytes = match outcome {
        Read::Bytes { bytes, truncated } => {
            if truncated {
                e.note("truncated", format!("read capped at {READ_CAP} bytes"));
            }
            bytes
        }
        Read::NotRegular | Read::Absent => {
            e.note("not_regular_file", if meta.is_symlink { "link resolves to nothing readable" } else { "not a regular file" });
            out.push(e);
            return;
        }
        Read::NotFollowed(target) => {
            e.note("not_followed", format!("leads out of its owner's home to {}", target.display()));
            out.push(e);
            return;
        }
        Read::Failed(err) => {
            e.note("unreadable", err.to_string());
            out.push(e);
            return;
        }
    };
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
        Syntax::Opaque(shell) => e.note("syntax", shell),
    }

    apply(&mut e, match syntax {
        Syntax::Shell => scan_shell(&bytes),
        Syntax::KeyValue => scan_pam_env(&bytes),
        Syntax::PamEnvConf => scan_pam_env_conf(&bytes),
        Syntax::Opaque(_) => Scanned::default(),
    });
    out.push(e);
}

/// A real ld.so.preload names a few libraries. Far past this is not one.
const PRELOAD_CAP: usize = 4 << 20;

/// `/etc/ld.so.preload`: the mechanism static linking exists to defend against
/// (§3). One entry per library, because each named object is its own payload.
fn preload(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let rel = Path::new("etc/ld.so.preload");
    let Ok(meta) = cx.root.stat(rel) else { return };
    if !meta.is_file && !(meta.is_symlink && cx.root.stat_follow(rel).map(|m| m.is_file).unwrap_or(false)) {
        return;
    }
    let Ok((bytes, truncated)) = cx.root.read_capped(rel, PRELOAD_CAP) else {
        cx.note_unreadable(format!("{} unreadable", cx.root.abs(rel).display()));
        return;
    };
    if truncated {
        cx.note_limited(format!("{} (truncated at {PRELOAD_CAP} bytes)", cx.root.abs(rel).display()));
    }

    let libs = preload_names(&bytes);
    let ignored = musl_only(cx);
    // glibc reads the whole file, so one longer than the cap hides what lies
    // past it behind blanks. A file that size is a finding of its own.
    if truncated {
        let mut e = cx.entry(Kind::LdPreload, rel, format!("(names past {PRELOAD_CAP} bytes)"));
        e.trigger = Trigger::Always;
        e.enabled = if ignored { Enablement::Disabled } else { Enablement::Enabled };
        e.note("not_read_whole", format!("longer than {PRELOAD_CAP} bytes; glibc loads every name in it"));
        out.push(e);
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
        // glibc loads a library listed here into every dynamically linked
        // process on the system.
        e.enabled = Enablement::Enabled;
        if ignored {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "musl's loader does not read /etc/ld.so.preload");
        }
        if !nonstandard.is_empty() {
            e.note("ld_so_conf.nonstandard", nonstandard.join("\n"));
        }
        out.push(e);
    }
}

/// The libraries `/etc/ld.so.preload` names, each with the line that named it,
/// as glibc's loader reads the file. Names are separated by blanks, tabs,
/// colons and newlines and by nothing else, so a carriage return or a form
/// feed is part of a name, and a NUL ends what is read.
///
/// Comments are a port of the loader's own blanking pass, faults included:
/// the search for the next `#` restarts at the top of the file with the
/// length left over from the last comment, so a comment past the first one
/// often survives and its words are loaded as names (a `#` alone, a word
/// after it). The port is checked against glibc 2.41 on random files; the
/// vectors in the test below were measured there.
fn preload_names(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut buf = bytes.to_vec();
    let mut rest = buf.len();
    while rest > 0 {
        let Some(found) = buf[..rest].iter().position(|b| *b == b'#') else { break };
        rest -= found;
        let mut at = found;
        loop {
            buf[at] = b' ';
            rest -= 1;
            if rest == 0 {
                break;
            }
            at += 1;
            if buf[at] == b'\n' {
                break;
            }
        }
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    let mut libs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut listed = BTreeSet::new();
    let mut start = 0;
    while start <= end {
        let stop = buf[start..end].iter().position(|b| matches!(b, b' ' | b'\t' | b':' | b'\n')).map_or(end, |n| start + n);
        let name = &buf[start..stop];
        if !name.is_empty() && listed.insert(name.to_vec()) {
            let from = bytes[..start].iter().rposition(|b| *b == b'\n').map_or(0, |n| n + 1);
            let to = bytes[start..].iter().position(|b| *b == b'\n').map_or(bytes.len(), |n| start + n);
            libs.push((name.to_vec(), bytes[from..to].to_vec()));
        }
        start = stop + 1;
    }
    libs
}

/// Whether the loader on this host is musl's alone. musl reads `LD_PRELOAD`
/// and nothing else: `/etc/ld.so.preload` does nothing on Alpine (measured on
/// 3.22 and 3.24), so a host with musl's loader and none of glibc's is one
/// where the file is a leftover or a plant and not a mechanism.
fn musl_only(cx: &mut Ctx) -> bool {
    let named = |cx: &mut Ctx, prefix: &str| {
        ["lib", "lib64", "usr/lib", "usr/lib64"].iter().any(|d| cx.dir(d).iter().any(|e| e.name.to_string_lossy().starts_with(prefix)))
    };
    // glibc's loader is ld-linux* on most architectures and ld64.so.* on
    // ppc64 and s390x.
    named(cx, "ld-musl-") && !named(cx, "ld-linux") && !named(cx, "ld64.so")
}

/// Search directories configured outside the set every distribution already
/// has, as a note on each ld.so.preload entry: a preloaded library is looked
/// for there too. `library_dirs` reports each directory as an entry of its own.
fn nonstandard_lib_dirs(cx: &mut Ctx) -> Vec<String> {
    super::ld_so_conf_dirs(cx).into_iter().map(|(d, _)| d).filter(|d| !is_standard_lib_dir(d)).collect()
}

/// A directory ld.so.conf adds to the loader's search outside the set every
/// distribution already has. Every dynamically linked program looks there,
/// so a library dropped into it under a common soname is loaded in place of
/// the real one. The file that names it is the source; a vendor's packaged
/// drop-in is hidden like any other packaged file.
fn library_dirs(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let mut dirs = super::ld_so_conf_dirs(cx);
    dirs.extend(musl_path_dirs(cx));
    for (dir, rel) in dirs {
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

/// The directories musl's loader searches, from `/etc/ld-musl-<arch>.path`,
/// each with the file that names it. A present file replaces the default
/// search path outright, so a directory listed first decides which library
/// answers a soname. Measured on Alpine 3.24: entries are separated by
/// newlines and colons and by nothing else, so a blank or a carriage return
/// belongs to the name, and there is no comment syntax.
fn musl_path_dirs(cx: &mut Ctx) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for ent in cx.dir("etc") {
        let name = ent.name.to_string_lossy().into_owned();
        if ent.is_dir || !name.starts_with("ld-musl-") || !name.ends_with(".path") {
            continue;
        }
        let rel = Path::new("etc").join(&name);
        let Some(bytes) = cx.read_capped(&rel, 64 * 1024) else { continue };
        for dir in bytes.split(|b| matches!(b, b'\n' | b':')).filter(|d| !d.is_empty()) {
            out.push((String::from_utf8_lossy(dir).into_owned(), rel.clone()));
        }
    }
    out
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

/// `/etc/security/pam_env.conf` is read by pam_env, not by a shell: lines of
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

/// `/etc/environment` is read by pam_env, not by a shell: plain `KEY=value`
/// lines, no `export`, no expansion, no commands. Parsing it as shell would
/// invent findings that cannot happen.
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
        let dir = crate::testing::Tree::new("pamenv");
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

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan, Status};
    use std::fs;
    use std::os::unix::fs::symlink;

    fn tmpdir(tag: &str) -> crate::testing::Tree {
        crate::testing::Tree::new(&format!("shell-{tag}"))
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
        assert!(st.truncated.iter().any(|u| u.contains(".bashrc") && u.contains("read to")));

        let a = by_name(&scan, Kind::ShellProfile, ".bashrc");
        assert!(a.raw.contains_key("truncated"));
        assert_eq!(a.raw["env.EVIL"].len(), VALUE_CAP + "…[clipped]".len());

        let b = by_name(&scan, Kind::ShellProfile, ".zshrc");
        assert!(b.has_flag(Flag::EncodingAnomaly), "invalid UTF-8 is evidence");
        assert_eq!(b.raw["line_endings"], "crlf");
        assert_eq!(b.raw["nul_bytes"], "2");
        assert!(b.raw["env.LD_PRELOAD"].starts_with("/tmp/"));
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
    }

    #[test]
    fn preload_names_are_read_the_way_glibc_reads_them() {
        // Each row was measured on glibc 2.41: the file, then the names the
        // loader tried, in order.
        let vectors: [(&[u8], &[&[u8]]); 9] = [
            (b"/e#f::x\n/e#f/d/b", &[b"/e", b"/e#f/d/b"]),
            (b"/a\n\n # /e#f/e#f/a\n#", &[b"/a", b"#"]),
            (b"#\n#/e#f/d # /b /a", &[b"a"]),
            (b"\t/a\nx/d\n\n#/a\t/d/e#f", &[b"/a", b"x/d"]),
            (b"#/b\n# \n#\n#\t\n\tx/d#", &[b"#", b"x/d#"]),
            (b"/c \t\n#/e#fx\n# /b:x", &[b"/c", b"#", b"/b", b"x"]),
            (b"/A.so # c1\n/B.so # c2\n/C.so # c3\n", &[b"#", b"/A.so", b"/B.so", b"/C.so", b"c3"]),
            (b"/a.so\r\n/b.so\n", &[b"/a.so\r", b"/b.so"]),
            (b"/a.so\0/never.so\n", &[b"/a.so"]),
        ];
        for (file, want) in vectors {
            let mut got: Vec<Vec<u8>> = preload_names(file).into_iter().map(|(n, _)| n).collect();
            let mut want: Vec<Vec<u8>> = want.iter().map(|w| w.to_vec()).collect();
            // The loader prints each name once per process and the order it
            // tried them in is not what was recorded for the rows above.
            got.sort();
            want.sort();
            assert_eq!(got, want, "{:?}", String::from_utf8_lossy(file));
        }
    }

    #[test]
    fn musl_search_path_file_names_directories_by_its_own_rules() {
        let dir = tmpdir("musl-path");
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("etc/ld-musl-x86_64.path"), "/opt/x:/lib\n#/hash\n/usr/lib\n").unwrap();
        let scan = run(&dir);
        let names: Vec<_> = scan.entries.iter().filter(|e| e.kind == Kind::LibraryDir).map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["#/hash", "/opt/x"], "colon and newline separate, nothing comments, /lib and /usr/lib are standard");
    }

    #[test]
    fn ld_so_conf_files_that_include_the_same_glob_are_read_once() {
        let dir = tmpdir("ldconf-fan");
        fs::create_dir_all(dir.join("etc/ld.so.conf.d")).unwrap();
        fs::write(dir.join("etc/ld.so.conf"), "include /etc/ld.so.conf.d/*.conf\n").unwrap();
        for k in 0..12 {
            fs::write(dir.join(format!("etc/ld.so.conf.d/f{k}.conf")), format!("include /etc/ld.so.conf.d/*.conf\n/opt/l{k}\n")).unwrap();
        }
        let started = std::time::Instant::now();
        let scan = run(&dir);
        assert!(started.elapsed().as_secs() < 5, "the include fan-out is bounded");
        assert_eq!(scan.entries.iter().filter(|e| e.kind == Kind::LibraryDir).count(), 12);
    }

    #[test]
    fn ld_so_conf_directories_are_capped_and_quick() {
        let dir = tmpdir("ldconf-flood");
        fs::create_dir_all(dir.join("etc")).unwrap();
        let body: String = (0..9000).map(|n| format!("/opt/d{n}\n")).collect();
        fs::write(dir.join("etc/ld.so.conf"), body).unwrap();
        let started = std::time::Instant::now();
        let scan = run(&dir);
        assert!(started.elapsed().as_secs() < 5);
        assert_eq!(scan.entries.iter().filter(|e| e.kind == Kind::LibraryDir).count(), 4096);
    }

    #[test]
    fn a_preload_file_past_the_cap_is_reported_not_silently_cut() {
        let dir = tmpdir("preload-long");
        fs::create_dir_all(dir.join("etc")).unwrap();
        let mut body = vec![b' '; PRELOAD_CAP + 10];
        body.extend_from_slice(b"\n/tmp/evil.so\n");
        fs::write(dir.join("etc/ld.so.preload"), body).unwrap();
        let scan = run(&dir);
        let cut = scan.entries.iter().find(|e| e.kind == Kind::LdPreload).expect("an entry for the unread tail");
        assert!(cut.raw.contains_key("not_read_whole"));
        assert_eq!(cut.enabled, Enablement::Enabled);
    }

    #[test]
    fn preload_is_a_leftover_where_only_musl_is_the_loader() {
        let dir = tmpdir("preload-musl");
        fs::create_dir_all(dir.join("lib")).unwrap();
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("lib/ld-musl-x86_64.so.1"), "").unwrap();
        fs::write(dir.join("etc/ld.so.preload"), "/tmp/evil.so\n").unwrap();
        let scan = run(&dir);
        let evil = by_name(&scan, Kind::LdPreload, "/tmp/evil.so");
        assert_eq!(evil.enabled, Enablement::Disabled);
        assert!(evil.raw["not_run"].contains("musl"));
        // A host that carries glibc's loader as well reads the file.
        fs::create_dir_all(dir.join("lib64")).unwrap();
        fs::write(dir.join("lib64/ld-linux-x86-64.so.2"), "").unwrap();
        let scan = run(&dir);
        assert_eq!(by_name(&scan, Kind::LdPreload, "/tmp/evil.so").enabled, Enablement::Enabled);
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
    }

    #[test]
    fn a_service_account_home_outside_home_confines_links_too() {
        // /srv/alice and /var/lib/svc are homes as much as /home/alice is.
        let dir = tmpdir("escape-srv");
        for home in ["srv/alice", "var/lib/svc"] {
            fs::create_dir_all(dir.join(home)).unwrap();
            symlink("/etc/shadow", dir.join(home).join(".bashrc")).unwrap();
        }
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("etc/passwd"), "alice:x:1000:1000::/srv/alice:/bin/bash\nsvc:x:998:998::/var/lib/svc:/bin/sh\n").unwrap();
        fs::write(dir.join("etc/shadow"), "root:$6$secret:19000::::::\nexport LEAK=1\n").unwrap();
        let scan = run(&dir);
        let bashrc: Vec<_> = scan.entries.iter().filter(|e| e.name == ".bashrc").collect();
        assert_eq!(bashrc.len(), 2);
        for e in bashrc {
            assert!(e.raw.contains_key("not_followed"), "{:?}", e.raw);
            assert!(e.raw.keys().all(|k| !k.starts_with("env.") && k != "exec"), "the target was not read: {:?}", e.raw);
        }
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
    }

    #[test]
    fn an_x11_login_sources_its_session_files_by_each_distributions_rules() {
        use std::os::unix::fs::PermissionsExt;
        let put = |dir: &Path, rel: &str, body: &[u8]| {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        let state = |s: &Scan, rel: &str, dir: &Path| {
            s.entries.iter().find(|e| e.source == dir.join(rel)).map(|e| e.enabled).unwrap_or_else(|| panic!("no {rel}"))
        };

        // Debian family.
        let d = tmpdir("xsession-deb");
        put(&d, "etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/bash\n");
        put(&d, "etc/X11/Xsession", b"#!/bin/sh\n");
        put(&d, "etc/X11/Xsession.options", b"# allow-user-xsession\nuse-ssh-agent\n");
        put(&d, "etc/X11/Xsession.d/40x11-common_xsessionrc", b". \"$USERXSESSIONRC\"\n");
        put(&d, "etc/X11/Xsession.d/99evil.sh", b"/tmp/x &\n");
        put(&d, "etc/xprofile", b"export LD_PRELOAD=/tmp/p.so\n");
        put(&d, "home/alice/.xsessionrc", b"/home/alice/.b &\n");
        put(&d, "home/alice/.xsession", b"exec cinnamon-session\n");
        put(&d, "home/alice/.Xclients", b"exec twm\n");
        let s = run(&d);
        assert_eq!(state(&s, "etc/X11/Xsession.d/40x11-common_xsessionrc", &d), Enablement::NotApplicable);
        assert_eq!(state(&s, "etc/X11/Xsession.d/99evil.sh", &d), Enablement::Disabled, "run-parts --list skips a dotted name");
        assert_eq!(state(&s, "home/alice/.xsessionrc", &d), Enablement::NotApplicable);
        assert_eq!(state(&s, "home/alice/.xsession", &d), Enablement::Disabled, "allow-user-xsession is commented out");
        assert_eq!(state(&s, "home/alice/.Xclients", &d), Enablement::Disabled);
        let xprofile = s.entries.iter().find(|e| e.source == d.join("etc/xprofile")).unwrap();
        assert_eq!(xprofile.raw["env.LD_PRELOAD"], "/tmp/p.so");
        assert!(xprofile.raw["session"].contains("Wayland"));
        put(&d, "etc/X11/Xsession.options.d/local.conf", b"allow-user-xsession\n");
        assert_eq!(state(&run(&d), "home/alice/.xsession", &d), Enablement::NotApplicable);

        // Fedora.
        let d = tmpdir("xsession-fed");
        put(&d, "etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/bash\n");
        put(&d, "etc/X11/xinit/xinitrc.d/50-hook.sh", b"/tmp/y &\n");
        put(&d, "etc/X11/xinit/xinitrc.d/.hidden", b"/tmp/z &\n");
        put(&d, "home/alice/.xsession", b"exec twm\n");
        put(&d, "home/alice/.Xclients", b"exec twm\n");
        std::fs::set_permissions(d.join("home/alice/.Xclients"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let s = run(&d);
        assert_eq!(state(&s, "etc/X11/xinit/xinitrc.d/50-hook.sh", &d), Enablement::NotApplicable);
        assert!(!s.entries.iter().any(|e| e.source == d.join("etc/X11/xinit/xinitrc.d/.hidden")));
        assert_eq!(state(&s, "home/alice/.xsession", &d), Enablement::Disabled, "not executable");
        assert_eq!(state(&s, "home/alice/.Xclients", &d), Enablement::NotApplicable, "the executable one is used");
    }

    #[test]
    fn plasma_sources_its_env_scripts_at_every_login() {
        let d = tmpdir("plasma-env");
        let put = |rel: &str, body: &[u8]| {
            let p = d.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        };
        put("etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/bash\n");
        put("home/alice/.config/plasma-workspace/env/agent.sh", b"export LD_PRELOAD=/home/alice/.x.so\n");
        put("home/alice/.config/plasma-workspace/env/notes.txt", b"export NOT=1\n");
        put("etc/xdg/plasma-workspace/env/sys.sh", b"export A=1\n");
        let s = run(&d);
        let env: Vec<&Entry> = s.entries.iter().filter(|e| e.raw.get("sourced_by").is_some_and(|b| b.starts_with("startplasma"))).collect();
        assert_eq!(env.len(), 2, "only *.sh is sourced");
        let agent = env.iter().find(|e| e.principal.as_deref() == Some("alice")).unwrap();
        assert_eq!(agent.raw["env.LD_PRELOAD"], "/home/alice/.x.so");
    }

    #[test]
    fn other_shells_are_read_only_where_installed_and_never_as_sh() {
        let d = tmpdir("other-shells");
        let put = |rel: &str, body: &[u8]| {
            let p = d.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        };
        put("etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/bash\n");
        put("etc/csh.cshrc", b"setenv LD_PRELOAD /tmp/c.so\n");
        put("home/alice/.config/fish/conf.d/x.fish", b"set -gx LD_PRELOAD /tmp/f.so\n");
        put("home/alice/.bash_aliases", b"export LD_PRELOAD=/tmp/a.so\n");
        put("usr/share/bash-completion/bash_completion", b"");
        put("etc/bash_completion.d/tool", b"complete -F _t tool\n");
        put("etc/bash_completion.d/tool.dpkg-old", b"");
        put("etc/bash_completion.d/Makefile.am", b"");
        let has = |s: &Scan, rel: &str| s.entries.iter().any(|e| e.source == d.join(rel));
        let s = run(&d);
        assert!(!has(&s, "etc/csh.cshrc") && !has(&s, "home/alice/.config/fish/conf.d/x.fish"), "neither shell is installed");
        assert!(has(&s, "home/alice/.bash_aliases") && has(&s, "etc/bash_completion.d/tool"));
        assert!(!has(&s, "etc/bash_completion.d/tool.dpkg-old") && !has(&s, "etc/bash_completion.d/Makefile.am"));

        put("bin/tcsh", b"");
        put("usr/bin/fish", b"");
        put("etc/fish/conf.d/a.fish", b"");
        put("usr/share/fish/vendor_conf.d/a.fish", b"");
        let s = run(&d);
        let csh = s.entries.iter().find(|e| e.source == d.join("etc/csh.cshrc")).unwrap();
        assert_eq!(csh.raw["syntax"], "csh");
        assert!(!csh.raw.contains_key("env.LD_PRELOAD"), "csh is not read by sh rules");
        assert!(has(&s, "home/alice/.config/fish/conf.d/x.fish"));
        let vendor = s.entries.iter().find(|e| e.source == d.join("usr/share/fish/vendor_conf.d/a.fish")).unwrap();
        assert_eq!(vendor.enabled, Enablement::Disabled, "/etc's a.fish comes first");
    }
}
