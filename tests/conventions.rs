//! The conventions §3 and §11 state as rules, enforced rather than trusted.
//!
//! §11 asks for this directly — "a lint or a #[deny]-style convention should
//! enforce this, because one collector reaching for an absolute path silently
//! breaks offline mode for everyone". The same applies to shelling out: it is
//! the one thing the threat model forbids outright, and it is one careless
//! line away at all times.
//!
//! A line that genuinely must break a rule says so with a trailing
//! `// convention-exempt: <reason>`, which keeps the exceptions countable and
//! makes adding one a deliberate act.

use std::path::{Path, PathBuf};

const EXEMPT: &str = "convention-exempt:";

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// One line of production code: its text with every literal's contents
/// blanked, so a rule about code cannot fire on prose, and the literals
/// themselves, for the rules that are about them.
struct Line {
    n: usize,
    code: String,
    literals: Vec<String>,
}

/// A small lexer: enough of Rust to know what is a comment, what is a string
/// or char literal, and where each `#[cfg(test)]` item ends.
///
/// The first version stopped reading a file at its first `#[cfg(test)]`, so
/// production code placed after a test module — root.rs has some, render.rs
/// has more — was never checked at all.
fn production_lines(path: &Path) -> Vec<Line> {
    let text = std::fs::read_to_string(path).unwrap();
    let chars: Vec<char> = text.chars().collect();
    let mut lines: Vec<Line> = vec![Line { n: 1, code: String::new(), literals: Vec::new() }];
    let mut i = 0;
    let mut depth = 0usize;
    // Depth at which a #[cfg(test)] item opened, while inside one.
    let mut test_item: Option<usize> = None;
    let mut test_pending = false;

    let push_code = |lines: &mut Vec<Line>, c: char| {
        if c == '\n' {
            let n = lines.last().unwrap().n + 1;
            lines.push(Line { n, code: String::new(), literals: Vec::new() });
        } else {
            lines.last_mut().unwrap().code.push(c);
        }
    };

    while i < chars.len() {
        let c = chars[i];
        let rest: String = chars[i..chars.len().min(i + 12)].iter().collect();

        if rest.starts_with("//") {
            while i < chars.len() && chars[i] != '\n' {
                lines.last_mut().unwrap().code.push(chars[i]);
                i += 1;
            }
            continue;
        }
        if rest.starts_with("/*") {
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                push_code(&mut lines, if chars[i] == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            i += 2;
            continue;
        }
        if rest.starts_with("#[cfg(test)]") {
            test_pending = true;
        }

        // A string literal: plain, byte, raw or raw byte.
        let prev_ident = i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
        let raw = !prev_ident && (rest.starts_with("r\"") || rest.starts_with("r#") || rest.starts_with("br\"") || rest.starts_with("br#"));
        let plain = c == '"' || (!prev_ident && rest.starts_with("b\""));
        if raw || plain {
            let mut j = i;
            while chars[j] != '"' && chars[j] != '#' {
                j += 1;
            }
            let hashes = if raw { chars[j..].iter().take_while(|c| **c == '#').count() } else { 0 };
            j += hashes + 1;
            let mut literal = String::new();
            let mut newlines = 0;
            loop {
                if j >= chars.len() {
                    break;
                }
                if raw {
                    if chars[j] == '"' && chars[j + 1..].iter().take(hashes).filter(|c| **c == '#').count() == hashes {
                        j += 1 + hashes;
                        break;
                    }
                } else if chars[j] == '\\' && chars.get(j + 1) == Some(&'\n') {
                    // A continuation: Rust drops the newline and the
                    // indentation after it, and so does this.
                    newlines += 1;
                    j += 2;
                    while j < chars.len() && chars[j].is_whitespace() {
                        if chars[j] == '\n' {
                            newlines += 1;
                        }
                        j += 1;
                    }
                    continue;
                } else if chars[j] == '\\' {
                    literal.push(chars[j]);
                    literal.push(*chars.get(j + 1).unwrap_or(&' '));
                    j += 2;
                    continue;
                } else if chars[j] == '"' {
                    j += 1;
                    break;
                }
                if chars[j] == '\n' {
                    newlines += 1;
                }
                literal.push(chars[j]);
                j += 1;
            }
            lines.last_mut().unwrap().code.push_str("\"\"");
            lines.last_mut().unwrap().literals.push(literal);
            for _ in 0..newlines {
                push_code(&mut lines, '\n');
            }
            i = j;
            continue;
        }
        // A char literal, as opposed to a lifetime.
        if c == '\'' {
            let close = if chars.get(i + 1) == Some(&'\\') {
                chars[i + 2..].iter().position(|c| *c == '\'').map(|p| i + 2 + p)
            } else if chars.get(i + 2) == Some(&'\'') {
                Some(i + 2)
            } else {
                None
            };
            if let Some(end) = close {
                lines.last_mut().unwrap().code.push_str("' '");
                i = end + 1;
                continue;
            }
        }

        match c {
            '{' => {
                if test_pending && test_item.is_none() {
                    test_item = Some(depth);
                    test_pending = false;
                }
                depth += 1;
            }
            '}' => {
                depth = depth.saturating_sub(1);
                if test_item == Some(depth) {
                    test_item = None;
                    // The closing brace of the test item is part of it.
                    lines.last_mut().unwrap().code.push_str("#TEST#");
                }
            }
            // `#[cfg(test)] use x;` is an item with no body.
            ';' if test_pending && test_item.is_none() => test_pending = false,
            _ => {}
        }
        if test_item.is_some() || test_pending {
            lines.last_mut().unwrap().code.push_str("#TEST#");
        }
        push_code(&mut lines, c);
        i += 1;
    }

    lines
        .into_iter()
        .filter(|l| !l.code.contains("#TEST#") && !l.code.contains(EXEMPT))
        .map(|mut l| {
            l.code = l.code.split("//").next().unwrap_or("").to_string();
            l
        })
        .filter(|l| !l.code.trim().is_empty())
        .collect()
}

fn all_sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    files.sort();
    assert!(files.len() > 15, "found almost no source files; the walk is wrong");
    files
}

fn relative(file: &Path) -> String {
    file.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap_or(file).display().to_string()
}

#[test]
fn the_lexer_skips_test_items_and_nothing_else() {
    let dir = std::env::temp_dir().join(format!("unbidden-conventions-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("sample.rs");
    std::fs::write(
        &file,
        concat!(
            "fn before() { let s = \"} not a brace\"; }\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    fn t() { let j = r#\"{\"a\": {}}\"#; Command::new(\"x\"); }\n",
            "}\n",
            "#[cfg(test)]\n",
            "use std::fs;\n",
            "fn after() { std::fs::read(\"/etc/x\"); let c = '{'; }\n",
            "fn joined() { let m = \"one, \\\n    two\"; }\n",
            "fn last() {}\n",
        ),
    )
    .unwrap();
    let lines = production_lines(&file);
    let text: Vec<&str> = lines.iter().map(|l| l.code.as_str()).collect();
    assert!(text.iter().any(|l| l.contains("fn before")));
    assert!(text.iter().any(|l| l.contains("std::fs::read")), "code after a test module is still read: {text:?}");
    assert!(!text.iter().any(|l| l.contains("Command::new")), "the test module is skipped: {text:?}");
    assert!(!text.iter().any(|l| l.contains("use std::fs")), "and so is a bodiless test item: {text:?}");
    let joined = lines.iter().find(|l| l.code.contains("fn joined")).unwrap();
    assert_eq!(joined.literals, vec!["one, two".to_string()], "a continuation is joined as Rust joins it");
    assert_eq!(lines.iter().find(|l| l.code.contains("fn last")).unwrap().n, 11, "and still counts its line");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn nothing_executes_a_binary_on_the_host_being_examined() {
    // rpm, dpkg, systemctl, crontab and ls are all binaries on the host
    // under examination, and wrapping one so it filters itself out of the
    // output is a standard persistence technique. Anything this tool learned
    // by running a host binary would be worthless.
    let mut bad = Vec::new();
    for file in all_sources() {
        for line in production_lines(&file) {
            for banned in ["Command::new", "process::Command", "std::process::exit", "libc::exec", "execv"] {
                if line.code.contains(banned) {
                    bad.push(format!("{}:{}: {banned}", relative(&file), line.n));
                }
            }
        }
    }
    assert!(bad.is_empty(), "the threat model forbids these:\n  {}", bad.join("\n  "));
}

/// The two files allowed to touch the filesystem by path. Root is the
/// abstraction itself. main.rs reads and writes the operator's own files —
/// a baseline passed to --against, the file --save writes — which live on
/// the analyst's machine by design and are never part of the scan root.
const FILESYSTEM_OWNERS: [&str; 2] = ["src/root.rs", "src/main.rs"];

#[test]
fn nothing_reaches_the_filesystem_except_through_the_scan_root() {
    // A module that opens a path itself works perfectly on a live host and
    // silently reads the analyst's own machine when the root is a mounted
    // image. The failure is invisible until it matters, and it is no less
    // true of provenance or enrichment than of a collector.
    let mut bad = Vec::new();
    for file in all_sources() {
        let rel = relative(&file);
        if FILESYSTEM_OWNERS.contains(&rel.as_str()) {
            continue;
        }
        for line in production_lines(&file) {
            for banned in [
                "std::fs::",
                "fs::read",
                "fs::write",
                "File::open",
                "File::create",
                "OpenOptions",
                "rustix::fs::",
                "read_to_string(",
                "Connection::open(",
                "Path::exists",
                ".exists()",
                ".metadata()",
                ".canonicalize()",
                ".read_link()",
            ] {
                if line.code.contains(banned) {
                    bad.push(format!("{rel}:{}: {banned} — use cx.read/cx.dir/cx.root", line.n));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "everything but {FILESYSTEM_OWNERS:?} must go through Root:\n  {}\n\nIf a line genuinely cannot, append `// {EXEMPT} <reason>`.",
        bad.join("\n  ")
    );
}

#[test]
fn a_string_continuation_keeps_its_backslash() {
    // A `\` at the end of a line inside a string swallows the newline and
    // the indentation after it. Lose it and the literal carries both: the
    // diff's enablement error printed fourteen spaces mid-sentence. A run of
    // spaces after punctuation, or a newline followed by indentation, is
    // that mistake and nothing else in this codebase's messages.
    let mut bad = Vec::new();
    for file in all_sources() {
        for line in production_lines(&file) {
            for lit in &line.literals {
                let spaced = lit.as_bytes().windows(4).any(|w| {
                    matches!(w[0], b'.' | b';' | b':' | b',' | b'!' | b'?')
                        && w[1] == b' '
                        && w[2] == b' '
                        && (w[3] == b' ' || w[3].is_ascii_alphabetic())
                });
                let indented = lit.contains("\n    ") || lit.contains("\n\t");
                if spaced || indented {
                    bad.push(format!("{}:{}: {:?}", relative(&file), line.n, lit));
                }
            }
        }
    }
    assert!(bad.is_empty(), "string literals with a lost line continuation:\n  {}", bad.join("\n  "));
}

#[test]
fn the_exemptions_stay_countable() {
    // The point is that the number moves only when somebody means it to.
    let mut found = Vec::new();
    for file in all_sources() {
        let text = std::fs::read_to_string(&file).unwrap();
        for (n, line) in text.lines().enumerate() {
            if line.contains(EXEMPT) {
                found.push(format!("{}:{}", relative(&file), n + 1));
            }
        }
    }
    assert!(
        found.len() <= 2,
        "{} conventions exemptions, which is more than this project has agreed to:\n  {}",
        found.len(),
        found.join("\n  ")
    );
}
