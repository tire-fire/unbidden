//! System-wide startup files of programs people start every day, read for
//! every account: code the program loads before anything the person asked
//! for. Per-account files (~/.vimrc, ~/.emacs, ~/.tmux.conf) are the
//! account's own and are not read (decided 2026-09-27).
//!
//! vim (`vim --version`, `:set rtp`): the system vimrc, /etc/vim/vimrc on
//! Debian and /etc/vimrc on Fedora, the vimrc.local each sources beside it,
//! and every `plugin/**/*.vim` under the system runtimepath entries
//! (/etc/vim, /var/lib/vim/addons, /usr/share/vim/vimfiles, the versioned
//! runtime, and their `after` directories), which vim loads at every start.
//! Neovim: /etc/xdg/nvim/sysinit.vim and `plugin/**/*.vim` and `*.lua`
//! under /etc/xdg/nvim, /usr/local/share/nvim/site, /usr/share/nvim/site,
//! /usr/share/nvim/runtime and /usr/lib/nvim. Emacs: site-start.el and
//! default.el in /usr/share/emacs/site-lisp, and the site-start.d files:
//! Debian's debian-startup.el loads /etc/emacs/site-start.d names matching
//! `^[0-9][0-9].*\.elc?$`, Fedora's site-start.el every `.el` or `.elc` in
//! /usr/share/emacs/site-lisp/site-start.d. tmux: /etc/tmux.conf, its
//! run-shell, if-shell, set-hook, source-file and the command a
//! new-session, new-window or split-window starts. screen: /etc/screenrc,
//! its exec, shell, source and the command a `screen` line starts. A key
//! binding runs on a keypress and is not read.

use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Editors;

const CAP: usize = 1 << 20;
/// How far `plugin/**` is followed: this tool's own bound, since vim's `**`
/// goes deeper.
const MAX_DEPTH: usize = 4;

impl Collector for Editors {
    fn name(&self) -> &'static str {
        "editors"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        vim(cx, &mut out);
        neovim(cx, &mut out);
        emacs(cx, &mut out);
        tmux(cx, &mut out);
        screen(cx, &mut out);
        out
    }
}

fn entry(cx: &mut Ctx, rel: &Path, name: String, program: &str, installed: bool) -> Entry {
    let mut e = cx.entry(Kind::ProgramStartup, rel, name);
    e.trigger = Trigger::Always;
    e.enabled = Enablement::Enabled;
    e.note("loaded_by", program);
    e.note("runs_when", format!("{program} starts, for every account"));
    if !installed {
        e.enabled = Enablement::Disabled;
        e.note("not_run", format!("{program} is not installed"));
    }
    e
}

/// A file that is itself the code: its own path is the target.
fn file_entry(cx: &mut Ctx, rel: &Path, name: String, program: &str, installed: bool, out: &mut Vec<Entry>) {
    if !cx.root.stat_follow(rel).is_ok_and(|m| m.is_file) {
        return;
    }
    let mut e = entry(cx, rel, name, program, installed);
    e.target_path = Some(cx.root.abs(rel));
    out.push(e);
}

/// Every file under `dir` whose name ends in one of `exts`, to a depth.
fn tree(cx: &mut Ctx, dir: &Path, exts: &[&str], depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH {
        return;
    }
    let mut ents: Vec<_> = cx.dir(dir).into_iter().collect();
    ents.sort_by(|a, b| a.name.cmp(&b.name));
    for e in ents {
        let p = dir.join(&e.name);
        if e.is_dir {
            tree(cx, &p, exts, depth + 1, out);
        } else if exts.iter().any(|x| e.name.to_string_lossy().ends_with(x)) {
            out.push(p);
        }
    }
}

fn any_exists(cx: &Ctx, paths: &[&str]) -> bool {
    paths.iter().any(|p| cx.root.exists(p))
}

fn vim(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = any_exists(cx, &["usr/bin/vim", "usr/bin/vim.basic", "usr/bin/vim.tiny", "usr/bin/vi", "usr/bin/vimx"]);
    for rc in ["etc/vim/vimrc", "etc/vim/vimrc.local", "etc/vimrc", "etc/vimrc.local"] {
        file_entry(cx, Path::new(rc), format!("vim:{}", rc.rsplit('/').next().unwrap_or(rc)), "vim", installed, out);
    }
    let mut dirs: Vec<PathBuf> = ["var/lib/vim/addons", "etc/vim", "usr/share/vim/vimfiles"].iter().map(PathBuf::from).collect();
    for ent in cx.dir(Path::new("usr/share/vim")) {
        let n = ent.name.to_string_lossy().into_owned();
        if ent.is_dir && n.starts_with("vim") && n[3..].chars().all(|c| c.is_ascii_digit()) && n.len() > 3 {
            dirs.push(Path::new("usr/share/vim").join(&ent.name));
        }
    }
    let after: Vec<PathBuf> = dirs.iter().map(|d| d.join("after")).collect();
    dirs.extend(after);
    for d in dirs {
        let mut files = Vec::new();
        tree(cx, &d.join("plugin"), &[".vim"], 0, &mut files);
        for pack in cx.dir(d.join("pack")).into_iter().filter(|e| e.is_dir).map(|e| e.name) {
            let start = d.join("pack").join(pack).join("start");
            for p in cx.dir(&start).into_iter().filter(|e| e.is_dir).map(|e| e.name) {
                tree(cx, &start.join(p).join("plugin"), &[".vim"], 0, &mut files);
            }
        }
        for f in files {
            let name = f.strip_prefix(&d).unwrap_or(&f).display().to_string();
            file_entry(cx, &f, format!("vim:{name}"), "vim", installed, out);
        }
    }
}

fn neovim(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/bin/nvim");
    file_entry(cx, Path::new("etc/xdg/nvim/sysinit.vim"), "nvim:sysinit.vim".into(), "nvim", installed, out);
    let mut dirs: Vec<PathBuf> = ["etc/xdg/nvim", "usr/local/share/nvim/site", "usr/share/nvim/site", "usr/share/nvim/runtime", "usr/lib/nvim", "usr/lib64/nvim"]
        .iter()
        .map(PathBuf::from)
        .collect();
    let after: Vec<PathBuf> = dirs[..3].iter().map(|d| d.join("after")).collect();
    dirs.extend(after);
    for d in dirs {
        let mut files = Vec::new();
        tree(cx, &d.join("plugin"), &[".vim", ".lua"], 0, &mut files);
        for f in files {
            let name = f.strip_prefix(&d).unwrap_or(&f).display().to_string();
            file_entry(cx, &f, format!("nvim:{name}"), "nvim", installed, out);
        }
    }
}

fn emacs(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = any_exists(cx, &["usr/bin/emacs", "usr/bin/emacs-nw", "usr/bin/emacs-gtk"]);
    for f in ["etc/emacs/site-start.el", "usr/share/emacs/site-lisp/site-start.el", "usr/share/emacs/site-lisp/default.el"] {
        file_entry(cx, Path::new(f), format!("emacs:{}", f.rsplit('/').next().unwrap_or(f)), "emacs", installed, out);
    }
    // Debian's rule and Fedora's differ; each is applied to its directory.
    let debian = |n: &str| {
        let b = n.as_bytes();
        b.len() > 2 && b[0].is_ascii_digit() && b[1].is_ascii_digit() && (n.ends_with(".el") || n.ends_with(".elc"))
    };
    let fedora = |n: &str| n.ends_with(".el") || n.ends_with(".elc");
    for (dir, accept) in [("etc/emacs/site-start.d", &debian as &dyn Fn(&str) -> bool), ("usr/share/emacs/site-lisp/site-start.d", &fedora)] {
        let names: Vec<_> = cx.dir(Path::new(dir)).into_iter().filter(|e| !e.is_dir).map(|e| e.name).collect();
        for n in names {
            let name = n.to_string_lossy().into_owned();
            if !accept(&name) {
                continue;
            }
            file_entry(cx, &Path::new(dir).join(&n), format!("emacs:site-start.d/{name}"), "emacs", installed, out);
        }
    }
}

/// A config line split into words: blanks separate, quotes group, a backslash
/// escapes. Enough for the directives read here; tmux's own lexer also has
/// `{}` blocks and `$VAR`, which this does not.
fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    let mut had = false;
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            (Some(_), c) => cur.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                had = true;
            }
            (None, '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    had = true;
                }
            }
            (None, c) if c.is_whitespace() => {
                if had || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    had = false;
                }
            }
            (None, '#') if cur.is_empty() && !had => break,
            (None, c) => {
                cur.push(c);
                had = true;
            }
        }
    }
    if had || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Lines with `\` continuations joined, as both programs join them.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        if let Some(head) = line.strip_suffix('\\') {
            cur.push_str(head);
            cur.push(' ');
            continue;
        }
        cur.push_str(line);
        out.push(std::mem::take(&mut cur));
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn command_entry(cx: &mut Ctx, rel: &Path, program: &str, installed: bool, verb: &str, command: &str, n: usize, out: &mut Vec<Entry>) {
    let mut e = entry(cx, rel, format!("{program}:{verb}:{n}"), program, installed);
    e.note("directive", verb);
    e.command = Some(command.as_bytes().to_vec());
    out.push(e);
}

/// The words that are not options, where an option whose last letter is in
/// `valued` consumes the word after it (`-ds name` as tmux's getopt reads
/// it).
fn positionals(args: &[String], valued: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.len() > 1 && a.starts_with('-') && !a.starts_with("--") {
            let last = format!("-{}", a.chars().last().unwrap_or('-'));
            if valued.contains(&last.as_str()) {
                i += 1;
            }
            i += 1;
            continue;
        }
        out.push(a.clone());
        i += 1;
    }
    out
}

fn tmux(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/bin/tmux");
    let rel = Path::new("etc/tmux.conf");
    let Some(bytes) = cx.read_capped(rel, CAP) else { return };
    for (n, line) in logical_lines(&String::from_utf8_lossy(&bytes)).iter().enumerate() {
        let w = words(line);
        let Some(verb) = w.first() else { continue };
        // Each command's options that take a value, so the value is not
        // mistaken for the command text; the text is then the first
        // positional, the second for set-hook (after the hook name), and the
        // last for the commands that open a window running it.
        let (valued, pick): (&[&str], usize) = match verb.as_str() {
            "run-shell" | "run" => (&["-c", "-d", "-t"], 0),
            "if-shell" | "if" => (&["-t"], 0),
            "set-hook" => (&["-t"], 1),
            "new-session" | "new" => (&["-c", "-e", "-f", "-F", "-n", "-s", "-t", "-x", "-y"], usize::MAX),
            "new-window" | "neww" => (&["-c", "-e", "-F", "-n", "-t"], usize::MAX),
            "split-window" | "splitw" => (&["-c", "-e", "-F", "-l", "-t"], usize::MAX),
            "source-file" | "source" => (&["-t"], 0),
            _ => continue,
        };
        let positional = positionals(&w[1..], valued);
        let cmd = if pick == usize::MAX { positional.last().cloned() } else { positional.get(pick).cloned() };
        if let Some(c) = cmd.filter(|c| !c.is_empty()) {
            command_entry(cx, rel, "tmux", installed, verb, &c, n + 1, out);
        }
    }
}

fn screen(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/bin/screen");
    let rel = Path::new("etc/screenrc");
    let Some(bytes) = cx.read_capped(rel, CAP) else { return };
    for (n, line) in logical_lines(&String::from_utf8_lossy(&bytes)).iter().enumerate() {
        let w = words(line);
        let Some(verb) = w.first() else { continue };
        let cmd = match verb.as_str() {
            "exec" | "shell" | "source" => Some(w[1..].join(" ")),
            // `screen [-flags] [title] cmd args`: the first word after the
            // options that is not a number and not a title flag's value.
            "screen" => {
                let mut rest = &w[1..];
                let mut cmdv: Vec<String> = Vec::new();
                while let Some(a) = rest.first() {
                    if let Some(f) = a.strip_prefix('-') {
                        rest = &rest[1..];
                        if matches!(f, "t" | "L" | "h" | "e") && !rest.is_empty() && f != "L" {
                            rest = &rest[1..];
                        }
                        continue;
                    }
                    if a.chars().all(|c| c.is_ascii_digit()) && cmdv.is_empty() {
                        rest = &rest[1..];
                        continue;
                    }
                    cmdv = rest.to_vec();
                    break;
                }
                Some(cmdv.join(" "))
            }
            _ => None,
        };
        if let Some(c) = cmd.filter(|c| !c.is_empty()) {
            command_entry(cx, rel, "screen", installed, verb, &c, n + 1, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan};

    fn put(dir: &Path, rel: &str, body: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Editors)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    #[test]
    fn system_wide_startup_files_are_read_by_each_programs_rule() {
        let d = crate::testing::Tree::new("editors");
        put(&d, "usr/bin/vim", b"");
        put(&d, "etc/vim/vimrc", b"runtime! debian.vim\n");
        put(&d, "etc/vim/vimrc.local", b"call system('/opt/x')\n");
        put(&d, "etc/vim/plugin/evil.vim", b"\n");
        put(&d, "usr/share/vim/vim90/plugin/matchparen.vim", b"\n");
        put(&d, "usr/share/vim/vimfiles/pack/dist/start/x/plugin/x.vim", b"\n");
        put(&d, "usr/share/vim/vimfiles/plugin/deep/nested/y.vim", b"\n");
        put(&d, "usr/share/vim/vimfiles/plugin/notes.txt", b"\n");
        put(&d, "home/alice/.vimrc", b"\n");
        put(&d, "etc/xdg/nvim/sysinit.vim", b"\n");
        put(&d, "usr/share/nvim/site/plugin/p.lua", b"\n");
        put(&d, "usr/bin/emacs", b"");
        put(&d, "etc/emacs/site-start.d/00debian.el", b"\n");
        put(&d, "etc/emacs/site-start.d/evil.el", b"\n");
        put(&d, "usr/share/emacs/site-lisp/site-start.d/evil.el", b"\n");
        put(&d, "usr/bin/tmux", b"");
        put(&d, "etc/tmux.conf", b"# c\nset -g status on\nrun-shell -b \"/opt/beacon --bg\"\nif-shell 'test -x /opt/t' 'display yes'\nset-hook -g session-created 'run-shell /opt/h'\nbind-key r run-shell /opt/never\nnew-session -d -s bg \\\n  '/opt/daemon'\n");
        put(&d, "etc/screenrc", b"startup_message off\nscreen -t log 1 /usr/bin/tail -f /var/log/syslog\nshell /opt/sh\nbind e exec /never\n");
        let s = scan(&d);
        let mut got: Vec<(&str, &str)> = s.entries.iter().map(|e| (e.name.as_str(), e.command.as_deref().map(|c| std::str::from_utf8(c).unwrap()).unwrap_or("-"))).collect();
        got.sort();
        assert_eq!(
            got,
            [
                ("emacs:site-start.d/00debian.el", "-"),
                ("emacs:site-start.d/evil.el", "-"),
                ("nvim:plugin/p.lua", "-"),
                ("nvim:sysinit.vim", "-"),
                ("screen:screen:2", "/usr/bin/tail -f /var/log/syslog"),
                ("screen:shell:3", "/opt/sh"),
                ("tmux:if-shell:4", "test -x /opt/t"),
                ("tmux:new-session:7", "/opt/daemon"),
                ("tmux:run-shell:3", "/opt/beacon --bg"),
                ("tmux:set-hook:5", "run-shell /opt/h"),
                ("vim:pack/dist/start/x/plugin/x.vim", "-"),
                ("vim:plugin/deep/nested/y.vim", "-"),
                ("vim:plugin/evil.vim", "-"),
                ("vim:plugin/matchparen.vim", "-"),
                ("vim:vimrc", "-"),
                ("vim:vimrc.local", "-"),
            ],
            "Debian's emacs rule takes only NN-prefixed names, Fedora's any .el; a key binding is not read; ~/.vimrc is the account's own"
        );
        let nvim = s.entries.iter().find(|e| e.name == "nvim:sysinit.vim").unwrap();
        assert_eq!(nvim.enabled, Enablement::Disabled, "nvim is not installed here");
    }
}
