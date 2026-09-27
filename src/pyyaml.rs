//! PyYAML's reader, scanner and parser (reader.py, scanner.py, parser.py),
//! ported function for function, so that YAML is tokenised and parsed
//! exactly as cloud-init's `yaml.safe_load` does it: SafeLoader is the pure
//! Python loader, not libyaml. The three files are identical from PyYAML 6.0
//! through 6.0.3, which covers every supported distribution.
//!
//! Both halves are state machines over explicit stacks, as in Python, so
//! nesting costs heap in proportion to the input and never stack. Every
//! error PyYAML raises, including the ones Python raises for it (a pop from
//! an empty list, `chr` past U+10FFFF), is an `Err` here. The one deliberate
//! difference: a `\uD800`-style escape, which Python keeps as a lone
//! surrogate, becomes U+FFFD, since a Rust string cannot hold one.

use std::collections::{BTreeMap, HashMap, VecDeque};

/// Where the scanner was, for messages.
#[derive(Clone, Copy, Debug, Default)]
pub struct Mark {
    pub line: usize,
    pub column: usize,
}

impl std::fmt::Display for Mark {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "line {}, column {}", self.line + 1, self.column + 1)
    }
}

#[derive(Debug, PartialEq)]
pub enum Event {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Alias { anchor: String },
    /// `implicit` is PyYAML's first flag: whether the resolver may type the
    /// value, as it does for a plain scalar with no tag or one tagged `!`.
    Scalar { anchor: Option<String>, tag: Option<String>, implicit: bool, value: String },
    SequenceStart { anchor: Option<String>, tag: Option<String> },
    SequenceEnd,
    MappingStart { anchor: Option<String>, tag: Option<String> },
    MappingEnd,
}

// Character classes, as the Python spells them at each use.
/// End of a token: NUL, blanks with the tab, line breaks.
const BLANKZ_TAB: &str = "\0 \t\r\n\u{85}\u{2028}\u{2029}";
/// The same without the tab, where PyYAML leaves it out.
const BLANKZ: &str = "\0 \r\n\u{85}\u{2028}\u{2029}";
const BREAKZ: &str = "\0\r\n\u{85}\u{2028}\u{2029}";
const BREAK: &str = "\r\n\u{85}\u{2028}\u{2029}";
const HEX: &str = "0123456789ABCDEFabcdef";

fn word(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
}

fn err<T>(context: &str, problem: String, mark: Mark) -> Result<T, String> {
    Err(if context.is_empty() { format!("{problem} at {mark}") } else { format!("{context}: {problem} at {mark}") })
}

#[derive(Debug)]
enum Directive {
    /// `%YAML`, and whether its major version is 1.
    Yaml(bool),
    Tag(String, String),
    Other,
}

#[derive(Debug)]
enum Tok {
    StreamStart,
    StreamEnd,
    Directive(Directive),
    DocumentStart,
    DocumentEnd,
    BlockSequenceStart,
    BlockMappingStart,
    BlockEnd,
    FlowSequenceStart,
    FlowMappingStart,
    FlowSequenceEnd,
    FlowMappingEnd,
    Key,
    Value,
    BlockEntry,
    FlowEntry,
    Alias(String),
    Anchor(String),
    Tag(Option<String>, String),
    Scalar { value: String, plain: bool },
}

struct Token {
    tok: Tok,
    mark: Mark,
}

struct SimpleKey {
    token_number: usize,
    required: bool,
    index: usize,
    line: usize,
    column: usize,
    mark: Mark,
}

struct Scanner {
    // reader.py
    buffer: Vec<char>,
    pointer: usize,
    line: usize,
    column: usize,
    // scanner.py
    done: bool,
    flow_level: i64,
    tokens: VecDeque<Token>,
    tokens_taken: usize,
    indent: i64,
    indents: Vec<i64>,
    allow_simple_key: bool,
    possible_simple_keys: BTreeMap<i64, SimpleKey>,
}

impl Scanner {
    /// Reader.__init__ for a `str`: every character checked printable, and
    /// a NUL appended.
    fn new(text: &str) -> Result<Scanner, String> {
        for (i, ch) in text.chars().enumerate() {
            let printable = matches!(ch, '\t' | '\n' | '\r' | '\x20'..='\x7e' | '\u{85}' | '\u{a0}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..);
            if !printable {
                return Err(format!("special characters are not allowed: {:#x} at position {i}", ch as u32));
            }
        }
        let mut buffer: Vec<char> = text.chars().collect();
        buffer.push('\0');
        let mut s = Scanner {
            buffer,
            pointer: 0,
            line: 0,
            column: 0,
            done: false,
            flow_level: 0,
            tokens: VecDeque::new(),
            tokens_taken: 0,
            indent: -1,
            indents: Vec::new(),
            allow_simple_key: true,
            possible_simple_keys: BTreeMap::new(),
        };
        let mark = s.mark();
        s.tokens.push_back(Token { tok: Tok::StreamStart, mark });
        Ok(s)
    }

    // --- reader.py

    fn peek(&self, index: usize) -> char {
        self.buffer.get(self.pointer + index).copied().unwrap_or('\0')
    }

    fn prefix(&self, length: usize) -> String {
        let end = (self.pointer + length).min(self.buffer.len());
        self.buffer[self.pointer.min(end)..end].iter().collect()
    }

    fn forward(&mut self, length: usize) {
        for _ in 0..length {
            let Some(&ch) = self.buffer.get(self.pointer) else { return };
            self.pointer += 1;
            if "\n\u{85}\u{2028}\u{2029}".contains(ch) || (ch == '\r' && self.peek(0) != '\n') {
                self.line += 1;
                self.column = 0;
            } else if ch != '\u{feff}' {
                self.column += 1;
            }
        }
    }

    fn mark(&self) -> Mark {
        Mark { line: self.line, column: self.column }
    }

    fn push(&mut self, tok: Tok, mark: Mark) {
        self.tokens.push_back(Token { tok, mark });
    }

    // --- the public face

    fn need_more_tokens(&mut self) -> Result<bool, String> {
        if self.done {
            return Ok(false);
        }
        if self.tokens.is_empty() {
            return Ok(true);
        }
        self.stale_possible_simple_keys()?;
        Ok(self.next_possible_simple_key() == Some(self.tokens_taken))
    }

    fn peek_token(&mut self) -> Result<Option<&Token>, String> {
        while self.need_more_tokens()? {
            self.fetch_more_tokens()?;
        }
        Ok(self.tokens.front())
    }

    fn get_token(&mut self) -> Result<Token, String> {
        while self.need_more_tokens()? {
            self.fetch_more_tokens()?;
        }
        let t = self.tokens.pop_front().ok_or("no more tokens")?;
        self.tokens_taken += 1;
        Ok(t)
    }

    fn fetch_more_tokens(&mut self) -> Result<(), String> {
        self.scan_to_next_token();
        self.stale_possible_simple_keys()?;
        self.unwind_indent(self.column as i64);
        let ch = self.peek(0);
        match ch {
            '\0' => return self.fetch_stream_end(),
            '%' if self.column == 0 => return self.fetch_directive(),
            '-' if self.check_document_indicator("---") => return self.fetch_document_indicator(Tok::DocumentStart),
            '.' if self.check_document_indicator("...") => return self.fetch_document_indicator(Tok::DocumentEnd),
            '[' => return self.fetch_flow_collection_start(Tok::FlowSequenceStart),
            '{' => return self.fetch_flow_collection_start(Tok::FlowMappingStart),
            ']' => return self.fetch_flow_collection_end(Tok::FlowSequenceEnd),
            '}' => return self.fetch_flow_collection_end(Tok::FlowMappingEnd),
            ',' => return self.fetch_flow_entry(),
            _ => {}
        }
        if ch == '-' && BLANKZ_TAB.contains(self.peek(1)) {
            return self.fetch_block_entry();
        }
        if ch == '?' && (self.flow_level != 0 || BLANKZ_TAB.contains(self.peek(1))) {
            return self.fetch_key();
        }
        if ch == ':' && (self.flow_level != 0 || BLANKZ_TAB.contains(self.peek(1))) {
            return self.fetch_value();
        }
        match ch {
            '*' => return self.fetch_anchor(true),
            '&' => return self.fetch_anchor(false),
            '!' => return self.fetch_tag(),
            '|' | '>' if self.flow_level == 0 => return self.fetch_block_scalar(ch == '>'),
            '\'' | '"' => return self.fetch_flow_scalar(ch == '"'),
            _ => {}
        }
        if self.check_plain() {
            return self.fetch_plain();
        }
        err("while scanning for the next token", format!("found character {ch:?} that cannot start any token"), self.mark())
    }

    // --- simple keys

    fn next_possible_simple_key(&self) -> Option<usize> {
        self.possible_simple_keys.values().map(|k| k.token_number).min()
    }

    fn stale_possible_simple_keys(&mut self) -> Result<(), String> {
        let levels: Vec<i64> = self.possible_simple_keys.keys().copied().collect();
        for level in levels {
            let key = &self.possible_simple_keys[&level];
            if key.line != self.line || self.pointer - key.index > 1024 {
                if key.required {
                    return err("while scanning a simple key", "could not find expected ':'".into(), self.mark());
                }
                self.possible_simple_keys.remove(&level);
            }
        }
        Ok(())
    }

    fn save_possible_simple_key(&mut self) -> Result<(), String> {
        let required = self.flow_level == 0 && self.indent == self.column as i64;
        if self.allow_simple_key {
            self.remove_possible_simple_key()?;
            let key = SimpleKey {
                token_number: self.tokens_taken + self.tokens.len(),
                required,
                index: self.pointer,
                line: self.line,
                column: self.column,
                mark: self.mark(),
            };
            self.possible_simple_keys.insert(self.flow_level, key);
        }
        Ok(())
    }

    fn remove_possible_simple_key(&mut self) -> Result<(), String> {
        if let Some(key) = self.possible_simple_keys.remove(&self.flow_level) {
            if key.required {
                return err("while scanning a simple key", "could not find expected ':'".into(), self.mark());
            }
        }
        Ok(())
    }

    // --- indentation

    fn unwind_indent(&mut self, column: i64) {
        if self.flow_level != 0 {
            return;
        }
        while self.indent > column {
            let mark = self.mark();
            self.indent = self.indents.pop().unwrap_or(-1);
            self.push(Tok::BlockEnd, mark);
        }
    }

    fn add_indent(&mut self, column: i64) -> bool {
        if self.indent < column {
            self.indents.push(self.indent);
            self.indent = column;
            return true;
        }
        false
    }

    // --- fetchers

    fn fetch_stream_end(&mut self) -> Result<(), String> {
        self.unwind_indent(-1);
        self.remove_possible_simple_key()?;
        self.allow_simple_key = false;
        self.possible_simple_keys.clear();
        let mark = self.mark();
        self.push(Tok::StreamEnd, mark);
        self.done = true;
        Ok(())
    }

    fn fetch_directive(&mut self) -> Result<(), String> {
        self.unwind_indent(-1);
        self.remove_possible_simple_key()?;
        self.allow_simple_key = false;
        let mark = self.mark();
        let d = self.scan_directive()?;
        self.push(Tok::Directive(d), mark);
        Ok(())
    }

    fn check_document_indicator(&self, indicator: &str) -> bool {
        self.column == 0 && self.prefix(3) == indicator && BLANKZ_TAB.contains(self.peek(3))
    }

    fn fetch_document_indicator(&mut self, tok: Tok) -> Result<(), String> {
        self.unwind_indent(-1);
        self.remove_possible_simple_key()?;
        self.allow_simple_key = false;
        let mark = self.mark();
        self.forward(3);
        self.push(tok, mark);
        Ok(())
    }

    fn fetch_flow_collection_start(&mut self, tok: Tok) -> Result<(), String> {
        self.save_possible_simple_key()?;
        self.flow_level += 1;
        self.allow_simple_key = true;
        let mark = self.mark();
        self.forward(1);
        self.push(tok, mark);
        Ok(())
    }

    fn fetch_flow_collection_end(&mut self, tok: Tok) -> Result<(), String> {
        self.remove_possible_simple_key()?;
        self.flow_level -= 1;
        self.allow_simple_key = false;
        let mark = self.mark();
        self.forward(1);
        self.push(tok, mark);
        Ok(())
    }

    fn fetch_flow_entry(&mut self) -> Result<(), String> {
        self.allow_simple_key = true;
        self.remove_possible_simple_key()?;
        let mark = self.mark();
        self.forward(1);
        self.push(Tok::FlowEntry, mark);
        Ok(())
    }

    fn fetch_block_entry(&mut self) -> Result<(), String> {
        if self.flow_level == 0 {
            if !self.allow_simple_key {
                return err("", "sequence entries are not allowed here".into(), self.mark());
            }
            if self.add_indent(self.column as i64) {
                let mark = self.mark();
                self.push(Tok::BlockSequenceStart, mark);
            }
        }
        self.allow_simple_key = true;
        self.remove_possible_simple_key()?;
        let mark = self.mark();
        self.forward(1);
        self.push(Tok::BlockEntry, mark);
        Ok(())
    }

    fn fetch_key(&mut self) -> Result<(), String> {
        if self.flow_level == 0 {
            if !self.allow_simple_key {
                return err("", "mapping keys are not allowed here".into(), self.mark());
            }
            if self.add_indent(self.column as i64) {
                let mark = self.mark();
                self.push(Tok::BlockMappingStart, mark);
            }
        }
        self.allow_simple_key = self.flow_level == 0;
        self.remove_possible_simple_key()?;
        let mark = self.mark();
        self.forward(1);
        self.push(Tok::Key, mark);
        Ok(())
    }

    fn fetch_value(&mut self) -> Result<(), String> {
        if let Some(key) = self.possible_simple_keys.remove(&self.flow_level) {
            let at = key.token_number - self.tokens_taken;
            self.tokens.insert(at, Token { tok: Tok::Key, mark: key.mark });
            if self.flow_level == 0 && self.add_indent(key.column as i64) {
                self.tokens.insert(at, Token { tok: Tok::BlockMappingStart, mark: key.mark });
            }
            self.allow_simple_key = false;
        } else {
            if self.flow_level == 0 {
                if !self.allow_simple_key {
                    return err("", "mapping values are not allowed here".into(), self.mark());
                }
                if self.add_indent(self.column as i64) {
                    let mark = self.mark();
                    self.push(Tok::BlockMappingStart, mark);
                }
            }
            self.allow_simple_key = self.flow_level == 0;
            self.remove_possible_simple_key()?;
        }
        let mark = self.mark();
        self.forward(1);
        self.push(Tok::Value, mark);
        Ok(())
    }

    fn fetch_anchor(&mut self, alias: bool) -> Result<(), String> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let mark = self.mark();
        let name = self.scan_anchor(alias)?;
        self.push(if alias { Tok::Alias(name) } else { Tok::Anchor(name) }, mark);
        Ok(())
    }

    fn fetch_tag(&mut self) -> Result<(), String> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let mark = self.mark();
        let (handle, suffix) = self.scan_tag()?;
        self.push(Tok::Tag(handle, suffix), mark);
        Ok(())
    }

    fn fetch_block_scalar(&mut self, folded: bool) -> Result<(), String> {
        self.allow_simple_key = true;
        self.remove_possible_simple_key()?;
        let mark = self.mark();
        let value = self.scan_block_scalar(folded)?;
        self.push(Tok::Scalar { value, plain: false }, mark);
        Ok(())
    }

    fn fetch_flow_scalar(&mut self, double: bool) -> Result<(), String> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let mark = self.mark();
        let value = self.scan_flow_scalar(double)?;
        self.push(Tok::Scalar { value, plain: false }, mark);
        Ok(())
    }

    fn fetch_plain(&mut self) -> Result<(), String> {
        self.save_possible_simple_key()?;
        self.allow_simple_key = false;
        let mark = self.mark();
        let value = self.scan_plain();
        self.push(Tok::Scalar { value, plain: true }, mark);
        Ok(())
    }

    fn check_plain(&self) -> bool {
        let ch = self.peek(0);
        !"\0 \t\r\n\u{85}\u{2028}\u{2029}-?:,[]{}#&*!|>'\"%@`".contains(ch)
            || (!BLANKZ_TAB.contains(self.peek(1)) && (ch == '-' || (self.flow_level == 0 && "?:".contains(ch))))
    }

    // --- scanners

    fn scan_to_next_token(&mut self) {
        if self.pointer == 0 && self.peek(0) == '\u{feff}' {
            self.forward(1);
        }
        loop {
            while self.peek(0) == ' ' {
                self.forward(1);
            }
            if self.peek(0) == '#' {
                while !BREAKZ.contains(self.peek(0)) {
                    self.forward(1);
                }
            }
            if self.scan_line_break().is_empty() {
                return;
            }
            if self.flow_level == 0 {
                self.allow_simple_key = true;
            }
        }
    }

    fn scan_directive(&mut self) -> Result<Directive, String> {
        let start = self.mark();
        self.forward(1);
        let name = self.scan_directive_name(start)?;
        let value = match name.as_str() {
            "YAML" => self.scan_yaml_directive_value(start)?,
            "TAG" => self.scan_tag_directive_value(start)?,
            _ => {
                while !BREAKZ.contains(self.peek(0)) {
                    self.forward(1);
                }
                Directive::Other
            }
        };
        self.scan_ignored_line("while scanning a directive", start)?;
        Ok(value)
    }

    fn scan_directive_name(&mut self, start: Mark) -> Result<String, String> {
        let mut length = 0;
        while word(self.peek(length)) {
            length += 1;
        }
        if length == 0 {
            return err("while scanning a directive", format!("expected alphabetic or numeric character, but found {:?}", self.peek(0)), start);
        }
        let value = self.prefix(length);
        self.forward(length);
        if !BLANKZ.contains(self.peek(0)) {
            return err("while scanning a directive", format!("expected alphabetic or numeric character, but found {:?}", self.peek(0)), start);
        }
        Ok(value)
    }

    fn scan_yaml_directive_value(&mut self, start: Mark) -> Result<Directive, String> {
        while self.peek(0) == ' ' {
            self.forward(1);
        }
        let major = self.scan_yaml_directive_number(start)?;
        if self.peek(0) != '.' {
            return err("while scanning a directive", format!("expected a digit or '.', but found {:?}", self.peek(0)), self.mark());
        }
        self.forward(1);
        self.scan_yaml_directive_number(start)?;
        if !BLANKZ.contains(self.peek(0)) {
            return err("while scanning a directive", format!("expected a digit or ' ', but found {:?}", self.peek(0)), self.mark());
        }
        // Python compares int(major) with 1, at any length.
        Ok(Directive::Yaml(major.trim_start_matches('0') == "1"))
    }

    fn scan_yaml_directive_number(&mut self, start: Mark) -> Result<String, String> {
        if !self.peek(0).is_ascii_digit() {
            return err("while scanning a directive", format!("expected a digit, but found {:?}", self.peek(0)), start);
        }
        let mut length = 0;
        while self.peek(length).is_ascii_digit() {
            length += 1;
        }
        let value = self.prefix(length);
        self.forward(length);
        Ok(value)
    }

    fn scan_tag_directive_value(&mut self, start: Mark) -> Result<Directive, String> {
        while self.peek(0) == ' ' {
            self.forward(1);
        }
        let handle = self.scan_tag_handle("directive", start)?;
        if self.peek(0) != ' ' {
            return err("while scanning a directive", format!("expected ' ', but found {:?}", self.peek(0)), self.mark());
        }
        while self.peek(0) == ' ' {
            self.forward(1);
        }
        let prefix = self.scan_tag_uri("directive", start)?;
        if !BLANKZ.contains(self.peek(0)) {
            return err("while scanning a directive", format!("expected ' ', but found {:?}", self.peek(0)), self.mark());
        }
        Ok(Directive::Tag(handle, prefix))
    }

    /// The rest of a directive's or a block scalar header's line: blanks,
    /// a comment, a break.
    fn scan_ignored_line(&mut self, context: &str, start: Mark) -> Result<(), String> {
        while self.peek(0) == ' ' {
            self.forward(1);
        }
        if self.peek(0) == '#' {
            while !BREAKZ.contains(self.peek(0)) {
                self.forward(1);
            }
        }
        if !BREAKZ.contains(self.peek(0)) {
            let _ = start;
            return err(context, format!("expected a comment or a line break, but found {:?}", self.peek(0)), self.mark());
        }
        self.scan_line_break();
        Ok(())
    }

    fn scan_anchor(&mut self, alias: bool) -> Result<String, String> {
        let what = if alias { "while scanning an alias" } else { "while scanning an anchor" };
        self.forward(1);
        let mut length = 0;
        while word(self.peek(length)) {
            length += 1;
        }
        if length == 0 {
            return err(what, format!("expected alphabetic or numeric character, but found {:?}", self.peek(0)), self.mark());
        }
        let value = self.prefix(length);
        self.forward(length);
        if !"\0 \t\r\n\u{85}\u{2028}\u{2029}?:,]}%@`".contains(self.peek(0)) {
            return err(what, format!("expected alphabetic or numeric character, but found {:?}", self.peek(0)), self.mark());
        }
        Ok(value)
    }

    fn scan_tag(&mut self) -> Result<(Option<String>, String), String> {
        let start = self.mark();
        let ch = self.peek(1);
        let (handle, suffix) = if ch == '<' {
            self.forward(2);
            let suffix = self.scan_tag_uri("tag", start)?;
            if self.peek(0) != '>' {
                return err("while parsing a tag", format!("expected '>', but found {:?}", self.peek(0)), self.mark());
            }
            self.forward(1);
            (None, suffix)
        } else if BLANKZ_TAB.contains(ch) {
            self.forward(1);
            (None, "!".to_string())
        } else {
            let mut length = 1;
            let mut ch = ch;
            let mut use_handle = false;
            while !BLANKZ.contains(ch) {
                if ch == '!' {
                    use_handle = true;
                    break;
                }
                length += 1;
                ch = self.peek(length);
            }
            let handle = if use_handle {
                self.scan_tag_handle("tag", start)?
            } else {
                self.forward(1);
                "!".to_string()
            };
            (Some(handle), self.scan_tag_uri("tag", start)?)
        };
        if !BLANKZ.contains(self.peek(0)) {
            return err("while scanning a tag", format!("expected ' ', but found {:?}", self.peek(0)), self.mark());
        }
        Ok((handle, suffix))
    }

    fn scan_block_scalar(&mut self, folded: bool) -> Result<String, String> {
        let start = self.mark();
        let mut chunks = String::new();
        self.forward(1);
        let (chomping, increment) = self.scan_block_scalar_indicators(start)?;
        self.scan_ignored_line("while scanning a block scalar", start)?;
        let min_indent = (self.indent + 1).max(1) as usize;
        let (mut breaks, indent) = match increment {
            None => {
                let (breaks, max_indent) = self.scan_block_scalar_indentation();
                (breaks, min_indent.max(max_indent))
            }
            Some(inc) => {
                let indent = min_indent + inc - 1;
                (self.scan_block_scalar_breaks(indent), indent)
            }
        };
        let mut line_break = String::new();
        while self.column == indent && self.peek(0) != '\0' {
            chunks.extend(breaks.drain(..));
            let leading_non_space = !" \t".contains(self.peek(0));
            let mut length = 0;
            while !BREAKZ.contains(self.peek(length)) {
                length += 1;
            }
            chunks.push_str(&self.prefix(length));
            self.forward(length);
            line_break = self.scan_line_break();
            breaks = self.scan_block_scalar_breaks(indent);
            if self.column == indent && self.peek(0) != '\0' {
                if folded && line_break == "\n" && leading_non_space && !" \t".contains(self.peek(0)) {
                    if breaks.is_empty() {
                        chunks.push(' ');
                    }
                } else {
                    chunks.push_str(&line_break);
                }
            } else {
                break;
            }
        }
        if chomping != Some(false) {
            chunks.push_str(&line_break);
        }
        if chomping == Some(true) {
            chunks.extend(breaks.drain(..));
        }
        Ok(chunks)
    }

    fn scan_block_scalar_indicators(&mut self, start: Mark) -> Result<(Option<bool>, Option<usize>), String> {
        let (mut chomping, mut increment) = (None, None);
        let zero = || err("while scanning a block scalar", "expected indentation indicator in the range 1-9, but found 0".into(), start);
        let ch = self.peek(0);
        if ch == '+' || ch == '-' {
            chomping = Some(ch == '+');
            self.forward(1);
            if let Some(d) = self.peek(0).to_digit(10) {
                if d == 0 {
                    return zero();
                }
                increment = Some(d as usize);
                self.forward(1);
            }
        } else if let Some(d) = ch.to_digit(10) {
            if d == 0 {
                return zero();
            }
            increment = Some(d as usize);
            self.forward(1);
            let ch = self.peek(0);
            if ch == '+' || ch == '-' {
                chomping = Some(ch == '+');
                self.forward(1);
            }
        }
        if !BLANKZ.contains(self.peek(0)) {
            return err("while scanning a block scalar", format!("expected chomping or indentation indicators, but found {:?}", self.peek(0)), self.mark());
        }
        Ok((chomping, increment))
    }

    fn scan_block_scalar_indentation(&mut self) -> (Vec<String>, usize) {
        let mut chunks = Vec::new();
        let mut max_indent = 0;
        while " \r\n\u{85}\u{2028}\u{2029}".contains(self.peek(0)) {
            if self.peek(0) != ' ' {
                chunks.push(self.scan_line_break());
            } else {
                self.forward(1);
                max_indent = max_indent.max(self.column);
            }
        }
        (chunks, max_indent)
    }

    fn scan_block_scalar_breaks(&mut self, indent: usize) -> Vec<String> {
        let mut chunks = Vec::new();
        while self.column < indent && self.peek(0) == ' ' {
            self.forward(1);
        }
        while BREAK.contains(self.peek(0)) {
            chunks.push(self.scan_line_break());
            while self.column < indent && self.peek(0) == ' ' {
                self.forward(1);
            }
        }
        chunks
    }

    fn scan_flow_scalar(&mut self, double: bool) -> Result<String, String> {
        let start = self.mark();
        let mut chunks = String::new();
        let quote = self.peek(0);
        self.forward(1);
        self.scan_flow_scalar_non_spaces(double, start, &mut chunks)?;
        while self.peek(0) != quote {
            self.scan_flow_scalar_spaces(double, start, &mut chunks)?;
            self.scan_flow_scalar_non_spaces(double, start, &mut chunks)?;
        }
        self.forward(1);
        Ok(chunks)
    }

    fn scan_flow_scalar_non_spaces(&mut self, double: bool, start: Mark, chunks: &mut String) -> Result<(), String> {
        loop {
            let mut length = 0;
            while !"'\"\\\0 \t\r\n\u{85}\u{2028}\u{2029}".contains(self.peek(length)) {
                length += 1;
            }
            if length > 0 {
                chunks.push_str(&self.prefix(length));
                self.forward(length);
            }
            let ch = self.peek(0);
            if !double && ch == '\'' && self.peek(1) == '\'' {
                chunks.push('\'');
                self.forward(2);
            } else if (double && ch == '\'') || (!double && (ch == '"' || ch == '\\')) {
                chunks.push(ch);
                self.forward(1);
            } else if double && ch == '\\' {
                self.forward(1);
                let ch = self.peek(0);
                let replacement = match ch {
                    '0' => Some('\0'),
                    'a' => Some('\x07'),
                    'b' => Some('\x08'),
                    't' | '\t' => Some('\t'),
                    'n' => Some('\n'),
                    'v' => Some('\x0b'),
                    'f' => Some('\x0c'),
                    'r' => Some('\r'),
                    'e' => Some('\x1b'),
                    ' ' => Some(' '),
                    '"' => Some('"'),
                    '\\' => Some('\\'),
                    '/' => Some('/'),
                    'N' => Some('\u{85}'),
                    '_' => Some('\u{a0}'),
                    'L' => Some('\u{2028}'),
                    'P' => Some('\u{2029}'),
                    _ => None,
                };
                let code_length = match ch {
                    'x' => Some(2),
                    'u' => Some(4),
                    'U' => Some(8),
                    _ => None,
                };
                if let Some(r) = replacement {
                    chunks.push(r);
                    self.forward(1);
                } else if let Some(length) = code_length {
                    self.forward(1);
                    for k in 0..length {
                        if !HEX.contains(self.peek(k)) {
                            return err(
                                "while scanning a double-quoted scalar",
                                format!("expected escape sequence of {length} hexadecimal numbers, but found {:?}", self.peek(k)),
                                self.mark(),
                            );
                        }
                    }
                    let code = u32::from_str_radix(&self.prefix(length), 16).unwrap_or(u32::MAX);
                    match char::from_u32(code) {
                        Some(c) => chunks.push(c),
                        None if (0xd800..0xe000).contains(&code) => chunks.push('\u{fffd}'),
                        None => return err("while scanning a double-quoted scalar", format!("chr() arg not in range(0x110000): {code:#x}"), start),
                    }
                    self.forward(length);
                } else if BREAK.contains(ch) {
                    self.scan_line_break();
                    self.scan_flow_scalar_breaks(start, chunks)?;
                } else {
                    return err("while scanning a double-quoted scalar", format!("found unknown escape character {ch:?}"), self.mark());
                }
            } else {
                return Ok(());
            }
        }
    }

    fn scan_flow_scalar_spaces(&mut self, _double: bool, start: Mark, chunks: &mut String) -> Result<(), String> {
        let mut length = 0;
        while " \t".contains(self.peek(length)) {
            length += 1;
        }
        let whitespaces = self.prefix(length);
        self.forward(length);
        let ch = self.peek(0);
        if ch == '\0' {
            return err("while scanning a quoted scalar", "found unexpected end of stream".into(), self.mark());
        } else if BREAK.contains(ch) {
            let line_break = self.scan_line_break();
            let mut breaks = String::new();
            self.scan_flow_scalar_breaks(start, &mut breaks)?;
            if line_break != "\n" {
                chunks.push_str(&line_break);
            } else if breaks.is_empty() {
                chunks.push(' ');
            }
            chunks.push_str(&breaks);
        } else {
            chunks.push_str(&whitespaces);
        }
        Ok(())
    }

    fn scan_flow_scalar_breaks(&mut self, _start: Mark, chunks: &mut String) -> Result<(), String> {
        loop {
            let prefix = self.prefix(3);
            if (prefix == "---" || prefix == "...") && BLANKZ_TAB.contains(self.peek(3)) {
                return err("while scanning a quoted scalar", "found unexpected document separator".into(), self.mark());
            }
            while " \t".contains(self.peek(0)) {
                self.forward(1);
            }
            if BREAK.contains(self.peek(0)) {
                chunks.push_str(&self.scan_line_break());
            } else {
                return Ok(());
            }
        }
    }

    fn scan_plain(&mut self) -> String {
        let mut chunks = String::new();
        let indent = self.indent + 1;
        let mut spaces = String::new();
        loop {
            let mut length = 0;
            if self.peek(0) == '#' {
                break;
            }
            loop {
                let ch = self.peek(length);
                let after = self.peek(length + 1);
                if BLANKZ_TAB.contains(ch)
                    || (ch == ':' && (BLANKZ_TAB.contains(after) || (self.flow_level != 0 && ",[]{}".contains(after))))
                    || (self.flow_level != 0 && ",?[]{}".contains(ch))
                {
                    break;
                }
                length += 1;
            }
            if length == 0 {
                break;
            }
            self.allow_simple_key = false;
            chunks.push_str(&spaces);
            chunks.push_str(&self.prefix(length));
            self.forward(length);
            spaces = match self.scan_plain_spaces() {
                Some(s) => s,
                None => break,
            };
            if spaces.is_empty() || self.peek(0) == '#' || (self.flow_level == 0 && (self.column as i64) < indent) {
                break;
            }
        }
        chunks
    }

    /// The blanks and breaks after a plain scalar's line; `None` where a
    /// document separator follows.
    fn scan_plain_spaces(&mut self) -> Option<String> {
        let mut chunks = String::new();
        let mut length = 0;
        while self.peek(length) == ' ' {
            length += 1;
        }
        let whitespaces = self.prefix(length);
        self.forward(length);
        let ch = self.peek(0);
        let separator = |s: &Scanner| {
            let prefix = s.prefix(3);
            (prefix == "---" || prefix == "...") && BLANKZ_TAB.contains(s.peek(3))
        };
        if BREAK.contains(ch) {
            let line_break = self.scan_line_break();
            self.allow_simple_key = true;
            if separator(self) {
                return None;
            }
            let mut breaks = String::new();
            while " \r\n\u{85}\u{2028}\u{2029}".contains(self.peek(0)) {
                if self.peek(0) == ' ' {
                    self.forward(1);
                } else {
                    breaks.push_str(&self.scan_line_break());
                    if separator(self) {
                        return None;
                    }
                }
            }
            if line_break != "\n" {
                chunks.push_str(&line_break);
            } else if breaks.is_empty() {
                chunks.push(' ');
            }
            chunks.push_str(&breaks);
        } else if !whitespaces.is_empty() {
            chunks.push_str(&whitespaces);
        }
        Some(chunks)
    }

    fn scan_tag_handle(&mut self, name: &str, start: Mark) -> Result<String, String> {
        let context = format!("while scanning a {name}");
        if self.peek(0) != '!' {
            return err(&context, format!("expected '!', but found {:?}", self.peek(0)), start);
        }
        let mut length = 1;
        let mut ch = self.peek(length);
        if ch != ' ' {
            while word(ch) {
                length += 1;
                ch = self.peek(length);
            }
            if ch != '!' {
                self.forward(length);
                return err(&context, format!("expected '!', but found {ch:?}"), self.mark());
            }
            length += 1;
        }
        let value = self.prefix(length);
        self.forward(length);
        Ok(value)
    }

    fn scan_tag_uri(&mut self, name: &str, start: Mark) -> Result<String, String> {
        let mut chunks = String::new();
        let mut length = 0;
        let mut ch = self.peek(length);
        while ch.is_ascii_alphanumeric() || "-;/?:@&=+$,_.!~*'()[]%".contains(ch) {
            if ch == '%' {
                chunks.push_str(&self.prefix(length));
                self.forward(length);
                length = 0;
                chunks.push_str(&self.scan_uri_escapes(name, start)?);
            } else {
                length += 1;
            }
            ch = self.peek(length);
        }
        if length > 0 {
            chunks.push_str(&self.prefix(length));
            self.forward(length);
        }
        if chunks.is_empty() {
            return err(&format!("while parsing a {name}"), format!("expected URI, but found {ch:?}"), self.mark());
        }
        Ok(chunks)
    }

    fn scan_uri_escapes(&mut self, name: &str, start: Mark) -> Result<String, String> {
        let mut codes = Vec::new();
        while self.peek(0) == '%' {
            self.forward(1);
            for k in 0..2 {
                if !HEX.contains(self.peek(k)) {
                    return err(
                        &format!("while scanning a {name}"),
                        format!("expected URI escape sequence of 2 hexadecimal numbers, but found {:?}", self.peek(k)),
                        self.mark(),
                    );
                }
            }
            codes.push(u8::from_str_radix(&self.prefix(2), 16).unwrap_or(0));
            self.forward(2);
        }
        String::from_utf8(codes).or_else(|e| err(&format!("while scanning a {name}"), e.to_string(), start))
    }

    fn scan_line_break(&mut self) -> String {
        let ch = self.peek(0);
        if "\r\n\u{85}".contains(ch) {
            if self.prefix(2) == "\r\n" {
                self.forward(2);
            } else {
                self.forward(1);
            }
            return "\n".into();
        } else if "\u{2028}\u{2029}".contains(ch) {
            self.forward(1);
            return ch.to_string();
        }
        String::new()
    }
}

// --- parser.py

#[derive(Clone, Copy, Debug)]
enum State {
    StreamStart,
    ImplicitDocumentStart,
    DocumentStart,
    DocumentEnd,
    DocumentContent,
    BlockNode,
    BlockSequenceFirstEntry,
    BlockSequenceEntry,
    IndentlessSequenceEntry,
    BlockMappingFirstKey,
    BlockMappingKey,
    BlockMappingValue,
    FlowSequenceFirstEntry,
    FlowSequenceEntry,
    FlowSequenceEntryMappingKey,
    FlowSequenceEntryMappingValue,
    FlowSequenceEntryMappingEnd,
    FlowMappingFirstKey,
    FlowMappingKey,
    FlowMappingValue,
    FlowMappingEmptyValue,
}

/// Which token a check is for, by kind alone.
fn is(t: &Tok, kind: &str) -> bool {
    let k = match t {
        Tok::StreamStart => "stream-start",
        Tok::StreamEnd => "stream-end",
        Tok::Directive(_) => "directive",
        Tok::DocumentStart => "document-start",
        Tok::DocumentEnd => "document-end",
        Tok::BlockSequenceStart => "block-sequence-start",
        Tok::BlockMappingStart => "block-mapping-start",
        Tok::BlockEnd => "block-end",
        Tok::FlowSequenceStart => "flow-sequence-start",
        Tok::FlowMappingStart => "flow-mapping-start",
        Tok::FlowSequenceEnd => "flow-sequence-end",
        Tok::FlowMappingEnd => "flow-mapping-end",
        Tok::Key => "key",
        Tok::Value => "value",
        Tok::BlockEntry => "block-entry",
        Tok::FlowEntry => "flow-entry",
        Tok::Alias(_) => "alias",
        Tok::Anchor(_) => "anchor",
        Tok::Tag(..) => "tag",
        Tok::Scalar { .. } => "scalar",
    };
    kind.split(' ').any(|c| c == k)
}

pub struct Parser {
    scanner: Scanner,
    state: Option<State>,
    states: Vec<State>,
    marks: Vec<Mark>,
    tag_handles: HashMap<String, String>,
}

const DEFAULT_TAGS: [(&str, &str); 2] = [("!", "!"), ("!!", "tag:yaml.org,2002:")];

impl Parser {
    pub fn new(text: &str) -> Result<Parser, String> {
        Ok(Parser { scanner: Scanner::new(text)?, state: Some(State::StreamStart), states: Vec::new(), marks: Vec::new(), tag_handles: HashMap::new() })
    }

    fn check(&mut self, kinds: &str) -> Result<bool, String> {
        Ok(self.scanner.peek_token()?.is_some_and(|t| is(&t.tok, kinds)))
    }

    fn peek_mark(&mut self) -> Result<Mark, String> {
        Ok(self.scanner.peek_token()?.map(|t| t.mark).unwrap_or_default())
    }

    fn peek_kind(&mut self) -> Result<String, String> {
        Ok(self.scanner.peek_token()?.map(|t| format!("{:?}", t.tok)).unwrap_or_default())
    }

    fn pop_state(&mut self) -> Result<State, String> {
        self.states.pop().ok_or_else(|| "pop from empty list".to_string())
    }

    fn step(&mut self, state: State) -> Result<Event, String> {
        match state {
            State::StreamStart => {
                self.scanner.get_token()?;
                self.state = Some(State::ImplicitDocumentStart);
                Ok(Event::StreamStart)
            }
            State::ImplicitDocumentStart => {
                if !self.check("directive document-start stream-end")? {
                    self.tag_handles = DEFAULT_TAGS.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
                    self.states.push(State::DocumentEnd);
                    self.state = Some(State::BlockNode);
                    Ok(Event::DocumentStart)
                } else {
                    self.step(State::DocumentStart)
                }
            }
            State::DocumentStart => {
                while self.check("document-end")? {
                    self.scanner.get_token()?;
                }
                if !self.check("stream-end")? {
                    self.process_directives()?;
                    if !self.check("document-start")? {
                        let (kind, mark) = (self.peek_kind()?, self.peek_mark()?);
                        return err("", format!("expected '<document start>', but found {kind}"), mark);
                    }
                    self.scanner.get_token()?;
                    self.states.push(State::DocumentEnd);
                    self.state = Some(State::DocumentContent);
                    Ok(Event::DocumentStart)
                } else {
                    self.scanner.get_token()?;
                    self.state = None;
                    Ok(Event::StreamEnd)
                }
            }
            State::DocumentEnd => {
                if self.check("document-end")? {
                    self.scanner.get_token()?;
                }
                self.state = Some(State::DocumentStart);
                Ok(Event::DocumentEnd)
            }
            State::DocumentContent => {
                if self.check("directive document-start document-end stream-end")? {
                    self.state = Some(self.pop_state()?);
                    Ok(empty_scalar())
                } else {
                    self.parse_node(true, false)
                }
            }
            State::BlockNode => self.parse_node(true, false),
            State::BlockSequenceFirstEntry => {
                let t = self.scanner.get_token()?;
                self.marks.push(t.mark);
                self.step(State::BlockSequenceEntry)
            }
            State::BlockSequenceEntry => {
                if self.check("block-entry")? {
                    self.scanner.get_token()?;
                    if !self.check("block-entry block-end")? {
                        self.states.push(State::BlockSequenceEntry);
                        return self.parse_node(true, false);
                    }
                    self.state = Some(State::BlockSequenceEntry);
                    return Ok(empty_scalar());
                }
                if !self.check("block-end")? {
                    let (kind, mark) = (self.peek_kind()?, self.peek_mark()?);
                    return err("while parsing a block collection", format!("expected <block end>, but found {kind}"), mark);
                }
                self.scanner.get_token()?;
                self.state = Some(self.pop_state()?);
                self.marks.pop();
                Ok(Event::SequenceEnd)
            }
            State::IndentlessSequenceEntry => {
                if self.check("block-entry")? {
                    self.scanner.get_token()?;
                    if !self.check("block-entry key value block-end")? {
                        self.states.push(State::IndentlessSequenceEntry);
                        return self.parse_node(true, false);
                    }
                    self.state = Some(State::IndentlessSequenceEntry);
                    return Ok(empty_scalar());
                }
                self.state = Some(self.pop_state()?);
                Ok(Event::SequenceEnd)
            }
            State::BlockMappingFirstKey => {
                let t = self.scanner.get_token()?;
                self.marks.push(t.mark);
                self.step(State::BlockMappingKey)
            }
            State::BlockMappingKey => {
                if self.check("key")? {
                    self.scanner.get_token()?;
                    if !self.check("key value block-end")? {
                        self.states.push(State::BlockMappingValue);
                        return self.parse_node(true, true);
                    }
                    self.state = Some(State::BlockMappingValue);
                    return Ok(empty_scalar());
                }
                if !self.check("block-end")? {
                    let (kind, mark) = (self.peek_kind()?, self.peek_mark()?);
                    return err("while parsing a block mapping", format!("expected <block end>, but found {kind}"), mark);
                }
                self.scanner.get_token()?;
                self.state = Some(self.pop_state()?);
                self.marks.pop();
                Ok(Event::MappingEnd)
            }
            State::BlockMappingValue => {
                if self.check("value")? {
                    self.scanner.get_token()?;
                    if !self.check("key value block-end")? {
                        self.states.push(State::BlockMappingKey);
                        return self.parse_node(true, true);
                    }
                }
                self.state = Some(State::BlockMappingKey);
                Ok(empty_scalar())
            }
            State::FlowSequenceFirstEntry => {
                let t = self.scanner.get_token()?;
                self.marks.push(t.mark);
                self.flow_sequence_entry(true)
            }
            State::FlowSequenceEntry => self.flow_sequence_entry(false),
            State::FlowSequenceEntryMappingKey => {
                self.scanner.get_token()?;
                if !self.check("value flow-entry flow-sequence-end")? {
                    self.states.push(State::FlowSequenceEntryMappingValue);
                    return self.parse_node(false, false);
                }
                self.state = Some(State::FlowSequenceEntryMappingValue);
                Ok(empty_scalar())
            }
            State::FlowSequenceEntryMappingValue => {
                if self.check("value")? {
                    self.scanner.get_token()?;
                    if !self.check("flow-entry flow-sequence-end")? {
                        self.states.push(State::FlowSequenceEntryMappingEnd);
                        return self.parse_node(false, false);
                    }
                }
                self.state = Some(State::FlowSequenceEntryMappingEnd);
                Ok(empty_scalar())
            }
            State::FlowSequenceEntryMappingEnd => {
                self.state = Some(State::FlowSequenceEntry);
                Ok(Event::MappingEnd)
            }
            State::FlowMappingFirstKey => {
                let t = self.scanner.get_token()?;
                self.marks.push(t.mark);
                self.flow_mapping_key(true)
            }
            State::FlowMappingKey => self.flow_mapping_key(false),
            State::FlowMappingValue => {
                if self.check("value")? {
                    self.scanner.get_token()?;
                    if !self.check("flow-entry flow-mapping-end")? {
                        self.states.push(State::FlowMappingKey);
                        return self.parse_node(false, false);
                    }
                }
                self.state = Some(State::FlowMappingKey);
                Ok(empty_scalar())
            }
            State::FlowMappingEmptyValue => {
                self.state = Some(State::FlowMappingKey);
                Ok(empty_scalar())
            }
        }
    }

    fn process_directives(&mut self) -> Result<(), String> {
        let mut version = false;
        self.tag_handles.clear();
        while self.check("directive")? {
            let t = self.scanner.get_token()?;
            match t.tok {
                Tok::Directive(Directive::Yaml(major_is_one)) => {
                    if version {
                        return err("", "found duplicate YAML directive".into(), t.mark);
                    }
                    if !major_is_one {
                        return err("", "found incompatible YAML document (version 1.* is required)".into(), t.mark);
                    }
                    version = true;
                }
                Tok::Directive(Directive::Tag(handle, prefix)) => {
                    if self.tag_handles.contains_key(&handle) {
                        return err("", format!("duplicate tag handle {handle:?}"), t.mark);
                    }
                    self.tag_handles.insert(handle, prefix);
                }
                _ => {}
            }
        }
        for (k, v) in DEFAULT_TAGS {
            self.tag_handles.entry(k.to_string()).or_insert_with(|| v.to_string());
        }
        Ok(())
    }

    fn parse_node(&mut self, block: bool, indentless_sequence: bool) -> Result<Event, String> {
        if self.check("alias")? {
            let t = self.scanner.get_token()?;
            let Tok::Alias(anchor) = t.tok else { unreachable!("checked") };
            self.state = Some(self.pop_state()?);
            return Ok(Event::Alias { anchor });
        }
        let (mut anchor, mut tag) = (None, None);
        let mut start = None;
        if self.check("anchor")? {
            let t = self.scanner.get_token()?;
            start = Some(t.mark);
            if let Tok::Anchor(a) = t.tok {
                anchor = Some(a);
            }
            if self.check("tag")? {
                if let Tok::Tag(h, s) = self.scanner.get_token()?.tok {
                    tag = Some((h, s));
                }
            }
        } else if self.check("tag")? {
            let t = self.scanner.get_token()?;
            start = Some(t.mark);
            if let Tok::Tag(h, s) = t.tok {
                tag = Some((h, s));
            }
            if self.check("anchor")? {
                if let Tok::Anchor(a) = self.scanner.get_token()?.tok {
                    anchor = Some(a);
                }
            }
        }
        let tag = match tag {
            Some((Some(handle), suffix)) => match self.tag_handles.get(&handle) {
                Some(prefix) => Some(format!("{prefix}{suffix}")),
                None => return err("while parsing a node", format!("found undefined tag handle {handle:?}"), start.unwrap_or_default()),
            },
            Some((None, suffix)) => Some(suffix),
            None => None,
        };
        let implicit = tag.is_none() || tag.as_deref() == Some("!");
        if indentless_sequence && self.check("block-entry")? {
            self.state = Some(State::IndentlessSequenceEntry);
            return Ok(Event::SequenceStart { anchor, tag });
        }
        if self.check("scalar")? {
            let t = self.scanner.get_token()?;
            let Tok::Scalar { value, plain } = t.tok else { unreachable!("checked") };
            let implicit = (plain && tag.is_none()) || tag.as_deref() == Some("!");
            self.state = Some(self.pop_state()?);
            return Ok(Event::Scalar { anchor, tag, implicit, value });
        }
        if self.check("flow-sequence-start")? {
            self.state = Some(State::FlowSequenceFirstEntry);
            return Ok(Event::SequenceStart { anchor, tag });
        }
        if self.check("flow-mapping-start")? {
            self.state = Some(State::FlowMappingFirstKey);
            return Ok(Event::MappingStart { anchor, tag });
        }
        if block && self.check("block-sequence-start")? {
            self.state = Some(State::BlockSequenceFirstEntry);
            return Ok(Event::SequenceStart { anchor, tag });
        }
        if block && self.check("block-mapping-start")? {
            self.state = Some(State::BlockMappingFirstKey);
            return Ok(Event::MappingStart { anchor, tag });
        }
        if anchor.is_some() || tag.is_some() {
            self.state = Some(self.pop_state()?);
            return Ok(Event::Scalar { anchor, tag, implicit, value: String::new() });
        }
        let (kind, mark) = (self.peek_kind()?, self.peek_mark()?);
        let node = if block { "block" } else { "flow" };
        err(&format!("while parsing a {node} node"), format!("expected the node content, but found {kind}"), mark)
    }

    fn flow_sequence_entry(&mut self, first: bool) -> Result<Event, String> {
        if !self.check("flow-sequence-end")? {
            if !first {
                if self.check("flow-entry")? {
                    self.scanner.get_token()?;
                } else {
                    let (kind, mark) = (self.peek_kind()?, self.peek_mark()?);
                    return err("while parsing a flow sequence", format!("expected ',' or ']', but got {kind}"), mark);
                }
            }
            if self.check("key")? {
                self.state = Some(State::FlowSequenceEntryMappingKey);
                return Ok(Event::MappingStart { anchor: None, tag: None });
            } else if !self.check("flow-sequence-end")? {
                self.states.push(State::FlowSequenceEntry);
                return self.parse_node(false, false);
            }
        }
        self.scanner.get_token()?;
        self.state = Some(self.pop_state()?);
        self.marks.pop();
        Ok(Event::SequenceEnd)
    }

    fn flow_mapping_key(&mut self, first: bool) -> Result<Event, String> {
        if !self.check("flow-mapping-end")? {
            if !first {
                if self.check("flow-entry")? {
                    self.scanner.get_token()?;
                } else {
                    let (kind, mark) = (self.peek_kind()?, self.peek_mark()?);
                    return err("while parsing a flow mapping", format!("expected ',' or '}}', but got {kind}"), mark);
                }
            }
            if self.check("key")? {
                self.scanner.get_token()?;
                if !self.check("value flow-entry flow-mapping-end")? {
                    self.states.push(State::FlowMappingValue);
                    return self.parse_node(false, false);
                }
                self.state = Some(State::FlowMappingValue);
                return Ok(empty_scalar());
            } else if !self.check("flow-mapping-end")? {
                self.states.push(State::FlowMappingEmptyValue);
                return self.parse_node(false, false);
            }
        }
        self.scanner.get_token()?;
        self.state = Some(self.pop_state()?);
        self.marks.pop();
        Ok(Event::MappingEnd)
    }
}

fn empty_scalar() -> Event {
    Event::Scalar { anchor: None, tag: None, implicit: true, value: String::new() }
}

impl Iterator for Parser {
    type Item = Result<Event, String>;

    fn next(&mut self) -> Option<Self::Item> {
        let state = self.state.take()?;
        let ev = self.step(state);
        if ev.is_err() {
            self.state = None;
        }
        Some(ev)
    }
}
