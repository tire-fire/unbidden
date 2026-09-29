//! Byte-text helpers that every reader of a hostile file needs. What comes off
//! a disk is bytes, not text, so nothing here assumes UTF-8.

/// The bytes as text for a note or a name, each invalid sequence shown as
/// U+FFFD. The original bytes stay wherever they are evidence.
pub fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Twelve hex digits of a hash: enough to tell apart the lines of one file
/// whose names are built from them, and short enough to read.
pub fn short_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex()[..12].to_string()
}

/// The first whitespace-separated word, and what follows it with its leading
/// whitespace gone. None when nothing but whitespace is left.
pub fn take_word(s: &[u8]) -> Option<(&[u8], &[u8])> {
    let s = s.trim_ascii_start();
    if s.is_empty() {
        return None;
    }
    let end = s.iter().position(|b| b.is_ascii_whitespace()).unwrap_or(s.len());
    Some((&s[..end], s[end..].trim_ascii_start()))
}

/// A shell-style glob with `*` and `?`, as sudoers includes and systemd
/// preset patterns use it.
pub fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0, 0);
    let (mut star, mut mark) = (usize::MAX, 0);
    while i < s.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == s[i]) {
            p += 1;
            i += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = p;
            p += 1;
            mark = i;
        } else if star != usize::MAX {
            p = star + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// A path with `.` and `..` resolved in the text rather than on disk, for what
/// an operator is shown: it matches how the root resolves a path (confined, so
/// a `..` above the root stays at the root) and keeps `..` out of paths that
/// would otherwise make one file look like two across a diff. Matching is done
/// against the kernel's answer, not this.
pub fn normalize(p: &std::path::Path) -> std::path::PathBuf {
    use std::path::Component;
    let mut out = std::path::PathBuf::new();
    for component in p.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => out.push(name),
            _ => {}
        }
    }
    out
}

/// Strips one matched pair of surrounding quotes, as pam_env and crond do.
pub fn unquote(v: &[u8]) -> &[u8] {
    match v {
        [q @ (b'"' | b'\''), inner @ .., last] if q == last => inner,
        _ => v,
    }
}

/// Whether `=` padding is required to make the length a multiple of four, or
/// whatever the alphabet decodes is taken up to the first `=` or the end.
#[derive(Clone, Copy, PartialEq)]
pub enum Padding {
    /// Standard alphabet with padding, refusing anything else, as apk's own
    /// table does.
    Required,
    /// An ssh key blob in an authorized_keys file, which sshd reads by what
    /// decodes.
    Optional,
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn sextet(b: u8) -> Option<u32> {
    match b {
        b'A'..=b'Z' => Some(u32::from(b - b'A')),
        b'a'..=b'z' => Some(u32::from(b - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(b - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Standard-alphabet base64, or None where the text is not.
pub fn base64_decode(text: &[u8], padding: Padding) -> Option<Vec<u8>> {
    let body = match padding {
        Padding::Required => {
            let body = text.iter().rev().skip_while(|b| **b == b'=').count();
            if text.len() % 4 != 0 || text.len() - body > 2 {
                return None;
            }
            &text[..body]
        }
        Padding::Optional => text.split(|b| *b == b'=').next().unwrap_or_default(),
    };
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    let (mut acc, mut bits) = (0u32, 0);
    for &c in body {
        acc = (acc << 6) | sextet(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Standard-alphabet base64 without padding, the way `ssh-keygen -lf` prints a
/// fingerprint.
pub fn base64_encode_unpadded(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = u32::from(c[0]) << 16 | u32::from(*c.get(1).unwrap_or(&0)) << 8 | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..c.len() + 1 {
            s.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

/// One `key=value` line of an INI-style file and where it sits.
#[derive(Debug, PartialEq)]
pub struct IniLine {
    /// Which header it is under, counted from 1; lines before the first header
    /// are block 0. Two headers of one name are two blocks.
    pub block: usize,
    pub section: String,
    pub key: String,
    pub value: Vec<u8>,
}

/// `[section]` headers and `key=value` lines. A line starting `#` or `;` is a
/// comment; both sides of the `=` are trimmed; a line with no `=` or an empty
/// key is dropped; a `[` line with no `]` is no header. What GKeyFile, SDDM's
/// reader and dnf's agree on; a file with its own rules (continuations,
/// interpolation) reads itself.
pub fn ini(bytes: &[u8]) -> Vec<IniLine> {
    let mut out = Vec::new();
    let (mut block, mut section) = (0, String::new());
    for line in bytes.split(|b| *b == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() || line[0] == b'#' || line[0] == b';' {
            continue;
        }
        if line[0] == b'[' {
            if let Some(end) = line.iter().position(|b| *b == b']') {
                block += 1;
                section = lossy(&line[1..end]);
            }
            continue;
        }
        let Some(eq) = line.iter().position(|b| *b == b'=') else { continue };
        let key = lossy(line[..eq].trim_ascii());
        if !key.is_empty() {
            out.push(IniLine { block, section: section.clone(), key, value: line[eq + 1..].trim_ascii().to_vec() });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matching_is_not_a_prefix_check() {
        assert!(glob_match(b"*.conf", b"10-evil.conf"));
        assert!(!glob_match(b"*.conf", b"notes.txt"));
        assert!(glob_match(b"sshd_config_?", b"sshd_config_1"));
        assert!(glob_match(b"*", b"anything"));
        assert!(!glob_match(b"a*b", b"ab_"));
        assert!(glob_match(b"a*b*c", b"axxbxxc"));
    }

    #[test]
    fn base64_reads_what_apk_and_ssh_keygen_read() {
        // apk's checksum table: padded, and nothing else.
        let strict = |t: &[u8]| base64_decode(t, Padding::Required);
        assert_eq!(strict(b"AAAA"), Some(vec![0, 0, 0]));
        assert_eq!(strict(b"AQ=="), Some(vec![1]));
        assert_eq!(strict(b"AQI="), Some(vec![1, 2]));
        assert_eq!(strict(b"AQ="), None, "length not a multiple of four");
        assert_eq!(strict(b"A?=="), None);
        // A key blob, unpadded as ssh-keygen prints it.
        let lenient = |t: &[u8]| base64_decode(t, Padding::Optional);
        assert_eq!(base64_encode_unpadded(&[]), "");
        assert_eq!(base64_encode_unpadded(b"a"), "YQ");
        assert_eq!(base64_encode_unpadded(b"abc"), "YWJj");
        assert_eq!(lenient(b"YWJj").unwrap(), b"abc");
        assert_eq!(lenient(b"YQ").unwrap(), b"a");
        assert!(lenient(b"not base64!").is_none());
    }

    #[test]
    fn paths_and_quotes_are_tidied_as_the_files_read_them_do() {
        assert_eq!(normalize(std::path::Path::new("/a/b/../c/./d")), std::path::PathBuf::from("a/c/d"));
        assert_eq!(normalize(std::path::Path::new("../../x")), std::path::PathBuf::from("x"), "stays inside the root");
        assert_eq!(unquote(b"\"a b\""), b"a b");
        assert_eq!(unquote(b"'x'"), b"x");
        assert_eq!(unquote(b"\"mixed'"), b"\"mixed'");
        assert_eq!(unquote(b"\""), b"\"");
    }

    #[test]
    fn an_ini_file_reads_sections_blocks_and_keys() {
        let lines = ini(b"stray = 0\n# c\n; c\n[main]\nenabled = 1\n  Name =  x y \n[broken\nignored\n[main]\nenabled=2\n=novalue\n");
        let got: Vec<(usize, &str, &str, &[u8])> = lines.iter().map(|l| (l.block, l.section.as_str(), l.key.as_str(), l.value.as_slice())).collect();
        assert_eq!(
            got,
            [
                (0, "", "stray", &b"0"[..]),
                (1, "main", "enabled", b"1"),
                (1, "main", "Name", b"x y"),
                (2, "main", "enabled", b"2"),
            ],
            "the unterminated header is no header and the empty key is dropped"
        );
    }

    #[test]
    fn a_word_and_the_rest() {
        assert_eq!(take_word(b"  install x  /bin/y "), Some((&b"install"[..], &b"x  /bin/y "[..])));
        assert_eq!(take_word(b"one"), Some((&b"one"[..], &b""[..])));
        assert_eq!(take_word(b"   \t "), None);
    }

    #[test]
    fn invalid_bytes_are_shown_not_dropped() {
        assert_eq!(lossy(b"a\xffb"), "a\u{fffd}b");
        assert_eq!(short_hash(b"x").len(), 12);
    }
}
