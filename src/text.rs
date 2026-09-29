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
