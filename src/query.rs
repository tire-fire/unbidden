//! The filter language the terminal UI and the HTML report share.
//!
//! A query is words separated by blanks. A bare word must appear, in any case,
//! in the entry's id, name, kind, command, source, target, principal, package
//! or any note. `field:value` narrows a word to one field, `-` in front of
//! either negates it, `a|b` in a value accepts either, and a value with blanks
//! is quoted: `cmd:"curl -s"`. A word whose field name is not one below is an
//! ordinary word, so `http://x` still searches for itself.
//!
//! | field      | matches                                                       |
//! |------------|---------------------------------------------------------------|
//! | `kind`     | the mechanism class, by prefix (`kind:systemd` or `kind:cron`)|
//! | `flag`     | any flag, by prefix; `flag:none` is an entry with no flag     |
//! | `enabled`  | the enablement, by prefix                                     |
//! | `trigger`  | what makes it run, by prefix                                  |
//! | `prov`     | `packaged`, `intact`, `modified`, `unpackaged`, `unknown`,    |
//! |            | `generated` or `reproduced`                                   |
//! | `pkg`      | the owning package's name                                     |
//! | `collector`| the collector that found it                                   |
//! | `user`     | the account it runs as                                        |
//! | `name`, `src`, `cmd`, `id` | those fields, as a substring (`id` as a prefix)|
//! | `note`     | a note, as `key=value` text                                   |
//!
//! The same grammar is implemented in the report's script; the tests below
//! are the contract for both.

use crate::entry::{Entry, Integrity, Provenance};

#[derive(Clone, Copy, PartialEq, Debug)]
enum Field {
    Kind,
    Flag,
    Enabled,
    Trigger,
    Prov,
    Pkg,
    Collector,
    User,
    Name,
    Src,
    Cmd,
    Id,
    Note,
}

const FIELDS: [(&str, Field); 13] = [
    ("kind", Field::Kind),
    ("flag", Field::Flag),
    ("enabled", Field::Enabled),
    ("trigger", Field::Trigger),
    ("prov", Field::Prov),
    ("pkg", Field::Pkg),
    ("collector", Field::Collector),
    ("user", Field::User),
    ("name", Field::Name),
    ("src", Field::Src),
    ("cmd", Field::Cmd),
    ("id", Field::Id),
    ("note", Field::Note),
];

#[derive(Debug)]
struct Term {
    negate: bool,
    field: Option<Field>,
    /// Lower case; the term holds if any of them does.
    any_of: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Query {
    terms: Vec<Term>,
}

/// The query's words, with quotes honoured and kept: `cmd:"a b"` is one.
fn words(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in text.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn unquote(value: &str) -> String {
    value.chars().filter(|c| *c != '"').collect()
}

fn parse_term(word: &str) -> Option<Term> {
    let (negate, rest) = match word.strip_prefix('-') {
        Some(r) if !r.is_empty() => (true, r),
        _ => (false, word),
    };
    let (field, value) = match rest.split_once(':') {
        Some((name, value)) => match FIELDS.iter().find(|(n, _)| *n == name.to_ascii_lowercase()) {
            Some((_, f)) => (Some(*f), value),
            None => (None, rest),
        },
        None => (None, rest),
    };
    let value = unquote(value).to_lowercase();
    if value.is_empty() {
        return None;
    }
    let any_of = if field.is_some() { value.split('|').filter(|v| !v.is_empty()).map(str::to_string).collect() } else { vec![value] };
    (!any_of.is_empty()).then_some(Term { negate, field, any_of })
}

impl Query {
    pub fn parse(text: &str) -> Query {
        Query { terms: words(text).iter().filter_map(|w| parse_term(w)).collect() }
    }

    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    pub fn matches(&self, e: &Entry) -> bool {
        self.terms.iter().all(|t| t.any_of.iter().any(|v| holds(t.field, v, e)) != t.negate)
    }
}

/// The provenance as one word a query can name.
pub fn provenance_words(p: &Provenance) -> Vec<&'static str> {
    match p {
        Provenance::Packaged { integrity: Integrity::Intact, .. } => vec!["packaged", "intact"],
        Provenance::Packaged { .. } => vec!["packaged", "modified"],
        Provenance::GeneratedBy { .. } => vec!["generated"],
        Provenance::Reproduced { .. } => vec!["reproduced"],
        Provenance::Unpackaged => vec!["unpackaged"],
        Provenance::Unknown => vec!["unknown"],
    }
}

fn lower(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_lowercase()
}

fn holds(field: Option<Field>, v: &str, e: &Entry) -> bool {
    let has = |s: &str| s.to_lowercase().contains(v);
    let command = || e.command.as_deref().map(lower).unwrap_or_default();
    let package = || match &e.provenance {
        Provenance::Packaged { package, .. } => package.to_lowercase(),
        _ => String::new(),
    };
    match field {
        Some(Field::Kind) => e.kind.as_str().starts_with(v),
        Some(Field::Flag) => {
            if v == "none" {
                e.flags.is_empty()
            } else {
                e.flags.iter().any(|f| f.as_str().starts_with(v))
            }
        }
        Some(Field::Enabled) => e.enabled.as_str().starts_with(v),
        Some(Field::Trigger) => e.trigger.as_str().starts_with(v),
        Some(Field::Prov) => provenance_words(&e.provenance).contains(&v),
        Some(Field::Pkg) => package().contains(v),
        Some(Field::Collector) => e.collector.as_deref().is_some_and(|c| c.to_lowercase().contains(v)),
        Some(Field::User) => e.principal.as_deref().is_some_and(|p| p.to_lowercase().contains(v)),
        Some(Field::Name) => has(&e.name),
        Some(Field::Src) => has(&e.source.to_string_lossy()),
        Some(Field::Cmd) => command().contains(v),
        Some(Field::Id) => e.id.starts_with(v),
        Some(Field::Note) => e.raw.iter().any(|(k, val)| has(&format!("{k}={val}"))),
        None => {
            has(&e.name)
                || has(&e.source.to_string_lossy())
                || e.id.starts_with(v)
                || e.kind.as_str().contains(v)
                || command().contains(v)
                || e.target_path.as_ref().is_some_and(|p| has(&p.to_string_lossy()))
                || e.principal.as_deref().is_some_and(has)
                || package().contains(v)
                || e.raw.iter().any(|(k, val)| has(k) || has(val))
        }
    }
}

/// Whether `field:value` is one of the alternatives of a word in the query.
pub fn has_choice(query: &str, field: &str, value: &str) -> bool {
    words(query).iter().any(|w| choices(w, field).is_some_and(|c| c.iter().any(|x| x == value)))
}

/// The alternatives of a non-negated `field:a|b` word.
fn choices(word: &str, field: &str) -> Option<Vec<String>> {
    let (name, value) = word.split_once(':')?;
    (name.eq_ignore_ascii_case(field) && !word.starts_with('-')).then(|| unquote(value).split('|').map(str::to_string).collect())
}

/// The query without any `field:` word, negated or not: what a picker for
/// that field counts against.
pub fn without_field(query: &str, field: &str) -> String {
    words(query)
        .into_iter()
        .filter(|w| {
            let w = w.strip_prefix('-').unwrap_or(w);
            !w.split_once(':').is_some_and(|(name, _)| name.eq_ignore_ascii_case(field))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The query with `value` added to its `field:` word, or taken from it: a
/// picker that edits the text keeps the text the one source of truth.
pub fn toggle_choice(query: &str, field: &str, value: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut found = false;
    for w in words(query) {
        match choices(&w, field) {
            Some(mut c) if !found => {
                found = true;
                if let Some(at) = c.iter().position(|x| x == value) {
                    c.remove(at);
                } else {
                    c.push(value.to_string());
                }
                if !c.is_empty() {
                    out.push(format!("{field}:{}", c.join("|")));
                }
            }
            _ => out.push(w),
        }
    }
    if !found {
        out.push(format!("{field}:{value}"));
    }
    out.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Flag, Kind};

    fn entry(kind: Kind, name: &str, cmd: &str) -> Entry {
        let mut e = Entry::new(kind, format!("/etc/{name}"), name);
        e.command = Some(cmd.as_bytes().to_vec());
        e
    }

    fn hits(q: &str, entries: &[Entry]) -> Vec<String> {
        let q = Query::parse(q);
        entries.iter().filter(|e| q.matches(e)).map(|e| e.name.clone()).collect()
    }

    #[test]
    fn words_fields_negation_and_alternatives() {
        let mut a = entry(Kind::Cron, "backup", "/usr/bin/curl -s http://x");
        a.provenance = Provenance::Unpackaged;
        a.flag(Flag::Unpackaged);
        let mut b = entry(Kind::SystemdUnit, "sshd.service", "/usr/sbin/sshd");
        b.provenance = Provenance::Packaged { package: "openssh".into(), version: "9".into(), integrity: Integrity::Intact };
        let mut c = entry(Kind::LdPreload, "evil.so", "LD_PRELOAD=/tmp/evil.so");
        c.note("env.LD_PRELOAD", "/tmp/evil.so");
        let all = [a, b, c];
        assert_eq!(hits("", &all).len(), 3, "an empty query keeps everything");
        assert_eq!(hits("CURL", &all), ["backup"], "a bare word ignores case");
        assert_eq!(hits("kind:cron", &all), ["backup"]);
        assert_eq!(hits("kind:cron|ld", &all), ["backup", "evil.so"], "a prefix, and either alternative");
        assert_eq!(hits("-kind:cron", &all), ["sshd.service", "evil.so"]);
        assert_eq!(hits("flag:unpackaged prov:unpackaged", &all), ["backup"]);
        assert_eq!(hits("flag:none", &all), ["sshd.service", "evil.so"]);
        assert_eq!(hits("prov:intact pkg:openssh", &all), ["sshd.service"]);
        assert_eq!(hits("cmd:\"curl -s\"", &all), ["backup"], "a quoted value keeps its blank");
        assert_eq!(hits("note:ld_preload=/tmp", &all), ["evil.so"]);
        assert_eq!(hits("LD_PRELOAD", &all), ["evil.so"], "a bare word reads the notes too");
        assert_eq!(hits("http://x", &all), ["backup"], "an unknown field name is ordinary text");
        assert_eq!(hits("sshd -kind:systemd", &all), Vec::<String>::new());
    }

    #[test]
    fn a_picker_edits_the_query_text() {
        assert_eq!(toggle_choice("", "kind", "cron"), "kind:cron");
        assert_eq!(toggle_choice("kind:cron", "kind", "udev"), "kind:cron|udev");
        assert_eq!(toggle_choice("kind:cron|udev", "kind", "cron"), "kind:udev");
        assert_eq!(toggle_choice("kind:udev curl", "kind", "udev"), "curl");
        assert_eq!(toggle_choice("curl", "flag", "x"), "curl flag:x");
        assert!(has_choice("a kind:cron|udev", "kind", "udev"));
        assert!(!has_choice("-kind:udev", "kind", "udev"), "a negated word is not a choice");
        assert_eq!(without_field("curl -kind:cron kind:udev flag:x", "kind"), "curl flag:x");
    }
}
