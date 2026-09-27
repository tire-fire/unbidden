//! YAML read the way PyYAML's `safe_load` reads it, which is how cloud-init
//! reads its configuration: YAML 1.1 plain scalars, so `yes` and `on` are
//! booleans and `010` is octal; `<<` merge keys; a later duplicate key
//! replacing an earlier one; an unhashable key, an unknown tag or a second
//! document refusing the whole stream.
//!
//! saphyr-parser supplies the events and nothing else. The tree is built
//! here so that what a hostile file can cost is bounded here: nesting past
//! [`MAX_DEPTH`], or more than [`MAX_NODES`] nodes counting every copy an
//! alias makes, is an error rather than a stack overflow or a billion laughs.

use std::collections::HashMap;

use saphyr_parser::{Event, Parser, ScalarStyle};

pub const MAX_DEPTH: usize = 64;
pub const MAX_NODES: usize = 100_000;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i128),
    /// A float or a timestamp, kept as written: nothing here computes with
    /// one, and what matters is that it is not a string.
    Other(String),
    Str(String),
    Seq(Vec<Value>),
    Map(Vec<(Value, Value)>),
}

impl Value {
    /// The value under a string key of a mapping.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| matches!(k, Value::Str(s) if s == key)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Python's `str()` of a scalar. A float or timestamp comes back as
    /// written, which Python may print differently.
    pub fn python_str(&self) -> Option<String> {
        Some(match self {
            Value::Null => "None".into(),
            Value::Bool(true) => "True".into(),
            Value::Bool(false) => "False".into(),
            Value::Int(n) => n.to_string(),
            Value::Other(s) | Value::Str(s) => s.clone(),
            _ => return None,
        })
    }
}

/// Parses a stream holding at most one document. `Ok(None)` is an empty
/// one, which cloud-init reads as no configuration.
pub fn parse(text: &str) -> Result<Option<Value>, String> {
    let mut b = Builder::default();
    let mut docs = 0;
    for ev in Parser::new_from_str(text) {
        let (ev, _) = ev.map_err(|e| e.to_string())?;
        match ev {
            Event::DocumentStart(_) => {
                docs += 1;
                if docs > 1 {
                    return Err("more than one document".into());
                }
            }
            Event::SequenceStart(anchor, _) => b.open(Frame::Seq(Vec::new()), anchor)?,
            Event::MappingStart(anchor, _) => b.open(Frame::Map(Vec::new(), None), anchor)?,
            Event::SequenceEnd | Event::MappingEnd => b.close()?,
            Event::Scalar(text, style, anchor, tag) => {
                let tag = tag.map(|t| format!("{}{}", t.handle, t.suffix));
                let plain = style == ScalarStyle::Plain && tag.is_none();
                b.count(1)?;
                let item = match &*text {
                    "<<" if plain => Item::Merge,
                    "=" if plain => Item::Equals,
                    _ => Item::Value(scalar(&text, style, tag.as_deref())?),
                };
                b.push(item, anchor)?;
            }
            Event::Alias(id) => {
                let (v, depth) = b.anchors.get(&id).cloned().ok_or("alias to an undefined anchor")?;
                // What an alias pastes in counts towards the depth too, or a
                // chain of anchors each one level deeper would nest without
                // limit.
                if b.stack.len() + depth > MAX_DEPTH {
                    return Err(format!("nested deeper than {MAX_DEPTH}"));
                }
                b.count(size(&v))?;
                b.push(Item::Value(v), 0)?;
            }
            _ => {}
        }
    }
    Ok(b.done)
}

enum Frame {
    Seq(Vec<Value>),
    /// The pairs so far, and a key waiting for its value.
    Map(Vec<(Item, Value)>, Option<Item>),
}

/// A node as it arrives: a value, the `<<` that merges a mapping in, or a
/// plain `=`. PyYAML resolves the last two to tags it can construct only as
/// a mapping key, and the `=` one then as the string it is.
#[derive(Clone)]
enum Item {
    Value(Value),
    Merge,
    Equals,
}

#[derive(Default)]
struct Builder {
    stack: Vec<(Frame, usize)>,
    /// Each anchored value and how deeply it nests.
    anchors: HashMap<usize, (Value, usize)>,
    nodes: usize,
    done: Option<Value>,
}

impl Builder {
    fn count(&mut self, n: usize) -> Result<(), String> {
        self.nodes = self.nodes.saturating_add(n);
        if self.nodes > MAX_NODES {
            return Err(format!("more than {MAX_NODES} nodes"));
        }
        Ok(())
    }

    fn open(&mut self, f: Frame, anchor: usize) -> Result<(), String> {
        if self.stack.len() >= MAX_DEPTH {
            return Err(format!("nested deeper than {MAX_DEPTH}"));
        }
        self.count(1)?;
        self.stack.push((f, anchor));
        Ok(())
    }

    fn close(&mut self) -> Result<(), String> {
        let (f, anchor) = self.stack.pop().ok_or("unbalanced end")?;
        let v = match f {
            Frame::Seq(items) => Value::Seq(items),
            Frame::Map(pairs, None) => Value::Map(flatten(pairs)?),
            Frame::Map(_, Some(_)) => return Err("mapping ended after a key".into()),
        };
        self.push(Item::Value(v), anchor)
    }

    fn push(&mut self, item: Item, anchor: usize) -> Result<(), String> {
        let value = |item: Item| match item {
            Item::Value(v) => Ok(v),
            Item::Merge => Err("<< outside a mapping key".to_string()),
            Item::Equals => Err("= outside a mapping key".to_string()),
        };
        if anchor != 0
            && let Item::Value(v) = &item
        {
            self.anchors.insert(anchor, (v.clone(), depth(v)));
        }
        let Some((frame, _)) = self.stack.last_mut() else {
            self.done = Some(value(item)?);
            return Ok(());
        };
        match frame {
            Frame::Seq(items) => items.push(value(item)?),
            Frame::Map(pairs, key) => match key.take() {
                None if matches!(item, Item::Equals) => *key = Some(Item::Value(Value::Str("=".into()))),
                None => *key = Some(item),
                Some(k) => pairs.push((k, value(item)?)),
            },
        }
        Ok(())
    }
}

/// A mapping as PyYAML's constructor makes it: the mappings `<<` names
/// merged in first, a list of them with its earlier members winning, then
/// the mapping's own keys, a later one replacing an earlier one.
fn flatten(pairs: Vec<(Item, Value)>) -> Result<Vec<(Value, Value)>, String> {
    let mut merged: Vec<(Value, Value)> = Vec::new();
    let mut own: Vec<(Value, Value)> = Vec::new();
    for (k, v) in pairs {
        match k {
            Item::Equals => unreachable!("an = key is stored as its string"),
            Item::Merge => match v {
                Value::Map(m) => merged.extend(m),
                Value::Seq(maps) => {
                    for m in maps.into_iter().rev() {
                        let Value::Map(m) = m else { return Err("merge of a list holding a non-mapping".into()) };
                        merged.extend(m);
                    }
                }
                _ => return Err("merge of a non-mapping".into()),
            },
            Item::Value(k) => own.push((k, v)),
        }
    }
    let mut out: Vec<(Value, Value)> = Vec::new();
    for (k, v) in merged.into_iter().chain(own) {
        if matches!(k, Value::Seq(_) | Value::Map(_)) {
            return Err("unhashable key".into());
        }
        match out.iter_mut().find(|(e, _)| same_key(e, &k)) {
            Some(slot) => slot.1 = v,
            None => out.push((k, v)),
        }
    }
    Ok(out)
}

/// Python dict key equality, where `True == 1 == 1.0`.
fn same_key(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x == y,
        // PyYAML builds every .nan from one object, so they are one key.
        _ => match (number(a), number(b)) {
            (Some(x), Some(y)) => x == y || (x.is_nan() && y.is_nan()),
            _ => a == b,
        },
    }
}

/// A key's numeric value, for a bool, an int or a float, including one
/// tagged `!!float` that the float pattern would not match. A timestamp
/// has none.
fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        Value::Int(i) => Some(*i as f64),
        Value::Other(t) => {
            let t = t.replace('_', "").to_ascii_lowercase();
            let (neg, body) = match t.strip_prefix('-') {
                Some(b) => (true, b),
                None => (false, t.strip_prefix('+').unwrap_or(&t)),
            };
            let n = match body {
                ".inf" => f64::INFINITY,
                ".nan" => f64::NAN,
                b if b.contains(':') => b.split(':').try_fold(0.0, |n, p| p.parse::<f64>().ok().map(|x| n * 60.0 + x))?,
                b => b.parse::<f64>().ok()?,
            };
            Some(if neg { -n } else { n })
        }
        _ => None,
    }
}

fn depth(v: &Value) -> usize {
    match v {
        Value::Seq(s) => 1 + s.iter().map(depth).max().unwrap_or(0),
        Value::Map(m) => 1 + m.iter().map(|(k, v)| depth(k).max(depth(v))).max().unwrap_or(0),
        _ => 0,
    }
}

fn size(v: &Value) -> usize {
    match v {
        Value::Seq(s) => s.iter().fold(1, |n, v| n.saturating_add(size(v))),
        Value::Map(m) => m.iter().fold(1, |n, (k, v)| n.saturating_add(size(k)).saturating_add(size(v))),
        _ => 1,
    }
}

const TAG: &str = "tag:yaml.org,2002:";

/// A scalar as PyYAML's SafeLoader resolves and constructs it. A plain
/// scalar is resolved, and so is one tagged `!`; a quoted one, or one
/// tagged `!!str`, is a string. A tag SafeLoader has no constructor for fails the load.
fn scalar(text: &str, style: ScalarStyle, tag: Option<&str>) -> Result<Value, String> {
    let kind = match tag {
        None if style == ScalarStyle::Plain => resolve(text),
        // PyYAML resolves under the non-specific tag, quoted or not.
        Some("!") => resolve(text),
        None => "str",
        Some(t) => match t.strip_prefix(TAG) {
            Some(k @ ("str" | "null" | "bool" | "int" | "float" | "timestamp")) => k,
            _ => return Err(format!("no constructor for tag {t}")),
        },
    };
    Ok(match kind {
        "null" => Value::Null,
        "bool" => Value::Bool(matches!(text.to_ascii_lowercase().as_str(), "yes" | "true" | "on")),
        "int" => int(text).map(Value::Int).ok_or_else(|| format!("not an int: {text}"))?,
        "float" | "timestamp" => Value::Other(text.to_string()),
        _ => Value::Str(text.to_string()),
    })
}

/// Which of YAML 1.1's implicit types a plain scalar is, by PyYAML's
/// resolver patterns.
fn resolve(t: &str) -> &'static str {
    const NULL: [&str; 5] = ["", "~", "null", "Null", "NULL"];
    const BOOL: [&str; 18] = [
        "yes", "Yes", "YES", "no", "No", "NO", "true", "True", "TRUE", "false", "False", "FALSE", "on", "On", "ON", "off", "Off", "OFF",
    ];
    if NULL.contains(&t) {
        "null"
    } else if BOOL.contains(&t) {
        "bool"
    } else if int(t).is_some() {
        "int"
    } else if is_float(t) {
        "float"
    } else if is_timestamp(t) {
        "timestamp"
    } else {
        "str"
    }
}

/// PyYAML's int: binary, octal with a leading 0, decimal, hex, or base 60
/// with colons, underscores allowed after the first digit, an optional sign.
fn int(t: &str) -> Option<i128> {
    let (neg, body) = match t.as_bytes().first()? {
        b'-' => (true, &t[1..]),
        b'+' => (false, &t[1..]),
        _ => (false, t),
    };
    let digits = |s: &str, radix: u32| -> Option<i128> {
        let s: String = s.chars().filter(|c| *c != '_').collect();
        if s.is_empty() {
            return None;
        }
        i128::from_str_radix(&s, radix).ok()
    };
    let first_ok = |s: &str, f: fn(char) -> bool| s.chars().all(|c| c == '_' || f(c)) && !s.is_empty();
    let n = if let Some(b) = body.strip_prefix("0b") {
        first_ok(b, |c| matches!(c, '0' | '1')).then(|| digits(b, 2))??
    } else if let Some(h) = body.strip_prefix("0x") {
        first_ok(h, |c| c.is_ascii_hexdigit()).then(|| digits(h, 16))??
    } else if body == "0" {
        0
    } else if let Some(o) = body.strip_prefix('0') {
        first_ok(o, |c| matches!(c, '0'..='7')).then(|| digits(o, 8))??
    } else if body.contains(':') {
        let mut parts = body.split(':');
        let head = parts.next()?;
        if !head.starts_with(|c: char| matches!(c, '1'..='9')) || !first_ok(head, |c| c.is_ascii_digit()) {
            return None;
        }
        let mut n = digits(head, 10)?;
        for p in parts {
            let ok = matches!(p.len(), 1 | 2) && p.chars().all(|c| c.is_ascii_digit()) && (p.len() == 1 || p.as_bytes()[0] <= b'5');
            if !ok {
                return None;
            }
            n = n.checked_mul(60)?.checked_add(p.parse::<i128>().ok()?)?;
        }
        n
    } else {
        if !body.starts_with(|c: char| matches!(c, '1'..='9')) || !first_ok(body, |c| c.is_ascii_digit()) {
            return None;
        }
        digits(body, 10)?
    };
    Some(if neg { -n } else { n })
}

/// PyYAML's float pattern: digits and a dot (an exponent needs a sign),
/// a leading dot, base 60 with a dot, or the infinities and NaNs.
fn is_float(t: &str) -> bool {
    if matches!(t.trim_start_matches(['-', '+']), ".inf" | ".Inf" | ".INF") || matches!(t, ".nan" | ".NaN" | ".NAN") {
        return true;
    }
    let body = t.strip_prefix(['-', '+']).unwrap_or(t);
    let Some((int_part, rest)) = body.split_once('.') else { return false };
    let (frac, exp) = match rest.find(['e', 'E']) {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };
    let digits_ = |s: &str| s.chars().all(|c| c.is_ascii_digit() || c == '_');
    let exp_ok = exp.is_none_or(|e| e.len() > 1 && e.starts_with(['-', '+']) && e[1..].chars().all(|c| c.is_ascii_digit()));
    if !digits_(frac) || !exp_ok {
        return false;
    }
    if int_part.is_empty() {
        // `.5`, but no sign before a leading dot.
        return body == t && !frac.is_empty() && !frac.starts_with('_');
    }
    if int_part.contains(':') {
        let mut parts = int_part.split(':');
        let head = parts.next().unwrap_or_default();
        return exp.is_none()
            && head.starts_with(|c: char| c.is_ascii_digit())
            && digits_(head)
            && parts.all(|p| matches!(p.len(), 1 | 2) && p.chars().all(|c| c.is_ascii_digit()) && (p.len() == 1 || p.as_bytes()[0] <= b'5'));
    }
    int_part.starts_with(|c: char| c.is_ascii_digit()) && digits_(int_part)
}

/// PyYAML's timestamp: a date, optionally with a time after `T`, `t` or
/// whitespace.
fn is_timestamp(t: &str) -> bool {
    let b = t.as_bytes();
    let d = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    if !(d(0) && d(1) && d(2) && d(3) && b.get(4) == Some(&b'-')) {
        return false;
    }
    // Month and day are one or two digits in the long form, two in the
    // short one; the date alone must be exactly YYYY-MM-DD.
    let rest = &t[5..];
    let (date_rest, time) = match rest.find(['T', 't', ' ', '\t']) {
        Some(i) => (&rest[..i], Some(rest[i + 1..].trim_start_matches([' ', '\t']))),
        None => (rest, None),
    };
    let Some((m, day)) = date_rest.split_once('-') else { return false };
    let num = |s: &str, lens: &[usize]| lens.contains(&s.len()) && s.chars().all(|c| c.is_ascii_digit());
    match time {
        None => num(m, &[2]) && num(day, &[2]),
        Some(time) => {
            if !(num(m, &[1, 2]) && num(day, &[1, 2])) {
                return false;
            }
            let mut hms = time.splitn(3, ':');
            let (Some(h), Some(mi), Some(s)) = (hms.next(), hms.next(), hms.next()) else { return false };
            let sec_len = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
            num(h, &[1, 2]) && num(mi, &[2]) && sec_len == 2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(t: &str) -> Value {
        parse(t).unwrap().unwrap()
    }

    #[test]
    fn scalars_resolve_as_yaml_1_1() {
        let v = one("[yes, No, on, OFF, ~, '', 010, 0x1F, 0b101, 1_000, 190:20:30, -7, 1.5, 1e5, 2001-12-14, 'yes', !!str 12, 3.0e+2, .inf, 08]");
        let Value::Seq(items) = v else { panic!() };
        assert_eq!(
            items,
            [
                Value::Bool(true),
                Value::Bool(false),
                Value::Bool(true),
                Value::Bool(false),
                Value::Null,
                Value::Str(String::new()),
                Value::Int(8),
                Value::Int(31),
                Value::Int(5),
                Value::Int(1000),
                Value::Int(685230),
                Value::Int(-7),
                Value::Other("1.5".into()),
                Value::Str("1e5".into()),
                Value::Other("2001-12-14".into()),
                Value::Str("yes".into()),
                Value::Str("12".into()),
                Value::Other("3.0e+2".into()),
                Value::Other(".inf".into()),
                Value::Str("08".into()),
            ]
        );
    }

    #[test]
    fn merge_keys_duplicates_and_refusals_follow_pyyaml() {
        let v = one("base: &b {runcmd: [a], x: 1}\nother: &o {runcmd: [b], y: 2}\nm:\n  <<: [*b, *o]\n  x: 9\n  x: 10\n");
        let m = v.get("m").unwrap();
        assert_eq!(m.get("runcmd"), Some(&Value::Seq(vec![Value::Str("a".into())])), "the first mapping merged wins");
        assert_eq!(m.get("x"), Some(&Value::Int(10)), "the mapping's own key, the later one");
        assert_eq!(m.get("y"), Some(&Value::Int(2)));
        assert!(one("'<<': {a: 1}").get("<<").is_some(), "a quoted << is a key");
        assert_eq!(one("{1: a, true: b}"), Value::Map(vec![(Value::Int(1), Value::Str("b".into()))]));
        assert!(parse("a: 1\n---\nb: 2\n").is_err());
        assert!(parse("? [a]\n: 1\n").is_err(), "unhashable key");
        assert!(parse("a: !foo 1\n").is_err());
        assert!(parse("a: *nope\n").is_err());
        assert_eq!(parse("# nothing\n").unwrap(), None);
        assert!(parse("- <<\n").is_err() && parse("a: =\n").is_err());
        assert_eq!(one("{=: ! '12'}"), Value::Map(vec![(Value::Str("=".into()), Value::Int(12))]));
    }

    #[test]
    fn implicit_pairs_in_flow_sequences_hold_nested_collections() {
        // saphyr-parser 0.1.0 ended `k:`'s mapping at the first `,` inside
        // the `{}`; the vendored patch keeps the state per flow level.
        let s = |t: &str| Value::Str(t.into());
        let m = |pairs: Vec<(Value, Value)>| Value::Map(pairs);
        assert_eq!(one("[k: {a: b, c: d}]"), Value::Seq(vec![m(vec![(s("k"), m(vec![(s("a"), s("b")), (s("c"), s("d"))]))])]));
        assert_eq!(one("[{a: b}, k: v]"), Value::Seq(vec![m(vec![(s("a"), s("b"))]), m(vec![(s("k"), s("v"))])]));
        assert_eq!(one("[? a : b, c: d]"), Value::Seq(vec![m(vec![(s("a"), s("b"))]), m(vec![(s("c"), s("d"))])]));
        assert_eq!(one("[k: [b, c], j: 1]"), Value::Seq(vec![m(vec![(s("k"), Value::Seq(vec![s("b"), s("c")]))]), m(vec![(s("j"), Value::Int(1))])]));
        assert_eq!(
            one("[\n  k: {a: \"b\", c: d}, x]"),
            Value::Seq(vec![m(vec![(s("k"), m(vec![(s("a"), s("b")), (s("c"), s("d"))]))]), s("x")])
        );
    }

    #[test]
    fn hostile_input_is_bounded() {
        let mut laughs = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 0..12 {
            let p = (b'a' + i) as char;
            let n = (b'a' + i + 1) as char;
            laughs.push_str(&format!("{n}: &{n} [*{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}]\n"));
        }
        assert!(parse(&laughs).unwrap_err().contains("nodes"));
        let deep = "[".repeat(100_000);
        assert!(parse(&deep).is_err());
        let deep_block: String = (0..200).map(|i| format!("{}- \n", "  ".repeat(i))).collect();
        assert!(parse(&deep_block).is_err());
        // Each anchor one level deeper than the last, through aliases.
        let mut chain = String::from("a0: &a0 x\n");
        for i in 1..100 {
            chain.push_str(&format!("a{i}: &a{i} [*a{}]\n", i - 1));
        }
        assert!(parse(&chain).unwrap_err().contains("deeper"));
    }
}

