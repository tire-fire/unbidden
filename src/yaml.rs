//! YAML read the way PyYAML's `safe_load` reads it, which is how cloud-init
//! reads its configuration: YAML 1.1 plain scalars, so `yes` and `on` are
//! booleans and `010` is octal; `<<` merge keys; a later duplicate key
//! replacing an earlier one; an unhashable key, an unknown tag or a second
//! document refusing the whole stream.
//!
//! [`crate::pyyaml`], a port of the pure-Python reader, scanner and parser
//! SafeLoader runs, supplies the events and nothing else. The tree is built here so that what a hostile
//! file can cost is bounded here: nesting past [`MAX_DEPTH`], or more than
//! [`MAX_NODES`] nodes counting every copy an alias makes, is an error rather
//! than a stack overflow or a billion laughs.

use std::collections::HashMap;

use crate::pyyaml::{Event, Parser};

/// Above what PyYAML reaches before Python's recursion limit stops it:
/// 491 levels measured with 6.0.1, and fewer inside cloud-init, whose own
/// frames count against the same limit. A lower bound would refuse a file
/// cloud-init loads, and every command in it would go unread.
pub const MAX_DEPTH: usize = 512;
/// A flow mapping of bare keys makes two nodes out of two bytes (`{a,b}` is
/// `a: null, b: null`), so a node can take one byte of text and this is the
/// most a file the collectors read whole can hold. PyYAML loads it, and a
/// budget below that would refuse a file cloud-init loads and leave every
/// command in it unread. What an alias copies is charged against it too.
pub const MAX_NODES: usize = crate::root::READ_CAP + 16;

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
    for ev in Parser::new(text)? {
        match ev? {
            Event::DocumentStart => {
                docs += 1;
                if docs > 1 {
                    return Err("more than one document".into());
                }
            }
            Event::SequenceStart { anchor, tag } => {
                let anchor = b.anchor_id(anchor)?;
                let shape = shape(tag.as_deref(), false)?;
                b.open(Frame::Seq(Vec::new(), shape), anchor)?;
            }
            Event::MappingStart { anchor, tag } => {
                let anchor = b.anchor_id(anchor)?;
                let shape = shape(tag.as_deref(), true)?;
                b.open(Frame::Map(Vec::new(), None, shape), anchor)?;
            }
            Event::SequenceEnd | Event::MappingEnd => b.close()?,
            Event::Scalar { anchor, tag, implicit, value } => {
                let anchor = b.anchor_id(anchor)?;
                b.count(1)?;
                // The resolver runs where PyYAML's composer lets it: a plain
                // scalar with no tag, or any tagged `!`.
                let item = match &*value {
                    "<<" if implicit => Item::Merge,
                    "=" if implicit => Item::Equals,
                    _ => Item::Value(scalar(&value, implicit, tag.as_deref())?),
                };
                b.push(item, anchor)?;
            }
            Event::Alias { anchor } => {
                let id = b.names.get(&anchor).copied().ok_or("alias to an undefined anchor")?;
                // Cost and depth are read off the anchor before it is copied,
                // so an alias the budget refuses allocates nothing.
                let (cost, depth) = {
                    let (v, depth) = b.anchors.get(&id).ok_or("alias to an undefined anchor")?;
                    (size(v), *depth)
                };
                // What an alias pastes in counts towards the depth too, or a
                // chain of anchors each one level deeper would nest without
                // limit.
                if b.stack.len() + depth > MAX_DEPTH {
                    return Err(format!("nested deeper than {MAX_DEPTH}"));
                }
                b.count(cost)?;
                let (v, _) = b.anchors.get(&id).cloned().ok_or("alias to an undefined anchor")?;
                b.push(Item::Value(v), 0)?;
            }
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
        }
    }
    Ok(b.done)
}

enum Frame {
    Seq(Vec<Value>, Shape),
    /// The pairs so far, and a key waiting for its value.
    Map(Vec<(Item, Value)>, Option<Item>, Shape),
}

/// What SafeConstructor builds of a collection, by its tag.
#[derive(Clone, Copy, PartialEq)]
enum Shape {
    /// A list or a dict: untagged, `!`, `!!seq` or `!!map`.
    Plain,
    /// `!!set`, a mapping whose keys are the set.
    Set,
    /// `!!omap` or `!!pairs`, a sequence of one-pair mappings, built as a
    /// list of `[key, value]`.
    Pairs,
}

/// The shape a tag gives a collection, or the error SafeConstructor raises
/// for a tag it has no constructor for, or one that does not fit the node.
fn shape(tag: Option<&str>, mapping: bool) -> Result<Shape, String> {
    let kind = match tag {
        None | Some("!") => return Ok(Shape::Plain),
        Some(t) => t.strip_prefix(TAG).unwrap_or(t),
    };
    match (kind, mapping) {
        ("map", true) | ("seq", false) => Ok(Shape::Plain),
        ("set", true) => Ok(Shape::Set),
        ("omap" | "pairs", false) => Ok(Shape::Pairs),
        ("map" | "set", false) => Err(format!("expected a mapping node for {}", tag.unwrap_or_default())),
        ("seq" | "omap" | "pairs", true) => Err(format!("expected a sequence node for {}", tag.unwrap_or_default())),
        _ => Err(format!("no constructor for tag {}", tag.unwrap_or_default())),
    }
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
    /// Each anchored value and how deeply it nests, by anchor id.
    anchors: HashMap<usize, (Value, usize)>,
    /// Anchor names to ids; each name is defined once.
    names: HashMap<String, usize>,
    nodes: usize,
    done: Option<Value>,
}

impl Builder {
    /// An anchor's id; 0 is none. PyYAML's composer refuses a name
    /// defined twice.
    fn anchor_id(&mut self, name: Option<String>) -> Result<usize, String> {
        let Some(name) = name else { return Ok(0) };
        if self.names.contains_key(&name) {
            return Err(format!("found duplicate anchor {name:?}"));
        }
        let id = self.names.len() + 1;
        self.names.insert(name, id);
        Ok(id)
    }

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
            Frame::Seq(items, Shape::Pairs) => Value::Seq(
                items
                    .into_iter()
                    .map(|item| match item {
                        Value::Map(mut m) if m.len() == 1 => {
                            let (k, v) = m.remove(0);
                            Ok(Value::Seq(vec![k, v]))
                        }
                        _ => Err("an ordered map holds a mapping of one pair per item".to_string()),
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Frame::Seq(items, _) => Value::Seq(items),
            Frame::Map(pairs, None, Shape::Set) => Value::Map(flatten(pairs)?.into_iter().map(|(k, _)| (k, Value::Null)).collect()),
            Frame::Map(pairs, None, _) => Value::Map(flatten(pairs)?),
            Frame::Map(_, Some(_), _) => return Err("mapping ended after a key".into()),
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
            Frame::Seq(items, _) => items.push(value(item)?),
            Frame::Map(pairs, key, _) => match key.take() {
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
    let mut index: HashMap<Key, usize> = HashMap::new();
    for (k, v) in merged.into_iter().chain(own) {
        let key = Key::of(&k).ok_or("unhashable key")?;
        match index.get(&key) {
            Some(&i) => out[i].1 = v,
            None => {
                index.insert(key, out.len());
                out.push((k, v));
            }
        }
    }
    Ok(out)
}

/// A mapping key as Python's dict compares it: `True == 1 == 1.0`, and every
/// `.nan` one key, since PyYAML builds them all from one object.
#[derive(PartialEq, Eq, Hash)]
enum Key {
    Null,
    Int(i128),
    Float(u64),
    Nan,
    Str(String),
    Other(String),
}

impl Key {
    /// `None` for a sequence or mapping, which is unhashable.
    fn of(v: &Value) -> Option<Key> {
        Some(match v {
            Value::Null => Key::Null,
            Value::Int(i) => Key::Int(*i),
            Value::Str(s) => Key::Str(s.clone()),
            Value::Seq(_) | Value::Map(_) => return None,
            _ => match number(v) {
                Some(n) if n.is_nan() => Key::Nan,
                // An integral float is the int it equals.
                Some(n) if n.fract() == 0.0 && n.abs() < 1e36 => Key::Int(n as i128),
                Some(n) => Key::Float(n.to_bits()),
                None => Key::Other(v.python_str().unwrap_or_default()),
            },
        })
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

/// What pasting `v` in costs against `MAX_NODES`: one per node, and one more
/// per 64 bytes of text. A node budget alone bounds the tree and not the
/// bytes in it: a 600 KB scalar aliased thirty thousand times is thirty
/// thousand nodes and eighteen gigabytes, which aborted the whole process
/// (an allocation failure no `catch_unwind` can catch).
fn size(v: &Value) -> usize {
    match v {
        Value::Seq(s) => s.iter().fold(1, |n, v| n.saturating_add(size(v))),
        Value::Map(m) => m.iter().fold(1, |n, (k, v)| n.saturating_add(size(k)).saturating_add(size(v))),
        Value::Str(s) | Value::Other(s) => 1 + s.len() / 64,
        _ => 1,
    }
}

const TAG: &str = "tag:yaml.org,2002:";

/// A scalar as PyYAML's SafeLoader resolves and constructs it. A plain
/// scalar is resolved, and so is one tagged `!`; a quoted one, or one
/// tagged `!!str`, is a string. A tag SafeLoader has no constructor for fails the load.
fn scalar(text: &str, plain: bool, tag: Option<&str>) -> Result<Value, String> {
    let kind = match tag {
        None if plain => resolve(text),
        // PyYAML resolves under the non-specific tag, quoted or not.
        Some("!") => resolve(text),
        None => "str",
        Some(t) => match t.strip_prefix(TAG) {
            Some(k @ ("str" | "null" | "bool" | "int" | "float" | "timestamp")) => k,
            Some("binary") => return binary(text),
            _ => return Err(format!("no constructor for tag {t}")),
        },
    };
    Ok(match kind {
        "null" => Value::Null,
        "bool" => match text.to_lowercase().as_str() {
            "yes" | "true" | "on" => Value::Bool(true),
            "no" | "false" | "off" => Value::Bool(false),
            _ => return Err(format!("not a bool: {text}")),
        },
        "int" => construct_int(text)?,
        "timestamp" => match timestamp(text, false) {
            Some(ts) if timestamp_valid(&ts) => Value::Other(text.to_string()),
            _ => return Err(format!("not a timestamp datetime accepts: {text}")),
        },
        "float" => construct_float(text)?,
        _ => Value::Str(text.to_string()),
    })
}

/// `!!binary`, as SafeConstructor builds it: ASCII text that
/// `base64.decodebytes` accepts, which is binascii's `a2b_base64` outside
/// strict mode. Characters outside the alphabet are skipped; enough `=`
/// after two or three characters of a group ends the data; a group left
/// part-filled is an error.
fn binary(text: &str) -> Result<Value, String> {
    if !text.is_ascii() {
        return Err("!!binary holds a non-ASCII character".into());
    }
    let (mut quad_pos, mut pads) = (0u32, 0u32);
    for c in text.bytes() {
        if c == b'=' {
            if quad_pos >= 2 {
                pads += 1;
                if quad_pos + pads >= 4 {
                    quad_pos = 0;
                    break;
                }
            }
            continue;
        }
        if !(c.is_ascii_alphanumeric() || c == b'+' || c == b'/') {
            continue;
        }
        pads = 0;
        quad_pos = (quad_pos + 1) % 4;
    }
    match quad_pos {
        0 => Ok(Value::Other("binary".into())),
        1 => Err("!!binary: a base64 length one more than a multiple of four".into()),
        _ => Err("!!binary: incorrect padding".into()),
    }
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
    } else if int_syntax(t) {
        "int"
    } else if is_float(t) {
        "float"
    } else if timestamp(t, true).is_some() {
        "timestamp"
    } else {
        "str"
    }
}

/// PyYAML's int pattern: binary, octal with a leading 0, decimal, hex, or
/// base 60 with colons, underscores anywhere after the prefix, one sign.
fn int_syntax(t: &str) -> bool {
    let body = t.strip_prefix(['-', '+']).unwrap_or(t);
    let all = |s: &str, f: fn(char) -> bool| !s.is_empty() && s.chars().all(|c| c == '_' || f(c));
    if let Some(b) = body.strip_prefix("0b") {
        return all(b, |c| matches!(c, '0' | '1'));
    }
    if let Some(h) = body.strip_prefix("0x") {
        return all(h, |c| c.is_ascii_hexdigit());
    }
    if body == "0" {
        return true;
    }
    if let Some(o) = body.strip_prefix('0') {
        return all(o, |c| matches!(c, '0'..='7'));
    }
    if !body.starts_with(|c: char| matches!(c, '1'..='9')) {
        return false;
    }
    let mut parts = body.split(':');
    let head = parts.next().unwrap_or_default();
    if !all(head, |c| c.is_ascii_digit()) {
        return false;
    }
    // Each `:` part is `[0-5]?[0-9]`.
    parts.all(|p| {
        let b = p.as_bytes();
        match b {
            [d] => d.is_ascii_digit(),
            [a, d] => (b'0'..=b'5').contains(a) && d.is_ascii_digit(),
            _ => false,
        }
    })
}

/// Python's `int(s, radix)`: white space around, one sign, the base's
/// own `0b`, `0o` or `0x` prefix allowed, then at least one digit. Whether
/// it converts, and the value where it fits in i128.
fn python_int(s: &str, radix: u32) -> Option<Option<i128>> {
    let s = s.trim_matches(|c: char| c.is_whitespace());
    let (neg, body) = match s.as_bytes().first()? {
        b'-' => (true, &s[1..]),
        b'+' => (false, &s[1..]),
        _ => (false, s),
    };
    let prefix = match radix {
        2 => Some("0b"),
        8 => Some("0o"),
        16 => Some("0x"),
        _ => None,
    };
    let digits = match prefix {
        // `get`, not an index: a multibyte character can straddle byte 2
        // (`0€`), and slicing there panics.
        Some(p) if body.len() > 2 && body.get(..2).is_some_and(|h| h.eq_ignore_ascii_case(p)) => &body[2..],
        _ => body,
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    Some(i128::from_str_radix(digits, radix).ok().map(|n| if neg { -n } else { n }))
}

/// Python's `float(s)` on text already lowercased: white space around, one
/// sign, then `inf`, `infinity`, `nan`, or digits with an optional point
/// and exponent.
fn python_float(s: &str) -> bool {
    let s = s.trim_matches(|c: char| c.is_whitespace());
    let body = s.strip_prefix(['-', '+']).unwrap_or(s);
    if matches!(body, "inf" | "infinity" | "nan") {
        return true;
    }
    let (mantissa, exp) = match body.split_once('e') {
        Some((m, e)) => (m, Some(e)),
        None => (body, None),
    };
    let (whole, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all = |d: &str| d.chars().all(|c| c.is_ascii_digit());
    let mantissa_ok = all(whole) && all(frac) && !(whole.is_empty() && frac.is_empty());
    let exp_ok = exp.is_none_or(|e| {
        let e = e.strip_prefix(['-', '+']).unwrap_or(e);
        !e.is_empty() && all(e)
    });
    mantissa_ok && exp_ok
}

/// SafeConstructor's `construct_yaml_int`: underscores dropped, one sign
/// taken, then by prefix binary, hex, octal after a 0, base 60 with colons,
/// or decimal, each through Python's `int`. A value past i128 is kept as
/// written, since Python's ints have no bound; `Err` is text Python cannot
/// convert.
fn construct_int(t: &str) -> Result<Value, String> {
    let fail = || format!("not an int: {t}");
    let v: String = t.chars().filter(|c| *c != '_').collect();
    let (neg, body) = match v.as_bytes().first() {
        Some(b'-') => (true, &v[1..]),
        Some(b'+') => (false, &v[1..]),
        Some(_) => (false, &v[..]),
        None => return Err(fail()),
    };
    let n = if body == "0" {
        Some(0)
    } else if let Some(b) = body.strip_prefix("0b") {
        python_int(b, 2).ok_or_else(fail)?
    } else if let Some(h) = body.strip_prefix("0x") {
        python_int(h, 16).ok_or_else(fail)?
    } else if body.starts_with('0') {
        python_int(body, 8).ok_or_else(fail)?
    } else if body.contains(':') {
        let mut n = Some(0i128);
        for p in body.split(':') {
            let d = python_int(p, 10).ok_or_else(fail)?;
            n = n.and_then(|n| n.checked_mul(60)).zip(d).and_then(|(n, d)| n.checked_add(d));
        }
        n
    } else {
        python_int(body, 10).ok_or_else(fail)?
    };
    Ok(match n.and_then(|n| if neg { n.checked_neg() } else { Some(n) }) {
        Some(n) => Value::Int(n),
        None => Value::Other(t.to_string()),
    })
}

/// SafeConstructor's `construct_yaml_float`: underscores dropped,
/// lowercased, one sign taken, then `.inf`, `.nan`, base 60 with colons,
/// or Python's `float`.
fn construct_float(t: &str) -> Result<Value, String> {
    let v = t.replace('_', "").to_lowercase();
    let body = v.strip_prefix(['-', '+']).unwrap_or(&v);
    if v.is_empty() {
        return Err(format!("not a float: {t}"));
    }
    let ok = matches!(body, ".inf" | ".nan") || if body.contains(':') { body.split(':').all(python_float) } else { python_float(body) };
    if ok { Ok(Value::Other(t.to_string())) } else { Err(format!("not a float: {t}")) }
}

/// PyYAML's float pattern: digits and a dot (an exponent needs a sign),
/// a leading dot, base 60 with a dot, or the infinities and NaNs.
fn is_float(t: &str) -> bool {
    if matches!(t.strip_prefix(['-', '+']).unwrap_or(t), ".inf" | ".Inf" | ".INF") || matches!(t, ".nan" | ".NaN" | ".NAN") {
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

/// A timestamp's fields as PyYAML's `timestamp_regexp` reads them: a
/// date of one- or two-digit month and day, then optionally `T`, `t` or
/// blanks, a time to the second, a fraction and a zone. `short` is the
/// resolver's own pattern, which wants the two-digit date when there is no
/// time.
struct Timestamp {
    date: (u32, u32, u32),
    time: Option<(u32, u32, u32)>,
    zone: Option<(u32, u32)>,
}

fn timestamp(t: &str, short: bool) -> Option<Timestamp> {
    let b = t.as_bytes();
    let mut i = 0;
    let digits = |i: &mut usize, min: usize, max: usize| -> Option<u32> {
        let start = *i;
        while *i < b.len() && *i - start < max && b[*i].is_ascii_digit() {
            *i += 1;
        }
        if *i - start < min {
            return None;
        }
        t[start..*i].parse().ok()
    };
    let lit = |i: &mut usize, c: u8| -> Option<()> {
        (b.get(*i) == Some(&c)).then(|| *i += 1)
    };
    let year = digits(&mut i, 4, 4)?;
    lit(&mut i, b'-')?;
    let month = digits(&mut i, 1, 2)?;
    lit(&mut i, b'-')?;
    let day = digits(&mut i, 1, 2)?;
    if i == b.len() {
        return (!short || t.len() == 10).then_some(Timestamp { date: (year, month, day), time: None, zone: None });
    }
    match b[i] {
        b'T' | b't' => i += 1,
        b' ' | b'\t' => {
            while matches!(b.get(i), Some(b' ' | b'\t')) {
                i += 1;
            }
        }
        _ => return None,
    }
    let hour = digits(&mut i, 1, 2)?;
    lit(&mut i, b':')?;
    let minute = digits(&mut i, 2, 2)?;
    lit(&mut i, b':')?;
    let second = digits(&mut i, 2, 2)?;
    if lit(&mut i, b'.').is_some() {
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    let before_blanks = i;
    while matches!(b.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    let zone = match b.get(i) {
        Some(b'Z') => {
            i += 1;
            Some((0, 0))
        }
        Some(b'-' | b'+') => {
            i += 1;
            let h = digits(&mut i, 1, 2)?;
            let m = if lit(&mut i, b':').is_some() { digits(&mut i, 2, 2)? } else { 0 };
            Some((h, m))
        }
        _ => {
            i = before_blanks;
            None
        }
    };
    (i == b.len()).then_some(Timestamp { date: (year, month, day), time: Some((hour, minute, second)), zone })
}

/// What `datetime` refuses when SafeConstructor builds the value, which
/// fails the whole load: a date or time out of range, or a zone offset of a
/// day or more.
fn timestamp_valid(ts: &Timestamp) -> bool {
    let (y, m, d) = ts.date;
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if y == 0 || d == 0 || d > days {
        return false;
    }
    if let Some((h, mi, s)) = ts.time
        && (h > 23 || mi > 59 || s > 59)
    {
        return false;
    }
    ts.zone.is_none_or(|(h, m)| h * 60 + m < 24 * 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(t: &str) -> Value {
        parse(t).unwrap().unwrap()
    }

    #[test]
    fn what_panicked_libyaml_safer_is_an_error_as_in_pyyaml() {
        assert!(parse("[!,").is_err());
        assert!(parse("a: ''|\n 0").is_err());
        assert!(parse("[!x,]").is_err(), "PyYAML wants a blank after a tag");
    }

    #[test]
    fn an_integer_tag_on_multibyte_text_is_an_error_not_a_panic() {
        // PyYAML raises ValueError for these; the file then reads as empty.
        for text in ["a: !!int \"0x\u{20ac}1\"", "a: !!int \"\u{20ac}\u{20ac}\"", "a: !!int \"-0b\u{20ac}\"", "a: !!int \"0o\u{20ac}\u{20ac}\""] {
            let _ = parse(text);
        }
        assert!(parse("a: !!int \"0x\u{20ac}1\"").is_err());
    }

    #[test]
    fn every_file_the_collectors_read_whole_fits_the_budget() {
        // A byte a node, the densest text there is, up to the read cap: a
        // flow mapping of bare keys is a key and a null for every two bytes.
        let items = (crate::root::READ_CAP - 16) / 2;
        let doc = format!("{{{}}}", "a,".repeat(items));
        assert!(doc.len() <= crate::root::READ_CAP);
        assert!(parse(&doc).is_ok(), "refused a file within the read cap");
        let doc = format!("[{}]", "a,".repeat(items));
        match parse(&doc) {
            Ok(Some(Value::Seq(v))) => assert_eq!(v.len(), items),
            other => panic!("refused a file within the read cap: {:?}", other.err()),
        }
    }

    #[test]
    fn an_alias_is_charged_for_the_bytes_it_pastes_in() {
        // Without the byte charge this document is 4,000 nodes and 800 MB.
        let big = "x".repeat(200_000);
        let mut doc = format!("a: &big \"{big}\"\nl:\n");
        for _ in 0..4_000 {
            doc.push_str("  - *big\n");
        }
        assert!(parse(&doc).is_err(), "refused by the budget rather than expanded");
        // A few uses of a large value, and many of a small one, still load.
        let mut ok = format!("a: &big \"{}\"\nl:\n", "x".repeat(2_000));
        for _ in 0..50 {
            ok.push_str("  - *big\n");
        }
        assert!(parse(&ok).is_ok());
        let mut many = String::from("a: &s x\nl:\n");
        for _ in 0..20_000 {
            many.push_str("  - *s\n");
        }
        assert!(parse(&many).is_ok());
    }

    #[test]
    fn nesting_pyyaml_loads_is_read() {
        let deep = |d: usize| format!("runcmd: [x]\nk: {}{}\n", "[".repeat(d), "]".repeat(d));
        assert!(parse(&deep(490)).is_ok(), "PyYAML loads 490 levels, so a runcmd beside them runs");
        assert!(parse(&deep(600)).is_err());
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
        // the `{}`, silently; libyaml does not.
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
    fn many_keys_are_not_quadratic() {
        let many: String = (0..30_000).map(|i| format!("k{i}: v\n")).collect();
        let started = std::time::Instant::now();
        let Some(Value::Map(m)) = parse(&many).unwrap() else { panic!() };
        assert_eq!(m.len(), 30_000);
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());
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
        let deep_block: String = (0..600).map(|i| format!("{}- \n", "  ".repeat(i))).collect();
        assert!(parse(&deep_block).is_err());
        // Depth counts what an alias pastes in: 300 levels anchored, pasted
        // in 300 levels down.
        let chain = format!("a: &a {}x{}\nb: {}*a{}\n", "[".repeat(300), "]".repeat(300), "[".repeat(300), "]".repeat(300));
        let e = parse(&chain).unwrap_err();
        assert!(e.contains("deeper"), "{e}");
    }
}

