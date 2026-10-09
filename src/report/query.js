// The filter language, as src/query.rs implements it. The two are held
// together by tests/vectors/query.json, which both test suites run.

function words(text) {
  const out = [];
  let cur = '';
  let quoted = false;
  for (const c of text) {
    if (c === '"') { quoted = !quoted; cur += c; }
    else if (/\s/.test(c) && !quoted) { if (cur) { out.push(cur); cur = ''; } }
    else cur += c;
  }
  if (cur) out.push(cur);
  return out;
}

const FIELDS = ['kind', 'flag', 'enabled', 'trigger', 'prov', 'pkg', 'collector', 'user', 'name', 'src', 'cmd', 'id', 'note'];

function unquote(v) { return v.replace(/"/g, ''); }

function parseTerm(word) {
  let negate = false;
  let rest = word;
  if (word.startsWith('-') && word.length > 1) { negate = true; rest = word.slice(1); }
  let field = null;
  let value = rest;
  const at = rest.indexOf(':');
  if (at >= 0) {
    const name = rest.slice(0, at).toLowerCase();
    if (FIELDS.includes(name)) { field = name; value = rest.slice(at + 1); }
  }
  value = unquote(value).toLowerCase();
  if (!value) return null;
  const anyOf = field ? value.split('|').filter(Boolean) : [value];
  return anyOf.length ? { negate, field, anyOf } : null;
}

function parseQuery(text) {
  return words(text).map(parseTerm).filter(Boolean);
}

function lc(s) { return (s || '').toLowerCase(); }

function holds(field, v, e) {
  const has = (s) => lc(s).includes(v);
  const command = lc(e.command);
  const pkg = lc(e.pkg);
  const notes = Object.entries(e.notes || {});
  switch (field) {
    case 'kind': return lc(e.kind).startsWith(v);
    case 'flag': return v === 'none' ? e.flags.length === 0 : e.flags.some((f) => f.startsWith(v));
    case 'enabled': return lc(e.enabled).startsWith(v);
    case 'trigger': return lc(e.trigger).startsWith(v);
    case 'prov': return e.prov.includes(v);
    case 'pkg': return pkg.includes(v);
    case 'collector': return has(e.collector);
    case 'user': return has(e.user);
    case 'name': return has(e.name);
    case 'src': return has(e.source);
    case 'cmd': return command.includes(v);
    case 'id': return e.id.startsWith(v);
    case 'note': return notes.some(([k, val]) => has(k + '=' + val));
    default:
      return has(e.name) || has(e.source) || e.id.startsWith(v) || lc(e.kind).includes(v) ||
        command.includes(v) || has(e.target) || has(e.user) || pkg.includes(v) ||
        notes.some(([k, val]) => has(k) || has(val));
  }
}

function matches(terms, e) {
  return terms.every((t) => t.anyOf.some((v) => holds(t.field, v, e)) !== t.negate);
}

function choices(word, field) {
  const at = word.indexOf(':');
  if (at < 0 || word.startsWith('-')) return null;
  if (word.slice(0, at).toLowerCase() !== field) return null;
  return unquote(word.slice(at + 1)).split('|');
}

function hasChoice(query, field, value) {
  return words(query).some((w) => { const c = choices(w, field); return c && c.includes(value); });
}

function withoutField(query, field) {
  return words(query).filter((w) => {
    const x = w.startsWith('-') ? w.slice(1) : w;
    const at = x.indexOf(':');
    return !(at >= 0 && x.slice(0, at).toLowerCase() === field);
  }).join(' ');
}

function toggleChoice(query, field, value) {
  const out = [];
  let found = false;
  for (const w of words(query)) {
    const c = choices(w, field);
    if (c && !found) {
      found = true;
      const at = c.indexOf(value);
      if (at >= 0) c.splice(at, 1); else c.push(value);
      if (c.length) out.push(field + ':' + c.join('|'));
    } else out.push(w);
  }
  if (!found) out.push(field + ':' + value);
  return out.join(' ');
}

if (typeof module !== 'undefined') module.exports = { parseQuery, matches, toggleChoice, hasChoice, withoutField };
