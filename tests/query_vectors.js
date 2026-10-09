// Runs tests/vectors/query.json against the report's JavaScript, the way
// src/query.rs runs it against the Rust. `node tests/query_vectors.js`.
const fs = require('fs');
const path = require('path');
const { parseQuery, matches, toggleChoice } = require('../src/report/query.js');
const v = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors', 'query.json'), 'utf8'));
let bad = 0;
for (const c of v.cases) {
  const q = parseQuery(c.q);
  const got = v.entries.filter((e) => matches(q, e)).map((e) => e.name);
  if (JSON.stringify(got) !== JSON.stringify(c.hits)) { bad++; console.error('query', JSON.stringify(c.q), 'expected', c.hits, 'got', got); }
}
for (const t of v.toggles) {
  const got = toggleChoice(t.query, t.field, t.value);
  if (got !== t.result) { bad++; console.error('toggle', t, 'got', got); }
}
if (bad) process.exit(1);
console.log(v.cases.length + ' queries and ' + v.toggles.length + ' toggles agree');
