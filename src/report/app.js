// The report's interface. Every string from the scan reaches the page through
// textContent: a file name or command line is hostile input, and none of it is
// ever parsed as markup.
(function () {
  const DATA = JSON.parse(document.getElementById('data').textContent);
  const entries = DATA.entries;
  const state = { query: '', showHidden: false, sort: { key: null, desc: false }, limit: 400, open: new Set() };

  const $ = (id) => document.getElementById(id);
  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function visibleEntries(query, ignoreField) {
    const q = parseQuery(ignoreField ? withoutField(query, ignoreField) : query);
    return entries.filter((e) => (state.showHidden || !e.hidden) && matches(q, e));
  }

  function facetValues(field) {
    const counts = new Map();
    for (const e of visibleEntries(state.query, field)) {
      let values;
      if (field === 'kind') values = [e.kind];
      else if (field === 'enabled') values = [e.enabled];
      else if (field === 'trigger') values = [e.trigger];
      else if (field === 'prov') values = e.prov;
      else values = e.flags.length ? e.flags : ['none'];
      for (const v of values) counts.set(v, (counts.get(v) || 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }

  const FACETS = [['kind', 'Kind'], ['flag', 'Flag'], ['enabled', 'Enabled'], ['prov', 'Provenance'], ['trigger', 'Trigger']];

  function drawFacets() {
    const box = $('facets');
    box.textContent = '';
    for (const [field, title] of FACETS) {
      const group = el('details', 'facet');
      group.open = field === 'kind' || field === 'flag' || hasQueryField(field);
      group.appendChild(el('summary', null, title));
      for (const [value, count] of facetValues(field)) {
        const on = hasChoice(state.query, field, value);
        const row = el('button', 'choice' + (on ? ' on' : ''));
        row.type = 'button';
        row.appendChild(el('span', 'v', value));
        row.appendChild(el('span', 'n', String(count)));
        row.addEventListener('click', () => setQuery(toggleChoice(state.query, field, value)));
        group.appendChild(row);
      }
      box.appendChild(group);
    }
  }

  function hasQueryField(field) {
    return parseQuery(state.query).some((t) => t.field === field);
  }

  function command(e) { return e.command || e.target || e.source; }

  function sortRows(rows) {
    const { key, desc } = state.sort;
    if (!key) return rows;
    const val = (e) => key === 'flags' ? e.flags.length : (e[key] || '').toString().toLowerCase();
    return [...rows].sort((a, b) => {
      const x = val(a), y = val(b);
      return (x < y ? -1 : x > y ? 1 : 0) * (desc ? -1 : 1);
    });
  }

  function detail(e) {
    const d = el('dl', 'detail');
    const add = (k, v) => { if (v !== undefined && v !== null && v !== '') { d.appendChild(el('dt', null, k)); d.appendChild(el('dd', null, String(v))); } };
    add('id', e.id);
    add('source', e.source);
    add('command', e.command);
    add('target', e.target);
    add('principal', e.user);
    add('trigger', e.trigger);
    add('enabled', e.enabled);
    add('provenance', e.pkg ? e.prov.join(', ') + ' (' + e.pkg + ' ' + e.version + ')' : e.prov.join(', '));
    add('flags', e.flags.join(', '));
    add('collector', e.collector);
    add('owner uid / mode', e.owner + ' / ' + e.mode);
    add('modified', e.mtime ? new Date(e.mtime * 1000).toISOString() : '');
    for (const [k, v] of Object.entries(e.notes || {})) add('note ' + k, v);
    const cmd = el('code', 'explain', 'unbidden explain ' + e.id.slice(0, 12));
    d.appendChild(el('dt', null, 'the text it came from'));
    const dd = el('dd');
    dd.appendChild(cmd);
    d.appendChild(dd);
    return d;
  }

  function drawTable() {
    const rows = sortRows(visibleEntries(state.query));
    $('count').textContent = rows.length + ' of ' + entries.length + ' shown';
    const body = $('rows');
    body.textContent = '';
    for (const e of rows.slice(0, state.limit)) {
      const tr = el('tr', 'row' + (e.flags.some((f) => f !== 'degraded-enablement') ? ' flagged' : ''));
      tr.appendChild(el('td', 'id', e.id.slice(0, 12)));
      tr.appendChild(el('td', null, e.kind));
      tr.appendChild(el('td', null, e.enabled));
      tr.appendChild(el('td', 'name', e.name));
      tr.appendChild(el('td', 'flags', e.flags.join(', ')));
      tr.appendChild(el('td', 'cmd', command(e)));
      tr.addEventListener('click', () => {
        if (state.open.has(e.id)) state.open.delete(e.id); else state.open.add(e.id);
        drawTable();
      });
      body.appendChild(tr);
      if (state.open.has(e.id)) {
        const dr = el('tr', 'detailrow');
        const td = el('td');
        td.colSpan = 6;
        td.appendChild(detail(e));
        dr.appendChild(td);
        body.appendChild(dr);
      }
    }
    const more = $('more');
    more.hidden = rows.length <= state.limit;
    more.textContent = 'show ' + Math.min(400, rows.length - state.limit) + ' more';
    $('empty').hidden = rows.length > 0;
  }

  function setQuery(q) {
    state.query = q;
    $('q').value = q;
    state.limit = 400;
    try { history.replaceState(null, '', q ? '#' + encodeURIComponent(q) : location.pathname); } catch (_) { /* a file: page may refuse */ }
    drawFacets();
    drawTable();
  }

  function drawHeader() {
    const h = DATA.header;
    $('title').textContent = h.hostname + ' · ' + h.distro;
    $('when').textContent = new Date(h.scan_time * 1000).toLocaleString() + ' · unbidden ' + h.version + (h.privileged ? '' : ' · unprivileged');
    const box = $('notices');
    for (const n of h.notices) box.appendChild(el('p', 'notice', n));
    $('hiddenCount').textContent = String(entries.filter((e) => e.hidden).length);
  }

  function boot() {
    drawHeader();
    $('q').addEventListener('input', (ev) => setQuery(ev.target.value));
    $('showHidden').addEventListener('change', (ev) => { state.showHidden = ev.target.checked; drawFacets(); drawTable(); });
    $('clear').addEventListener('click', () => setQuery(''));
    $('more').addEventListener('click', () => { state.limit += 400; drawTable(); });
    for (const th of document.querySelectorAll('th[data-sort]')) {
      th.addEventListener('click', () => {
        const key = th.dataset.sort;
        state.sort = state.sort.key === key ? { key, desc: !state.sort.desc } : { key, desc: false };
        drawTable();
      });
    }
    document.addEventListener('keydown', (ev) => {
      if (ev.key === '/' && document.activeElement !== $('q')) { ev.preventDefault(); $('q').focus(); }
      else if (ev.key === 'Escape') { $('q').blur(); }
    });
    const initial = location.hash ? decodeURIComponent(location.hash.slice(1)) : '';
    setQuery(initial);
  }

  boot();
})();
