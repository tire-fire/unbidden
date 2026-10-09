// Loads the report's script against a stand-in for the page and checks it
// draws and filters. `node tests/report_page.js` (no browser needed).
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const data = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors', 'query.json'), 'utf8')).entries.map((e, i) => ({
  ...e, owner: 0, mode: '0644', mtime: null, hidden: e.prov.includes('intact'),
}));

function node(tag) {
  let text = '';
  return {
    // Setting text replaces the children, as it does in a page.
    get textContent() { return text; },
    set textContent(v) { text = v; this.children = []; },
    tag, children: [], listeners: {}, className: '', hidden: false, dataset: {}, value: '', checked: false, open: false,
    appendChild(c) { this.children.push(c); return c; },
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
    fire(t, ev) { (this.listeners[t] || []).forEach((f) => f(ev || { target: this })); },
    focus() {}, blur() {},
  };
}
const byId = {};
const doc = {
  getElementById(id) {
    if (id === 'data') return { textContent: JSON.stringify({ header: { hostname: 'h', distro: 'arch', version: '0', scan_time: 0, privileged: true, notices: ['n1'] }, entries: data }) };
    return (byId[id] = byId[id] || node(id));
  },
  createElement: node,
  querySelectorAll() { return []; },
  addEventListener() {},
  get activeElement() { return null; },
};
const ctx = { document: doc, location: { hash: '', pathname: '/' }, history: { replaceState() {} }, console, Date, Map, Set, JSON, Object, String, Array };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'src', 'report', 'query.js'), 'utf8'), ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'src', 'report', 'app.js'), 'utf8'), ctx);

const rows = () => byId.rows.children.filter((r) => r.className.startsWith('row'));
const fail = (m) => { console.error('FAIL: ' + m); process.exit(1); };
if (rows().length !== 4) fail('the default view should hide the packaged, intact entry, got ' + rows().length);
if (!byId.count.textContent.startsWith('4 of 5')) fail(byId.count.textContent);
byId.q.fire('input', { target: { value: 'kind:cron' } });
if (rows().length !== 1) fail('kind:cron should leave one row, got ' + rows().length);
byId.showHidden.fire('change', { target: { checked: true } });
byId.q.fire('input', { target: { value: '' } });
if (rows().length !== 5) fail('with hidden shown there are five, got ' + rows().length);
byId.rows.children[0].fire('click');
if (!byId.rows.children.some((r) => r.className === 'detailrow')) fail('a click should open the detail');
if (byId.notices.children.length !== 1) fail('the notice is shown');
console.log('the report draws, filters and opens an entry');
