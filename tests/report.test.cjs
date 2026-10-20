const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const script = fs.readFileSync(path.join(__dirname, '../assets/report.js'), 'utf8');
function fixture() {
  const elements = {};
  for (const name of ['search', 'severity', 'category', 'reset', 'count']) {
    elements['finding-' + name] = {value: name === 'severity' || name === 'category' ? 'all' : '',
      events: {}, addEventListener(event, callback) { this.events[event] = callback; }, focus() {}};
  }
  const rows = [
    {textContent: 'SQL error /search?q=1', dataset: {severity: 'high', category: 'scanner_match'}},
    {textContent: 'HTTPServer nginx', dataset: {severity: 'info', category: 'technology'}},
    {textContent: 'Missing header', dataset: {severity: 'low', category: 'configuration'}}
  ];
  vm.runInNewContext(script, {document: {getElementById: id => elements[id], querySelectorAll: () => rows}});
  return {elements, rows};
}
test('category, severity and literal text filters intersect; reset restores all', () => {
  const {elements: e, rows} = fixture();
  assert.equal(e['finding-count'].textContent, '3 of 3 observations shown');
  e['finding-category'].value = 'scanner_match';
  e['finding-category'].events.change();
  assert.deepEqual(rows.map(r => r.hidden), [false, true, true]);
  e['finding-severity'].value = 'info'; e['finding-severity'].events.change();
  assert.ok(rows.every(r => r.hidden));
  e['finding-reset'].events.click();
  e['finding-search'].value = '  NGINX  '; e['finding-search'].events.input();
  assert.deepEqual(rows.map(r => r.hidden), [true, false, true]);
  e['finding-search'].value = '.*'; e['finding-search'].events.input();
  assert.ok(rows.every(r => r.hidden));
});
test('missing report controls do not break the document', () => {
  vm.runInNewContext(script, {document: {getElementById: () => null}});
});
