// Smoke test: loads Presentation.gs + Code.gs with a recording fake CardService and
// checks that every card builds for edge-case backend results without throwing.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function load() {
  const calls = [];
  const chain = new Proxy(function () {}, {
    get: (_, prop) => (prop === 'then' ? undefined : (...args) => { calls.push([String(prop), args]); return chain; }),
  });
  const fake = new Proxy({}, { get: (_, prop) => (prop === 'ImageStyle' || prop === 'TextButtonStyle' ? { SQUARE: 1, FILLED: 2, OUTLINED: 3 } : () => chain) });
  const ctx = vm.createContext({ CardService: fake, console });
  for (const f of ['Code.gs', 'Presentation.gs']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '..', f), 'utf8'), ctx, { filename: f });
  }
  return { ctx, calls };
}
const email = { senderEmail: 'a@b.com', senderDisplayName: 'A', };
const strings = (calls) => calls.flatMap(([, args]) => args).filter((a) => typeof a === 'string');

test('result card builds for edge-case results', () => {
  const { ctx, calls } = load();
  const cases = [
    { verdict: 'Malicious', score: 150, reasoning: [] },
    { verdict: 'Weird', score: -3, reasoning: [{ category: 'link', rule: 'nope', weight: 5, description: 'x' }] },
    { verdict: 'Suspicious', score: 72.6, reasoning: [{ category: 'link', rule: 'url_shortener', weight: 9, description: '<script>alert(1)</script>' + 'z'.repeat(5000) }] },
    { verdict: 'Safe', score: 3, reasoning: [] },
  ];
  cases.forEach((r) => {
    assert.doesNotThrow(() => ctx.buildResultCard(email, r, 'id', false));
    assert.doesNotThrow(() => ctx.buildDetailsCard(r));
  });
  assert.doesNotThrow(() => ctx.buildNotScannedCard());
  assert.doesNotThrow(() => ctx.buildTrustedSenderCard(email));
  assert.ok(!strings(calls).some((s) => s.includes('<script>')), 'attacker HTML must be escaped');
  const urls = calls.filter(([p]) => p === 'setImageUrl').map(([, a]) => a[0]);
  assert.ok(urls.includes(vm.runInContext('ASSET_BASE_URL', ctx) + 'gauge_alert.png'));
  assert.ok(urls.includes(vm.runInContext('ASSET_BASE_URL', ctx) + 'gauge_0.png'));
  assert.ok(urls.includes(vm.runInContext('ASSET_BASE_URL', ctx) + 'banner_malicious.png'));
});

test('malicious card has the report button; safe card does not', () => {
  const a = load(); a.ctx.buildResultCard(email, { verdict: 'Malicious', score: 95, reasoning: [] }, 'id', false);
  assert.ok(strings(a.calls).includes('Report as phishing'));
  const b = load(); b.ctx.buildResultCard(email, { verdict: 'Safe', score: 3, reasoning: [] }, 'id', false);
  assert.ok(!strings(b.calls).includes('Report as phishing'));
});
