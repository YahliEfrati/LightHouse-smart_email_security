// Smoke test: loads Presentation.gs + Code.gs with a recording fake CardService and
// checks that every card builds for edge-case backend results without throwing.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function load(extra = {}) {
  const calls = [];
  const chain = new Proxy(function () {}, {
    get: (_, prop) => (prop === 'then' ? undefined : (...args) => { calls.push([String(prop), args]); return chain; }),
  });
  const fake = new Proxy({}, { get: (_, prop) => (prop === 'ImageStyle' || prop === 'TextButtonStyle' ? { SQUARE: 1, FILLED: 2, OUTLINED: 3 } : () => chain) });
  const ctx = vm.createContext({ CardService: fake, console, ...extra });
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
  const base = vm.runInContext('ASSET_BASE_URL', ctx);
  assert.ok(urls.includes(base + 'hero_100.png'), 'score 150 is clamped to 100');
  assert.ok(urls.includes(base + 'hero_0.png'), 'score -3 is clamped to 0');
  assert.ok(urls.includes(base + 'hero_73.png'));
  assert.ok(urls.includes(base + 'hero_unscanned.png'));
});

test('malicious card has the report button and no banner/gauge images; safe card has no report button', () => {
  const a = load(); a.ctx.buildResultCard(email, { verdict: 'Malicious', score: 95, reasoning: [] }, 'id', false);
  assert.ok(strings(a.calls).includes('Report this email'));
  const b = load(); b.ctx.buildResultCard(email, { verdict: 'Safe', score: 3, reasoning: [] }, 'id', false);
  assert.ok(!strings(b.calls).includes('Report this email'));
});

test('first screen: score is native text, check strip and at most 3 findings shown', () => {
  const { ctx, calls } = load();
  const reasoning = [1, 2, 3, 4, 5].map((n) => ({ category: 'link', rule: 'url_shortener', weight: n, description: 'd' + n }));
  ctx.buildResultCard(email, { verdict: 'Suspicious', score: 48, reasoning }, 'id', false);
  const texts = strings(calls);
  assert.ok(texts.some((s) => /<b>48<\/b><\/font> \/ 100/.test(s)), 'native score text');
  assert.ok(texts.some((s) => s.includes('\u26A0 Links')), 'check strip');
  assert.strictEqual(calls.filter(([m]) => m === 'setStartIcon').length, 3);
  assert.ok(texts.includes('<i>+2 more in the details</i>'));
});

test('safe first screen has the strip and no findings', () => {
  const { ctx, calls } = load();
  ctx.buildResultCard(email, { verdict: 'Safe', score: 3, reasoning: [] }, 'id', false);
  assert.strictEqual(calls.filter(([m]) => m === 'setStartIcon').length, 0);
  assert.ok(strings(calls).some((s) => s.includes('\u2713 Sender')));
});

// ---- flow tests with fake Apps Script services ----
function services({ trusted = [], backend }) {
  const store = { trustedSenders: JSON.stringify(trusted) };
  const message = {
    getFrom: () => 'Ann <ann@corp.example>', getReplyTo: () => null, getSubject: () => 's',
    getBody: () => '<p>hi</p>', getPlainBody: () => 'hi', getAttachments: () => [],
  };
  return {
    store,
    globals: {
      PropertiesService: { getUserProperties: () => ({ getProperty: (k) => store[k] || null, setProperty: (k, v) => { store[k] = v; } }) },
      CacheService: { getUserCache: () => ({ put: () => {}, get: () => null }) },
      GmailApp: { setCurrentMessageAccessToken: () => {}, getMessageById: () => message },
      UrlFetchApp: { fetch: () => ({ getResponseCode: () => backend.status || 200, getContentText: () => JSON.stringify(backend.body) }) },
    },
  };
}
const open = (ctx) => ctx.buildAddOn({ gmail: { accessToken: 't', messageId: 'm' } });
const urlsOf = (calls) => calls.filter(([p]) => p === 'setImageUrl').map(([, a]) => a[0]);

test('trusted sender + non-malicious scan -> calm trusted card (score 0)', () => {
  const s = services({ trusted: ['corp.example'], backend: { body: { score: 50, verdict: 'Suspicious', reasoning: [] } } });
  const { ctx, calls } = load(s.globals);
  open(ctx);
  assert.ok(urlsOf(calls).some((u) => u.endsWith('hero_trusted.png')));
  assert.ok(strings(calls).includes('Remove from trusted'));
});

test('trusted sender + malicious scan -> warning result card, no trust button', () => {
  const s = services({ trusted: ['ann@corp.example'], backend: { body: { score: 85, verdict: 'Malicious', reasoning: [] } } });
  const { ctx, calls } = load(s.globals);
  open(ctx);
  const texts = strings(calls);
  assert.ok(urlsOf(calls).some((u) => u.endsWith('hero_85.png')));
  assert.ok(texts.some((t) => t.includes('trusted list, but this email looks dangerous')));
  assert.ok(!texts.includes('Trust sender'));
});

test('untrusted suspicious card offers Trust sender and This is a mistake; backend down -> not scanned', () => {
  const s = services({ backend: { body: { score: 40, verdict: 'Suspicious', reasoning: [] } } });
  const a = load(s.globals); open(a.ctx);
  assert.ok(strings(a.calls).includes('Trust sender') && strings(a.calls).includes('This is a mistake'));
  assert.ok(strings(a.calls).includes('Trusted senders'), 'overflow menu entry');
  const down = services({ backend: { status: 500, body: {} } });
  const b = load(down.globals); open(b.ctx);
  assert.ok(urlsOf(b.calls).some((u) => u.endsWith('hero_unscanned.png')));
});

test('adding a whole free-mail provider as trusted is refused; a full address is accepted', () => {
  const s = services({ backend: { body: {} } });
  const { ctx } = load(s.globals);
  ctx.onAddTrustedSender({ formInput: { newTrustedEntry: 'gmail.com' } });
  assert.deepStrictEqual(JSON.parse(s.store.trustedSenders), []);
  ctx.onAddTrustedSender({ formInput: { newTrustedEntry: 'Friend@Gmail.com' } });
  assert.deepStrictEqual(JSON.parse(s.store.trustedSenders), ['friend@gmail.com']);
  ctx.onUntrustThisSender({ parameters: { senderEmail: 'friend@gmail.com' } });
  assert.deepStrictEqual(JSON.parse(s.store.trustedSenders), []);
});
