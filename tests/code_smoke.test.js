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
  assert.ok(urls.includes(base + 'hero_100.gif'), 'score 150 is clamped to 100');
  assert.ok(urls.includes(base + 'hero_0.gif'), 'score -3 is clamped to 0');
  assert.ok(urls.includes(base + 'hero_73.gif'));
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
  const rules = ['url_shortener', 'base64_obfuscation', 'html_entity_obfuscation', 'excessive_url_encoding', 'ip_literal_host'];
  const reasoning = rules.map((rule, n) => ({ category: 'link', rule: rule, weight: n === 0 ? 9 : n, description: 'd' + n }));
  ctx.buildResultCard(email, { verdict: 'Suspicious', score: 48, reasoning }, 'id', false);
  const texts = strings(calls);
  assert.ok(texts.some((s) => /<b>48<\/b><\/font> \/ 100/.test(s)), 'native score text');
  assert.ok(texts.some((s) => s.includes('\u26A0 Links')), 'check strip');
  assert.strictEqual(calls.filter(([m]) => m === 'setStartIcon').length, 3);
  assert.ok(texts.includes('<i>+2 more in the details</i>'));
  assert.ok(texts.includes('Shortened link'), 'short one-line label, not the long sentence');
  assert.ok(!texts.some((t) => t.includes('behind a shortener')), 'no long sentence on the first screen');
});

test('safe first screen has the strip and no findings', () => {
  const { ctx, calls } = load();
  ctx.buildResultCard(email, { verdict: 'Safe', score: 3, reasoning: [] }, 'id', false);
  assert.strictEqual(calls.filter(([m]) => m === 'setStartIcon').length, 0);
  assert.ok(strings(calls).some((s) => s.includes('\u2713 Sender')));
});

// ---- flow tests with fake Apps Script services ----
function services({ trusted = [], backend, scriptProps = {}, onFetch }) {
  const store = { trustedSenders: JSON.stringify(trusted) };
  const message = {
    getFrom: () => 'Ann <ann@corp.example>', getReplyTo: () => null, getSubject: () => 's',
    getBody: () => '<p>hi</p>', getPlainBody: () => 'hi', getAttachments: () => [],
  };
  return {
    store,
    globals: {
      PropertiesService: { getScriptProperties: () => ({ getProperty: (k) => scriptProps[k] || null }), getUserProperties: () => ({ getProperty: (k) => store[k] || null, setProperty: (k, v) => { store[k] = v; } }) },
      CacheService: { getUserCache: () => ({ put: () => {}, get: () => null }) },
      GmailApp: { setCurrentMessageAccessToken: () => {}, getMessageById: () => message },
      UrlFetchApp: { fetch: (url, options) => { if (onFetch) onFetch(url, options); return { getResponseCode: () => backend.status || 200, getContentText: () => JSON.stringify(backend.body) }; } },
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
  assert.ok(urlsOf(calls).some((u) => u.endsWith('hero_85.gif')));
  assert.ok(texts.some((t) => t.includes('trusted list, but this email looks dangerous')));
  assert.ok(!texts.includes('Trust sender'));
});

test('untrusted suspicious card offers Trust sender (no empty feedback button); backend down -> not scanned', () => {
  const s = services({ backend: { body: { score: 40, verdict: 'Suspicious', reasoning: [] } } });
  const a = load(s.globals); open(a.ctx);
  assert.ok(strings(a.calls).includes('Trust sender'));
  assert.ok(!strings(a.calls).includes('This is a mistake'), 'button removed on purpose'); 
  const bad = load(services({ backend: { body: { score: 90, verdict: 'Malicious', reasoning: [] } } }).globals);
  open(bad.ctx);
  assert.ok(!bad.calls.some(([m]) => m === 'newButtonSet'), 'no empty button row on a malicious card');
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


test('backend call sends the shared secret from Script Properties (trimmed)', () => {
  let seen;
  const s = services({
    scriptProps: { BACKEND_API_KEY: ' k-123 ' },
    onFetch: (url, options) => { seen = options; },
    backend: { body: { score: 5, verdict: 'Safe', reasoning: [] } },
  });
  const { ctx } = load(s.globals);
  open(ctx);
  assert.strictEqual(seen.headers['X-Lighthouse-Key'], 'k-123');
});

test('backend 401 (missing/wrong key) -> grey Not scanned card, never a safe look', () => {
  const s = services({ backend: { status: 401, body: { detail: 'Unauthorized' } } });
  const { ctx, calls } = load(s.globals);
  open(ctx);
  assert.ok(urlsOf(calls).some((u) => u.endsWith('hero_unscanned.png')));
});

// ---- link inspector flow ----
const linksEmail = { senderEmail: 'a@b.com', senderDisplayName: 'A', links: [{ text: 'https://paypal.com', href: 'https://evil.example/x' }] };

test('result card offers "Check the links" only when the email has web links', () => {
  const { ctx, calls } = load();
  ctx.buildResultCard(linksEmail, { verdict: 'Suspicious', score: 40, reasoning: [] }, 'id', false);
  assert.ok(strings(calls).includes('Check the links'));
  const second = load();
  second.ctx.buildResultCard({ ...linksEmail, links: [] }, { verdict: 'Suspicious', score: 40, reasoning: [] }, 'id', false);
  assert.ok(!strings(second.calls).includes('Check the links'));
});

test('links card shows the real host, escapes hostile text, and never promises safety', () => {
  const { ctx, calls } = load();
  const report = ctx.inspectLinks([{ text: '<b>paypal.com</b>', href: 'https://evil.example/x' }], 8);
  assert.doesNotThrow(() => ctx.buildLinksCard(report));
  const texts = strings(calls);
  assert.ok(texts.some((t) => t.includes('evil.example')));
  assert.ok(!texts.some((t) => t.includes('<b>paypal.com</b>')), 'attacker HTML must be escaped');
});

test('onInspectLinks reads the cached report, and handles an expired cache', () => {
  const store = {};
  const cache = { put: (k, v) => { store[k] = v; }, get: (k) => store[k] || null };
  const s = services({ backend: { body: { score: 40, verdict: 'Suspicious', reasoning: [] } } });
  s.globals.CacheService = { getUserCache: () => cache };
  s.globals.GmailApp.getMessageById = () => ({
    getFrom: () => 'Ann <ann@corp.example>', getReplyTo: () => null, getSubject: () => 's',
    getBody: () => '<a href="https://evil.example/x">https://paypal.com</a>', getPlainBody: () => 'hi', getAttachments: () => [],
  });
  const { ctx, calls } = load(s.globals);
  open(ctx);
  assert.ok(Object.keys(store).some((k) => k.startsWith('links_')), 'link report cached');
  assert.doesNotThrow(() => ctx.onInspectLinks({ parameters: { messageId: 'm' } }));
  assert.ok(strings(calls).some((t) => t.includes('evil.example')));
  assert.doesNotThrow(() => ctx.onInspectLinks({ parameters: { messageId: 'gone' } }));
});

test('first screen merges identical findings instead of repeating the line', () => {
  const { ctx, calls } = load();
  const reasoning = [1, 2].map((n) => ({ category: 'link', rule: 'link_text_href_mismatch', weight: n, description: 'd' }));
  ctx.buildResultCard(email, { verdict: 'Suspicious', score: 48, reasoning }, 'id', false);
  assert.ok(strings(calls).includes('Link goes somewhere else (\u00D72)'));
  assert.strictEqual(calls.filter(([m]) => m === 'setStartIcon').length, 1);
});

test('credential_request_language and suspicious_tld render with labels on both cards', () => {
  const reasoning = [
    { category: 'content', rule: 'credential_request_language', weight: 15, description: "asks 'verify your account'" },
    { category: 'link', rule: 'suspicious_tld', weight: 10, description: "host 'a.top'" },
  ];
  const result = { verdict: 'Safe', score: 25, reasoning };
  const first = load();
  first.ctx.buildResultCard(email, { ...result, verdict: 'Suspicious' }, 'id', false);
  const texts = strings(first.calls);
  assert.ok(texts.includes('Asks for your login details'));
  assert.ok(texts.includes('Link to a risky web ending'));
  assert.ok(!texts.some((t) => t.includes('credential_request_language') || t.includes('suspicious_tld')), 'no raw rule ids');
  const details = load();
  details.ctx.buildDetailsCard({ ...result, verdict: 'Suspicious' });
  const wisdom = vm.runInContext('RULE_WISDOM', details.ctx);
  const detailTexts = strings(details.calls);
  assert.ok(detailTexts.some((t) => t.includes(wisdom.credential_request_language)));
  assert.ok(detailTexts.some((t) => t.includes(wisdom.suspicious_tld)));
});

// ---- trusted list ----
test('homepage keeps just the intro and opens the trusted list via a button', () => {
  const s = services({ trusted: ['a@x.example'], backend: { body: {} } });
  const { ctx, calls } = load(s.globals);
  assert.doesNotThrow(() => ctx.onHomepage({}));
  assert.ok(!calls.some(([m]) => m === 'newTextInput'), 'no text input on the homepage');
  assert.ok(strings(calls).includes('Manage trusted senders'));
  assert.ok(!strings(calls).includes('a@x.example'), 'list lives on its own card');
});

test('trusted list card: count, newest first, wraps long addresses, collapses a long list', () => {
  const list = Array.from({ length: 12 }, (_, i) => 'person' + i + '@a-very-long-company-domain.example');
  const s = services({ trusted: list, backend: { body: {} } });
  const { ctx, calls } = load(s.globals);
  assert.doesNotThrow(() => ctx.buildManageTrustedSendersCard());
  const texts = strings(calls);
  assert.ok(texts.includes('12 trusted senders'));
  const rows = calls.filter(([m, a]) => m === 'setText' && /^person\d+@/.test(a[0])).map(([, a]) => a[0]);
  assert.strictEqual(rows[0], 'person11@a-very-long-company-domain.example', 'newest first');
  assert.strictEqual(rows.length, 12);
  assert.ok(calls.some(([m, a]) => m === 'setCollapsible' && a[0] === true));
  assert.ok(calls.some(([m, a]) => m === 'setNumUncollapsibleWidgets' && a[0] === 5));
  assert.strictEqual(calls.filter(([m, a]) => m === 'setWrapText' && a[0] === true).length >= 12, true);
  const empty = load(services({ trusted: [], backend: { body: {} } }).globals);
  assert.doesNotThrow(() => empty.ctx.buildManageTrustedSendersCard());
  assert.ok(strings(empty.calls).includes('No trusted senders yet'));
});

test('a full trusted list refuses new entries from both the card and the result-card button', () => {
  const full = Array.from({ length: 100 }, (_, i) => i + '@x.example');
  const s = services({ trusted: full, backend: { body: {} } });
  const { ctx, calls } = load(s.globals);
  ctx.buildManageTrustedSendersCard();
  assert.ok(!calls.some(([m]) => m === 'newTextInput'), 'no add field when full');
  ctx.onAddTrustedSender({ formInput: { newTrustedEntry: 'new@x.example' } });
  ctx.onTrustThisSender({ parameters: { senderEmail: 'other@x.example', senderDisplayName: 'O' } });
  assert.strictEqual(JSON.parse(s.store.trustedSenders).length, 100);
  assert.ok(strings(calls).some((t) => /list is full/.test(t)));
  ctx.onAddTrustedSender({ formInput: { newTrustedEntry: '5@x.example' } }); // already there: not "full"
  assert.ok(strings(calls).includes('"5@x.example" is already trusted.'));
});

test('details card merges repeated findings of one rule under a single headline', () => {
  const { ctx, calls } = load();
  const reasoning = [
    { category: 'link', rule: 'link_text_href_mismatch', weight: 25, description: "shows 'a.example'" },
    { category: 'link', rule: 'link_text_href_mismatch', weight: 25, description: "shows 'b.example'" },
    { category: 'header', rule: 'reply_to_mismatch', weight: 15, description: 'one <b>' },
  ];
  ctx.buildDetailsCard({ verdict: 'Suspicious', score: 55, reasoning });
  const texts = strings(calls);
  const wisdom = vm.runInContext('RULE_WISDOM', ctx);
  assert.strictEqual(texts.filter((t) => t.startsWith(wisdom.link_text_href_mismatch)).length, 1, 'one headline');
  assert.ok(texts.includes(wisdom.link_text_href_mismatch + ' (×2)'));
  assert.ok(texts.some((t) => t.includes("• shows &#39;a.example&#39;") || t.includes("• shows 'a.example'")));
  assert.ok(texts.some((t) => t.includes("b.example")));
  assert.ok(texts.includes('one &lt;b&gt;'), 'single finding keeps its bottom label, escaped');
});

test('Reply-To is sent to the backend as a bare address, without the display name', () => {
  let sent = null;
  const s = services({ backend: { body: { score: 0, verdict: 'Safe', reasoning: [] } }, onFetch: (u, o) => { sent = JSON.parse(o.payload); } });
  const base = s.globals.GmailApp.getMessageById();
  s.globals.GmailApp.getMessageById = () => ({ ...base, getReplyTo: () => 'Tel Aviv Salon <info@tlvsalon.com>' });
  const { ctx } = load(s.globals);
  open(ctx);
  assert.strictEqual(sent.reply_to, 'info@tlvsalon.com');
});

test('an untrusted sender posing as a trusted contact gets a raised score and a clear finding', () => {
  const s = services({ trusted: ['ceo@acmecorp.example'], backend: { body: { score: 10, verdict: 'Safe', reasoning: [] } } });
  const base = s.globals.GmailApp.getMessageById();
  s.globals.GmailApp.getMessageById = () => ({ ...base, getFrom: () => 'CEO <ceo@acmec0rp.example>' });
  const { ctx, calls } = load(s.globals);
  open(ctx);
  const texts = strings(calls);
  assert.ok(texts.includes('Poses as someone you trust'));
  assert.ok(texts.some((t) => /<b>50<\/b><\/font> \/ 100/.test(t)), 'score raised from 10 to 50');
  assert.ok(urlsOf(calls).some((u) => u.endsWith('hero_50.gif')));
});
