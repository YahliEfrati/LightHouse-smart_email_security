const test = require('node:test');
const assert = require('node:assert');

globalThis.ASSET_BASE_URL = 'https://example.test/assets/';
const p = require('../Presentation.gs');

test('heroFile is one image per integer score, clamped to 0-100', () => {
  const cases = [[0, 'hero_0.png'], [34, 'hero_34.png'], [72, 'hero_72.png'], [91, 'hero_91.png'],
    [100, 'hero_100.png'], [150, 'hero_100.png'], [-3, 'hero_0.png'], [72.6, 'hero_73.png'], [NaN, 'hero_0.png']];
  cases.forEach(([score, file]) => assert.strictEqual(p.heroFile(score), file, 'score ' + score));
  assert.strictEqual(p.HERO_UNSCANNED_FILE, 'hero_unscanned.png');
});

test('stateForResult maps verdicts and falls back to suspicious', () => {
  assert.strictEqual(p.stateForResult({ verdict: 'Safe' }), 'safe');
  assert.strictEqual(p.stateForResult({ verdict: 'Suspicious' }), 'suspicious');
  assert.strictEqual(p.stateForResult({ verdict: 'Malicious' }), 'malicious');
  assert.strictEqual(p.stateForResult({ verdict: 'Weird' }), 'suspicious');
});

test('topFinding picks highest weight, first on ties, null when empty', () => {
  const a = { weight: 10, rule: 'a' }; const b = { weight: 30, rule: 'b' }; const c = { weight: 30, rule: 'c' };
  assert.strictEqual(p.topFinding([a, b, c]), b);
  assert.strictEqual(p.topFinding([]), null);
  assert.strictEqual(p.topFinding(undefined), null);
});

test('safeText escapes HTML and truncates', () => {
  assert.ok(!p.safeText('<b>x</b>', 100).includes('<'));
  const long = p.safeText('a'.repeat(5000), 80);
  assert.ok(long.length <= 81);
  assert.ok(long.endsWith('…'));
});

test('checksPassed excludes categories that fired', () => {
  const passed = p.checksPassed([{ category: 'link' }]);
  assert.ok(!passed.includes('Where links lead'));
  assert.ok(passed.includes('Sender identity') && passed.includes('Message wording') && passed.includes('Attachments'));
});

test('presentationFor unscanned never implies safety', () => {
  assert.ok(/use your usual caution/.test(p.presentationFor('unscanned').todo));
  assert.strictEqual(p.assetUrl('x.png'), 'https://example.test/assets/x.png');
});

test('sortFindings orders heaviest first, keeps ties stable, does not mutate', () => {
  const a = { weight: 10, rule: 'a' }; const b = { weight: 30, rule: 'b' }; const c = { weight: 30, rule: 'c' };
  const input = [a, b, c];
  assert.deepStrictEqual(p.sortFindings(input).map((i) => i.rule), ['b', 'c', 'a']);
  assert.deepStrictEqual(input.map((i) => i.rule), ['a', 'b', 'c']);
  assert.deepStrictEqual(p.sortFindings(undefined), []);
});

test('score legend mirrors the backend thresholds', () => {
  assert.ok(p.SCORE_LEGEND.includes('35') && p.SCORE_LEGEND.includes('70'));
});

test('checkStatuses: ok / warn / alert by summed weight per category', () => {
  const st = p.checkStatuses([{ category: 'link', weight: 10 }, { category: 'content', weight: 20 }, { category: 'content', weight: 20 }]);
  const by = Object.fromEntries(st.map((s) => [s.category, s.status]));
  assert.deepStrictEqual(by, { header: 'ok', content: 'alert', link: 'warn', attachment: 'ok' });
  assert.strictEqual(p.checkStatuses(undefined).every((s) => s.status === 'ok'), true);
});

test('checkStripText shows a colored symbol and label per check', () => {
  const text = p.checkStripText(p.checkStatuses([{ category: 'link', weight: 10 }]));
  assert.ok(text.includes('\u2713 Sender') && text.includes('\u26A0 Links'));
  assert.ok(text.includes('#C98A2C') && text.includes('#2E7D6B'));
});

test('topFindings returns at most n heaviest', () => {
  const r = [{ weight: 1 }, { weight: 9 }, { weight: 5 }, { weight: 7 }];
  assert.deepStrictEqual(p.topFindings(r, 3).map((i) => i.weight), [9, 7, 5]);
  assert.deepStrictEqual(p.topFindings([], 3), []);
});

test('isTrustedBy: exact address or bare domain, case-insensitive, no subdomains', () => {
  const list = ['Alice@Example.com', 'corp.example'];
  assert.strictEqual(p.isTrustedBy('alice@example.com', list), true);
  assert.strictEqual(p.isTrustedBy('bob@corp.example', list), true);
  assert.strictEqual(p.isTrustedBy('bob@evil.corp.example', list), false);
  assert.strictEqual(p.isTrustedBy('bob@example.com', list), false);
  assert.strictEqual(p.isTrustedBy('', list), false);
  assert.strictEqual(p.isTrustedBy('a@b.com', undefined), false);
});

test('public mail provider domains are never trusted as a whole, but full addresses are', () => {
  assert.strictEqual(p.isPublicMailDomain('Gmail.com'), true);
  assert.strictEqual(p.isTrustedBy('stranger@gmail.com', ['gmail.com']), false);
  assert.strictEqual(p.isTrustedBy('friend@gmail.com', ['friend@gmail.com']), true);
});
