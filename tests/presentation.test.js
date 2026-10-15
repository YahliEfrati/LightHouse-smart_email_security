const test = require('node:test');
const assert = require('node:assert');

globalThis.ASSET_BASE_URL = 'https://example.test/assets/';
const p = require('../Presentation.gs');

test('gaugeFile rounds to steps of 5 and uses alert above 90', () => {
  const cases = [[0, 'gauge_0.png'], [2, 'gauge_0.png'], [3, 'gauge_5.png'], [72, 'gauge_70.png'],
    [90, 'gauge_90.png'], [91, 'gauge_alert.png'], [100, 'gauge_alert.png'], [150, 'gauge_alert.png'],
    [-3, 'gauge_0.png'], [72.6, 'gauge_75.png'], [NaN, 'gauge_0.png']];
  cases.forEach(([score, file]) => assert.strictEqual(p.gaugeFile(score), file, 'score ' + score));
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
