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

test('every backend rule has a short one-line label; unknown rules get a fallback', () => {
  const rules = ['typosquat_domain', 'display_name_domain_mismatch', 'reply_to_mismatch', 'spf_fail', 'dkim_fail', 'dmarc_fail',
    'urgency_financial_proximity', 'base64_obfuscation', 'excessive_url_encoding', 'html_entity_obfuscation',
    'link_text_href_mismatch', 'ip_literal_host', 'url_shortener', 'high_entropy_domain', 'double_extension',
    'dangerous_extension', 'macro_enabled_with_pressure_context', 'macro_enabled_attachment',
    'credential_request_language', 'suspicious_tld'];
  rules.forEach((r) => {
    const label = p.shortLabelForRule(r);
    assert.notStrictEqual(label, 'Something unusual', r);
    assert.ok(label.length <= 40, r + ' label too long');
  });
  assert.strictEqual(p.shortLabelForRule('nope'), 'Something unusual');
});

// ---- link inspector ----
const L = (text, href) => ({ text, href });

test('hostOf extracts the real host and ignores userinfo, port, path and case', () => {
  assert.strictEqual(p.hostOf('https://Example.COM/a?b=c'), 'example.com');
  assert.strictEqual(p.hostOf('http://paypal.com@evil.example:8080/x'), 'evil.example');
  assert.strictEqual(p.hostOf('https://sub.a.co.uk./'), 'sub.a.co.uk');
  assert.strictEqual(p.hostOf('mailto:a@b.com'), '');
  assert.strictEqual(p.hostOf('javascript:alert(1)'), '');
  assert.strictEqual(p.hostOf(''), '');
  assert.strictEqual(p.hostOf(null), '');
});

test('registrableDomain handles common two-part suffixes and IPs', () => {
  assert.strictEqual(p.registrableDomain('a.b.paypal.com'), 'paypal.com');
  assert.strictEqual(p.registrableDomain('shop.example.co.uk'), 'example.co.uk');
  assert.strictEqual(p.registrableDomain('mail.example.co.il'), 'example.co.il');
  assert.strictEqual(p.registrableDomain('10.0.0.1'), '10.0.0.1');
});

test('inspectLink flags a link whose text names a different site', () => {
  const r = p.inspectLink(L('https://paypal.com/verify', 'http://paypa1-support.com/verify'));
  assert.strictEqual(r.status, 'mismatch');
  assert.strictEqual(r.host, 'paypa1-support.com');
  assert.strictEqual(r.shownDomain, 'paypal.com');
});

test('inspectLink: lookalike subdomain trick is a mismatch', () => {
  assert.strictEqual(p.inspectLink(L('paypal.com', 'https://paypal.com.evil.example/x')).status, 'mismatch');
});

test('inspectLink: same site (even via subdomain) and plain words are ok', () => {
  assert.strictEqual(p.inspectLink(L('www.telus.com', 'https://r.communications.telus.com/x')).status, 'ok');
  assert.strictEqual(p.inspectLink(L('Unsubscribe', 'https://mailchimp.com/u')).status, 'ok');
  assert.strictEqual(p.inspectLink(L('', 'https://example.com')).status, 'ok');
});

test('inspectLink flags numeric hosts, look-alike (punycode) hosts and shorteners', () => {
  assert.strictEqual(p.inspectLink(L('Click', 'http://192.168.4.4/login')).status, 'ip');
  assert.strictEqual(p.inspectLink(L('Click', 'https://xn--pypal-4ve.com/')).status, 'lookalike');
  assert.strictEqual(p.inspectLink(L('Click', 'https://bit.ly/abc')).status, 'shortener');
});

test('inspectLinks: dedupes, drops non-web links, puts the worst first and caps rows', () => {
  const links = [
    L('Unsubscribe', 'https://mailchimp.com/u'),
    L('Unsubscribe', 'https://mailchimp.com/u'),
    L('mail us', 'mailto:a@b.com'),
    L('https://paypal.com', 'https://evil.example/x'),
    L('Click', 'https://bit.ly/z'),
  ];
  const r = p.inspectLinks(links, 8);
  assert.strictEqual(r.total, 3);
  assert.strictEqual(r.suspicious, 2);
  assert.deepStrictEqual(r.rows.map((x) => x.status), ['mismatch', 'shortener', 'ok']);
  const many = Array.from({ length: 20 }, (_, i) => L('t', 'https://site' + i + '.example/'));
  const capped = p.inspectLinks(many, 5);
  assert.strictEqual(capped.rows.length, 5);
  assert.strictEqual(capped.more, 15);
});

test('inspectLinks tolerates junk input and hostile text', () => {
  assert.deepStrictEqual(p.inspectLinks(null).rows, []);
  assert.doesNotThrow(() => p.inspectLinks([null, {}, L(undefined, undefined), L('<script>', 'https://x.example')]));
  const r = p.inspectLinks([L('<script>alert(1)</script>' + 'z'.repeat(5000), 'https://x.example')]);
  assert.ok(!r.rows[0].shown.includes('<'), 'escaped');
  assert.ok(r.rows[0].shown.length < 200, 'truncated before escaping');
});

test('linkSummaryText states counts honestly and never claims safety', () => {
  assert.ok(p.linkSummaryText({ total: 5, suspicious: 2 }).includes('2'));
  assert.ok(!/safe/i.test(p.linkSummaryText({ total: 3, suspicious: 0 })));
  assert.ok(p.linkSummaryText({ total: 0, suspicious: 0 }).length > 0);
});

test('inspectLinks groups fine links that share a host into one row with a count', () => {
  const r = p.inspectLinks([L('Apply', 'https://track.example/a'), L('Unsubscribe', 'https://track.example/b'),
    L('https://paypal.com', 'https://evil.example/x')], 8);
  assert.strictEqual(r.total, 3);
  assert.strictEqual(r.suspicious, 1);
  assert.deepStrictEqual(r.rows.map((x) => [x.status, x.count || 0]), [['mismatch', 0], ['ok', 2]]);
});

test('linkRowText leads with the verdict and shows the real host second', () => {
  const bad = p.linkRowText({ status: 'mismatch', host: 'evil.example', shownDomain: 'paypal.com', shown: 'x' });
  assert.ok(bad.indexOf('Says paypal.com') < bad.indexOf('evil.example'));
  assert.ok(p.linkRowText({ status: 'ok', host: 'a.example', count: 5, shown: '' }).includes('5 links go where they say'));
});

test('groupedFindings merges identical labels, heaviest first, never mutates input', () => {
  const input = [
    { category: 'link', rule: 'url_shortener', weight: 5 },
    { category: 'content', rule: 'base64_obfuscation', weight: 20 },
    { category: 'link', rule: 'url_shortener', weight: 5 },
  ];
  const copy = JSON.stringify(input);
  const g = p.groupedFindings(input);
  assert.deepStrictEqual(g.map((x) => [x.label, x.count]), [['Hidden encoded text', 1], ['Shortened link', 2]]);
  assert.strictEqual(JSON.stringify(input), copy);
  assert.deepStrictEqual(p.groupedFindings(null), []);
});

test('new rules get plain-English short labels, not the raw rule id', () => {
  assert.strictEqual(p.shortLabelForRule('credential_request_language'), 'Asks for your login details');
  assert.strictEqual(p.shortLabelForRule('suspicious_tld'), 'Link to a risky web ending');
  const g = p.groupedFindings([
    { category: 'link', rule: 'suspicious_tld', weight: 10 },
    { category: 'content', rule: 'credential_request_language', weight: 15 },
  ]);
  assert.deepStrictEqual(g.map((x) => x.label), ['Asks for your login details', 'Link to a risky web ending']);
});
