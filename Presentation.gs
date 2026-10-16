/**
 * Pure presentation helpers for the Lighthouse add-on (no CardService calls).
 * Kept free of Apps Script services so they can be unit-tested in Node
 * (see tests/presentation.test.js); Apps Script loads this file as-is.
 * Depends on the global ASSET_BASE_URL defined in Code.gs.
 */

const RESULT_STATES = ['safe', 'suspicious', 'malicious', 'unscanned'];

const STATE_PRESENTATION = {
  safe: {
    icon: 'icon_safe.png',
    headline: 'Looks safe', subtitle: 'Calm waters ahead',
    todo: 'No action needed.',
  },
  suspicious: {
    icon: 'icon_suspicious.png',
    headline: 'Check before you act', subtitle: 'Worth a closer look',
    todo: 'Verify the sender before clicking or replying.',
  },
  malicious: {
    icon: 'icon_malicious.png',
    headline: 'DANGER — LIKELY MALICIOUS', subtitle: 'Steer clear of this one',
    todo: 'Do not click links or open attachments. Report this email.',
  },
  trusted: {
    icon: 'icon_safe.png',
    headline: 'Trusted sender', subtitle: 'A familiar face',
    todo: '',
  },
  unscanned: {
    icon: 'icon_unscanned.png',
    headline: 'Not scanned', subtitle: 'The beacon is resting',
    todo: "This email wasn't scanned — use your usual caution.",
  },
};

/** Friendly labels for the checks Lighthouse performs, keyed by finding category. */
const CHECKS_PERFORMED = {
  header: 'Sender identity',
  content: 'Message wording',
  link: 'Where links lead',
  attachment: 'Attachments',
};

/** Rounds to an integer in [0, 100]; non-finite input becomes 0. */
function normalizeScore(score) {
  const n = Number(score);
  if (!isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

/**
 * Hero image for a score: one pre-rendered image per integer score 0-100 (verdict color,
 * big score and gradient gauge in a single full-width block). Colors follow the backend
 * thresholds (35 suspicious, 70 malicious) - see tools/generate_assets.py.
 */
function heroFile(score) {
  // Animated: the lighthouse beam sweeps twice, then the GIF rests on the static image (plays once).
  return 'hero_' + normalizeScore(score) + '.gif';
}

const HERO_UNSCANNED_FILE = 'hero_unscanned.png';
const HERO_TRUSTED_FILE = 'hero_trusted.png';

function assetUrl(file) {
  return ASSET_BASE_URL + file;
}

/** Maps a backend verdict to a visual state; anything unknown is treated as suspicious. */
function stateForResult(result) {
  const verdict = result && result.verdict;
  if (verdict === 'Safe') return 'safe';
  if (verdict === 'Malicious') return 'malicious';
  return 'suspicious';
}

function presentationFor(state) {
  return STATE_PRESENTATION[state] || STATE_PRESENTATION.suspicious;
}

/** Highest-weight finding (first wins ties), or null when there are none. */
function topFinding(reasoning) {
  if (!Array.isArray(reasoning) || reasoning.length === 0) return null;
  return reasoning.reduce((best, item) => (item.weight > best.weight ? item : best), reasoning[0]);
}

/** Truncates attacker-controlled text, then HTML-escapes it for CardService widgets. */
function safeText(value, maxLen) {
  let text = String(value == null ? '' : value);
  if (text.length > maxLen) text = text.substring(0, maxLen) + '…';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Copy of the findings ordered heaviest first (stable for equal weights); never mutates the input. */
function sortFindings(reasoning) {
  if (!Array.isArray(reasoning)) return [];
  return reasoning
    .map((item, index) => ({ item, index }))
    .sort((a, b) => (b.item.weight - a.item.weight) || (a.index - b.index))
    .map((entry) => entry.item);
}

/** Footer for the details card: how to read the score (mirrors the backend thresholds). */
const SCORE_LEGEND = '0\u201334 safe \u00B7 35\u201369 suspicious \u00B7 70+ likely malicious.<br>' +
  '<i>An automated estimate, not a guarantee.</i>';

const STATUS_COLORS = { ok: '#2E7D6B', warn: '#C98A2C', alert: '#D32F2F' };
const STATUS_SYMBOLS = { ok: '\u2713', warn: '\u26A0', alert: '\u2715' };
const CHECK_SHORT_LABELS = { header: 'Sender', content: 'Message', link: 'Links', attachment: 'Files' };

/**
 * Status of each check category: 'ok' (no finding), 'warn' (some weight), 'alert' (summed weight >= 35,
 * the backend's suspicious threshold).
 */
function checkStatuses(reasoning) {
  const totals = {};
  (Array.isArray(reasoning) ? reasoning : []).forEach((item) => {
    totals[item.category] = (totals[item.category] || 0) + (Number(item.weight) || 0);
  });
  return Object.keys(CHECK_SHORT_LABELS).map((key) => {
    const total = totals[key] || 0;
    const status = total >= 35 ? 'alert' : total > 0 ? 'warn' : 'ok';
    return { category: key, label: CHECK_SHORT_LABELS[key], status: status };
  });
}

/** Compact colored status strip: "✓ Sender · ⚠ Message · ✓ Links · ✓ Files". */
function checkStripText(statuses) {
  return statuses
    .map((s) => '<font color="' + STATUS_COLORS[s.status] + '">' + STATUS_SYMBOLS[s.status] + ' ' + s.label + '</font>')
    .join(' &nbsp;\u00B7&nbsp; ');
}

/** The n heaviest findings (see sortFindings). */
function topFindings(reasoning, n) {
  return sortFindings(reasoning).slice(0, n);
}

/** Free-mail providers: trusting a whole provider domain would trust millions of strangers. */
const PUBLIC_MAIL_DOMAINS = ['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  'yahoo.com', 'ymail.com', 'icloud.com', 'me.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com',
  'walla.co.il', 'zoho.com'];

function isPublicMailDomain(domain) {
  return PUBLIC_MAIL_DOMAINS.indexOf(String(domain || '').toLowerCase().trim()) !== -1;
}

/**
 * True if senderEmail matches a trusted full address or a trusted bare domain (exact match; subdomains
 * do not match). Bare public-mail domains in the list are ignored, even if they were stored earlier.
 */
function isTrustedBy(senderEmail, trustedList) {
  if (!senderEmail || !Array.isArray(trustedList)) return false;
  const email = String(senderEmail).toLowerCase().trim();
  const domain = email.split('@')[1] || '';
  return trustedList.some((entry) => {
    const normalized = String(entry).toLowerCase().trim();
    if (normalized.indexOf('@') === -1 && isPublicMailDomain(normalized)) return false;
    return normalized === email || normalized === domain;
  });
}

/**
 * Upper bound on the trusted list. Keeps the card short enough to scan and the stored JSON far below
 * the ~9 KB per-value limit of PropertiesService.
 */
const MAX_TRUSTED_SENDERS = 100;
/** Rows shown before the list collapses behind Gmail's "Show more". */
const TRUSTED_VISIBLE_ROWS = 5;

/** View model for the trusted list card: newest first, plus a count heading. Never mutates the input. */
function trustedListView(list) {
  const entries = (Array.isArray(list) ? list : []).slice().reverse();
  const n = entries.length;
  return {
    entries: entries,
    heading: n === 0 ? 'No trusted senders yet' : n === 1 ? '1 trusted sender' : n + ' trusted senders',
    collapsible: n > TRUSTED_VISIBLE_ROWS,
    full: n >= MAX_TRUSTED_SENDERS,
  };
}

/** One-line labels for the first screen; the full, friendlier sentences live in the details card. */
const RULE_SHORT_LABELS = {
  typosquat_domain: 'Look-alike sender address',
  display_name_domain_mismatch: 'Sender name doesn\u2019t match address',
  reply_to_mismatch: 'Replies go somewhere else',
  spf_fail: 'Sender not verified',
  dkim_fail: 'Signature check failed',
  dmarc_fail: 'Authenticity check failed',
  urgency_financial_proximity: 'Pressure plus money talk',
  credential_request_language: 'Asks for your login details',
  base64_obfuscation: 'Hidden encoded text',
  excessive_url_encoding: 'Scrambled link encoding',
  html_entity_obfuscation: 'Disguised characters',
  link_text_href_mismatch: 'Link goes somewhere else',
  ip_literal_host: 'Link to a bare IP address',
  url_shortener: 'Shortened link',
  high_entropy_domain: 'Random-looking link domain',
  suspicious_tld: 'Link to a risky web ending',
  double_extension: 'Disguised file extension',
  dangerous_extension: 'Program or script attached',
  macro_enabled_with_pressure_context: 'Macro file plus pressure',
  macro_enabled_attachment: 'Macro-enabled attachment',
};

function shortLabelForRule(rule) {
  return RULE_SHORT_LABELS[rule] || 'Something unusual';
}

/** Labels of the check categories that raised no finding ("what we checked"). */
function checksPassed(reasoning) {
  const fired = {};
  (Array.isArray(reasoning) ? reasoning : []).forEach((item) => { fired[item.category] = true; });
  return Object.keys(CHECKS_PERFORMED).filter((key) => !fired[key]).map((key) => CHECKS_PERFORMED[key]);
}

/**
 * Findings for the first screen: heaviest first, identical short labels merged ("... (x2)") so the
 * same line never repeats. Returns [{category, label, count}].
 */
function groupedFindings(reasoning) {
  const groups = [];
  const byLabel = {};
  sortFindings(reasoning).forEach((item) => {
    const label = shortLabelForRule(item.rule);
    if (byLabel[label]) {
      byLabel[label].count += 1;
    } else {
      byLabel[label] = { category: item.category, label: label, count: 1 };
      groups.push(byLabel[label]);
    }
  });
  return groups;
}

// --------------------------------------------------------------------------
// Link inspector: where does each link REALLY go? (pure, never fetches anything)
// --------------------------------------------------------------------------

const TWO_PART_SUFFIXES = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.il', 'org.il',
  'ac.il', 'co.jp', 'co.in', 'com.br', 'com.mx', 'com.tr', 'com.cn', 'co.za'];
const SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly',
  'shorturl.at', 'tiny.cc', 'rb.gy'];
const LINK_STATUS_ORDER = { mismatch: 0, ip: 1, lookalike: 2, shortener: 3, ok: 4 };

/** Host of an http(s) URL, lower-cased; '' for anything else (mailto:, javascript:, junk). */
function hostOf(url) {
  const match = /^https?:\/\/(?:[^\/?#@]*@)?(\[[^\]]+\]|[^\/?#:@]+)/i.exec(String(url == null ? '' : url).trim());
  return match ? match[1].toLowerCase().replace(/\.$/, '') : '';
}

function isIpHost(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.charAt(0) === '[';
}

/** The "site" part of a host: example.com for a.b.example.com (small built-in suffix list, no network). */
function registrableDomain(host) {
  if (!host || isIpHost(host)) return host || '';
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  return TWO_PART_SUFFIXES.indexOf(lastTwo) !== -1 ? labels.slice(-3).join('.') : lastTwo;
}

/** First domain-looking token in the visible link text ('' when the text is just words). */
function domainInText(text) {
  const match = /(?:https?:\/\/)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i.exec(String(text == null ? '' : text));
  return match ? match[1].toLowerCase() : '';
}

/** Verdict on a single {text, href} link. status: mismatch | ip | lookalike | shortener | ok. */
function inspectLink(link) {
  const href = link && link.href;
  const text = link && link.text;
  const host = hostOf(href);
  const shownDomain = domainInText(text);
  const real = registrableDomain(host);
  let status = 'ok';
  if (shownDomain && registrableDomain(shownDomain) !== real) status = 'mismatch';
  else if (isIpHost(host)) status = 'ip';
  else if (host.split('.').some((label) => label.indexOf('xn--') === 0)) status = 'lookalike';
  else if (SHORTENER_DOMAINS.indexOf(real) !== -1) status = 'shortener';
  return { status: status, host: host, shownDomain: shownDomain, shown: safeText(String(text == null ? '' : text).trim(), 60) };
}

/**
 * Report for the "Check the links" card: unique web links, worst first, capped at maxRows.
 * { total, suspicious, more, rows: [{status, host, shownDomain, shown}] }
 */
function inspectLinks(links, maxRows) {
  const seen = {};
  const rows = [];
  (Array.isArray(links) ? links : []).forEach((link) => {
    if (!link || !hostOf(link.href)) return;
    const row = inspectLink(link);
    const key = row.host + '|' + row.shown;
    if (seen[key]) return;
    seen[key] = true;
    rows.push(row);
  });
  // Fine links to the same host collapse into one row ("5 links go where they say").
  const grouped = [];
  const okByHost = {};
  rows.forEach((row) => {
    if (row.status !== 'ok') {
      grouped.push(row);
    } else if (okByHost[row.host]) {
      okByHost[row.host].count += 1;
    } else {
      row.count = 1;
      okByHost[row.host] = row;
      grouped.push(row);
    }
  });
  grouped.sort((a, b) => LINK_STATUS_ORDER[a.status] - LINK_STATUS_ORDER[b.status]);
  const cap = maxRows > 0 ? maxRows : 8;
  return {
    total: rows.length,
    suspicious: rows.filter((r) => r.status !== 'ok').length,
    more: Math.max(0, grouped.length - cap),
    rows: grouped.slice(0, cap),
  };
}

/** One honest line above the list. Never claims the links are safe. */
function linkSummaryText(report) {
  const total = report && report.total ? report.total : 0;
  const bad = report && report.suspicious ? report.suspicious : 0;
  if (total === 0) return 'No web links in this email.';
  const noun = total === 1 ? 'link' : 'links';
  if (bad === 0) return total + ' ' + noun + ' · none hides where it goes.';
  return total + ' ' + noun + ' · <font color="#D32F2F"><b>' + bad + ' worth a closer look</b></font>';
}

const LINK_STATUS_SYMBOL = { mismatch: '✕', ip: '✕', lookalike: '✕', shortener: '⚠', ok: '✓' };
const LINK_STATUS_COLOR = { mismatch: '#D32F2F', ip: '#D32F2F', lookalike: '#D32F2F', shortener: '#C98A2C', ok: '#2E7D6B' };

/** Headline (line 1) of a links-card row, without the symbol. */
function linkHeadline(row) {
  if (row.status === 'mismatch') return 'Says ' + safeText(row.shownDomain, 40);
  if (row.status === 'ip') return 'Numeric address, not a website name';
  if (row.status === 'lookalike') return 'Look-alike characters in the name';
  if (row.status === 'shortener') return 'Shortened link';
  return row.count > 1 ? row.count + ' links go where they say' : 'Goes where it says';
}

/** Two-line text for one row of the links card (HTML-safe): verdict, then the real destination. */
function linkRowText(row) {
  const color = LINK_STATUS_COLOR[row.status];
  const head = '<font color="' + color + '"><b>' + LINK_STATUS_SYMBOL[row.status] + ' ' + linkHeadline(row) + '</b></font><br>';
  const host = '<b>' + safeText(row.host, 60) + '</b>';
  if (row.status === 'ok') return head + host;
  if (row.status === 'shortener') return head + 'Real destination hidden — starts at ' + host;
  return head + 'Goes to ' + host;
}

if (typeof module !== 'undefined') {
  module.exports = {
    normalizeScore, heroFile, HERO_UNSCANNED_FILE, HERO_TRUSTED_FILE, isPublicMailDomain, isTrustedBy, assetUrl, stateForResult, presentationFor,
    topFinding, topFindings, sortFindings, checkStatuses, checkStripText, shortLabelForRule, RULE_SHORT_LABELS, safeText, checksPassed, CHECKS_PERFORMED, SCORE_LEGEND,
    hostOf, registrableDomain, domainInText, inspectLink, inspectLinks, linkSummaryText, linkRowText, linkHeadline, groupedFindings,
    trustedListView, MAX_TRUSTED_SENDERS, TRUSTED_VISIBLE_ROWS,
  };
}
