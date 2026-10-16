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

/** Free-mail providers: trusting a whole provider domain would trust millions of strangers. */
const PUBLIC_MAIL_DOMAINS = ['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  'yahoo.com', 'ymail.com', 'icloud.com', 'me.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com',
  'walla.co.il', 'zoho.com', 'yandex.com', 'yandex.ru'];

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

// --------------------------------------------------------------------------
// Trusted-contact impersonation (runs in the add-on so the contact list never leaves Google)
// --------------------------------------------------------------------------

/** Mirrors EmailRiskAnalyzer.VERDICT_THRESHOLDS (backend/tests/test_shared_lists.py checks it). */
const VERDICT_THRESHOLDS = { malicious: 70, suspicious: 35 };
/** Same weight as the backend's typosquat_domain: a look-alike of someone you trust is as strong a signal. */
const IMPERSONATION_WEIGHT = 40;

function verdictForScore(score) {
  const n = normalizeScore(score);
  return n >= VERDICT_THRESHOLDS.malicious ? 'Malicious' : n >= VERDICT_THRESHOLDS.suspicious ? 'Suspicious' : 'Safe';
}

/** Levenshtein distance, stopping early once it exceeds `max`. */
function editDistance(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      best = Math.min(best, cur[j]);
    }
    if (best > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

/** Collapses common look-alike swaps (c0rp -> corp, rn -> m, hyphens) before comparing domains. */
function lookalikeKey(domain) {
  return domain.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/[1|]/g, 'l')
    .replace(/3/g, 'e').replace(/5/g, 's').replace(/-/g, '');
}

/**
 * Does this (untrusted) sender pose as someone on the trusted list? Returns { entry, how } or null.
 * how: 'name'   - the display name shows a trusted address but the mail comes from another one;
 *      'domain' - the sending domain is a near-copy of a trusted contact's domain (c0rp.example).
 * Free-mail domains are never compared (mail.com vs gmail.com is not an attack).
 */
function trustedLookalike(senderEmail, displayName, trustedList) {
  const sender = String(senderEmail || '').toLowerCase().trim();
  if (!sender || !Array.isArray(trustedList) || isTrustedBy(sender, trustedList)) return null;
  const name = String(displayName || '').toLowerCase();
  const senderSite = registrableDomain(sender.split('@')[1] || '');
  for (let i = 0; i < trustedList.length; i++) {
    const entry = String(trustedList[i]).toLowerCase().trim();
    if (entry.indexOf('@') !== -1 && name.indexOf(entry) !== -1) return { entry: entry, how: 'name' };
    const site = registrableDomain(entry.indexOf('@') !== -1 ? entry.split('@')[1] : entry);
    if (!site || !senderSite || site === senderSite || isPublicMailDomain(site) || isPublicMailDomain(senderSite)) continue;
    // Measure the name ("acmecorp"), not the whole domain: short names (abc vs abd) are different companies.
    const nameLength = site.split('.')[0].length;
    const limit = nameLength >= 10 ? 2 : 1;
    if (lookalikeKey(site) === lookalikeKey(senderSite) || (nameLength >= 5 && editDistance(site, senderSite, limit) <= limit)) {
      return { entry: entry, how: 'domain' };
    }
  }
  return null;
}

/**
 * Adds a trusted_contact_impersonation finding (and its weight) to a backend result when the sender poses
 * as a trusted contact. Returns a new result; never mutates the input.
 */
function applyTrustedLookalike(result, senderEmail, displayName, trustedList) {
  const hit = trustedLookalike(senderEmail, displayName, trustedList);
  if (!hit) return result;
  const description = hit.how === 'name'
    ? 'The sender name shows your trusted contact ' + hit.entry + ', but the email really comes from ' + senderEmail + '.'
    : 'The sender ' + senderEmail + ' looks like your trusted contact ' + hit.entry + ' but is a different address.';
  const score = Math.min(100, normalizeScore(result.score) + IMPERSONATION_WEIGHT);
  return Object.assign({}, result, {
    score: score,
    verdict: verdictForScore(score),
    reasoning: (Array.isArray(result.reasoning) ? result.reasoning : []).concat([
      { category: 'header', rule: 'trusted_contact_impersonation', weight: IMPERSONATION_WEIGHT, description: description },
    ]),
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
  trusted_contact_impersonation: 'Poses as someone you trust',
  spf_fail: 'Sender not verified',
  dkim_fail: 'Signature check failed',
  dmarc_fail: 'Authenticity check failed',
  urgency_financial_proximity: 'Pressure plus money talk',
  credential_request_language: 'Asks for your login details',
  payment_request_pressure: 'Money request under pressure',
  payment_request_unverified_sender: 'Money request from a personal address',
  base64_obfuscation: 'Hidden encoded text',
  excessive_url_encoding: 'Scrambled link encoding',
  html_entity_obfuscation: 'Disguised characters',
  link_text_href_mismatch: 'Link goes somewhere else',
  ip_literal_host: 'Link to a bare IP address',
  url_shortener: 'Shortened link',
  high_entropy_domain: 'Random-looking link domain',
  suspicious_tld: 'Link to a risky web ending',
  punycode_lookalike_domain: 'Look-alike letters in a link',
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

/**
 * Details card: findings of the same rule merged into one entry (first-seen order, so pass them sorted),
 * keeping every specific description. Returns [{rule, category, descriptions: [...]}].
 */
function findingsByRule(items) {
  const merged = [];
  const byRule = {};
  (Array.isArray(items) ? items : []).forEach((item) => {
    if (!byRule[item.rule]) {
      byRule[item.rule] = { rule: item.rule, category: item.category, descriptions: [] };
      merged.push(byRule[item.rule]);
    }
    byRule[item.rule].descriptions.push(item.description);
  });
  return merged;
}

// --------------------------------------------------------------------------
// Link inspector: where does each link REALLY go? (pure, never fetches anything)
// --------------------------------------------------------------------------

const TWO_PART_SUFFIXES = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.il', 'org.il',
  'ac.il', 'co.jp', 'co.in', 'com.br', 'com.mx', 'com.tr', 'com.cn', 'co.za'];
/**
 * Shared hosting: anyone can get name.github.io, so each subdomain is its own site (mybank.github.io and
 * evil.github.io must not look like one site). Keep in sync with backend/analyzer.py (test_shared_lists.py).
 */
const SHARED_HOSTING_SUFFIXES = ['github.io', 'gitlab.io', 'web.app', 'firebaseapp.com', 'netlify.app', 'vercel.app',
  'pages.dev', 'workers.dev', 'herokuapp.com', 'azurewebsites.net', 'blogspot.com', 'wixsite.com', 'weebly.com',
  'glitch.me', 'onrender.com', 'appspot.com', 's3.amazonaws.com', 'r2.dev', 'ngrok-free.app'];
const SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly',
  'shorturl.at', 'tiny.cc', 'rb.gy'];
/**
 * Click-tracking domains of mainstream newsletter services: legit newsletters wrap every link in these.
 * Keep in sync with LinkAnalyzer.ESP_CLICK_TRACKERS in backend/analyzer.py.
 */
const EMAIL_TRACKER_DOMAINS = ['list-manage.com', 'mailchi.mp', 'mandrillapp.com', 'sendgrid.net', 'rs6.net', 'createsend1.com',
  'cmail19.com', 'cmail20.com', 'hubspotlinks.com', 'exacttarget.com', 'sparkpostmail.com', 'mlsend.com', 'klclick.com'];
const LINK_STATUS_ORDER = { mismatch: 0, ip: 1, lookalike: 2, shortener: 3, tracker: 4, ok: 5 };

function isEmailTrackerHost(host) {
  return EMAIL_TRACKER_DOMAINS.some((d) => host === d || host.slice(-(d.length + 1)) === '.' + d);
}

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
  // Longest matching suffix wins (mysite.s3.amazonaws.com before amazonaws.com); same logic as
  // registrable_domain() in backend/analyzer.py.
  const suffixes = TWO_PART_SUFFIXES.concat(SHARED_HOSTING_SUFFIXES).sort((a, b) => b.length - a.length);
  for (let i = 0; i < suffixes.length; i++) {
    const suffix = suffixes[i];
    if (host === suffix) return host;
    if (host.slice(-(suffix.length + 1)) === '.' + suffix) {
      const rest = host.slice(0, -(suffix.length + 1)).split('.');
      return rest[rest.length - 1] + '.' + suffix;
    }
  }
  return host.split('.').slice(-2).join('.');
}

/** First domain-looking token in the visible link text ('' when the text is just words). */
function domainInText(text) {
  // An email address ("mailed to you@gmail.com") is not a promise about which site the link opens.
  const withoutEmails = String(text == null ? '' : text).replace(/[^\s@<>()\[\]"',;]+@[^\s@<>()\[\]"',;]+/g, ' ');
  const match = /(?:https?:\/\/)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i.exec(withoutEmails);
  return match ? match[1].toLowerCase() : '';
}

/** Verdict on a single {text, href} link. status: mismatch | ip | lookalike | shortener | tracker | ok. */
function inspectLink(link) {
  const href = link && link.href;
  const text = link && link.text;
  const host = hostOf(href);
  const shownDomain = domainInText(text);
  const real = registrableDomain(host);
  let status = 'ok';
  // A newsletter service's click tracker hides the destination by design; it is not a mismatch.
  if (isEmailTrackerHost(host)) status = 'tracker';
  else if (shownDomain && registrableDomain(shownDomain) !== real) status = 'mismatch';
  else if (isIpHost(host)) status = 'ip';
  else if (host.split('.').some((label) => label.indexOf('xn--') === 0) || /[^\x00-\x7f]/.test(host)) status = 'lookalike';
  else if (SHORTENER_DOMAINS.indexOf(real) !== -1) status = 'shortener';
  return { status: status, host: host, shownDomain: shownDomain, shown: safeText(String(text == null ? '' : text).trim(), 60) };
}

/**
 * Report for the "Check the links" card: unique web links, worst first, capped at maxRows.
 * { total, suspicious, tracked, more, rows: [{status, host, shownDomain, shown}] }
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
  // Fine (or newsletter-tracked) links to the same host collapse into one row ("5 links go where they say").
  const grouped = [];
  const okByHost = {};
  rows.forEach((row) => {
    const key = row.status + '|' + row.host;
    if (row.status !== 'ok' && row.status !== 'tracker') {
      grouped.push(row);
    } else if (okByHost[key]) {
      okByHost[key].count += 1;
    } else {
      row.count = 1;
      okByHost[key] = row;
      grouped.push(row);
    }
  });
  grouped.sort((a, b) => LINK_STATUS_ORDER[a.status] - LINK_STATUS_ORDER[b.status]);
  const cap = maxRows > 0 ? maxRows : 8;
  return {
    total: rows.length,
    suspicious: rows.filter((r) => r.status !== 'ok' && r.status !== 'tracker').length,
    tracked: rows.filter((r) => r.status === 'tracker').length,
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
  const tracked = report && report.tracked ? report.tracked : 0;
  if (bad === 0 && tracked > 0) return total + ' ' + noun + ' · ' + tracked + ' routed through a mailing service.';
  if (bad === 0) return total + ' ' + noun + ' · none hides where it goes.';
  return total + ' ' + noun + ' · <font color="#D32F2F"><b>' + bad + ' worth a closer look</b></font>';
}

const LINK_STATUS_SYMBOL = { mismatch: '✕', ip: '✕', lookalike: '✕', shortener: '⚠', tracker: 'ℹ', ok: '✓' };
const LINK_STATUS_COLOR = { mismatch: '#D32F2F', ip: '#D32F2F', lookalike: '#D32F2F', shortener: '#C98A2C', tracker: '#6B6B6B', ok: '#2E7D6B' };

/** Headline (line 1) of a links-card row, without the symbol. */
function linkHeadline(row) {
  if (row.status === 'mismatch') return 'Says ' + safeText(row.shownDomain, 40);
  if (row.status === 'ip') return 'Numeric address, not a website name';
  if (row.status === 'lookalike') return 'Look-alike characters in the name';
  if (row.status === 'shortener') return 'Shortened link';
  if (row.status === 'tracker') return row.count > 1 ? row.count + ' newsletter tracking links' : 'Newsletter tracking link';
  return row.count > 1 ? row.count + ' links go where they say' : 'Goes where it says';
}

/** Two-line text for one row of the links card (HTML-safe): verdict, then the real destination. */
function linkRowText(row) {
  const color = LINK_STATUS_COLOR[row.status];
  const head = '<font color="' + color + '"><b>' + LINK_STATUS_SYMBOL[row.status] + ' ' + linkHeadline(row) + '</b></font><br>';
  const host = '<b>' + safeText(row.host, 60) + '</b>';
  if (row.status === 'ok') return head + host;
  if (row.status === 'shortener') return head + 'Real destination hidden — starts at ' + host;
  if (row.status === 'tracker') return head + 'Routed through the mailing service at ' + host;
  return head + 'Goes to ' + host;
}

if (typeof module !== 'undefined') {
  module.exports = {
    normalizeScore, heroFile, HERO_UNSCANNED_FILE, HERO_TRUSTED_FILE, isPublicMailDomain, isTrustedBy, assetUrl, stateForResult, presentationFor,
    sortFindings, checkStatuses, checkStripText, shortLabelForRule, RULE_SHORT_LABELS, safeText, checksPassed, CHECKS_PERFORMED, SCORE_LEGEND,
    hostOf, registrableDomain, domainInText, inspectLink, inspectLinks, linkSummaryText, linkRowText, linkHeadline, groupedFindings,
    trustedListView, MAX_TRUSTED_SENDERS, TRUSTED_VISIBLE_ROWS, findingsByRule, isEmailTrackerHost,
    verdictForScore, editDistance, trustedLookalike, applyTrustedLookalike, VERDICT_THRESHOLDS,
  };
}
