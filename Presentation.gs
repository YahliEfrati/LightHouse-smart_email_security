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
  return 'hero_' + normalizeScore(score) + '.png';
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

/** Labels of the check categories that raised no finding ("what we checked"). */
function checksPassed(reasoning) {
  const fired = {};
  (Array.isArray(reasoning) ? reasoning : []).forEach((item) => { fired[item.category] = true; });
  return Object.keys(CHECKS_PERFORMED).filter((key) => !fired[key]).map((key) => CHECKS_PERFORMED[key]);
}

if (typeof module !== 'undefined') {
  module.exports = {
    normalizeScore, heroFile, HERO_UNSCANNED_FILE, HERO_TRUSTED_FILE, isPublicMailDomain, isTrustedBy, assetUrl, stateForResult, presentationFor,
    topFinding, topFindings, sortFindings, checkStatuses, checkStripText, safeText, checksPassed, CHECKS_PERFORMED, SCORE_LEGEND,
  };
}
