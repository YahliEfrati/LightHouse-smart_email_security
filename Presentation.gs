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

/** Labels of the check categories that raised no finding ("what we checked"). */
function checksPassed(reasoning) {
  const fired = {};
  (Array.isArray(reasoning) ? reasoning : []).forEach((item) => { fired[item.category] = true; });
  return Object.keys(CHECKS_PERFORMED).filter((key) => !fired[key]).map((key) => CHECKS_PERFORMED[key]);
}

if (typeof module !== 'undefined') {
  module.exports = {
    normalizeScore, heroFile, HERO_UNSCANNED_FILE, assetUrl, stateForResult, presentationFor,
    topFinding, safeText, checksPassed, CHECKS_PERFORMED,
  };
}
