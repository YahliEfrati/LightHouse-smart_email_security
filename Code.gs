/**
 * Lighthouse - Smart Email Security — Gmail Add-on client
 * =========================================================
 *
 * Brand voice: Lighthouse is a calm, protective guide — not a siren. Think
 * warm beacon light cutting through fog, not a blaring cyber-alarm. The UI
 * stays gentle and reassuring for Safe/Suspicious verdicts, and only breaks
 * that calm, deliberately and dramatically, for genuinely dangerous
 * (Malicious) emails, where clarity and urgency matter more than warmth.
 *
 * Security posture (principle of least privilege):
 *   - oauthScopes in appsscript.json are limited to:
 *       gmail.addons.execute                      (run as a Gmail add-on)
 *       gmail.addons.current.message.readonly      (read ONLY the opened message)
 *       script.external_request                    (call our own local backend)
 *   - We never request gmail.readonly / gmail.modify or any scope that would
 *     grant access to the user's full mailbox. The add-on can only ever see
 *     the single message the user currently has open.
 *   - Only lightweight, already-parsed fields (sender, subject, body text,
 *     link hrefs, attachment metadata) are sent to the backend — never raw
 *     attachment bytes, and never anything beyond the open message.
 */

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

/** Full display name - used only as a subtitle, never as the card title (too long to fit). */
const APP_NAME = 'Lighthouse - Smart Email Security';

/** Short name used for every CardHeader.setTitle() so it never gets clipped. */
const APP_SHORT_NAME = '🗼 Lighthouse';

/**
 * Small, square lighthouse icon shown in the card header via
 * CardHeader.setImageUrl(), establishing the lighthouse motif immediately.
 * Square and compact on purpose - Gmail renders header images in a small
 * fixed avatar slot, so a wide banner gets cropped and bloats card height.
 * Replace with real branded artwork when available.
 */
const HEADER_BANNER_URL = 'https://img.icons8.com/ios-filled/100/FDB813/lighthouse.png';

/**
 * Base URL of the local FastAPI backend (see /backend).
 *
 * For local development/demo, run the backend with:
 *   uvicorn main:app --reload --port 8000
 * then expose it publicly with ngrok (Apps Script runs in Google's cloud and
 * cannot reach "localhost" directly):
 *   ngrok http 8000
 * and paste the printed https://xxxx.ngrok-free.app URL below.
 *
 * Replace this with your own ngrok (or deployed) URL before running the add-on.
 */
const BACKEND_URL = 'https://macaroni-hardwired-uneasily.ngrok-free.dev/api/v1/analyze';

/**
 * Note: Apps Script's UrlFetchApp does not expose a configurable per-request
 * timeout; it enforces its own platform-level timeout (~a few minutes for
 * add-ons, far shorter in practice for interactive calls). We rely on the
 * try/catch in callBackend() below to gracefully handle slow/unreachable
 * backends rather than a custom timeout value.
 */

/**
 * Verdict -> visual style mapping used across cards.
 *
 * Safe and Suspicious keep the calm, Ghibli-esque "safe harbor" aesthetic:
 * soft emoji, gentle Material Icons (verified / explore), muted colors.
 * Malicious deliberately abandons that calm — bold red, uppercase heading,
 * a hard-to-miss report/error icon — because a genuinely dangerous email
 * deserves to interrupt, not soothe.
 */
const VERDICT_STYLE = {
  Safe: {
    color: '#2E7D6B',
    emoji: '🌊',
    materialIcon: 'verified',
    heading: 'Calm waters ahead',
    label: 'No known threats detected. This email looks safe to read.',
  },
  Suspicious: {
    color: '#C98A2C',
    emoji: '💡',
    materialIcon: 'explore',
    heading: 'Worth a closer look',
    label: "Proceed with caution — a few things here are worth a second glance.",
  },
  Malicious: {
    color: '#D32F2F',
    emoji: '⚠️',
    materialIcon: 'report',
    heading: 'DANGER — LIKELY PHISHING',
    label: 'HIGH RISK OF PHISHING. Do not click links or open attachments in this email.',
  },
};

/**
 * Color stops used to build a continuous green -> amber -> red gradient for
 * the risk gauge, keyed by score (0-100). Interpolated at render time so the
 * gauge color slides smoothly with the score instead of jumping between only
 * three fixed verdict colors.
 */
const SCORE_GRADIENT_STOPS = [
  { score: 0, rgb: [46, 125, 107] },   // calm teal-green (matches VERDICT_STYLE.Safe)
  { score: 50, rgb: [201, 138, 44] },  // amber (matches VERDICT_STYLE.Suspicious)
  { score: 100, rgb: [211, 47, 47] },  // red (matches VERDICT_STYLE.Malicious)
];

/**
 * Returns a '#RRGGBB' hex color that linearly interpolates along
 * SCORE_GRADIENT_STOPS for the given 0-100 score, so the gauge color eases
 * gradually from green to red as the score climbs, rather than snapping
 * abruptly at the Safe/Suspicious/Malicious thresholds.
 */
function scoreToColor(score) {
  const clamped = Math.max(0, Math.min(100, score));
  let lower = SCORE_GRADIENT_STOPS[0];
  let upper = SCORE_GRADIENT_STOPS[SCORE_GRADIENT_STOPS.length - 1];
  for (let i = 0; i < SCORE_GRADIENT_STOPS.length - 1; i++) {
    if (clamped >= SCORE_GRADIENT_STOPS[i].score && clamped <= SCORE_GRADIENT_STOPS[i + 1].score) {
      lower = SCORE_GRADIENT_STOPS[i];
      upper = SCORE_GRADIENT_STOPS[i + 1];
      break;
    }
  }
  const span = upper.score - lower.score || 1;
  const t = (clamped - lower.score) / span;
  const rgb = lower.rgb.map((channel, i) => Math.round(channel + (upper.rgb[i] - channel) * t));
  return '#' + rgb.map((c) => c.toString(16).padStart(2, '0')).join('');
}

/** Key used in CacheService to stash the last analysis for the details card. */
const CACHE_KEY_PREFIX = 'last_analysis_';

/** Key used in UserProperties to persist the trusted-sender list. */
const TRUSTED_SENDERS_KEY = 'trustedSenders';

// --------------------------------------------------------------------------
// Entry points
// --------------------------------------------------------------------------

/**
 * Homepage trigger — shown when the add-on is opened without a message
 * context (e.g. from the Gmail add-on tray homepage).
 */
function onHomepage(e) {
  return [buildHomepageCard()];
}

/** Builds the single homepage Card object (shared by the trigger and the Retry button). */
function buildHomepageCard() {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle(APP_SHORT_NAME)
        .setSubtitle('A steady light in a sea of suspicious email')
        .setImageUrl(HEADER_BANNER_URL)
        .setImageStyle(CardService.ImageStyle.SQUARE)
    )
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          'Open any email and Lighthouse will quietly keep watch, scanning it for ' +
            'phishing and malicious-content indicators. Nothing is scanned until you ' +
            'open a message.'
        )
      )
    )
    .addSection(buildManageTrustedSendersSection())
    .build();
}

/**
 * Gmail contextual trigger — fired whenever the user opens an email.
 * This is the main entry point that extracts the message, checks the
 * trusted-sender whitelist, calls the backend, and renders the result.
 */
function buildAddOn(e) {
  try {
    const accessToken = e.gmail.accessToken;
    const messageId = e.gmail.messageId;
    GmailApp.setCurrentMessageAccessToken(accessToken);
    const message = GmailApp.getMessageById(messageId);

    const email = extractEmailData(message);

    // 1. Trusted-sender whitelist short-circuit — never calls the backend.
    if (isTrustedSender(email.senderEmail)) {
      return [buildTrustedSenderCard(email)];
    }

    // 2. Call the local backend (with graceful degradation on failure).
    const result = callBackend(email);
    if (result.error) {
      return [buildBackendDownCard()];
    }

    // Cache the full result (including reasoning) so the "details" card can
    // be rebuilt on a separate navigation round-trip without re-sending data.
    CacheService.getUserCache().put(
      CACHE_KEY_PREFIX + messageId,
      JSON.stringify(result),
      1800 // 30 minutes
    );

    return [buildResultCard(email, result, messageId)];
  } catch (err) {
    return [buildBackendDownCard()];
  }
}

// --------------------------------------------------------------------------
// Email extraction (reads ONLY the currently open message)
// --------------------------------------------------------------------------

/**
 * Extracts the minimal set of fields the backend needs from the open
 * message. Only plain, already-parsed strings/metadata are extracted —
 * never raw attachment bytes.
 */
function extractEmailData(message) {
  const from = message.getFrom() || '';
  const parsedSender = parseSender(from);
  const bodyHtml = safeGet(() => message.getBody()) || '';
  const bodyText = safeGet(() => message.getPlainBody()) || '';

  return {
    senderEmail: parsedSender.email,
    senderDisplayName: parsedSender.displayName,
    replyTo: message.getReplyTo() || null,
    subject: message.getSubject() || '',
    bodyText: bodyText.substring(0, 200000),
    bodyHtml: bodyHtml.substring(0, 400000),
    links: extractLinks(bodyHtml).slice(0, 200),
    attachments: extractAttachmentMetadata(message).slice(0, 50),
  };
}

/** Splits a raw "From" header like `"Alice" <alice@example.com>` into parts. */
function parseSender(from) {
  const match = from.match(/^(.*?)<([^>]+)>$/);
  if (match) {
    return {
      displayName: match[1].trim().replace(/^"|"$/g, ''),
      email: match[2].trim(),
    };
  }
  return { displayName: '', email: from.trim() };
}

/** Extracts visible-text/href pairs for every anchor tag in the HTML body. */
function extractLinks(html) {
  const links = [];
  const anchorRegex = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = anchorRegex.exec(html)) !== null) {
    const href = match[1];
    const text = match[2].replace(/<[^>]+>/g, '').trim();
    links.push({ text: text.substring(0, 2048), href: href.substring(0, 4096) });
  }
  return links;
}

/** Extracts attachment metadata only — filenames/types/sizes, never bytes. */
function extractAttachmentMetadata(message) {
  const attachments = safeGet(() => message.getAttachments({ includeInlineImages: false })) || [];
  return attachments.map((att) => ({
    filename: att.getName(),
    content_type: att.getContentType(),
    size_bytes: att.getSize(),
  }));
}

/** Runs fn() and returns null instead of throwing (used for optional fields). */
function safeGet(fn) {
  try {
    return fn();
  } catch (err) {
    return null;
  }
}

// --------------------------------------------------------------------------
// Backend communication (graceful degradation — never throws)
// --------------------------------------------------------------------------

/**
 * Calls the FastAPI backend's /api/v1/analyze endpoint.
 * Never throws: on any network error, timeout, or non-2xx response it
 * returns { error: true } so the caller can render a friendly fallback card
 * instead of a raw stack trace.
 */
function callBackend(email) {
  const payload = {
    sender: { email: email.senderEmail, display_name: email.senderDisplayName },
    reply_to: email.replyTo,
    subject: email.subject,
    body_text: email.bodyText,
    body_html: email.bodyHtml,
    links: email.links,
    attachments: email.attachments,
    headers: {},
  };

  const options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
    followRedirects: true,
    validateHttpsCertificates: true,
  };

  try {
    const response = UrlFetchApp.fetch(BACKEND_URL, options);
    const statusCode = response.getResponseCode();
    if (statusCode < 200 || statusCode >= 300) {
      return { error: true, reason: 'http_' + statusCode };
    }
    const parsed = JSON.parse(response.getContentText());
    if (
      typeof parsed.score !== 'number' ||
      typeof parsed.verdict !== 'string' ||
      !Array.isArray(parsed.reasoning)
    ) {
      return { error: true, reason: 'malformed_response' };
    }
    return parsed;
  } catch (err) {
    // Covers: connection refused (backend down), DNS failure, timeout,
    // malformed JSON, and any other unexpected UrlFetchApp exception.
    return { error: true, reason: 'exception' };
  }
}

// --------------------------------------------------------------------------
// Trusted senders (user whitelist, stored per-user via PropertiesService)
// --------------------------------------------------------------------------

/** Reads the user's trusted-sender list (emails and/or bare domains). */
function getTrustedSenders() {
  const raw = PropertiesService.getUserProperties().getProperty(TRUSTED_SENDERS_KEY);
  if (!raw) return [];
  try {
    const list = JSON.parse(raw);
    return Array.isArray(list) ? list : [];
  } catch (err) {
    return [];
  }
}

/** Persists the user's trusted-sender list. */
function saveTrustedSenders(list) {
  PropertiesService.getUserProperties().setProperty(TRUSTED_SENDERS_KEY, JSON.stringify(list));
}

/**
 * Returns true if senderEmail matches a trusted full address
 * (alice@example.com) or a trusted bare domain (example.com).
 */
function isTrustedSender(senderEmail) {
  if (!senderEmail) return false;
  const email = senderEmail.toLowerCase().trim();
  const domain = email.split('@')[1] || '';
  const trusted = getTrustedSenders();
  return trusted.some((entry) => {
    const normalized = entry.toLowerCase().trim();
    return normalized === email || normalized === domain;
  });
}

/** Very small validation: either a full address or a bare domain. */
function isValidSenderEntry(entry) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(entry) || /^[^\s@]+\.[^\s@]+$/.test(entry);
}

/**
 * Action handler: adds the email/domain typed into the "Manage Trusted
 * Senders" card's text input to the user's whitelist.
 */
function onAddTrustedSender(e) {
  const entry = ((e.formInput && e.formInput.newTrustedEntry) || '').toLowerCase().trim();
  let notificationText = '';

  if (!entry) {
    notificationText = 'Please enter an email address or domain first.';
  } else if (!isValidSenderEntry(entry)) {
    notificationText = '"' + entry + '" doesn\'t look like a valid email or domain.';
  } else {
    const trusted = getTrustedSenders();
    if (trusted.indexOf(entry) === -1) {
      trusted.push(entry);
      saveTrustedSenders(trusted);
      notificationText = '"' + entry + '" was added to your trusted senders.';
    } else {
      notificationText = '"' + entry + '" is already trusted.';
    }
  }

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(buildManageTrustedSendersCard()))
    .setNotification(CardService.newNotification().setText(notificationText))
    .build();
}

/** Action handler: removes one entry from the trusted-sender whitelist. */
function onRemoveTrustedSender(e) {
  const entry = e.parameters.entry;
  const trusted = getTrustedSenders().filter((item) => item !== entry);
  saveTrustedSenders(trusted);

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(buildManageTrustedSendersCard()))
    .setNotification(CardService.newNotification().setText('"' + entry + '" was removed.'))
    .build();
}

/**
 * Action handler: one-tap "Trust This Sender" button shown on a scan-result
 * card. Adds the current message's sender to the whitelist and re-renders
 * the current message's card as a Trusted Sender card.
 */
function onTrustThisSender(e) {
  const senderEmail = e.parameters.senderEmail;
  const trusted = getTrustedSenders();
  if (trusted.indexOf(senderEmail) === -1) {
    trusted.push(senderEmail);
    saveTrustedSenders(trusted);
  }

  const email = {
    senderEmail: senderEmail,
    senderDisplayName: e.parameters.senderDisplayName || '',
  };

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(buildTrustedSenderCard(email)))
    .setNotification(
      CardService.newNotification().setText(senderEmail + ' is now a familiar, trusted face to the Lighthouse.')
    )
    .build();
}

// --------------------------------------------------------------------------
// UI: risk gauge helper
// --------------------------------------------------------------------------

/**
 * Renders a 10-segment Unicode progress bar for the given 0-100 score, e.g.
 * "[██████░░░░] 65/100", colored with a continuous green -> amber -> red
 * gradient (via scoreToColor) so the gauge itself visibly eases from calm
 * to alarming as the score climbs, rather than only the verdict label
 * changing color in three abrupt steps. CardService has no native
 * gauge/progress widget or custom CSS, so this is the most visually
 * informative option available within DecoratedText's basic HTML support.
 */
function renderRiskGauge(score) {
  const totalSegments = 10;
  const filled = Math.round((Math.max(0, Math.min(100, score)) / 100) * totalSegments);
  const bar = '█'.repeat(filled) + '░'.repeat(totalSegments - filled);
  const color = scoreToColor(score);
  return '<font color="' + color + '">[' + bar + ']</font>  ' + score + ' / 100';
}

/** Looks up the visual style (color/icon/copy) for a verdict string. */
function styleForVerdict(verdict) {
  return VERDICT_STYLE[verdict] || VERDICT_STYLE.Suspicious;
}

/** Builds an IconImage from a Material Icon name, used next to verdict text. */
function materialIconImage(iconName) {
  return CardService.newIconImage().setMaterialIcon(CardService.newMaterialIcon().setName(iconName));
}

/**
 * Tone of voice: translates each backend rule id into a warm, "wise guide"
 * opening line — reassuring and plain-spoken rather than alarmist jargon.
 * The backend's own technical description (with the specific domains,
 * filenames, etc. it found) is still shown underneath in smaller text for
 * anyone who wants the full detail.
 */
const RULE_WISDOM = {
  typosquat_domain: "The sender's address looks very similar to a known brand. Let's be careful here.",
  display_name_domain_mismatch: "This sender's name doesn't quite match where the email actually came from.",
  reply_to_mismatch: 'A reply to this email would quietly travel somewhere different than where it came from.',
  spf_fail: "This email couldn't be verified as coming from where it claims. Worth a second look.",
  dkim_fail: "This email's digital signature didn't check out. Worth a second look.",
  dmarc_fail: 'This email failed its own sender-authenticity check.',
  urgency_financial_proximity: 'This message leans on urgency right alongside money or personal details — a classic pressure tactic.',
  base64_obfuscation: "There's a long block of hidden, encoded text tucked into this email — sometimes used to slip something past the usual checks.",
  excessive_url_encoding: "This email's links are oddly scrambled with encoding, which can be used to hide where they really lead.",
  html_entity_obfuscation: 'Parts of this email are spelled out in a hidden code that only appears once rendered — a known way to dodge filters.',
  link_text_href_mismatch: 'A link here says one thing but quietly leads somewhere else entirely.',
  ip_literal_host: 'One of the links points to a bare numeric address instead of a normal website name — unusual for legitimate mail.',
  url_shortener: "A link here hides behind a shortener, so its true destination isn't visible at a glance.",
  high_entropy_domain: 'One of the links uses a domain name that looks randomly generated, which is unusual for a trustworthy site.',
  double_extension: "This attachment wears two file extensions like a disguise — a classic trick to sneak a program past a quick glance.",
  dangerous_extension: 'This attachment is a program or script file, which can run code on your device if opened.',
  macro_enabled_with_pressure_context: 'This attachment can run automated macros, and it arrived wrapped in urgent, money-related language. That combination deserves real caution.',
  macro_enabled_attachment: 'This attachment can run automated macros when opened — worth knowing before you proceed.',
};

/** Friendly, guide-like labels for each finding category (replacing raw ids). */
const CATEGORY_LABELS = {
  header: { title: 'Who it says it\'s from', icon: 'badge' },
  content: { title: 'What the message says', icon: 'chat_bubble' },
  link: { title: 'Where its links lead', icon: 'link' },
  attachment: { title: "What's attached", icon: 'attach_file' },
};

/** Returns the wise-guide framing for a rule, falling back gracefully for unknown ids. */
function wisdomForRule(rule) {
  return RULE_WISDOM[rule] || "Here's something worth noticing in this email.";
}

// --------------------------------------------------------------------------
// UI: main scan result card
// --------------------------------------------------------------------------

function buildResultCard(email, result, messageId) {
  const style = styleForVerdict(result.verdict);
  const isDanger = result.verdict === 'Malicious';

  // The header always carries the lighthouse banner — the beacon never
  // disappears, even when the news it delivers is urgent.
  const header = CardService.newCardHeader()
    .setTitle(isDanger ? '🚨 ' + style.heading : style.emoji + '  ' + style.heading)
    .setSubtitle(APP_NAME)
    .setImageUrl(HEADER_BANNER_URL)
    .setImageStyle(CardService.ImageStyle.SQUARE);

  // Verdict text is always colored along the same green->amber->red gradient
  // as the risk gauge, so the two reinforce the same continuous signal.
  const verdictColor = scoreToColor(result.score);
  const verdictText = isDanger
    ? '<font color="' + verdictColor + '"><b>' + result.verdict.toUpperCase() + '</b></font>'
    : '<font color="' + verdictColor + '"><b>' + result.verdict + '</b></font>';

  const gaugeSection = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setStartIcon(materialIconImage(style.materialIcon))
        .setText(verdictText + ' &nbsp;·&nbsp; ' + renderRiskGauge(result.score))
        .setBottomLabel(isDanger ? style.label.toUpperCase() : style.label)
        .setWrapText(true)
    )
    .addWidget(
      CardService.newTextParagraph().setText(
        '<b>From:</b> ' + escapeHtml(email.senderDisplayName || email.senderEmail) +
          ' &lt;' + escapeHtml(email.senderEmail) + '&gt;'
      )
    );

  const detailsButton = CardService.newTextButton()
    .setText(isDanger ? '⚠ VIEW WHY THIS IS DANGEROUS' : 'View Analysis Details')
    .setOnClickAction(
      CardService.newAction().setFunctionName('onViewDetails').setParameters({ messageId: messageId })
    );
  if (isDanger) {
    detailsButton.setTextButtonStyle(CardService.TextButtonStyle.FILLED).setBackgroundColor('#D32F2F');
  } else {
    detailsButton.setTextButtonStyle(CardService.TextButtonStyle.OUTLINED);
  }

  const actionsSection = CardService.newCardSection()
    .addWidget(detailsButton)
    .addWidget(
      CardService.newTextButton()
        .setText('✓ Trust This Sender')
        .setOnClickAction(
          CardService.newAction().setFunctionName('onTrustThisSender').setParameters({
            senderEmail: email.senderEmail,
            senderDisplayName: email.senderDisplayName || '',
          })
        )
    )
    .addWidget(
      CardService.newTextButton()
        .setText('⚑ I think this is a mistake')
        .setOnClickAction(CardService.newAction().setFunctionName('onSubmitFeedback'))
    );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(gaugeSection)
    .addSection(actionsSection)
    .build();
}

// --------------------------------------------------------------------------
// UI: "View Analysis Details" — progressive disclosure via pushCard()
// --------------------------------------------------------------------------

/**
 * Action handler for the "View Analysis Details" button. Reads the cached
 * reasoning for this message and pushes a new card onto the navigation
 * stack, triggering Gmail's native slide-in animation (no custom CSS used
 * or needed).
 */
function onViewDetails(e) {
  const messageId = e.parameters.messageId;
  const cached = CacheService.getUserCache().get(CACHE_KEY_PREFIX + messageId);

  let result;
  try {
    result = cached ? JSON.parse(cached) : null;
  } catch (err) {
    result = null;
  }

  const detailsCard = result
    ? buildDetailsCard(result)
    : buildSimpleMessageCard('Analysis Details', 'This analysis has expired. Please re-open the email to re-scan it.');

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(detailsCard))
    .build();
}

/** Builds the pushed "Analysis Details" card, grouped by category. */
function buildDetailsCard(result) {
  const style = styleForVerdict(result.verdict);
  const isDanger = result.verdict === 'Malicious';

  const header = CardService.newCardHeader()
    .setTitle(isDanger ? "The Lighthouse's Warning" : "The Lighthouse's Notes")
    .setSubtitle(style.emoji + ' ' + result.verdict + '  ·  score ' + result.score + '/100')
    .setImageUrl(HEADER_BANNER_URL)
    .setImageStyle(CardService.ImageStyle.SQUARE);

  const card = CardService.newCardBuilder().setHeader(header);

  if (!result.reasoning || result.reasoning.length === 0) {
    card.addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          'The waters look calm — Lighthouse did not notice anything worth flagging in this email.'
        )
      )
    );
    return card.build();
  }

  const byCategory = groupByCategory(result.reasoning);
  Object.keys(byCategory).forEach((category) => {
    const meta = CATEGORY_LABELS[category] || { title: capitalize(category), icon: 'info' };
    const section = CardService.newCardSection().setHeader(meta.title);
    byCategory[category].forEach((item) => {
      section.addWidget(
        CardService.newDecoratedText()
          .setStartIcon(materialIconImage(meta.icon))
          .setText(escapeHtml(wisdomForRule(item.rule)))
          .setBottomLabel(escapeHtml(item.description))
          .setWrapText(true)
      );
    });
    card.addSection(section);
  });

  return card.build();
}

function groupByCategory(reasoning) {
  const groups = {};
  reasoning.forEach((item) => {
    const key = item.category || 'other';
    if (!groups[key]) groups[key] = [];
    groups[key].push(item);
  });
  return groups;
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// --------------------------------------------------------------------------
// UI: trusted sender / backend-down fallback cards
// --------------------------------------------------------------------------

/** Friendly, calm card shown when the sender is on the user's whitelist. */
function buildTrustedSenderCard(email) {
  const header = CardService.newCardHeader()
    .setTitle('🌊  A Familiar Face')
    .setSubtitle(APP_NAME)
    .setImageUrl(HEADER_BANNER_URL)
    .setImageStyle(CardService.ImageStyle.SQUARE);

  const section = CardService.newCardSection().addWidget(
    CardService.newDecoratedText()
      .setStartIcon(materialIconImage('verified'))
      .setText(
        '<b>' + escapeHtml(email.senderDisplayName || email.senderEmail) + '</b> (' +
          escapeHtml(email.senderEmail) +
          ') is on your trusted list, so Lighthouse let this one pass by without a scan.'
      )
      .setWrapText(true)
  );

  return CardService.newCardBuilder().setHeader(header).addSection(section).build();
}

/**
 * Friendly fallback card shown whenever the backend is unreachable, slow,
 * or returns an unexpected response — the user never sees a raw exception.
 */
function buildBackendDownCard() {
  const header = CardService.newCardHeader()
    .setTitle('🕯️  The Beacon Rests')
    .setSubtitle(APP_NAME)
    .setImageUrl(HEADER_BANNER_URL)
    .setImageStyle(CardService.ImageStyle.SQUARE);
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        'The Lighthouse beacon is currently resting. Please try again later.'
      )
    )
    .addWidget(
      CardService.newTextParagraph().setText(
        '<i>Tip: closing and re-opening this email will relight the beacon for a fresh scan.</i>'
      )
    );
  return CardService.newCardBuilder().setHeader(header).addSection(section).build();
}

/** Generic single-message card used for minor fallback states. */
function buildSimpleMessageCard(title, message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle(title))
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(message)))
    .build();
}

// --------------------------------------------------------------------------
// UI: manage trusted senders
// --------------------------------------------------------------------------

/** Standalone card (pushed from the homepage) for managing the whitelist. */
function buildManageTrustedSendersCard() {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle('Familiar Faces')
        .setSubtitle(APP_NAME)
        .setImageUrl(HEADER_BANNER_URL)
        .setImageStyle(CardService.ImageStyle.SQUARE)
    )
    .addSection(buildManageTrustedSendersSection())
    .build();
}

/** The reusable section (input + list) embedded in both the homepage and the standalone card. */
function buildManageTrustedSendersSection() {
  const section = CardService.newCardSection().setHeader('Trusted Senders — Familiar Faces Lighthouse Won\'t Scan');

  section.addWidget(
    CardService.newTextInput()
      .setFieldName('newTrustedEntry')
      .setTitle('Add email or domain')
      .setHint('e.g. alice@example.com or example.com')
  );
  section.addWidget(
    CardService.newTextButton()
      .setText('Add to Trusted List')
      .setOnClickAction(CardService.newAction().setFunctionName('onAddTrustedSender'))
  );

  const trusted = getTrustedSenders();
  if (trusted.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText('No trusted senders yet.'));
  } else {
    trusted.forEach((entry) => {
      section.addWidget(
        CardService.newDecoratedText()
          .setText(escapeHtml(entry))
          .setButton(
            CardService.newTextButton()
              .setText('Remove')
              .setOnClickAction(
                CardService.newAction().setFunctionName('onRemoveTrustedSender').setParameters({ entry: entry })
              )
          )
      );
    });
  }

  return section;
}

/** Opens the "Manage Trusted Senders" card via navigation (e.g. from a menu). */
function onOpenManageTrustedSenders(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(buildManageTrustedSendersCard()))
    .build();
}

// --------------------------------------------------------------------------
// User feedback loop
// --------------------------------------------------------------------------

/**
 * Action handler for the "I think this is a mistake" button. Records
 * nothing sensitive server-side (this is a local demo); simply acknowledges
 * the feedback with a toast, per the UX requirement.
 */
function onSubmitFeedback(e) {
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText('Thank you! Your feedback helps calibrate the Lighthouse.')
    )
    .build();
}

// --------------------------------------------------------------------------
// Small utilities
// --------------------------------------------------------------------------

/** Minimal HTML-escaping for values interpolated into CardService text widgets. */
function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
