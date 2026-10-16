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
 * Public base URL of the static image assets (icons and per-score hero images).
 * Gmail card images must be loaded from a public HTTPS URL, so the PNGs generated
 * by tools/generate_assets.py are committed to the repo's /assets folder and served
 * from raw.githubusercontent.com (the repository must be public).
 */
const ASSET_BASE_URL = 'https://raw.githubusercontent.com/YahliEfrati/LightHouse-smart_email_security/main/assets/';

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

/** Per-state accent colors, shared with the generated assets (tools/generate_assets.py). */
const STATE_COLORS = {
  safe: '#2E7D6B',
  suspicious: '#C98A2C',
  malicious: '#D32F2F',
  unscanned: '#8A949B',
};

/** How many findings the first screen shows before pointing to the details card. */
const MAX_FINDINGS_ON_CARD = 3;

/** Key used in CacheService to stash the last analysis for the details card. */
const CACHE_KEY_PREFIX = 'last_analysis_';

/** CacheService key prefix for the per-message link report behind the "Check the links" button. */
const LINKS_CACHE_PREFIX = 'links_';

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
        // Gmail's top bar shows the manifest name on one line only (the full name was cut off there),
        // so the full product name lives here, where the subtitle wraps.
        .setSubtitle('Smart Email Security')
        .setImageUrl(assetUrl('icon_safe.png'))
        .setImageStyle(CardService.ImageStyle.SQUARE)
    )
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          '<i>A steady light in a sea of suspicious email.</i><br><br>' +
            'Open any email and Lighthouse will quietly keep watch, scanning it for ' +
            'phishing and other malicious-content indicators. Nothing is scanned until you ' +
            'open a message.'
        )
      )
    )
    // Only a button here: the list lives on its own card, so a long list never buries the intro.
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextButton()
          .setText('Manage trusted senders')
          .setOnClickAction(CardService.newAction().setFunctionName('onOpenManageTrustedSenders'))
      )
    )
    .build();
}

function buildAddOn(e) {
  try {
    const accessToken = e.gmail.accessToken;
    const messageId = e.gmail.messageId;
    GmailApp.setCurrentMessageAccessToken(accessToken);
    const message = GmailApp.getMessageById(messageId);

    const email = extractEmailData(message);
    const trusted = isTrustedSender(email.senderEmail);

    // Trusted senders are still scanned silently: a forged "trusted" address must not bypass the checks.
    const scanned = callBackend(email);
    if (scanned.error) {
      return [buildNotScannedCard()];
    }
    // Checked here, not in the backend, so the user's contact list never leaves Google.
    const result = applyTrustedLookalike(scanned, email.senderEmail, email.senderDisplayName, getTrustedSenders());

    // Cache the full result (including reasoning) so the "details" card can
    // be rebuilt on a separate navigation round-trip without re-sending data.
    CacheService.getUserCache().put(
      CACHE_KEY_PREFIX + messageId,
      JSON.stringify(result),
      1800 // 30 minutes
    );

    // The link report is computed here (links are only available while the message is open) and cached
    // so the "Check the links" button can render later without re-reading the message.
    CacheService.getUserCache().put(
      LINKS_CACHE_PREFIX + messageId,
      JSON.stringify(inspectLinks(email.links, 8)),
      1800
    );

    // Trusted sender: calm "0" card, unless the scan says the email is dangerous.
    if (trusted && stateForResult(result) !== 'malicious') {
      return [buildTrustedSenderCard(email)];
    }
    return [buildResultCard(email, result, messageId, trusted)];
  } catch (err) {
    return [buildNotScannedCard()];
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
    // Address only: getReplyTo() can return 'Name <x@y.com>', which once made the backend read the
    // domain as 'y.com>' and report a Reply-To mismatch on ordinary newsletters.
    replyTo: parseSender(String(message.getReplyTo() || '').split(',')[0]).email || null,
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
 * Shared secret for the backend, kept in Script Properties (never in source or git):
 * Apps Script editor -> Project Settings -> Script Properties -> BACKEND_API_KEY.
 * If it is missing or wrong the backend answers 401 and the user sees the grey "Not scanned" card.
 */
function getBackendApiKey() {
  return (PropertiesService.getScriptProperties().getProperty('BACKEND_API_KEY') || '').trim();
}

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
    headers: { 'X-Lighthouse-Key': getBackendApiKey() },
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

/** True if the sender is on the user's trusted list (see isTrustedBy for the matching rules). */
function isTrustedSender(senderEmail) {
  return isTrustedBy(senderEmail, getTrustedSenders());
}

/** Very small validation: either a full address or a bare domain. */
function isValidSenderEntry(entry) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(entry) || /^[^\s@]+\.[^\s@]+$/.test(entry);
}

/**
 * Action handler: adds the email/domain typed into the "Trusted senders" card's text input
 * to the user's list. Whole free-mail provider domains (gmail.com...) are refused.
 */
function onAddTrustedSender(e) {
  const entry = ((e.formInput && e.formInput.newTrustedEntry) || '').toLowerCase().trim();
  let notificationText = '';

  if (!entry) {
    notificationText = 'Please enter an email address or domain first.';
  } else if (!isValidSenderEntry(entry)) {
    notificationText = '"' + entry + '" doesn\'t look like a valid email or domain.';
  } else if (entry.indexOf('@') === -1 && isPublicMailDomain(entry)) {
    notificationText = 'Trusting all of ' + entry + ' would trust millions of strangers. Add specific addresses instead.';
  } else {
    const trusted = getTrustedSenders();
    if (trusted.indexOf(entry) === -1 && trusted.length >= MAX_TRUSTED_SENDERS) {
      notificationText = 'Your trusted list is full (' + MAX_TRUSTED_SENDERS + '). Remove someone first.';
    } else if (trusted.indexOf(entry) === -1) {
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
 * Action handler: one-tap "Trust sender" on a scan-result card. Adds the sender's full address
 * (never the whole domain) and re-renders the card as a Trusted sender card.
 */
function onTrustThisSender(e) {
  const senderEmail = (e.parameters.senderEmail || '').toLowerCase().trim();
  if (senderEmail) {
    const trusted = getTrustedSenders();
    if (trusted.indexOf(senderEmail) === -1 && trusted.length >= MAX_TRUSTED_SENDERS) {
      // Stay on the result card; just explain.
      return CardService.newActionResponseBuilder()
        .setNotification(
          CardService.newNotification().setText('Your trusted list is full (' + MAX_TRUSTED_SENDERS + '). Remove someone from ⋮ > Trusted senders.')
        )
        .build();
    }
    if (trusted.indexOf(senderEmail) === -1) {
      trusted.push(senderEmail);
      saveTrustedSenders(trusted);
    }
  }

  const email = {
    senderEmail: senderEmail,
    senderDisplayName: e.parameters.senderDisplayName || '',
  };

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(buildTrustedSenderCard(email)))
    .setNotification(CardService.newNotification().setText(senderEmail + ' was added to your trusted senders.'))
    .build();
}

/** Action handler: "Remove from trusted" on the Trusted sender card. */
function onUntrustThisSender(e) {
  const senderEmail = (e.parameters.senderEmail || '').toLowerCase().trim();
  saveTrustedSenders(getTrustedSenders().filter((item) => item !== senderEmail));
  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().updateCard(
        buildSimpleMessageCard('Removed from trusted', senderEmail + ' is no longer trusted. Re-open the email for a normal scan.')
      )
    )
    .setNotification(CardService.newNotification().setText('Removed from your trusted senders.'))
    .build();
}

// --------------------------------------------------------------------------
// UI: shared helpers
// --------------------------------------------------------------------------

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
  trusted_contact_impersonation: "This sender is dressed up as someone on your trusted list, but it isn't them. Don't act on it before checking with them another way.",
  reply_to_mismatch: 'A reply to this email would quietly travel somewhere different than where it came from.',
  spf_fail: "This email couldn't be verified as coming from where it claims. Worth a second look.",
  dkim_fail: "This email's digital signature didn't check out. Worth a second look.",
  dmarc_fail: 'This email failed its own sender-authenticity check.',
  urgency_financial_proximity: 'This message leans on urgency right alongside money or personal details — a classic pressure tactic.',
  credential_request_language: 'This message asks you to enter or confirm your login or payment details — the one thing a phishing email really wants.',
  base64_obfuscation: "There's a long block of hidden, encoded text tucked into this email — sometimes used to slip something past the usual checks.",
  excessive_url_encoding: "This email's links are oddly scrambled with encoding, which can be used to hide where they really lead.",
  html_entity_obfuscation: 'Parts of this email are spelled out in a hidden code that only appears once rendered — a known way to dodge filters.',
  link_text_href_mismatch: 'A link here says one thing but quietly leads somewhere else entirely.',
  ip_literal_host: 'One of the links points to a bare numeric address instead of a normal website name — unusual for legitimate mail.',
  url_shortener: "A link here hides behind a shortener, so its true destination isn't visible at a glance.",
  high_entropy_domain: 'One of the links uses a domain name that looks randomly generated, which is unusual for a trustworthy site.',
  punycode_lookalike_domain: 'A link uses letters from another alphabet that can look exactly like a familiar website name.',
  suspicious_tld: 'One of the links ends in a web address ending (like .top or .xyz) that scammers favor because it is cheap and rarely checked.',
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

function buildResultCard(email, result, messageId, isTrusted) {
  const state = stateForResult(result);
  const view = presentationFor(state);
  const isDanger = state === 'malicious';
  const score = normalizeScore(result.score);
  const color = STATE_COLORS[state];

  // The band carries the verdict color and the gradient gauge; the score itself is native text.
  const bandSection = CardService.newCardSection()
    .addWidget(
      CardService.newImage()
        .setImageUrl(assetUrl(heroFile(score)))
        .setAltText(view.headline + ' — risk ' + score + ' out of 100')
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('RISK SCORE')
        .setText('<font color="' + color + '"><b>' + score + '</b></font> / 100')
        .setBottomLabel('Scanned just now')
    )
    .addWidget(CardService.newTextParagraph().setText(checkStripText(checkStatuses(result.reasoning))));

  if (isTrusted) {
    bandSection.addWidget(
      CardService.newTextParagraph().setText('<b>This sender is on your trusted list, but this email looks dangerous.</b>')
    );
  }

  const card = CardService.newCardBuilder().addSection(bandSection);

  const allGroups = state === 'safe' ? [] : groupedFindings(result.reasoning);
  const findings = allGroups.slice(0, MAX_FINDINGS_ON_CARD);
  if (findings.length > 0) {
    const findingsSection = CardService.newCardSection();
    findings.forEach((item) => {
      const meta = CATEGORY_LABELS[item.category] || { icon: 'info' };
      findingsSection.addWidget(
        CardService.newDecoratedText()
          .setStartIcon(materialIconImage(meta.icon))
          .setText(safeText(item.label, 60) + (item.count > 1 ? ' (\u00D7' + item.count + ')' : ''))
      );
    });
    const more = allGroups.length - findings.length;
    if (more > 0) {
      findingsSection.addWidget(CardService.newTextParagraph().setText('<i>+' + more + ' more in the details</i>'));
    }
    card.addSection(findingsSection);
  }

  const actionsSection = CardService.newCardSection();
  if (isDanger) {
    actionsSection.addWidget(
      CardService.newTextParagraph().setText('<font color="' + STATE_COLORS.malicious + '"><b>' + view.todo + '</b></font>')
    );
  }
  const detailsButton = CardService.newTextButton()
    .setText(isDanger ? 'View why this is dangerous' : 'View details')
    .setOnClickAction(
      CardService.newAction().setFunctionName('onViewDetails').setParameters({ messageId: messageId })
    );
  if (isDanger) {
    detailsButton.setTextButtonStyle(CardService.TextButtonStyle.FILLED).setBackgroundColor(STATE_COLORS.malicious);
  } else {
    detailsButton.setTextButtonStyle(CardService.TextButtonStyle.OUTLINED);
  }
  actionsSection.addWidget(detailsButton);
  if (email.links && inspectLinks(email.links, 1).total > 0) {
    actionsSection.addWidget(
      CardService.newTextButton()
        .setText('Check the links')
        .setOnClickAction(CardService.newAction().setFunctionName('onInspectLinks').setParameters({ messageId: messageId }))
    );
  }
  if (isDanger) {
    actionsSection.addWidget(
      CardService.newTextButton()
        .setText('Report this email')
        .setOnClickAction(CardService.newAction().setFunctionName('onReportEmail'))
    );
  }

  // Quiet secondary actions side by side. A likely-malicious sender is never offered as "trust".
  // A false alarm is answered by "Trust sender" (never offered on a likely-malicious email). There is no
  // "this is a mistake" button on purpose: one that recorded nothing would be an empty promise. See Roadmap.
  if (!isDanger) {
    actionsSection.addWidget(
      CardService.newButtonSet().addButton(
        CardService.newTextButton()
          .setText('Trust sender')
          .setOnClickAction(
            CardService.newAction().setFunctionName('onTrustThisSender').setParameters({
              senderEmail: email.senderEmail,
              senderDisplayName: email.senderDisplayName || '',
            })
          )
      )
    );
  }
  card.addSection(actionsSection);

  return withMenu(card).build();
}

/** Adds the overflow-menu (three dots) entry that opens the trusted-senders list. */
function withMenu(cardBuilder) {
  return cardBuilder.addCardAction(
    CardService.newCardAction()
      .setText('Trusted senders')
      .setOnClickAction(CardService.newAction().setFunctionName('onOpenManageTrustedSenders'))
  );
}

/**
 * Action handler for "Report this email". Reporting from inside the add-on would need
 * the gmail.modify scope, which we deliberately do not request (least privilege), so we
 * open Google's own instructions instead.
 */
function onReportEmail(e) {
  return CardService.newActionResponseBuilder()
    .setOpenLink(CardService.newOpenLink().setUrl('https://support.google.com/mail/answer/8253'))
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

/** "Check the links": where each link really leads. Reads only the cached, already-analyzed report. */
function onInspectLinks(e) {
  const cached = CacheService.getUserCache().get(LINKS_CACHE_PREFIX + e.parameters.messageId);
  let report = null;
  try {
    report = cached ? JSON.parse(cached) : null;
  } catch (err) {
    report = null;
  }
  const card = report
    ? buildLinksCard(report)
    : buildSimpleMessageCard('Links', 'This check has expired. Please re-open the email to run it again.');
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .build();
}

function buildLinksCard(report) {
  const section = CardService.newCardSection()
    .setHeader('Where the links really go')
    .addWidget(CardService.newTextParagraph().setText(linkSummaryText(report)));
  report.rows.forEach((row) => {
    section.addWidget(CardService.newDecoratedText().setWrapText(true).setText(linkRowText(row)));
  });
  if (report.more > 0) {
    section.addWidget(CardService.newTextParagraph().setText('<i>+' + report.more + ' more links not shown</i>'));
  }
  section.addWidget(
    CardService.newTextParagraph().setText(
      '<font color="#6B6B6B"><i>The Lighthouse never opens these links. This shows where each one points, not whether the site is safe.</i></font>'
    )
  );
  return withMenu(CardService.newCardBuilder().setName('links').addSection(section)).build();
}

function buildDetailsCard(result) {
  const state = stateForResult(result);
  const view = presentationFor(state);
  const isDanger = state === 'malicious';

  const header = CardService.newCardHeader()
    .setTitle(isDanger ? "The Lighthouse's Warning" : "The Lighthouse's Notes")
    .setSubtitle(safeText(result.verdict, 30) + '  \u00B7  score ' + normalizeScore(result.score) + '/100')
    .setImageUrl(assetUrl(view.icon))
    .setImageStyle(CardService.ImageStyle.SQUARE);

  const card = CardService.newCardBuilder().setHeader(header);

  if (!result.reasoning || result.reasoning.length === 0) {
    card.addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          'The waters look calm \u2014 Lighthouse did not notice anything worth flagging in this email.'
        )
      )
    );
  } else {
    const byCategory = groupByCategory(sortFindings(result.reasoning));
    Object.keys(byCategory).forEach((category) => {
      const meta = CATEGORY_LABELS[category] || { title: capitalize(category), icon: 'info' };
      const section = CardService.newCardSection().setHeader(safeText(meta.title, 60));
      // Same rule fired several times (e.g. two mismatched links): one headline, then each specific detail.
      findingsByRule(byCategory[category]).forEach((item) => {
        const n = item.descriptions.length;
        const line = CardService.newDecoratedText()
          .setStartIcon(materialIconImage(meta.icon))
          .setText(safeText(wisdomForRule(item.rule), 200) + (n > 1 ? ' (×' + n + ')' : ''))
          .setWrapText(true);
        if (n === 1) {
          section.addWidget(line.setBottomLabel(safeText(item.descriptions[0], 300)));
          return;
        }
        section.addWidget(line);
        const shown = item.descriptions.slice(0, 5).map((d) => '• ' + safeText(d, 300));
        if (n > 5) shown.push('+' + (n - 5) + ' more');
        section.addWidget(CardService.newTextParagraph().setText('<font color="#6B6B6B">' + shown.join('<br>') + '</font>'));
      });
      card.addSection(section);
    });
  }

  // "What we checked": makes a clean result feel earned rather than empty.
  const passed = checksPassed(result.reasoning);
  if (passed.length > 0) {
    const checked = CardService.newCardSection().setHeader('What we checked');
    passed.forEach((label) => {
      checked.addWidget(CardService.newTextParagraph().setText('\u2713 ' + label + ' \u2014 nothing unusual'));
    });
    card.addSection(checked);
  }

  card.addSection(
    CardService.newCardSection()
      .setHeader('How to read this score')
      .addWidget(CardService.newTextParagraph().setText(SCORE_LEGEND))
  );

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

function buildTrustedSenderCard(email) {
  const view = presentationFor('trusted');
  const section = CardService.newCardSection()
    .addWidget(CardService.newImage().setImageUrl(assetUrl(HERO_TRUSTED_FILE)).setAltText('Trusted sender \u2014 risk 0'))
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('RISK SCORE')
        .setText('<font color="' + STATE_COLORS.safe + '"><b>0</b></font> / 100')
        .setBottomLabel('Trusted sender')
    )
    .addWidget(
      CardService.newTextParagraph().setText(
        '<b>' + safeText(email.senderDisplayName || email.senderEmail, 80) + '</b> (' +
          safeText(email.senderEmail, 120) + ') is on your trusted list.'
      )
    )
    .addWidget(
      CardService.newTextButton()
        .setText('Remove from trusted')
        .setOnClickAction(
          CardService.newAction().setFunctionName('onUntrustThisSender').setParameters({ senderEmail: email.senderEmail })
        )
    );
  return withMenu(CardService.newCardBuilder().addSection(section)).build();
}

function buildNotScannedCard() {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newImage().setImageUrl(assetUrl(HERO_UNSCANNED_FILE)).setAltText('Not scanned \u2014 use your usual caution')
    )
    .addWidget(
      CardService.newTextParagraph().setText(
        '<i>Tip: closing and re-opening this email will relight the beacon for a fresh scan.</i>'
      )
    );
  return CardService.newCardBuilder().addSection(section).build();
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

/**
 * The one place the whitelist is managed (opened from the homepage and the ⋮ menu): an "add" section,
 * then the list newest first under a count, collapsing behind "Show more" when it is long.
 */
function buildManageTrustedSendersCard() {
  const view = trustedListView(getTrustedSenders());

  const addSection = CardService.newCardSection();
  if (view.full) {
    addSection.addWidget(
      CardService.newTextParagraph().setText(
        'Your list is full (' + MAX_TRUSTED_SENDERS + ' senders). Remove someone to add another.'
      )
    );
  } else {
    addSection.addWidget(
      CardService.newTextInput()
        .setFieldName('newTrustedEntry')
        .setTitle('Add email or domain')
        .setHint('e.g. alice@example.com or example.com')
    );
    addSection.addWidget(
      CardService.newTextButton()
        .setText('Add to trusted')
        .setOnClickAction(CardService.newAction().setFunctionName('onAddTrustedSender'))
    );
  }

  const listSection = CardService.newCardSection().setHeader(view.heading);
  if (view.collapsible) {
    listSection.setCollapsible(true).setNumUncollapsibleWidgets(TRUSTED_VISIBLE_ROWS);
  }
  view.entries.forEach((entry) => {
    listSection.addWidget(
      CardService.newDecoratedText()
        .setText(escapeHtml(entry))
        .setWrapText(true)
        .setButton(
          CardService.newTextButton()
            .setText('Remove')
            .setOnClickAction(
              CardService.newAction().setFunctionName('onRemoveTrustedSender').setParameters({ entry: entry })
            )
        )
    );
  });
  if (view.entries.length === 0) {
    // A section needs at least one widget.
    listSection.addWidget(
      CardService.newTextParagraph().setText('<font color="#6B6B6B">Emails from trusted senders get a calm card, unless they look dangerous.</font>')
    );
  }

  return CardService.newCardBuilder()
    .setName('trusted')
    .setHeader(CardService.newCardHeader().setTitle('Trusted senders').setSubtitle(APP_NAME))
    .addSection(addSection)
    .addSection(listSection)
    .build();
}

/** Opens the "Manage Trusted Senders" card via navigation (e.g. from a menu). */
function onOpenManageTrustedSenders(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(buildManageTrustedSendersCard()))
    .build();
}

// --------------------------------------------------------------------------
// Small utilities
// --------------------------------------------------------------------------

function escapeHtml(str) {
  return safeText(str, 2000);
}
