# Lighthouse - Smart Email Security — Gmail Add-on

A Google Workspace Gmail Add-on (built with `CardService`) that scans the
currently open email against the local FastAPI backend (see `/backend`)
and shows the user a maliciousness score, verdict, and reasoning.

## Brand & tone

Lighthouse is designed to feel like a calm, protective guide — a warm
beacon cutting through fog — rather than an aggressive cyber-alarm. Safe
and Suspicious verdicts use soft colors, gentle Material Icons
(`verified`, `explore`), and reassuring, non-alarmist language written in
a "wise guide" voice (e.g. *"The sender's address looks very similar to a
known brand. Let's be careful here."* instead of raw jargon like
"TYPOSQUATTING DETECTED"). For a genuinely dangerous **Malicious** verdict,
the add-on deliberately drops that calm: a bold red `report` icon,
uppercase warning text, and a filled red "VIEW WHY THIS IS DANGEROUS"
button make the danger impossible to miss.

## Security posture: principle of least privilege

`appsscript.json` requests only the three scopes strictly required:

| Scope | Why |
|---|---|
| `gmail.addons.execute` | Required for any Gmail add-on to run at all. |
| `gmail.addons.current.message.readonly` | Lets the add-on read **only the single message the user currently has open** — never the inbox, never other threads. |
| `script.external_request` | Required for `UrlFetchApp` to call our own local backend. |

We deliberately do **not** request `gmail.readonly`, `gmail.modify`, or any
broad mailbox scope. If this add-on is compromised or misbehaves, the
blast radius is a single opened email, not the user's whole mailbox.

## Files

```
addon/
├── appsscript.json   Manifest: oauth scopes, contextual trigger, homepage trigger
└── Code.gs           All add-on logic (CardService UI + backend client)
```

## How it works

1. **Message opened** → `buildAddOn(e)` fires (the `gmail.contextualTriggers`
   unconditional trigger). It reads the access token/message id Gmail hands
   it, and uses `GmailApp.getMessageById` to read sender, subject, body, and
   links from the **currently open message only**.
2. **Trusted-sender short-circuit** — if the sender's address or domain is
   on the user's whitelist (`PropertiesService.getUserProperties()`), the
   backend is **never called** and a calm "A Familiar Face" card renders
   immediately.
3. **Backend call** — otherwise, `callBackend()` POSTs the parsed fields to
   `BACKEND_URL` (`/api/v1/analyze`) wrapped in try/catch. Any network
   error, timeout, or malformed/non-2xx response is treated as "down" and
   renders a friendly "The Beacon Rests" card instead of a stack trace,
   with the exact copy: *"The Lighthouse beacon is currently resting.
   Please try again later."*
4. **Result card** — carries the lighthouse banner image in its header
   (`CardHeader.setImageUrl`) and shows a Unicode risk gauge
   (`[██████░░░░] 65/100`) next to a Material Icon that matches the
   verdict (`verified` for Safe, `explore` for Suspicious, a bold red
   `report` for Malicious), plus three actions: **View Analysis
   Details**, **Trust This Sender**, and **I think this is a mistake**.
5. **Details card** — "View Analysis Details" uses
   `CardService.newNavigation().pushCard()`, which triggers Gmail's native
   slide-in card animation, to reveal the full per-rule reasoning (grouped
   by category, each rephrased into a warm "wise guide" sentence via
   `RULE_WISDOM`) that was deliberately hidden from the main card to avoid
   overwhelming the user.
6. **Feedback** — "I think this is a mistake" returns an
   `ActionResponseBuilder` with `setNotification(...)`, showing a toast
   ("Thank you! Your feedback helps calibrate the Lighthouse.") without
   navigating away.

## Setup & local testing

The backend runs locally; Apps Script executes in Google's cloud and
cannot reach `localhost` directly, so you need a tunnel:

```powershell
# 1. Start the backend (see /backend/README.md)
cd ../backend
uvicorn main:app --reload --port 8000

# 2. In a second terminal, expose it publicly
ngrok http 8000
# -> copy the printed https://xxxx.ngrok-free.app URL
```

Then:

1. Open [script.google.com](https://script.google.com), create/open the
   Apps Script project (or use `clasp push` with the existing
   `.clasp.json` in this folder).
2. Paste `Code.gs` and `appsscript.json` into the project (or `clasp push`).
3. In `Code.gs`, set `BACKEND_URL` to
   `https://xxxx.ngrok-free.app/api/v1/analyze`.
4. **Deploy → Test deployments → Install add-on** (or use "Run" from the
   script editor's Gmail add-on preview) and open it against your own
   Gmail account.
5. Open any email — the add-on card should appear in the right-hand panel
   within a few seconds.

> Note: every time ngrok restarts, its URL changes — update `BACKEND_URL`
> and re-push/re-deploy.

## Managing trusted senders

From the add-on's homepage (when no email is open) or from the result
card's "Trust This Sender" button, users can add an email address
(`alice@example.com`) or a bare domain (`example.com`) to their personal
whitelist, stored via `PropertiesService.getUserProperties()` (private to
that user, not shared or synced anywhere else). Entries can be removed
individually from the "Manage Trusted Senders" section.

## Known limitations

- `BACKEND_URL` must be manually updated whenever the ngrok tunnel
  restarts — there's no service discovery for a purely local demo setup.
- The trusted-sender list is stored per Google account via
  `PropertiesService`, so it doesn't carry over between different Google
  accounts/browsers.
- Analysis results are cached for 30 minutes via `CacheService` to let the
  "View Analysis Details" button work without re-sending the email to the
  backend; after that window, re-opening the email re-triggers a fresh scan.
- `UrlFetchApp` has no configurable timeout in Apps Script; a very slow
  backend will be bounded by the platform's own execution limits rather
  than an app-level timeout.
