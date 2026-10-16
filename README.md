# Lighthouse - Smart Email Security — Gmail Add-on

A Google Workspace Gmail Add-on (built with `CardService`) that scans the
currently open email against the local FastAPI backend (see `/backend`)
and shows the user a maliciousness score, verdict, and reasoning.

## Design principles

1. **Explainable** — every verdict comes with the evidence behind it, not just a number.
2. **Loudness is calibrated** — safe email stays quiet so a dangerous one can shout. The card
   escalates through an intensity ladder:

   | State | What the user sees |
   |---|---|
   | Safe | Short, quiet card, green banner |
   | Suspicious | Amber banner, the single most important finding, "verify before you act" |
   | Malicious | Full-width red banner first, bold red "What to do", filled red buttons, solid-red gauge above 90 |
   | Not scanned | Grey card — "This email wasn't scanned, use your usual caution" (never implies safety) |

3. **Privacy first** — all analysis is local heuristics; no email content goes to third-party services.
4. **Least privilege** — see the scopes below.
5. **Plain headlines, warm voice** — headlines and findings are direct; the Lighthouse personality
   lives in subtitles and explanatory copy.

The lighthouse icon changes beam color with the verdict, and the risk gauge fades green → amber →
red along the backend's thresholds (35 suspicious, 70 malicious).

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
.
├── appsscript.json         Manifest: oauth scopes, contextual trigger, homepage trigger
├── Code.gs                 Add-on logic (CardService UI + backend client)
├── Presentation.gs         Pure helpers: state -> banner/gauge/copy, top finding, escaping (unit-tested in Node)
├── assets/                 Generated PNGs: icons, state banners, risk gauges (served via GitHub raw)
├── tools/generate_assets.py  Regenerates /assets  (python tools/generate_assets.py)
├── tests/                  Node tests for Presentation.gs and a CardService smoke test
├── docs/                   Design spec, implementation plan, demo script
├── backend/                FastAPI scoring service (see backend/README.md)
├── .claspignore            Keeps clasp from pushing anything except Code.gs, Presentation.gs, appsscript.json
└── .gitignore
```

Images in Gmail cards must come from a public HTTPS URL, so the PNGs are committed and loaded from
`raw.githubusercontent.com` (`ASSET_BASE_URL` in `Code.gs`; the repository must be public).
Run the tests with `node --test tests/presentation.test.js tests/code_smoke.test.js` and
`python -m unittest discover -s tools/tests`.

## How it works

1. **Message opened** → `buildAddOn(e)` fires (the `gmail.contextualTriggers`
   unconditional trigger). It reads the access token/message id Gmail hands
   it, and uses `GmailApp.getMessageById` to read sender, subject, body, and
   links from the **currently open message only**.
2. **Backend call** — `callBackend()` POSTs the parsed fields to `BACKEND_URL`
   (`/api/v1/analyze`) wrapped in try/catch. Any network error, timeout, or
   malformed/non-2xx response renders the grey **Not scanned** card instead of a
   stack trace. Trusted senders (user whitelist in `PropertiesService`) are
   **still scanned**: a spoofed "trusted" address must not bypass the checks. They
   get the calm "A familiar face" card only when the verdict is Safe.
3. **Result card** — header icon and a full-width banner in the state color, the
   top finding with its evidence, a gradient risk-gauge image plus the exact score
   (labelled an estimate), a "What to do" line, and actions: **View details**,
   **Trust this sender**, **I think this is a mistake**, and for malicious email a
   red **Report as phishing** (opens Google's reporting instructions — reporting
   in place would need `gmail.modify`, which we deliberately do not request).
4. **Details card** — "View details" uses
   `CardService.newNavigation().pushCard()`, which triggers Gmail's native
   slide-in card animation, to reveal the full per-rule reasoning (grouped
   by category, each rephrased into a warm "wise guide" sentence via
   `RULE_WISDOM`) that was deliberately hidden from the main card to avoid
   overwhelming the user, followed by a "What we checked" list so a clean
   result is not an empty screen.
5. **Feedback** — "I think this is a mistake" returns an
   `ActionResponseBuilder` with `setNotification(...)`, showing a toast
   ("Thank you! Your feedback helps calibrate the Lighthouse.") without
   navigating away.

## Setup & local testing

The backend runs locally; Apps Script executes in Google's cloud and
cannot reach `localhost` directly, so you need a tunnel:

```powershell
# 1. Start the backend (see /backend/README.md)
cd backend
uvicorn main:app --reload --port 8000

# 2. In a second terminal, expose it publicly
ngrok http 8000
# -> copy the printed https://xxxx.ngrok-free.app URL
```

Then:

1. Open [script.google.com](https://script.google.com), create/open the
   Apps Script project (or use `clasp push` with the existing
   `.clasp.json` in this folder).
2. Paste `Code.gs`, `Presentation.gs` and `appsscript.json` into the project (or `clasp push`).
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

- `headers` are sent empty, so the SPF/DKIM/DMARC rules in the backend never fire; reading
  authentication headers needs access the add-on does not request today.
- No URL-reputation lookups — a deliberate privacy choice (nothing leaves the backend).
- No mailbox-level actions (label, move to spam): they require `gmail.modify`.
- The gauge image uses the score rounded to the nearest 5; the exact score is shown as text.
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
