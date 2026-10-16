# Malicious Email Scorer — Backend

A local, explainable FastAPI service that scores the maliciousness of an
email. It is the backend half of the Gmail Security Add-on: the add-on
extracts the relevant fields from the currently open email (sender,
subject, body, links, attachment metadata, a few headers), POSTs them
here, and renders the returned `score`, `verdict`, and `reasoning` to
the user.

## Why this design

* **Entirely local, no external calls.** Every signal is computed
  in-process from the fields the client sends. There are no outbound
  HTTP calls, no third-party threat-intel/reputation APIs, and no LLM
  calls. This keeps email content from ever leaving the machine running
  the backend and makes the service runnable fully offline/air-gapped.
* **Cross-vector heuristics, not keyword matching.** A single urgent
  word or a single link proves very little. The engine looks for
  *combinations* that are hard to produce by accident: an urgency
  phrase sitting next to a request for financial/credential data, a
  brand name in the display name paired with a domain that doesn't
  belong to that brand, a macro-enabled attachment arriving alongside
  pressure language, etc. It also detects obfuscation techniques
  (long base64 blobs, excessive `%XX` URL-encoding, HTML character
  entities) that are specifically used to dodge naive text scanners.
* **Explainable by construction.** Every triggered rule is a `Finding`
  (category, rule id, weight, human-readable description). The API
  returns the full list, not just a number, so the add-on can show the
  user *why* an email was flagged.
* **Attachments are metadata-only.** The API never accepts or inspects
  raw file bytes — only `filename`, `content_type`, `size_bytes`. This
  avoids handling potentially sensitive or malicious binary payloads
  server-side, which is out of scope for a local heuristic scorer.
* **Untrusted input everywhere.** Every field in the request is
  attacker-controlled (it comes from an email). Pydantic models bound
  every string/list length to avoid oversized payloads or regex/DoS
  amplification, and nothing in the pipeline ever executes, renders, or
  fetches anything it is given — it is purely pattern matching over
  plain strings.

## Architecture

```
backend/
├── main.py        FastAPI app: POST /api/v1/analyze, GET /health
├── models.py      Pydantic request/response schemas (the untrusted-input boundary)
├── analyzer.py     OOP heuristic pipeline + scoring engine
├── tests/
│   ├── test_analyzer.py   unit tests per analyzer/rule
│   └── test_api.py        HTTP-level tests via FastAPI's TestClient
├── requirements.txt       runtime deps
├── requirements-dev.txt   + pytest/httpx for testing
└── pytest.ini
```

### The pipeline (`analyzer.py`)

`Analyzer` is an abstract base class. Each concrete subclass inspects
one vector of the email and returns a list of `Finding`s:

| Analyzer | Vector | Key checks |
|---|---|---|
| `HeaderAnalyzer` | Sender identity | In-memory whitelist of heavily-targeted brand domains; `difflib`-based typosquat detection (e.g. `paypa1.com` vs `paypal.com`); display-name/domain mismatch; Reply-To mismatch; SPF/DKIM/DMARC `=fail` in `Authentication-Results` |
| `ContentAnalyzer` | Body/subject text | Proximity of urgency phrases to financial/credential terms; long base64 blobs; excessive `%XX` URL-encoding; HTML numeric/hex entity obfuscation (`&#x...;`); requests to enter/confirm login or payment details (verb + credential noun) |
| `LinkAnalyzer` | Hyperlinks | Visible-text-vs-`href` domain mismatch; IP-literal hosts; known URL shorteners; Shannon-entropy check for randomly-generated-looking domains; hosts on phishing-abused TLDs (`SUSPICIOUS_TLDS`) |
| `AttachmentAnalyzer` | Attachments | Double extensions (`invoice.pdf.exe`); directly dangerous extensions (`.exe`, `.scr`, `.js`, ...); macro-enabled Office files (`.docm`, `.xlsm`, ...), severity escalated when the email also has urgency/financial language |

`EmailRiskAnalyzer` is the orchestrator: it runs all four analyzers,
then aggregates findings into a score using a **weighted matrix with a
per-category cap**. Each category (`header`, `content`, `link`,
`attachment`) can contribute at most N points to the raw total (see
`EmailRiskAnalyzer.CATEGORY_CAPS`). This means a single noisy category
(e.g. many minor content findings) can't alone push an email to
"Malicious", while genuinely independent weak signals across *different*
vectors still compound — which mirrors how a human triager reasons
about a suspicious email (no single clue is damning, but several
together are).

The final score is clamped to `[0, 100]` and mapped to a verdict:

* `score >= 70` → **Malicious**
* `35 <= score < 70` → **Suspicious**
* `score < 35` → **Safe**

## Running it

```powershell
# 1. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the API
uvicorn main:app --reload --port 8000

# 4. Interactive docs: off by default (the API sits behind a public tunnel).
#    $env:LIGHTHOUSE_DOCS = "1" before step 3, then open http://127.0.0.1:8000/docs
```

### Authentication

`/api/v1/analyze` requires the header `X-Lighthouse-Key`. On first start the backend creates
`backend/.env` (git-ignored) containing `LIGHTHOUSE_API_KEY=<random>`; copy that value into the
add-on's Script Property `BACKEND_API_KEY`. Wrong or missing key -> `401`. `/health` stays open and
returns only `{"status": "ok"}`. The file is the single source of truth.

### Example request

```http
POST http://127.0.0.1:8000/api/v1/analyze
Content-Type: application/json

{
  "sender": {"email": "security@paypa1-support.com", "display_name": "PayPal Security"},
  "reply_to": "attacker@evil.com",
  "subject": "URGENT: Your account will be suspended",
  "body_text": "Your account has been locked. Act now and verify your account immediately by confirming your bank account details and password.",
  "links": [{"text": "https://paypal.com/verify", "href": "http://paypa1-support.com/verify"}],
  "attachments": [{"filename": "account_form.pdf.exe"}],
  "headers": {"Authentication-Results": "spf=fail; dkim=fail"}
}
```

### Example response

```json
{
  "score": 100,
  "verdict": "Malicious",
  "reasoning": [
    {"category": "header", "rule": "typosquat_domain", "weight": 40, "description": "..."},
    {"category": "header", "rule": "reply_to_mismatch", "weight": 15, "description": "..."},
    {"category": "header", "rule": "spf_fail", "weight": 20, "description": "..."},
    {"category": "header", "rule": "dkim_fail", "weight": 20, "description": "..."},
    {"category": "content", "rule": "urgency_financial_proximity", "weight": 20, "description": "..."},
    {"category": "link", "rule": "link_text_href_mismatch", "weight": 25, "description": "..."},
    {"category": "attachment", "rule": "double_extension", "weight": 45, "description": "..."}
  ]
}
```

## Testing

```powershell
pip install -r requirements-dev.txt
pytest -v
```

153 tests cover every heuristic rule in isolation (including that
legitimate/benign emails are *not* flagged), the full scoring/verdict
aggregation, and the HTTP layer end-to-end (including malformed and
oversized-payload rejection with `422`). All 153 currently pass; the
real server was also manually smoke-tested end-to-end via a standalone
`uvicorn` process hitting `/health` and `/api/v1/analyze` over HTTP.

## Known limitations / trade-offs

* The brand/typosquat whitelist (`HeaderAnalyzer.BRAND_DOMAINS`) is a
  small, hand-curated, in-memory set for demonstration purposes — a
  production system would source this from a maintained, larger list.
* No historical/statistical model (e.g. sender reputation over time) —
  every request is scored independently and statelessly.
* Attachment analysis is metadata-only; it cannot detect malicious
  macro *content* inside a `.docm`, only the presence of the risky file
  type in a risky context.
* Entropy/typosquat thresholds were tuned by hand against a handful of
  examples (see `tests/test_analyzer.py`) rather than a labeled corpus.
