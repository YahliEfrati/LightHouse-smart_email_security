"""Lighthouse scoring API.

A local-only FastAPI service used by the Gmail Add-on to score the
maliciousness of the currently open email. The add-on (or any other
trusted caller) sends it the already-parsed email fields (sender,
subject, body, links, attachment metadata, select headers); the service
runs them through the heuristic pipeline in ``analyzer.py`` and returns
a 0-100 score, a Safe/Suspicious/Malicious verdict, and the detailed
list of reasons that led to that verdict.

No data ever leaves this process: there are no outbound network calls,
no third-party APIs, and no persistence layer. This is intentional - it
keeps potentially sensitive email content from being exposed to
external services and makes the service trivial to run fully offline.

Run instructions
-----------------
1. Create and activate a virtual environment (recommended):

       python -m venv .venv
       .venv\\Scripts\\activate        (Windows)
       source .venv/bin/activate      (macOS/Linux)

2. Install dependencies:

       pip install -r requirements.txt

3. Start the API (auto-reload while developing):

       uvicorn main:app --reload --port 8000

4. Interactive docs (off by default, the API sits behind a public tunnel):
       set LIGHTHOUSE_DOCS=1 before starting, then open http://127.0.0.1:8000/docs

5. Example request:

       POST http://127.0.0.1:8000/api/v1/analyze
       Content-Type: application/json

       {
         "sender": {"email": "security@paypa1-support.com", "display_name": "PayPal Security"},
         "subject": "URGENT: Your account will be suspended",
         "body_text": "Please verify your account immediately by confirming your bank account details.",
         "links": [{"text": "https://paypal.com/verify", "href": "http://paypa1-support.com/verify"}],
         "attachments": [{"filename": "invoice.pdf.exe"}]
       }

Authentication: the add-on sends the header X-Lighthouse-Key. The key is created automatically in
backend/.env on first start (see config.py and README).

Run tests with:  pytest
"""
from __future__ import annotations

import logging
import os
import secrets
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from analyzer import EmailRiskAnalyzer
from config import load_api_key
from models import AnalysisResponse, EmailAnalysisRequest, ReasoningItem

logger = logging.getLogger("malicious_email_scorer")
logging.basicConfig(level=logging.INFO)

_api_key: Optional[str] = None


def get_api_key() -> str:
    """The shared secret, loaded lazily (and created on first run) by ``config.load_api_key``."""
    global _api_key
    if not _api_key:
        _api_key = load_api_key()
    return _api_key


@asynccontextmanager
async def lifespan(_: FastAPI):
    get_api_key()  # create/load the key at startup so first-run instructions appear immediately
    yield


def require_api_key(x_lighthouse_key: str = Header(default="")) -> None:
    """Shared-secret authentication between the Gmail Add-on and this API.

    The comparison is constant-time (no timing leak) and a rejection never says *why*.
    """
    expected = get_api_key()
    if not secrets.compare_digest(x_lighthouse_key.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


# The API is reachable through a public tunnel: don't publish its schema to strangers by default.
# Set LIGHTHOUSE_DOCS=1 to get /docs and /openapi.json while developing locally.
_docs_enabled = os.getenv("LIGHTHOUSE_DOCS") == "1"

app = FastAPI(
    lifespan=lifespan,
    title="Lighthouse scoring API",
    description="Local, explainable heuristic scoring of email maliciousness for the Gmail Security Add-on.",
    version="1.0.0",
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

# A single, stateless, reusable instance of the analysis pipeline.
_risk_analyzer = EmailRiskAnalyzer()


@app.get("/health", tags=["meta"])
def health() -> dict:
    """Simple liveness probe used by the add-on / deployment tooling."""
    return {"status": "ok"}


@app.post(
    "/api/v1/analyze",
    response_model=AnalysisResponse,
    tags=["analysis"],
    dependencies=[Depends(require_api_key)],
    summary="Analyze an email and return a maliciousness score, verdict, and reasoning.",
)
def analyze_email(payload: EmailAnalysisRequest) -> AnalysisResponse:
    """Run the full analyzer pipeline against an untrusted, client-supplied
    email payload and return the aggregated verdict.

    All request fields are treated as attacker-controlled: Pydantic
    enforces type/length constraints at the boundary (see ``models.py``),
    and the analyzers themselves only ever pattern-match the content as
    plain strings - nothing is executed, rendered, or fetched.
    """
    try:
        score, verdict, findings = _risk_analyzer.analyze(payload)
    except Exception:  # noqa: BLE001 - never leak internals for untrusted input
        logger.exception("Unexpected error while analyzing an email payload")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error while analyzing the email.",
        )

    reasoning = [
        ReasoningItem(category=f.category, rule=f.rule, weight=f.weight, description=f.description)
        for f in findings
    ]
    return AnalysisResponse(score=score, verdict=verdict, reasoning=reasoning)


@app.exception_handler(ValidationError)
def handle_validation_error(_: Request, exc: ValidationError) -> JSONResponse:
    """Return a clean 422 without leaking stack traces for malformed/untrusted input."""
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": exc.errors()})
