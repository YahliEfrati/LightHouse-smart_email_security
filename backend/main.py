"""Malicious Email Scorer API.

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

4. Interactive docs are then available at http://127.0.0.1:8000/docs

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

Authentication: set LIGHTHOUSE_API_KEY (see README) and send it as the X-Lighthouse-Key header.

Run tests with:  pytest
"""
from __future__ import annotations

import logging
import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from analyzer import EmailRiskAnalyzer
from models import AnalysisResponse, EmailAnalysisRequest, ReasoningItem

logger = logging.getLogger("malicious_email_scorer")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="Malicious Email Scorer API",
    description="Local, explainable heuristic scoring of email maliciousness for the Gmail Security Add-on.",
    version="1.0.0",
)

API_KEY_ENV = "LIGHTHOUSE_API_KEY"


def require_api_key(x_lighthouse_key: str = Header(default="")) -> None:
    """Shared-secret authentication between the Gmail Add-on and this API.

    The expected key comes from the ``LIGHTHOUSE_API_KEY`` environment variable and is
    read per request. If it is not configured the endpoint **fails closed** (503) rather
    than silently running open. The comparison is constant-time to avoid timing leaks, and
    rejections never say *why* a key was wrong.
    """
    expected = os.environ.get(API_KEY_ENV, "")
    if not expected:
        logger.error("%s is not set; refusing all analysis requests.", API_KEY_ENV)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service is not configured.",
        )
    if not secrets.compare_digest(x_lighthouse_key.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


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
