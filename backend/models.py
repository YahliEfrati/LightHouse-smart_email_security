"""Pydantic schemas for the Malicious Email Scorer API.

These models define the contract between the Gmail Add-on client and this
backend. Every field originates from an email (sender, subject, body,
links, attachments, headers) and MUST be treated as untrusted,
attacker-controlled input:

* All string/collection fields are length-bounded to prevent abuse
  (oversized payloads, ReDoS-style amplification, memory exhaustion).
* Attachments are represented by metadata only (filename, content-type,
  size) - raw file bytes are never accepted, stored, or analyzed here,
  which keeps the service lightweight and avoids handling potentially
  sensitive or malicious binary payloads server-side.
* Nothing in these models is ever executed, evaluated, or rendered; it is
  only pattern-matched as plain text/strings by analyzer.py.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class SenderInfo(BaseModel):
    """The email's From header, split into address and display name."""

    email: str = Field(..., max_length=320, description="Raw sender email address, e.g. 'alerts@paypa1-secure.com'")
    display_name: Optional[str] = Field(
        default=None, max_length=256, description="The human-readable From display name, e.g. 'PayPal Security'"
    )


class LinkInfo(BaseModel):
    """A single hyperlink extracted from the email body."""

    text: str = Field(default="", max_length=2048, description="The visible anchor text shown to the user")
    href: str = Field(..., max_length=4096, description="The actual destination URL the link points to")


class AttachmentInfo(BaseModel):
    """Attachment metadata only - never raw file content."""

    filename: str = Field(..., max_length=512)
    content_type: Optional[str] = Field(default=None, max_length=256)
    size_bytes: Optional[int] = Field(default=None, ge=0)


class EmailAnalysisRequest(BaseModel):
    """The full, already-parsed email payload submitted by the Gmail Add-on."""

    model_config = ConfigDict(str_strip_whitespace=True)

    sender: SenderInfo
    reply_to: Optional[str] = Field(default=None, max_length=320)
    subject: str = Field(default="", max_length=998)
    body_text: Optional[str] = Field(default="", max_length=200_000)
    body_html: Optional[str] = Field(default="", max_length=400_000)
    links: List[LinkInfo] = Field(default_factory=list, max_length=200)
    attachments: List[AttachmentInfo] = Field(default_factory=list, max_length=50)
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Optional raw authentication-related headers the add-on could fetch via the Gmail API, "
            "e.g. 'Authentication-Results', 'Received-SPF', 'Return-Path'."
        ),
    )


class ReasoningItem(BaseModel):
    """A single triggered heuristic rule, returned to the client for transparency."""

    category: str
    rule: str
    weight: int
    description: str


class AnalysisResponse(BaseModel):
    """The final result returned by POST /api/v1/analyze."""

    score: int = Field(..., ge=0, le=100)
    verdict: str
    reasoning: List[ReasoningItem]
