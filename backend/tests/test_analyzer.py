"""Unit tests for the analyzer pipeline and scoring engine."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyzer import (  # noqa: E402
    AttachmentAnalyzer,
    ContentAnalyzer,
    EmailRiskAnalyzer,
    HeaderAnalyzer,
    LinkAnalyzer,
)
from models import (  # noqa: E402
    AttachmentInfo,
    EmailAnalysisRequest,
    LinkInfo,
    SenderInfo,
)


def make_email(**overrides) -> EmailAnalysisRequest:
    defaults = dict(
        sender=SenderInfo(email="friend@example.com", display_name="A Friend"),
        subject="Hello",
        body_text="Just checking in, how are you?",
        links=[],
        attachments=[],
        headers={},
    )
    defaults.update(overrides)
    return EmailAnalysisRequest(**defaults)


# --------------------------------------------------------------------------- #
# Benign baseline
# --------------------------------------------------------------------------- #


def test_benign_email_is_safe():
    email = make_email()
    score, verdict, findings = EmailRiskAnalyzer().analyze(email)
    assert verdict == "Safe"
    assert score < 35
    assert findings == []


# --------------------------------------------------------------------------- #
# HeaderAnalyzer
# --------------------------------------------------------------------------- #


def test_typosquat_domain_detected():
    email = make_email(
        sender=SenderInfo(email="security@paypa1.com", display_name="PayPal Security"),
    )
    findings = HeaderAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "typosquat_domain" in rules


def test_display_name_domain_mismatch_detected():
    email = make_email(
        sender=SenderInfo(email="update@totally-unrelated-domain.net", display_name="Google Accounts Team"),
    )
    findings = HeaderAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "display_name_domain_mismatch" in rules


def test_legitimate_brand_sender_not_flagged():
    email = make_email(sender=SenderInfo(email="no-reply@paypal.com", display_name="PayPal"))
    findings = HeaderAnalyzer().analyze(email)
    assert findings == []


def test_reply_to_mismatch_detected():
    email = make_email(reply_to="attacker@evil.com", sender=SenderInfo(email="ceo@example.com"))
    findings = HeaderAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "reply_to_mismatch" in rules


def test_spf_fail_detected():
    email = make_email(headers={"Authentication-Results": "mx.google.com; spf=fail smtp.mailfrom=evil.com"})
    findings = HeaderAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "spf_fail" in rules


# --------------------------------------------------------------------------- #
# ContentAnalyzer
# --------------------------------------------------------------------------- #


def test_urgency_financial_proximity_detected():
    email = make_email(
        body_text="URGENT: verify your account immediately by confirming your bank account details."
    )
    findings = ContentAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "urgency_financial_proximity" in rules


def test_base64_obfuscation_detected():
    long_b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk="
    email = make_email(body_text=f"See attached payload: {long_b64}")
    findings = ContentAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "base64_obfuscation" in rules


def test_html_entity_obfuscation_detected():
    html = "".join(f"&#x{ord(c):x};" for c in "clickhere") * 2
    email = make_email(body_html=html)
    findings = ContentAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "html_entity_obfuscation" in rules


def test_excessive_url_encoding_detected():
    body = "http://example.com/" + "%2F%2E%2E" * 5
    email = make_email(body_text=body)
    findings = ContentAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "excessive_url_encoding" in rules


# --------------------------------------------------------------------------- #
# LinkAnalyzer
# --------------------------------------------------------------------------- #


def test_link_text_href_mismatch_detected():
    email = make_email(links=[LinkInfo(text="https://paypal.com/login", href="http://paypa1-login.com/x")])
    findings = LinkAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "link_text_href_mismatch" in rules


def test_ip_literal_link_detected():
    email = make_email(links=[LinkInfo(text="Click here", href="http://192.168.1.50/login")])
    findings = LinkAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "ip_literal_host" in rules


def test_url_shortener_detected():
    email = make_email(links=[LinkInfo(text="Click here", href="https://bit.ly/abc123")])
    findings = LinkAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "url_shortener" in rules


def test_high_entropy_domain_detected():
    email = make_email(links=[LinkInfo(text="Click here", href="http://xk4j9qz7wmvbpt.com/login")])
    findings = LinkAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "high_entropy_domain" in rules


def test_benign_link_not_flagged():
    email = make_email(links=[LinkInfo(text="https://example.com", href="https://example.com/page")])
    findings = LinkAnalyzer().analyze(email)
    assert findings == []


# --------------------------------------------------------------------------- #
# AttachmentAnalyzer
# --------------------------------------------------------------------------- #


def test_double_extension_detected():
    email = make_email(attachments=[AttachmentInfo(filename="invoice.pdf.exe")])
    findings = AttachmentAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "double_extension" in rules


def test_dangerous_extension_detected():
    email = make_email(attachments=[AttachmentInfo(filename="setup.exe")])
    findings = AttachmentAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "dangerous_extension" in rules


def test_macro_with_pressure_context_escalated():
    email = make_email(
        body_text="URGENT action required: confirm your bank account to avoid account suspension.",
        attachments=[AttachmentInfo(filename="payment_form.docm")],
    )
    findings = AttachmentAnalyzer().analyze(email)
    rules = {f.rule for f in findings}
    assert "macro_enabled_with_pressure_context" in rules


def test_macro_without_pressure_context_lower_weight():
    email = make_email(attachments=[AttachmentInfo(filename="notes.docm")])
    findings = AttachmentAnalyzer().analyze(email)
    rules = {f.rule: f.weight for f in findings}
    assert rules.get("macro_enabled_attachment") == 20


def test_benign_attachment_not_flagged():
    email = make_email(attachments=[AttachmentInfo(filename="report.pdf")])
    findings = AttachmentAnalyzer().analyze(email)
    assert findings == []


# --------------------------------------------------------------------------- #
# End-to-end orchestrator
# --------------------------------------------------------------------------- #


def test_full_phishing_email_scores_malicious():
    email = make_email(
        sender=SenderInfo(email="security@paypa1-support.com", display_name="PayPal Security"),
        reply_to="attacker@evil.com",
        subject="URGENT: Your account will be suspended",
        body_text=(
            "Your account has been locked. Act now and verify your account immediately by "
            "confirming your bank account details and password to avoid permanent suspension."
        ),
        links=[LinkInfo(text="https://paypal.com/verify", href="http://paypa1-support.com/verify")],
        attachments=[AttachmentInfo(filename="account_form.pdf.exe")],
        headers={"Authentication-Results": "spf=fail; dkim=fail"},
    )
    score, verdict, findings = EmailRiskAnalyzer().analyze(email)
    assert verdict == "Malicious"
    assert score >= 70
    assert len(findings) >= 5


def test_score_is_clamped_between_0_and_100():
    email = make_email(
        sender=SenderInfo(email="security@paypa1-support.com", display_name="PayPal Security"),
        reply_to="attacker@evil.com",
        subject="URGENT: Your account will be suspended",
        body_text=(
            "Act now immediately, final notice, failure to comply, account suspended, "
            "verify your account, confirm your bank account, credit card, wire transfer, "
            "password, gift card, bitcoin, ssn."
        ),
        links=[
            LinkInfo(text="https://paypal.com/a", href="http://paypa1-support.com/a"),
            LinkInfo(text="https://paypal.com/b", href="http://192.168.1.1/b"),
            LinkInfo(text="https://paypal.com/c", href="https://bit.ly/c"),
        ],
        attachments=[
            AttachmentInfo(filename="a.pdf.exe"),
            AttachmentInfo(filename="b.docm"),
            AttachmentInfo(filename="c.scr"),
        ],
        headers={"Authentication-Results": "spf=fail; dkim=fail; dmarc=fail"},
    )
    score, verdict, _ = EmailRiskAnalyzer().analyze(email)
    assert 0 <= score <= 100
    assert verdict == "Malicious"


@pytest.mark.parametrize(
    "score,expected",
    [(0, "Safe"), (34, "Safe"), (35, "Suspicious"), (69, "Suspicious"), (70, "Malicious"), (100, "Malicious")],
)
def test_verdict_thresholds(score, expected):
    assert EmailRiskAnalyzer()._verdict_for(score) == expected
