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


# --------------------------------------------------------------------------- #
# credential_request_language (content)
# --------------------------------------------------------------------------- #


def _credential_findings(body: str, subject: str = "Hello"):
    findings = ContentAnalyzer().analyze(make_email(subject=subject, body_text=body))
    return [f for f in findings if f.rule == "credential_request_language"]


@pytest.mark.parametrize(
    "body",
    [
        "Please verify your account to keep using our service.",
        "To restore access, confirm your password using the form below.",
        "You must sign in to continue.",
        "Update your billing details before Friday.",
        "Enter your password on the next page.",
        "Kindly confirm your Microsoft\ncredentials here.",
    ],
)
def test_credential_request_language_detected(body):
    found = _credential_findings(body)
    assert len(found) == 1
    assert found[0].category == "content"
    assert found[0].weight == 15


@pytest.mark.parametrize(
    "body",
    [
        "You changed your password on Monday. If this was you, no action is needed.",
        "Your password was updated successfully.",
        "Reminder: never share your password with anyone, including us.",
        "Click here to reset your password.",
        "Please confirm your attendance at Thursday's meeting.",
    ],
)
def test_credential_request_language_not_fired_on_bare_mentions(body):
    assert _credential_findings(body) == []


def test_credential_request_language_fires_once_per_message():
    body = (
        "Verify your account now. Confirm your password. Enter your password. "
        "Sign in to continue. Update your payment details."
    )
    assert len(_credential_findings(body, subject="Confirm your login")) == 1


def test_credential_request_language_respects_content_cap():
    # urgency/financial proximity (2 x 20) + credential request (15) = 55 raw content points
    email = make_email(
        body_text=(
            "URGENT: verify your account immediately by confirming your bank account details. "
            "Act now and enter your password."
        )
    )
    score, _, findings = EmailRiskAnalyzer().analyze(email)
    content = [f for f in findings if f.category == "content"]
    assert "credential_request_language" in {f.rule for f in content}
    assert sum(f.weight for f in content) > EmailRiskAnalyzer.CATEGORY_CAPS["content"]
    assert {f.category for f in findings} == {"content"}
    assert score == EmailRiskAnalyzer.CATEGORY_CAPS["content"]


# --------------------------------------------------------------------------- #
# suspicious_tld (link)
# --------------------------------------------------------------------------- #


def _tld_findings(*hrefs: str):
    links = [LinkInfo(text="Click here", href=h) for h in hrefs]
    return [f for f in LinkAnalyzer().analyze(make_email(links=links)) if f.rule == "suspicious_tld"]


@pytest.mark.parametrize(
    "href",
    [
        "https://secure-login.top/verify",
        "http://parcel-update.xyz/track?id=1",
        "https://WWW.Account-Help.Support/",
        "https://invoice.zip/",
        "http://free-gift.tk",
    ],
)
def test_suspicious_tld_detected(href):
    found = _tld_findings(href)
    assert len(found) == 1
    assert found[0].category == "link"
    assert found[0].weight == 10


@pytest.mark.parametrize(
    "href",
    [
        "https://example.com/page",
        "https://wikipedia.org/wiki/Phishing",
        "https://example.net/",
        "https://github.io/",
        "https://www.gov.co.il/",
        "https://top.example.com/",  # abused TLD as a subdomain label only
        "https://shop.example.com/archive.zip",  # .zip in the path, not the host
        "http://192.168.1.50/login",
    ],
)
def test_suspicious_tld_not_fired_on_normal_tlds(href):
    assert _tld_findings(href) == []


def test_suspicious_tld_fires_once_per_message():
    assert len(_tld_findings("https://a.top/x", "https://b.xyz/y", "https://c.click/z")) == 1


def test_suspicious_tld_respects_link_cap():
    # 2 x text/href mismatch (25 each) + suspicious TLD (10) = 60 raw link points
    email = make_email(
        links=[
            LinkInfo(text="https://paypal.com/a", href="https://paypal-help.top/a"),
            LinkInfo(text="https://paypal.com/b", href="https://paypal-help.top/b"),
        ]
    )
    score, _, findings = EmailRiskAnalyzer().analyze(email)
    link = [f for f in findings if f.category == "link"]
    assert "suspicious_tld" in {f.rule for f in link}
    assert sum(f.weight for f in link) > EmailRiskAnalyzer.CATEGORY_CAPS["link"]
    assert {f.category for f in findings} == {"link"}
    assert score == EmailRiskAnalyzer.CATEGORY_CAPS["link"]


# --------------------------------------------------------------------------- #
# Regression: newsletter false positive (Mailchimp + display-name Reply-To)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "reply_to",
    ["Tel Aviv Salon <info@tlvsalon.com>", '"Salon" <INFO@TLVSALON.COM>', "info@tlvsalon.com, other@tlvsalon.com"],
)
def test_reply_to_with_display_name_same_domain_not_flagged(reply_to):
    email = make_email(sender=SenderInfo(email="news@tlvsalon.com", display_name="Salon"), reply_to=reply_to)
    assert "reply_to_mismatch" not in {f.rule for f in HeaderAnalyzer().analyze(email)}


def test_reply_to_with_display_name_other_domain_still_flagged():
    email = make_email(sender=SenderInfo(email="ceo@example.com"), reply_to="CEO <ceo@evil-example.net>")
    found = [f for f in HeaderAnalyzer().analyze(email) if f.rule == "reply_to_mismatch"]
    assert len(found) == 1
    assert "'evil-example.net'" in found[0].description


@pytest.mark.parametrize(
    "href",
    [
        "https://tlvsalon.us7.list-manage.com/track/click?u=abc&id=1",
        "https://mailchi.mp/tlvsalon/invite",
        "https://u123.ct.sendgrid.net/ls/click?upn=x",
        "https://r20.rs6.net/tn.jsp?f=x",
    ],
)
def test_newsletter_click_tracker_is_not_a_text_href_mismatch(href):
    email = make_email(links=[LinkInfo(text="bibinetanyahu.eventbrite.com", href=href)])
    assert "link_text_href_mismatch" not in {f.rule for f in LinkAnalyzer().analyze(email)}


def test_lookalike_of_a_tracker_domain_still_counts_as_mismatch():
    email = make_email(links=[LinkInfo(text="paypal.com", href="https://list-manage.com.evil.example/x")])
    assert "link_text_href_mismatch" in {f.rule for f in LinkAnalyzer().analyze(email)}


def test_tracked_link_still_gets_other_link_rules():
    email = make_email(links=[LinkInfo(text="Click here", href="https://x.list-manage.top/a")])
    rules = {f.rule for f in LinkAnalyzer().analyze(email)}
    assert "suspicious_tld" in rules  # not a tracker (wrong TLD), and TLD rule unaffected


def test_mailchimp_newsletter_from_screenshot_is_not_malicious():
    email = make_email(
        sender=SenderInfo(email="info@tlvsalon.com", display_name="Tel Aviv International Salon"),
        reply_to="Tel Aviv International Salon <info@tlvsalon.com>",
        subject="INVITATION: Prime Minister Benjamin Netanyahu, Oct 19th",
        body_text="Leading Ideas, Leading Israel. View this email in your browser. FREE RSVP HERE.",
        links=[
            LinkInfo(text="bibinetanyahu.eventbrite.com", href="https://tlvsalon.us7.list-manage.com/track/click?u=1"),
            LinkInfo(text="www.facebook.com", href="https://tlvsalon.us7.list-manage.com/track/click?u=2"),
        ],
    )
    score, verdict, findings = EmailRiskAnalyzer().analyze(email)
    assert verdict == "Safe", (score, [f.rule for f in findings])


# --------------------------------------------------------------------------- #
# punycode_lookalike_domain (link)
# --------------------------------------------------------------------------- #


def _lookalike_findings(*hrefs: str):
    links = [LinkInfo(text="Click here", href=h) for h in hrefs]
    return [f for f in LinkAnalyzer().analyze(make_email(links=links)) if f.rule == "punycode_lookalike_domain"]


@pytest.mark.parametrize("href", ["https://xn--pypal-4ve.com/login", "https://www.xn--80ak6aa92e.com/", "https://раypal.com/"])
def test_punycode_lookalike_detected(href):
    found = _lookalike_findings(href)
    assert len(found) == 1
    assert (found[0].category, found[0].weight) == ("link", 20)


@pytest.mark.parametrize("href", ["https://paypal.com/", "https://max-xn--a.example.com/", "https://example.com/xn--path"])
def test_punycode_lookalike_not_fired_on_ascii_hosts(href):
    assert _lookalike_findings(href) == []


def test_punycode_lookalike_fires_once_per_message():
    assert len(_lookalike_findings("https://xn--pypal-4ve.com/", "https://xn--80ak6aa92e.com/")) == 1


# --------------------------------------------------------------------------- #
# Regression: html_entity_obfuscation on ordinary rich HTML (Claude welcome email)
# --------------------------------------------------------------------------- #


def _entity_rules(html: str):
    return {f.rule for f in ContentAnalyzer().analyze(make_email(body_html=html))}


def test_typographic_entities_are_not_obfuscation():
    # nbsp, curly quotes, dashes, ellipsis, emoji: 921 of these were in a real welcome email.
    html = "<p>We&#8217;re glad&#160;you&#8217;re here &#8212; welcome&#8230; &#x1F44B; &#x2013;</p>" * 150
    assert "html_entity_obfuscation" not in _entity_rules(html)


@pytest.mark.parametrize(
    "html",
    [
        "".join(f"&#{ord(c)};" for c in "paypal") + ".com",  # decimal letters
        "".join(f"&#x{ord(c):X};" for c in "verify123"),  # uppercase hex letters and digits
        "<a href='x'>" + "".join(f"&#x{ord(c):x};" for c in "Login") + "&#160;" * 50 + "&#x6e;</a>",  # mixed with nbsp
    ],
)
def test_entities_spelling_letters_are_obfuscation(html):
    assert "html_entity_obfuscation" in _entity_rules(html)


def test_entity_rule_survives_absurd_codepoints():
    html = "&#99999999999999999999;&#x110000;" + "&#160;" * 10
    assert "html_entity_obfuscation" not in _entity_rules(html)


# --------------------------------------------------------------------------- #
# Regression: real Netflix mail from a subdomain scored 100 ("typosquatting")
# --------------------------------------------------------------------------- #

from analyzer import registrable_domain  # noqa: E402


def _header_rules(email_address: str, display_name: str):
    email = make_email(sender=SenderInfo(email=email_address, display_name=display_name))
    return {f.rule for f in HeaderAnalyzer().analyze(email)}


@pytest.mark.parametrize("address", ["info@members.netflix.com", "x@mailer.members.netflix.com", "a@netflix.com"])
def test_brand_subdomain_is_legitimate(address):
    assert _header_rules(address, "Netflix") == set()


@pytest.mark.parametrize(
    "address",
    [
        "info@netflix.com.evil.example",  # brand name as a *subdomain of the attacker's* domain
        "info@members-netflix.com",  # hyphen, not a subdomain
        "info@notnetflix.com",  # ends with the text but not with ".netflix.com"
        "info@netfl1x.com",  # classic typosquat
    ],
)
def test_brand_lookalikes_are_still_flagged(address):
    assert _header_rules(address, "Netflix") & {"typosquat_domain", "display_name_domain_mismatch"}


@pytest.mark.parametrize(
    "host,site",
    [
        ("members.netflix.com", "netflix.com"),
        ("paypal.com.evil.example", "evil.example"),
        ("shop.example.co.uk", "example.co.uk"),
        ("mybank.github.io", "mybank.github.io"),
        ("a.b.mysite.s3.amazonaws.com", "mysite.s3.amazonaws.com"),
        ("192.168.1.1", "192.168.1.1"),
        ("", ""),
    ],
)
def test_registrable_domain(host, site):
    assert registrable_domain(host) == site


def _mismatch(text: str, href: str) -> bool:
    email = make_email(links=[LinkInfo(text=text, href=href)])
    return "link_text_href_mismatch" in {f.rule for f in LinkAnalyzer().analyze(email)}


@pytest.mark.parametrize(
    "text,href",
    [
        ("netflix.com", "https://www.netflix.com/browse"),
        ("www.netflix.com", "https://links.netflix.com/track?x=1"),
        ("example.co.uk", "https://shop.example.co.uk/"),
    ],
)
def test_same_site_subdomains_are_not_a_mismatch(text, href):
    assert not _mismatch(text, href)


@pytest.mark.parametrize(
    "text,href",
    [
        ("paypal.com", "https://paypal.com.evil.example/login"),
        ("mybank.github.io", "https://evil.github.io/login"),  # shared hosting: different sites
        ("paypal.com", "https://paypal.github.io/"),
        ("example.co.uk", "https://example.co.uk.evil.example/"),
    ],
)
def test_different_sites_are_still_a_mismatch(text, href):
    assert _mismatch(text, href)


def test_netflix_marketing_mail_is_not_malicious():
    email = make_email(
        sender=SenderInfo(email="info@members.netflix.com", display_name="Netflix"),
        subject="Time to come back",
        links=[
            LinkInfo(text="netflix.com", href="https://www.netflix.com/browse?trkid=1"),
            LinkInfo(text="www.netflix.com", href="https://links.netflix.com/track?x=2"),
        ],
    )
    score, verdict, findings = EmailRiskAnalyzer().analyze(email)
    assert verdict == "Safe", (score, [f.rule for f in findings])


# Regression: Netflix footer "mailed to yahli@gmail.com" linked to netflix.com was a "mismatch".
@pytest.mark.parametrize("text", ["yahli7@gmail.com", "This message was mailed to [yahli7@gmail.com] by Netflix", "Contact support@paypal.com"])
def test_email_address_in_link_text_is_not_a_site_promise(text):
    assert not _mismatch(text, "https://www.netflix.com/account")


def test_site_shown_next_to_an_email_address_still_counts():
    assert _mismatch("Write to me@gmail.com or visit paypal.com", "https://evil.example/")


# --------------------------------------------------------------------------- #
# PaymentRequestAnalyzer (BEC: money requests, often with no link at all)
# --------------------------------------------------------------------------- #

from analyzer import PaymentRequestAnalyzer  # noqa: E402


def _bec_rules(body: str, sender: str = "ceo@company.example", reply_to=None, subject: str = "Request"):
    email = make_email(sender=SenderInfo(email=sender, display_name="X"), reply_to=reply_to, subject=subject, body_text=body)
    return {f.rule: f.category for f in PaymentRequestAnalyzer().analyze(email)}


@pytest.mark.parametrize(
    "body",
    [
        "I'm in a meeting and can't talk. Please buy some Apple gift cards for a client today.",
        "Are you at your desk? I need an urgent wire transfer processed before end of day.",
        "Our bank details have changed. Please remit payment immediately to the new account.",
        "Keep this confidential: update my direct deposit to the account below asap.",
    ],
)
def test_money_request_under_pressure(body):
    assert _bec_rules(body) == {"payment_request_pressure": "content"}


@pytest.mark.parametrize(
    "sender,reply_to",
    [("robert.smith22@yahoo.com", None), ("ceo@company.example", "ceo.private@gmail.com")],
)
def test_money_request_from_personal_mailbox(sender, reply_to):
    body = "Please update my direct deposit information for the next payroll."
    assert _bec_rules(body, sender, reply_to) == {"payment_request_unverified_sender": "header"}


def test_all_three_ingredients_reach_malicious():
    email = make_email(
        sender=SenderInfo(email="ceo.office11@gmail.com", display_name="Michael Boss"),
        subject="Quick request",
        body_text="I'm in a meeting right now. I need you to purchase some gift cards for a client. Keep it discreet.",
    )
    score, verdict, findings = EmailRiskAnalyzer().analyze(email)
    assert {"payment_request_pressure", "payment_request_unverified_sender"} <= {f.rule for f in findings}
    assert verdict == "Malicious", score


@pytest.mark.parametrize(
    "body,sender",
    [
        # vendor invoice from the vendor's own domain, no pressure
        ("Please find attached invoice #4411. Payment is due within 30 days to the account on file.", "billing@vendor.example"),
        # store promoting gift cards: marketing words, not BEC pressure
        ("Holiday gifts made easy! Buy a gift card today - limited time, free shipping.", "news@shop.example"),
        # friend from Gmail mentions money, but no request for new payment details
        ("Thanks for dinner! I sent you the money on PayPal, let me know it arrived.", "friend@gmail.com"),
        # manager approving a budget
        ("Looks good to me, go ahead and approve the Q3 budget.", "david@company.example"),
        # pressure without any money request (first-contact BEC opener is out of scope here)
        ("Are you at your desk? I need a quick favor, reply as soon as you get this.", "ceo@company.example"),
    ],
)
def test_legitimate_money_talk_is_not_bec(body, sender):
    assert _bec_rules(body, sender) == {}


# --------------------------------------------------------------------------- #
# Dangerous attachment types (HTML smuggling, disk images, shortcuts, OneNote)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", ["Benefits_2024.html", "Remittance.HTM", "Audit_Q3.iso", "photo.img", "invoice.lnk", "notes.one"])
def test_modern_malware_delivery_types_flagged(name):
    email = make_email(attachments=[AttachmentInfo(filename=name)])
    assert "dangerous_extension" in {f.rule for f in AttachmentAnalyzer().analyze(email)}


def test_document_disguised_as_html_is_double_extension():
    email = make_email(attachments=[AttachmentInfo(filename="invoice.pdf.html")])
    assert "double_extension" in {f.rule for f in AttachmentAnalyzer().analyze(email)}


@pytest.mark.parametrize("name", ["report.pdf", "Q3.xlsx", "deck.pptx", "photo.jpg", "data.csv", "archive.zip"])
def test_ordinary_attachments_not_flagged(name):
    email = make_email(attachments=[AttachmentInfo(filename=name)])
    assert AttachmentAnalyzer().analyze(email) == []


# Regression: the one holdout false alarm was a genuine PayPal email from paypal.co.il.
@pytest.mark.parametrize(
    "address,name",
    [("service@paypal.co.il", "PayPal"), ("service@intl.paypal.com", "PayPal"), ("ship-confirm@amazon.de", "Amazon.de")],
)
def test_official_regional_brand_domains_are_legitimate(address, name):
    assert _header_rules(address, name) == set()


@pytest.mark.parametrize(
    "address",
    ["service@paypal.tk", "service@paypa1.co.il", "service@paypal.co.il.evil.example", "service@paypal-co-il.com"],
)
def test_regional_look_alikes_are_still_flagged(address):
    assert _header_rules(address, "PayPal") & {"typosquat_domain", "display_name_domain_mismatch"}


# --------------------------------------------------------------------------- #
# Hebrew support (wording rules, encoded Hebrew URLs, Hebrew domains)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "body",
    [
        "שלום, יש לאמת את פרטי החשבון שלך בקישור המצורף.",
        "אנא הזינו את הסיסמה שלכם כדי להמשיך.",
        "עליך להזין את הסיסמה שלך עכשיו, אחרת תיבת הדואר תיחסם.",
        "נא לעדכן את פרטי האשראי לצורך המשך השירות.",
    ],
)
def test_hebrew_credential_request_detected(body):
    assert len(_credential_findings(body)) == 1


@pytest.mark.parametrize(
    "body",
    [
        "שינית את הסיסמה שלך ביום שני. אם זה היית את/ה, אין צורך לעשות דבר.",
        "לעולם אל תמסור את הסיסמה שלך לאף אחד, גם לא לנו.",
        "המסמך אשר נשלח אליך אתמול כולל את סיכום הפגישה.",
    ],
)
def test_hebrew_bare_password_mention_not_flagged(body):
    assert _credential_findings(body) == []


def test_hebrew_urgency_next_to_money_detected():
    rules = {f.rule for f in ContentAnalyzer().analyze(make_email(body_text="דחוף: יש לעדכן את כרטיס האשראי שלך תוך 24 שעות"))}
    assert "urgency_financial_proximity" in rules


def test_hebrew_ceo_gift_card_fraud_reaches_malicious():
    email = make_email(
        sender=SenderInfo(email="ceo.office11@gmail.com", display_name="דני כהן"),
        subject="בקשה דחופה",
        body_text="אני בישיבה ולא יכול לדבר. תקנה בבקשה כרטיסי מתנה ללקוח, זה דחוף ותשמור את זה בינינו.",
    )
    score, verdict, findings = EmailRiskAnalyzer().analyze(email)
    assert {"payment_request_pressure", "payment_request_unverified_sender"} <= {f.rule for f in findings}
    assert verdict == "Malicious", score


@pytest.mark.parametrize(
    "body,sender",
    [
        ("קנו עכשיו כרטיס מתנה לחג! משלוח חינם לכל הארץ.", "news@shop.example"),
        ("העברתי לך את הכסף בביט על הארוחה, תודה!", "friend@gmail.com"),
        ("אישרתי את החשבונית של הספק, אפשר להעביר לתשלום בתנאים הרגילים.", "manager@company.example"),
    ],
)
def test_hebrew_legitimate_money_talk_is_not_bec(body, sender):
    assert _bec_rules(body, sender) == {}


def test_encoded_hebrew_url_is_not_obfuscation():
    from urllib.parse import quote

    url = "https://www.shop.co.il/" + quote("מבצעים/נעליים-לגברים?קטגוריה=ספורט")
    email = make_email(body_html=f"<a href='{url}'>לכל המבצעים</a>", links=[LinkInfo(text="לכל המבצעים", href=url)])
    assert "excessive_url_encoding" not in {f.rule for f in ContentAnalyzer().analyze(email)}


@pytest.mark.parametrize("href", ["https://www.עירייה.ישראל/", "https://xn--4dbrk0ce.xn--4dbrk0ce/", "https://שופ.co.il/"])
def test_hebrew_only_domains_are_not_lookalikes(href):
    assert _lookalike_findings(href) == []


def test_latin_mixed_with_hebrew_is_still_a_lookalike():
    assert len(_lookalike_findings("https://paypalי.com/")) == 1


# A direct "transfer / send me <amount>" request (found testing a real Hebrew CEO-fraud email).
@pytest.mark.parametrize(
    "body",
    [
        "אחי אני בישיבה לא זמין כרגע צריך שתעביר לי 3000 שקל לעסקה",
        "דחוף: תעבירי לי ₪2,500 עד סוף היום",
        "I'm in a meeting, please send me $3,000 for the deal asap.",
        "Urgent: transfer 5,000 USD to the supplier before end of day.",
    ],
)
def test_amount_transfer_request_under_pressure(body):
    assert _bec_rules(body) == {"payment_request_pressure": "content"}


@pytest.mark.parametrize(
    "body,sender",
    [
        ("העברתי לך 145 שקל בביט על הארוחה, תודה!", "friend@gmail.com"),
        ("Can you send me 3 files before end of day? Urgent for the review.", "colleague@company.example"),
        ("Thanks, I paid 40 dollars for the tickets last week.", "friend@gmail.com"),
    ],
)
def test_amount_mentions_without_a_request_do_not_fire(body, sender):
    assert _bec_rules(body, sender) == {}
