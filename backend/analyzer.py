"""Local, explainable heuristic engine for scoring email maliciousness.

Design goals
------------
* **Entirely local** - no network calls, no third-party threat-intel
  lookups, no LLM calls. Every signal is computed in-process from the
  parsed email fields the client sends us. This avoids leaking email
  content/PII to external services.
* **Cross-vector heuristics over keyword matching** - individual signals
  (a single urgent word, a single link) are weak evidence on their own.
  The engine favors *combinations* (e.g. urgency language next to a
  financial term, or a brand name in the display name paired with a
  domain that doesn't belong to that brand) and known obfuscation
  techniques that are typically used to evade naive scanners.
* **Explainable** - every triggered rule produces a ``Finding`` with a
  category, a weight, and a human-readable reason. The API returns the
  full list so the Gmail Add-on can show the user *why* an email was
  flagged, not just a number.

Architecture
------------
``Analyzer`` is an abstract base class. Each concrete subclass inspects
one "vector" of the email and returns a list of ``Finding`` objects:

* ``HeaderAnalyzer``         - sender identity: brand impersonation, typosquats, Reply-To, SPF/DKIM/DMARC
* ``ContentAnalyzer``        - wording: credential requests, urgency + money, obfuscation tricks
* ``PaymentRequestAnalyzer`` - CEO / vendor fraud: a money request plus pressure or a personal mailbox
* ``LinkAnalyzer``           - links: text vs. real site, IP hosts, shorteners, look-alike domains
* ``AttachmentAnalyzer``     - attachments (metadata only): double extensions, risky file types, macros

The ``EmailRiskAnalyzer`` orchestrator runs the full pipeline and aggregates
the findings into a single 0-100 score using a weighted matrix with a
per-category cap, so that a single hyperactive category can't alone
dominate the verdict while multiple independent weak signals across
categories still add up (defense-in-depth scoring, mirroring how a
human triager reasons about an email).

Shared domain helpers (``registrable_domain`` and the suffix lists) sit at the
top of the module; lists that the add-on also uses are kept in sync with
``Presentation.gs`` by ``tests/test_shared_lists.py``.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from difflib import get_close_matches
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

from models import EmailAnalysisRequest

# --------------------------------------------------------------------------- #
# Domain helpers
# --------------------------------------------------------------------------- #

#: Country suffixes where the "site" is three labels (example.co.uk). Keep in sync with
#: TWO_PART_SUFFIXES in Presentation.gs (tests/test_shared_lists.py checks it).
TWO_PART_SUFFIXES: Set[str] = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.il", "org.il",
    "ac.il", "co.jp", "co.in", "com.br", "com.mx", "com.tr", "com.cn", "co.za",
}
#: Shared-hosting suffixes: anyone can get name.github.io, so each subdomain is a separate site.
#: Without this, mybank.github.io and evil.github.io would look like one site - and phishing pages
#: are often hosted exactly there. Keep in sync with SHARED_HOSTING_SUFFIXES in Presentation.gs.
SHARED_HOSTING_SUFFIXES: Set[str] = {
    "github.io", "gitlab.io", "web.app", "firebaseapp.com", "netlify.app", "vercel.app", "pages.dev",
    "workers.dev", "herokuapp.com", "azurewebsites.net", "blogspot.com", "wixsite.com", "weebly.com",
    "glitch.me", "onrender.com", "appspot.com", "s3.amazonaws.com", "r2.dev", "ngrok-free.app",
}


def registrable_domain(host: str) -> str:
    """The "site" a host belongs to: a.b.example.com -> example.com, shop.example.co.uk ->
    example.co.uk, evil.github.io -> evil.github.io. Small built-in suffix lists, no network."""
    host = (host or "").lower().rstrip(".")
    if not host or LinkAnalyzer.IPV4_RE.match(host):
        return host
    for suffix in sorted(TWO_PART_SUFFIXES | SHARED_HOSTING_SUFFIXES, key=len, reverse=True):
        if host == suffix:
            return host
        if host.endswith("." + suffix):
            return host[: -len(suffix) - 1].rsplit(".", 1)[-1] + "." + suffix
    return ".".join(host.split(".")[-2:])


# --------------------------------------------------------------------------- #
# Shared data structures
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Finding:
    """A single triggered heuristic rule."""

    category: str
    rule: str
    weight: int
    description: str


# --------------------------------------------------------------------------- #
# Base class
# --------------------------------------------------------------------------- #


class Analyzer(ABC):
    """Base class for all single-vector analyzers in the pipeline."""

    #: Human readable name of the vector this analyzer inspects, used as
    #: the ``category`` on every ``Finding`` it produces.
    category: str = "generic"

    @abstractmethod
    def analyze(self, email: EmailAnalysisRequest) -> List[Finding]:
        """Inspect ``email`` and return the list of findings it triggers."""
        raise NotImplementedError

    def _finding(self, rule: str, weight: int, description: str) -> Finding:
        return Finding(category=self.category, rule=rule, weight=weight, description=description)


# --------------------------------------------------------------------------- #
# Header / sender identity analyzer
# --------------------------------------------------------------------------- #


class HeaderAnalyzer(Analyzer):
    """Detects sender-identity spoofing against a local whitelist of
    heavily-targeted brands, using typosquatting and display-name/domain
    mismatch checks.
    """

    category = "header"

    #: In-memory whitelist: brand keyword -> its set of legitimate domains.
    #: Kept intentionally small and local (no external lookups) per the
    #: "entirely local" requirement. Extend as needed.
    BRAND_DOMAINS: Dict[str, Set[str]] = {
        # Official regional domains are listed explicitly, never as "paypal.<anything>": a look-alike on
        # another TLD (paypal.tk) must still be caught. paypal.co.il was the one holdout false alarm.
        "paypal": {"paypal.com", "paypal.co.uk", "paypal.co.il", "paypal.de", "paypal.fr", "paypal.ca"},
        "google": {"google.com", "accounts.google.com", "gmail.com"},
        "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com"},
        "apple": {"apple.com", "icloud.com"},
        "amazon": {
            "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.ca",
            "amazon.co.jp", "amazon.in", "amazon.com.au",
        },
        "bank of america": {"bankofamerica.com"},
        "chase": {"chase.com"},
        "wells fargo": {"wellsfargo.com"},
        "netflix": {"netflix.com"},
        "dhl": {"dhl.com"},
        "docusign": {"docusign.com", "docusign.net"},
        "linkedin": {"linkedin.com"},
    }

    #: Typosquat similarity cutoff for difflib.get_close_matches - tuned so
    #: that near-identical lookalikes (paypa1.com, paypal-secure.net) match
    #: while unrelated domains don't.
    TYPOSQUAT_CUTOFF = 0.72

    def analyze(self, email: EmailAnalysisRequest) -> List[Finding]:
        findings: List[Finding] = []
        sender_domain = self._domain(email.sender.email)
        display_name = (email.sender.display_name or "").lower()
        local_and_domain = email.sender.email.lower()

        for brand, legit_domains in self.BRAND_DOMAINS.items():
            claims_brand = brand in display_name or brand in local_and_domain
            if not claims_brand or not sender_domain:
                continue
            # Exact domain or a real subdomain (members.netflix.com): only the domain's owner can create
            # those. Never "contains": netflix.com.evil.example belongs to evil.example.
            if any(sender_domain == d or sender_domain.endswith("." + d) for d in legit_domains):
                continue  # genuinely from the brand, nothing to flag

            close = get_close_matches(sender_domain, legit_domains, n=1, cutoff=self.TYPOSQUAT_CUTOFF)
            if close:
                findings.append(
                    self._finding(
                        rule="typosquat_domain",
                        weight=40,
                        description=(
                            f"Sender claims to be '{brand}' but domain '{sender_domain}' is a close "
                            f"lookalike of the legitimate domain '{close[0]}' (typosquatting)."
                        ),
                    )
                )
            else:
                findings.append(
                    self._finding(
                        rule="display_name_domain_mismatch",
                        weight=35,
                        description=(
                            f"Sender display name/address references '{brand}' but the sending domain "
                            f"'{sender_domain}' does not belong to any known '{brand}' domain."
                        ),
                    )
                )
            break  # one brand-impersonation finding is enough signal

        if email.reply_to:
            reply_domain = self._domain(email.reply_to)
            if reply_domain and sender_domain and reply_domain != sender_domain:
                findings.append(
                    self._finding(
                        rule="reply_to_mismatch",
                        weight=15,
                        description=(
                            f"Reply-To domain '{reply_domain}' differs from the From domain "
                            f"'{sender_domain}', a common tactic to redirect replies away from the "
                            "apparent sender."
                        ),
                    )
                )

        findings.extend(self._auth_results_findings(email.headers))
        return findings

    #: First bare address inside a header value such as 'Name <a@b.com>' or 'a@b.com, c@d.com'.
    ADDRESS_RE = re.compile(r"[^\s<>\"',;:]+@[^\s<>\"',;:]+")

    @classmethod
    def _domain(cls, address: str) -> str:
        match = cls.ADDRESS_RE.search(address or "")
        if not match:
            return ""
        return match.group().rsplit("@", 1)[-1].strip().lower().rstrip(".")

    def _auth_results_findings(self, headers: Dict[str, str]) -> List[Finding]:
        findings: List[Finding] = []
        auth_results = ""
        for key, value in headers.items():
            if key.lower() in ("authentication-results", "received-spf"):
                auth_results += f" {value}".lower()

        for mechanism in ("spf", "dkim", "dmarc"):
            if re.search(rf"\b{mechanism}\s*=\s*fail\b", auth_results):
                findings.append(
                    self._finding(
                        rule=f"{mechanism}_fail",
                        weight=20,
                        description=f"Authentication-Results header reports {mechanism.upper()}=fail.",
                    )
                )
        return findings


# --------------------------------------------------------------------------- #
# Content analyzer
# --------------------------------------------------------------------------- #


class ContentAnalyzer(Analyzer):
    """Detects social-engineering language patterns and obfuscation
    techniques commonly used to evade naive keyword/regex scanners.
    """

    category = "content"

    URGENCY_TERMS: Tuple[str, ...] = (
        "urgent", "immediately", "act now", "verify your account", "account suspended",
        "will be suspended", "expires today", "expire within", "action required",
        "within 24 hours", "limited time", "final notice", "failure to comply",
        "your account has been locked", "confirm your identity",
    )
    FINANCIAL_TERMS: Tuple[str, ...] = (
        "bank account", "credit card", "wire transfer", "payment details", "invoice",
        "social security", "ssn", "password", "login credentials", "gift card",
        "bitcoin", "crypto wallet", "tax refund", "routing number", "pin code",
    )

    #: Character window within which an urgency term and a financial term
    #: must both appear to be considered "proximate" (same sentence/clause).
    PROXIMITY_WINDOW = 120

    #: A run of base64 alphabet characters this long is unlikely to be
    #: incidental and is flagged as potential payload/obfuscation.
    BASE64_MIN_LENGTH = 60
    BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{%d,}={0,2})" % BASE64_MIN_LENGTH)
    URL_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")
    HTML_ENTITY_RE = re.compile(r"&#x[0-9A-Fa-f]+;|&#[0-9]+;")

    #: Requests to hand over login/payment details. Each pattern needs an
    #: action verb *followed by* a credential noun, so a bare mention of
    #: "password" (e.g. "you changed your password") never matches.
    #: "reset your password" is deliberately absent: legit reset mails say it.
    CREDENTIAL_REQUEST_RES: Tuple[re.Pattern, ...] = (
        re.compile(
            r"\b(?:verify|confirm|validate|re-?enter|enter|provide|submit)\s+(?:(?:your|the)\s+)?"
            r"(?:[\w-]+\s+)?(?:account|identity|password|passcode|credentials|login|username)\b"
        ),
        re.compile(
            r"\b(?:update|verify|confirm|validate|re-?enter|enter|provide|submit)\s+(?:(?:your|the)\s+)?"
            r"(?:payment|billing|card|bank|banking)\s+(?:details|information|info|method|address)\b"
        ),
        re.compile(
            r"\b(?:sign|log)[- ]?in\s+(?:(?:now|again|immediately)\s+)?to\s+"
            r"(?:continue|avoid|keep|restore|unlock|verify|confirm|prevent|reactivate)\b"
        ),
    )

    def analyze(self, email: EmailAnalysisRequest) -> List[Finding]:
        findings: List[Finding] = []
        text = f"{email.subject}\n{email.body_text or ''}".lower()
        html = email.body_html or ""

        findings.extend(self._proximity_findings(text))
        findings.extend(self._credential_request_findings(text))
        findings.extend(self._base64_findings(text + "\n" + html))
        findings.extend(self._url_encoding_findings(text + "\n" + html))
        findings.extend(self._html_entity_findings(html))
        return findings

    def _proximity_findings(self, text: str) -> List[Finding]:
        urgency_hits = [(m.start(), m.group()) for t in self.URGENCY_TERMS for m in re.finditer(re.escape(t), text)]
        financial_hits = [(m.start(), m.group()) for t in self.FINANCIAL_TERMS for m in re.finditer(re.escape(t), text)]
        if not urgency_hits or not financial_hits:
            return []

        pairs_reported = 0
        findings: List[Finding] = []
        for u_pos, u_term in urgency_hits:
            for f_pos, f_term in financial_hits:
                if abs(u_pos - f_pos) <= self.PROXIMITY_WINDOW:
                    findings.append(
                        self._finding(
                            rule="urgency_financial_proximity",
                            weight=20,
                            description=(
                                f"Urgency phrase '{u_term}' appears close to financial term '{f_term}' "
                                "(classic pressure-to-act phishing pattern)."
                            ),
                        )
                    )
                    pairs_reported += 1
                    break
            if pairs_reported >= 2:  # cap evidence volume; category cap also protects the score
                break
        return findings

    def _credential_request_findings(self, text: str) -> List[Finding]:
        for pattern in self.CREDENTIAL_REQUEST_RES:
            match = pattern.search(text)
            if match:
                phrase = " ".join(match.group().split())
                return [
                    self._finding(
                        rule="credential_request_language",
                        weight=15,
                        description=(
                            f"Message asks the reader to hand over login or payment details ('{phrase}'), "
                            "the core ask of a credential-phishing email."
                        ),
                    )
                ]
        return []

    def _base64_findings(self, text: str) -> List[Finding]:
        for match in self.BASE64_RE.finditer(text):
            candidate = match.group()
            try:
                # validate it actually decodes as base64, not just matches the charset
                base64.b64decode(candidate, validate=False)
            except (binascii.Error, ValueError):
                continue
            return [
                self._finding(
                    rule="base64_obfuscation",
                    weight=25,
                    description=(
                        f"Email body contains a long base64-like string ({len(candidate)} chars), "
                        "a common technique to hide payloads/links from text-based scanners."
                    ),
                )
            ]
        return []

    def _url_encoding_findings(self, text: str) -> List[Finding]:
        count = len(self.URL_ENCODED_RE.findall(text))
        if count >= 10:
            return [
                self._finding(
                    rule="excessive_url_encoding",
                    weight=15,
                    description=(
                        f"Found {count} percent-encoded sequences (%XX) in the message body, "
                        "suggestive of URL-encoding used to obfuscate a malicious link or text."
                    ),
                )
            ]
        return []

    @staticmethod
    def _spells_letter_or_digit(entity: str) -> bool:
        """True for &#112; / &#x70; style entities that encode a plain ASCII letter or digit."""
        body = entity[2:-1]
        code = int(body[1:], 16) if body[:1] in ("x", "X") else int(body)
        return 48 <= code <= 57 or 65 <= code <= 90 or 97 <= code <= 122

    def _html_entity_findings(self, html: str) -> List[Finding]:
        # Only entities that spell plain letters/digits count (&#112;&#97;&#121; = "pay"): that is the
        # evasion trick. Typographic ones (&#160; nbsp, &#8217; quote, dashes, emoji) are in every
        # rich newsletter; counting all of them flagged a real welcome email (921 entities).
        count = sum(1 for entity in self.HTML_ENTITY_RE.findall(html) if self._spells_letter_or_digit(entity))
        if count >= 6:
            return [
                self._finding(
                    rule="html_entity_obfuscation",
                    weight=20,
                    description=(
                        f"Found {count} HTML character entities (e.g. &#x70;) that spell out ordinary "
                        "letters or digits, a technique used to hide words/links from plain-text keyword "
                        "scanners while still rendering normally to the victim."
                    ),
                )
            ]
        return []


# --------------------------------------------------------------------------- #
# Link analyzer
# --------------------------------------------------------------------------- #


class LinkAnalyzer(Analyzer):
    """Detects link discrepancies (visible text vs. real destination),
    IP-literal hosts, URL shorteners, and high-entropy/DGA-like domains.
    """

    category = "link"

    SHORTENERS: Set[str] = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
    }
    # SHORTENERS above: keep in sync with SHORTENER_DOMAINS in Presentation.gs (tests/test_shared_lists.py).
    #: Click-tracking domains of mainstream email/newsletter services. Legitimate newsletters wrap
    #: *every* link in these, so "text says eventbrite.com, link goes to list-manage.com" is normal
    #: and must not count as a text/href mismatch. Matched on the host or any of its subdomains.
    #: Keep in sync with EMAIL_TRACKER_DOMAINS in Presentation.gs (tests/test_shared_lists.py).
    ESP_CLICK_TRACKERS: Set[str] = {
        "list-manage.com",  # Mailchimp
        "mailchi.mp",  # Mailchimp
        "mandrillapp.com",  # Mailchimp transactional
        "sendgrid.net",  # Twilio SendGrid
        "rs6.net",  # Constant Contact
        "createsend1.com",  # Campaign Monitor
        "cmail19.com",  # Campaign Monitor
        "cmail20.com",  # Campaign Monitor
        "hubspotlinks.com",  # HubSpot
        "exacttarget.com",  # Salesforce Marketing Cloud
        "sparkpostmail.com",  # SparkPost
        "mlsend.com",  # MailerLite
        "klclick.com",  # Klaviyo
    }
    #: Small, conservative list of TLDs heavily abused for phishing (cheap or
    #: free registration, or confusable with file names like .zip/.mov).
    #: Matched against the last label of a link's host only.
    SUSPICIOUS_TLDS: Set[str] = {
        "top", "xyz", "click", "gq", "tk", "ml", "cf", "ga", "zip", "mov", "work", "rest", "support",
    }
    IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    #: Reasonably recognizable "this text is itself a URL/domain" pattern,
    #: used to extract the domain a user *believes* they are clicking.
    URL_LIKE_IN_TEXT_RE = re.compile(r"(?:https?://)?([a-z0-9][a-z0-9\-]*\.)+[a-z]{2,}", re.IGNORECASE)

    #: Minimum domain-label length and entropy above which we consider a
    #: domain suspicious (random-looking / DGA-style).
    ENTROPY_MIN_LABEL_LENGTH = 12
    ENTROPY_THRESHOLD = 3.6

    def analyze(self, email: EmailAnalysisRequest) -> List[Finding]:
        findings: List[Finding] = []
        mismatches_reported = 0
        suspicious_tld_reported = False
        lookalike_reported = False
        for link in email.links:
            href_domain = self._domain(link.href)
            if not href_domain:
                continue

            text_domain = self._extract_domain_from_text(link.text)
            # Same site = no mismatch: "netflix.com" text with a www./links. host is normal.
            if (
                text_domain
                and registrable_domain(text_domain) != registrable_domain(href_domain)
                and not self._is_click_tracker(href_domain)
                and mismatches_reported < 2
            ):
                findings.append(
                    self._finding(
                        rule="link_text_href_mismatch",
                        weight=25,
                        description=(
                            f"Link text shows '{text_domain}' but actually points to "
                            f"'{href_domain}' - the visible destination does not match the real one."
                        ),
                    )
                )
                mismatches_reported += 1

            if self.IPV4_RE.match(href_domain):
                findings.append(
                    self._finding(
                        rule="ip_literal_host",
                        weight=20,
                        description=f"Link points directly to an IP address ({href_domain}) instead of a domain name.",
                    )
                )

            if href_domain in self.SHORTENERS:
                findings.append(
                    self._finding(
                        rule="url_shortener",
                        weight=10,
                        description=f"Link uses a URL shortener ('{href_domain}') which hides the true destination.",
                    )
                )

            if not lookalike_reported and self._is_lookalike_host(href_domain):
                findings.append(
                    self._finding(
                        rule="punycode_lookalike_domain",
                        weight=20,
                        description=(
                            f"Link host '{href_domain}' uses non-Latin or punycode (xn--) characters, which can "
                            "make a fake domain look identical to a real one (homograph attack)."
                        ),
                    )
                )
                lookalike_reported = True

            tld = href_domain.rsplit(".", 1)[-1]
            if not suspicious_tld_reported and "." in href_domain and tld in self.SUSPICIOUS_TLDS:
                findings.append(
                    self._finding(
                        rule="suspicious_tld",
                        weight=10,
                        description=(
                            f"Link points to '{href_domain}', whose top-level domain '.{tld}' is "
                            "frequently abused for phishing."
                        ),
                    )
                )
                suspicious_tld_reported = True

            entropy_finding = self._entropy_finding(href_domain)
            if entropy_finding:
                findings.append(entropy_finding)

        return findings

    @staticmethod
    def _is_lookalike_host(host: str) -> bool:
        """Punycode label (xn--) or raw non-ASCII characters in the host."""
        return any(label.startswith("xn--") for label in host.split(".")) or not host.isascii()

    def _is_click_tracker(self, host: str) -> bool:
        return any(host == d or host.endswith("." + d) for d in self.ESP_CLICK_TRACKERS)

    def _entropy_finding(self, domain: str) -> Optional[Finding]:
        labels = [lbl for lbl in domain.split(".")[:-1] if len(lbl) >= self.ENTROPY_MIN_LABEL_LENGTH]
        for label in labels:
            entropy = self._shannon_entropy(label)
            if entropy >= self.ENTROPY_THRESHOLD:
                return self._finding(
                    rule="high_entropy_domain",
                    weight=15,
                    description=(
                        f"Domain label '{label}' has high character entropy ({entropy:.2f}), "
                        "typical of randomly generated/DGA phishing domains."
                    ),
                )
        return None

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    @staticmethod
    def _domain(url: str) -> str:
        try:
            parsed = urlparse(url if "//" in url else f"//{url}")
            return (parsed.hostname or "").lower().rstrip(".")
        except ValueError:
            return ""

    #: An email address in link text ("mailed to you@gmail.com") is not a promise about which *site*
    #: the link opens, so it is removed before looking for a domain.
    EMAIL_IN_TEXT_RE = re.compile(r"[^\s@<>()\[\]\"',;]+@[^\s@<>()\[\]\"',;]+")

    @classmethod
    def _extract_domain_from_text(cls, text: str) -> str:
        match = cls.URL_LIKE_IN_TEXT_RE.search(cls.EMAIL_IN_TEXT_RE.sub(" ", text or ""))
        if not match:
            return ""
        return cls._domain(match.group())


# --------------------------------------------------------------------------- #
# Payment-request (BEC) analyzer
# --------------------------------------------------------------------------- #

#: Free-mail providers: a "CEO" or "vendor" asking for money from one of these is a classic BEC sign.
#: Keep in sync with PUBLIC_MAIL_DOMAINS in Presentation.gs (tests/test_shared_lists.py checks it).
FREE_MAIL_DOMAINS: Set[str] = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
    "ymail.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
    "walla.co.il", "zoho.com", "yandex.com", "yandex.ru",
}


class PaymentRequestAnalyzer(Analyzer):
    """CEO / vendor fraud (BEC): a request for money or for new payment details, which often comes
    with no link and no attachment at all. Three ingredients, each harmless alone:

    1. the request itself (buy gift cards, wire money, change bank / payroll details);
    2. pressure or secrecy ("urgent", "I'm in a meeting", "keep this confidential");
    3. a sender who should not be asking (free-mail address, or replies routed elsewhere).

    Request + pressure -> content finding (35); request + sender -> header finding (35). Each alone is
    "Suspicious"; all three land in two categories and reach "Malicious" (70) by the normal scoring.
    """

    category = "content"

    MONEY_REQUEST_RES: Tuple[re.Pattern, ...] = (
        re.compile(r"\b(?:buy|purchase|get|pick up)\b[^.\n]{0,40}\b(?:gift|itunes|apple|google play|steam|amazon) ?cards?\b"),
        re.compile(r"\bwire (?:transfer|the (?:funds|money|payment)|instructions)\b"),
        re.compile(r"\b(?:bank|banking|account|payment|remittance) (?:details|information|info) (?:have|has) (?:been )?(?:changed|updated)\b"),
        re.compile(r"\b(?:update|change)\b[^.\n]{0,40}\b(?:direct deposit|bank details|bank account|account details|banking details|payroll)\b"),
        re.compile(r"\bremit (?:the )?payment\b[^.\n]{0,40}\bnew account\b"),
    )
    #: BEC-style pressure. Deliberately not marketing words ("today only", "limited time"), so a store
    #: promoting gift cards does not look like a CEO asking for them.
    PRESSURE_RES: Tuple[re.Pattern, ...] = (
        re.compile(r"\b(?:urgent(?:ly)?|immediately|asap|right now|as soon as you (?:get|see|read) this)\b"),
        re.compile(r"\b(?:before |by )?(?:end of (?:the )?day|eod|close of business)\b"),
        re.compile(r"\b(?:confidential|discreet(?:ly)?|do not (?:discuss|tell|share)|don't (?:tell|mention)|between us)\b"),
        re.compile(r"\b(?:in a meeting|can(?:no|')t (?:talk|take calls)|are you (?:at your desk|available))\b"),
    )

    def analyze(self, email: EmailAnalysisRequest) -> List[Finding]:
        text = " ".join(f"{email.subject}\n{email.body_text or ''}".lower().split())
        request = next((m.group() for r in self.MONEY_REQUEST_RES for m in [r.search(text)] if m), None)
        if not request:
            return []

        findings: List[Finding] = []
        pressure = next((m.group() for r in self.PRESSURE_RES for m in [r.search(text)] if m), None)
        if pressure:
            findings.append(
                self._finding(
                    rule="payment_request_pressure",
                    weight=35,
                    description=(
                        f"Asks for money or new payment details ('{request}') under pressure or secrecy "
                        f"('{pressure}') - the pattern of CEO / vendor fraud. Verify by phone before acting."
                    ),
                )
            )

        unverified = self._unverified_sender(email)
        if unverified:
            findings.append(
                Finding(
                    category="header",
                    rule="payment_request_unverified_sender",
                    weight=35,
                    description=(
                        f"Asks for money or new payment details ('{request}') from {unverified}. Real "
                        "executives and vendors do not handle payments from personal mailboxes."
                    ),
                )
            )
        return findings

    @staticmethod
    def _unverified_sender(email: EmailAnalysisRequest) -> Optional[str]:
        sender = HeaderAnalyzer._domain(email.sender.email)
        reply = HeaderAnalyzer._domain(email.reply_to or "")
        if sender in FREE_MAIL_DOMAINS:
            return f"a free-mail address ({sender})"
        if reply and reply in FREE_MAIL_DOMAINS:
            return f"a sender whose replies go to a free-mail address ({reply})"
        return None


# --------------------------------------------------------------------------- #
# Attachment analyzer
# --------------------------------------------------------------------------- #


class AttachmentAnalyzer(Analyzer):
    """Detects execution-evasion via double extensions, directly dangerous
    extensions, and macro-enabled Office documents - the latter escalated
    severely when the surrounding email uses urgency/financial language.
    """

    category = "attachment"

    DANGEROUS_EXTENSIONS: Set[str] = {
        "exe", "scr", "bat", "cmd", "js", "vbs", "ps1", "jar", "msi", "com", "pif", "hta", "wsf",
        # Common modern delivery vehicles: HTML smuggling, disk images (bypass Mark-of-the-Web),
        # shortcut files and OneNote notebooks.
        "html", "htm", "shtml", "iso", "img", "vhd", "vhdx", "lnk", "one",
    }
    MACRO_EXTENSIONS: Set[str] = {"docm", "xlsm", "pptm", "dotm", "xltm", "ppsm"}
    #: Common benign/document "carrier" extensions seen before a dangerous
    #: second extension in a double-extension attack, e.g. invoice.pdf.exe
    CARRIER_EXTENSIONS: Set[str] = {
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg",
        "png", "gif", "zip", "rar", "tar", "gz", "7z", "csv",
    }

    DOUBLE_EXTENSION_RE = re.compile(
        r"\.(" + "|".join(CARRIER_EXTENSIONS) + r")\.(" + "|".join(DANGEROUS_EXTENSIONS) + r")$",
        re.IGNORECASE,
    )

    def analyze(self, email: EmailAnalysisRequest) -> List[Finding]:
        findings: List[Finding] = []
        if not email.attachments:
            return findings

        urgency_or_financial_context = self._has_pressure_context(email)

        for attachment in email.attachments:
            name = attachment.filename.strip().lower()
            if not name:
                continue

            if self.DOUBLE_EXTENSION_RE.search(name):
                findings.append(
                    self._finding(
                        rule="double_extension",
                        weight=45,
                        description=(
                            f"Attachment '{attachment.filename}' uses a double extension "
                            "(e.g. document.pdf.exe), a classic technique to disguise an "
                            "executable as a harmless document."
                        ),
                    )
                )
                continue  # already the strongest attachment signal for this file

            ext = name.rsplit(".", 1)[-1] if "." in name else ""
            if ext in self.DANGEROUS_EXTENSIONS:
                findings.append(
                    self._finding(
                        rule="dangerous_extension",
                        weight=35,
                        description=(
                            f"Attachment '{attachment.filename}' is a .{ext} file, a type that can run code or open "
                            "a fake login page, and is commonly used to deliver malware."
                        ),
                    )
                )
            elif ext in self.MACRO_EXTENSIONS:
                if urgency_or_financial_context:
                    findings.append(
                        self._finding(
                            rule="macro_enabled_with_pressure_context",
                            weight=45,
                            description=(
                                f"Attachment '{attachment.filename}' is a macro-enabled Office document "
                                f"(.{ext}) sent alongside urgency/financial language - a strong "
                                "indicator of a malicious-macro phishing attempt."
                            ),
                        )
                    )
                else:
                    findings.append(
                        self._finding(
                            rule="macro_enabled_attachment",
                            weight=20,
                            description=f"Attachment '{attachment.filename}' is a macro-enabled Office document (.{ext}).",
                        )
                    )
        return findings

    @staticmethod
    def _has_pressure_context(email: EmailAnalysisRequest) -> bool:
        text = f"{email.subject}\n{email.body_text or ''}".lower()
        return any(term in text for term in ContentAnalyzer.URGENCY_TERMS) and any(
            term in text for term in ContentAnalyzer.FINANCIAL_TERMS
        )


# --------------------------------------------------------------------------- #
# Orchestrator / scoring engine
# --------------------------------------------------------------------------- #


class EmailRiskAnalyzer:
    """Runs the full analyzer pipeline and aggregates findings into a
    final 0-100 score and verdict using a weighted, per-category-capped
    matrix.

    The cap per category prevents a single noisy vector (e.g. many minor
    content findings) from alone driving the score to "Malicious", while
    still letting independent signals across *different* vectors compound
    - which is exactly the "cross-vector" reasoning a human analyst uses.
    """

    #: Maximum points any single category may contribute to the raw score.
    CATEGORY_CAPS: Dict[str, int] = {
        "header": 50,
        "content": 35,
        "link": 40,
        "attachment": 50,
    }

    VERDICT_THRESHOLDS: Tuple[Tuple[int, str], ...] = (
        (70, "Malicious"),
        (35, "Suspicious"),
    )

    def __init__(self, analyzers: Optional[Iterable[Analyzer]] = None) -> None:
        self.analyzers: List[Analyzer] = list(analyzers) if analyzers is not None else [
            HeaderAnalyzer(),
            ContentAnalyzer(),
            PaymentRequestAnalyzer(),
            LinkAnalyzer(),
            AttachmentAnalyzer(),
        ]

    def analyze(self, email: EmailAnalysisRequest) -> Tuple[int, str, List[Finding]]:
        all_findings: List[Finding] = []
        for analyzer in self.analyzers:
            all_findings.extend(analyzer.analyze(email))

        score = self._aggregate_score(all_findings)
        verdict = self._verdict_for(score)
        return score, verdict, all_findings

    def _aggregate_score(self, findings: List[Finding]) -> int:
        totals: Dict[str, int] = {}
        for finding in findings:
            totals[finding.category] = totals.get(finding.category, 0) + finding.weight

        capped_total = 0
        for category, raw_total in totals.items():
            cap = self.CATEGORY_CAPS.get(category, raw_total)
            capped_total += min(raw_total, cap)

        return max(0, min(100, capped_total))

    def _verdict_for(self, score: int) -> str:
        for threshold, verdict in self.VERDICT_THRESHOLDS:
            if score >= threshold:
                return verdict
        return "Safe"
