"""The add-on's "Check the links" card and the scoring engine must agree on these lists."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyzer import LinkAnalyzer  # noqa: E402

PRESENTATION = Path(__file__).resolve().parents[2] / "Presentation.gs"


def _js_list(name: str) -> set:
    source = PRESENTATION.read_text(encoding="utf-8")
    match = re.search(rf"const {name} = \[(.*?)\];", source, re.DOTALL)
    assert match, f"{name} not found in Presentation.gs"
    return set(re.findall(r"'([^']+)'", match.group(1)))


def test_shortener_lists_match():
    assert _js_list("SHORTENER_DOMAINS") == LinkAnalyzer.SHORTENERS


def test_newsletter_tracker_lists_match():
    assert _js_list("EMAIL_TRACKER_DOMAINS") == LinkAnalyzer.ESP_CLICK_TRACKERS


def test_verdict_thresholds_match():
    source = PRESENTATION.read_text(encoding="utf-8")
    match = re.search(r"const VERDICT_THRESHOLDS = \{ malicious: (\d+), suspicious: (\d+) \};", source)
    assert match, "VERDICT_THRESHOLDS not found in Presentation.gs"
    from analyzer import EmailRiskAnalyzer

    assert dict(EmailRiskAnalyzer.VERDICT_THRESHOLDS) == {int(match.group(1)): "Malicious", int(match.group(2)): "Suspicious"}


def test_domain_suffix_lists_match():
    from analyzer import SHARED_HOSTING_SUFFIXES, TWO_PART_SUFFIXES

    assert _js_list("TWO_PART_SUFFIXES") == TWO_PART_SUFFIXES
    assert _js_list("SHARED_HOSTING_SUFFIXES") == SHARED_HOSTING_SUFFIXES


def test_free_mail_lists_match():
    from analyzer import FREE_MAIL_DOMAINS

    assert _js_list("PUBLIC_MAIL_DOMAINS") == FREE_MAIL_DOMAINS
