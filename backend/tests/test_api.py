"""Integration tests for the FastAPI endpoint."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
import main as main_module  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402

TEST_KEY = "test-key-123"
client = TestClient(app, headers={"X-Lighthouse-Key": TEST_KEY})
anonymous_client = TestClient(app)


@pytest.fixture(autouse=True)
def _api_key(monkeypatch):
    # Never touch the real backend/.env in tests.
    monkeypatch.setattr(main_module, "_api_key", TEST_KEY)


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_analyze_endpoint_benign_email():
    payload = {
        "sender": {"email": "friend@example.com", "display_name": "A Friend"},
        "subject": "Hello",
        "body_text": "Just checking in, how are you?",
    }
    resp = client.post("/api/v1/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "Safe"
    assert data["score"] < 35
    assert data["reasoning"] == []


def test_analyze_endpoint_phishing_email():
    payload = {
        "sender": {"email": "security@paypa1-support.com", "display_name": "PayPal Security"},
        "reply_to": "attacker@evil.com",
        "subject": "URGENT: Your account will be suspended",
        "body_text": (
            "Your account has been locked. Act now and verify your account immediately by "
            "confirming your bank account details and password to avoid permanent suspension."
        ),
        "links": [{"text": "https://paypal.com/verify", "href": "http://paypa1-support.com/verify"}],
        "attachments": [{"filename": "account_form.pdf.exe"}],
        "headers": {"Authentication-Results": "spf=fail; dkim=fail"},
    }
    resp = client.post("/api/v1/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "Malicious"
    assert data["score"] >= 70
    assert len(data["reasoning"]) >= 5
    assert all({"category", "rule", "weight", "description"} <= set(item) for item in data["reasoning"])


def test_analyze_endpoint_rejects_malformed_payload():
    resp = client.post("/api/v1/analyze", json={"subject": "missing sender"})
    assert resp.status_code == 422


def test_analyze_endpoint_rejects_oversized_body():
    payload = {
        "sender": {"email": "a@example.com"},
        "body_text": "x" * 200_001,
    }
    resp = client.post("/api/v1/analyze", json=payload)
    assert resp.status_code == 422


# ---- authentication (shared secret) ----
_BENIGN = {"sender": {"email": "friend@example.com"}, "subject": "Hello", "body_text": "Hi"}


def test_analyze_rejects_missing_key():
    assert anonymous_client.post("/api/v1/analyze", json=_BENIGN).status_code == 401


def test_analyze_rejects_wrong_key():
    resp = anonymous_client.post("/api/v1/analyze", json=_BENIGN, headers={"X-Lighthouse-Key": "nope"})
    assert resp.status_code == 401


def test_analyze_rejects_key_of_different_length():
    resp = anonymous_client.post("/api/v1/analyze", json=_BENIGN, headers={"X-Lighthouse-Key": TEST_KEY + "x"})
    assert resp.status_code == 401


def test_analyze_accepts_correct_key():
    resp = anonymous_client.post("/api/v1/analyze", json=_BENIGN, headers={"X-Lighthouse-Key": TEST_KEY})
    assert resp.status_code == 200


def test_unauthorized_response_leaks_nothing():
    resp = anonymous_client.post("/api/v1/analyze", json=_BENIGN)
    assert resp.json() == {"detail": "Unauthorized"}


def test_health_stays_open_and_minimal():
    resp = anonymous_client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
