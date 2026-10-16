"""Integration tests for the FastAPI endpoint."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402

client = TestClient(app)


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
