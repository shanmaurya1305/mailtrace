import sys
import re
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

root_dir = Path(__file__).resolve().parent.parent
ai_engine_path = root_dir / "ai" / "threat-engine"
if str(ai_engine_path) not in sys.path:
    sys.path.insert(0, str(ai_engine_path))

from app.main import app

client = TestClient(app)

def build_headers_from_metadata(sender: str, recipient: str, subject: str) -> str:
    """Helper mirroring apps/extension/src/services/api.ts logic."""
    return (
        f"From: {sender}\r\n"
        f"To: {recipient}\r\n"
        f"Subject: {subject}\r\n"
        f"Date: Sun, 27 Sep 2026 12:00:00 +0000\r\n"
        f"Message-ID: <ext-test-123@mailtrace.local>\r\n"
        f"X-Mailer: Gmail Web Client\r\n"
    )

# 1. API request construction and investigation success for extension
def test_extension_request_construction_and_analysis():
    """Verify investigation endpoint handles payload constructed by extension."""
    raw_headers = build_headers_from_metadata(
        sender="attacker@spoofed.example.net",
        recipient="victim@company.example.org",
        subject="Urgent Payroll Account Verification"
    )
    payload = {
        "subject": "Urgent Payroll Account Verification",
        "body": "Please login to verify your payroll: https://fake-payroll.example.net/login and notify hr@example.net",
        "raw_headers": raw_headers
    }
    response = client.post("/api/v1/investigation/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Verify expected extension response schema
    assert "analysis_id" in data
    assert data["status"] == "completed"
    assert "authentication" in data
    assert "routing" in data
    assert "indicators" in data
    assert "threat_analysis" in data

    # Verify IOC extraction from body
    urls = [u["value"] for u in data["indicators"]["urls"]]
    assert "https://fake-payroll.example.net/login" in urls

    emails = [e["value"] for e in data["indicators"]["email_addresses"]]
    assert "hr@example.net" in emails
    assert "attacker@spoofed.example.net" in emails

# 2. Extension CORS Origin allowance
def test_extension_cors_origin_allowed():
    """Verify Chrome extension origin (chrome-extension://...) is permitted by CORS."""
    headers = {
        "Origin": "chrome-extension://abcdefghijklmnop1234567890abcdef",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    }
    response = client.options("/api/v1/investigation/analyze", headers=headers)
    assert response.status_code == 200
    allow_origin = response.headers.get("access-control-allow-origin")
    assert allow_origin == "chrome-extension://abcdefghijklmnop1234567890abcdef"

# 3. AI unavailable state response to extension
def test_extension_ai_model_unavailable_honest_response():
    """Verify extension receives honest model_unavailable status without fake predictions."""
    raw_headers = build_headers_from_metadata(
        sender="admin@example.org",
        recipient="user@example.org",
        subject="System Notification"
    )
    payload = {
        "subject": "System Notification",
        "body": "Normal system notification",
        "raw_headers": raw_headers
    }
    response = client.post("/api/v1/investigation/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    ai_data = data["threat_analysis"]
    assert ai_data["model_available"] is False
    assert ai_data["status"] == "model_unavailable"
    assert ai_data["primary_label"] is None
    assert ai_data["confidence"] is None
    assert ai_data["probabilities"] == {}
    assert "explanation" in ai_data

# 4. Malformed payload from extension rejected gracefully
def test_extension_malformed_payload_rejected():
    """Verify missing raw_headers triggers HTTP 422 with clear error detail."""
    response = client.post("/api/v1/investigation/analyze", json={
        "subject": "Incomplete Payload",
        "body": "Body without headers"
    })
    assert response.status_code == 422
    assert "raw_headers" in str(response.json()["detail"])

# 5. Extension content extraction helper logic test
def test_extension_content_extraction_helper_regex():
    """Verify URL and email regexes handle typical Gmail web client links and redirects."""
    body_sample = (
        "Check this link: https://portal.example.org/auth/reset?user=alice@example.com. "
        "Also contact helpdesk@corp.example.net for inquiries."
    )
    # URL extraction check
    url_pattern = re.compile(r"https?://(?:[a-zA-Z0-9-._~:/?#\[\]@!$&'()*+,;=]|%[0-9a-fA-F]{2})+")
    urls = [u.rstrip(".,;:!?)>\"'") for u in url_pattern.findall(body_sample)]
    assert "https://portal.example.org/auth/reset?user=alice@example.com" in urls

    # Email extraction check
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    emails = email_pattern.findall(body_sample)
    assert "alice@example.com" in emails
    assert "helpdesk@corp.example.net" in emails
