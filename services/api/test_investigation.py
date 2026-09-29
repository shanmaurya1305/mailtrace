import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

# Ensure project root and threat engine are in path
root_dir = Path(__file__).resolve().parent.parent
ai_engine_path = root_dir / "ai" / "threat-engine"
if str(ai_engine_path) not in sys.path:
    sys.path.insert(0, str(ai_engine_path))

from app.main import app
from schemas import ThreatClassificationResult

client = TestClient(app)

SAMPLE_HEADERS_PASS = """From: Security Team <security@example.com>
To: Analyst <analyst@example.org>
Subject: Quarterly Security Review
Date: Sun, 27 Sep 2026 12:00:00 +0000
Message-ID: <sec-2026@example.com>
Reply-To: security@example.com
Return-Path: <bounce@example.com>
Received: from mail-relay.example.com (mail-relay.example.com [203.0.113.10])
    by mx.example.org (Postfix) with ESMTPS id 4Sxyz90123
    for <analyst@example.org>; Sun, 27 Sep 2026 12:00:01 +0000
Authentication-Results: mx.example.org;
    spf=pass (example.org: domain of security@example.com designates 203.0.113.10 as permitted sender) smtp.mailfrom=bounce@example.com;
    dkim=pass header.i=@example.com header.s=2026 header.b=AbCd123;
    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com"""

SAMPLE_HEADERS_SPOOFED = """From: Executive <ceo@example.com>
To: Finance <finance@example.org>
Subject: Confidential Wire Transfer Request
Date: Sun, 27 Sep 2026 12:30:00 +0000
Message-ID: <wire-req@example.com>
Reply-To: collector@attacker.net
Return-Path: <bounce@attacker.net>
Received: from bad-host.attacker.net (bad-host.attacker.net [192.0.2.77])
    by mx.example.org (Postfix) with SMTP id 9Zqwerty123
    for <finance@example.org>; Sun, 27 Sep 2026 12:30:05 +0000
Authentication-Results: mx.example.org;
    spf=fail (sender IP 192.0.2.77 is not authorized for example.com);
    dkim=fail;
    dmarc=fail (p=REJECT header.from=example.com)"""

# 1. Investigation endpoint success
def test_investigation_endpoint_success():
    """Verify POST /api/v1/investigation/analyze returns complete structured response."""
    payload = {
        "subject": "Quarterly Security Review",
        "body": "Please read our security update at https://security.example.com/login and contact ops@example.com",
        "raw_headers": SAMPLE_HEADERS_PASS
    }
    response = client.post("/api/v1/investigation/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert "analysis_id" in data
    assert data["status"] == "completed"
    assert "summary" in data
    assert "authentication" in data
    assert "routing" in data
    assert "indicators" in data
    assert "evidence" in data
    assert "threat_analysis" in data

# 2. Malformed input handling
def test_investigation_malformed_input():
    """Verify malformed JSON or invalid data types return HTTP 422 error."""
    # Invalid data type for raw_headers (list instead of string)
    res = client.post("/api/v1/investigation/analyze", json={"raw_headers": ["not", "a", "string"]})
    assert res.status_code == 422

    # Malformed empty JSON
    res2 = client.post("/api/v1/investigation/analyze", json={})
    assert res2.status_code == 422

# 3. Empty email body is supported
def test_investigation_empty_email_body():
    """Verify investigation succeeds gracefully when body is empty or omitted."""
    payload = {
        "subject": "Header Only Notice",
        "body": "",
        "raw_headers": SAMPLE_HEADERS_PASS
    }
    response = client.post("/api/v1/investigation/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["routing"]["sender_domain"] == "example.com"

# 4. Forensic results preserved
def test_investigation_forensic_results_preserved():
    """Verify header forensics, authentication, and hops are preserved accurately."""
    payload = {
        "subject": "Quarterly Review",
        "body": "Test body",
        "raw_headers": SAMPLE_HEADERS_PASS
    }
    response = client.post("/api/v1/investigation/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["authentication"]["spf"]["status"] == "pass"
    assert data["authentication"]["dkim"]["status"] == "pass"
    assert data["authentication"]["dmarc"]["status"] == "pass"

    assert data["routing"]["sender"] == "Security Team <security@example.com>"
    assert data["routing"]["sender_domain"] == "example.com"
    assert len(data["routing"]["received_hops"]) == 1
    assert data["routing"]["received_hops"][0]["source_ip"] == "203.0.113.10"

# 5. IOC extraction (IPs, domains, URLs, email addresses, suspicious indicators)
def test_investigation_ioc_extraction():
    """Verify comprehensive IOC extraction and deterministic deduplication."""
    payload = {
        "subject": "SSO Login Link",
        "body": """Your account is expiring.
Please verify at https://login.portal.example.org/verify?id=123
Alternate: https://login.portal.example.org/verify?id=123
Contact admin at helpdesk@example.net or helpdesk@example.net.
Server IP: 198.51.100.89 and IPv6 2001:db8::1""",
        "raw_headers": SAMPLE_HEADERS_PASS
    }
    response = client.post("/api/v1/investigation/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    iocs = data["indicators"]

    # URLs extracted & deduplicated
    url_values = [u["value"] for u in iocs["urls"]]
    assert "https://login.portal.example.org/verify?id=123" in url_values
    assert len(url_values) == len(set(url_values))  # Deduplicated

    # Emails extracted & deduplicated
    email_values = [e["value"] for e in iocs["email_addresses"]]
    assert "helpdesk@example.net" in email_values
    assert len(email_values) == len(set(email_values))

    # IPs extracted (IPv4 and IPv6)
    ip_values = [i["value"] for i in iocs["ip_addresses"]]
    assert "203.0.113.10" in ip_values
    assert "198.51.100.89" in ip_values
    assert "2001:db8::1" in ip_values

    # Domains extracted
    domain_values = [d["value"] for d in iocs["domains"]]
    assert "example.com" in domain_values
    assert "login.portal.example.org" in domain_values

# 6. AI model unavailable state
def test_investigation_ai_model_unavailable_state():
    """Verify AI model unavailable state is cleanly reported without failing the investigation."""
    payload = {
        "subject": "Wire Transfer Notice",
        "body": "Please wire funds to account 123",
        "raw_headers": SAMPLE_HEADERS_SPOOFED
    }
    response = client.post("/api/v1/investigation/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    ai_data = data["threat_analysis"]
    assert ai_data["model_available"] is False
    assert ai_data["status"] == "model_unavailable"
    assert ai_data["primary_label"] is None
    assert ai_data["confidence"] is None
    assert data["summary"]["threat_model_status"] == "model_unavailable"
    assert data["summary"]["threat_model_prediction"] is None
    assert "explanation" in ai_data

# 7. Real model response handling if model exists (mocked test)
def test_investigation_real_model_response_mocked():
    """Verify investigation reflects model output when a real trained model is available."""
    mock_result = ThreatClassificationResult(
        model_available=True,
        status="model_available",
        primary_label="phishing",
        confidence=0.985,
        probabilities={
            "phishing": 0.985,
            "benign": 0.005,
            "suspicious": 0.005,
            "business_email_compromise": 0.005
        },
        device_used="cpu",
        model_name_or_path="roberta-threat-classifier",
        details="Inference executed successfully.",
        explanation="Inference executed successfully."
    )

    with patch("app.api.routes.investigation.roberta_classifier.predict", return_value=mock_result):
        payload = {
            "subject": "Urgent Verify Link",
            "body": "Click link to login",
            "raw_headers": SAMPLE_HEADERS_PASS
        }
        response = client.post("/api/v1/investigation/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["threat_analysis"]["model_available"] is True
        assert data["threat_analysis"]["status"] in ["model_available", "completed"]
        assert data["threat_analysis"]["primary_label"] == "phishing"
        assert data["threat_analysis"]["confidence"] == 0.985
        assert data["summary"]["threat_model_prediction"] == "phishing"

# 8. No fabricated probability values
def test_investigation_no_fabricated_probability_values():
    """Verify that when model is unavailable, probabilities dict is empty and confidence is null."""
    payload = {
        "subject": "Test",
        "body": "Test",
        "raw_headers": SAMPLE_HEADERS_PASS
    }
    response = client.post("/api/v1/investigation/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    ai_data = data["threat_analysis"]
    assert ai_data["probabilities"] == {}
    assert ai_data["confidence"] is None

# 9. API input validation (missing, empty, oversized headers)
def test_investigation_api_validation():
    """Verify input validation rejects empty or oversized headers."""
    # Empty string headers
    res_empty = client.post("/api/v1/investigation/analyze", json={"raw_headers": "   "})
    assert res_empty.status_code == 422
    assert "cannot be empty" in str(res_empty.json()["detail"])

    # Oversized headers > 500 KB
    oversized = "From: a@b.com\n" + ("X-Padding: " + "A" * 1000 + "\n") * 600
    res_oversized = client.post("/api/v1/investigation/analyze", json={"raw_headers": oversized})
    assert res_oversized.status_code == 422
    assert "exceeds maximum allowed size" in str(res_oversized.json()["detail"])

# 10. Suspicious header indicators
def test_investigation_suspicious_header_indicators():
    """Verify spoofed headers trigger factual suspicious indicators."""
    payload = {
        "subject": "Wire Transfer Request",
        "body": "Please wire funds",
        "raw_headers": SAMPLE_HEADERS_SPOOFED
    }
    response = client.post("/api/v1/investigation/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    indicators = data["indicators"]["suspicious_header_indicators"]
    assert len(indicators) > 0
    # Must capture Reply-To mismatch or SPF/DMARC failure
    assert any("Reply-To Mismatch" in ind or "DMARC" in ind or "SPF" in ind for ind in indicators)
