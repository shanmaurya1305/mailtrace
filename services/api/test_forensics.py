import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

# Test 1: Basic headers extraction
def test_basic_headers_extraction():
    raw_headers = """From: Alice <alice@example.com>
To: Bob <bob@example.org>
Subject: Phase 1 Verification Test
Date: Sat, 26 Sep 2026 12:00:00 +0000
Message-ID: <msg-001@example.com>"""

    response = client.post("/api/v1/forensics/analyze", json={"raw_headers": raw_headers})
    assert response.status_code == 200
    data = response.json()
    assert data["headers"]["from_address"] == "Alice <alice@example.com>"
    assert data["headers"]["to_addresses"] == ["Bob <bob@example.org>"]
    assert data["headers"]["subject"] == "Phase 1 Verification Test"
    assert data["headers"]["message_id"] == "<msg-001@example.com>"
    assert data["headers"]["date"] == "Sat, 26 Sep 2026 12:00:00 +0000"

# Test 2: Multiple Received headers order preservation & IP extraction
def test_multiple_received_headers():
    raw_headers = """From: sender@example.com
To: recipient@example.org
Received: from mail3.example.org (mail3.example.org [203.0.113.30])
    by mx.example.org with ESMTP id 333; Mon, 26 Sep 2026 12:02:00 +0000
Received: from mail2.example.net (mail2.example.net [198.51.100.20])
    by mail3.example.org with ESMTP id 222; Mon, 26 Sep 2026 12:01:00 +0000
Received: from mail1.example.com (mail1.example.com [192.0.2.10])
    by mail2.example.net with ESMTP id 111; Mon, 26 Sep 2026 12:00:00 +0000"""

    response = client.post("/api/v1/forensics/analyze", json={"raw_headers": raw_headers})
    assert response.status_code == 200
    data = response.json()
    hops = data["received_chain"]
    assert len(hops) == 3
    assert hops[0]["hop_index"] == 1
    assert hops[0]["source_ip"] == "203.0.113.30"
    assert hops[1]["hop_index"] == 2
    assert hops[1]["source_ip"] == "198.51.100.20"
    assert hops[2]["hop_index"] == 3
    assert hops[2]["source_ip"] == "192.0.2.10"

# Test 3: Authentication pass
def test_authentication_pass():
    raw_headers = """From: auth@example.com
To: user@example.org
Authentication-Results: mx.example.org;
    spf=pass smtp.mailfrom=auth@example.com;
    dkim=pass header.i=@example.com;
    dmarc=pass header.from=example.com"""

    response = client.post("/api/v1/forensics/analyze", json={"raw_headers": raw_headers})
    assert response.status_code == 200
    data = response.json()
    auth = data["authentication"]
    assert auth["spf"]["status"] == "pass"
    assert auth["spf"]["available"] is True
    assert auth["dkim"]["status"] == "pass"
    assert auth["dkim"]["available"] is True
    assert auth["dmarc"]["status"] == "pass"
    assert auth["dmarc"]["available"] is True

# Test 4: Authentication failure
def test_authentication_failure():
    raw_headers = """From: auth@example.com
To: user@example.org
Authentication-Results: mx.example.org;
    spf=fail smtp.mailfrom=auth@example.com;
    dkim=fail header.i=@example.com;
    dmarc=fail header.from=example.com"""

    response = client.post("/api/v1/forensics/analyze", json={"raw_headers": raw_headers})
    assert response.status_code == 200
    data = response.json()
    auth = data["authentication"]
    assert auth["spf"]["status"] == "fail"
    assert auth["dkim"]["status"] == "fail"
    assert auth["dmarc"]["status"] == "fail"

# Test 5: Authentication unavailable (unavailable != fail)
def test_authentication_unavailable():
    raw_headers = """From: noauth@example.com
To: user@example.org
Subject: No auth header present"""

    response = client.post("/api/v1/forensics/analyze", json={"raw_headers": raw_headers})
    assert response.status_code == 200
    data = response.json()
    auth = data["authentication"]
    assert auth["spf"]["available"] is False
    assert auth["spf"]["status"] == "unavailable"
    assert auth["spf"]["status"] != "fail"
    assert auth["dkim"]["available"] is False
    assert auth["dkim"]["status"] == "unavailable"
    assert auth["dkim"]["status"] != "fail"
    assert auth["dmarc"]["available"] is False
    assert auth["dmarc"]["status"] == "unavailable"
    assert auth["dmarc"]["status"] != "fail"

# Test 6: Reply-To mismatch generates neutral evidence
def test_reply_to_mismatch():
    raw_headers = """From: Official <admin@example.com>
Reply-To: Collector <phish@example.org>
To: User <user@example.net>"""

    response = client.post("/api/v1/forensics/analyze", json={"raw_headers": raw_headers})
    assert response.status_code == 200
    data = response.json()
    evidence = data["evidence"]
    mismatch_item = next((item for item in evidence if item["title"] == "Reply-To domain differs from From domain"), None)
    assert mismatch_item is not None
    assert mismatch_item["severity"] == "medium"
    assert "Reply-To domain (example.org) differs from the From domain (example.com)" in mismatch_item["description"]

# Test 7: Malformed headers handled gracefully without API crash
def test_malformed_headers():
    raw_headers = """This is not a valid header: value line
Another random line without colon
From sender@example.com"""

    response = client.post("/api/v1/forensics/analyze", json={"raw_headers": raw_headers})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"

# Test 8: Empty input validation error
def test_empty_input_validation():
    response = client.post("/api/v1/forensics/analyze", json={"raw_headers": "   "})
    assert response.status_code == 422
    data = response.json()
    assert "raw_headers input cannot be empty" in str(data)

# Test 9: Oversized input validation error
def test_oversized_input_validation():
    large_headers = "X-Header: " + ("A" * 600000)
    response = client.post("/api/v1/forensics/analyze", json={"raw_headers": large_headers})
    assert response.status_code == 422
    data = response.json()
    assert "exceeds maximum allowed size" in str(data)

# Test 10: Header case variation handling
def test_header_case_variation():
    raw_headers = """from: case1@example.com
REPLY-TO: case2@example.org
SUBJECT: Case Sensitivity Test"""

    response = client.post("/api/v1/forensics/analyze", json={"raw_headers": raw_headers})
    assert response.status_code == 200
    data = response.json()
    assert data["headers"]["from_address"] == "case1@example.com"
    assert data["headers"]["reply_to"] == "case2@example.org"
    assert data["headers"]["subject"] == "Case Sensitivity Test"
