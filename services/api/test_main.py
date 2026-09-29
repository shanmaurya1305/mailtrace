import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data == {
        "status": "ok",
        "service": "mailtrace-api"
    }

def test_cors_preflight_for_port_5174():
    """Verify CORS preflight OPTIONS request from http://localhost:5174 succeeds with correct headers."""
    headers = {
        "Origin": "http://localhost:5174",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    }
    response = client.options("/api/v1/forensics/analyze", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5174"
    assert "POST" in response.headers.get("access-control-allow-methods", "")

def test_cors_post_for_port_5174():
    """Verify POST request from http://localhost:5174 origin includes CORS allow headers."""
    headers = {
        "Origin": "http://localhost:5174",
        "Content-Type": "application/json",
    }
    raw_headers = "From: sender@example.com\r\nTo: user@example.org\r\nSubject: Test"
    response = client.post("/api/v1/forensics/analyze", headers=headers, json={"raw_headers": raw_headers})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5174"
