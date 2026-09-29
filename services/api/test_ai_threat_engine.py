import sys
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch
import torch
from fastapi.testclient import TestClient

# Locate project root and threat-engine
root_dir = Path(__file__).resolve().parent.parent
ai_engine_path = root_dir / "ai" / "threat-engine"
if str(ai_engine_path) not in sys.path:
    sys.path.insert(0, str(ai_engine_path))

from app.main import app
from config import ai_settings, AIModelSettings
from model_loader import model_container
from classifier import roberta_classifier, RoBERTaThreatClassifier
from schemas import ThreatClassificationInput
from inference import run_inference

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_container():
    """Ensure clean container state before each test."""
    model_container.reset_state()
    yield
    model_container.reset_state()

# 1. Configuration tests
def test_ai_config_defaults():
    """Verify default AI Threat Engine settings and device resolution."""
    assert ai_settings.MAILTRACE_MODEL_ENABLED is True
    assert ai_settings.MAILTRACE_MODEL_LOCAL_ONLY is True
    assert ai_settings.MAILTRACE_MODEL_MAX_LENGTH == 512
    assert ai_settings.resolved_device in ["cpu", "cuda"]
    # Verify sanitized model name does not expose full server filesystem path
    assert ai_settings.sanitized_model_name == "roberta-threat-classifier"
    assert "C:" not in ai_settings.sanitized_model_name

# 2. Disabled model tests
def test_model_disabled_state():
    """Verify engine handles disabled model setting gracefully."""
    with patch.object(ai_settings, "MAILTRACE_MODEL_ENABLED", False):
        classifier = RoBERTaThreatClassifier()
        assert classifier.is_available() is False
        
        payload = ThreatClassificationInput(
            subject="Test subject",
            body="Test email body text"
        )
        result = classifier.predict(payload)
        assert result.model_available is False
        assert result.status == "model_unavailable"
        assert result.primary_label is None
        assert "disabled by configuration" in result.details

# 3. Missing model tests
def test_model_loader_missing_path():
    """Verify model loader reports model_available: False when local weights do not exist."""
    assert model_container.is_available() is False
    loaded, error_msg = model_container.load()
    assert loaded is False
    assert model_container._available is False
    assert "No trained RoBERTa model weights found" in error_msg

# 4. Lazy loading tests
def test_lazy_loading_behavior():
    """Verify classifier instantiation does not trigger model loading."""
    fresh_classifier = RoBERTaThreatClassifier()
    # Before load_model or predict, container should not be loaded
    assert model_container._loaded is False
    assert model_container._tokenizer is None
    assert model_container._model is None

# 5. API validation tests
def test_threat_classify_api_validation():
    """Verify empty payload or missing body returns HTTP 422 error."""
    # Missing required body
    response = client.post("/api/v1/threat/classify", json={"subject": "Only subject"})
    assert response.status_code == 422

    # Completely empty JSON
    response = client.post("/api/v1/threat/classify", json={})
    assert response.status_code == 422

# 6. API unavailable state tests
def test_threat_classify_endpoint_unavailable_response():
    """Verify POST /api/v1/threat/classify returns explicit model_unavailable state without fake scores."""
    payload = {
        "subject": "Urgent Invoice Payment Overdue",
        "body": "Please wire funds to the specified routing number immediately."
    }
    response = client.post("/api/v1/threat/classify", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["model_available"] is False
    assert data["status"] == "model_unavailable"
    assert data["primary_label"] is None
    assert data["confidence"] is None
    assert data["probabilities"] == {}
    assert data["model_name_or_path"] == "roberta-threat-classifier"
    # Ensure server path is not exposed
    assert "C:" not in data["details"]
    assert "No trained RoBERTa model weights found" in data["details"]

# 7. Probability normalization tests
def test_inference_probability_normalization():
    """Verify run_inference applies softmax correctly and maps probabilities."""
    mock_tokenizer = MagicMock()
    mock_tokenizer.return_value = {
        "input_ids": torch.tensor([[101, 102]]),
        "attention_mask": torch.tensor([[1, 1]])
    }

    mock_model = MagicMock()
    # Mock logits: class 2 has highest logit
    mock_model.return_value.logits = torch.tensor([[0.5, 1.2, 3.8, 0.1]])
    mock_model.config.id2label = {
        0: "benign",
        1: "suspicious",
        2: "phishing",
        3: "business_email_compromise"
    }

    payload = ThreatClassificationInput(
        subject="Suspicious link",
        body="Click here to claim reward"
    )

    result = run_inference(payload, mock_tokenizer, mock_model)
    assert result.model_available is True
    assert result.status in ["completed", "model_available"]
    assert result.primary_label == "phishing"
    assert isinstance(result.confidence, float)
    assert 0.0 <= result.confidence <= 1.0

    # Probabilities must sum close to 1.0
    prob_sum = sum(result.probabilities.values())
    assert pytest.approx(prob_sum, 0.01) == 1.0
    assert result.probabilities["phishing"] == result.confidence

# 8. Classifier error handling tests
def test_classifier_error_handling():
    """Verify runtime inference errors return safe model_unavailable state without 500 error."""
    classifier = RoBERTaThreatClassifier()
    with patch.object(classifier, "is_available", return_value=True):
        with patch("model_loader.model_container.load", return_value=(True, None)):
            with patch("model_loader.model_container.get_components", return_value=(MagicMock(), MagicMock())):
                with patch("inference.run_inference", side_effect=RuntimeError("CUDA out of memory")):
                    payload = ThreatClassificationInput(body="Test email")
                    result = classifier.predict(payload)
                    assert result.model_available is False
                    assert result.status == "model_unavailable"
                    assert "An error occurred during threat classification inference" in result.details
                    # Stack trace not exposed
                    assert "CUDA out of memory" not in result.details
