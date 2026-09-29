try:
    from .model_interface import ThreatClassifierInterface
    from .config import ai_settings
    from .schemas import ThreatClassificationInput, ThreatClassificationResult
    from .model_loader import model_container
except (ImportError, ValueError):
    from model_interface import ThreatClassifierInterface
    from config import ai_settings
    from schemas import ThreatClassificationInput, ThreatClassificationResult
    from model_loader import model_container

class RoBERTaThreatClassifier(ThreatClassifierInterface):
    """Production RoBERTa Threat Classifier Implementation."""

    def is_available(self) -> bool:
        """Check if trained model weights exist at configured local path."""
        return model_container.is_available()

    def load_model(self) -> bool:
        """Lazily load tokenizer and model into memory."""
        available, error = model_container.load()
        return available

    def predict(self, payload: ThreatClassificationInput) -> ThreatClassificationResult:
        """
        Classify email content into threat categories.
        If local model weights are absent or disabled, returns explicit model_unavailable state.
        Never generates fake threat scores or synthetic predictions.
        """
        if not ai_settings.MAILTRACE_MODEL_ENABLED:
            return ThreatClassificationResult(
                model_available=False,
                status="model_unavailable",
                primary_label=None,
                confidence=None,
                probabilities={},
                device_used=ai_settings.resolved_device,
                model_name_or_path=ai_settings.sanitized_model_name,
                details="RoBERTa threat classification engine is disabled by configuration."
            )

        if not self.is_available():
            return ThreatClassificationResult(
                model_available=False,
                status="model_unavailable",
                primary_label=None,
                confidence=None,
                probabilities={},
                device_used=ai_settings.resolved_device,
                model_name_or_path=ai_settings.sanitized_model_name,
                details="No trained RoBERTa model weights found at configured model path."
            )

        loaded, error_msg = model_container.load()
        if not loaded:
            return ThreatClassificationResult(
                model_available=False,
                status="model_unavailable",
                primary_label=None,
                confidence=None,
                probabilities={},
                device_used=ai_settings.resolved_device,
                model_name_or_path=ai_settings.sanitized_model_name,
                details=error_msg or "Failed to load model weights."
            )

        tokenizer, model = model_container.get_components()
        try:
            try:
                from .inference import run_inference
            except (ImportError, ValueError):
                from inference import run_inference

            return run_inference(payload, tokenizer, model)
        except Exception:
            return ThreatClassificationResult(
                model_available=False,
                status="model_unavailable",
                primary_label=None,
                confidence=None,
                probabilities={},
                device_used=ai_settings.resolved_device,
                model_name_or_path=ai_settings.sanitized_model_name,
                details="An error occurred during threat classification inference."
            )

# Global default instance
roberta_classifier = RoBERTaThreatClassifier()
