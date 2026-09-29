"""Abstract model interface for RoBERTa threat classification."""

from abc import ABC, abstractmethod
from typing import Dict, Any

try:
    from .schemas import ThreatClassificationInput, ThreatClassificationResult
except (ImportError, ValueError):
    from schemas import ThreatClassificationInput, ThreatClassificationResult

class ThreatClassifierInterface(ABC):
    """Abstract Base Class for email threat classification models."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether local model weights are present and ready."""
        pass

    @abstractmethod
    def load_model(self) -> bool:
        """Lazily load fine-tuned model weights and tokenizer."""
        pass

    @abstractmethod
    def predict(self, payload: ThreatClassificationInput) -> ThreatClassificationResult:
        """Classify email content into threat labels with probabilities."""
        pass
