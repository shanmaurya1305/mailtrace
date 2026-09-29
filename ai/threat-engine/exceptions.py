class ThreatEngineError(Exception):
    """Base exception class for Threat Engine."""
    pass

class ModelNotFoundError(ThreatEngineError):
    """Raised when model weights or tokenizer directory are missing."""
    pass

class ModelNotLoadedError(ThreatEngineError):
    """Raised when attempting inference before loading model."""
    pass

class InferenceError(ThreatEngineError):
    """Raised when an error occurs during forward pass."""
    pass
