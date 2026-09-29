import os
import logging
from typing import Tuple, Optional

try:
    from .config import ai_settings
    from .exceptions import ModelNotFoundError
except (ImportError, ValueError):
    from config import ai_settings
    from exceptions import ModelNotFoundError

logger = logging.getLogger("mailtrace-ai-loader")

class ModelContainer:
    _instance: Optional["ModelContainer"] = None
    _loaded: bool = False
    _available: bool = False
    _tokenizer = None
    _model = None
    _error_message: Optional[str] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModelContainer, cls).__new__(cls)
        return cls._instance

    def is_available(self) -> bool:
        """Check if local model directory exists, is enabled, and contains required files."""
        if not ai_settings.MAILTRACE_MODEL_ENABLED:
            return False

        path = ai_settings.MAILTRACE_MODEL_PATH
        if not path or not os.path.exists(path):
            return False

        # Must contain config.json and model weights
        config_file = os.path.join(path, "config.json")
        has_weights = (
            os.path.exists(os.path.join(path, "pytorch_model.bin")) or
            os.path.exists(os.path.join(path, "model.safetensors"))
        )
        return os.path.exists(config_file) and has_weights

    def load(self) -> Tuple[bool, Optional[str]]:
        """Lazily load model and tokenizer into memory if available."""
        if self._loaded:
            return self._available, self._error_message

        if not ai_settings.MAILTRACE_MODEL_ENABLED:
            self._loaded = True
            self._available = False
            self._error_message = "RoBERTa threat classification engine is disabled by configuration."
            logger.info(self._error_message)
            return False, self._error_message

        if not self.is_available():
            self._loaded = True
            self._available = False
            self._error_message = "No trained RoBERTa model weights found at configured model path."
            logger.info(self._error_message)
            return False, self._error_message

        model_path = ai_settings.MAILTRACE_MODEL_PATH

        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            logger.info(f"Loading local RoBERTa model from '{ai_settings.sanitized_model_name}' on device '{ai_settings.resolved_device}'...")

            self._tokenizer = AutoTokenizer.from_pretrained(
                model_path,
                local_files_only=ai_settings.MAILTRACE_MODEL_LOCAL_ONLY
            )

            self._model = AutoModelForSequenceClassification.from_pretrained(
                model_path,
                local_files_only=ai_settings.MAILTRACE_MODEL_LOCAL_ONLY
            )

            device = torch.device(ai_settings.resolved_device)
            self._model.to(device)
            self._model.eval()

            self._loaded = True
            self._available = True
            self._error_message = None
            logger.info("RoBERTa model loaded successfully.")
            return True, None

        except Exception as exc:
            self._loaded = True
            self._available = False
            self._error_message = "Failed to load RoBERTa model weights."
            logger.error(f"Failed to load RoBERTa model: {str(exc)}", exc_info=True)
            return False, self._error_message

    def get_components(self):
        """Retrieve loaded (tokenizer, model) tuple."""
        if not self._loaded:
            self.load()
        return self._tokenizer, self._model

    def reset_state(self):
        """Reset container state for testing."""
        self._loaded = False
        self._available = False
        self._tokenizer = None
        self._model = None
        self._error_message = None

model_container = ModelContainer()
