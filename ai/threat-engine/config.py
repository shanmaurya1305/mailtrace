import os
from pydantic_settings import BaseSettings

class AIModelSettings(BaseSettings):
    """Configuration settings for RoBERTa Threat Engine."""
    MAILTRACE_MODEL_PATH: str = os.path.join("ai", "threat-engine", "models", "roberta-threat-classifier")
    MAILTRACE_MODEL_ENABLED: bool = True
    MAILTRACE_MODEL_LOCAL_ONLY: bool = True
    MAILTRACE_MODEL_MAX_LENGTH: int = 512
    MAILTRACE_MODEL_DEVICE: str = "auto"  # "auto", "cuda", or "cpu"

    @property
    def resolved_device(self) -> str:
        """Resolve target device (CUDA vs CPU) safely without top-level torch dependency."""
        if self.MAILTRACE_MODEL_DEVICE.lower() in ["auto", "cuda"]:
            try:
                import torch
                return "cuda" if torch.cuda.is_available() else "cpu"
            except ImportError:
                return "cpu"
        return "cpu"

    @property
    def sanitized_model_name(self) -> str:
        """Return safe, non-filesystem-revealing model identifier."""
        if not self.MAILTRACE_MODEL_PATH:
            return "none"
        basename = os.path.basename(self.MAILTRACE_MODEL_PATH.rstrip("/\\"))
        return basename or "roberta-threat-classifier"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

ai_settings = AIModelSettings()
