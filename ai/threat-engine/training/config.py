import os
from typing import Dict
from pydantic_settings import BaseSettings

# Canonical 4-class email threat taxonomy
LABEL2ID: Dict[str, int] = {
    "benign": 0,
    "suspicious": 1,
    "phishing": 2,
    "business_email_compromise": 3,
}

ID2LABEL: Dict[int, str] = {idx: label for label, idx in LABEL2ID.items()}
NUM_LABELS: int = len(LABEL2ID)

class TrainingConfig(BaseSettings):
    """Configuration and Hyperparameters for RoBERTa Fine-Tuning Pipeline."""

    # Model & Tokenization
    MAILTRACE_BASE_MODEL: str = "roberta-base"
    MAILTRACE_MODEL_MAX_LENGTH: int = 512

    # Reproducibility Seed
    MAILTRACE_TRAIN_SEED: int = 42

    # Dataset & Split Ratios (70% Train, 15% Val, 15% Test)
    MAILTRACE_DATA_PATH: str = os.path.join("ai", "threat-engine", "training", "data", "dataset.csv")
    MAILTRACE_TRAIN_SPLIT: float = 0.70
    MAILTRACE_VAL_SPLIT: float = 0.15
    MAILTRACE_TEST_SPLIT: float = 0.15

    # Hyperparameters
    MAILTRACE_TRAIN_EPOCHS: int = 3
    MAILTRACE_TRAIN_BATCH_SIZE: int = 8
    MAILTRACE_EVAL_BATCH_SIZE: int = 8
    MAILTRACE_TRAIN_LEARNING_RATE: float = 2e-5
    MAILTRACE_WEIGHT_DECAY: float = 0.01
    MAILTRACE_WARMUP_RATIO: float = 0.1
    MAILTRACE_WARMUP_STEPS: int = 0

    # Class Imbalance Handling
    MAILTRACE_CLASS_WEIGHTS: bool = False

    # Output Paths
    MAILTRACE_OUTPUT_DIR: str = os.path.join("ai", "threat-engine", "models", "roberta-threat-classifier")
    MAILTRACE_METRICS_DIR: str = os.path.join("ai", "threat-engine", "training", "metrics")

    # Hardware & Device Execution
    MAILTRACE_TRAIN_DEVICE: str = "auto"  # "auto", "cuda", or "cpu"

    @property
    def resolved_device(self) -> str:
        """Resolve target device (CUDA vs CPU) safely."""
        if self.MAILTRACE_TRAIN_DEVICE.lower() in ["auto", "cuda"]:
            try:
                import torch
                return "cuda" if torch.cuda.is_available() else "cpu"
            except ImportError:
                return "cpu"
        return "cpu"

    @property
    def sanitized_output_dir(self) -> str:
        """Return safe, non-filesystem-revealing path representation."""
        if not self.MAILTRACE_OUTPUT_DIR:
            return "roberta-threat-classifier"
        return os.path.basename(self.MAILTRACE_OUTPUT_DIR.rstrip("/\\")) or "roberta-threat-classifier"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

training_settings = TrainingConfig()
