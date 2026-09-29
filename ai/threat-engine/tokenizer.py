from typing import Dict, Any, Optional

try:
    from .config import ai_settings
    from .schemas import ThreatClassificationInput
except (ImportError, ValueError):
    from config import ai_settings
    from schemas import ThreatClassificationInput

def prepare_email_text(payload: ThreatClassificationInput) -> str:
    """Format subject and body into a structured input sequence."""
    text_parts = []
    if payload.subject and payload.subject.strip():
        text_parts.append(f"Subject: {payload.subject.strip()}")
    if payload.body and payload.body.strip():
        text_parts.append(f"Body: {payload.body.strip()}")
    return "\n\n".join(text_parts) if text_parts else "Empty Email Content"

def tokenize_payload(payload: ThreatClassificationInput, tokenizer: Any) -> Dict[str, Any]:
    """Tokenize email payload into PyTorch model inputs."""
    raw_text = prepare_email_text(payload)
    return tokenizer(
        raw_text,
        max_length=ai_settings.MAILTRACE_MODEL_MAX_LENGTH,
        padding=True,
        truncation=True,
        return_tensors="pt"
    )
