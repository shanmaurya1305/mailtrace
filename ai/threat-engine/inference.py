import torch
from typing import Dict, Any

try:
    from .config import ai_settings
    from .schemas import ThreatClassificationInput, ThreatClassificationResult
    from .tokenizer import tokenize_payload
except (ImportError, ValueError):
    from config import ai_settings
    from schemas import ThreatClassificationInput, ThreatClassificationResult
    from tokenizer import tokenize_payload

# Default fallback label mapping for 4-class email threat classification
DEFAULT_ID2LABEL = {
    0: "benign",
    1: "suspicious",
    2: "phishing",
    3: "business_email_compromise"
}

def run_inference(
    payload: ThreatClassificationInput,
    tokenizer: Any,
    model: Any
) -> ThreatClassificationResult:
    """
    Execute model forward pass under torch.inference_mode().
    Returns ThreatClassificationResult with normalized softmax probabilities.
    """
    device = torch.device(ai_settings.resolved_device)

    # 1. Tokenize input payload
    inputs = tokenize_payload(payload, tokenizer)
    inputs = {k: v.to(device) for k, v in inputs.items()}

    # 2. Run inference in evaluation & inference_mode
    with torch.inference_mode():
        outputs = model(**inputs)
        logits = outputs.logits
        probabilities = torch.softmax(logits, dim=-1).squeeze(0)

    # 3. Map probabilities to labels
    id2label = getattr(model.config, "id2label", DEFAULT_ID2LABEL)
    prob_dict: Dict[str, float] = {}

    for idx, prob in enumerate(probabilities.tolist()):
        label_name = id2label.get(idx, f"label_{idx}")
        clean_label = str(label_name).lower().replace(" ", "_")
        prob_dict[clean_label] = round(float(prob), 4)

    # 4. Determine primary label & confidence
    if prob_dict:
        primary_label = max(prob_dict, key=prob_dict.get)
        confidence = prob_dict[primary_label]
    else:
        primary_label = "unknown"
        confidence = 0.0

    return ThreatClassificationResult(
        model_available=True,
        status="model_available",
        primary_label=primary_label,
        confidence=confidence,
        probabilities=prob_dict,
        device_used=ai_settings.resolved_device,
        model_name_or_path=ai_settings.sanitized_model_name,
        details="RoBERTa threat classification inference completed successfully.",
        explanation="RoBERTa threat classification inference completed successfully."
    )
