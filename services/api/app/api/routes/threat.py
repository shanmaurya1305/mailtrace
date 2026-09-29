import sys
from pathlib import Path
from fastapi import APIRouter, status

def _setup_threat_engine_path():
    curr = Path(__file__).resolve()
    for parent in curr.parents:
        candidate = parent / "ai" / "threat-engine"
        if candidate.is_dir():
            if str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
            return candidate
    raise RuntimeError("Could not find ai/threat-engine directory")

_setup_threat_engine_path()

from schemas import ThreatClassificationInput, ThreatClassificationResult
from classifier import roberta_classifier

router = APIRouter(prefix="/v1/threat", tags=["AI Threat Engine"])

@router.post("/classify", response_model=ThreatClassificationResult, status_code=status.HTTP_200_OK)
async def classify_email_threat(payload: ThreatClassificationInput) -> ThreatClassificationResult:
    """
    AI Threat Engine Email Classification Endpoint.
    Classifies email subject & body into threat categories (phishing, BEC, suspicious, benign)
    using fine-tuned RoBERTa sequence classification.
    If no trained model weights are found at the configured local path, explicitly returns
    status="model_unavailable" without generating fake threat scores.
    """
    return roberta_classifier.predict(payload)
