from typing import Optional, Dict
from pydantic import BaseModel, Field, model_validator

class ThreatClassificationInput(BaseModel):
    subject: Optional[str] = Field(None, description="Email subject header")
    body: str = Field(..., description="Email body text content")
    headers_snippet: Optional[str] = Field(None, description="Optional raw header snippet")

class ThreatClassificationResult(BaseModel):
    model_available: bool
    status: str  # "model_available" or "model_unavailable"
    primary_label: Optional[str] = None  # "phishing", "business_email_compromise", "suspicious", "benign"
    confidence: Optional[float] = None
    probabilities: Dict[str, float] = Field(default_factory=dict)
    device_used: str
    model_name_or_path: Optional[str] = None
    details: Optional[str] = None
    explanation: Optional[str] = None

    @model_validator(mode="after")
    def sync_details_and_explanation(self):
        if not self.explanation and self.details:
            self.explanation = self.details
        elif not self.details and self.explanation:
            self.details = self.explanation
        return self

    class Config:
        json_schema_extra = {
            "example": {
                "model_available": False,
                "status": "model_unavailable",
                "primary_label": None,
                "confidence": None,
                "probabilities": {},
                "device_used": "cpu",
                "model_name_or_path": "roberta-threat-classifier",
                "details": "No trained RoBERTa model weights found at configured path.",
                "explanation": "No trained RoBERTa model weights found at configured path."
            }
        }
