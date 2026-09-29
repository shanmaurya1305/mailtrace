from typing import List, Dict, Optional
from pydantic import BaseModel, Field, field_validator

class HealthResponse(BaseModel):
    status: str
    service: str

    class Config:
        json_schema_extra = {
            "example": {
                "status": "ok",
                "service": "mailtrace-api"
            }
        }

class ForensicAnalysisRequest(BaseModel):
    raw_headers: str = Field(..., description="Raw RFC 822 email headers string")

    @field_validator("raw_headers")
    @classmethod
    def validate_raw_headers(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("raw_headers input cannot be empty")
        if len(v.encode("utf-8")) > 524288:  # 500 KB limit
            raise ValueError("raw_headers input exceeds maximum allowed size of 500 KB")
        return v

class HeaderDetails(BaseModel):
    from_address: Optional[str] = None
    to_addresses: List[str] = Field(default_factory=list)
    cc_addresses: List[str] = Field(default_factory=list)
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject: Optional[str] = None
    message_id: Optional[str] = None
    date: Optional[str] = None
    raw_headers_dict: Dict[str, List[str]] = Field(default_factory=dict)

class AuthMechanismStatus(BaseModel):
    available: bool = False
    status: str = "unavailable"  # pass, fail, softfail, neutral, none, temperror, permerror, policy, unavailable
    source: Optional[str] = None
    raw_details: Optional[str] = None
    signature_present: Optional[bool] = None  # Indicates if signature header exists (e.g. DKIM-Signature)
    verification_performed: bool = False      # Explicitly states cryptographic verification status

class AuthenticationSummary(BaseModel):
    spf: AuthMechanismStatus
    dkim: AuthMechanismStatus
    dmarc: AuthMechanismStatus

class ReceivedHop(BaseModel):
    hop_index: int
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    id_string: Optional[str] = None
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    raw_header: str

class ExtractedIP(BaseModel):
    type: str = "ip"
    value: str
    source: str
    validated: bool = True

class ExtractedDomain(BaseModel):
    type: str = "domain"
    value: str
    source: str

class ExtractedURL(BaseModel):
    type: str = "url"
    value: str
    source: str

class ExtractedEmailAddress(BaseModel):
    type: str = "email"
    value: str
    source: str

class ExtractedInfrastructure(BaseModel):
    ip_addresses: List[ExtractedIP] = Field(default_factory=list)
    domains: List[ExtractedDomain] = Field(default_factory=list)

class ForensicEvidence(BaseModel):
    evidence_id: str
    type: str  # header_observation, authentication_observation, infrastructure_observation, parser_warning
    severity: str  # info, low, medium, high
    title: str
    description: str
    source: str
    observed_value: Optional[str] = None

class ForensicAnalysisResponse(BaseModel):
    analysis_id: str
    status: str = "completed"
    headers: HeaderDetails
    authentication: AuthenticationSummary
    received_chain: List[ReceivedHop]
    infrastructure: ExtractedInfrastructure
    evidence: List[ForensicEvidence]
    warnings: List[str] = Field(default_factory=list)

# --- Phase 2C Investigation Schemas ---

class InvestigationRequest(BaseModel):
    subject: Optional[str] = Field(None, description="Email subject line")
    body: Optional[str] = Field("", description="Email body text content")
    raw_headers: str = Field(..., description="Raw RFC 822 email headers")

    @field_validator("raw_headers")
    @classmethod
    def validate_raw_headers(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("raw_headers input cannot be empty")
        if len(v.encode("utf-8")) > 524288:  # 500 KB limit
            raise ValueError("raw_headers input exceeds maximum allowed size of 500 KB")
        return v

class InvestigationIOCs(BaseModel):
    ip_addresses: List[ExtractedIP] = Field(default_factory=list)
    domains: List[ExtractedDomain] = Field(default_factory=list)
    urls: List[ExtractedURL] = Field(default_factory=list)
    email_addresses: List[ExtractedEmailAddress] = Field(default_factory=list)
    suspicious_header_indicators: List[str] = Field(default_factory=list)

class InvestigationSummary(BaseModel):
    analysis_id: str
    status: str = "completed"
    timestamp_utc: str
    threat_model_status: str  # "model_available" or "model_unavailable"
    threat_model_prediction: Optional[str] = None

class InvestigationRouting(BaseModel):
    sender: Optional[str] = None
    sender_domain: Optional[str] = None
    reply_to: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path: Optional[str] = None
    return_path_domain: Optional[str] = None
    received_hops: List[ReceivedHop] = Field(default_factory=list)

class ThreatModelOutput(BaseModel):
    model_available: bool
    status: str  # "model_available" or "model_unavailable"
    primary_label: Optional[str] = None
    confidence: Optional[float] = None
    probabilities: Dict[str, float] = Field(default_factory=dict)
    device_used: str
    model_name_or_path: Optional[str] = None
    details: Optional[str] = None
    explanation: Optional[str] = None

class InvestigationResponse(BaseModel):
    analysis_id: str
    status: str = "completed"
    summary: InvestigationSummary
    authentication: AuthenticationSummary
    routing: InvestigationRouting
    indicators: InvestigationIOCs
    evidence: List[ForensicEvidence]
    threat_analysis: ThreatModelOutput
    warnings: List[str] = Field(default_factory=list)
