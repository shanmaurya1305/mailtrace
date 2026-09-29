import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, HTTPException, status

# Ensure ai/threat-engine is accessible for classification engine
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

from schemas import ThreatClassificationInput
from classifier import roberta_classifier

from app.schemas import (
    InvestigationRequest,
    InvestigationResponse,
    InvestigationSummary,
    InvestigationRouting,
    ThreatModelOutput,
)
from app.forensics.parser import parse_raw_headers
from app.forensics.received import parse_received_headers
from app.forensics.authentication import parse_authentication_headers
from app.forensics.indicators import extract_investigation_iocs, extract_domain_from_email_address
from app.forensics.evidence import generate_forensic_evidence

router = APIRouter(prefix="/v1/investigation", tags=["Investigation"])

@router.post("/analyze", response_model=InvestigationResponse, status_code=status.HTTP_200_OK)
async def analyze_email_investigation(request: InvestigationRequest) -> InvestigationResponse:
    """
    Unified Email Threat Investigation Endpoint.
    Orchestrates deterministic header forensics, SPF/DKIM/DMARC authentication analysis,
    routing hop tracking, IOC extraction (IPv4/IPv6, domains, URLs, emails, suspicious flags),
    and AI threat classification attempt.
    
    If RoBERTa weights are unavailable, the investigation succeeds with full forensic evidence
    and explicitly reports threat_model_status="model_unavailable" without fabricating predictions.
    """
    try:
        # 1. Parse raw headers into canonical details
        headers_details, warnings = parse_raw_headers(request.raw_headers)

        # 2. Parse Received routing hop chain
        received_chain = parse_received_headers(headers_details.raw_headers_dict)

        # 3. Parse Authentication headers (SPF, DKIM, DMARC)
        auth_summary = parse_authentication_headers(headers_details.raw_headers_dict)

        # 4. Generate deterministic forensic evidence
        evidence = generate_forensic_evidence(
            headers=headers_details,
            auth=auth_summary,
            received_chain=received_chain,
            parser_warnings=warnings
        )

        # 5. Extract comprehensive indicators (IPs, Domains, URLs, Emails, Suspicious flags)
        effective_subject = request.subject or headers_details.subject
        iocs = extract_investigation_iocs(
            headers=headers_details,
            received_chain=received_chain,
            subject=effective_subject,
            body=request.body or "",
            forensic_evidence=evidence
        )

        # 6. Attempt AI Threat Classification
        # If model weights are missing or disabled, roberta_classifier returns status="model_unavailable"
        threat_input = ThreatClassificationInput(
            subject=effective_subject,
            body=request.body or "",
            headers_snippet=request.raw_headers[:500] if request.raw_headers else None
        )
        ai_res = roberta_classifier.predict(threat_input)

        threat_output = ThreatModelOutput(
            model_available=ai_res.model_available,
            status=ai_res.status,
            primary_label=ai_res.primary_label,
            confidence=ai_res.confidence,
            probabilities=ai_res.probabilities,
            device_used=ai_res.device_used,
            model_name_or_path=ai_res.model_name_or_path,
            details=ai_res.details,
            explanation=ai_res.explanation or ai_res.details,
        )

        # 7. Build routing summary
        routing = InvestigationRouting(
            sender=headers_details.from_address,
            sender_domain=extract_domain_from_email_address(headers_details.from_address),
            reply_to=headers_details.reply_to,
            reply_to_domain=extract_domain_from_email_address(headers_details.reply_to),
            return_path=headers_details.return_path,
            return_path_domain=extract_domain_from_email_address(headers_details.return_path),
            received_hops=received_chain
        )

        analysis_id = str(uuid.uuid4())
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        # 8. Build investigation summary
        summary = InvestigationSummary(
            analysis_id=analysis_id,
            status="completed",
            timestamp_utc=timestamp_utc,
            threat_model_status=threat_output.status,
            threat_model_prediction=threat_output.primary_label if threat_output.model_available else None
        )

        return InvestigationResponse(
            analysis_id=analysis_id,
            status="completed",
            summary=summary,
            authentication=auth_summary,
            routing=routing,
            indicators=iocs,
            evidence=evidence,
            threat_analysis=threat_output,
            warnings=warnings
        )

    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during email threat investigation: {str(exc)}"
        )
