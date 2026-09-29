import uuid
from fastapi import APIRouter, HTTPException, status
from app.schemas import ForensicAnalysisRequest, ForensicAnalysisResponse
from app.forensics.parser import parse_raw_headers
from app.forensics.received import parse_received_headers
from app.forensics.authentication import parse_authentication_headers
from app.forensics.indicators import extract_infrastructure
from app.forensics.evidence import generate_forensic_evidence

router = APIRouter(prefix="/v1/forensics", tags=["Email Forensics"])

@router.post("/analyze", response_model=ForensicAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_email_headers(request: ForensicAnalysisRequest) -> ForensicAnalysisResponse:
    """
    Forensic Email Header Analysis Endpoint.
    Parses raw headers safely, extracts Received hops, SPF/DKIM/DMARC authentication results,
    extracts IP/Domain indicators, and generates neutral forensic observations.
    """
    try:
        # 1. Parse raw headers into standard fields
        headers_details, warnings = parse_raw_headers(request.raw_headers)
        
        # 2. Parse Received header chain
        received_chain = parse_received_headers(headers_details.raw_headers_dict)
        
        # 3. Parse Authentication results
        auth_summary = parse_authentication_headers(headers_details.raw_headers_dict)
        
        # 4. Extract IP and Domain indicators
        infrastructure = extract_infrastructure(headers_details, received_chain)
        
        # 5. Generate deterministic evidence items
        evidence = generate_forensic_evidence(
            headers=headers_details,
            auth=auth_summary,
            received_chain=received_chain,
            parser_warnings=warnings
        )
        
        # Generate safe UUID analysis_id
        analysis_id = str(uuid.uuid4())
        
        return ForensicAnalysisResponse(
            analysis_id=analysis_id,
            status="completed",
            headers=headers_details,
            authentication=auth_summary,
            received_chain=received_chain,
            infrastructure=infrastructure,
            evidence=evidence,
            warnings=warnings
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while processing forensic headers: {str(exc)}"
        )
