import uuid
from typing import List
from app.schemas import HeaderDetails, AuthenticationSummary, ForensicEvidence, ReceivedHop
from app.forensics.indicators import extract_domain_from_email_address

def generate_forensic_evidence(
    headers: HeaderDetails,
    auth: AuthenticationSummary,
    received_chain: List[ReceivedHop],
    parser_warnings: List[str]
) -> List[ForensicEvidence]:
    """
    Generate deterministic evidence items based on parsed header observations.
    All descriptions use objective, neutral wording without declaring threat scores.
    """
    evidence_list: List[ForensicEvidence] = []
    counter = 1

    def make_id() -> str:
        nonlocal counter
        eid = f"EV-{counter:03d}"
        counter += 1
        return eid

    from_domain = extract_domain_from_email_address(headers.from_address)
    reply_to_domain = extract_domain_from_email_address(headers.reply_to)
    return_path_domain = extract_domain_from_email_address(headers.return_path)

    # 1. Reply-To / From Domain Observation
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        evidence_list.append(ForensicEvidence(
            evidence_id=make_id(),
            type="header_observation",
            severity="medium",
            title="Reply-To domain differs from From domain",
            description=f"The Reply-To domain ({reply_to_domain}) differs from the From domain ({from_domain}).",
            source="Reply-To / From Headers",
            observed_value=f"From: {from_domain} | Reply-To: {reply_to_domain}"
        ))

    # 2. Return-Path / From Domain Observation
    if from_domain and return_path_domain and from_domain != return_path_domain:
        evidence_list.append(ForensicEvidence(
            evidence_id=make_id(),
            type="header_observation",
            severity="low",
            title="Return-Path domain differs from From domain",
            description=f"The Return-Path domain ({return_path_domain}) differs from the From domain ({from_domain}).",
            source="Return-Path / From Headers",
            observed_value=f"From: {from_domain} | Return-Path: {return_path_domain}"
        ))

    # 3. Authentication Observations
    # SPF
    if auth.spf.available:
        sev = "info" if auth.spf.status == "pass" else "medium"
        evidence_list.append(ForensicEvidence(
            evidence_id=make_id(),
            type="authentication_observation",
            severity=sev,
            title=f"SPF Authentication Result: {auth.spf.status.upper()}",
            description=f"SPF check returned status '{auth.spf.status}' from {auth.spf.source}.",
            source=auth.spf.source or "SPF Engine",
            observed_value=auth.spf.raw_details
        ))
    else:
        evidence_list.append(ForensicEvidence(
            evidence_id=make_id(),
            type="authentication_observation",
            severity="info",
            title="SPF Information Unavailable",
            description="No explicit SPF authentication record was found in email headers.",
            source="Header Analysis"
        ))

    # DKIM
    if auth.dkim.available:
        sev = "info" if auth.dkim.status == "pass" else "medium"
        evidence_list.append(ForensicEvidence(
            evidence_id=make_id(),
            type="authentication_observation",
            severity=sev,
            title=f"DKIM Authentication Result: {auth.dkim.status.upper()}",
            description=f"DKIM result explicitly documented as '{auth.dkim.status}'.",
            source=auth.dkim.source or "Authentication-Results",
            observed_value=auth.dkim.raw_details
        ))
    elif auth.dkim.signature_present:
        evidence_list.append(ForensicEvidence(
            evidence_id=make_id(),
            type="authentication_observation",
            severity="info",
            title="DKIM Signature Header Present (Verification Not Performed)",
            description="A DKIM-Signature header is present in the email, but documented verification results were not included.",
            source="DKIM-Signature Header"
        ))
    else:
        evidence_list.append(ForensicEvidence(
            evidence_id=make_id(),
            type="authentication_observation",
            severity="info",
            title="DKIM Information Unavailable",
            description="No DKIM signature or verification result was found in email headers.",
            source="Header Analysis"
        ))

    # DMARC
    if auth.dmarc.available:
        sev = "info" if auth.dmarc.status == "pass" else "medium"
        evidence_list.append(ForensicEvidence(
            evidence_id=make_id(),
            type="authentication_observation",
            severity=sev,
            title=f"DMARC Authentication Result: {auth.dmarc.status.upper()}",
            description=f"DMARC verification result documented as '{auth.dmarc.status}'.",
            source=auth.dmarc.source or "Authentication-Results",
            observed_value=auth.dmarc.raw_details
        ))
    else:
        evidence_list.append(ForensicEvidence(
            evidence_id=make_id(),
            type="authentication_observation",
            severity="info",
            title="DMARC Information Unavailable",
            description="No explicit DMARC evaluation result was documented in email headers.",
            source="Header Analysis"
        ))

    # 4. Routing Hops Evidence
    if received_chain:
        evidence_list.append(ForensicEvidence(
            evidence_id=make_id(),
            type="infrastructure_observation",
            severity="info",
            title=f"Received Header Chain Parsed ({len(received_chain)} Hops)",
            description=f"Extracted {len(received_chain)} transit routing hops from Received headers.",
            source="Received Chain"
        ))

    # 5. Parser Warnings
    for warn in parser_warnings:
        evidence_list.append(ForensicEvidence(
            evidence_id=make_id(),
            type="parser_warning",
            severity="low",
            title="Header Parser Warning",
            description=warn,
            source="Parser Engine"
        ))

    return evidence_list
