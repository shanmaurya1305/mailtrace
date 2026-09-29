import re
from typing import Dict, List, Optional
from app.schemas import AuthMechanismStatus, AuthenticationSummary

def parse_auth_status(value: str) -> str:
    """Normalize authentication result status string."""
    v = value.lower().strip()
    if "pass" in v:
        return "pass"
    elif "fail" in v and "softfail" not in v:
        return "fail"
    elif "softfail" in v:
        return "softfail"
    elif "neutral" in v:
        return "neutral"
    elif "none" in v:
        return "none"
    elif "temperror" in v or "temp-error" in v:
        return "temperror"
    elif "permerror" in v or "perm-error" in v:
        return "permerror"
    elif "policy" in v:
        return "policy"
    return "unknown"

def parse_authentication_headers(raw_headers_dict: Dict[str, List[str]]) -> AuthenticationSummary:
    """
    Parse SPF, DKIM, and DMARC authentication results from email headers.
    Distinguishes presence of DKIM-Signature from DKIM verification results.
    Explicitly marks missing authentication as unavailable (unavailable != fail).
    """
    # Case-insensitive helper
    def get_headers(name: str) -> List[str]:
        for k, v in raw_headers_dict.items():
            if k.lower() == name.lower():
                return v
        return []

    auth_results_list = get_headers("Authentication-Results") + get_headers("ARC-Authentication-Results")
    received_spf_list = get_headers("Received-SPF")
    dkim_sig_list = get_headers("DKIM-Signature")

    spf_status = AuthMechanismStatus(available=False, status="unavailable", verification_performed=False)
    dkim_status = AuthMechanismStatus(
        available=False,
        status="unavailable",
        signature_present=len(dkim_sig_list) > 0,
        verification_performed=False
    )
    dmarc_status = AuthMechanismStatus(available=False, status="unavailable", verification_performed=False)

    # 1. Parse SPF from Received-SPF header if present
    if received_spf_list:
        raw = received_spf_list[0]
        status_part = raw.split()[0] if raw.split() else raw
        spf_status = AuthMechanismStatus(
            available=True,
            status=parse_auth_status(status_part),
            source="Received-SPF",
            raw_details=raw,
            verification_performed=True
        )

    # 2. Parse Authentication-Results headers (overrides or complements Received-SPF)
    for auth_raw in auth_results_list:
        # Match SPF in Authentication-Results
        spf_match = re.search(r"\bspf\s*=\s*([a-zA-Z0-9_-]+)", auth_raw, re.IGNORECASE)
        if spf_match and not spf_status.available:
            st = parse_auth_status(spf_match.group(1))
            spf_status = AuthMechanismStatus(
                available=True,
                status=st,
                source="Authentication-Results",
                raw_details=auth_raw,
                verification_performed=True
            )

        # Match DKIM in Authentication-Results
        dkim_match = re.search(r"\bdkim\s*=\s*([a-zA-Z0-9_-]+)", auth_raw, re.IGNORECASE)
        if dkim_match:
            st = parse_auth_status(dkim_match.group(1))
            dkim_status = AuthMechanismStatus(
                available=True,
                status=st,
                source="Authentication-Results",
                raw_details=auth_raw,
                signature_present=len(dkim_sig_list) > 0,
                verification_performed=True
            )

        # Match DMARC in Authentication-Results
        dmarc_match = re.search(r"\bdmarc\s*=\s*([a-zA-Z0-9_-]+)", auth_raw, re.IGNORECASE)
        if dmarc_match:
            st = parse_auth_status(dmarc_match.group(1))
            dmarc_status = AuthMechanismStatus(
                available=True,
                status=st,
                source="Authentication-Results",
                raw_details=auth_raw,
                verification_performed=True
            )

    return AuthenticationSummary(
        spf=spf_status,
        dkim=dkim_status,
        dmarc=dmarc_status
    )
