import email
from email.policy import default
from typing import Dict, List, Tuple
from app.schemas import HeaderDetails

def parse_raw_headers(raw_headers: str) -> Tuple[HeaderDetails, List[str]]:
    """
    Safely parse raw RFC 822 email headers string into HeaderDetails schema.
    Returns (HeaderDetails, List[warnings]).
    """
    warnings: List[str] = []
    
    # Parse headers using standard email parser with default policy
    msg = email.message_from_string(raw_headers, policy=default)
    
    # Build dictionary of all headers with lists of values to preserve duplicates
    raw_headers_dict: Dict[str, List[str]] = {}
    for name, value in msg.items():
        key = name.strip()
        val = str(value).strip()
        if key in raw_headers_dict:
            raw_headers_dict[key].append(val)
        else:
            raw_headers_dict[key] = [val]

    def get_single(header_name: str) -> str | None:
        """Case-insensitive single header lookup."""
        for key, vals in raw_headers_dict.items():
            if key.lower() == header_name.lower() and vals:
                return vals[0]
        return None

    def get_list(header_name: str) -> List[str]:
        """Case-insensitive list header lookup, splitting comma-separated addresses if needed."""
        results: List[str] = []
        for key, vals in raw_headers_dict.items():
            if key.lower() == header_name.lower():
                for v in vals:
                    # split multi-address lines if comma present
                    parts = [p.strip() for p in v.split(",") if p.strip()]
                    results.extend(parts)
        return results

    from_addr = get_single("From")
    reply_to = get_single("Reply-To")
    return_path = get_single("Return-Path")
    subject = get_single("Subject")
    message_id = get_single("Message-ID")
    date_val = get_single("Date")
    to_addrs = get_list("To")
    cc_addrs = get_list("Cc")

    # Check for malformed or suspicious raw header structure
    if not msg.keys():
        warnings.append("Raw input contained no valid RFC 822 header key-value pairs")

    header_details = HeaderDetails(
        from_address=from_addr,
        to_addresses=to_addrs,
        cc_addresses=cc_addrs,
        reply_to=reply_to,
        return_path=return_path,
        subject=subject,
        message_id=message_id,
        date=date_val,
        raw_headers_dict=raw_headers_dict
    )

    return header_details, warnings
