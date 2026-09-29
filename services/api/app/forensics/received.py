import re
import ipaddress
from typing import List, Dict, Optional
from app.schemas import ReceivedHop

# Regex patterns for extracting clauses from Received header
IP_REGEX = re.compile(r"\[(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[a-fA-F0-9:]+::?[a-fA-F0-9:]*))\]")
FROM_REGEX = re.compile(r"\bfrom\s+([^\s;()]+(?:\s*\([^)]*\))?)", re.IGNORECASE)
BY_REGEX = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)
WITH_REGEX = re.compile(r"\bwith\s+([^\s;()]+)", re.IGNORECASE)
ID_REGEX = re.compile(r"\bid\s+([^\s;()]+)", re.IGNORECASE)

def extract_ip_from_text(text: str) -> Optional[str]:
    """Find and validate IPv4/IPv6 address inside brackets in Received header text."""
    matches = IP_REGEX.findall(text)
    for m in matches:
        try:
            ip_obj = ipaddress.ip_address(m)
            return str(ip_obj)
        except ValueError:
            continue
    return None

def parse_received_headers(raw_headers_dict: Dict[str, List[str]]) -> List[ReceivedHop]:
    """
    Parse Received headers list in chronological/routing order.
    In RFC 822 emails, the topmost Received header is the last hop (closest to recipient).
    We preserve top-to-bottom order with hop_index starting at 1.
    """
    received_list: List[str] = []
    
    # Case-insensitive lookup for Received headers
    for key, vals in raw_headers_dict.items():
        if key.lower() == "received":
            received_list = vals
            break

    hops: List[ReceivedHop] = []
    
    for idx, raw in enumerate(received_list, start=1):
        # Clean line breaks inside received header
        clean_raw = " ".join([line.strip() for line in raw.splitlines() if line.strip()])
        
        # Split timestamp part after semicolon if present
        parts = clean_raw.split(";", 1)
        header_body = parts[0]
        timestamp = parts[1].strip() if len(parts) > 1 else None

        from_match = FROM_REGEX.search(header_body)
        by_match = BY_REGEX.search(header_body)
        with_match = WITH_REGEX.search(header_body)
        id_match = ID_REGEX.search(header_body)

        from_host = from_match.group(1).strip() if from_match else None
        by_host = by_match.group(1).strip() if by_match else None
        with_protocol = with_match.group(1).strip() if with_match else None
        id_string = id_match.group(1).strip() if id_match else None
        source_ip = extract_ip_from_text(header_body)

        hop = ReceivedHop(
            hop_index=idx,
            from_host=from_host,
            by_host=by_host,
            with_protocol=with_protocol,
            id_string=id_string,
            timestamp=timestamp,
            source_ip=source_ip,
            raw_header=clean_raw
        )
        hops.append(hop)

    return hops
