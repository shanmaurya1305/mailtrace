import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Set, Optional
from app.schemas import (
    HeaderDetails,
    ReceivedHop,
    ExtractedIP,
    ExtractedDomain,
    ExtractedInfrastructure,
    ExtractedURL,
    ExtractedEmailAddress,
    InvestigationIOCs,
    ForensicEvidence,
)

DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
URL_REGEX = re.compile(r"https?://(?:[a-zA-Z0-9-._~:/?#\[\]@!$&'()*+,;=]|%[0-9a-fA-F]{2})+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def extract_domain_from_email_address(addr: str | None) -> str | None:
    """Extract domain from an email address like 'User <user@example.com>'."""
    if not addr:
        return None
    if "@" in addr:
        parts = addr.split("@")
        domain_part = parts[-1].rstrip(">").strip()
        # Clean port or trailing brackets
        domain_part = domain_part.split(":")[0].split("]")[0]
        if DOMAIN_REGEX.match(domain_part):
            return domain_part.lower()
    return None

def extract_infrastructure(
    headers: HeaderDetails,
    received_chain: List[ReceivedHop]
) -> ExtractedInfrastructure:
    """
    Extract validated IPv4/IPv6 addresses and normalized domain indicators
    from email headers and routing hops.
    Preserved for Phase 1 forensics backwards compatibility.
    """
    extracted_ips: List[ExtractedIP] = []
    seen_ips: Set[str] = set()

    extracted_domains: List[ExtractedDomain] = []
    seen_domains: Set[str] = set()

    def add_ip(ip_val: str, source: str):
        if not ip_val:
            return
        cleaned_ip = ip_val.strip("[] ")
        try:
            ip_obj = ipaddress.ip_address(cleaned_ip)
            val_str = str(ip_obj)
            if val_str not in seen_ips:
                seen_ips.add(val_str)
                extracted_ips.append(ExtractedIP(
                    type="ip",
                    value=val_str,
                    source=source,
                    validated=True
                ))
        except ValueError:
            pass

    def add_domain(domain_val: str | None, source: str):
        if not domain_val:
            return
        cleaned = domain_val.strip().lower()
        # Exclude IP addresses parsed as domains
        try:
            ipaddress.ip_address(cleaned)
            return
        except ValueError:
            pass

        if DOMAIN_REGEX.match(cleaned) and cleaned not in seen_domains:
            seen_domains.add(cleaned)
            extracted_domains.append(ExtractedDomain(
                type="domain",
                value=cleaned,
                source=source
            ))

    # 1. Extract IPs from Received Hops
    for hop in received_chain:
        if hop.source_ip:
            add_ip(hop.source_ip, source=f"Received (Hop {hop.hop_index})")
        if hop.from_host:
            possible_domains = DOMAIN_REGEX.findall(hop.from_host)
            for d in possible_domains:
                add_domain(d, source=f"Received (Hop {hop.hop_index})")

    # 2. Extract Domains from From, Reply-To, Return-Path, Message-ID
    add_domain(extract_domain_from_email_address(headers.from_address), source="From Header")
    add_domain(extract_domain_from_email_address(headers.reply_to), source="Reply-To Header")
    add_domain(extract_domain_from_email_address(headers.return_path), source="Return-Path Header")

    if headers.message_id:
        msg_domain = extract_domain_from_email_address(headers.message_id)
        add_domain(msg_domain, source="Message-ID Header")

    return ExtractedInfrastructure(
        ip_addresses=extracted_ips,
        domains=extracted_domains
    )

def extract_investigation_iocs(
    headers: HeaderDetails,
    received_chain: List[ReceivedHop],
    subject: Optional[str] = None,
    body: Optional[str] = None,
    forensic_evidence: Optional[List[ForensicEvidence]] = None,
) -> InvestigationIOCs:
    """
    Extract comprehensive, deduplicated IOCs from headers, routing hops, subject, and body:
    - IPv4 & IPv6 addresses
    - Domains
    - URLs (extracted safely without visiting)
    - Email addresses
    - Suspicious header indicators
    """
    seen_ips: Set[str] = set()
    extracted_ips: List[ExtractedIP] = []

    seen_domains: Set[str] = set()
    extracted_domains: List[ExtractedDomain] = []

    seen_urls: Set[str] = set()
    extracted_urls: List[ExtractedURL] = []

    seen_emails: Set[str] = set()
    extracted_emails: List[ExtractedEmailAddress] = []

    suspicious_indicators: List[str] = []
    seen_indicators: Set[str] = set()

    def add_ip(ip_val: str, source: str):
        if not ip_val:
            return
        cleaned = ip_val.strip("[]() \t\r\n")
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            val_str = str(ip_obj)
            if val_str not in seen_ips:
                seen_ips.add(val_str)
                extracted_ips.append(ExtractedIP(
                    type="ip",
                    value=val_str,
                    source=source,
                    validated=True
                ))
        except ValueError:
            pass

    def add_domain(domain_val: Optional[str], source: str):
        if not domain_val:
            return
        cleaned = domain_val.strip().lower()
        try:
            ipaddress.ip_address(cleaned)
            return
        except ValueError:
            pass

        if DOMAIN_REGEX.match(cleaned) and cleaned not in seen_domains:
            seen_domains.add(cleaned)
            extracted_domains.append(ExtractedDomain(
                type="domain",
                value=cleaned,
                source=source
            ))

    def add_url(raw_url: str, source: str):
        clean_url = raw_url.rstrip(".,;:!?)>\"'}\\]")
        if clean_url and clean_url not in seen_urls:
            seen_urls.add(clean_url)
            extracted_urls.append(ExtractedURL(
                type="url",
                value=clean_url,
                source=source
            ))
            # Extract domain from URL netloc
            try:
                parsed = urlparse(clean_url)
                if parsed.netloc:
                    netloc_domain = parsed.netloc.split(":")[0].strip().lower()
                    add_domain(netloc_domain, source=f"Extracted from URL ({source})")
            except Exception:
                pass

    def add_email(raw_email: Optional[str], source: str):
        if not raw_email:
            return
        matches = EMAIL_REGEX.findall(str(raw_email))
        for m in matches:
            cleaned = m.strip().lower()
            if cleaned not in seen_emails:
                seen_emails.add(cleaned)
                extracted_emails.append(ExtractedEmailAddress(
                    type="email",
                    value=cleaned,
                    source=source
                ))
                domain = extract_domain_from_email_address(cleaned)
                if domain:
                    add_domain(domain, source=f"Extracted from Email ({source})")

    def add_indicator(indicator_text: str):
        cleaned = indicator_text.strip()
        if cleaned and cleaned not in seen_indicators:
            seen_indicators.add(cleaned)
            suspicious_indicators.append(cleaned)

    # 1. Process Received Hops
    for hop in received_chain:
        if hop.source_ip:
            add_ip(hop.source_ip, source=f"Received (Hop {hop.hop_index})")
        if hop.from_host:
            for d in DOMAIN_REGEX.findall(hop.from_host):
                add_domain(d, source=f"Received (Hop {hop.hop_index})")
        if hop.by_host:
            for d in DOMAIN_REGEX.findall(hop.by_host):
                add_domain(d, source=f"Received (Hop {hop.hop_index})")

    # 2. Process Header Email Addresses and Domains
    add_email(headers.from_address, source="From Header")
    for to_addr in headers.to_addresses:
        add_email(to_addr, source="To Header")
    for cc_addr in headers.cc_addresses:
        add_email(cc_addr, source="Cc Header")
    add_email(headers.reply_to, source="Reply-To Header")
    add_email(headers.return_path, source="Return-Path Header")

    if headers.message_id:
        msg_domain = extract_domain_from_email_address(headers.message_id)
        if msg_domain:
            add_domain(msg_domain, source="Message-ID Header")

    # 3. Process Header Dict for URLs and IPs (e.g. List-Unsubscribe, X-Originating-IP)
    for h_name, h_vals in headers.raw_headers_dict.items():
        h_name_lower = h_name.lower()
        for v in h_vals:
            if "ip" in h_name_lower:
                for match_ip in IPV4_REGEX.findall(v):
                    add_ip(match_ip, source=f"Header: {h_name}")
            if "unsubscribe" in h_name_lower or "url" in h_name_lower or "link" in h_name_lower:
                for match_url in URL_REGEX.findall(v):
                    add_url(match_url, source=f"Header: {h_name}")

    # 4. Process Email Body for URLs, IPs, Emails, and Domains
    if body and body.strip():
        # URLs
        for match_url in URL_REGEX.findall(body):
            add_url(match_url, source="Email Body")

        # Email addresses
        for match_email in EMAIL_REGEX.findall(body):
            add_email(match_email, source="Email Body")

        # Standalone IPv4 addresses in body
        for match_ip in IPV4_REGEX.findall(body):
            add_ip(match_ip, source="Email Body")

        # Potential IPv6 addresses in body
        for token in re.findall(r"\b[0-9a-fA-F:]{3,39}\b", body):
            if ":" in token:
                add_ip(token, source="Email Body")

    # 5. Process Forensic Evidence into Suspicious Header Indicators
    if forensic_evidence:
        for ev in forensic_evidence:
            if ev.severity in ["high", "medium"]:
                add_indicator(f"[{ev.severity.upper()}] {ev.title}: {ev.description}")
            elif ev.type in ["authentication_observation", "header_observation"]:
                if "fail" in ev.description.lower() or "mismatch" in ev.description.lower():
                    add_indicator(f"[{ev.severity.upper()}] {ev.title}: {ev.description}")

    # Check for Reply-To mismatch explicitly
    from_dom = extract_domain_from_email_address(headers.from_address)
    reply_dom = extract_domain_from_email_address(headers.reply_to)
    if from_dom and reply_dom and from_dom != reply_dom:
        add_indicator(f"[MEDIUM] Reply-To Mismatch: From domain '{from_dom}' differs from Reply-To domain '{reply_dom}'")

    return InvestigationIOCs(
        ip_addresses=extracted_ips,
        domains=extracted_domains,
        urls=extracted_urls,
        email_addresses=extracted_emails,
        suspicious_header_indicators=suspicious_indicators,
    )
