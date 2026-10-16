"""
Privacy Guard & PII Sanitization Engine
=======================================
Provides deterministic privacy guardrails and PII masking across the ADK
multi-agent system.

Core Guarantees:
1. Threat Intelligence Preservation: Public IP addresses, file hashes, malware
   names, command-lines, external domains, and MITRE tactics are strictly preserved.
2. Search Query Privacy: Blocks outbound search queries from leaking employee
   identities (user IDs), internal workstation hostnames, RFC-1918 private IPs,
   or personal PII to public search engines.
3. Ingress/Egress Masking: Redacts personal identifiers (SSNs, payment cards,
   emails, phone numbers, credentials, and private IPs) from desktop OCR and
   incident reports.
"""

import ipaddress
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# --- Patterns for PII & Sensitive Data ---
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
SSN_PATTERN = re.compile(
    r"\b(?:\d{3}-\d{2}-\d{4})\b"
)
PHONE_PATTERN = re.compile(
    r"(?:(?<=\b)|(?<=\s)|(?<=^))(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)
IPV4_CANDIDATE_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)
INTERNAL_DOMAIN_PATTERN = re.compile(
    r"(?i)\b[a-zA-Z0-9_-]+\.(?:internal|corp|local|lan|priv)\b"
)
INTERNAL_HOST_PATTERN = re.compile(
    r"(?i)\b(?:ws|srv|dc|laptop|pc|desktop|workstation)-[a-zA-Z0-9_-]+\b"
)
SECRET_PATTERN = re.compile(
    r"(?i)\b(?:bearer\s+[A-Za-z0-9_\-\.]{20,}|(?:password|passwd|api[_-]?key|secret)\s*[:=]\s*['\"][^'\"]{6,}['\"])"
)

# Potential card pattern (13-19 digits, possibly space/hyphen separated)
CARD_CANDIDATE_PATTERN = re.compile(
    r"\b(?:\d[ -]?){13,19}\b"
)


def _luhn_checksum_valid(number_str: str) -> bool:
    """Validates whether a digit sequence passes the Luhn checksum algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


def is_private_ip(ip_str: str) -> bool:
    """True if ip_str is a valid RFC-1918 private, loopback, or link-local IP."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def is_public_ip(ip_str: str) -> bool:
    """True if ip_str is a valid routable public IP address."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


def validate_search_query_privacy(query: str, state: Any = None) -> tuple[bool, str | None]:
    """
    Validates that an outbound Google Search query does not leak internal corporate
    identities, private infrastructure addresses, or employee PII.

    Args:
        query: The raw query string sent to the search tool.
        state: Optional ADK session state containing verified alert entities.

    Returns:
        tuple[bool, str | None]: (True, None) if query is safe; (False, reason) if blocked.
    """
    if not query or not query.strip():
        return True, None

    cleaned_query = query.strip()
    lowered = cleaned_query.lower()

    # 1. Check against investigated user identity from state
    if state is not None:
        user_id = str(state.get("user_id") or state.get("investigated_user") or "").strip()
        if user_id and len(user_id) >= 3:
            pattern = rf"\b{re.escape(user_id.lower())}\b"
            if re.search(pattern, lowered):
                return False, f"Query contains investigated employee username: '{user_id}'"

        device_id = str(state.get("device_id") or "").strip()
        if device_id and len(device_id) >= 3:
            pattern = rf"\b{re.escape(device_id.lower())}\b"
            if re.search(pattern, lowered):
                return False, f"Query contains investigated corporate device ID: '{device_id}'"

    # 2. Check for generic internal workstation / server patterns
    host_match = INTERNAL_HOST_PATTERN.search(cleaned_query)
    if host_match:
        return False, f"Query contains internal corporate hostname pattern: '{host_match.group(0)}'"

    # 3. Check for internal corporate domain extensions (.internal, .corp, etc.)
    domain_match = INTERNAL_DOMAIN_PATTERN.search(cleaned_query)
    if domain_match:
        return False, f"Query contains internal corporate domain name: '{domain_match.group(0)}'"

    # 4. Check for private RFC-1918 IP addresses (preserve public external IPs)
    for match in IPV4_CANDIDATE_PATTERN.finditer(cleaned_query):
        candidate_ip = match.group(0)
        if is_private_ip(candidate_ip):
            return False, f"Query contains private/internal RFC-1918 IP address: '{candidate_ip}'"

    # 5. Check for email addresses
    email_match = EMAIL_PATTERN.search(cleaned_query)
    if email_match:
        return False, f"Query contains email address: '{email_match.group(0)}'"

    # 6. Check for Social Security Numbers
    ssn_match = SSN_PATTERN.search(cleaned_query)
    if ssn_match:
        return False, "Query contains a Social Security Number pattern"

    # 7. Check for credit card numbers passing Luhn validation
    for card_match in CARD_CANDIDATE_PATTERN.finditer(cleaned_query):
        raw_digits = re.sub(r"[ -]", "", card_match.group(0))
        if _luhn_checksum_valid(raw_digits):
            return False, "Query contains a valid payment card number"

    return True, None


def mask_pii(text: str | None) -> str:
    """
    Redacts personal identifiers and sensitive private infrastructure values from text
    while preserving security threat intelligence indicators (public IPs, hashes,
    command lines, and threat domains).

    Redactions:
    - Email addresses -> [REDACTED_EMAIL]
    - US SSNs -> [REDACTED_SSN]
    - Payment card numbers (Luhn verified) -> [REDACTED_CREDIT_CARD]
    - Phone numbers -> [REDACTED_PHONE]
    - Private RFC-1918 IPs -> [REDACTED_INTERNAL_IP] (Public IPs remain untouched)
    - Secret tokens/passwords -> [REDACTED_SECRET]

    Args:
        text: Arbitrary text (desktop OCR, report prose, telemetry summary).

    Returns:
        Sanitized text with PII replaced by explicit tokens.
    """
    if not text or not isinstance(text, str):
        return text or ""

    sanitized = text

    # 1. Mask explicit secrets, tokens, passwords
    sanitized = SECRET_PATTERN.sub("[REDACTED_SECRET]", sanitized)

    # 2. Mask payment cards with Luhn check
    for match in list(CARD_CANDIDATE_PATTERN.finditer(sanitized)):
        candidate = match.group(0)
        digits = re.sub(r"[ -]", "", candidate)
        # Avoid matching 16-hex characters from hashes by ensuring bounds
        if _luhn_checksum_valid(digits):
            sanitized = sanitized.replace(candidate, "[REDACTED_CREDIT_CARD]")

    # 3. Mask Social Security Numbers
    sanitized = SSN_PATTERN.sub("[REDACTED_SSN]", sanitized)

    # 4. Mask Email Addresses
    sanitized = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", sanitized)

    # 5. Mask Phone Numbers
    sanitized = PHONE_PATTERN.sub("[REDACTED_PHONE]", sanitized)

    # 6. Mask private RFC-1918 IPs (only private; public IPs are strictly preserved)
    for match in list(IPV4_CANDIDATE_PATTERN.finditer(sanitized)):
        ip_candidate = match.group(0)
        if is_private_ip(ip_candidate):
            sanitized = re.sub(
                r"\b" + re.escape(ip_candidate) + r"\b",
                "[REDACTED_INTERNAL_IP]",
                sanitized,
            )

    return sanitized
