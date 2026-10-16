"""
Unit tests for Privacy Guard and PII Sanitization Engine.
"""

from adk_agent.privacy_guard import (
    is_private_ip,
    is_public_ip,
    mask_pii,
    validate_search_query_privacy,
)


def test_ip_classification():
    """Validates private vs public IP differentiation."""
    # Private / internal IPs
    assert is_private_ip("10.0.0.1") is True
    assert is_public_ip("10.0.0.1") is False

    assert is_private_ip("192.168.1.100") is True
    assert is_public_ip("192.168.1.100") is False

    assert is_private_ip("172.16.5.4") is True
    assert is_public_ip("172.16.5.4") is False

    assert is_private_ip("127.0.0.1") is True
    assert is_public_ip("127.0.0.1") is False

    # Routable public IPs (IOCs)
    assert is_private_ip("175.45.176.10") is False
    assert is_public_ip("175.45.176.10") is True

    assert is_private_ip("8.8.8.8") is False
    assert is_public_ip("8.8.8.8") is True

    # Invalid values
    assert is_private_ip("invalid-ip") is False
    assert is_public_ip("invalid-ip") is False


def test_search_query_privacy_permits_clean_threat_queries():
    """Validates that public IPs, malware names, and threat intel terms pass search gate."""
    safe_queries = [
        "175.45.176.10",
        "175.45.176.10 threat intelligence reputation abuse",
        "c2-server.ru malicious domain",
        "mimikatz powershell credential dumping",
        "CVE-2024-3094 xz backdoor",
        "8.8.8.8 dns",
    ]
    for q in safe_queries:
        is_safe, reason = validate_search_query_privacy(q, state=None)
        assert is_safe is True, f"Expected '{q}' to be safe, but blocked: {reason}"
        assert reason is None


def test_search_query_privacy_blocks_investigated_user():
    """Validates that outbound search queries cannot leak the investigated employee ID."""
    state = {"user_id": "u.lewis"}
    is_safe, reason = validate_search_query_privacy(
        "u.lewis 175.45.176.10", state=state
    )
    assert is_safe is False
    assert "u.lewis" in reason


def test_search_query_privacy_blocks_investigated_device():
    """Validates that outbound search queries cannot leak the corporate device ID."""
    state = {"device_id": "ws-hr-05"}
    is_safe, reason = validate_search_query_privacy(
        "check vulnerability for ws-hr-05", state=state
    )
    assert is_safe is False
    assert "ws-hr-05" in reason


def test_search_query_privacy_blocks_private_ips():
    """Validates that outbound search queries cannot leak internal RFC-1918 IPs."""
    for ip in ["10.0.1.5", "192.168.1.1", "172.16.0.100", "127.0.0.1"]:
        is_safe, reason = validate_search_query_privacy(f"whois {ip}", state=None)
        assert is_safe is False, f"Expected {ip} to be blocked"
        assert ip in reason


def test_search_query_privacy_blocks_corporate_host_and_domain():
    """Validates that internal hostnames and domain extensions are blocked."""
    is_safe, reason = validate_search_query_privacy(
        "server srv-finance-01 issues", state=None
    )
    assert is_safe is False
    assert "srv-finance-01" in reason

    is_safe, reason = validate_search_query_privacy("portal.corp network", state=None)
    assert is_safe is False
    assert "portal.corp" in reason


def test_search_query_privacy_blocks_pii():
    """Validates that search queries containing emails, SSNs, or cards are blocked."""
    is_safe, reason = validate_search_query_privacy(
        "search john.doe@example.com", state=None
    )
    assert is_safe is False
    assert "john.doe@example.com" in reason

    is_safe, reason = validate_search_query_privacy("leak 123-45-6789", state=None)
    assert is_safe is False
    assert "Social Security Number" in reason


def test_mask_pii_redacts_sensitive_data():
    """Validates that mask_pii redacts emails, SSNs, phone numbers, and secrets."""
    text = (
        "User report: Contact alice.smith@company.com or bob@test.org. "
        "Employee SSN: 987-65-4321. Phone: +1-555-123-4567. "
        "Internal DB at 10.200.1.5 and 192.168.1.50. "
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tokensecret1234567890."
    )
    masked = mask_pii(text)

    assert "alice.smith@company.com" not in masked
    assert "bob@test.org" not in masked
    assert "[REDACTED_EMAIL]" in masked

    assert "987-65-4321" not in masked
    assert "[REDACTED_SSN]" in masked

    assert "+1-555-123-4567" not in masked
    assert "[REDACTED_PHONE]" in masked

    assert "10.200.1.5" not in masked
    assert "192.168.1.50" not in masked
    assert "[REDACTED_INTERNAL_IP]" in masked

    assert "eyJhbGci" not in masked
    assert "[REDACTED_SECRET]" in masked


def test_mask_pii_preserves_threat_intelligence_iocs():
    """Validates that threat IOCs (public IPs, attack commands, hashes, CVEs) are NOT masked."""
    forensics = (
        "Alert: Outbound connection from host [REDACTED_INTERNAL_IP] to malicious C2 175.45.176.10. "
        "DNS lookup for evil-domain.ru resolved to 8.8.8.8. "
        "Executed: mimikatz.exe sekurlsa::logonpasswords and powershell -enc aW52b2tl. "
        "Payload SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae. "
        "Technique: MITRE T1059.001."
    )
    result = mask_pii(forensics)

    assert "175.45.176.10" in result, "Public IP 175.45.176.10 must be preserved!"
    assert "8.8.8.8" in result, "Public IP 8.8.8.8 must be preserved!"
    assert "evil-domain.ru" in result
    assert "mimikatz.exe" in result
    assert "powershell -enc" in result
    assert "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae" in result
    assert "MITRE T1059.001" in result


def test_google_search_privacy_gate_callback():
    """Validates that google_search_privacy_gate_callback blocks unsafe queries and allows clean public IPs."""
    from unittest.mock import MagicMock

    from adk_agent.agent import google_search_agent, google_search_privacy_gate_callback

    # Ensure before_tool_callback is wired
    assert (
        google_search_agent.before_tool_callback == google_search_privacy_gate_callback
    )

    mock_tool = MagicMock()
    mock_tool.name = "google_search"

    mock_ctx = MagicMock()
    mock_ctx.state = {"user_id": "u.lewis", "device_id": "ws-hr-05"}

    # 1. Unsafe query leaking user_id
    res = google_search_privacy_gate_callback(
        mock_tool, {"query": "u.lewis background"}, mock_ctx
    )
    assert res is not None
    assert res["error"] == "PRIVACY_GATE_VIOLATION"
    assert res["status"] == "BLOCKED"
    assert "u.lewis" in res["reason"]

    # 2. Unsafe query leaking private IP
    res = google_search_privacy_gate_callback(
        mock_tool, {"query": "lookup 10.0.1.5"}, mock_ctx
    )
    assert res is not None
    assert res["error"] == "PRIVACY_GATE_VIOLATION"
    assert "10.0.1.5" in res["reason"]

    # 3. Clean public IP query
    res = google_search_privacy_gate_callback(
        mock_tool, {"query": "175.45.176.10 threat intel"}, mock_ctx
    )
    assert res is None


def test_visual_analysis_masks_desktop_pii(monkeypatch):
    """Validates that get_visual_analysis_for_user redacts desktop OCR PII."""
    from adk_agent.tools import get_visual_analysis_for_user

    # Mock read_png_text_chunks in LOCAL_MODE to return desktop text containing employee PII
    pii_desktop_ocr = (
        "Terminal output: whoami -> u.lewis\n"
        "Browser open: Outlook Web App - user contact hr-helpdesk@company.com, SSN: 111-22-3333.\n"
        "Powershell execution: powershell -enc aW52b2tl mimikatz\n"
        "Connected to external host 175.45.176.10"
    )
    monkeypatch.setenv("LOCAL_MODE", "true")
    monkeypatch.setattr(
        "adk_agent.tools.read_png_text_chunks",
        lambda path: {"forensic_ocr_text": pii_desktop_ocr},
    )
    monkeypatch.setattr("os.path.exists", lambda path: True)

    result = get_visual_analysis_for_user("file:///dummy_screenshot.png")
    analysis = result.get("analysis", "")

    # PII must be redacted
    assert "hr-helpdesk@company.com" not in analysis
    assert "[REDACTED_EMAIL]" in analysis
    assert "111-22-3333" not in analysis
    assert "[REDACTED_SSN]" in analysis

    # Threat telemetry must remain intact
    assert "175.45.176.10" in analysis
    assert "mimikatz" in analysis
    assert "powershell -enc" in analysis
