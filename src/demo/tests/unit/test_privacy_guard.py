"""
Unit tests for Privacy Guard and PII Sanitization Engine.
"""

from collections.abc import AsyncGenerator
from unittest.mock import MagicMock

import pytest
from google.adk.models import BaseLlm, LlmRequest, LlmResponse
from google.genai import types
from pydantic import Field

import adk_agent.agent  # noqa: F401  (must precede anything that imports httpx)
from adk_agent.privacy_guard import (
    extract_public_ips,
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


class _CaptureLlm(BaseLlm):
    """Records every request the search agent sends to the model; never searches."""

    requests: list[LlmRequest] = Field(default_factory=list)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        self.requests.append(llm_request)
        yield LlmResponse(
            content=types.Content(role="model", parts=[types.Part(text="ok")])
        )


async def _run_search_agent(alert_text: str) -> tuple[list[LlmRequest], str]:
    """Runs the real google_search_agent (real callbacks, real built-in tool)."""
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService

    from adk_agent.agent import google_search_agent

    # A "gemini" model name so the built-in google_search tool attaches as in production.
    model = _CaptureLlm(model="gemini-capture", requests=[])
    saved = google_search_agent.model
    google_search_agent.model = model
    try:
        runner = Runner(
            app_name="privacy",
            agent=google_search_agent,
            session_service=InMemorySessionService(),
            auto_create_session=True,
        )
        final = ""
        async for event in runner.run_async(
            user_id="u",
            session_id="s",
            new_message=types.Content(role="user", parts=[types.Part(text=alert_text)]),
        ):
            if event.content and event.content.parts:
                final = "".join(p.text or "" for p in event.content.parts)
        return model.requests, final
    finally:
        google_search_agent.model = saved


ALERT_WITH_INTERNAL_IDENTITIES = (
    "Investigate incoming continuous security alert: "
    '{"alert_id": "u.lewis|2026-10-16T10:02:00Z", "user_id": "u.lewis", '
    '"device_id": "WS-HR-05", "source_ip": "175.45.176.10", '
    '"internal_host_ip": "10.20.1.15", "contact": "uma.lewis@cymbal.example"}'
)


@pytest.mark.asyncio
async def test_search_model_sees_only_public_ips():
    """The search model never receives the alert's user, device, internal IP or email."""
    requests, _ = await _run_search_agent(ALERT_WITH_INTERNAL_IDENTITIES)

    assert requests, "the search model should be called when a public IP exists"
    for request in requests:
        sent = " ".join(p.text or "" for c in request.contents for p in (c.parts or []))
        assert "175.45.176.10" in sent
        for private in (
            "u.lewis",
            "WS-HR-05",
            "10.20.1.15",
            "uma.lewis@cymbal.example",
        ):
            assert private not in sent, f"{private!r} reached the search model"
        # Search capability is still attached as the Gemini built-in tool.
        assert any(t.google_search for t in request.config.tools)


@pytest.mark.asyncio
async def test_search_skipped_without_public_ip():
    """With only internal addresses, the model is not called and nothing is searched."""
    from adk_agent.agent import NO_PUBLIC_IP_RESULT

    requests, final = await _run_search_agent(
        'Investigate incoming continuous security alert: {"user_id": "u.lewis", '
        '"device_id": "WS-HR-05", "source_ip": "10.20.1.15"}'
    )
    assert requests == []
    assert final == NO_PUBLIC_IP_RESULT


def test_search_query_audit_withholds_results_on_violation():
    """Queries Gemini actually ran are audited; a leaking query withholds the results."""
    from adk_agent.agent import search_query_audit_callback

    ctx = MagicMock()
    ctx.state = {"user_id": "u.lewis", "device_id": "ws-hr-05"}

    leaked = LlmResponse(
        grounding_metadata=types.GroundingMetadata(
            web_search_queries=["175.45.176.10 abuse", "u.lewis cymbal"]
        )
    )
    blocked = search_query_audit_callback(ctx, leaked)
    assert blocked is not None
    assert "withheld" in blocked.content.parts[0].text

    clean = LlmResponse(
        grounding_metadata=types.GroundingMetadata(
            web_search_queries=["175.45.176.10 threat intel"]
        )
    )
    assert search_query_audit_callback(ctx, clean) is None
    assert search_query_audit_callback(ctx, LlmResponse()) is None


def test_extract_public_ips():
    assert extract_public_ips(
        "from 10.0.0.5 to 175.45.176.10 and 8.8.8.8, 8.8.8.8"
    ) == [
        "175.45.176.10",
        "8.8.8.8",
    ]
    assert extract_public_ips(None) == []


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
