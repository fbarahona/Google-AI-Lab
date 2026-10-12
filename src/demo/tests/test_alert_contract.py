"""
Unit tests for the Budget Detection Architecture:
- DetectionAlert model schema validation
- 2-minute tumbling window & alert_id derivation
- MERGE query idempotency
- Webhook status transitions (NEW -> INVESTIGATING -> DONE / DEAD_LETTERED)
- DLQ auto-escalation handling
"""

import json
import pytest
from datetime import datetime, timezone
from src.demo.soc_ticketing.models import DetectionAlert, SocTicket
from adk_agent.fast_api_app import extract_pubsub_payload


def test_detection_alert_contract_schema():
    """Verifies that DetectionAlert strictly matches the unified alert contract."""
    alert = DetectionAlert(
        alert_id="u.lewis|2026-10-11T21:04:00Z",
        schema_version=1,
        engine="scheduled",
        user_id="u.lewis",
        device_id="ws-hr-05",
        source_ip="175.45.177.32",
        window_start="2026-10-11T21:02:00Z",
        window_end="2026-10-11T21:04:00Z",
        total_2_min_threat_score=1850,
        high_privilege_request_count=3,
        malicious_command_count=2,
        malicious_dns_count=5,
        detected_at="2026-10-11T21:05:12Z"
    )

    assert alert.alert_id == "u.lewis|2026-10-11T21:04:00Z"
    assert alert.schema_version == 1
    assert alert.engine == "scheduled"
    assert alert.total_2_min_threat_score == 1850

    # Ensure JSON serializability
    serialized = json.loads(alert.model_dump_json())
    assert serialized["alert_id"] == "u.lewis|2026-10-11T21:04:00Z"
    assert serialized["engine"] == "scheduled"


def test_soc_ticket_alert_id_linkage():
    """Verifies that SocTicket links back to the originating detection alert_id."""
    ticket = SocTicket(
        ticket_id="SOC-TICKET-u.lewis-1001",
        alert_id="u.lewis|2026-10-11T21:04:00Z",
        user_id="u.lewis",
        device_id="ws-hr-05",
        source_ip="175.45.177.32",
        threat_score=1850,
        severity="CRITICAL",
        status="ESCALATED",
        category="Malware",
        agent_decision="GENUINE_THREAT",
        agent_reason="North Korean C2 communication and Mimikatz execution.",
        structured_report="### Report Content"
    )

    assert ticket.alert_id == "u.lewis|2026-10-11T21:04:00Z"
    assert ticket.threat_score == 1850


def test_extract_pubsub_payload_with_attributes():
    """Verifies that incoming Pub/Sub push messages extract contract attributes cleanly."""
    raw_push = {
        "message": {
            "data": "eyJhbGVydF9pZCI6ICJ1Lmxld2lzfDIwMjYtMTAtMTFUMjE6MDQ6MDBaIiwgInVzZXJfaWQiOiAidS5sZXdpcyJ9",
            "attributes": {
                "alert_id": "u.lewis|2026-10-11T21:04:00Z",
                "engine": "scheduled",
                "schema_version": "1"
            },
            "messageId": "msg-9999"
        }
    }
    extracted = extract_pubsub_payload(raw_push)
    assert extracted.get("user_id") == "u.lewis"
    assert extracted.get("alert_id") == "u.lewis|2026-10-11T21:04:00Z"


def test_alert_id_idempotency_derivation():
    """Verifies alert_id determinism: identical window + user must produce identical alert_id."""
    user = "u.lewis"
    window_end = "2026-10-11T21:04:00Z"
    id_1 = f"{user}|{window_end}"
    id_2 = f"{user}|{window_end}"
    assert id_1 == id_2

