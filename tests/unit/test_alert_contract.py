"""
Unit tests for alert contract schema validation and malformed Pub/Sub payload rejection.
"""

import base64
import json
import pytest
from starlette.testclient import TestClient

from adk_agent.fast_api_app import app, extract_pubsub_payload
from src.demo.soc_ticketing.models import DetectionAlert


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
        detected_at="2026-10-11T21:05:12Z",
    )
    assert alert.alert_id == "u.lewis|2026-10-11T21:04:00Z"
    assert alert.schema_version == 1
    assert alert.total_2_min_threat_score == 1850


def test_extract_pubsub_payload_rejects_non_json_binary_base64():
    """Verify that extract_pubsub_payload raises ValueError on non-JSON binary bytes."""
    corrupt_binary = b"\x00\x01\x02\xff\xfe\x00corrupt-bytes"
    b64_data = base64.b64encode(corrupt_binary).decode("utf-8")
    raw_push = {
        "message": {
            "data": b64_data,
            "messageId": "msg-corrupt-123",
        }
    }
    with pytest.raises(ValueError, match="payload is not valid JSON"):
        extract_pubsub_payload(raw_push)


def test_webhook_rejects_non_json_binary_base64_payload(monkeypatch):
    """Verify that fast_api_app rejects valid base64 non-JSON binary payloads with 400 Bad Request,
    rather than an unhandled 500 Internal Server Error."""
    monkeypatch.setenv("LOCAL_MODE", "true")
    monkeypatch.setenv("DISABLE_AUTH", "true")

    client = TestClient(app)
    corrupt_binary = b"\x00\x01\x02\xff\xfe\x00\xaa\xbb\xcccorrupt-bytes"
    b64_data = base64.b64encode(corrupt_binary).decode("utf-8")
    payload = {
        "message": {
            "data": b64_data,
            "messageId": "msg-corrupt-binary-456",
        }
    }
    response = client.post("/apps/adk_agent/trigger/pubsub", json=payload)
    assert response.status_code == 400
    assert "Bad Request" in response.json().get("detail", "")

