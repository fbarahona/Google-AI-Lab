"""
Unit tests for the Pub/Sub push webhook endpoint in adk_agent.fast_api_app.
Verifies payload unwrapping, base64 decoding, and webhook acknowledgement.
"""

import base64
import json
import pytest
from starlette.testclient import TestClient

from adk_agent.fast_api_app import app, extract_pubsub_payload


def test_extract_pubsub_payload_wrapped_base64():
    """Verify that wrapped Pub/Sub messages with base64 data are decoded properly."""
    raw_alert = {
        "user_id": "u.lewis",
        "total_2_min_threat_score": 1850,
        "source_ip": "175.45.178.110"
    }
    b64_data = base64.b64encode(json.dumps(raw_alert).encode("utf-8")).decode("utf-8")
    wrapped_message = {
        "message": {
            "data": b64_data,
            "messageId": "9876543210",
            "publishTime": "2026-10-11T18:00:00Z"
        },
        "subscription": "projects/test-proj/subscriptions/adk_agent_trigger"
    }

    unwrapped = extract_pubsub_payload(wrapped_message)
    assert unwrapped["user_id"] == "u.lewis"
    assert unwrapped["total_2_min_threat_score"] == 1850
    assert unwrapped["source_ip"] == "175.45.178.110"


def test_extract_pubsub_payload_unwrapped_direct():
    """Verify that direct JSON payloads (no_wrapper) pass through directly."""
    direct_alert = {
        "user_id": "l.taylor",
        "total_2_min_threat_score": 120,
        "source_ip": "10.0.4.15"
    }
    unwrapped = extract_pubsub_payload(direct_alert)
    assert unwrapped["user_id"] == "l.taylor"
    assert unwrapped["total_2_min_threat_score"] == 120


def test_extract_pubsub_payload_raw_bytes():
    """Verify handling of raw JSON bytes."""
    payload_bytes = json.dumps({"user_id": "c.wilson"}).encode("utf-8")
    unwrapped = extract_pubsub_payload(payload_bytes)
    assert unwrapped["user_id"] == "c.wilson"


def test_pubsub_push_endpoint_returns_503_when_runner_uninitialized():
    """Verify that uninitialized runner returns 503 so Pub/Sub retries rather than dropping."""
    client = TestClient(app)
    # Ensure runner is None
    app.state.runner = None
    raw_alert = {
        "user_id": "u.lewis",
        "total_2_min_threat_score": 1850
    }
    b64_data = base64.b64encode(json.dumps(raw_alert).encode("utf-8")).decode("utf-8")
    payload = {
        "message": {
            "data": b64_data,
            "messageId": f"msg-test-503-{raw_alert['user_id']}"
        }
    }

    response = client.post("/apps/adk_agent/trigger/pubsub", json=payload)
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "SERVICE_UNAVAILABLE"


def test_pubsub_push_endpoint_deduplication():
    """Verify that duplicate Pub/Sub deliveries are recognized and acknowledged with 200."""
    client = TestClient(app)
    msg_id = "test-pubsub-dedup-12345"
    payload = {
        "message": {
            "data": base64.b64encode(b'{"user_id": "l.taylor"}').decode("utf-8"),
            "messageId": msg_id
        }
    }

    # First call records the key (returns 503 because runner is uninitialized)
    client.post("/apps/adk_agent/trigger/pubsub", json=payload)

    # Second call with identical messageId should be recognized as duplicate and return 200 DUPLICATE_ACK
    res2 = client.post("/apps/adk_agent/trigger/pubsub", json=payload)
    assert res2.status_code == 200
    assert res2.json()["status"] == "DUPLICATE_ACK"


def test_pubsub_push_endpoint_with_mock_runner():
    """Test successful synchronous investigation execution when runner is ready."""
    from unittest.mock import AsyncMock, MagicMock

    mock_runner = MagicMock()
    mock_session = MagicMock()
    mock_session.id = "session-123"
    mock_runner.session_service.get_session = AsyncMock(return_value=mock_session)
    mock_runner.session_service.create_session = AsyncMock(return_value=mock_session)

    mock_event = MagicMock()
    mock_part = MagicMock()
    mock_part.text = "Investigation complete: FALSE_POSITIVE verified."
    mock_event.content.parts = [mock_part]

    async def mock_run_async(*args, **kwargs):
        yield mock_event

    mock_runner.run_async = mock_run_async

    app.state.runner = mock_runner
    app.state.agent_app_name = "adk_agent"
    client = TestClient(app)

    raw_alert = {"user_id": "fresh.user.1", "threat_score": 100}
    b64_data = base64.b64encode(json.dumps(raw_alert).encode("utf-8")).decode("utf-8")
    payload = {
        "message": {
            "data": b64_data,
            "messageId": f"msg-fresh-mock-{raw_alert['user_id']}"
        }
    }

    response = client.post("/apps/adk_agent/trigger/pubsub", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "COMPLETED"
    assert "Investigation complete" in data["output"]
    app.state.runner = None
