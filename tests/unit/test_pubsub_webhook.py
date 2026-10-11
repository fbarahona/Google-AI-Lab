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


def test_pubsub_push_endpoint_returns_503_and_allows_retry_when_runner_uninitialized():
    """Verify that uninitialized runner returns 503 and does NOT record dedup, so retries are NOT dropped."""
    client = TestClient(app)
    app.state.runner = None
    msg_id = "msg-retry-test-503"
    payload = {
        "message": {
            "data": base64.b64encode(b'{"user_id": "u.lewis"}').decode("utf-8"),
            "messageId": msg_id
        }
    }

    # First attempt: returns 503
    r1 = client.post("/apps/adk_agent/trigger/pubsub", json=payload)
    assert r1.status_code == 503
    assert r1.json()["status"] == "SERVICE_UNAVAILABLE"

    # Pub/Sub retries with the exact same messageId: MUST NOT return DUPLICATE_ACK (200), must still return 503!
    r2 = client.post("/apps/adk_agent/trigger/pubsub", json=payload)
    assert r2.status_code == 503
    assert r2.json()["status"] == "SERVICE_UNAVAILABLE"


def test_pubsub_push_endpoint_deduplication_after_success():
    """Verify that duplicate Pub/Sub deliveries are recognized and acknowledged with 200 ONLY after a successful run."""
    from unittest.mock import AsyncMock, MagicMock

    mock_runner = MagicMock()
    mock_session = MagicMock()
    mock_session.id = "session-test"
    mock_runner.session_service.get_session = AsyncMock(return_value=mock_session)
    mock_runner.session_service.create_session = AsyncMock(return_value=mock_session)

    mock_event = MagicMock()
    mock_part = MagicMock()
    mock_part.text = "Investigation complete."
    mock_event.content.parts = [mock_part]

    async def mock_run_async(*args, **kwargs):
        yield mock_event

    mock_runner.run_async = mock_run_async
    app.state.runner = mock_runner
    app.state.agent_app_name = "adk_agent"
    client = TestClient(app)

    msg_id = "test-pubsub-dedup-success-999"
    payload = {
        "message": {
            "data": base64.b64encode(b'{"user_id": "l.taylor"}').decode("utf-8"),
            "messageId": msg_id
        }
    }

    # First attempt: succeeds (200 COMPLETED)
    r1 = client.post("/apps/adk_agent/trigger/pubsub", json=payload)
    assert r1.status_code == 200
    assert r1.json()["status"] == "COMPLETED"

    # Second delivery (at-least-once retry of already-completed message): returns 200 DUPLICATE_ACK
    r2 = client.post("/apps/adk_agent/trigger/pubsub", json=payload)
    assert r2.status_code == 200
    assert r2.json()["status"] == "DUPLICATE_ACK"
    app.state.runner = None


def test_pubsub_push_endpoint_failure_allows_retry():
    """Verify that when an investigation raises an error (500), retries are NOT dropped by dedup."""
    from unittest.mock import AsyncMock, MagicMock

    mock_runner = MagicMock()
    mock_session = MagicMock()
    mock_runner.session_service.get_session = AsyncMock(return_value=mock_session)
    mock_runner.session_service.create_session = AsyncMock(return_value=mock_session)

    # Runner that raises an exception
    async def mock_failing_run(*args, **kwargs):
        raise RuntimeError("Transient network timeout connecting to BigQuery")
        yield None

    mock_runner.run_async = mock_failing_run
    app.state.runner = mock_runner
    app.state.agent_app_name = "adk_agent"
    client = TestClient(app)

    msg_id = "test-failing-msg-500"
    payload = {
        "message": {
            "data": base64.b64encode(b'{"user_id": "u.lewis"}').decode("utf-8"),
            "messageId": msg_id
        }
    }

    # First attempt fails with 500
    r1 = client.post("/apps/adk_agent/trigger/pubsub", json=payload)
    assert r1.status_code == 500

    # Pub/Sub retries: MUST NOT be swallowed by DUPLICATE_ACK (200), must attempt run again!
    r2 = client.post("/apps/adk_agent/trigger/pubsub", json=payload)
    assert r2.status_code == 500
    app.state.runner = None


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


def test_scheduled_scan_endpoint():
    """Test POST to /apps/adk_agent/trigger/scan endpoint."""
    client = TestClient(app)
    response = client.post("/apps/adk_agent/trigger/scan")
    assert response.status_code in [200, 500]
    data = response.json()
    assert "status" in data
