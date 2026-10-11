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


def test_pubsub_push_endpoint_wrapped():
    """Test POST to /apps/adk_agent/trigger/pubsub with wrapped Pub/Sub message."""
    client = TestClient(app)
    raw_alert = {
        "user_id": "u.lewis",
        "total_2_min_threat_score": 1850
    }
    b64_data = base64.b64encode(json.dumps(raw_alert).encode("utf-8")).decode("utf-8")
    payload = {
        "message": {
            "data": b64_data,
            "messageId": "12345"
        }
    }

    response = client.post("/apps/adk_agent/trigger/pubsub", json=payload)
    assert response.status_code in [200, 202]
    data = response.json()
    assert data["status"] in ["ACK", "ACCEPTED"]
    assert "session_id" in data


def test_pubsub_push_endpoint_alias():
    """Test POST to /trigger/pubsub convenience alias route."""
    client = TestClient(app)
    direct_payload = {
        "user_id": "l.taylor",
        "total_2_min_threat_score": 120
    }

    response = client.post("/trigger/pubsub", json=direct_payload)
    assert response.status_code in [200, 202]
    data = response.json()
    assert data["status"] in ["ACK", "ACCEPTED"]
