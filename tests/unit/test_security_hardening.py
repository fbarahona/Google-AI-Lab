"""
Unit tests for security hardening & execution guardrails:
1. SQL injection & destructive query token rejection
2. BigQuery maximum_bytes_billed scan ceiling enforcement
3. Webhook inbound OIDC JWT validation and local mode bypass
"""

import pytest
from starlette.testclient import TestClient

from adk_agent.fast_api_app import app
from adk_agent.tools import (
    DEFAULT_MAX_BYTES_BILLED,
    build_event_logs_query,
    validate_safe_sql_query,
)

# ==============================================================================
# 1. SQL DESTRUCTIVE TOKEN GUARDRAIL TESTS
# ==============================================================================

def test_validate_safe_sql_query_permits_read_only_sql():
    """Verify that read-only SELECT queries pass validation."""
    safe_query = "SELECT user_id, event_timestamp FROM `proj.dataset.user_access_events` WHERE user_id = @user_id;"
    # Should not raise exception
    validate_safe_sql_query(safe_query)


@pytest.mark.parametrize("token", ["DROP", "ALTER", "DELETE", "UPDATE", "INSERT", "TRUNCATE", "GRANT", "REVOKE", "MERGE"])
def test_validate_safe_sql_query_blocks_destructive_tokens(token):
    """Verify that every destructive SQL keyword is intercepted and rejected."""
    malicious_query = f"{token} TABLE `proj.dataset.soc_tickets`;"
    with pytest.raises(ValueError, match="Destructive SQL operation"):
        validate_safe_sql_query(malicious_query)


def test_validate_safe_sql_query_blocks_embedded_destructive_tokens():
    """Verify that destructive operations embedded in CTE or subqueries are blocked."""
    embedded_query = "SELECT * FROM users; DROP TABLE soc_tickets; --"
    with pytest.raises(ValueError, match="Destructive SQL operation"):
        validate_safe_sql_query(embedded_query)


# ==============================================================================
# 2. BIGQUERY MAXIMUM_BYTES_BILLED CEILING TESTS
# ==============================================================================

def test_build_event_logs_query_enforces_maximum_bytes_billed():
    """Verify that QueryJobConfig includes maximum_bytes_billed to prevent runaway table scans."""
    _, job_config = build_event_logs_query("user", "u.lewis", "24 HOUR")
    assert job_config.maximum_bytes_billed is not None
    assert job_config.maximum_bytes_billed == DEFAULT_MAX_BYTES_BILLED
    assert job_config.maximum_bytes_billed == 1073741824  # 1 GB ceiling


# ==============================================================================
# 3. WEBHOOK INBOUND OIDC JWT VALIDATION TESTS
# ==============================================================================

def test_webhook_oidc_bypasses_in_local_mode(monkeypatch):
    """Verify that in LOCAL_MODE=true, requests pass without requiring Google OIDC tokens."""
    monkeypatch.setenv("LOCAL_MODE", "true")
    client = TestClient(app)

    # Calling scan endpoint in local mode should not return 401/403
    response = client.post("/apps/adk_agent/trigger/scan")
    assert response.status_code != 401
    assert response.status_code != 403


def test_webhook_oidc_rejects_missing_auth_header_in_cloud_mode(monkeypatch):
    """Verify that in non-local mode, requests lacking Authorization header are rejected with 401."""
    monkeypatch.setenv("LOCAL_MODE", "false")
    monkeypatch.setenv("DISABLE_AUTH", "false")
    client = TestClient(app)

    response = client.post("/apps/adk_agent/trigger/pubsub", json={"message": {}})
    assert response.status_code == 401
    assert "Authorization header" in response.json()["detail"]


def test_webhook_oidc_rejects_invalid_bearer_token_in_cloud_mode(monkeypatch):
    """Verify that in non-local mode, forged or invalid bearer tokens are rejected with 403."""
    monkeypatch.setenv("LOCAL_MODE", "false")
    monkeypatch.setenv("DISABLE_AUTH", "false")
    client = TestClient(app)

    headers = {"Authorization": "Bearer invalid.forged.jwt"}
    response = client.post("/apps/adk_agent/trigger/pubsub", json={"message": {}}, headers=headers)
    assert response.status_code == 403
    assert "Invalid OIDC bearer token" in response.json()["detail"]
