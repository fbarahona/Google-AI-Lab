"""
Unit tests for security hardening & execution guardrails:
1. SQL injection & destructive query token rejection
2. BigQuery maximum_bytes_billed scan ceiling enforcement
3. Webhook inbound OIDC JWT validation and local mode bypass
"""

import re

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


@pytest.mark.parametrize(
    "token",
    [
        "DROP",
        "ALTER",
        "DELETE",
        "UPDATE",
        "INSERT",
        "TRUNCATE",
        "GRANT",
        "REVOKE",
        "MERGE",
    ],
)
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


def test_validate_safe_sql_query_blocks_information_schema():
    """Verify that queries referencing INFORMATION_SCHEMA are blocked unless allow_metadata=True."""
    metadata_query = "SELECT * FROM `region-us.INFORMATION_SCHEMA.TABLES`;"
    with pytest.raises(
        ValueError, match=re.escape("Access to INFORMATION_SCHEMA is restricted.")
    ):
        validate_safe_sql_query(metadata_query)

    # Test case-insensitivity
    with pytest.raises(
        ValueError, match=re.escape("Access to INFORMATION_SCHEMA is restricted.")
    ):
        validate_safe_sql_query(
            "SELECT table_name FROM my_dataset.information_schema.columns"
        )


def test_validate_safe_sql_query_permits_information_schema_when_authorized():
    """Verify that INFORMATION_SCHEMA queries pass when explicitly authorized for schema introspection."""
    metadata_query = "SELECT * FROM `region-us.INFORMATION_SCHEMA.TABLES`;"
    validate_safe_sql_query(metadata_query, allow_metadata=True)


def test_validate_safe_sql_query_sandboxes_dataset_references():
    """Verify that queries referencing unauthorized tenant datasets are blocked."""
    # Authorized dataset passes
    authorized_query = "SELECT * FROM `my-proj.Cymbal_Cyber.user_access_events`;"
    validate_safe_sql_query(authorized_query, allowed_dataset="Cymbal_Cyber")

    # Bare table passes (resolved via default_dataset)
    bare_query = "SELECT * FROM user_access_events WHERE user_id = 'u.lewis';"
    validate_safe_sql_query(bare_query, allowed_dataset="Cymbal_Cyber")

    # Unauthorized dataset blocked
    unauthorized_query = "SELECT * FROM `other_tenant.financial_records.payroll`;"
    with pytest.raises(ValueError, match="Cross-dataset reference forbidden"):
        validate_safe_sql_query(unauthorized_query, allowed_dataset="Cymbal_Cyber")


# ==============================================================================
# 2. BIGQUERY MAXIMUM_BYTES_BILLED CEILING TESTS
# ==============================================================================


def test_build_event_logs_query_enforces_maximum_bytes_billed():
    """Verify that QueryJobConfig includes maximum_bytes_billed to prevent runaway table scans."""
    _, job_config = build_event_logs_query("user", "u.lewis", "24 HOUR")
    assert job_config.maximum_bytes_billed is not None
    assert job_config.maximum_bytes_billed == DEFAULT_MAX_BYTES_BILLED
    assert job_config.maximum_bytes_billed == 1073741824  # 1 GB ceiling


def test_build_event_logs_query_includes_partition_filter_on_all_ctes():
    """Verify that every CTE (FlaggedSessions, AccessMetrics, NetworkMetrics)
    includes an explicit DATE(event_timestamp) partition filter so scans of
    user_access_events and network_events prune DAY partitions."""
    sql, _ = build_event_logs_query("user", "u.lewis", "24 HOUR")

    # Verify each CTE has its own partition filter
    assert "DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 1 DAY)" in sql

    # Check partition filter count: must appear at least 3 times (FlaggedSessions, AccessMetrics, NetworkMetrics)
    partition_filter_count = sql.count(
        "DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 1 DAY)"
    )
    assert partition_filter_count >= 3


@pytest.mark.parametrize(
    ("window", "expected_days"),
    [
        ("1 HOUR", 1),
        ("2 HOUR", 1),
        ("6 HOUR", 1),
        ("12 HOUR", 1),
        ("24 HOUR", 1),
        ("48 HOUR", 2),
        ("7 DAY", 7),
        ("30 DAY", 30),
    ],
)
def test_build_event_logs_query_partition_days_mapping(window, expected_days):
    """Verify lookback windows map correctly to partition interval days."""
    sql, _ = build_event_logs_query("user", "u.lewis", window)
    expected_clause = f"DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL {expected_days} DAY)"
    assert expected_clause in sql


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
    response = client.post(
        "/apps/adk_agent/trigger/pubsub", json={"message": {}}, headers=headers
    )
    assert response.status_code == 403
    assert "Invalid OIDC bearer token" in response.json()["detail"]


def test_webhook_oidc_accepts_service_uri_audience(monkeypatch):
    """Verify that when EXPECTED_OIDC_AUDIENCE is set to the Cloud Run service URI,
    OIDC token verification validates tokens addressed to the root service URI."""
    from unittest.mock import patch

    monkeypatch.setenv("LOCAL_MODE", "false")
    monkeypatch.setenv("DISABLE_AUTH", "false")
    monkeypatch.setenv(
        "EXPECTED_OIDC_AUDIENCE",
        "https://cymbal-cyber-adk-agent-12345.us-east1.run.app",
    )
    monkeypatch.setenv(
        "EXPECTED_INVOKER_EMAIL", "pubsub-invoker-sa@proj.iam.gserviceaccount.com"
    )

    client = TestClient(app)

    with patch("google.oauth2.id_token.verify_oauth2_token") as mock_verify:
        mock_verify.return_value = {
            "email": "pubsub-invoker-sa@proj.iam.gserviceaccount.com",
            "email_verified": True,
            "aud": "https://cymbal-cyber-adk-agent-12345.us-east1.run.app",
        }
        headers = {"Authorization": "Bearer valid.google.token"}
        response = client.post(
            "/apps/adk_agent/trigger/pubsub", json={"message": {}}, headers=headers
        )
        # Should not be rejected by OIDC auth (401 or 403)
        assert response.status_code not in (401, 403)
        assert mock_verify.called


# ==============================================================================
# 4. CLOUD RUN PORT CONFIGURATION TESTS
# ==============================================================================


def test_cloud_run_port_configuration_default(monkeypatch):
    """Verify that port defaults to 8080 when PORT env var is unset."""
    from adk_agent.fast_api_app import get_app_port

    monkeypatch.delenv("PORT", raising=False)
    assert get_app_port() == 8080


def test_cloud_run_port_configuration_custom(monkeypatch):
    """Verify that custom PORT env var is respected."""
    from adk_agent.fast_api_app import get_app_port

    monkeypatch.setenv("PORT", "9090")
    assert get_app_port() == 9090


# ==============================================================================
# 5. INVESTIGATION AGENT SQL ELIMINATION TESTS
# ==============================================================================


def test_bq_investigation_agent_does_not_have_execute_sql():
    """Verify that bq_investigation_agent does not expose execute_sql,
    enforcing that the LLM cannot write or execute arbitrary SQL queries."""
    from adk_agent.agent import bq_investigation_agent

    tool_names = [
        getattr(t, "__name__", getattr(t, "name", str(t)))
        for t in bq_investigation_agent.tools
    ]
    assert "get_entity_behavioral_profile" in tool_names
    assert "execute_sql" not in tool_names
    assert len(bq_investigation_agent.tools) == 1
