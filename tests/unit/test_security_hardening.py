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
    execute_sql,
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


def test_validate_safe_sql_query_blocks_information_schema():
    """Verify that queries referencing INFORMATION_SCHEMA are blocked unless allow_metadata=True."""
    metadata_query = "SELECT * FROM `region-us.INFORMATION_SCHEMA.TABLES`;"
    with pytest.raises(ValueError, match=re.escape("Access to INFORMATION_SCHEMA is restricted.")):
        validate_safe_sql_query(metadata_query)

    # Test case-insensitivity
    with pytest.raises(ValueError, match=re.escape("Access to INFORMATION_SCHEMA is restricted.")):
        validate_safe_sql_query("SELECT table_name FROM my_dataset.information_schema.columns")


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


def test_execute_sql_security_gate_and_interpolation(monkeypatch):
    """Verify execute_sql enforces INFORMATION_SCHEMA restriction, dataset sandboxing, and injects dataset dynamically."""
    monkeypatch.setenv("LOCAL_MODE", "true")

    # INFORMATION_SCHEMA blocked
    with pytest.raises(ValueError, match=re.escape("Access to INFORMATION_SCHEMA is restricted.")):
        execute_sql("SELECT * FROM INFORMATION_SCHEMA.TABLES;")

    # Cross-dataset blocked
    with pytest.raises(ValueError, match="Cross-dataset reference forbidden"):
        execute_sql("SELECT * FROM `other_project.tenant_x.logs`;")

    # Valid bare table query interpolates dataset and succeeds in local mode
    res = execute_sql("SELECT * FROM user_access_events WHERE user_id = 'u.lewis';")
    assert "LOCAL_SIMULATION_SUCCESS" in res
    assert "Cymbal_Cyber.user_access_events" in res


def test_forbidden_dml_check_blocks_destructive_and_metadata_queries():
    """Verify forbidden_dml_check callback intercepts destructive DML, INFORMATION_SCHEMA, and cross-dataset."""
    from unittest.mock import MagicMock

    from adk_agent.agent import forbidden_dml_check

    mock_tool = MagicMock()
    mock_tool.name = "execute_sql"
    mock_context = MagicMock()

    # Destructive blocked
    res_drop = forbidden_dml_check(mock_tool, {"query": "DROP TABLE soc_tickets;"}, mock_context)
    assert res_drop is not None
    assert "Tool execution was blocked" in res_drop["result"]

    # INFORMATION_SCHEMA blocked
    res_meta = forbidden_dml_check(mock_tool, {"query": "SELECT * FROM INFORMATION_SCHEMA.TABLES;"}, mock_context)
    assert res_meta is not None
    assert "Access to INFORMATION_SCHEMA is restricted" in res_meta["result"]

    # Cross-dataset blocked
    res_cross = forbidden_dml_check(mock_tool, {"query": "SELECT * FROM `other_tenant.secret.tbl`;"}, mock_context)
    assert res_cross is not None
    assert "Cross-dataset reference forbidden" in res_cross["result"]


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
    includes an explicit DATE(event_timestamp) partition filter satisfying
    require_partition_filter = true on user_access_events and network_events."""
    sql, _ = build_event_logs_query("user", "u.lewis", "24 HOUR")

    # Verify each CTE has its own partition filter
    assert "DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 1 DAY)" in sql

    # Check partition filter count: must appear at least 3 times (FlaggedSessions, AccessMetrics, NetworkMetrics)
    partition_filter_count = sql.count("DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 1 DAY)")
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
    response = client.post("/apps/adk_agent/trigger/pubsub", json={"message": {}}, headers=headers)
    assert response.status_code == 403
    assert "Invalid OIDC bearer token" in response.json()["detail"]
