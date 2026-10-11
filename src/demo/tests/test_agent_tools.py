"""
Unit tests for ADK Agent tools, safety callbacks, SQL parameterization, and signed URL generation.
"""
import os
import time
from unittest.mock import MagicMock, patch

import pytest
from google.adk.sessions.state import State

from adk_agent.agent import default_deny_soc_callback, forbidden_dml_check, security_gate_callback
from adk_agent.tools import (
    _parse_alert_payload_to_row,
    build_event_logs_query,
    create_rich_ticket_id,
    escalate_to_human,
    generate_signed_url,
    get_entity_behavioral_profile,
    get_gcs_uri_for_user,
    get_visual_analysis_for_user,
    read_png_text_chunks,
    sanitize_entity_value,
)


def test_get_entity_behavioral_profile():
    """Verify that get_entity_behavioral_profile validates inputs and blocks injection."""
    with patch.dict("os.environ", {"LOCAL_MODE": "true"}):
        with pytest.raises(ValueError, match=r"SQL Injection|invalid|illegal"):
            get_entity_behavioral_profile("user", "u.lewis' OR '1'='1")

        with pytest.raises(ValueError, match=r"Invalid entity_type"):
            get_entity_behavioral_profile("hacker_type", "u.lewis")

        profile = get_entity_behavioral_profile("user", "u.lewis")
        assert "total_access_events_24h" in profile
        assert "total_login_failures_24h" in profile
        assert "risky_file_transfers_24h" in profile


@patch("adk_agent.tools.get_bq_client")
def test_get_entity_behavioral_profile_cloud_mode_success(mock_get_bq):
    """Verify that in cloud mode, query results are properly converted to metrics dict."""
    mock_bq = MagicMock()
    mock_row = MagicMock()
    mock_row.items.return_value = [("total_access_events_24h", 50), ("total_login_failures_24h", 12)]
    mock_job = MagicMock()
    mock_job.result.return_value = [mock_row]
    mock_bq.query.return_value = mock_job
    mock_get_bq.return_value = mock_bq

    with patch.dict("os.environ", {"LOCAL_MODE": "false"}):
        res = get_entity_behavioral_profile("user", "u.lewis")
        assert res["total_access_events_24h"] == 50
        assert res["total_login_failures_24h"] == 12


def test_build_event_logs_query():
    sql, job_config = build_event_logs_query("user", "u.lewis")
    # Verify SQL query uses parameterized @entity_id and does NOT interpolate user value
    assert "user_id = @entity_id" in sql
    assert "u.lewis" not in sql
    assert "AccessMetrics" in sql
    assert "NetworkMetrics" in sql
    assert "INTERVAL 24 HOUR" in sql

    # Verify query job configuration
    assert job_config is not None
    assert len(job_config.query_parameters) == 1
    param = job_config.query_parameters[0]
    assert param.name == "entity_id"
    assert param.type_ == "STRING"
    assert param.value == "u.lewis"


def test_build_event_logs_query_entity_types():
    """Verify that different valid entity types generate appropriate parameterized filters and windows."""
    user_sql, user_cfg = build_event_logs_query("user", "u.lewis", "12 HOUR")
    assert "user_id = @entity_id" in user_sql
    assert "INTERVAL 12 HOUR" in user_sql
    assert user_cfg.query_parameters[0].value == "u.lewis"

    device_sql, dev_cfg = build_event_logs_query("device", "ws-hr-05", "24 HOUR")
    assert "device_id = @entity_id" in device_sql
    assert dev_cfg.query_parameters[0].value == "ws-hr-05"

    ip_sql, ip_cfg = build_event_logs_query("ip", "198.51.100.23", "6 HOUR")
    assert "source_ip = @entity_id" in ip_sql
    assert ip_cfg.query_parameters[0].value == "198.51.100.23"


def test_query_structure_invariance_against_hostile_input():
    """Verify that hostile input cannot alter SQL structure and query configuration binds parameters safely."""
    # 1. Hostile inputs containing SQL injection syntax are blocked at validation
    hostile_payloads = [
        "u.lewis' OR '1'='1",
        "u.lewis' OR 1=1 --",
        "admin'; DROP TABLE Cymbal_Cyber.network_events; --",
        "u.lewis' UNION SELECT 1, 2, 3 --",
        "admin' /* comment */",
        "u.lewis'; DELETE FROM user_access_events; --",
        "attacker' OR 'x'='x",
        "admin' EXEC sp_executesql --",
        "test' AND (SELECT COUNT(*) FROM users) > 0 --",
        "user\nOR 1=1",
        "user'--",
        "'; TRUNCATE TABLE soc_tickets; --",
    ]

    for hostile in hostile_payloads:
        with pytest.raises(ValueError, match=r"SQL Injection|invalid|illegal"):
            build_event_logs_query("user", hostile)

    # 2. Legitimate entities with complex allowed characters are bound strictly via parameter,
    # ensuring query text structure remains invariant and free from interpolation.
    legit_entities = ["j.doe@example.com", "ws-dev:01", "svc_backup-01.corp"]
    for entity in legit_entities:
        sql, config = build_event_logs_query("user", entity)
        assert entity not in sql
        assert "user_id = @entity_id" in sql
        assert config.query_parameters[0].name == "entity_id"
        assert config.query_parameters[0].value == entity


def test_invalid_entity_type_and_window_rejected():
    """Verify that invalid entity types or time windows raise ValueError."""
    with pytest.raises(ValueError, match=r"Invalid entity_type"):
        build_event_logs_query("malicious_type; DROP TABLE", "u.lewis")

    with pytest.raises(ValueError, match=r"Invalid window"):
        build_event_logs_query("user", "u.lewis", "24 HOUR; DROP TABLE")


def test_sanitize_entity_value_valid_inputs():
    """Verify that legitimate enterprise usernames, device IDs, and IPs are accepted."""
    assert sanitize_entity_value("u.lewis") == "u.lewis"
    assert sanitize_entity_value("ws-hr-05") == "ws-hr-05"
    assert sanitize_entity_value("175.45.176.10") == "175.45.176.10"
    assert sanitize_entity_value("svc_backup") == "svc_backup"
    assert sanitize_entity_value("admin") == "admin"
    assert sanitize_entity_value("j.doe@example.com") == "j.doe@example.com"


def test_create_rich_ticket_id():
    t1 = create_rich_ticket_id("u.lewis")
    assert t1.startswith("SOC-TICKET-u.lewis-")

    # JSON sanitization test
    bad_json = '{"user": "attacker"}'
    t2 = create_rich_ticket_id(bad_json)
    assert not t2.startswith('{"')


def test_parse_alert_payload_to_row():
    payload = '{"user_id": "u.lewis", "device_id": "ws-hr-05", "source_ip": "175.45.177.32", "total_2_min_threat_score": 500}'
    row = _parse_alert_payload_to_row(payload)
    assert row["user_id"] == "u.lewis"
    assert row["device_id"] == "ws-hr-05"
    assert row["source_ip"] == "175.45.177.32"
    assert row["total_2_min_threat_score"] == 500


def test_forbidden_dml_check():
    mock_tool = MagicMock()
    mock_tool.name = "execute_sql"
    mock_context = MagicMock()

    # Block DELETE
    result = forbidden_dml_check(mock_tool, {"query": "DELETE FROM Cymbal_Cyber.network_events WHERE 1=1"}, mock_context)
    assert result is not None
    assert "blocked" in result["result"].lower()

    # Block DROP
    result_drop = forbidden_dml_check(mock_tool, {"query": "DROP TABLE Cymbal_Cyber.network_events"}, mock_context)
    assert result_drop is not None

    # Block INSERT
    result_insert = forbidden_dml_check(mock_tool, {"query": "INSERT INTO Cymbal_Cyber.soc_tickets VALUES (1)"}, mock_context)
    assert result_insert is not None

    # Allow SELECT
    result_select = forbidden_dml_check(mock_tool, {"query": "SELECT * FROM Cymbal_Cyber.network_events LIMIT 10"}, mock_context)
    assert result_select is None


def test_generate_signed_url_invalid_uri():
    """Verify that generate_signed_url returns explicit error on invalid GCS URI."""
    err1 = generate_signed_url("")
    assert err1.startswith("Error:")
    assert "Invalid GCS URI" in err1
    assert not err1.startswith("https://")

    err2 = generate_signed_url("https://storage.googleapis.com/bucket/screenshot.png")
    assert err2.startswith("Error:")
    assert "Invalid GCS URI" in err2
    assert "https://storage.cloud.google.com" not in err2


@patch("adk_agent.tools.storage.Client")
@patch("adk_agent.tools.google.auth.default")
def test_generate_signed_url_failure_returns_explicit_error(mock_auth_default, mock_storage_client_cls):
    """Verify that a signing failure produces an explicit error, never a misleading success URL."""
    mock_auth_default.side_effect = Exception("Credentials unavailable in environment")

    # When credential retrieval fails and storage client raises error during signing
    mock_client = MagicMock()
    mock_blob = MagicMock()
    mock_blob.generate_signed_url.side_effect = Exception("IAM permission denied: ServiceAccountTokenCreator missing")
    mock_client.bucket.return_value.blob.return_value = mock_blob
    mock_storage_client_cls.return_value = mock_client

    result = generate_signed_url("gs://cymbal-cyber-screenshots/u.lewis.png")

    # Must be an explicit failure
    assert result.startswith("Error: Failed to generate signed URL:")
    # Must NEVER produce a misleading success result or public console URL
    assert "https://storage.cloud.google.com" not in result
    assert not result.startswith("https://")


@patch("adk_agent.tools.storage.Client")
@patch("adk_agent.tools.google.auth.default")
def test_generate_signed_url_success(mock_auth_default, mock_storage_client_cls):
    """Verify that a successful signing operation returns the signed URL."""
    mock_auth_default.return_value = (MagicMock(), "project-id")
    mock_client = MagicMock()
    mock_blob = MagicMock()
    expected_signed_url = "https://storage.googleapis.com/cymbal-cyber-screenshots/u.lewis.png?X-Goog-Signature=abcd123"
    mock_blob.generate_signed_url.return_value = expected_signed_url
    mock_client.bucket.return_value.blob.return_value = mock_blob
    mock_storage_client_cls.return_value = mock_client

    result = generate_signed_url("gs://cymbal-cyber-screenshots/u.lewis.png")
    assert result == expected_signed_url


def test_security_gate_blocks_false_positive_on_injection():
    """Verify that security gate deterministically blocks log_false_positive with real ADK State object."""
    mock_tool = MagicMock()
    mock_tool.name = "log_false_positive"
    mock_context = MagicMock()
    # Real ADK State object (not a dict subclass!)
    state_obj = State({}, {})
    state_obj["prompt_injection_detected"] = True
    mock_context.state = state_obj

    res = security_gate_callback(mock_tool, {}, mock_context)
    assert res is not None
    assert res["status"] == "BLOCKED"
    assert "SECURITY_GATE_VIOLATION" in res["error"]
    assert "prompt injection" in res["reason"]


def test_security_gate_blocks_false_positive_on_malicious_telemetry():
    """Verify that security gate blocks log_false_positive when high-risk behavioral indicators are present."""
    mock_tool = MagicMock()
    mock_tool.name = "log_false_positive"
    mock_context = MagicMock()
    state_obj = State({}, {})
    state_obj["malicious_indicators"] = True
    mock_context.state = state_obj

    res = security_gate_callback(mock_tool, {}, mock_context)
    assert res is not None
    assert res["status"] == "BLOCKED"
    assert "SECURITY_GATE_VIOLATION" in res["error"]
    assert "anomalous behavioral" in res["reason"]


def test_security_gate_blocks_false_positive_on_evidence_unavailable():
    """Verify that security gate blocks log_false_positive when forensic evidence was unavailable."""
    mock_tool = MagicMock()
    mock_tool.name = "log_false_positive"
    mock_context = MagicMock()
    state_obj = State({}, {})
    state_obj["evidence_unavailable"] = True
    mock_context.state = state_obj

    res = security_gate_callback(mock_tool, {}, mock_context)
    assert res is not None
    assert res["status"] == "BLOCKED"
    assert "evidence" in res["reason"].lower()


def test_security_gate_permits_clean_false_positive():
    """Verify that security gate permits log_false_positive when neither risk flag is set."""
    mock_tool = MagicMock()
    mock_tool.name = "log_false_positive"
    mock_context = MagicMock()
    mock_context.state = State({}, {})

    res = security_gate_callback(mock_tool, {}, mock_context)
    assert res is None


def test_security_gate_permits_incident_dispatch():
    """Verify that other tools (e.g. ticket dispatch) are never blocked by the security gate."""
    mock_tool = MagicMock()
    mock_tool.name = "dispatch_to_soc_ticketing_system"
    mock_context = MagicMock()
    state_obj = State({}, {})
    state_obj["prompt_injection_detected"] = True
    state_obj["malicious_indicators"] = True
    mock_context.state = state_obj

    res = security_gate_callback(mock_tool, {}, mock_context)
    assert res is None


def test_default_deny_callback_escalates_when_unresolved():
    """Verify that default_deny_soc_callback escalates high-risk alerts if no ticket was dispatched."""
    callback_ctx = MagicMock()
    state_obj = State({}, {})
    state_obj["prompt_injection_detected"] = True
    state_obj["user_id"] = "c.wilson"
    state_obj["threat_score"] = 1850
    callback_ctx.state = state_obj

    default_deny_soc_callback(callback_ctx)
    assert state_obj.get("escalation_dispatched") is True


@patch("adk_agent.tools.get_bq_client")
def test_get_entity_behavioral_profile_cloud_mode_fails_closed(mock_get_bq):
    """Verify that in cloud mode (LOCAL_MODE=false), BigQuery failure returns ERROR and sets evidence_unavailable."""
    mock_get_bq.side_effect = Exception("BigQuery 403 Forbidden: Missing roles/bigquery.user")
    mock_ctx = MagicMock()
    mock_ctx.state = State({}, {})

    with patch.dict("os.environ", {"LOCAL_MODE": "false"}):
        res = get_entity_behavioral_profile("user", "u.lewis", tool_context=mock_ctx)
        assert res["status"] == "ERROR"
        assert "BigQuery telemetry query failed" in res["error"]
        assert mock_ctx.state.get("evidence_unavailable") is True


def test_get_entity_behavioral_profile_local_mode_schema_parity():
    """Verify that local mode computes metrics without schema drift (no extra risk_profile field)."""
    with patch.dict("os.environ", {"LOCAL_MODE": "true"}):
        mock_ctx = MagicMock()
        mock_ctx.state = State({}, {})
        profile = get_entity_behavioral_profile("user", "u.lewis", tool_context=mock_ctx)
        assert "total_access_events_24h" in profile
        assert "risk_profile" not in profile  # Exact parity with BigQuery query columns


def test_read_png_text_chunks_and_injection_detection():
    """Verify that read_png_text_chunks extracts embedded OCR text and triggers prompt injection flag in State."""
    chunks = read_png_text_chunks("src/demo/user_screenshots/c.wilson.png")
    assert "forensic_ocr_text" in chunks
    assert "AUTHORIZED RED TEAM PENTEST" in chunks["forensic_ocr_text"]

    mock_ctx = MagicMock()
    mock_ctx.state = State({}, {})
    vis = get_visual_analysis_for_user("file://c.wilson.png", tool_context=mock_ctx)
    assert "PROMPT INJECTION DETECTED" in vis
    assert mock_ctx.state.get("prompt_injection_detected") is True


def test_escalate_to_human_non_blocking():
    """Verify that escalate_to_human dispatches immediately without blocking sleep loops."""
    test_ticket_id = "SOC-TEST-FAST-1"
    mock_service = MagicMock()
    mock_service.create_and_dispatch_ticket.return_value = "Ticket dispatched to queue"

    with patch("adk_agent.tools.get_soc_service", return_value=mock_service):
        start = time.time()
        payload = '{"user_id": "u.lewis", "total_2_min_threat_score": 1500}'
        mock_ctx = MagicMock()
        mock_ctx.state = State({}, {})
        res = escalate_to_human(test_ticket_id, payload, "Escalating for review", "Report text", tool_context=mock_ctx)
        elapsed = time.time() - start

        assert elapsed < 0.2  # Runs in under a second (never blocks for 180s)
        assert "ESCALATED_PENDING_REVIEW" in res
        assert test_ticket_id in res
        assert mock_ctx.state.get("escalation_dispatched") is True
        assert mock_service.create_and_dispatch_ticket.called

    # Clean up test artifact if created
    test_file = f"./local_demo_data/escalations/human_escalation_information_{test_ticket_id}.json"
    if os.path.exists(test_file):
        os.remove(test_file)
