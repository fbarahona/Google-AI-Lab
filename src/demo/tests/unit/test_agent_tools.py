"""
Unit tests for ADK Agent tools, safety callbacks, SQL parameterization, and signed URL generation.
"""

import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from google.adk.sessions.state import State

from adk_agent.agent import (
    before_orchestrator_starts,
    default_deny_soc_callback,
    forbidden_dml_check,
    security_gate_callback,
)
from adk_agent.tools import (
    _parse_alert_payload_to_row,
    alert_id_from_payload,
    build_event_logs_query,
    create_rich_ticket_id,
    escalate_to_human,
    generate_signed_url,
    get_entity_behavioral_profile,
    get_visual_analysis_for_user,
    log_false_positive,
    normalize_severity,
    read_png_text_chunks,
    sanitize_entity_value,
    ticket_id_for_alert,
)
from src.demo.soc_ticketing.models import AUTO_CLOSED_FP_DECISION
from src.demo.soc_ticketing.ticketing_service import SocTicketingService

C_WILSON_PNG = (
    Path(__file__).resolve().parents[4]
    / "local_demo_data"
    / "user_screenshots"
    / "c.wilson.png"
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
    mock_row.items.return_value = [
        ("total_access_events_24h", 50),
        ("total_login_failures_24h", 12),
    ]
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
    result = forbidden_dml_check(
        mock_tool,
        {"query": "DELETE FROM Cymbal_Cyber.network_events WHERE 1=1"},
        mock_context,
    )
    assert result is not None
    assert "blocked" in result["result"].lower()

    # Block DROP
    result_drop = forbidden_dml_check(
        mock_tool, {"query": "DROP TABLE Cymbal_Cyber.network_events"}, mock_context
    )
    assert result_drop is not None

    # Block INSERT
    result_insert = forbidden_dml_check(
        mock_tool,
        {"query": "INSERT INTO Cymbal_Cyber.soc_tickets VALUES (1)"},
        mock_context,
    )
    assert result_insert is not None

    # Allow SELECT
    result_select = forbidden_dml_check(
        mock_tool,
        {"query": "SELECT * FROM Cymbal_Cyber.network_events LIMIT 10"},
        mock_context,
    )
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
def test_generate_signed_url_failure_returns_explicit_error(
    mock_auth_default, mock_storage_client_cls
):
    """Verify that a signing failure produces an explicit error, never a misleading success URL."""
    mock_auth_default.side_effect = Exception("Credentials unavailable in environment")

    # When credential retrieval fails and storage client raises error during signing
    mock_client = MagicMock()
    mock_blob = MagicMock()
    mock_blob.generate_signed_url.side_effect = Exception(
        "IAM permission denied: ServiceAccountTokenCreator missing"
    )
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
    """Verify that security gate permits log_false_positive when all evidence was gathered and no risk flag is set."""
    mock_tool = MagicMock()
    mock_tool.name = "log_false_positive"
    mock_context = MagicMock()
    mock_context.state = State(
        {"telemetry_evidence_collected": True, "visual_evidence_collected": True}, {}
    )

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


def _cloud_soc_service(insert_errors):
    """A cloud-mode ticketing service whose BigQuery client returns insert_errors."""
    service = SocTicketingService(project_id="test-project", dataset_id="Test_Dataset")
    service._bq_client = MagicMock()
    service._bq_client.insert_rows_json.return_value = insert_errors
    service._storage_client = MagicMock()
    return service


def test_log_false_positive_failed_write_does_not_set_flag(tmp_path, monkeypatch):
    """Verify that a failed BigQuery write does not count as resolved and sets evidence_unavailable."""
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODE", "false")
    service = _cloud_soc_service([{"error": "Quota exceeded"}])

    mock_ctx = MagicMock()
    mock_ctx.state = State({}, {})
    payload = '{"user_id": "l.taylor", "total_2_min_threat_score": 120}'
    with patch("adk_agent.tools.get_soc_service", return_value=service):
        res = log_false_positive(payload, "Benign admin noise", tool_context=mock_ctx)

    assert "Failed to log false positive" in res
    assert mock_ctx.state.get("false_positive_logged") is not True
    assert mock_ctx.state.get("evidence_unavailable") is True


def test_log_false_positive_archives_auto_closed_ticket(tmp_path, monkeypatch):
    """A successful closure sets the flag and archives a RESOLVED ticket marked as auto-closed."""
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODE", "false")
    service = _cloud_soc_service([])

    mock_ctx = MagicMock()
    mock_ctx.state = State({}, {})
    payload = '{"user_id": "l.taylor", "total_2_min_threat_score": 120}'
    with patch("adk_agent.tools.get_soc_service", return_value=service):
        res = log_false_positive(
            payload,
            "Benign admin noise",
            ticket_id="SOC-TICKET-l.taylor-abc",
            tool_context=mock_ctx,
        )

    assert "Successfully logged alert as a False Positive" in res
    assert mock_ctx.state.get("false_positive_logged") is True
    rows = {
        c.args[0].rsplit(".", 1)[-1]: c.args[1][0]
        for c in service._bq_client.insert_rows_json.call_args_list
    }
    assert rows["soc_tickets"]["ticket_id"] == "SOC-TICKET-l.taylor-abc"
    assert rows["soc_tickets"]["status"] == "RESOLVED"
    assert rows["soc_tickets"]["agent_decision"] == AUTO_CLOSED_FP_DECISION
    assert not rows["soc_tickets"].get("human_decision")
    assert rows["adk_threat_assessment"]["agent_decision"] == "FALSE_POSITIVE"


def test_before_orchestrator_starts_resets_flags_and_seeds_state():
    """Verify that before_orchestrator_starts resets invocation flags, clears prior identities, and seeds new state."""
    callback_ctx = MagicMock()
    # Leftover flags and old alert identity from a prior invocation in the same session
    state_obj = State(
        {
            "user_id": "prior_user_from_alert_1",
            "device_id": "ws-old-01",
            "source_ip": "1.1.1.1",
            "threat_score": 9999,
            "prompt_injection_detected": True,
            "ticket_dispatched": True,
            "malicious_indicators": True,
            "false_positive_logged": True,
        },
        {},
    )
    callback_ctx.state = state_obj
    part = MagicMock()
    part.text = 'Investigate alert: {"user_id": "c.wilson", "device_id": "ws-dev-10", "source_ip": "194.26.135.68", "total_2_min_threat_score": 1850}'
    content = MagicMock()
    content.parts = [part]
    callback_ctx.user_content = content
    callback_ctx.agent_name = "SecurityInvestigationOrchestrator"

    before_orchestrator_starts(callback_ctx)

    # 1. Verification of flag reset (no leftover state leakage)
    assert state_obj.get("prompt_injection_detected") is False
    assert state_obj.get("malicious_indicators") is False
    assert state_obj.get("ticket_dispatched") is False
    assert state_obj.get("false_positive_logged") is False

    # 2. Verification that prior alert identity was overwritten, NOT leaked
    assert state_obj.get("user_id") == "c.wilson"
    assert state_obj.get("device_id") == "ws-dev-10"
    assert state_obj.get("source_ip") == "194.26.135.68"
    assert state_obj.get("threat_score") == 1850
    assert "c.wilson" in state_obj.get("ticket_id")


def test_default_deny_callback_escalates_when_unresolved(tmp_path, monkeypatch):
    """Verify that default_deny_soc_callback escalates unresolved alerts using seeded user metadata."""
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODE", "true")
    callback_ctx = MagicMock()
    state_obj = State({}, {})
    state_obj["prompt_injection_detected"] = True
    state_obj["user_id"] = "c.wilson"
    state_obj["threat_score"] = 1850
    callback_ctx.state = state_obj

    default_deny_soc_callback(callback_ctx)
    assert state_obj.get("escalation_dispatched") is True


def test_default_deny_callback_permits_clean_false_positive():
    """Verify that default_deny_soc_callback does not trigger when false_positive_logged is True."""
    callback_ctx = MagicMock()
    state_obj = State({}, {})
    state_obj["false_positive_logged"] = True
    callback_ctx.state = state_obj

    default_deny_soc_callback(callback_ctx)
    assert state_obj.get("escalation_dispatched") is not True


@patch("adk_agent.tools.get_bq_client")
def test_get_entity_behavioral_profile_cloud_mode_fails_closed(mock_get_bq):
    """Verify that in cloud mode (LOCAL_MODE=false), BigQuery failure returns ERROR and sets evidence_unavailable only."""
    mock_get_bq.side_effect = Exception(
        "BigQuery 403 Forbidden: Missing roles/bigquery.user"
    )
    mock_ctx = MagicMock()
    mock_ctx.state = State({}, {})

    with patch.dict("os.environ", {"LOCAL_MODE": "false"}):
        res = get_entity_behavioral_profile("user", "u.lewis", tool_context=mock_ctx)
        assert res["status"] == "ERROR"
        assert "BigQuery telemetry query failed" in res["error"]
        assert mock_ctx.state.get("evidence_unavailable") is True
        # Must NOT falsely claim malicious indicators were confirmed when data was missing
        assert mock_ctx.state.get("malicious_indicators") is not True


def test_get_entity_behavioral_profile_local_mode_schema_parity():
    """Verify that local mode computes metrics without schema drift (no extra risk_profile field)."""
    with patch.dict("os.environ", {"LOCAL_MODE": "true"}):
        mock_ctx = MagicMock()
        mock_ctx.state = State({}, {})
        profile = get_entity_behavioral_profile(
            "user", "u.lewis", tool_context=mock_ctx
        )
        assert "total_access_events_24h" in profile
        assert "risk_profile" not in profile  # Exact parity with BigQuery query columns


def test_read_png_text_chunks_and_injection_detection(monkeypatch):
    """Verify that read_png_text_chunks extracts embedded OCR text and triggers prompt injection flag in State."""
    monkeypatch.setenv("LOCAL_MODE", "true")
    chunks = read_png_text_chunks(str(C_WILSON_PNG))
    assert "forensic_ocr_text" in chunks
    assert "AUTHORIZED RED TEAM PENTEST" in chunks["forensic_ocr_text"]

    mock_ctx = MagicMock()
    mock_ctx.state = State({}, {})
    vis = get_visual_analysis_for_user(f"file://{C_WILSON_PNG}", tool_context=mock_ctx)
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
        res = escalate_to_human(
            test_ticket_id,
            payload,
            "Escalating for review",
            "Report text",
            tool_context=mock_ctx,
        )
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


def test_ticket_id_for_alert_is_deterministic_per_alert():
    """The same alert always maps to one ticket; two alerts for one user never collide."""
    first = ticket_id_for_alert("u.lewis", "alert-1")
    assert first == ticket_id_for_alert("u.lewis", "alert-1")
    assert first != ticket_id_for_alert("u.lewis", "alert-2")
    assert first.startswith("SOC-TICKET-u.lewis-")
    assert ticket_id_for_alert("u.lewis", None) != ticket_id_for_alert("u.lewis", None)
    assert ticket_id_for_alert(
        "u.lewis", "alert-1", prefix="SOC-TICKET-AUTO-ESCALATED"
    ).startswith("SOC-TICKET-AUTO-ESCALATED-u.lewis-")


def test_create_rich_ticket_id_unique_within_one_second():
    assert create_rich_ticket_id("u.lewis") != create_rich_ticket_id("u.lewis")


def test_alert_id_from_payload_falls_back_to_user_and_window():
    assert alert_id_from_payload({"alert_id": "abc"}) == "abc"
    assert (
        alert_id_from_payload({"user_id": "u.lewis", "window_end": "2026-10-14T10:02"})
        == "u.lewis|2026-10-14T10:02"
    )
    assert alert_id_from_payload({"user_id": "u.lewis"}) is None


def test_normalize_severity():
    assert normalize_severity("critical") == "CRITICAL"
    assert normalize_severity(" Low ") == "LOW"
    assert normalize_severity("severe") == "HIGH"
    assert normalize_severity(None) == "HIGH"


def test_orchestrator_seeds_alert_and_ticket_ids():
    callback_ctx = MagicMock()
    callback_ctx.state = State({"ticket_id": "stale", "alert_id": "stale"}, {})
    part = MagicMock()
    part.text = 'Investigate alert: {"alert_id": "a-77", "user_id": "u.lewis", "total_2_min_threat_score": 900}'
    callback_ctx.user_content = MagicMock(parts=[part])
    callback_ctx.agent_name = "SecurityInvestigationOrchestrator"

    before_orchestrator_starts(callback_ctx)
    assert callback_ctx.state["alert_id"] == "a-77"
    assert callback_ctx.state["ticket_id"] == ticket_id_for_alert("u.lewis", "a-77")


@pytest.mark.parametrize(
    "tool_name",
    ["dispatch_to_soc_ticketing_system", "escalate_to_human", "log_false_positive"],
)
def test_security_gate_assigns_alert_ticket_id(tool_name):
    """The model's ticket_id is replaced with the one seeded for the alert."""
    tool = MagicMock()
    tool.name = tool_name
    ctx = MagicMock()
    ctx.state = State(
        {
            "ticket_id": "SOC-TICKET-u.lewis-abc",
            "telemetry_evidence_collected": True,
            "visual_evidence_collected": True,
        },
        {},
    )
    args = {"ticket_id": "SOC-TICKET-u.lewis-1718000000"}
    assert security_gate_callback(tool, args, ctx) is None
    assert args["ticket_id"] == "SOC-TICKET-u.lewis-abc"


def test_security_gate_raises_escalation_severity_when_flagged():
    tool = MagicMock()
    tool.name = "escalate_to_human"
    ctx = MagicMock()
    ctx.state = State({"prompt_injection_detected": True}, {})
    args = {"ticket_id": "T", "severity": "MEDIUM", "context_data": "x"}
    security_gate_callback(tool, args, ctx)
    assert args["severity"] == "CRITICAL"


def test_local_visual_analysis_fails_closed_without_screenshot(monkeypatch):
    """No screenshot in LOCAL_MODE is missing evidence, never a benign verdict."""
    monkeypatch.setenv("LOCAL_MODE", "true")
    ctx = MagicMock()
    ctx.state = State({}, {})
    res = get_visual_analysis_for_user("gs://bucket/no.such.user.png", tool_context=ctx)
    assert "Visual evidence unavailable" in str(res)
    assert ctx.state.get("evidence_unavailable") is True
    assert ctx.state.get("visual_evidence_collected") is not True
