"""
Unit tests for ADK Agent tools, safety callbacks, and SQL injection prevention.
"""
from unittest.mock import MagicMock

import pytest

from adk_agent.agent import forbidden_dml_check
from adk_agent.tools import (
    _parse_alert_payload_to_row,
    build_event_logs_query,
    create_rich_ticket_id,
    get_gcs_uri_for_user,
    sanitize_entity_value,
)


def test_build_event_logs_query():
    sql = build_event_logs_query("user", "u.lewis")
    assert "user_id = 'u.lewis'" in sql
    assert "AccessMetrics" in sql
    assert "NetworkMetrics" in sql
    assert "INTERVAL 24 HOUR" in sql


def test_build_event_logs_query_entity_types():
    """Verify that different valid entity types generate appropriate filters and windows."""
    user_sql = build_event_logs_query("user", "u.lewis", "12 HOUR")
    assert "user_id = 'u.lewis'" in user_sql
    assert "INTERVAL 12 HOUR" in user_sql

    device_sql = build_event_logs_query("device", "ws-hr-05", "24 HOUR")
    assert "device_id = 'ws-hr-05'" in device_sql

    ip_sql = build_event_logs_query("ip", "198.51.100.23", "6 HOUR")
    assert "source_ip = '198.51.100.23'" in ip_sql


def test_sql_injection_malicious_inputs_rejected():
    """Verify that diverse SQL injection attack vectors are blocked and raise ValueError."""
    malicious_inputs = [
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

    for malicious_input in malicious_inputs:
        with pytest.raises(ValueError, match=r"SQL Injection|invalid|illegal"):
            build_event_logs_query("user", malicious_input)

        with pytest.raises(ValueError, match=r"SQL Injection|invalid|illegal"):
            sanitize_entity_value(malicious_input)

        with pytest.raises(ValueError, match=r"SQL Injection|invalid|illegal"):
            get_gcs_uri_for_user(malicious_input)


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
