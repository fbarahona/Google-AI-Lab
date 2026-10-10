"""
Unit tests for ADK Agent tools and safety callbacks.
"""
from unittest.mock import MagicMock

from adk_agent.agent import forbidden_dml_check
from adk_agent.tools import (
    _parse_alert_payload_to_row,
    build_event_logs_query,
    create_rich_ticket_id,
)


def test_build_event_logs_query():
    sql = build_event_logs_query("user", "u.lewis")
    assert "user_id = 'u.lewis'" in sql
    assert "AccessMetrics" in sql
    assert "NetworkMetrics" in sql
    assert "INTERVAL 24 HOUR" in sql


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

    # Allow SELECT
    result_select = forbidden_dml_check(mock_tool, {"query": "SELECT * FROM Cymbal_Cyber.network_events LIMIT 10"}, mock_context)
    assert result_select is None
