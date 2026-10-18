"""
Unit tests for SOC Ticketing System models and operations.
"""

import os
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from src.demo.soc_ticketing.models import (
    AUTO_CLOSED_FP_DECISION,
    SIMULATED_DECISION,
    SocTicket,
)
from src.demo.soc_ticketing.ticketing_service import (
    SocTicketingService,
    TicketPersistenceError,
    _row_dict,
)


def test_soc_ticket_validation():
    ticket = SocTicket(
        ticket_id="SOC-TICKET-u.lewis-1718000000",
        user_id="u.lewis",
        device_id="ws-hr-05",
        source_ip="175.45.177.32",
        threat_score=2500,
        severity="CRITICAL",
        status="ESCALATED",
        category="Malware",
        sla_status="Within SLA",
        agent_decision="PERCEIVED_THREAT",
        agent_reason="High volume of suspicious PowerShell and external IP connections.",
        mitre_tactics=["Command and Control", "Execution"],
        indicators_of_compromise=["175.45.177.32", "c2-server-1.xyz"],
        structured_report="### Security Incident Report\nConfirmed threat.",
    )
    assert ticket.ticket_id == "SOC-TICKET-u.lewis-1718000000"
    assert ticket.severity == "CRITICAL"
    assert ticket.category == "Malware"
    assert len(ticket.mitre_tactics) == 2


def test_soc_ticketing_service_dispatch(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODE", "false")
    service = SocTicketingService(project_id="test-project", dataset_id="Test_Dataset")

    # Mock GCP clients
    mock_storage = MagicMock()
    mock_bucket = MagicMock()
    mock_blob = MagicMock()
    mock_storage.bucket.return_value = mock_bucket
    mock_bucket.blob.return_value = mock_blob
    service._storage_client = mock_storage

    mock_bq = MagicMock()
    mock_bq.insert_rows_json.return_value = []
    service._bq_client = mock_bq

    ticket = SocTicket(
        ticket_id="SOC-TICKET-test-123",
        user_id="u.lewis",
        device_id="ws-hr-05",
        source_ip="175.45.177.32",
        threat_score=1500,
        severity="HIGH",
        status="ESCALATED",
        agent_decision="PERCEIVED_THREAT",
        agent_reason="Detected malicious commands.",
        structured_report="Report content.",
    )

    result = service.create_and_dispatch_ticket(ticket)
    assert "Successfully dispatched ticket SOC-TICKET-test-123" in result
    assert mock_blob.upload_from_string.called
    assert mock_bq.insert_rows_json.call_count == 2
    called_tables = [call[0][0] for call in mock_bq.insert_rows_json.call_args_list]
    assert any("soc_tickets" in t for t in called_tables)
    assert any("adk_threat_assessment" in t for t in called_tables)


def test_soc_ticketing_fetch_historic_and_verdict(tmp_path, monkeypatch):
    queue_dir = tmp_path / "escalations"
    hist_dir = queue_dir / "history"
    hist_dir.mkdir(parents=True)
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(queue_dir))
    # Local archive flow; cloud mode stores tickets in BigQuery only.
    monkeypatch.setenv("LOCAL_MODE", "true")
    src_history = "./local_demo_data/escalations/history"
    if os.path.exists(src_history):
        shutil.copytree(src_history, str(hist_dir), dirs_exist_ok=True)

    service = SocTicketingService(project_id="test-project", dataset_id="Test_Dataset")

    # 1. Fetch historic tickets (should return seeded + archived records)
    historic = service.fetch_historic_tickets()
    assert len(historic) >= 5
    assert any(t.get("human_decision") == "Genuine Threat" for t in historic)
    assert any(t.get("human_decision") == "False Positive" for t in historic)

    # 2. Record verdict for a ticket
    test_id = "SOC-TICKET-test-verdict-99"
    ticket = SocTicket(
        ticket_id=test_id,
        user_id="test_user",
        device_id="ws-01",
        source_ip="10.1.1.1",
        threat_score=100,
        severity="LOW",
        status="ESCALATED",
        agent_decision="PERCEIVED_THREAT",
        agent_reason="Escalated for test",
        structured_report="Test report",
    )
    service.create_and_dispatch_ticket(ticket)

    success = service.record_human_verdict(
        test_id, "False Positive", "Test resolution notes"
    )
    assert success is True

    # Check updated in history
    updated_hist = service.fetch_historic_tickets()
    assert any(
        t.get("ticket_id") == test_id and t.get("human_decision") == "False Positive"
        for t in updated_hist
    )


def _ticket(ticket_id="SOC-TICKET-u.lewis-abc"):
    return SocTicket(
        ticket_id=ticket_id,
        user_id="u.lewis",
        device_id="ws-hr-05",
        source_ip="175.45.177.32",
        threat_score=1500,
        severity="HIGH",
        status="ESCALATED",
        agent_decision="PERCEIVED_THREAT",
        agent_reason="Detected malicious commands.",
        structured_report="Report content.",
    )


def test_cloud_dispatch_fails_closed_on_bigquery_insert_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODE", "false")
    service = SocTicketingService(project_id="test-project", dataset_id="Test_Dataset")
    service._bq_client = MagicMock()
    service._bq_client.insert_rows_json.return_value = [{"errors": ["denied"]}]
    service._storage_client = MagicMock()

    with pytest.raises(TicketPersistenceError):
        service.create_and_dispatch_ticket(_ticket())
    # Nothing is reported or copied once the system of record rejected the ticket.
    assert not service._storage_client.bucket.called
    assert list(tmp_path.glob("*.json")) == []


def test_cloud_dispatch_fails_closed_without_bigquery_client(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODE", "false")
    service = SocTicketingService(project_id="test-project", dataset_id="Test_Dataset")
    with patch.object(
        SocTicketingService, "bq_client", new_callable=PropertyMock, return_value=None
    ):
        with pytest.raises(TicketPersistenceError, match="no BigQuery client"):
            service.create_and_dispatch_ticket(_ticket())


def test_cloud_dispatch_tolerates_gcs_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODE", "false")
    service = SocTicketingService(project_id="test-project", dataset_id="Test_Dataset")
    service._bq_client = MagicMock()
    service._bq_client.insert_rows_json.return_value = []
    service._storage_client = MagicMock()
    service._storage_client.bucket.side_effect = RuntimeError("bucket missing")

    assert "Successfully dispatched" in service.create_and_dispatch_ticket(_ticket())


def test_local_dispatch_fails_closed_when_queue_unwritable(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODE", "true")
    service = SocTicketingService(project_id="test-project", dataset_id="Test_Dataset")
    # A directory where the ticket file should go makes the write fail.
    (tmp_path / "human_escalation_information_SOC-TICKET-u.lewis-abc.json").mkdir()
    with pytest.raises(TicketPersistenceError):
        service.create_and_dispatch_ticket(_ticket())


def test_redispatching_same_ticket_overwrites_local_file(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODE", "true")
    service = SocTicketingService(project_id="test-project", dataset_id="Test_Dataset")
    service.create_and_dispatch_ticket(_ticket())
    service.create_and_dispatch_ticket(_ticket())
    assert len(list(tmp_path.glob("human_escalation_information_*.json"))) == 1


def test_auto_closed_false_positive_is_archived_and_counted(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODE", "true")
    service = SocTicketingService(project_id="test-project", dataset_id="Test_Dataset")
    service.record_auto_closed_false_positive(_ticket("SOC-TICKET-l.taylor-fp1"))

    archived = [
        t
        for t in service.fetch_historic_tickets()
        if t.get("ticket_id") == "SOC-TICKET-l.taylor-fp1"
    ]
    assert len(archived) == 1
    assert archived[0]["status"] == "RESOLVED"
    assert archived[0]["agent_decision"] == AUTO_CLOSED_FP_DECISION
    assert not archived[0].get("human_decision")
    assert service.fetch_dashboard_metrics()["auto_closed_alerts"] == 1
    assert all(
        t.get("ticket_id") != "SOC-TICKET-l.taylor-fp1"
        for t in service.fetch_new_tickets()
    )


def test_cloud_auto_closed_false_positive_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODE", "false")
    service = SocTicketingService(project_id="test-project", dataset_id="Test_Dataset")
    service._bq_client = MagicMock()
    service._bq_client.insert_rows_json.side_effect = RuntimeError("403")
    with pytest.raises(TicketPersistenceError):
        service.record_auto_closed_false_positive(_ticket())


def test_local_sample_history_is_simulated_and_not_counted(tmp_path, monkeypatch):
    """The sample archive shown on a fresh local console never inflates the KPIs."""
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("LOCAL_MODE", "true")
    service = SocTicketingService(project_id="local-demo")

    history = service.fetch_historic_tickets()
    assert history
    assert all(t["agent_decision"] == SIMULATED_DECISION for t in history)
    assert all(t["ticket_id"].startswith("SIM-TICKET-") for t in history)
    assert not list((tmp_path / "history").glob("*.json"))  # nothing written
    assert service.fetch_dashboard_metrics()["triaged_alerts"] == 0


# --- soc_tickets modelling: typed timestamps and the soc_tickets_current view ---

_TERRAFORM = Path(__file__).resolve().parents[2] / "terraform"


def _view_sql(table_id: str) -> str:
    tf = (_TERRAFORM / "bigquery.tf").read_text()
    match = re.search(
        rf'table_id\s*=\s*"{table_id}".*?query\s*=\s*<<-SQL\n(.*?)\n\s*SQL', tf, re.S
    )
    assert match, f"view {table_id} not found"
    return match.group(1)


def test_current_view_classifies_with_the_model_constants():
    sql = _view_sql("soc_tickets_current")
    assert f"agent_decision = '{SIMULATED_DECISION}' AS is_simulated" in sql
    assert f"agent_decision = '{AUTO_CLOSED_FP_DECISION}' AS is_auto_closed" in sql
    assert "QUALIFY ROW_NUMBER() OVER" in sql


def test_service_reads_tickets_only_through_the_current_view():
    package = Path(__file__).resolve().parents[2] / "soc_ticketing"
    source = "\n".join(
        path.read_text()
        for path in [package / "ticketing_service.py", *package.glob("service/*.py")]
    )
    assert ".soc_tickets`" not in source  # every read goes through soc_tickets_current
    assert "PARSE_TIMESTAMP" not in source  # created_at is a TIMESTAMP now


def test_ticket_rows_carry_valid_timestamps():
    row = SocTicketingService._soc_tickets_row(
        {"ticket_id": "T-1", "created_at": "", "adjudicated_at": ""}
    )
    assert datetime.fromisoformat(row["created_at"])
    assert "adjudicated_at" not in row  # NULL, not an empty string


def test_bigquery_timestamps_come_back_as_iso_strings():
    created = datetime(2026, 10, 15, 2, 0, tzinfo=UTC)
    assert _row_dict({"ticket_id": "T-1", "created_at": created}) == {
        "ticket_id": "T-1",
        "created_at": "2026-10-15T02:00:00+00:00",
    }


def test_dashboard_breakdowns_come_from_one_grouping_sets_query(monkeypatch):
    monkeypatch.setenv("LOCAL_MODE", "false")
    service = SocTicketingService(project_id="p")
    breakdown_rows = [
        {"dimension": "severity", "label": "Critical", "count": 3},
        {"dimension": "status", "label": "Open", "count": 2},
        {"dimension": "sla", "label": "Within SLA", "count": 3},
        {"dimension": "category", "label": "Credential Access", "count": 1},
    ]
    queries = []

    def query(sql):
        queries.append(sql)
        job = MagicMock()
        job.result.return_value = breakdown_rows if "GROUPING SETS" in sql else []
        return job

    service._bq_client = MagicMock()
    service._bq_client.query.side_effect = query
    metrics = service.fetch_dashboard_metrics("Last 7 Days")

    assert metrics["alerts_by_severity"] == [{"severity": "Critical", "count": 3}]
    assert metrics["alerts_by_status"] == [{"status": "Open", "count": 2}]
    assert metrics["alerts_by_sla"] == [{"sla": "Within SLA", "count": 3}]
    assert metrics["alerts_by_category"] == [
        {"category": "Credential Access", "count": 1}
    ]
    ticket_queries = [q for q in queries if "soc_tickets_current" in q]
    assert len(ticket_queries) == 3  # summary, breakdowns, map (was 6 deduped CTEs)
    assert all("NOT is_simulated" in q for q in ticket_queries)
    assert all("created_at >= TIMESTAMP_SUB" in q for q in ticket_queries)


def test_tickets_carry_their_incident_rollup(monkeypatch):
    """A ticket matches its incident through the alert_id hash in its ticket ID."""
    import hashlib

    monkeypatch.setenv("LOCAL_MODE", "false")
    service = SocTicketingService(project_id="p", dataset_id="d")
    suffix = hashlib.sha256(b"u.lewis|2026-10-15T05:00:00Z").hexdigest()[:10]
    bq = MagicMock()
    bq.query.return_value.result.return_value = [
        {
            "ticket_suffix": suffix,
            "windows": 3,
            "total_threat_score": 1600,
            "peak_window_score": 830,
        }
    ]
    service._bq_client = bq
    tickets = [
        {"ticket_id": f"SOC-TICKET-u.lewis-{suffix}", "user_id": "u.lewis"},
        {"ticket_id": "SOC-TICKET-c.wilson-0000000000", "user_id": "c.wilson"},
    ]
    service._attach_incident_stats(tickets)
    assert tickets[0]["incident_total_score"] == 1600
    assert tickets[0]["incident_windows"] == 3
    assert tickets[0]["incident_peak_score"] == 830
    assert "incident_windows" not in tickets[1]
    params = bq.query.call_args.kwargs["job_config"].query_parameters
    assert params[0].values == ["c.wilson", "u.lewis"]


def test_incident_lookup_failure_leaves_tickets_alone(monkeypatch):
    monkeypatch.setenv("LOCAL_MODE", "false")
    service = SocTicketingService(project_id="p", dataset_id="d")
    service._bq_client = MagicMock()
    service._bq_client.query.side_effect = RuntimeError("no view")
    tickets = [{"ticket_id": "SOC-TICKET-u.lewis-abc", "user_id": "u.lewis"}]
    service._attach_incident_stats(tickets)
    assert tickets == [{"ticket_id": "SOC-TICKET-u.lewis-abc", "user_id": "u.lewis"}]
