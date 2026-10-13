"""
Unit tests for SOC Ticketing System models and operations.
"""

import os
import shutil
from unittest.mock import MagicMock

from src.demo.soc_ticketing.models import SocTicket
from src.demo.soc_ticketing.ticketing_service import SocTicketingService


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
