"""
Unit tests for SOC Ticketing System models and operations.
"""
from unittest.mock import MagicMock, patch
import pytest
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
        agent_decision="PERCEIVED_THREAT",
        agent_reason="High volume of suspicious PowerShell and external IP connections.",
        mitre_tactics=["Command and Control", "Execution"],
        indicators_of_compromise=["175.45.177.32", "c2-server-1.xyz"],
        structured_report="### Security Incident Report\nConfirmed threat."
    )
    assert ticket.ticket_id == "SOC-TICKET-u.lewis-1718000000"
    assert ticket.severity == "CRITICAL"
    assert len(ticket.mitre_tactics) == 2


def test_soc_ticketing_service_dispatch():
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
        structured_report="Report content."
    )

    result = service.create_and_dispatch_ticket(ticket)
    assert "Successfully dispatched ticket SOC-TICKET-test-123" in result
    assert mock_blob.upload_from_string.called
    assert mock_bq.insert_rows_json.called

