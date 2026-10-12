"""
Unit tests for the Scheduled Micro-Batch Threat Detector Job (adk_agent.threat_detector).
Verifies module import, detection cycle execution with mocked clients, and query construction.
"""

from unittest.mock import MagicMock, patch
import pytest

from adk_agent.threat_detector import ThreatDetector


@pytest.fixture
def mock_clients():
    with patch("adk_agent.threat_detector.bigquery.Client") as mock_bq_cls, \
         patch("adk_agent.threat_detector.pubsub_v1.PublisherClient") as mock_pub_cls:
        mock_bq = MagicMock()
        mock_pub = MagicMock()
        mock_bq_cls.return_value = mock_bq
        mock_pub_cls.return_value = mock_pub
        yield mock_bq, mock_pub


def test_threat_detector_import_and_init(mock_clients):
    """Verify ThreatDetector imports cleanly and initializes clients."""
    mock_bq, mock_pub = mock_clients
    detector = ThreatDetector(project_id="test-proj", dataset_id="Test_Dataset", topic_id="test_alerts")
    assert detector.project_id == "test-proj"
    assert detector.dataset_id == "Test_Dataset"
    assert detector.topic_id == "test_alerts"


def test_threat_detector_run_cycle_empty(mock_clients):
    """Verify run_detection_cycle runs without error when no alerts are detected."""
    mock_bq, mock_pub = mock_clients
    # Mock query results (empty list)
    mock_query_job = MagicMock()
    mock_query_job.result.return_value = []
    mock_bq.query.return_value = mock_query_job

    detector = ThreatDetector(project_id="test-proj", dataset_id="Test_Dataset")
    published = detector.run_detection_cycle(lookback_minutes=15, min_score=100)
    assert published == 0
    assert mock_bq.query.call_count >= 1


def test_threat_detector_publishes_new_alert(mock_clients):
    """Verify detected alerts are published to Pub/Sub and marked as PUBLISHED with expected_current_status='NEW'."""
    mock_bq, mock_pub = mock_clients

    # 1. First query: MERGE (returns empty result)
    merge_job = MagicMock()
    # 2. Second query: fetch new alerts (returns 1 alert)
    fetch_job = MagicMock()
    alert_row = {
        "alert_id": "u.lewis|2026-10-12T04:00:00Z",
        "engine": "scheduled",
        "user_id": "u.lewis",
        "device_id": "ws-hr-05",
        "source_ip": "175.45.177.32",
        "window_start": "2026-10-12T03:58:00Z",
        "window_end": "2026-10-12T04:00:00Z",
        "total_2_min_threat_score": 1500,
        "high_privilege_request_count": 2,
        "malicious_command_count": 1,
        "malicious_dns_count": 3,
        "detected_at": "2026-10-12T04:01:00Z",
        "payload_str": None
    }
    fetch_job.result.return_value = [alert_row]

    # 3. Third query: DLQ inspection (returns empty list)
    dlq_job = MagicMock()
    dlq_job.result.return_value = []

    # 4. Status update query
    update_job = MagicMock()

    mock_bq.query.side_effect = [merge_job, fetch_job, update_job, dlq_job]

    mock_future = MagicMock()
    mock_future.result.return_value = "msg-123"
    mock_pub.publish.return_value = mock_future

    detector = ThreatDetector(project_id="test-proj", dataset_id="Test_Dataset")
    published = detector.run_detection_cycle(lookback_minutes=15, min_score=100)

    assert published == 1
    assert mock_pub.publish.call_count == 1

    # Verify status update included AND status = @expected_current_status to prevent overwriting INVESTIGATING
    update_call_args = mock_bq.query.call_args_list[2]
    update_sql = update_call_args[0][0]
    assert "status = @expected_current_status" in update_sql

    # Verify MERGE query enforces late-data boundary guard in WHERE clause
    merge_call_args = mock_bq.query.call_args_list[0]
    merge_sql = merge_call_args[0][0]
    assert "INTERVAL 60 SECOND" in merge_sql

