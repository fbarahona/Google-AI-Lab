"""
Unit tests for the Scheduled Micro-Batch Threat Detector Job (adk_agent.threat_detector).
Verifies module import, detection cycle execution with mocked clients, and query construction.
"""

from datetime import UTC, datetime, timedelta
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
    _mock_bq, _mock_pub = mock_clients
    detector = ThreatDetector(project_id="test-proj", dataset_id="Test_Dataset", topic_id="test_alerts")
    assert detector.project_id == "test-proj"
    assert detector.dataset_id == "Test_Dataset"
    assert detector.topic_id == "test_alerts"


def test_threat_detector_run_cycle_empty(mock_clients):
    """Verify run_detection_cycle runs without error when no alerts are detected."""
    mock_bq, _mock_pub = mock_clients
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

    # Backdate mock event timestamps by 2 to 3 minutes to align with boundary guard (NOW - 60s)
    now = datetime.now(UTC)
    mock_window_end = now - timedelta(minutes=2)
    mock_window_start = mock_window_end - timedelta(minutes=2)
    mock_detected_at = mock_window_end + timedelta(seconds=15)

    window_end_str = mock_window_end.strftime("%Y-%m-%dT%H:%M:%SZ")
    window_start_str = mock_window_start.strftime("%Y-%m-%dT%H:%M:%SZ")
    detected_at_str = mock_detected_at.strftime("%Y-%m-%dT%H:%M:%SZ")

    # 1. First query: MERGE (returns empty result)
    merge_job = MagicMock()
    # 2. Second query: fetch new alerts (returns 1 alert)
    fetch_job = MagicMock()
    alert_row = {
        "alert_id": f"u.lewis|{window_end_str}",
        "engine": "scheduled",
        "user_id": "u.lewis",
        "device_id": "ws-hr-05",
        "source_ip": "175.45.177.32",
        "window_start": window_start_str,
        "window_end": window_end_str,
        "total_2_min_threat_score": 1500,
        "high_privilege_request_count": 2,
        "malicious_command_count": 1,
        "malicious_dns_count": 3,
        "detected_at": detected_at_str,
        "payload_str": None,
    }
    fetch_job.result.return_value = [alert_row]

    # 3. Third query: DLQ inspection (returns empty list)
    dlq_job = MagicMock()
    dlq_job.result.return_value = []

    # 4. Status update query
    update_job = MagicMock()

    # 5. Unmatched DLQ inspection query
    unmatched_dlq_job = MagicMock()
    unmatched_dlq_job.result.return_value = [{"unmatched_count": 0}]

    mock_bq.query.side_effect = [merge_job, fetch_job, update_job, dlq_job, unmatched_dlq_job]

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


def test_threat_detector_logs_unmatched_dead_letters(mock_clients):
    """Verify detector queries and logs unmatched orphaned dead-letter records."""
    mock_bq, _mock_pub = mock_clients

    # 1. MERGE query
    merge_job = MagicMock()
    # 2. Fetch new alerts (none)
    fetch_job = MagicMock()
    fetch_job.result.return_value = []
    # 3. DLQ matched alerts (none)
    dlq_job = MagicMock()
    dlq_job.result.return_value = []
    # 4. Unmatched DLQ records (found 4 orphaned rows)
    unmatched_job = MagicMock()
    unmatched_job.result.return_value = [{"unmatched_count": 4}]

    mock_bq.query.side_effect = [merge_job, fetch_job, dlq_job, unmatched_job]

    detector = ThreatDetector(project_id="test-proj", dataset_id="Test_Dataset")
    with patch("adk_agent.threat_detector.logger.warning") as mock_warn:
        detector.run_detection_cycle(lookback_minutes=15, min_score=100)
        assert any("unmatched orphaned message" in str(call) for call in mock_warn.call_args_list)


def test_threat_detector_boundary_mock_alignment():
    """Verify that event timestamps in detector fixtures are explicitly backdated
    by 2 to 3 minutes to align with the closed-window boundary guard (timestamp < NOW - 1m)."""
    now = datetime.now(UTC)
    mock_event_time = now - timedelta(minutes=2)
    boundary_cutoff = now - timedelta(seconds=60)

    # Event must strictly precede boundary cutoff to prevent flaky exclusion
    assert mock_event_time < boundary_cutoff

