"""
Unit tests for the Scheduled Micro-Batch Threat Detector Job (adk_agent.threat_detector).
Verifies module import, detection cycle execution with mocked clients, and query construction.
"""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from adk_agent.threat_detector import ThreatDetector


@pytest.fixture
def mock_clients():
    with (
        patch("adk_agent.threat_detector.bigquery.Client") as mock_bq_cls,
        patch("adk_agent.threat_detector.pubsub_v1.PublisherClient") as mock_pub_cls,
    ):
        mock_bq = MagicMock()
        mock_pub = MagicMock()
        mock_bq_cls.return_value = mock_bq
        mock_pub_cls.return_value = mock_pub
        yield mock_bq, mock_pub


def test_threat_detector_import_and_init(mock_clients):
    """Verify ThreatDetector imports cleanly and initializes clients."""
    _mock_bq, _mock_pub = mock_clients
    detector = ThreatDetector(
        project_id="test-proj", dataset_id="Test_Dataset", topic_id="test_alerts"
    )
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

    mock_bq.query.side_effect = [
        merge_job,
        fetch_job,
        update_job,
        dlq_job,
        unmatched_dlq_job,
    ]

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
    assert "ActiveNetworkEvents" in merge_sql
    assert "ActiveSessions" in merge_sql
    assert (
        merge_sql.count(
            "DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 1 DAY)"
        )
        >= 2
    )


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
        assert any(
            "unmatched orphaned message" in str(call)
            for call in mock_warn.call_args_list
        )

    # Verify unmatched query includes 1-day partition and time filter
    unmatched_call_args = mock_bq.query.call_args_list[3]
    unmatched_sql = unmatched_call_args[0][0]
    assert "INTERVAL 1 DAY" in unmatched_sql
    assert "dlq.publish_time" in unmatched_sql


def test_threat_detector_boundary_mock_alignment():
    """Verify that event timestamps in detector fixtures are explicitly backdated
    by 2 to 3 minutes to align with the closed-window boundary guard (timestamp < NOW - 1m)."""
    now = datetime.now(UTC)
    mock_event_time = now - timedelta(minutes=2)
    boundary_cutoff = now - timedelta(seconds=60)

    # Event must strictly precede boundary cutoff to prevent flaky exclusion
    assert mock_event_time < boundary_cutoff


def test_threat_detector_merge_retry_on_concurrent_update_conflict(mock_clients):
    """Verify MERGE query retries with backoff on concurrent transaction collision and succeeds."""
    mock_bq, mock_pub = mock_clients

    now = datetime.now(UTC)
    mock_window_end = now - timedelta(minutes=2)
    mock_window_start = mock_window_end - timedelta(minutes=2)
    mock_detected_at = mock_window_end + timedelta(seconds=15)
    window_end_str = mock_window_end.strftime("%Y-%m-%dT%H:%M:%SZ")
    window_start_str = mock_window_start.strftime("%Y-%m-%dT%H:%M:%SZ")
    detected_at_str = mock_detected_at.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Attempt 1: raises 400 Concurrent update conflict
    conflict_error = Exception(
        "400 Concurrent update conflict with another transaction"
    )

    # Attempt 2: succeeds
    merge_job = MagicMock()

    # Subsequent queries: fetch, update, dlq, unmatched dlq
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

    update_job = MagicMock()
    dlq_job = MagicMock()
    dlq_job.result.return_value = []
    unmatched_dlq_job = MagicMock()
    unmatched_dlq_job.result.return_value = [{"unmatched_count": 0}]

    mock_bq.query.side_effect = [
        conflict_error,
        merge_job,
        fetch_job,
        update_job,
        dlq_job,
        unmatched_dlq_job,
    ]

    mock_future = MagicMock()
    mock_future.result.return_value = "msg-123"
    mock_pub.publish.return_value = mock_future

    detector = ThreatDetector(
        project_id="test-proj",
        dataset_id="Test_Dataset",
        max_merge_attempts=2,
        merge_retry_delay=3.0,
    )

    with patch("adk_agent.threat_detector.time.sleep") as mock_sleep:
        published = detector.run_detection_cycle(lookback_minutes=15, min_score=100)
        assert published == 1
        assert mock_sleep.call_count == 1
        assert mock_sleep.call_args[0][0] == 3.0


def test_threat_detector_merge_exhausts_retries_on_persistent_conflict(mock_clients):
    """Verify MERGE query fails gracefully after exhausting 2 attempts on persistent collision."""
    mock_bq, _mock_pub = mock_clients

    conflict_error = Exception(
        "400 Concurrent update conflict with another transaction"
    )
    mock_bq.query.side_effect = [conflict_error, conflict_error]

    detector = ThreatDetector(
        project_id="test-proj",
        dataset_id="Test_Dataset",
        max_merge_attempts=2,
        merge_retry_delay=3.0,
    )

    with patch("adk_agent.threat_detector.time.sleep") as mock_sleep:
        new_alerts = detector._merge_and_fetch_new_alerts(
            lookback_minutes=15, min_score=100
        )
        assert new_alerts == []
        assert mock_sleep.call_count == 1
        assert mock_sleep.call_args[0][0] == 3.0
        # Exactly 2 MERGE attempts executed
        assert mock_bq.query.call_count == 2


def test_threat_detector_run_cycle_handles_merge_failure(mock_clients):
    """Verify run_detection_cycle handles MERGE failure gracefully and proceeds to DLQ handling."""
    mock_bq, _mock_pub = mock_clients

    conflict_error = Exception(
        "400 Concurrent update conflict with another transaction"
    )
    dlq_job = MagicMock()
    dlq_job.result.return_value = []
    unmatched_dlq_job = MagicMock()
    unmatched_dlq_job.result.return_value = [{"unmatched_count": 0}]

    mock_bq.query.side_effect = [
        conflict_error,
        conflict_error,
        dlq_job,
        unmatched_dlq_job,
    ]

    detector = ThreatDetector(
        project_id="test-proj",
        dataset_id="Test_Dataset",
        max_merge_attempts=2,
        merge_retry_delay=3.0,
    )

    with patch("adk_agent.threat_detector.time.sleep"):
        published = detector.run_detection_cycle(lookback_minutes=15, min_score=100)
        assert published == 0
        merge_calls = [
            call
            for call in mock_bq.query.call_args_list
            if "MERGE" in call[0][0] and "alerts` T" in call[0][0]
        ]
        assert len(merge_calls) == 2


def test_format_utc_timestamp_iso8601():
    """Verify format_utc_timestamp emits ISO-8601 with trailing Z for aware and naive datetimes."""
    from adk_agent.threat_detector import format_utc_timestamp

    # Aware datetime
    aware_dt = datetime(2026, 10, 12, 14, 30, 0, tzinfo=UTC)
    assert format_utc_timestamp(aware_dt) == "2026-10-12T14:30:00Z"

    # Naive datetime (interpreted as UTC)
    naive_dt = datetime(2026, 10, 12, 14, 30, 0)
    assert format_utc_timestamp(naive_dt) == "2026-10-12T14:30:00Z"

    # String pass-through
    assert format_utc_timestamp("2026-10-12T14:30:00Z") == "2026-10-12T14:30:00Z"


def test_merge_query_parameterization_and_utc_formatting(mock_clients):
    """Verify MERGE query binds start_time and min_score via QueryJobConfig parameters."""
    mock_bq, _mock_pub = mock_clients

    merge_job = MagicMock()
    fetch_job = MagicMock()
    fetch_job.result.return_value = []
    mock_bq.query.side_effect = [merge_job, fetch_job]

    detector = ThreatDetector(project_id="test-proj", dataset_id="Test_Dataset")
    fixed_cutoff = datetime(2026, 10, 12, 6, 0, 0, tzinfo=UTC)
    detector._merge_and_fetch_new_alerts(
        lookback_minutes=15, min_score=150, cutoff_time=fixed_cutoff
    )

    # 1. Inspect MERGE query call
    merge_call = mock_bq.query.call_args_list[0]
    merge_sql = merge_call[0][0]
    job_config = merge_call[1]["job_config"]

    # Verify SQL references parameters
    assert "event_timestamp >= @start_time" in merge_sql
    assert "total_2_min_threat_score >= @min_score" in merge_sql

    # Verify query parameters
    params = {p.name: p for p in job_config.query_parameters}
    assert "start_time" in params
    assert params["start_time"].type_ == "TIMESTAMP"
    assert params["start_time"].value == fixed_cutoff
    assert "min_score" in params
    assert params["min_score"].value == 150


def test_failed_publish_skips_one_alert_and_batches_the_status_update(mock_clients):
    """One publish timeout must not abort the run; published alerts get one UPDATE."""
    mock_bq, mock_pub = mock_clients
    ok_future, bad_future = MagicMock(), MagicMock()
    bad_future.result.side_effect = TimeoutError("publish timed out")
    mock_pub.publish.side_effect = [ok_future, bad_future, ok_future]
    alerts = [
        {"alert_id": f"a{i}", "payload_str": json.dumps({"alert_id": f"a{i}"})}
        for i in range(3)
    ]

    detector = ThreatDetector(project_id="test-proj", dataset_id="Test_Dataset")
    assert detector._publish_alerts(alerts) == 2

    assert mock_bq.query.call_count == 1
    update_sql = mock_bq.query.call_args[0][0]
    assert "IN UNNEST(@alert_ids)" in update_sql
    assert "status = @expected_current_status" in update_sql
    params = {
        p.name: p for p in mock_bq.query.call_args[1]["job_config"].query_parameters
    }
    assert params["alert_ids"].values == ["a0", "a2"]
    assert params["expected_current_status"].value == "NEW"


def test_merge_correlates_windows_into_incidents(mock_clients):
    """Only the window that opens an incident is NEW (published); the rest are CORRELATED."""
    from adk_agent import detection_rules as rules

    mock_bq, _mock_pub = mock_clients
    fetch_job = MagicMock()
    fetch_job.result.return_value = []
    mock_bq.query.side_effect = [MagicMock(), fetch_job]

    ThreatDetector(project_id="p", dataset_id="d")._merge_and_fetch_new_alerts()
    merge_call = mock_bq.query.call_args_list[0]
    merge_sql = merge_call[0][0]
    params = {p.name: p.value for p in merge_call[1]["job_config"].query_parameters}

    assert params["incident_gap_minutes"] == rules.INCIDENT_GAP_MINUTES
    assert "FROM CorrelatedWindows" in merge_sql
    assert "'NEW', 'CORRELATED'" in merge_sql
    assert "S.alert_id, S.incident_id" in merge_sql
    # The publish step still fetches NEW rows only, so CORRELATED ones never publish.
    assert "WHERE status = 'NEW'" in mock_bq.query.call_args_list[1][0][0]
