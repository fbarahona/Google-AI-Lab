"""The local runner's detector step scores telemetry with the shared detection rules."""

from src.demo import local_runner


def test_detect_builds_an_alert_for_the_injected_threat(tmp_path):
    local_runner.generate_logs("malicious", "u.lewis", tmp_path)
    alert = local_runner.detect("u.lewis", tmp_path)

    assert alert is not None
    assert alert["user_id"] == "u.lewis"
    assert alert["alert_id"] == f"u.lewis|{alert['window_end']}"
    assert alert["total_2_min_threat_score"] >= local_runner.ALERT_MIN_SCORE


def test_detect_returns_none_without_activity(tmp_path):
    local_runner.generate_logs("malicious", "u.lewis", tmp_path)
    assert local_runner.detect("nobody.here", tmp_path) is None
