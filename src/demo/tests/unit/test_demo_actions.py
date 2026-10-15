"""
Unit tests for the console's demo controls: telemetry goes to Pub/Sub in the cloud,
failures surface instead of being swallowed, and injected tickets are marked
SIMULATED and kept out of the dashboard metrics.
"""

import json
from concurrent.futures import Future
from datetime import UTC, datetime

import pytest

import src.demo.data_generator.sinks as sinks
from src.demo.data_generator.sinks import PubSubSink, to_bq_subscription_row
from src.demo.data_pipeline.pubsub_to_bigquery_dataflow import parse_and_route_record
from src.demo.soc_ticketing import demo_actions
from src.demo.soc_ticketing.models import SIMULATED_DECISION
from src.demo.soc_ticketing.ticketing_service import SocTicketingService


def _future(exc: Exception | None = None) -> Future:
    f: Future = Future()
    if exc:
        f.set_exception(exc)
    else:
        f.set_result("msg-id")
    return f


class FakePublisher:
    def __init__(self, fail_on: int | None = None):
        self.calls: list[tuple[bytes, dict]] = []
        self.fail_on = fail_on

    def publish(self, topic, data, **attrs):
        self.calls.append((data, attrs))
        if self.fail_on is not None and len(self.calls) == self.fail_on:
            return _future(PermissionError("403 pubsub.topics.publish denied"))
        return _future()


def _sink(publisher: FakePublisher) -> PubSubSink:
    sink = PubSubSink.__new__(PubSubSink)
    sink.publisher = publisher
    sink.topic_path = "projects/p/topics/cymbal_cyber_raw_logs"
    sink.publish_timeout = 1
    return sink


ACCESS = {"event_timestamp": "2026-10-14T19:00:00.500000+00:00", "user_id": "u.lewis"}
NETWORK = {"event_timestamp": "2026-10-14T19:00:01+00:00", "source_ip": "10.0.0.5"}


def test_bq_subscription_row_uses_epoch_microseconds():
    row = to_bq_subscription_row(ACCESS)
    expected = int(datetime(2026, 10, 14, 19, 0, 0, 500000, UTC).timestamp() * 1e6)
    assert row["event_timestamp"] == expected
    assert row["user_id"] == "u.lewis"
    assert ACCESS["event_timestamp"].startswith("2026")  # input left untouched


def test_pubsub_sink_routes_by_event_family_and_waits():
    pub = FakePublisher()
    assert _sink(pub).write_events([ACCESS], [NETWORK]) == 2
    families = [attrs["event_family"] for _, attrs in pub.calls]
    assert families == ["access", "network"]
    assert isinstance(json.loads(pub.calls[0][0])["event_timestamp"], int)


def test_pubsub_sink_raises_when_a_publish_fails():
    with pytest.raises(RuntimeError, match="1 of 2 messages were not published"):
        _sink(FakePublisher(fail_on=2)).write_events([ACCESS], [NETWORK])


def test_dataflow_parser_turns_microseconds_back_into_iso():
    payload = to_bq_subscription_row(NETWORK)
    _, data = parse_and_route_record(json.dumps(payload).encode())
    assert data["event_timestamp"] == "2026-10-14T19:00:01+00:00"


@pytest.fixture
def cloud_service(monkeypatch):
    """A service that reports cloud mode and records tickets instead of writing them."""
    svc = SocTicketingService(project_id="p")
    monkeypatch.setattr(svc, "is_cloud_enabled", lambda: True)
    tickets = []
    monkeypatch.setattr(svc, "create_and_dispatch_ticket", tickets.append)
    return svc, tickets


def test_cloud_inject_publishes_to_raw_topic_and_marks_ticket(
    cloud_service, monkeypatch
):
    svc, tickets = cloud_service
    published = {}

    class RecordingSink:
        def __init__(self, project_id, topic_id):
            published["topic"] = topic_id

        def write_events(self, acc, net):
            published["count"] = len(acc) + len(net)
            return published["count"]

    monkeypatch.setattr(sinks, "PubSubSink", RecordingSink)
    monkeypatch.setenv("RAW_LOGS_TOPIC", "cymbal_cyber_raw_logs")

    msg = demo_actions.inject_threat_scenario(svc, "malicious", "u.lewis", "/shots")

    assert published["topic"] == "cymbal_cyber_raw_logs"
    assert published["count"] > 0
    assert f"Published {published['count']} events" in msg
    (ticket,) = tickets
    assert ticket.agent_decision == SIMULATED_DECISION
    assert ticket.ticket_id.startswith("SIM-TICKET-u.lewis-")
    assert "Scripted by the console's demo controls" in ticket.structured_report
    assert "blocklist" not in ticket.structured_report


def test_cloud_inject_failure_raises_and_adds_no_ticket(cloud_service, monkeypatch):
    svc, tickets = cloud_service

    class FailingSink:
        def __init__(self, project_id, topic_id):
            pass

        def write_events(self, acc, net):
            raise RuntimeError("permission denied")

    monkeypatch.setattr(sinks, "PubSubSink", FailingSink)
    with pytest.raises(RuntimeError, match="permission denied"):
        demo_actions.inject_threat_scenario(svc, "malicious", "u.lewis", "/shots")
    with pytest.raises(RuntimeError):
        demo_actions.stream_benign_logs(svc)
    assert tickets == []


def test_local_inject_is_simulated_and_left_out_of_metrics(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_MODE", "true")
    monkeypatch.setenv("LOCAL_QUEUE_DIR", str(tmp_path))
    svc = SocTicketingService(project_id="local-demo")

    demo_actions.inject_threat_scenario(svc, "false_positive", "l.taylor", "/shots")

    assert list((tmp_path / "telemetry").glob("access_events_*.jsonl"))
    queued = svc.fetch_new_tickets()
    assert [t["agent_decision"] for t in queued] == [SIMULATED_DECISION]
    assert svc.fetch_dashboard_metrics()["escalated_alerts"] == 0
