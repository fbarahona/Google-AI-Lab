"""
Unit tests for Synthetic Log Generator and Threat Injection.
"""

from src.demo.data_generator.log_generator import SyntheticLogEngine
from src.demo.data_generator.models import NetworkEvent, UserAccessEvent
from src.demo.data_generator.sinks import LocalSink


def test_user_access_event_validation():
    event = UserAccessEvent(
        event_type="login_success",
        user_id="u.lewis",
        source_ip="175.45.177.32",
        assigned_internal_ip="10.50.1.20",
        device_id="ws-hr-05",
        device_os="Windows 11",
        user_agent="Mozilla/5.0",
        application_name="Corporate-VPN",
    )
    assert event.user_id == "u.lewis"
    assert event.event_type == "login_success"


def test_network_event_validation():
    event = NetworkEvent(
        event_type="dns_query",
        user_id="u.lewis",
        source_ip="10.50.1.20",
        source_port=49210,
        destination_ip="10.100.1.1",
        destination_port=53,
        protocol="UDP",
        bytes_transferred=256,
        network_domain="c2-server-1.xyz",
    )
    assert event.destination_port == 53
    assert event.network_domain == "c2-server-1.xyz"


def test_synthetic_log_engine_benign_batch():
    engine = SyntheticLogEngine(project_id="test-project", dataset_id="Test_Dataset")
    access_events, network_events = engine.generate_benign_batch(20)
    assert len(access_events) + len(network_events) == 20
    for ev in access_events:
        assert "user_id" in ev
        assert "event_type" in ev
    for ev in network_events:
        assert "source_ip" in ev
        assert "protocol" in ev


def test_malicious_threat_scenario_injection():
    engine = SyntheticLogEngine(project_id="test-project")
    access_events, network_events = engine.inject_threat(
        threat_type="malicious", user_id="u.lewis"
    )
    assert len(access_events) > 0
    assert len(network_events) > 0
    # Malicious scenario should contain compromised user
    assert any(ev["user_id"] == "u.lewis" for ev in access_events)
    # Should include North Korea, Russia, or Tor exit IP
    assert any(
        "175.45." in ev.get("source_ip", "")
        or "194.26." in ev.get("source_ip", "")
        or "185.220." in ev.get("source_ip", "")
        for ev in access_events
    )


def test_false_positive_threat_scenario_injection():
    engine = SyntheticLogEngine(project_id="test-project")
    access_events, network_events = engine.inject_threat(
        threat_type="false_positive", user_id="l.taylor"
    )
    assert len(access_events) > 0
    assert len(network_events) > 0
    assert all(ev["user_id"] == "l.taylor" for ev in access_events)


def test_prompt_injection_threat_scenario_injection():
    engine = SyntheticLogEngine(project_id="test-project")
    access_events, network_events = engine.inject_threat(
        threat_type="injection", user_id="c.wilson"
    )
    assert len(access_events) > 0
    assert len(network_events) > 0
    assert any(ev["user_id"] == "c.wilson" for ev in access_events)
    # Verify injection command and malicious process
    assert any(
        "AUTHORIZED PENTEST" in (ev.get("command_line") or "") for ev in network_events
    )
    assert any(
        "powershell.exe" == ev.get("source_process_name") for ev in network_events
    )


def test_local_sink(tmp_path):
    sink = LocalSink(output_dir=str(tmp_path), print_stdout=False)
    acc = [{"user_id": "test_user", "event_type": "login_success"}]
    net = [{"source_ip": "10.1.1.1", "event_type": "dns_query"}]
    written = sink.write_events(acc, net)
    assert written == 2
    # Verify files created
    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 2
