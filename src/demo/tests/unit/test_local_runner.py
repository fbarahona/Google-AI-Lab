"""The local runner's detector step scores telemetry with the shared detection rules."""

from src.demo import local_runner


def test_detect_builds_an_alert_for_the_injected_threat(tmp_path):
    local_runner.generate_logs("malicious", "u.lewis", tmp_path)
    alert = local_runner.detect("u.lewis", tmp_path)

    assert alert is not None
    assert alert["user_id"] == "u.lewis"
    assert alert["alert_id"] == f"u.lewis|{alert['window_end']}"
    assert alert["incident_id"] == alert["alert_id"]  # the first window opens it
    assert alert["total_2_min_threat_score"] >= local_runner.ALERT_MIN_SCORE


def test_detect_returns_none_without_activity(tmp_path):
    local_runner.generate_logs("malicious", "u.lewis", tmp_path)
    assert local_runner.detect("nobody.here", tmp_path) is None


def test_scripted_report_is_built_from_the_investigation():
    from src.demo.scripted_model import build_report, telemetry_summary
    from src.demo.soc_ticketing.report_parser import split_sections

    alert = {
        "user_id": "u.lewis",
        "device_id": "ws-hr-05",
        "source_ip": "175.45.177.32",
        "window_end": "2026-10-15T02:00:00Z",
        "total_2_min_threat_score": 1235,
    }
    profile = {
        "total_login_failures_24h": 35,
        "malicious_commands_24h": 4,
        "malicious_dns_queries_24h": 0,
        "security_flags": {"malicious_indicators": True},
    }
    quoted = "<<<BEGIN_QUOTED_AGENT_CONTENT>>>\n{}\n<<<END_QUOTED_AGENT_CONTENT>>>"
    transcript = (
        "[bq_investigation_agent] said:\n"
        + quoted.format(telemetry_summary("u.lewis", profile))
        + "[visual_analysis_agent] said:\n"
        + quoted.format("Forensic Desktop OCR Output:\nmimikatz.exe")
    )

    report = build_report(alert, transcript, "GENUINE THREAT")
    titles = [s.title for s in split_sections(report)]

    assert titles[:6] == [
        "Alert Overview",
        "Behavioral Findings",
        "Visual Forensics",
        "External Threat Intelligence",
        "MITRE ATT&CK Mapping",
        "Recommended Response Actions",
    ]
    assert "- Login failures: 35" in report
    assert "mimikatz.exe" in report
    assert "T1110 Brute Force" in report and "T1059.001 PowerShell" in report
    assert "T1071.004" not in report  # no malicious DNS, so no C2 technique
    assert "Isolate host `ws-hr-05`" in report


def test_scripted_fp_rationale_cites_the_telemetry():
    from src.demo.scripted_model import fp_rationale, telemetry_summary

    summary = telemetry_summary("l.taylor", {"total_login_failures_24h": 2})
    transcript = (
        "[bq_investigation_agent] said:\n<<<BEGIN_QUOTED_AGENT_CONTENT>>>\n"
        f"{summary}\n<<<END_QUOTED_AGENT_CONTENT>>>"
    )
    assert "2 login failures" in fp_rationale(transcript)
    assert "no telemetry findings" in fp_rationale("")
