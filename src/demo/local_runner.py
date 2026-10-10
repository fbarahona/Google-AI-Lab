"""
End-to-End Local Demo Runner (Zero-Cloud Testing)
=================================================
Allows testing and demonstrating the complete cybersecurity AI pipeline locally
without deploying any infrastructure to Google Cloud or requiring Terraform:

1. Generates local synthetic logs (access and network events).
2. Injects synthetic threats (Malicious or Benign False Positive).
3. Runs local stream correlation (simulating BigQuery Continuous Queries).
4. Invokes the ADK multi-agent investigation workflow:
   - google_search_agent (IP threat intelligence)
   - bq_investigation_agent (24h behavioral profile)
   - visual_analysis_agent (screenshot OCR & visual evidence)
   - soc_ticketing_agent (incident report & ticket dispatch)
5. Dispatches the ticket to the local SOC queue for instant Streamlit triage.

Usage:
  python -m src.demo.local_runner --threat malicious
  python -m src.demo.local_runner --threat false_positive
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, List

from src.demo.data_generator.log_generator import SyntheticLogEngine
from src.demo.data_generator.sinks import LocalSink
from src.demo.soc_ticketing.models import SocTicket
from src.demo.soc_ticketing.ticketing_service import SocTicketingService

LOCAL_DATA_DIR = "./local_demo_data"
LOGS_DIR = os.path.join(LOCAL_DATA_DIR, "logs")
ESCALATIONS_DIR = os.path.join(LOCAL_DATA_DIR, "escalations")
SCREENSHOTS_DIR = "src/demo/user_screenshots"


def step_1_generate_logs(threat_type: str = "malicious", target_user: str = "u.lewis") -> Dict[str, Any]:
    """Generates local synthetic access and network logs with injected threat."""
    print(f"\n=======================================================")
    print(f"[STEP 1] Generating Synthetic Logs & Injecting Threat")
    print(f"=======================================================")
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(ESCALATIONS_DIR, exist_ok=True)

    engine = SyntheticLogEngine(project_id="local-demo")
    sink = LocalSink(output_dir=LOGS_DIR, print_stdout=False)

    # 1. Background benign noise
    benign_acc, benign_net = engine.generate_benign_batch(50)
    sink.write_events(benign_acc, benign_net)
    print(f"  -> Generated {len(benign_acc)} access events and {len(benign_net)} network events of benign background activity.")

    # 2. Inject threat scenario
    threat_acc, threat_net = engine.inject_threat(threat_type=threat_type, user_id=target_user)
    sink.write_events(threat_acc, threat_net)
    print(f"  -> Injected {len(threat_acc)} access events and {len(threat_net)} network events for scenario: '{threat_type.upper()}' (User: {target_user}).")

    return {
        "threat_type": threat_type,
        "user_id": target_user,
        "access_events": threat_acc,
        "network_events": threat_net
    }


def step_2_correlate_events(scenario_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simulates BigQuery Continuous Query locally:
    Joins access events and network events on assigned internal IP,
    scores anomalies, and computes tumbling window threat scores.
    """
    print(f"\n=======================================================")
    print(f"[STEP 2] Simulating BigQuery Continuous Query Stream Processing")
    print(f"=======================================================")

    threat_type = scenario_data["threat_type"]
    user_id = scenario_data["user_id"]
    access_events = scenario_data["access_events"]
    network_events = scenario_data["network_events"]

    # Extract successful login internal IP
    login_ev = next((ev for ev in access_events if ev.get("event_type") == "login_success"), None)
    assigned_ip = login_ev.get("assigned_internal_ip") if login_ev else "10.50.1.20"
    source_ip = login_ev.get("source_ip") if login_ev else "175.45.177.32"
    device_id = login_ev.get("device_id") if login_ev else "ws-hr-05"

    # Score correlated network events
    total_score = 0
    malicious_cmd_count = 0
    malicious_dns_count = 0
    risky_file_count = 0

    for ev in network_events:
        score = 0
        cmd = ev.get("command_line") or ""
        domain = ev.get("network_domain") or ""
        file_type = ev.get("file_type") or ""

        if "powershell -enc" in cmd or "mimikatz" in cmd or "IEX" in cmd:
            score += 100
            malicious_cmd_count += 1
        elif cmd:
            score += 10

        if any(bad in domain for bad in [".ru", ".xyz", ".org", "bad-domain", "c2-server"]):
            score += 60
            malicious_dns_count += 1

        if file_type in ["exe", "dll", "ps1", "bat"]:
            score += 40
            risky_file_count += 1

        if ev.get("permission_level_requested") in ["root", "admin"]:
            score += 35

        total_score += score

    # Fallback score if benign false positive
    if threat_type == "false_positive":
        total_score = max(total_score, 120)
    else:
        total_score = max(total_score, 1850)

    alert_payload = {
        "window_end": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "device_id": device_id,
        "source_ip": source_ip,
        "assigned_internal_ip": assigned_ip,
        "total_2_min_threat_score": total_score,
        "malicious_command_count": malicious_cmd_count,
        "malicious_dns_count": malicious_dns_count,
        "risky_file_transfer_count": risky_file_count
    }

    print(f"  -> Correlation Window Completed.")
    print(f"  -> Correlated User: {user_id} | Device: {device_id} | Public IP: {source_ip}")
    print(f"  -> Aggregated Anomaly Score: {total_score} (Threshold: >= 100)")
    print(f"  -> Alert payload emitted to ADK Multi-Agent Orchestrator!")
    return alert_payload


def step_3_run_agent_investigation(alert: Dict[str, Any], threat_type: str) -> Dict[str, Any]:
    """Simulates the 4 ADK agents investigating the security alert."""
    print(f"\n=======================================================")
    print(f"[STEP 3] ADK Multi-Agent Investigation Team Activated")
    print(f"=======================================================")

    user_id = alert["user_id"]
    source_ip = alert["source_ip"]
    device_id = alert["device_id"]
    score = alert["total_2_min_threat_score"]

    # 1. google_search_agent
    print(f"  [1] google_search_agent (OSINT & IP Reputation):")
    if "175.45." in source_ip:
        osint_intel = (
            f"Public IP {source_ip} traces to Ryugyong-dong, Pyongyang, North Korea (AS131279 Star JV). "
            f"Threat intel feeds associate this netblock with APT38 / Lazarus Group operations."
        )
    elif "194.26." in source_ip:
        osint_intel = (
            f"Public IP {source_ip} originates from Moscow, Russia. Threat intelligence correlates IP "
            f"with known bulletproof hosting and malware distribution infrastructure."
        )
    else:
        osint_intel = (
            f"Public IP {source_ip} resolves to standard corporate ISP / enterprise VPN range. "
            f"No malicious reputation or abuse reports found."
        )
    print(f"      Result: {osint_intel}")

    # 2. bq_investigation_agent
    print(f"  [2] bq_investigation_agent (24-Hour Forensic Log Query):")
    if threat_type == "malicious":
        bq_summary = (
            f"24h Profile for '{user_id}': 35 login failures (brute force password spray) followed by "
            f"successful VPN login from foreign IP {source_ip}. "
            f"Correlated subsequent commands executed: mimikatz, powershell -enc downloadstring, "
            f"and C2 DNS beaconing to 'c2-server-1.xyz'."
        )
    else:
        bq_summary = (
            f"24h Profile for '{user_id}': Normal corporate single sign-on activity. "
            f"Automated maintenance script executed benign commands (ipconfig, ping, df -h) with user privileges. "
            f"No foreign IPs, no privilege escalation."
        )
    print(f"      Result: {bq_summary}")

    # 3. visual_analysis_agent
    print(f"  [3] visual_analysis_agent (Multimodal Screenshot Vision Forensics):")
    screenshot_file = os.path.join(SCREENSHOTS_DIR, f"{user_id}.png")
    if os.path.exists(screenshot_file):
        has_screenshot = True
        if threat_type == "malicious":
            vision_analysis = (
                f"OCR and visual inspection of '{screenshot_file}' confirms active PowerShell terminal "
                f"executing exploit script: 'Invoke-Mimikatz' with elevated admin prompt visible. "
                f"Visual evidence directly corroborates genuine threat."
            )
        else:
            vision_analysis = (
                f"OCR inspection of '{screenshot_file}' displays a benign internal BigQuery console "
                f"and standard browser tabs. No suspicious terminal prompts or malicious tooling detected."
            )
    else:
        has_screenshot = False
        vision_analysis = f"No desktop screenshot found for user '{user_id}'."
    print(f"      Result: {vision_analysis}")

    # 4. soc_ticketing_agent
    print(f"  [4] soc_ticketing_agent (Consolidation & Triage Verdict):")
    ticket_id = f"SOC-TICKET-{user_id}-{int(time.time())}"

    if threat_type == "malicious":
        decision = "GENUINE_THREAT"
        severity = "CRITICAL"
        reason = f"Confirmed APT credential compromise, unauthorized Mimikatz execution, and North Korean C2 communication."
    else:
        decision = "FALSE_POSITIVE"
        severity = "LOW"
        reason = f"Benign administrative automation routine; no hostile IPs or malware identified."

    report = f"""### Security Incident Report
**1. Alert Overview**
* **Ticket ID:** `{ticket_id}`
* **Entity / User:** `{user_id}`
* **Endpoint / Device:** `{device_id}`
* **Originating IP:** `{source_ip}`
* **Anomaly Threat Score:** `{score}`
* **Autonomous ADK Verdict:** `{decision}`

**2. Behavioral Analysis (BigQuery)**
* {bq_summary}

**3. Visual Forensic Analysis**
* {vision_analysis}

**4. External Threat Intelligence (OSINT)**
* {osint_intel}
"""
    print(f"      Verdict: {decision} (Severity: {severity})")
    print(f"      Generated Ticket ID: {ticket_id}")

    ticket = SocTicket(
        ticket_id=ticket_id,
        user_id=user_id,
        device_id=device_id,
        source_ip=source_ip,
        threat_score=score,
        severity=severity,
        status="ESCALATED",
        agent_decision=decision,
        agent_reason=reason,
        screenshot_url=f"file://{os.path.abspath(screenshot_file)}" if has_screenshot else None,
        structured_report=report,
        mitre_tactics=["Initial Access", "Command and Control", "Credential Access"] if threat_type == "malicious" else ["Discovery"],
        indicators_of_compromise=[source_ip, "c2-server-1.xyz"] if threat_type == "malicious" else [source_ip]
    )

    return {
        "ticket": ticket,
        "report": report
    }


def step_4_dispatch_ticket_locally(ticket: SocTicket):
    """Writes ticket to local queue for Streamlit triage."""
    print(f"\n=======================================================")
    print(f"[STEP 4] Dispatching Ticket to Local SOC Ticketing Queue")
    print(f"=======================================================")
    service = SocTicketingService(project_id="local-demo")
    msg = service.create_and_dispatch_ticket(ticket)
    ticket_file = os.path.join(ESCALATIONS_DIR, f"human_escalation_information_{ticket.ticket_id}.json")

    print(f"  -> {msg}")
    print(f"  -> File Queue: {ticket_file}")
    print(f"\n-------------------------------------------------------")
    print(f"🎉 LOCAL DEMO EXECUTION COMPLETE!")
    print(f"-------------------------------------------------------")
    print(f"To open the interactive SOC Analyst Console, run:")
    print(f"  LOCAL_MODE=true streamlit run src/demo/soc_ticketing/streamlit_soc_console.py")
    print(f"-------------------------------------------------------\n")


def main():
    parser = argparse.ArgumentParser(description="End-to-End Local Demo Runner (No Cloud Required)")
    parser.add_argument("--threat", choices=["malicious", "false_positive"], default="malicious",
                        help="Threat scenario to inject (default: malicious).")
    parser.add_argument("--user", type=str, default=None,
                        help="Target user (default: u.lewis for malicious, l.taylor for false_positive).")
    args = parser.parse_args()

    target_user = args.user or ("u.lewis" if args.threat == "malicious" else "l.taylor")

    # Step 1: Generate logs
    scenario_data = step_1_generate_logs(threat_type=args.threat, target_user=target_user)

    # Step 2: Correlate
    alert = step_2_correlate_events(scenario_data)

    # Step 3: Run agent investigation
    result = step_3_run_agent_investigation(alert, threat_type=args.threat)

    # Step 4: Dispatch to SOC ticketing queue
    step_4_dispatch_ticket_locally(result["ticket"])


if __name__ == "__main__":
    main()

