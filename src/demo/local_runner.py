"""
Local end-to-end demo runner (no cloud required)
================================================
Runs one threat scenario through the same code the cloud runs:

1. Generates synthetic access and network logs with an injected threat.
2. Scores them with the detector's rules (adk_agent.detection_rules, the Python twin
   of the BigQuery UDFs) in 2-minute windows and builds the alert contract.
3. Sends the alert to the real ADK orchestrator: the parallel investigation team,
   the real MCP tool servers, the security gate and default-deny.
4. The SOC ticketing agent's tools write the ticket to the local queue the
   Streamlit console reads.

Only the model can be swapped. By default a scripted model makes the agents'
choices (no credentials needed), and for the injection and false-positive scenarios
it deliberately tries to close the alert as a false positive, so you can watch the
security gate decide. --live-model uses Gemini instead (needs Vertex AI or an API
key in the environment).

Usage (from the repository root):
  uv run python -m src.demo.local_runner --threat malicious
  uv run python -m src.demo.local_runner --threat injection
  uv run python -m src.demo.local_runner --threat false_positive --live-model
"""

import argparse
import asyncio
import json
import logging
import os
import shutil
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_USERS = {
    "malicious": "u.lewis",
    "injection": "c.wilson",
    "false_positive": "l.taylor",
}
# Scripted SOC behaviour per scenario: dispatch a genuine threat, or try to close the
# alert as a false positive so the security gate has something to decide.
SCRIPTED_POLICY = {
    "malicious": "dispatch",
    "injection": "try_fp",
    "false_positive": "try_fp",
}
WINDOW = timedelta(minutes=2)
ALERT_MIN_SCORE = 100


def banner(text: str) -> None:
    print(f"\n{'=' * 64}\n{text}\n{'=' * 64}")


def generate_logs(threat_type: str, user: str, logs_dir: Path) -> None:
    """Writes this run's telemetry, replacing the previous run's local logs."""
    from src.demo.data_generator.log_generator import SyntheticLogEngine
    from src.demo.data_generator.sinks import LocalSink

    banner("[1] Generating synthetic telemetry")
    shutil.rmtree(logs_dir, ignore_errors=True)
    engine = SyntheticLogEngine(project_id="local-demo")
    sink = LocalSink(output_dir=str(logs_dir))
    benign_access, benign_network = engine.generate_benign_batch(50)
    sink.write_events(benign_access, benign_network)
    access, network = engine.inject_threat(threat_type=threat_type, user_id=user)
    sink.write_events(access, network)
    print(f"  {len(benign_access) + len(benign_network)} benign events")
    print(
        f"  {len(access) + len(network)} events for the '{threat_type}' scenario ({user})"
    )


def _read_events(logs_dir: Path, pattern: str) -> list[dict[str, Any]]:
    events = []
    for path in sorted(logs_dir.glob(pattern)):
        with open(path, encoding="utf-8") as f:
            events.extend(json.loads(line) for line in f if line.strip())
    return events


def _window_end(timestamp: str) -> datetime:
    ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    ts = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    start = ts.replace(second=0, microsecond=0) - timedelta(minutes=ts.minute % 2)
    return start + WINDOW


def detect(user: str, logs_dir: Path) -> dict[str, Any] | None:
    """
    The scheduled detector's MERGE, in Python: network events joined to the VPN
    session that was assigned their source IP, scored per event with the shared
    rules and summed per user and 2-minute window. Returns the target user's
    highest-scoring window as an alert, or None if no window reaches the threshold.
    """
    from adk_agent import detection_rules as rules

    banner("[2] Scoring telemetry in 2-minute windows (detector rules)")
    sessions = {
        ev["assigned_internal_ip"]: ev
        for ev in _read_events(logs_dir, "access_events*.jsonl")
        if ev.get("event_type") == "login_success" and ev.get("assigned_internal_ip")
    }
    windows: dict[tuple[str, datetime], int] = defaultdict(int)
    for ev in _read_events(logs_dir, "network_events*.jsonl"):
        session = sessions.get(ev.get("source_ip"))
        if session is None:
            continue
        key = (session["user_id"], _window_end(ev["event_timestamp"]))
        windows[key] += rules.threat_score(
            {**ev, "user_agent": session.get("user_agent")}
        )

    user_windows = {end: score for (u, end), score in windows.items() if u == user}
    for end, score in sorted(user_windows.items()):
        print(f"  {user} window ending {end:%H:%M:%S}: score {score}")
    if not user_windows or max(user_windows.values()) < ALERT_MIN_SCORE:
        print(f"  No window reached the alert threshold ({ALERT_MIN_SCORE}).")
        return None

    window_end, score = max(user_windows.items(), key=lambda item: item[1])
    session = next(s for s in sessions.values() if s["user_id"] == user)
    window_end_str = window_end.strftime("%Y-%m-%dT%H:%M:%SZ")
    alert = {
        "alert_id": f"{user}|{window_end_str}",
        "schema_version": 1,
        "engine": "local",
        "user_id": user,
        "device_id": session.get("device_id"),
        "source_ip": session.get("source_ip"),
        "window_end": window_end_str,
        "total_2_min_threat_score": score,
    }
    print(f"  Alert: {json.dumps(alert)}")
    return alert


async def investigate(
    alert: dict[str, Any], threat_type: str, live_model: bool
) -> dict[str, Any]:
    """Runs the alert through the real orchestrator; prints each tool call."""
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService
    from google.genai import types

    import adk_agent.agent as ag
    from src.demo.scripted_model import ALERT_PREFIX, ScriptedLlm

    # The runner prints each tool call and gate decision itself.
    logging.getLogger("google_adk").setLevel(logging.ERROR)
    logging.getLogger("CymbalCyberADK").setLevel(logging.WARNING)

    model_name = "Gemini (live)" if live_model else "scripted model"
    banner(f"[3] Investigating with the ADK orchestrator ({model_name})")
    if not live_model:
        model = ScriptedLlm(
            model="scripted-local", soc_policy=SCRIPTED_POLICY[threat_type]
        )
        for agent in (
            ag.google_search_agent,
            ag.bq_investigation_agent,
            ag.visual_analysis_agent,
            ag.soc_ticketing_agent,
        ):
            agent.model = model
        ag.google_search_agent.tools = []  # Google Search grounding needs a real model

    runner = Runner(
        app_name="local-demo",
        agent=ag.root_agent,
        session_service=InMemorySessionService(),
    )
    session = await runner.session_service.create_session(
        app_name="local-demo", user_id="local"
    )
    message = types.Content(
        role="user", parts=[types.Part(text=ALERT_PREFIX + json.dumps(alert))]
    )
    try:
        async for event in runner.run_async(
            user_id="local", session_id=session.id, new_message=message
        ):
            for part in (event.content.parts if event.content else None) or []:
                if part.function_call:
                    print(f"  [{event.author}] calls {part.function_call.name}")
                if part.function_response:
                    response = json.dumps(part.function_response.response, default=str)
                    if "SECURITY_GATE_VIOLATION" in response:
                        print(f"  SECURITY GATE blocked {part.function_response.name}")
    finally:
        for agent in (
            ag.bq_investigation_agent,
            ag.visual_analysis_agent,
            ag.soc_ticketing_agent,
        ):
            for toolset in agent.tools:
                if isinstance(toolset, ag.ScopedMcpToolset):
                    await toolset.close()
    session = await runner.session_service.get_session(
        app_name="local-demo", user_id="local", session_id=session.id
    )
    return dict(session.state)


def report(state: dict[str, Any]) -> None:
    from src.demo.soc_ticketing.ticketing_service import SocTicketingService

    banner("[4] Outcome")
    flags = (
        "prompt_injection_detected",
        "malicious_indicators",
        "evidence_unavailable",
        "telemetry_evidence_collected",
        "visual_evidence_collected",
    )
    for flag in flags:
        print(f"  {flag}: {bool(state.get(flag))}")
    if state.get("ticket_dispatched"):
        outcome = "Incident ticket dispatched to the triage queue."
    elif state.get("escalation_dispatched"):
        outcome = "Escalated to a human analyst (triage queue)."
    elif state.get("false_positive_logged"):
        outcome = "Closed as a false positive (archived as 'Auto-closed by agent')."
    else:
        outcome = "No resolution recorded."
    print(f"\n  {outcome}")
    print(f"  Ticket: {state.get('ticket_id')}")
    print(f"  Local queue: {SocTicketingService().queue_dir}")
    print(
        "\n  Open the console with:\n"
        "  LOCAL_MODE=true uv run python -m streamlit run "
        "src/demo/soc_ticketing/streamlit_soc_console.py"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--threat", choices=sorted(DEFAULT_USERS), default="malicious")
    parser.add_argument("--user", help="Target user (default depends on --threat).")
    parser.add_argument(
        "--live-model",
        action="store_true",
        help="Use Gemini instead of the scripted model (needs model credentials).",
    )
    args = parser.parse_args()
    user = args.user or DEFAULT_USERS[args.threat]

    # Before adk_agent is imported: the agents read these when they are built.
    os.environ["LOCAL_MODE"] = "true"
    logs_dir = Path(
        os.environ.setdefault(
            "LOCAL_LOGS_DIR", str(REPO_ROOT / "local_demo_data" / "logs")
        )
    )

    generate_logs(args.threat, user, logs_dir)
    alert = detect(user, logs_dir)
    if alert is None:
        return
    state = asyncio.run(investigate(alert, args.threat, args.live_model))
    report(state)


if __name__ == "__main__":
    main()
