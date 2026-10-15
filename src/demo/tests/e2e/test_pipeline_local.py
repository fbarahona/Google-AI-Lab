"""
End-to-end pipeline test in LOCAL_MODE.

Synthetic logs -> alert -> the real ADK orchestrator (callbacks, security gate,
default-deny) -> real MCP servers over stdio -> real tools -> the local ticket queue
and archive the console reads. Only the model is scripted (see scripted_model.py).
"""

import json
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from google.genai import types

import adk_agent.agent as ag  # must precede anything that imports httpx
from adk_agent.tools import ticket_id_for_alert
from src.demo.data_generator.log_generator import SyntheticLogEngine
from src.demo.data_generator.sinks import LocalSink
from src.demo.scripted_model import ALERT_PREFIX, ScriptedLlm
from src.demo.soc_ticketing.models import AUTO_CLOSED_FP_DECISION
from src.demo.soc_ticketing.ticketing_service import SocTicketingService

pytestmark = pytest.mark.asyncio

AGENTS = (
    ag.google_search_agent,
    ag.bq_investigation_agent,
    ag.visual_analysis_agent,
    ag.soc_ticketing_agent,
)


def _mcp_toolsets(agent):
    return [t for t in agent.tools if isinstance(t, ag.ScopedMcpToolset)]


ALL_TOOLSETS = [ts for agent in AGENTS for ts in _mcp_toolsets(agent)]


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    """Points the agents and their MCP servers at a scratch work dir and queue."""
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService

    queue = tmp_path / "queue"
    env = {
        "LOCAL_MODE": "true",
        "LOCAL_QUEUE_DIR": str(queue),
        "LOCAL_LOGS_DIR": str(tmp_path / "logs"),
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    saved = [(a, a.model, list(a.tools)) for a in AGENTS]
    saved_params = [
        (
            ts,
            dict(ts._connection_params.server_params.env or {}),
            ts._connection_params.server_params.cwd,
        )
        for ts in ALL_TOOLSETS
    ]
    model = ScriptedLlm(model="scripted-e2e")
    for agent in AGENTS:
        agent.model = model
    ag.google_search_agent.tools = []  # built-in google_search needs a real model
    for ts in ALL_TOOLSETS:
        ts._connection_params.server_params.env.update(env)
        ts._connection_params.server_params.cwd = str(tmp_path)

    runner = Runner(
        app_name="e2e", agent=ag.root_agent, session_service=InMemorySessionService()
    )
    yield runner, model, queue

    for agent, agent_model, tools in saved:
        agent.model, agent.tools = agent_model, tools
    for ts, ts_env, cwd in saved_params:
        ts._connection_params.server_params.env = ts_env
        ts._connection_params.server_params.cwd = cwd


@asynccontextmanager
async def mcp_servers():
    """Closes the MCP server processes at the end, so the next test starts clean."""
    try:
        yield
    finally:
        for ts in ALL_TOOLSETS:
            await ts.close()


_window = datetime(2026, 10, 14, 10, 0, tzinfo=UTC)


def make_alert(threat_type: str, user: str, score: int) -> dict:
    """Writes the scenario's logs where the tools read them; returns its alert."""
    global _window
    _window += timedelta(minutes=2)
    access, network = SyntheticLogEngine(project_id="local-e2e").inject_threat(
        threat_type=threat_type, user_id=user
    )
    LocalSink(output_dir=os.environ["LOCAL_LOGS_DIR"]).write_events(access, network)
    login = next(a for a in access if a.get("user_id") == user)
    window_end = _window.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "alert_id": f"{user}|{window_end}",
        "schema_version": 1,
        "user_id": user,
        "device_id": login.get("device_id"),
        "source_ip": login.get("source_ip"),
        "window_end": window_end,
        "total_2_min_threat_score": score,
    }


async def investigate(runner, alert: dict) -> tuple[list[str], dict]:
    """Runs one alert through the orchestrator; returns tool calls and final state."""
    session = await runner.session_service.create_session(
        app_name="e2e", user_id="pubsub"
    )
    message = types.Content(
        role="user", parts=[types.Part(text=ALERT_PREFIX + json.dumps(alert))]
    )
    calls = []
    async for event in runner.run_async(
        user_id="pubsub", session_id=session.id, new_message=message
    ):
        for part in (event.content.parts if event.content else None) or []:
            if part.function_call:
                calls.append(part.function_call.name)
            if part.function_response and "SECURITY_GATE_VIOLATION" in json.dumps(
                part.function_response.response
            ):
                calls.append(f"BLOCKED:{part.function_response.name}")
    session = await runner.session_service.get_session(
        app_name="e2e", user_id="pubsub", session_id=session.id
    )
    return calls, dict(session.state)


def queued(queue: Path) -> dict[str, dict]:
    return {
        p.name: json.loads(p.read_text())
        for p in queue.glob("human_escalation_information_*.json")
    }


async def test_one_ticket_per_alert_with_redelivery(pipeline):
    runner, model, queue = pipeline
    model.soc_policy = "dispatch"
    first = make_alert("malicious", "u.lewis", 1950)
    second = make_alert("malicious", "u.lewis", 1850)

    async with mcp_servers():
        _, state = await investigate(runner, first)
        await investigate(runner, second)
        await investigate(runner, first)  # Pub/Sub redelivery of the same alert

    tickets = {t["ticket_id"]: t for t in queued(queue).values()}
    assert set(tickets) == {
        ticket_id_for_alert("u.lewis", first["alert_id"]),
        ticket_id_for_alert("u.lewis", second["alert_id"]),
    }
    assert state["ticket_dispatched"] is True
    ticket = tickets[ticket_id_for_alert("u.lewis", first["alert_id"])]
    assert ticket["severity"] == "CRITICAL"
    assert ticket["mitre_tactics"] == ["Credential Access"]
    assert "## Investigation Evidence" in ticket["structured_report"]


async def test_injection_blocks_false_positive_and_escalates_critical(pipeline):
    runner, model, queue = pipeline
    model.soc_policy = "try_fp"
    alert = make_alert("injection", "c.wilson", 1850)

    async with mcp_servers():
        calls, state = await investigate(runner, alert)

    assert "BLOCKED:log_false_positive" in calls
    assert state["prompt_injection_detected"] is True
    assert state["escalation_dispatched"] is True
    assert not state.get("false_positive_logged")
    (ticket,) = queued(queue).values()
    assert ticket["ticket_id"] == ticket_id_for_alert("c.wilson", alert["alert_id"])
    assert ticket["severity"] == "CRITICAL"


async def test_clean_false_positive_is_archived_for_review(pipeline):
    runner, model, queue = pipeline
    model.soc_policy = "try_fp"
    alert = make_alert("false_positive", "l.taylor", 120)

    async with mcp_servers():
        calls, state = await investigate(runner, alert)

    assert "BLOCKED:log_false_positive" not in calls
    assert state["false_positive_logged"] is True
    assert queued(queue) == {}  # nothing waits in the triage queue
    service = SocTicketingService(project_id="local-e2e")
    archived = [
        t
        for t in service.fetch_historic_tickets()
        if t.get("agent_decision") == AUTO_CLOSED_FP_DECISION
    ]
    assert [t["ticket_id"] for t in archived] == [
        ticket_id_for_alert("l.taylor", alert["alert_id"])
    ]
    assert service.fetch_dashboard_metrics()["auto_closed_alerts"] == 1


async def test_false_positive_without_screenshot_is_blocked(pipeline):
    runner, model, _ = pipeline
    model.soc_policy = "try_fp"
    alert = make_alert("false_positive", "t.wilson", 120)

    async with mcp_servers():
        calls, state = await investigate(runner, alert)

    assert "BLOCKED:log_false_positive" in calls
    assert state["evidence_unavailable"] is True
    assert state["escalation_dispatched"] is True
    assert not state.get("false_positive_logged")


async def test_skipped_visual_evidence_blocks_false_positive(pipeline):
    runner, model, _ = pipeline
    model.soc_policy = "try_fp"
    model.skip_visual = True
    alert = make_alert("false_positive", "l.taylor", 120)

    async with mcp_servers():
        calls, state = await investigate(runner, alert)

    assert "BLOCKED:log_false_positive" in calls
    assert not state.get("false_positive_logged")


async def test_failed_ticket_write_falls_back_to_default_deny(pipeline, tmp_path):
    """The SOC MCP server cannot store tickets: no lifecycle flag, then default-deny."""
    runner, model, queue = pipeline
    model.soc_policy = "dispatch"
    blocker = tmp_path / "unwritable"
    blocker.write_text("a file where the queue directory should be")
    for ts in _mcp_toolsets(ag.soc_ticketing_agent):
        ts._connection_params.server_params.env["LOCAL_QUEUE_DIR"] = str(blocker)
    alert = make_alert("malicious", "u.lewis", 1950)

    async with mcp_servers():
        _, state = await investigate(runner, alert)

    assert not state.get("ticket_dispatched")
    assert state["escalation_dispatched"] is True
    (ticket,) = queued(queue).values()
    assert ticket["ticket_id"] == ticket_id_for_alert(
        "u.lewis", alert["alert_id"], prefix="SOC-TICKET-AUTO-ESCALATED"
    )
    assert ticket["agent_decision"] == "AUTO_ESCALATED_DEFAULT_DENY"
