"""
Unit tests for ADK Multi-Agent Architecture and Configurations.
"""

from adk_agent.agent import (
    bq_investigation_agent,
    google_search_agent,
    root_agent,
    soc_ticketing_agent,
    visual_analysis_agent,
)


def test_google_search_agent_specification():
    """Validates the exact required name, description, and tools for google_search_agent."""
    assert google_search_agent.name == "google_search_agent"
    assert (
        google_search_agent.description
        == "Agent that researches IP addresses from security alerts."
    )
    tool_names = [getattr(t, "name", str(t)) for t in google_search_agent.tools]
    assert any("google_search" in tn for tn in tool_names)


def test_bq_investigation_agent_specification():
    """Validates the exact required name, description, and tools for bq_investigation_agent."""
    assert bq_investigation_agent.name == "bq_investigation_agent"
    assert "BigQuery" in bq_investigation_agent.description
    tool_names = [
        getattr(t, "__name__", getattr(t, "name", str(t)))
        for t in bq_investigation_agent.tools
    ]
    assert any("get_entity_behavioral_profile" in tn for tn in tool_names)
    assert not any("execute_sql" in tn for tn in tool_names)
    assert len(bq_investigation_agent.tools) == 1


def test_visual_analysis_agent_specification():
    """Validates visual_analysis_agent configuration."""
    assert visual_analysis_agent.name == "visual_analysis_agent"
    assert "visual" in visual_analysis_agent.description.lower()
    tool_filter = visual_analysis_agent.tools[0].tool_filter
    assert isinstance(tool_filter, list)
    assert "get_visual_analysis_for_user" in tool_filter


def test_soc_ticketing_agent_specification():
    """Validates soc_ticketing_agent configuration."""
    assert soc_ticketing_agent.name == "soc_ticketing_agent"
    assert "SOC ticketing system" in soc_ticketing_agent.description
    tool_filter = soc_ticketing_agent.tools[0].tool_filter
    assert isinstance(tool_filter, list)
    assert "dispatch_to_soc_ticketing_system" in tool_filter


def test_orchestrator_subagents():
    """Validates that orchestrator coordinates all investigation and decision agents."""
    assert root_agent.name in ["SecurityInvestigationOrchestrator", "WorkflowAgent"]
    # Check that root agent has sub-agents
    assert len(root_agent.sub_agents) >= 2


def test_analytics_plugin_does_not_create_views():
    """The agent SA has no dataset-level create, so the plugin must not try to create views."""
    import pytest

    from adk_agent.agent import bq_analytics_plugin

    if bq_analytics_plugin is None:
        pytest.skip("BigQuery analytics plugin not available")
    assert bq_analytics_plugin.config.create_views is False


def _tf_resources(tf: str, kind: str) -> dict[str, str]:
    """Maps each resource of a kind to its body."""
    import re

    return dict(re.findall(rf'resource "{kind}" "(\w+)" \{{(.*?)\n\}}', tf, re.DOTALL))


def test_agent_sa_reaches_evidence_and_tickets_only_through_mcp():
    """iam.tf: the agent SA writes only its own bookkeeping tables and may invoke the MCP
    tool service; evidence reads, buckets, signing and ticket writes belong to the MCP SA."""
    from pathlib import Path

    iam_tf = (Path(__file__).resolve().parents[2] / "terraform" / "iam.tf").read_text()
    assert "google_bigquery_dataset_iam_member" not in iam_tf
    assert "google_bigquery_dataset_iam_binding" not in iam_tf

    def grants(kind: str, sa: str) -> set[str]:
        out = set()
        for body in _tf_resources(iam_tf, kind).values():
            if f"{sa}.email" in body or f"{sa}.name" in body:
                out.add(body)
        return out

    def tables(sa: str) -> set[str]:
        import re

        return {
            re.search(r"google_bigquery_table\.(\w+)\.table_id", body).group(1)
            for body in grants("google_bigquery_table_iam_member", sa)
        }

    # Agent SA: no dataset access, no buckets, no token creator; its own tables only.
    assert not grants("google_bigquery_dataset_access", "agent_sa")
    assert not grants("google_storage_bucket_iam_member", "agent_sa")
    assert not grants("google_service_account_iam_member", "agent_sa")
    assert tables("agent_sa") == {"alerts", "agent_events"}
    invoke = _tf_resources(iam_tf, "google_cloud_run_v2_service_iam_member")[
        "agent_invokes_mcp"
    ]
    assert "google_cloud_run_v2_service.mcp_server.name" in invoke
    assert "agent_sa.email" in invoke

    # MCP SA: reads the dataset, writes tickets, reads screenshots, files escalations.
    (reader,) = grants("google_bigquery_dataset_access", "mcp_sa")
    assert 'role          = "READER"' in reader
    assert tables("mcp_sa") == {"soc_tickets", "adk_threat_assessment"}
    assert len(grants("google_storage_bucket_iam_member", "mcp_sa")) == 2


def test_mcp_service_runs_as_its_own_sa_and_admits_only_the_agent():
    from pathlib import Path

    tf = (
        Path(__file__).resolve().parents[2] / "terraform" / "cloud_run.tf"
    ).read_text()
    services = _tf_resources(tf, "google_cloud_run_v2_service")
    mcp = services["mcp_server"]
    assert "google_service_account.mcp_sa.email" in mcp
    assert '"adk_agent.mcp_server", "--http"' in mcp
    assert "MCP_ALLOWED_CALLER" in mcp
    assert "google_service_account.agent_sa.email" in mcp
    assert "MCP_SERVER_URL" in services["adk_agent_service"]
    assert "allUsers" not in tf


def test_dev_ui_trusts_the_proxy_origin_only_while_enabled():
    """Through `gcloud run services proxy` the browser's origin is localhost, so ADK
    refuses to create sessions unless ALLOW_ORIGINS names it."""
    from pathlib import Path

    tf_dir = Path(__file__).resolve().parents[2] / "terraform"
    agent = _tf_resources(
        (tf_dir / "cloud_run.tf").read_text(), "google_cloud_run_v2_service"
    )["adk_agent_service"]
    assert '"ALLOW_ORIGINS"' in agent
    assert 'var.enable_adk_dev_ui ? [join(",", var.adk_dev_ui_origins)] : []' in agent
    assert '"http://localhost:8080"' in (tf_dir / "variables.tf").read_text()


def test_dev_ui_creates_sessions_from_the_proxy_origin():
    import os
    import subprocess
    import sys
    from pathlib import Path

    script = """
from fastapi.testclient import TestClient
import adk_agent.fast_api_app as f
c = TestClient(f.app, base_url="https://cymbal-cyber-adk-agent-x-ue.a.run.app")
r = c.post("/apps/adk_agent/users/u/sessions", json={},
           headers={"Origin": "http://127.0.0.1:8080"})
print(r.status_code)
"""
    root = Path(__file__).resolve().parents[4]
    base = {
        **os.environ,
        "LOCAL_MODE": "true",
        "ADK_DEV_UI": "true",
        "OTEL_TO_CLOUD": "false",
        "PYTHONPATH": str(root),
    }

    def status(origins: str) -> str:
        env = {**base, "ALLOW_ORIGINS": origins}
        out = subprocess.run(
            [sys.executable, "-c", script],
            env=env,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=180,
        )
        return out.stdout.strip().splitlines()[-1]

    assert status("") == "403"
    assert status("http://localhost:8080,http://127.0.0.1:8080") == "200"
