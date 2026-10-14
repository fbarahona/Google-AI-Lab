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


def test_agent_sa_has_no_dataset_level_bigquery_write():
    """iam.tf: agent SA gets dataset READER plus table-level dataEditor on its four tables only."""
    import re
    from pathlib import Path

    iam_tf = (Path(__file__).resolve().parents[2] / "terraform" / "iam.tf").read_text()
    assert "google_bigquery_dataset_iam_member" not in iam_tf
    assert "google_bigquery_dataset_iam_binding" not in iam_tf

    reader = re.search(
        r'resource "google_bigquery_dataset_access" "agent_dataset_reader" \{(.*?)\n\}',
        iam_tf,
        re.DOTALL,
    )
    assert reader is not None
    assert 'role          = "READER"' in reader.group(1)
    assert "agent_sa.email" in reader.group(1)

    agent_tables = set(
        re.findall(
            r'resource "google_bigquery_table_iam_member" "agent_\w+" \{[^}]*?'
            r"google_bigquery_table\.(\w+)\.table_id[^}]*?agent_sa\.email",
            iam_tf,
            re.DOTALL,
        )
    )
    assert agent_tables == {
        "soc_tickets",
        "alerts",
        "adk_threat_assessment",
        "agent_events",
    }
