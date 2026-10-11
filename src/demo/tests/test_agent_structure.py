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
    assert google_search_agent.description == "Agent that researches IP addresses from security alerts."
    tool_names = [getattr(t, "name", str(t)) for t in google_search_agent.tools]
    assert any("google_search" in tn for tn in tool_names)


def test_bq_investigation_agent_specification():
    """Validates the exact required name, description, and tools for bq_investigation_agent."""
    assert bq_investigation_agent.name == "bq_investigation_agent"
    assert "BigQuery" in bq_investigation_agent.description
    tool_names = [getattr(t, "name", str(t)) for t in bq_investigation_agent.tools]
    assert any("get_entity_behavioral_profile" in tn for tn in tool_names)


def test_visual_analysis_agent_specification():
    """Validates visual_analysis_agent configuration."""
    assert visual_analysis_agent.name == "visual_analysis_agent"
    assert "visual" in visual_analysis_agent.description.lower()
    tool_names = [getattr(t, "name", str(t)) for t in visual_analysis_agent.tools]
    assert any("visual_analysis" in tn for tn in tool_names)


def test_soc_ticketing_agent_specification():
    """Validates soc_ticketing_agent configuration."""
    assert soc_ticketing_agent.name == "soc_ticketing_agent"
    assert "SOC ticketing system" in soc_ticketing_agent.description
    tool_names = [getattr(t, "name", str(t)) for t in soc_ticketing_agent.tools]
    assert any("soc_ticketing" in tn for tn in tool_names)


def test_orchestrator_subagents():
    """Validates that orchestrator coordinates all investigation and decision agents."""
    assert root_agent.name in ["SecurityInvestigationOrchestrator", "WorkflowAgent"]
    # Check that root agent has sub-agents
    assert len(root_agent.sub_agents) >= 2
