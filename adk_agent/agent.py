"""
Cymbal Cyber Multi-Agent Framework
==================================
Defines the structure and orchestration logic of the ADK multi-agent system:
- Orchestrator: Coordinates parallel investigation and final SOC resolution
- Sub-Agent 1: google_search_agent (Researches IP addresses from security alerts via Google Search)
- Sub-Agent 2: bq_investigation_agent (Analyzes BigQuery behavioral telemetry using parameterized profile queries)
- Sub-Agent 3: visual_analysis_agent (Performs multimodal forensic visual analysis of user desktop screenshots)
- Sub-Agent 4: soc_ticketing_agent (Consolidates findings and passes tickets to the SOC ticketing system)
"""

import warnings

# --- ADK Imports ---
from google.adk.agents import Agent, ParallelAgent, SequentialAgent
from google.adk.apps import App
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools import google_search

try:
    from google.adk.plugins.bigquery_agent_analytics_plugin import (
        BigQueryAgentAnalyticsPlugin,
        BigQueryLoggerConfig,
    )

    HAS_ANALYTICS = True
except Exception:
    BigQueryAgentAnalyticsPlugin = None
    HAS_ANALYTICS = False

# --- Local Imports ---
# Re-exported names keep `from adk_agent.agent import X` working for code and tests
# written before the guardrails, prompts and MCP wiring moved to their own modules.
from adk_agent.guardrails.evidence_state import (  # noqa: F401
    _COLLECTED_FLAG_BY_TOOL,
    _EVIDENCE_FLAGS,
    _EVIDENCE_SOURCES,
    _EVIDENCE_TOOLS,
    _LIFECYCLE_FLAG_BY_TOOL,
    _USER_ARG_BY_TOOL,
    EVIDENCE_APPENDIX_HEADING,
    append_investigation_evidence,
    mcp_tool_error_callback,
    sync_mcp_security_state_callback,
)
from adk_agent.guardrails.lifecycle import (
    before_orchestrator_starts,
    before_sub_agent_starts,
    log_agent_completion,
)
from adk_agent.guardrails.search_privacy import (  # noqa: F401
    NO_PUBLIC_IP_RESULT,
    _content_text,
    search_input_minimization_callback,
    search_query_audit_callback,
)
from adk_agent.guardrails.security_gate import (  # noqa: F401
    _ALERT_KEY_ALIASES,
    _REPORT_ARG_BY_TOOL,
    _TICKET_ID_TOOLS,
    _assign_ticket_id,
    _escalated,
    _pin_alert_identity,
    default_deny_soc_callback,
    security_gate_callback,
)
from adk_agent.logging_utils import log_agent_event
from adk_agent.mcp_client import (  # noqa: F401
    MCP_SERVER_URL,
    MCP_TOOL_TIMEOUT_SECONDS,
    McpIdTokenProvider,
    ScopedMcpToolset,
    _mcp_header_provider,
    create_mcp_toolset,
    default_deny_mcp,
    mcp_audience,
    mcp_connection_params,
)
from adk_agent.prompts import (
    BQ_INVESTIGATION_INSTRUCTION,
    GOOGLE_SEARCH_INSTRUCTION,
    SOC_TICKETING_INSTRUCTION,
    VISUAL_ANALYSIS_INSTRUCTION,
)
from adk_agent.settings import (  # noqa: F401
    DATASET_ID,
    LOCAL_MODE,
    MODEL_NAME,
    PROJECT_ID,
    REPO_ROOT,
)

# --- Configuration ---

warnings.filterwarnings("ignore", category=UserWarning, module="vertexai")
warnings.filterwarnings("ignore", category=UserWarning, module="google.adk")


# --- Initialize BigQuery Analytics Plugin ---
# Off in LOCAL_MODE: there is no BigQuery to write to, and the plugin would keep
# retrying credentials in the background.
bq_analytics_plugin = None
if not LOCAL_MODE and HAS_ANALYTICS and BigQueryAgentAnalyticsPlugin is not None:
    try:
        # create_views=False: per-event views need dataset-level tables.create, which
        # the agent SA deliberately lacks (it has dataset READER + table-level writes).
        bq_analytics_plugin = BigQueryAgentAnalyticsPlugin(
            project_id=PROJECT_ID,
            dataset_id=DATASET_ID,
            table_id="agent_events",
            config=BigQueryLoggerConfig(create_views=False),
        )
    except Exception as e:
        log_agent_event(f"BigQuery analytics plugin initialization note: {e}")


# --- Custom Agent Classes for ADK Analytics Plugin Compatibility ---
class OrchestratorAgent(SequentialAgent):
    """Sequential orchestrator with explicit instruction attribute for analytics logging."""

    instruction: str = (
        "Orchestrate security workflow between investigation agents and SOC ticketing."
    )


class ParallelOrchestratorAgent(ParallelAgent):
    """Parallel orchestrator with explicit instruction attribute for analytics logging."""

    instruction: str = (
        "Run multi-source forensic investigations simultaneously in parallel."
    )


# ==============================================================================
# SUB-AGENT 1: Google Search Investigator
# ==============================================================================
google_search_agent = Agent(
    model=MODEL_NAME,
    name="google_search_agent",
    description="Agent that researches IP addresses from security alerts.",
    instruction=GOOGLE_SEARCH_INSTRUCTION,
    output_key="google_search_results",
    before_agent_callback=before_sub_agent_starts,
    before_model_callback=search_input_minimization_callback,
    after_model_callback=search_query_audit_callback,
    after_agent_callback=log_agent_completion,
    tools=[google_search],
)


# ==============================================================================
# SUB-AGENT 2: BigQuery Data Investigator
# ==============================================================================
bq_investigation_agent = Agent(
    model=MODEL_NAME,
    name="bq_investigation_agent",
    description="Agent that analyzes BigQuery behavioral telemetry by querying historical access and network events.",
    instruction=BQ_INVESTIGATION_INSTRUCTION,
    output_key="bigquery_investigation_results",
    tools=[create_mcp_toolset(["get_entity_behavioral_profile"])],
    before_agent_callback=before_sub_agent_starts,
    after_agent_callback=log_agent_completion,
    after_tool_callback=sync_mcp_security_state_callback,
    on_tool_error_callback=mcp_tool_error_callback,
)


# ==============================================================================
# SUB-AGENT 3: Visual Analysis Agent (Multimodal Vision)
# ==============================================================================
visual_analysis_agent = Agent(
    model=MODEL_NAME,
    name="visual_analysis_agent",
    description="Agent that analyzes user desktop screenshots using multi-modal AI to uncover forensic visual evidence.",
    instruction=VISUAL_ANALYSIS_INSTRUCTION,
    output_key="visual_analysis_results",
    tools=[
        create_mcp_toolset(
            [
                "get_visual_analysis_for_user",
                "get_gcs_uri_for_user",
                "generate_signed_url",
            ],
            toolset_name="visual_analysis_mcp",
        ),
    ],
    before_agent_callback=before_sub_agent_starts,
    after_agent_callback=log_agent_completion,
    after_tool_callback=sync_mcp_security_state_callback,
    on_tool_error_callback=mcp_tool_error_callback,
)


# ==============================================================================
# SUB-AGENT 4: SOC Ticketing & Decision Agent
# ==============================================================================
soc_ticketing_agent = Agent(
    model=MODEL_NAME,
    name="soc_ticketing_agent",
    description="Agent that consolidates findings, decides on best action to take, and passes tickets to the SOC ticketing system.",
    instruction=SOC_TICKETING_INSTRUCTION,
    tools=[
        create_mcp_toolset(
            [
                "dispatch_to_soc_ticketing_system",
                "log_false_positive",
                "create_rich_ticket_id",
                "generate_signed_url",
                "escalate_to_human",
            ],
            toolset_name="soc_ticketing_mcp",
        ),
    ],
    before_tool_callback=security_gate_callback,
    before_agent_callback=before_sub_agent_starts,
    after_agent_callback=default_deny_soc_callback,
    after_tool_callback=sync_mcp_security_state_callback,
    on_tool_error_callback=mcp_tool_error_callback,
)


# ==============================================================================
# ORCHESTRATION ARCHITECTURE: Parallel Investigation + SOC Ticketing Resolution
# ==============================================================================

# Phase 1: Parallel Investigation Team (3 specialized investigation sub-agents)
investigation_team = ParallelOrchestratorAgent(
    name="InvestigationTeam",
    sub_agents=[google_search_agent, bq_investigation_agent, visual_analysis_agent],
    description="Executes Google Search OSINT, BigQuery log analysis, and visual evidence investigation simultaneously in parallel.",
    instruction="Execute multi-source investigation agents simultaneously.",
)

# Phase 2: Complete End-to-End Orchestrator
orchestrator_agent = OrchestratorAgent(
    name="SecurityInvestigationOrchestrator",
    sub_agents=[investigation_team, soc_ticketing_agent],
    description="Orchestrates full security investigation workflow and dispatches tickets to the SOC ticketing system.",
    instruction="Coordinate investigation team and pass final incident to SOC ticketing system.",
    before_agent_callback=before_orchestrator_starts,
)

# Backward Compatibility Aliases
root_agent = orchestrator_agent
decision_agent = soc_ticketing_agent
investigation_agent = investigation_team

# --- App Definition ---
app_plugins: list[BasePlugin] = [bq_analytics_plugin] if bq_analytics_plugin else []
app = App(name="CymbalCyberSecurityAgent", root_agent=root_agent, plugins=app_plugins)
