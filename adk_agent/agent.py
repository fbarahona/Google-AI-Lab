"""
Cymbal Cyber Multi-Agent Framework
==================================
Defines the structure and orchestration logic of the ADK multi-agent system:
- Orchestrator: Coordinates parallel investigation and final SOC resolution
- Sub-Agent 1: google_search_agent (Researches IP addresses from security alerts via Google Search)
- Sub-Agent 2: bq_investigation_agent (Answers questions about BigQuery data by executing SQL queries)
- Sub-Agent 3: visual_analysis_agent (Performs multimodal forensic visual analysis of user desktop screenshots)
- Sub-Agent 4: soc_ticketing_agent (Consolidates findings and passes tickets to the SOC ticketing system)
"""

import os
import re
import json
import warnings
from typing import Dict, Any, Optional

# --- ADK Imports ---
from google.adk.agents import Agent, SequentialAgent, ParallelAgent
from google.adk.tools import BaseTool, ToolContext, google_search
from google.adk.apps import App
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.agents.callback_context import CallbackContext

try:
    from google.adk.plugins.bigquery_agent_analytics_plugin import BigQueryAgentAnalyticsPlugin
    HAS_ANALYTICS = True
except Exception:
    BigQueryAgentAnalyticsPlugin = None
    HAS_ANALYTICS = False

import sys
from pathlib import Path

# Add directories to sys.path to support adk web / agents-cli execution
_CURRENT_DIR = Path(__file__).resolve().parent
_SRC_DIR = _CURRENT_DIR.parent.parent
for _p in [str(_CURRENT_DIR), str(_SRC_DIR), str(_CURRENT_DIR.parent)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# --- Local Imports ---
try:
    from .logging_utils import setup_logging, log_agent_event
    from .tools import (
        build_event_logs_query,
        get_visual_analysis_for_user,
        get_gcs_uri_for_user,
        generate_signed_url,
        dispatch_to_soc_ticketing_system,
        log_false_positive,
        create_rich_ticket_id,
        escalate_to_human,
        bigquery_toolset
    )
except ImportError:
    from logging_utils import setup_logging, log_agent_event
    from tools import (
        build_event_logs_query,
        get_visual_analysis_for_user,
        get_gcs_uri_for_user,
        generate_signed_url,
        dispatch_to_soc_ticketing_system,
        log_false_positive,
        create_rich_ticket_id,
        escalate_to_human,
        bigquery_toolset
    )

# --- Configuration ---
from dotenv import load_dotenv

load_dotenv()

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

warnings.filterwarnings("ignore", category=UserWarning, module="vertexai")
warnings.filterwarnings("ignore", category=UserWarning, module="google.adk")

setup_logging()

# --- Initialize BigQuery Analytics Plugin ---
bq_analytics_plugin = None
if HAS_ANALYTICS and BigQueryAgentAnalyticsPlugin is not None:
    try:
        bq_analytics_plugin = BigQueryAgentAnalyticsPlugin(
            project_id=PROJECT_ID,
            dataset_id=DATASET_ID,
            table_id="agent_events"
        )
    except Exception as e:
        log_agent_event(f"BigQuery analytics plugin initialization note: {e}")

# --- Custom Agent Classes for ADK Analytics Plugin Compatibility ---
class OrchestratorAgent(SequentialAgent):
    """Sequential orchestrator with explicit instruction attribute for analytics logging."""
    instruction: str = "Orchestrate security workflow between investigation agents and SOC ticketing."


class ParallelOrchestratorAgent(ParallelAgent):
    """Parallel orchestrator with explicit instruction attribute for analytics logging."""
    instruction: str = "Run multi-source forensic investigations simultaneously in parallel."


# --- Callbacks ---
def forbidden_dml_check(tool: BaseTool, args: Dict[str, Any], tool_context: ToolContext) -> Optional[Dict]:
    """Inspects SQL queries prior to execution to prevent destructive DML operations."""
    safe_args_str = json.dumps(args, default=str)
    log_agent_event(f"Tool '{tool.name}' called with arguments: {safe_args_str[:120]}...")

    if tool.name == "execute_sql":
        sql_query = args.get("query", "")
        if sql_query:
            forbidden_dml = ["UPDATE", "DELETE", "MERGE", "TRUNCATE", "DROP", "ALTER", "INSERT", "CREATE", "GRANT", "REVOKE"]
            normalized_query = sql_query.upper().strip()
            if any(re.search(rf"\b{kw}\b", normalized_query) for kw in forbidden_dml):
                return {"result": "Tool execution was blocked: Destructive DML operations are not permitted."}
    return None


def before_sub_agent_starts(callback_context: CallbackContext):
    """Logs the activation of any agent."""
    log_agent_event(f"Agent triggered: {callback_context.agent_name}", callback_context.agent_name)


def log_agent_completion(callback_context: CallbackContext):
    """Logs completion status of sub-agents."""
    output = getattr(callback_context, "output", None) or getattr(callback_context, "result", None)
    log_agent_event(f"Completed execution. Output summary: {str(output)[:150]}...", callback_context.agent_name)


# ==============================================================================
# SUB-AGENT 1: Google Search Investigator
# ==============================================================================
google_search_agent = Agent(
    model=MODEL_NAME,
    name="google_search_agent",
    description="Agent that researches IP addresses from security alerts.",
    instruction="""
    You are an expert OSINT and cyber threat intelligence web researcher.
    Your task is to inspect incoming security alerts for external IP addresses and perform Google searches
    to determine geographical origin, ISP/hosting provider, known malicious reputation, and threat intelligence.

    **Instructions:**
    1. Extract all external public IP addresses from the alert context.
    2. If no external public IP is present (or only private RFC-1918 IPs like 10.x.x.x exist), respond:
       "No external public IP address present in alert; no suspicious foreign IPs identified."
    3. For each public IP address:
       - Use google_search to look up IP threat intelligence, country of origin, abuse reports, or TOR/VPN nodes.
       - Highlight if the IP originates from high-risk or sanctioned jurisdictions (e.g., North Korea, Russia, Iran).
    4. Summarize your findings concisely with risk indicators for the decision and ticketing agent.
    """,
    output_key="google_search_results",
    before_agent_callback=before_sub_agent_starts,
    after_agent_callback=log_agent_completion,
    tools=[google_search]
)


# ==============================================================================
# SUB-AGENT 2: BigQuery Data Investigator
# ==============================================================================
bq_investigation_agent = Agent(
    model=MODEL_NAME,
    name="bq_investigation_agent",
    description="Agent that answers questions about BigQuery data by executing SQL queries.",
    instruction=f"""
    You are a Level 1 Security Operations Center (SOC) BigQuery data investigator.
    Your task is to query BigQuery to analyze behavioral anomalies and answer questions about event data.

    **Instructions:**
    1. Call `build_event_logs_query` passing the `user_id` from the alert to obtain the 24-hour parameterized SQL behavioral query and its QueryJobConfig.
    2. Use the BigQuery toolset (`execute_sql`) to execute the query against dataset `{DATASET_ID}` in project `{PROJECT_ID}`.
    3. Analyze the results:
       - Access Metrics: Total access events, login failures, distinct public source IPs, suspicious user agents (curl, python-requests).
       - Network Metrics: High privilege requests (admin/root), risky file transfers (.exe, .ps1, .dll), malicious command execution (mimikatz, powershell -enc), and C2 DNS queries.
    4. Summarize your findings into clear behavioral risk indicators.
    
    NEVER EXECUTE ANY DML OR DESTRUCTIVE STATEMENTS (UPDATE, DELETE, DROP).
    """,
    output_key="bigquery_investigation_results",
    tools=[build_event_logs_query, bigquery_toolset],
    before_tool_callback=forbidden_dml_check,
    before_agent_callback=before_sub_agent_starts,
    after_agent_callback=log_agent_completion
)


# ==============================================================================
# SUB-AGENT 3: Visual Analysis Agent (Multimodal Vision)
# ==============================================================================
visual_analysis_agent = Agent(
    model=MODEL_NAME,
    name="visual_analysis_agent",
    description="Agent that analyzes user desktop screenshots using multi-modal AI to uncover forensic visual evidence.",
    instruction=f"""
    You are a digital forensics and visual evidence investigator.
    Your task is to locate and visually inspect the desktop screenshot evidence associated with the user in the security alert.

    **Instructions:**
    1. Call `get_gcs_uri_for_user` using the `user_id` from the alert to find the screenshot GCS URI (starts with 'gs://').
    2. If a valid GCS URI is returned:
       - Call `get_visual_analysis_for_user` with that exact GCS URI to perform multimodal analysis and OCR.
       - Call `generate_signed_url` with that GCS URI to generate a clickable preview link.
    3. Return a structured visual summary containing:
       - Visual findings and OCR terminal observations.
       - Visual evidence verdict: Does the desktop screenshot confirm malicious activity (e.g. open terminal running exploit) or benign activity?
       - Clickable signed screenshot URL.
    """,
    output_key="visual_analysis_results",
    tools=[get_visual_analysis_for_user, get_gcs_uri_for_user, generate_signed_url],
    before_agent_callback=before_sub_agent_starts,
    after_agent_callback=log_agent_completion
)


# ==============================================================================
# SUB-AGENT 4: SOC Ticketing & Decision Agent
# ==============================================================================
soc_ticketing_agent = Agent(
    model=MODEL_NAME,
    name="soc_ticketing_agent",
    description="Agent that consolidates findings, decides on best action to take, and passes tickets to the SOC ticketing system.",
    instruction="""
    You are the Senior Incident Commander and SOC Decision Agent.
    
    **INPUTS:**
    - External Intelligence: {google_search_results:}
    - BigQuery Behavioral Analysis: {bigquery_investigation_results:}
    - Visual Evidence Analysis: {visual_analysis_results:}

    **YOUR GOAL:**
    Evaluate all findings and determine whether the incident is a GENUINE THREAT or a FALSE POSITIVE.
    Then immediately execute the appropriate tool action:

    **DECISION MATRIX:**
    1. **IF GENUINE THREAT or ESCALATION NEEDED:**
       - Call `create_rich_ticket_id` with the user_id to generate a unique ticket ID.
       - Construct a comprehensive markdown **Security Incident Report**:
         ### Security Incident Report
         **1. Alert Overview:** User, Device, Threat Score, Verdict
         **2. Behavioral Findings:** BigQuery correlated access and network metrics
         **3. Visual Forensics:** Screenshot observations and signed image URL
         **4. External Threat Intelligence:** IP reputation and geolocation
       - Call `dispatch_to_soc_ticketing_system` with the ticket_id, alert payload, agent reason, structured report, and severity.

    2. **IF FALSE POSITIVE:**
       - Call `log_false_positive` explaining why the alert represents benign activity (e.g. normal user, no foreign IP, benign commands).

    **RULES:**
    - No conversational banter. Your primary action must be invoking the correct resolution tool.
    """,
    tools=[
        dispatch_to_soc_ticketing_system,
        log_false_positive,
        create_rich_ticket_id,
        generate_signed_url,
        escalate_to_human
    ],
    before_tool_callback=forbidden_dml_check,
    before_agent_callback=before_sub_agent_starts,
    after_agent_callback=log_agent_completion
)


# ==============================================================================
# ORCHESTRATION ARCHITECTURE: Parallel Investigation + SOC Ticketing Resolution
# ==============================================================================

# Phase 1: Parallel Investigation Team (3 specialized investigation sub-agents)
investigation_team = ParallelOrchestratorAgent(
    name="InvestigationTeam",
    sub_agents=[google_search_agent, bq_investigation_agent, visual_analysis_agent],
    description="Executes Google Search OSINT, BigQuery log analysis, and visual evidence investigation simultaneously in parallel.",
    instruction="Execute multi-source investigation agents simultaneously."
)

# Phase 2: Complete End-to-End Orchestrator
orchestrator_agent = OrchestratorAgent(
    name="SecurityInvestigationOrchestrator",
    sub_agents=[investigation_team, soc_ticketing_agent],
    description="Orchestrates full security investigation workflow and dispatches tickets to the SOC ticketing system.",
    instruction="Coordinate investigation team and pass final incident to SOC ticketing system.",
    before_agent_callback=before_sub_agent_starts
)

# Backward Compatibility Aliases
root_agent = orchestrator_agent
decision_agent = soc_ticketing_agent
investigation_agent = investigation_team

# --- App Definition ---
app_plugins: list[BasePlugin] = [bq_analytics_plugin] if bq_analytics_plugin else []
app = App(
    name="CymbalCyberSecurityAgent",
    root_agent=root_agent,
    plugins=app_plugins
)

