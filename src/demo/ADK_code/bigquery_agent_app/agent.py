"""
Defines the structure and logic of the multi-agent system for Cymbal Cyber.
Refactored to support the modern ADK Orchestrator and 4 specialized sub-agents:
- google_search_agent: researches IP addresses from security alerts with google_search tool
- bq_investigation_agent: answers questions about BigQuery data by executing SQL queries
- visual_analysis_agent: multimodal visual analysis of user desktop screenshots
- soc_ticketing_agent: evaluates findings and passes tickets to the SOC ticketing system
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
from google.adk.agents.callback_context import CallbackContext

try:
    from google.adk.plugins.bigquery_agent_analytics_plugin import BigQueryAgentAnalyticsPlugin
    HAS_ANALYTICS = True
except Exception:
    HAS_ANALYTICS = False

# Local Tools Imports
from bigquery_agent_app.logging_utils import setup_logging, log_agent_event
from .tools import (
    build_event_logs_query,
    log_false_positive,
    escalate_to_human,
    log_human_decision,
    create_rich_ticket_id,
    get_visual_analysis_for_user,
    get_gcs_uri_for_user,
    generate_signed_url,
    dispatch_to_soc_ticketing_system,
    bigquery_toolset
)

# --- Configuration ---
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "oso-ai-503519")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

warnings.filterwarnings("ignore", category=UserWarning, module="vertexai")
warnings.filterwarnings("ignore", category=UserWarning, module="google.adk")

setup_logging()

# --- Initialize Plugin ---
bq_analytics_plugin = None
if HAS_ANALYTICS:
    try:
        bq_analytics_plugin = BigQueryAgentAnalyticsPlugin(
            project_id=PROJECT_ID,
            dataset_id=DATASET_ID,
            table_id="agent_events"
        )
    except Exception as e:
        log_agent_event(f"BigQuery analytics plugin note: {e}")


# --- Custom Agent Classes ---
class OrchestratorAgent(SequentialAgent):
    """A custom SequentialAgent that includes an 'instruction' field."""
    instruction: str = "Orchestrate the workflow between sub-agents and pass incidents to SOC ticketing."


class ParallelOrchestratorAgent(ParallelAgent):
    """A custom ParallelAgent that includes an 'instruction' field."""
    instruction: str = "Run forensic investigation sub-agents in parallel."


# --- Agent Callbacks ---
def forbidden_dml_check(tool: BaseTool, args: Dict[str, Any], tool_context: ToolContext) -> Optional[Dict]:
    """Inspects SQL queries before execution to prevent destructive operations."""
    safe_args_str = json.dumps(args, default=str)
    log_agent_event(f"Tool '{tool.name}' was called with args: {safe_args_str[:120]}...")

    if tool.name == "execute_sql":
        try:
            sql_query = args.get("query")
            if sql_query:
                forbidden_dml = ["UPDATE", "DELETE", "MERGE", "TRUNCATE", "DROP", "ALTER"]
                normalized_query = sql_query.upper().strip()
                if any(re.search(rf"\b{keyword}\b", normalized_query) for keyword in forbidden_dml):
                    return {"result": "Tool execution was blocked: destructive DML statement detected."}
        except Exception:
            return {"result": "Error: SQL query not provided in tool arguments."}
    return None


def before_sub_agent_starts(callback_context: CallbackContext):
    """Logs the start of any sub-agent."""
    log_agent_event(f"{callback_context.agent_name} Agent has been triggered")


def log_agent_completion(callback_context: CallbackContext):
    """Logs final output to catch silent failures."""
    output = getattr(callback_context, "output", None) or getattr(callback_context, "result", None)
    if output:
        log_agent_event(f"[{callback_context.agent_name}] FINISHED. Output:\n{str(output)[:150]}...")
    else:
        log_agent_event(f"[{callback_context.agent_name}] FINISHED.")


# ==============================================================================
# 1. Google Search Investigator Agent
# ==============================================================================
google_search_agent = Agent(
    model=MODEL_NAME,
    name="google_search_agent",
    description="Agent that researches IP addresses from security alerts.",
    instruction="""
    You are an expert web researcher. Your task is to check the incoming security alert for IP addresses
    and then do a google search to check if they originate from high-risk countries like North Korea or Russia.

    **Instructions:**
    1. Extract all external public IP addresses from the provided security alert.
    2. If no external public IP addresses are found, respond with: "No IP address present and so no suspicious IP addresses were found"
    3. For each public IP, use web searches (e.g., IP lookup services, threat intelligence databases) to determine its:
       - Country of origin.
       - Associated threat intelligence and malicious history.
    4. Summarize your results and return it as an output for the decision agent.
    """,
    output_key="google_search_results",
    before_agent_callback=before_sub_agent_starts,
    after_agent_callback=log_agent_completion,
    tools=[google_search]
)


# ==============================================================================
# 2. BigQuery Data Investigator Agent
# ==============================================================================
bq_investigation_agent = Agent(
    model=MODEL_NAME,
    name="bq_investigation_agent",
    description="Agent that answers questions about BigQuery data by executing SQL queries.",
    instruction=f"""
    You are a Level 1 Security Operations Center (SOC) analyst.
    Your goal is to triage the network security alert provided and determine if it is a false positive or genuine security threat.

    **IMPORTANT INSTRUCTIONS:**
    1. Use the `build_event_logs_query` tool to retrieve a query that creates a 24-hour behavioral profile for the entity.
    2. Execute the query using the BigQuery toolset and analyze the results returned.
    3. Call the `get_gcs_uri_for_user` tool with the user from the alert to find the URI of any visual evidence.
    4. Summarize all your results in the correct format.
    
    NEVER, EVER DELETE OR MODIFY ANY EXISTING DATA IN BIGQUERY.
    All BigQuery queries MUST be run in project-id: '{PROJECT_ID}' on dataset `{DATASET_ID}`.
    """,
    tools=[get_gcs_uri_for_user, bigquery_toolset, build_event_logs_query],
    before_tool_callback=forbidden_dml_check,
    before_agent_callback=before_sub_agent_starts,
    after_agent_callback=log_agent_completion,
    output_key="bigquery_investigation_results"
)


# ==============================================================================
# 3. Visual Analysis Agent
# ==============================================================================
visual_analysis_agent = Agent(
    model=MODEL_NAME,
    name="visual_analysis_agent",
    description="Agent that analyzes user desktop screenshots using multi-modal AI to uncover forensic visual evidence.",
    instruction="""
    You are a digital forensics expert specialized in multimodal visual analysis.
    Your task is to analyze user desktop screenshots from Cloud Storage associated with security alerts.
    1. Call get_gcs_uri_for_user to obtain the screenshot URI.
    2. If a valid URI is returned, call get_visual_analysis_for_user to perform multimodal analysis and OCR.
    3. Call generate_signed_url to create a secure clickable image link for SOC analysts.
    4. Conclude whether visual evidence confirms hostile activity or benign operations.
    """,
    output_key="visual_analysis_results",
    tools=[get_visual_analysis_for_user, get_gcs_uri_for_user, generate_signed_url],
    before_agent_callback=before_sub_agent_starts,
    after_agent_callback=log_agent_completion
)


# ==============================================================================
# 4. SOC Ticketing & Decision Agent
# ==============================================================================
soc_ticketing_agent = Agent(
    model=MODEL_NAME,
    name="soc_ticketing_agent",
    description="Agent that consolidates findings, decides on best action to take, and passes tickets to the SOC ticketing system.",
    instruction="""
    You are the Senior SOC Decision Agent and Incident Handler.

    **INPUT DATA:**
    - Google Search Results: {google_search_results:}
    - BigQuery Investigation Results: {bigquery_investigation_results:}
    - Visual Analysis Results: {visual_analysis_results:}

    **YOUR GOAL:**
    Review all inputs and IMMEDIATELY trigger the correct workflow tool.

    **DECISION LOGIC:**
    1. IF THREAT DETECTED or ESCALATION NEEDED:
       - Call `create_rich_ticket_id` with the user ID.
       - Construct a structured markdown Security Incident Report.
       - Call `dispatch_to_soc_ticketing_system` (or `escalate_to_human`) to pass the ticket to the SOC ticketing system.

    2. IF FALSE POSITIVE:
       - Call `log_false_positive` with a detailed explanation.
    """,
    tools=[
        dispatch_to_soc_ticketing_system,
        generate_signed_url,
        bigquery_toolset,
        log_false_positive,
        escalate_to_human,
        log_human_decision,
        create_rich_ticket_id
    ],
    before_tool_callback=forbidden_dml_check,
    before_agent_callback=before_sub_agent_starts,
    after_agent_callback=log_agent_completion
)

# Decision agent alias
decision_agent = soc_ticketing_agent

# ==============================================================================
# Orchestrator Architecture
# ==============================================================================
investigation_team = ParallelOrchestratorAgent(
    name="InvestigationTeam",
    sub_agents=[bq_investigation_agent, google_search_agent, visual_analysis_agent],
    description="Executes the BigQuery investigator, Google Search agent, and Visual Analysis agent in parallel.",
    instruction="Execute research and data gathering tasks simultaneously."
)
investigation_agent = investigation_team

root_agent = OrchestratorAgent(
    name="WorkflowAgent",
    sub_agents=[investigation_team, soc_ticketing_agent],
    description="Executes a sequence of investigation agents and passes tickets to the SOC ticketing system.",
    before_agent_callback=before_sub_agent_starts,
    instruction="Route the security incident to the investigation team, then pass tickets to the SOC ticketing system."
)

# --- App Definition ---
app_plugins = [bq_analytics_plugin] if bq_analytics_plugin else []
app = App(
    name="CymbalCyberSecurityAgent",
    root_agent=root_agent,
    plugins=app_plugins
)
