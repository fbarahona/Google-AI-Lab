"""
Configuration and cloud clients shared by every tool, plus the session-state helper.

The clients are created lazily, once per process. Tool modules call them through this
module (clients.get_bq_client()), so a test fakes cloud access in one place.
"""

import os
from typing import Any

from google import genai
from google.adk.tools import ToolContext
from google.cloud import bigquery

from adk_agent.settings import DATASET_ID, PROJECT_ID
from src.demo.soc_ticketing.ticketing_service import SocTicketingService

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Project configuration
LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-east1")
BIGQUERY_ADK_THREAT_ASSESSMENT = f"{PROJECT_ID}.{DATASET_ID}.adk_threat_assessment"
GCS_ESCALATION_BUCKET = os.getenv(
    "ESCALATION_BUCKET", f"cymbal-cyber-adk-escalations-bucket_{PROJECT_ID}"
)
SCREENSHOTS_BUCKET = os.getenv(
    "SCREENSHOTS_BUCKET", f"cymbal-cyber-screenshots_{PROJECT_ID}"
)
AGENT_SERVICE_ACCOUNT_NAME = os.getenv("AGENT_SERVICE_ACCOUNT", "cymbal-adk-agent-sa")
GCS_SIGNER_SERVICE_ACCOUNT = os.getenv(
    "GCS_SIGNER_SA",
    f"{AGENT_SERVICE_ACCOUNT_NAME}@{PROJECT_ID}.iam.gserviceaccount.com",
)

# Initialize GenAI Client
_genai_client = None


def get_genai_client():
    global _genai_client
    if _genai_client is None:
        _genai_client = genai.Client(
            vertexai=True, project=PROJECT_ID, location=LOCATION
        )
    return _genai_client


# Initialize BigQuery Client
_bq_client = None


def get_bq_client():
    """BigQuery client on Application Default Credentials (the service's SA in the cloud)."""
    global _bq_client
    if _bq_client is None:
        _bq_client = bigquery.Client(project=PROJECT_ID)
    return _bq_client


# Initialize SOC Ticketing Service
_soc_service = None


def get_soc_service():
    global _soc_service
    if _soc_service is None:
        _soc_service = SocTicketingService(
            project_id=PROJECT_ID,
            dataset_id=DATASET_ID,
            escalation_bucket=GCS_ESCALATION_BUCKET,
        )
    return _soc_service


def _set_state(tool_context: ToolContext | None, key: str, value: Any) -> None:
    if tool_context is not None and getattr(tool_context, "state", None) is not None:
        tool_context.state[key] = value


def _clean_list(values: list[str] | None) -> list[str]:
    return [str(v).strip() for v in values or [] if v and str(v).strip()]
