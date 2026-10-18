"""
Environment settings shared by the agent and the tools, read once at import.

The agent and the MCP tool service run as separate processes in the cloud, but both
must agree on the project, dataset and model, so those live here and nowhere else.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# The repository root is the one import root (adk_agent and src.demo both resolve
# from it); MCP server subprocesses get it on PYTHONPATH whatever their working dir.
REPO_ROOT = Path(__file__).resolve().parents[1]

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("PROJECT_ID", "local-demo")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
