"""Environment settings and display constants for the SOC console."""

import os
from pathlib import Path

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
REPO_ROOT = Path(__file__).resolve().parents[4]
SCREENSHOTS_DIR = str(REPO_ROOT / "local_demo_data" / "user_screenshots")
# How often the live panels poll for new data.
REFRESH_SECONDS = max(5, int(os.getenv("SOC_REFRESH_SECONDS", "20")))
# Optional link to the ADK web UI, shown next to the ticket assistant.
ADK_WEB_URL = os.getenv("ADK_WEB_URL", "")

SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "orange",
    "MEDIUM": "yellow",
    "LOW": "blue",
}
SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
TIME_RANGE_LABELS = {
    "All Time": "All time",
    "Last 24 Hours": "24h",
    "Last 7 Days": "7d",
    "Last 30 Days": "30d",
    "Last 90 Days": "90d",
}
TIME_RANGES = list(TIME_RANGE_LABELS)
SUGGESTED_QUESTIONS = [
    "Summarize this incident in three bullet points",
    "What should I do first to contain it?",
    "Is there any sign this could be a false positive?",
]
