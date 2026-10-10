"""
Logging utilities for Cymbal Cyber ADK agents.
"""
import os
import sys
import logging
from typing import Optional

logger = logging.getLogger("CymbalCyberADK")


def setup_logging():
    """Initializes console logging and optional Google Cloud Logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    if os.getenv("ENABLE_CLOUD_LOGGING", "false").lower() == "true":
        try:
            import google.cloud.logging
            client = google.cloud.logging.Client()
            client.setup_logging()
            logger.info("Google Cloud Logging successfully enabled.")
        except Exception as e:
            logger.warning("Could not initialize Google Cloud Logging: %s", e)


def log_agent_event(message: str, agent_name: Optional[str] = None):
    """Logs an agent lifecycle or tool execution event."""
    prefix = f"[{agent_name}] " if agent_name else ""
    logger.info("%s%s", prefix, message)

