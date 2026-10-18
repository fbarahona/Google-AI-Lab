"""
Logging utilities for Cymbal Cyber ADK agents.
"""

import logging
import os
import sys

logger = logging.getLogger("CymbalCyberADK")


def setup_logging():
    """
    Configures root logging once. On Cloud Run (K_SERVICE is set) every record is a
    one-line JSON entry with a real severity, so Cloud Logging can filter on
    severity>=ERROR and keeps a traceback in one entry instead of one per line.
    Elsewhere it is plain text on stdout. Optional Google Cloud Logging API export
    stays behind ENABLE_CLOUD_LOGGING.
    """
    root = logging.getLogger()
    if getattr(root, "_cymbal_logging_configured", False):
        return
    if os.getenv("K_SERVICE"):
        from google.cloud.logging.handlers import StructuredLogHandler

        handler: logging.Handler = StructuredLogHandler(
            stream=sys.stdout, project_id=os.getenv("GOOGLE_CLOUD_PROJECT")
        )
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    root._cymbal_logging_configured = True

    if os.getenv("ENABLE_CLOUD_LOGGING", "false").lower() == "true":
        try:
            import google.cloud.logging

            client = google.cloud.logging.Client()
            client.setup_logging()
            logger.info("Google Cloud Logging successfully enabled.")
        except Exception as e:
            logger.warning("Could not initialize Google Cloud Logging: %s", e)


def log_agent_event(message: str, agent_name: str | None = None):
    """Logs an agent lifecycle or tool execution event."""
    prefix = f"[{agent_name}] " if agent_name else ""
    logger.info("%s%s", prefix, message)
