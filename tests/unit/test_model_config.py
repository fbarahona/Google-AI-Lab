"""
Unit tests for model configuration and environment variable loading.
"""

import adk_agent.tools as tools
from adk_agent.agent import (
    MODEL_NAME,
    bq_investigation_agent,
    google_search_agent,
    soc_ticketing_agent,
    visual_analysis_agent,
)


def test_default_model_name():
    """Verify that MODEL_NAME is loaded and defaults to gemini-3.8-flash."""
    assert MODEL_NAME == "gemini-3.8-flash"
    assert tools.MODEL_NAME == "gemini-3.8-flash"


def test_agent_models():
    """Verify that all sub-agents are initialized with the configured model."""
    assert google_search_agent.model == "gemini-3.8-flash"
    assert bq_investigation_agent.model == "gemini-3.8-flash"
    assert visual_analysis_agent.model == "gemini-3.8-flash"
    assert soc_ticketing_agent.model == "gemini-3.8-flash"
