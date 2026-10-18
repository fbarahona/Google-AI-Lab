"""
Unit tests for dynamic model configuration and project environment variable loading.
"""

import os

from dotenv import load_dotenv

import adk_agent.tools as tools
from adk_agent.agent import (
    MODEL_NAME,
    PROJECT_ID,
    bq_investigation_agent,
    google_search_agent,
    soc_ticketing_agent,
    visual_analysis_agent,
)

load_dotenv()


def test_dynamic_model_name():
    """Verify that MODEL_NAME is loaded dynamically from the environment."""
    expected_model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    assert MODEL_NAME == expected_model
    assert tools.MODEL_NAME == expected_model


def test_dynamic_agent_models():
    """Verify that all sub-agents are initialized with the dynamic configured model."""
    expected_model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    assert google_search_agent.model == expected_model
    assert bq_investigation_agent.model == expected_model
    assert visual_analysis_agent.model == expected_model
    assert soc_ticketing_agent.model == expected_model


def test_dynamic_project_id():
    """Verify that PROJECT_ID is dynamically loaded from GOOGLE_CLOUD_PROJECT."""
    expected_project = os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
    assert PROJECT_ID == expected_project
    assert tools.PROJECT_ID == expected_project


def test_project_id_fallback_to_project_id_env(monkeypatch):
    """Verify that when GOOGLE_CLOUD_PROJECT is unset, PROJECT_ID falls back to the PROJECT_ID env var."""
    import importlib

    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: None)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.setenv("PROJECT_ID", "custom-fallback-project")
    import adk_agent.settings as settings

    reloaded_settings = importlib.reload(settings)
    assert reloaded_settings.PROJECT_ID == "custom-fallback-project"
    # Restore original module state
    monkeypatch.undo()
    importlib.reload(settings)
