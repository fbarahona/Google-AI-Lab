"""
Retry and fallback for every Gemini call (adk_agent.model_resilience).
"""

from unittest.mock import MagicMock

import pytest
from google.adk.models.google_llm import Gemini
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import errors as genai_errors
from google.genai import types

from adk_agent import model_resilience as mr


@pytest.fixture(autouse=True)
def _clear_cooldowns():
    mr.reset_cooldowns()
    yield
    mr.reset_cooldowns()


def _api_error(code: int) -> genai_errors.APIError:
    cls = genai_errors.ClientError if code < 500 else genai_errors.ServerError
    return cls(code, {"error": {"code": code, "message": "boom", "status": "X"}})


def _response(text: str) -> LlmResponse:
    return LlmResponse(
        content=types.Content(role="model", parts=[types.Part(text=text)])
    )


def _fake_parent(monkeypatch, failing: dict[str, int]):
    """Replaces Gemini.generate_content_async; models in `failing` raise that code."""
    calls: list[str] = []

    async def fake(self, llm_request, stream=False):
        calls.append(llm_request.model)
        if llm_request.model in failing:
            raise _api_error(failing[llm_request.model])
        yield _response(f"answer from {llm_request.model}")

    monkeypatch.setattr(Gemini, "generate_content_async", fake)
    return calls


async def _run(model, request_model="primary"):
    request = LlmRequest(model=request_model)
    return [r async for r in model.generate_content_async(request)]


def test_fallback_disabled_when_empty_none_or_same_as_primary():
    assert mr.fallback_model_for("primary", "") is None
    assert mr.fallback_model_for("primary", "none") is None
    assert mr.fallback_model_for("primary", "primary") is None
    assert mr.fallback_model_for("primary", "secondary") == "secondary"


def test_build_gemini_sets_retry_and_fallback():
    model = mr.build_gemini("primary", attempts=3, fallback_model="secondary")
    assert model.retry_options.attempts == 3
    assert 429 in model.retry_options.http_status_codes
    assert model.fallback_model == "secondary"


@pytest.mark.asyncio
async def test_primary_success_does_not_touch_fallback(monkeypatch):
    calls = _fake_parent(monkeypatch, failing={})
    model = mr.build_gemini("primary", fallback_model="secondary")
    out = await _run(model)
    assert calls == ["primary"]
    assert out[0].content.parts[0].text == "answer from primary"


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [429, 503])
async def test_retryable_error_falls_back_then_cools_down(monkeypatch, code):
    calls = _fake_parent(monkeypatch, failing={"primary": code})
    model = mr.build_gemini("primary", fallback_model="secondary")

    out = await _run(model)
    assert calls == ["primary", "secondary"]
    assert out[0].content.parts[0].text == "answer from secondary"

    # During the cooldown the primary is skipped instead of retried again.
    await _run(model)
    assert calls == ["primary", "secondary", "secondary"]


@pytest.mark.asyncio
async def test_non_retryable_error_is_not_masked(monkeypatch):
    calls = _fake_parent(monkeypatch, failing={"primary": 400})
    model = mr.build_gemini("primary", fallback_model="secondary")
    with pytest.raises(genai_errors.ClientError):
        await _run(model)
    assert calls == ["primary"]


@pytest.mark.asyncio
async def test_both_models_exhausted_raises_429_for_webhook(monkeypatch):
    _fake_parent(monkeypatch, failing={"primary": 429, "secondary": 429})
    model = mr.build_gemini("primary", fallback_model="secondary")
    with pytest.raises(genai_errors.APIError) as exc:
        await _run(model)
    assert exc.value.code == 429


def test_sync_helper_falls_back_on_429():
    client = MagicMock()
    client.models.generate_content.side_effect = [_api_error(429), "ok"]
    mr.FALLBACK_MODEL_NAME, saved = "secondary", mr.FALLBACK_MODEL_NAME
    try:
        assert (
            mr.generate_content_with_fallback(client, model="primary", contents=["x"])
            == "ok"
        )
    finally:
        mr.FALLBACK_MODEL_NAME = saved
    models = [c.kwargs["model"] for c in client.models.generate_content.call_args_list]
    assert models == ["primary", "secondary"]


def test_every_llm_entry_point_uses_the_fallback_model(monkeypatch):
    from adk_agent.agent import (
        bq_investigation_agent,
        google_search_agent,
        soc_ticketing_agent,
        visual_analysis_agent,
    )
    from adk_agent.tools import clients
    from src.demo.soc_ticketing import ticket_assistant

    for agent in (
        google_search_agent,
        bq_investigation_agent,
        visual_analysis_agent,
        soc_ticketing_agent,
    ):
        assert isinstance(agent.model, mr.FallbackGemini)

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    assistant_model = ticket_assistant._build_model()
    assert isinstance(assistant_model, mr.FallbackGemini)
    assert assistant_model.retry_options.attempts == 3

    monkeypatch.setattr(clients, "_genai_client", None)
    client = clients.get_genai_client()
    assert 429 in client._api_client._http_options.retry_options.http_status_codes
    monkeypatch.setattr(clients, "_genai_client", None)
