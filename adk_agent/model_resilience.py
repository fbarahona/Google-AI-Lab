"""
Retry and fallback for every Gemini call: the ADK agents, the console's Ask the Agent
assistant and the screenshot analysis tool.

Vertex AI answers 429 RESOURCE_EXHAUSTED when shared Gemini capacity is busy. Each call
first retries with exponential backoff and jitter inside the request. If the primary
model still fails with a retryable error, the call is sent once more to a secondary
model, which draws on separate capacity. After a fallback the primary model is skipped
for a short cooldown, so later calls do not each wait out the full retry budget again.
"""

import logging
import os
import threading
import time
from collections.abc import AsyncGenerator
from typing import Any

from google.adk.models.google_llm import Gemini
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import errors as genai_errors
from google.genai import types

from adk_agent.settings import MODEL_NAME

logger = logging.getLogger(__name__)

# 408 timeout, 429 capacity, 5xx transient server errors. Anything else (bad request,
# permission denied, safety block) would fail on the secondary model too.
RETRYABLE_STATUS_CODES = (408, 429, 500, 502, 503, 504)

GEMINI_RETRY_ATTEMPTS = int(os.getenv("GEMINI_RETRY_ATTEMPTS", "5"))
# The previous Flash generation: a separate model, so it draws on its own capacity
# (listed in Model Garden for the project on 2026-10-26).
# An empty value or "none" turns the fallback off.
FALLBACK_MODEL_NAME = os.getenv("GEMINI_FALLBACK_MODEL", "gemini-3.7-flash")
FALLBACK_COOLDOWN_SECONDS = float(os.getenv("GEMINI_FALLBACK_COOLDOWN_SECONDS", "60"))


def retry_options(attempts: int | None = None) -> types.HttpRetryOptions:
    """Backoff of 2, 4, 8, 16 s (capped at 30 s) with jitter, on the retryable codes."""
    return types.HttpRetryOptions(
        attempts=attempts or GEMINI_RETRY_ATTEMPTS,
        initial_delay=2.0,
        max_delay=30.0,
        exp_base=2.0,
        jitter=1.0,
        http_status_codes=list(RETRYABLE_STATUS_CODES),
    )


def fallback_model_for(primary: str, fallback: str | None = None) -> str | None:
    """The secondary model, or None when it is off or the same as the primary."""
    name = (FALLBACK_MODEL_NAME if fallback is None else fallback).strip()
    if not name or name.lower() == "none" or name == primary:
        return None
    return name


def is_retryable(exc: BaseException) -> bool:
    return isinstance(exc, genai_errors.APIError) and exc.code in RETRYABLE_STATUS_CODES


_cooldown_lock = threading.Lock()
_primary_unavailable_until: dict[str, float] = {}


def _in_cooldown(model: str) -> bool:
    with _cooldown_lock:
        return time.monotonic() < _primary_unavailable_until.get(model, 0.0)


def _start_cooldown(model: str) -> None:
    with _cooldown_lock:
        _primary_unavailable_until[model] = time.monotonic() + FALLBACK_COOLDOWN_SECONDS


def reset_cooldowns() -> None:
    """Clears the cooldowns (tests use this between cases)."""
    with _cooldown_lock:
        _primary_unavailable_until.clear()


def _log_fallback(primary: str, fallback: str, exc: BaseException) -> None:
    logger.warning(
        "Gemini model %s failed after retries (%s); falling back to %s for %.0f s.",
        primary,
        getattr(exc, "code", type(exc).__name__),
        fallback,
        FALLBACK_COOLDOWN_SECONDS,
    )


class FallbackGemini(Gemini):
    """ADK Gemini model that retries, then sends the request to a secondary model."""

    fallback_model: str | None = None

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        primary = llm_request.model or self.model
        fallback = fallback_model_for(primary, self.fallback_model or "")

        if fallback is None or not _in_cooldown(primary):
            yielded = False
            try:
                async for response in super().generate_content_async(
                    llm_request, stream
                ):
                    yielded = True
                    yield response
                return
            except genai_errors.APIError as exc:
                # A stream that already produced output cannot be restarted cleanly.
                if fallback is None or yielded or not is_retryable(exc):
                    raise
                _log_fallback(primary, fallback, exc)
                _start_cooldown(primary)

        llm_request.model = fallback
        async for response in super().generate_content_async(llm_request, stream):
            yield response


def build_gemini(
    model: str = MODEL_NAME,
    *,
    attempts: int | None = None,
    fallback_model: str | None = None,
    **kwargs: Any,
) -> FallbackGemini:
    """The one way the app builds an ADK model: retries plus the secondary model."""
    return FallbackGemini(
        model=model,
        retry_options=retry_options(attempts),
        fallback_model=fallback_model_for(model, fallback_model),
        **kwargs,
    )


def generate_content_with_fallback(
    client: Any, *, model: str = MODEL_NAME, contents: Any, config: Any = None
) -> Any:
    """Synchronous generate_content on a google-genai client, with the fallback.

    The client carries the retry options (see tools.clients.get_genai_client); this
    adds the secondary model once those retries are exhausted.
    """
    fallback = fallback_model_for(model)
    if fallback is None or not _in_cooldown(model):
        try:
            return client.models.generate_content(
                model=model, contents=contents, config=config
            )
        except genai_errors.APIError as exc:
            if fallback is None or not is_retryable(exc):
                raise
            _log_fallback(model, fallback, exc)
            _start_cooldown(model)
    return client.models.generate_content(
        model=fallback, contents=contents, config=config
    )
