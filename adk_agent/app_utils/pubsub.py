# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Pub/Sub push envelope parsing and the per-alert session ID."""

import base64
import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any


def extract_pubsub_payload(raw_body: Any) -> dict[str, Any]:
    """
    Decodes and extracts the alert payload from incoming Pub/Sub push requests.
    Handles:
    - Standard wrapped Pub/Sub envelope: {"message": {"data": "<base64>", "attributes": ...}}
    - Raw/unwrapped JSON payloads (Pub/Sub no_wrapper configuration)
    - Raw strings and byte payloads
    Raises ValueError if payload contains invalid or non-JSON binary data.
    """
    if isinstance(raw_body, bytes):
        try:
            raw_body = json.loads(raw_body.decode("utf-8"))
        except Exception as exc:
            raise ValueError(
                f"Malformed request body: payload is not valid JSON ({exc})"
            ) from exc
    elif isinstance(raw_body, str):
        try:
            raw_body = json.loads(raw_body)
        except Exception as exc:
            raise ValueError(
                f"Malformed request body: payload is not valid JSON ({exc})"
            ) from exc

    if not isinstance(raw_body, dict):
        raise ValueError("Malformed request body: root must be a JSON object")

    # Wrapped Pub/Sub push message
    if "message" in raw_body and isinstance(raw_body["message"], dict):
        msg = raw_body["message"]
        data = msg.get("data")
        payload = {}
        if data:
            try:
                decoded_bytes = base64.b64decode(data)
                decoded_text = decoded_bytes.decode("utf-8")
                payload = json.loads(decoded_text)
            except Exception as exc:
                raise ValueError(
                    f"Malformed Pub/Sub message data: payload is not valid JSON ({exc})"
                ) from exc
        if not isinstance(payload, dict):
            raise ValueError(
                "Malformed Pub/Sub message data: inner JSON must be an object"
            )
        attrs = msg.get("attributes")
        if isinstance(attrs, dict):
            for k, v in attrs.items():
                if k not in payload:
                    payload[k] = v
        return payload

    return raw_body


def _parse_timestamp(value: Any) -> datetime | None:
    """alerts.updated_at as a datetime, whether BigQuery returned one or a string."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def session_id_for_alert(user_id: str, alert_id: str | None) -> str:
    """One ADK session per alert, so a redelivery resumes it instead of colliding."""
    suffix = (
        hashlib.sha256(alert_id.encode("utf-8")).hexdigest()[:16]
        if alert_id
        else uuid.uuid4().hex[:16]
    )
    return f"pubsub-{user_id}-{suffix}"
