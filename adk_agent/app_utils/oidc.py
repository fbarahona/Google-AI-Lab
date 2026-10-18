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

"""
Authentication of the Pub/Sub push webhook: the caller must present a Google-signed
OIDC token for this service, with a verified email matching the invoker service
account. Bypassed only in LOCAL_MODE or with DISABLE_AUTH.
"""

import logging
import os
from typing import Any

from fastapi import HTTPException, Request

logger = logging.getLogger("CymbalCyberADK.Webhook")


def verify_incoming_oidc_token(request: Request) -> dict[str, Any]:
    """
    Validates Google-issued OpenID Connect (OIDC) JWT bearer tokens for Pub/Sub push
    and Cloud Scheduler endpoints to guarantee caller identity authenticity.
    Bypassed in local simulation mode (LOCAL_MODE=true) or when authentication is disabled.
    """
    if os.getenv("LOCAL_MODE", "false").lower() in ("true", "1") or os.getenv(
        "DISABLE_AUTH", "false"
    ).lower() in ("true", "1"):
        return {"email": "local-dev@internal", "local": True}

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header. Google OIDC bearer token required.",
        )

    token = auth_header.split(" ", 1)[1].strip()
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token

        claims = None
        expected_audience = os.getenv("EXPECTED_OIDC_AUDIENCE")
        if expected_audience:
            candidate_audiences = [expected_audience]
            clean_aud = expected_audience.replace("https://", "").replace("http://", "")
            if "/" in clean_aud:
                parts = expected_audience.split("/")
                root_uri = f"{parts[0]}//{parts[2]}"
                candidate_audiences.append(root_uri)
            else:
                candidate_audiences.append(
                    f"{expected_audience.rstrip('/')}/apps/adk_agent/trigger/pubsub"
                )
                candidate_audiences.append(
                    f"{expected_audience.rstrip('/')}/trigger/pubsub"
                )

            last_exc = None
            for aud in candidate_audiences:
                try:
                    claims = id_token.verify_oauth2_token(
                        token,
                        google_requests.Request(),
                        audience=aud,
                    )
                    break
                except Exception as e:
                    last_exc = e
            if not claims and last_exc:
                raise last_exc
        else:
            # Fallback: derive candidate audiences accounting for Cloud Run TLS termination / proxy headers
            host = request.headers.get("x-forwarded-host") or request.headers.get(
                "host"
            )
            proto = request.headers.get("x-forwarded-proto", "https")
            candidate_audiences = []
            if host:
                candidate_audiences.append(f"{proto}://{host}{request.url.path}")
                candidate_audiences.append(f"https://{host}{request.url.path}")
                candidate_audiences.append(f"{proto}://{host}")
                candidate_audiences.append(f"https://{host}")

            raw_url = str(request.url).split("?")[0]
            candidate_audiences.append(raw_url)
            if raw_url.startswith("http://"):
                candidate_audiences.append("https://" + raw_url[7:])

            last_exc = None
            for aud in candidate_audiences:
                try:
                    claims = id_token.verify_oauth2_token(
                        token,
                        google_requests.Request(),
                        audience=aud,
                    )
                    break
                except Exception as e:
                    last_exc = e

            if not claims:
                raise last_exc or ValueError(
                    "OIDC token verification failed for all candidate audiences."
                )

        # Verify caller email is verified by Google
        if not claims.get("email_verified"):
            logger.warning(
                "Inbound OIDC JWT rejected: email_verified claim is not true."
            )
            raise HTTPException(
                status_code=403,
                detail="Invalid OIDC bearer token: caller email is not verified.",
            )

        # Verify caller email matches authorized invoker service account
        expected_invoker = os.getenv("EXPECTED_INVOKER_EMAIL")
        if not expected_invoker:
            proj = os.getenv("GOOGLE_CLOUD_PROJECT")
            invoker_id = os.getenv("INVOKER_SA_NAME", "pubsub-invoker-sa")
            if proj and proj not in ("local-demo", "test-proj"):
                expected_invoker = f"{invoker_id}@{proj}.iam.gserviceaccount.com"

        if expected_invoker:
            caller_email = claims.get("email")
            if caller_email != expected_invoker:
                logger.warning(
                    "Inbound OIDC JWT rejected: caller email '%s' does not match expected invoker '%s'.",
                    caller_email,
                    expected_invoker,
                )
                raise HTTPException(
                    status_code=403,
                    detail="Forbidden: caller service account is not authorized.",
                )

        return claims
    except Exception as exc:
        logger.warning("Inbound OIDC JWT validation failed: %s", exc)
        raise HTTPException(
            status_code=403,
            detail="Invalid OIDC bearer token.",
        ) from exc
