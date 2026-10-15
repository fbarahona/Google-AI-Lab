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

# Base images are pinned by digest so a rebuild of the same commit gets the same bytes.
# Refresh with: docker buildx imagetools inspect python:3.12-slim (and the uv image).
ARG PYTHON_IMAGE=python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.8.13@sha256:4de5495181a281bc744845b9579acf7b221d6791f99bcc211b9ec13f417c2853

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE}

COPY --from=uv /uv /uvx /bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1

WORKDIR /code

COPY ./pyproject.toml ./README.md ./uv.lock ./

# Runtime dependencies only: no pytest or other dev tooling in the image.
RUN uv sync --frozen --no-dev --no-install-project

# Only the code the services run. Terraform, deploy scripts, tests and local data stay
# out of the image (.dockerignore also guards anything gitignored, such as state files).
COPY ./adk_agent ./adk_agent
COPY ./src/demo/soc_ticketing ./src/demo/soc_ticketing
COPY ./src/demo/data_generator ./src/demo/data_generator
COPY ./local_demo_data/user_screenshots ./local_demo_data/user_screenshots
COPY ./.streamlit ./.streamlit

# Run as an unprivileged user. It owns only local_demo_data (the ticket service creates
# its local queue directories there) and its home directory; the code is read-only.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /code/local_demo_data/escalations/history \
    && chown -R app:app /code/local_demo_data
USER 10001

ARG AGENT_VERSION=0.0.0
ENV PATH="/code/.venv/bin:$PATH"
ENV AGENT_VERSION=${AGENT_VERSION}

EXPOSE 8080

ENTRYPOINT ["python"]
CMD ["-m", "uvicorn", "adk_agent.fast_api_app:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*"]
