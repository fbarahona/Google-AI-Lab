# Real-Time Cyber Security AI & Google ADK Multi-Agent Platform

[![Google Cloud](https://img.shields.io/badge/Google_Cloud-4285F4?style=for-the-badge&logo=google-cloud&logoColor=white)](https://cloud.google.com/)
[![Google ADK](https://img.shields.io/badge/Google_ADK-Multi--Agent-34A853?style=for-the-badge&logo=google&logoColor=white)](https://adk.dev/)
[![Gemini 3.8 Flash](https://img.shields.io/badge/Gemini_3.8_Flash-Multimodal-FBBC04?style=for-the-badge&logo=google-gemini&logoColor=black)](https://ai.google.dev/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-Cloud_Run_Tool_Service-7B1FA2?style=for-the-badge&logo=protocol&logoColor=white)](https://modelcontextprotocol.io/)
[![BigQuery](https://img.shields.io/badge/BigQuery-Single_Source_of_Truth-673AB7?style=for-the-badge&logo=google-bigquery&logoColor=white)](https://cloud.google.com/bigquery)

> [!NOTE]
> **Portfolio demonstration.** This repository is a technical portfolio piece showing how to design, secure and operate an agentic AI system on Google Cloud. It is a reference architecture and working prototype, not an off-the-shelf product.

## Intent

Security Operations Center (SOC) analysts drown in alerts, and most of them are benign. This project shows how a team of AI agents can do the first 30 to 45 minutes of an investigation in under a minute, **without being trusted with more than it needs**: the agents gather and weigh evidence, deterministic code decides what they are allowed to conclude, and a human analyst reviews the result.

It is built to demonstrate four things at once: multi-agent AI with Google ADK and Gemini, cloud security and IAM design, serverless data engineering on BigQuery and Pub/Sub, and the engineering discipline to run all of it at near-zero idle cost.

## What it does

| The challenge in modern SOCs | How this platform answers it |
| :--- | :--- |
| **Alert fatigue:** hundreds of daily alerts, 70%+ of them benign administrative activity. | **Automated triage:** agents separate genuine attacks from benign scripts and close or escalate them with a written rationale. |
| **Fragmented evidence:** one investigation means querying logs, checking IP reputation and examining desktop artifacts in separate systems, **30 to 45 minutes per alert**. | **Parallel specialists:** OSINT, behavioral BigQuery profiling and multimodal screenshot forensics run at the same time, in **under 30 seconds**. |
| **Fragile, over-privileged AI tooling:** tools wired straight into the prompt loop, sharing the agent's credentials. | **MCP tool service with its own identity:** the agent's own service account cannot read evidence or write tickets; it can only call nine fixed, validated operations. |

```
 Log generator ─▶ Pub/Sub ─▶ BigQuery ─▶ Detector (Cloud Run job, every 5 min)
                                                   │ alert
                                                   ▼
               SOC console ◀─ tickets ◀─ MCP tool service ◀─ ADK agent team
               (Streamlit)                (own identity)      (Cloud Run)
```

## What to look at

- **Multi-agent design:** an ADK orchestrator runs three investigators in parallel, then an adjudicator. [Architecture §4](docs/ARCHITECTURE.md#4-the-multi-agent-investigation)
- **MCP as a privilege boundary:** tools run in a separate Cloud Run service under a separate service account. [Architecture §5](docs/ARCHITECTURE.md#5-mcp-tool-service)
- **Guardrails the model cannot talk past:** a security gate, fail-closed evidence and default-deny escalation, in code. [Security §8](docs/SECURITY_ARCHITECTURE.md#8-agent-guardrails-deterministic-controls-around-the-model)
- **Least-privilege IAM:** one identity per workload; analysts hold no project roles; deploy rights sit on an impersonated service account. [Security §4](docs/SECURITY_ARCHITECTURE.md#4-scoped-workload-identities--resource-level-bindings)
- **Data engineering:** protobuf data contract, zero-compute ingestion, incident correlation, append-only partitioned tickets. [Architecture §2](docs/ARCHITECTURE.md#2-ingestion-and-data-engineering)
- **Cost-driven evolution:** from a ~$4,300/month always-on design to near-zero idle cost. [History](docs/HISTORY.md)

## Try it in two minutes

No cloud project needed. A scripted model stands in for Gemini, and the real agents, tool server and security gate do the rest:

```bash
uv sync
uv run python -m src.demo.local_runner --threat injection
```

The screenshot in this scenario contains text that tries to make the AI close the alert as harmless. Watch the security gate block that closure and escalate to a human. [LOCAL.md](docs/LOCAL.md) has the other scenarios, the analyst console and the tests. These commands work in bash and in Windows PowerShell; for the console on PowerShell, see the note in [LOCAL.md](docs/LOCAL.md#2-install-and-configure).

## Documentation

| Document | Read it for |
| :--- | :--- |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | The components, the end-to-end flow, the data model and the key design decisions |
| [LOCAL.md](docs/LOCAL.md) | Running the scenarios, the console, the agent playground and the tests on your machine |
| [CLOUD.md](docs/CLOUD.md) | Deploying to Google Cloud, verifying it end to end, console access, cost and teardown |
| [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) | Identities and roles, human access, MCP boundary, agent guardrails, privacy and PII |
| [HISTORY.md](docs/HISTORY.md) | How the design evolved, and why each step was taken |
| [Terraform module](src/demo/terraform/README.md) | Infrastructure-as-code reference |
| [GEMINI.md](GEMINI.md) | Conventions for coding agents working in this repository |

## Built with

Python 3.12 · Google ADK · Gemini on Vertex AI · Model Context Protocol · Cloud Run (services and jobs) · Pub/Sub · BigQuery · Cloud Storage · Cloud Scheduler · Terraform · Streamlit · uv · GitHub Actions

## License

Licensed under the [Apache License 2.0](LICENSE).
