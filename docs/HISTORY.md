# How This Project Evolved

The architecture in [ARCHITECTURE.md](ARCHITECTURE.md) was not the first design. It is the result of a series of decisions, each made when the previous design hit a limit in cost, coupling or security. This page tells that story in order. For each step it gives the decision, the reason, the trade-off accepted, and what is still in the repository from the earlier design.

The first three steps predate this repository's git history, which starts with the serverless design already in place. They are still visible in the code, because the earlier engines were kept as opt-in Terraform toggles rather than deleted.

| # | Design | What drove the next change |
| :--- | :--- | :--- |
| 1 | Detection and AI reasoning inside BigQuery (continuous query + `ML.GENERATE_TEXT`) | Always-on slot cost; AI coupled to SQL |
| 2 | Dataflow streaming pipeline | Workers bill continuously |
| 3 | Pub/Sub subscriptions + scheduled Cloud Run job, agents on ADK | Tools and agent shared one process and one identity |
| 4 | Tools moved behind a local MCP server | Same identity still held every permission |
| 5 | MCP server as its own Cloud Run service and identity | Current design |
| 6 | Audit-driven hardening of every layer | Ongoing |

---

## 1. AI inside the warehouse: BigQuery continuous query

**Design.** Raw events streamed into BigQuery. A [continuous query](../src/demo/data_pipeline/continuous_query.sql) aggregated 2-minute tumbling windows as events arrived and published alerts to Pub/Sub, with latency of seconds. Gemini was called from inside SQL through `ML.GENERATE_TEXT` over a Vertex AI remote connection, so the warehouse did both detection and reasoning.

**Why it changed.**
- **Cost.** Continuous queries need a BigQuery Enterprise reservation. At 100 slots that is about $6 an hour, roughly **$4,300 a month**, billed whether or not anything arrives. Cancelling the query saves nothing; only removing the reservation does. For a demo that is idle most of the time, that is the wrong cost model.
- **Coupling.** With the model call inside SQL, every query depended on model availability. Rate limits, retries, multi-step reasoning, tool use and guardrails are hard or impossible to express in a SQL statement.

**What remains.** `enable_continuous_query` (default `false`) in [`variables.tf`](../src/demo/terraform/variables.tf) still provisions the reservation and the `bq-continuous-query-sa` identity, and [`launch_continuous_query.sh`](../src/demo/scripts/launch_continuous_query.sh) starts the query. The detection logic survived as BigQuery UDFs (`calculate_threat_score`, `is_malicious_domain`, `is_malicious_command`) that the current detector reuses. The Vertex AI connection was removed; BigQuery now makes no model calls.

## 2. A custom streaming pipeline: Dataflow

**Design.** An Apache Beam pipeline ([`pubsub_to_bigquery_dataflow.py`](../src/demo/data_pipeline/pubsub_to_bigquery_dataflow.py)) read the raw topic and routed each event type to its BigQuery table.

**Why it changed.** Streaming Dataflow keeps worker VMs running, about **$100 to $300 a month** at demo scale. The transformation it performed (route by event type, write to a table) needs no custom code: a Pub/Sub BigQuery subscription with a filter does the same with no workers at all.

**What remains.** `enable_dataflow_streaming` (default `false`) and [`run_dataflow_demo.sh`](../src/demo/scripts/run_dataflow_demo.sh) for a live comparison. The two paths must not run together, or every event is written twice.

## 3. Zero idle cost: Pub/Sub subscriptions, a scheduled Cloud Run job, and ADK agents

**Design.**
- **Ingestion:** Pub/Sub BigQuery subscriptions, filtered by `event_family`, write directly to the event tables.
- **Detection:** Cloud Scheduler starts the `threat-detector` Cloud Run job every 5 minutes. It scores closed 2-minute windows with the same UDFs and writes alerts with an idempotent `MERGE`.
- **Reasoning:** moved out of SQL into a Google ADK multi-agent team (OSINT, BigQuery behavior, desktop vision, adjudication) running on Cloud Run behind a Pub/Sub push webhook.
- **One alert contract** for every engine, so the investigator does not care which engine raised the alert.

**Trade-off accepted.** Alert latency rose from seconds to about 5 to 7 minutes. In exchange the continuous cost fell to near zero: every component scales to zero and BigQuery runs on demand.

**A detour: Vertex AI Agent Engine.** The agent was first scaffolded for Vertex AI Agent Engine with `agents-cli`. It moved to a plain Cloud Run service because Pub/Sub push with OIDC authentication works natively there, without a token-exchange relay, and because it gives full control of the FastAPI routes (webhook, deduplication). The leftover Agent Engine deployment was deleted, and its scaffolding guide was retired with this documentation restructure.

**What was still wrong.** The agents called Python tools in their own process, as their own service account. That one identity could therefore read every evidence table and bucket and write tickets. A prompt injection that steered the model could, in principle, use any of those rights.

## 4. Tools behind MCP (local)

*Pull requests #1 to #7, October 2026.*

**Design.** The tools moved into a Model Context Protocol server ([`adk_agent/mcp_server/`](../adk_agent/mcp_server/)) that each sub-agent reaches over `stdio`, with a `tool_filter` listing only the tools its role needs. Along the way:
- The free-form `execute_sql` and schema-discovery tools were removed, leaving only fixed, parameterized operations.
- Evidence tools were made to fail closed: an error, a timeout or an unstructured answer counts as missing evidence, which blocks a false-positive closure (#8).
- Tool output was stopped from marking alerts resolved; only the tool that actually performs a resolution may set that flag.

**What was still wrong.** MCP was now a code boundary but not a privilege boundary. The server ran as a child of the agent, with the agent's credentials.

## 5. A decoupled MCP service with its own identity

*Pull request #24, October 2026.*

**Design.** The MCP server became its own Cloud Run service, `cymbal-cyber-mcp`, running as `cymbal-mcp-tools-sa`. That identity holds every evidence read and ticket write. The agent's identity lost all of them; it keeps only Gemini access, its own bookkeeping tables, and `run.invoker` on the tool service. The agent calls the service over Streamable HTTP with an ID token, and the server re-checks the token's audience and caller itself. Even the platform's default-deny escalation goes through the service.

**Result.** A compromised or prompt-injected agent can only ask for the nine fixed operations, each validated server-side. It cannot run SQL, list a bucket or write a ticket by any other route. Locally the same server still runs over `stdio`, so development needs no cloud.

**Trade-off accepted.** One more service to deploy and a network hop per tool session. Google's MCP Toolbox for Databases was considered as a replacement for the custom server and deferred.

## 6. Audit-driven hardening

*Pull requests #8 to #35, October 2026.*

The design was reviewed several times against security, IAM, data-engineering and code-quality criteria, and each review became a staged plan that was approved before any change. The main results:

- **Ticket integrity:** ticket IDs derived from the alert, so a redelivered alert cannot create a duplicate; ticket writes that fail are reported as failures; an end-to-end test with a scripted model runs in CI.
- **Cloud hardening:** no API keys (Gemini through Vertex AI as a service account), a non-root, digest-pinned container image, the ADK web UI off in the cloud by default, separate identities for the scheduler, the push subscription and console access.
- **Data engineering:** incident correlation (one attack, one investigation, instead of about four), a protobuf contract on the raw topic, a partitioned append-only ticket table with a current view, and a BigLake object table for screenshots.
- **Human access:** analysts hold no project roles and reach the console only by impersonating a single-purpose service account; deploy rights moved to a `cymbal-deployer` service account that people impersonate.
- **Privacy:** a review found that the web-search privacy check could never fire, because `google_search` is a Gemini built-in tool and ADK tool callbacks do not see it. It was replaced with input minimization (the search model only ever receives the alert's public IPs) plus an audit of the queries Gemini actually ran. PII masking was made consistent, and the prompt-injection scan now runs on raw OCR text before masking.

The plans behind each stage are summarized in the pull request descriptions.
