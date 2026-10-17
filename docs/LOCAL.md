# Running Locally

Everything in this guide runs on your machine with **no Google Cloud project and no cost**. The local runner drives the real orchestrator, the real MCP tool servers and the real security gate; only the cloud services around them (Pub/Sub, BigQuery, Cloud Run) are replaced by local files. To deploy to Google Cloud instead, see [CLOUD.md](CLOUD.md).

---

## 1. Prerequisites

- **Python 3.12** (the project requires `>=3.12,<3.13`)
- **[uv](https://docs.astral.sh/uv/)** for dependency management
- **`agents-cli`** (optional, for the ADK playground)
- **Google Cloud SDK** with Application Default Credentials, only if you want to use a live Gemini model through Vertex AI or run the integration tests

## 2. Install and configure

```bash
uv sync
cp .env.example .env   # set GOOGLE_CLOUD_PROJECT, or GEMINI_API_KEY for Google AI Studio (local only; Cloud Run uses Vertex AI)
```

On Windows PowerShell, use `Copy-Item .env.example .env` for the second line.

On a corporate network that inspects TLS traffic, `uv sync` can fail with certificate errors because uv does not trust the company's root certificate by default. Run `uv sync --system-certs` instead, so uv uses the certificates installed in your operating system. To make it permanent, set `UV_SYSTEM_CERTS=true` in your environment (PowerShell: `$env:UV_SYSTEM_CERTS = "true"`).

> **Windows PowerShell:** the commands in this guide are written for bash, macOS and Linux shells. Plain `uv run ...` commands work as they are, but PowerShell does not accept the `LOCAL_MODE=true command` prefix (it reports "The term 'LOCAL_MODE=true' is not recognized"). Set the variable on its own line first, then run the command without the prefix:
>
> ```powershell
> $env:LOCAL_MODE = "true"
> ```
>
> The setting lasts until you close that PowerShell window. Do not move `LOCAL_MODE=true` to the end of the command instead: it then becomes an argument to the script, the console starts in cloud mode and tries to reach BigQuery ("Reauthentication is needed"). The console sidebar shows **Mode: Local simulation** when the variable is set.

`.env.example` documents the supported variables, including `GEMINI_MODEL` (default `gemini-3.8-flash`) and `ADK_ALLOW_CONFIG_STDIO_MCP_SERVERS=true`, which the ADK needs to launch the local MCP server. None of them are needed for the scripted runs below.

## 3. Run the three scenarios

The runner generates synthetic access and network logs, scores them with the detector's rules, and sends the resulting alert through the orchestrator, the MCP tool servers and the security gate, which write the ticket to the local queue.

A **scripted model** makes the agents' choices by default, so no credentials are needed and the run is repeatable. Add `--live-model` to use Gemini instead. In the false-positive and injection scenarios the scripted model deliberately tries to close the alert as a false positive, so you can watch the gate decide.

```bash
# Scenario A: Malicious APT attack (user u.lewis, Lazarus Group IP, Mimikatz in memory)
uv run python -m src.demo.local_runner --threat malicious

# Scenario B: Benign false positive (user l.taylor, admin running scheduled backup scripts)
uv run python -m src.demo.local_runner --threat false_positive

# Scenario C: Prompt injection (user c.wilson, screenshot text trying to coerce a false-positive closure)
uv run python -m src.demo.local_runner --threat injection
```

Use `--user <id>` to target a different user.

What to expect:

| Scenario | Outcome | Why |
| :--- | :--- | :--- |
| A, malicious | Incident ticket dispatched | Telemetry and the screenshot both show compromise. |
| B, false positive | Closed as false positive and archived | All evidence was gathered and none of it is malicious. |
| C, injection | Close attempt blocked, escalated to a human as `CRITICAL` | The screenshot contains an instruction aimed at the model; the security gate refuses the closure. |

## 4. Open the SOC analyst console

Inspect the incident queue, view desktop screenshot evidence, read the multi-agent report, and adjudicate tickets:

```bash
LOCAL_MODE=true uv run python -m streamlit run src/demo/soc_ticketing/streamlit_soc_console.py
```

Windows PowerShell:

```powershell
$env:LOCAL_MODE = "true"
uv run python -m streamlit run src/demo/soc_ticketing/streamlit_soc_console.py
```

The sidebar should show **Mode: Local simulation**. If it shows **Cloud (BigQuery SSOT)**, `LOCAL_MODE` is not set in that terminal.

Then open **http://localhost:8501**. The console's "Inject scenario" and "Stream logs" controls write events under the queue folder's `telemetry/` directory when running locally, and add a ticket marked **Simulated** so there is something to triage right away. Simulated tickets are left out of every dashboard metric.

## 5. Chat with the agents in the ADK playground

```bash
LOCAL_MODE=true agents-cli playground
```

On Windows PowerShell, run `$env:LOCAL_MODE = "true"` first, then `agents-cli playground`.

Pick `adk_agent` and send `investigate user c.wilson`, or paste an alert JSON to fill the whole ticket header. Locally the MCP tool server runs as a child process over `stdio`; no network or token is involved.

## 6. Generate synthetic logs on their own

```bash
# A batch of benign access and network logs to local files
uv run python -m src.demo.data_generator.log_generator --mode benign --batch-size 100 --sink=local
```

The same generator can stream to Pub/Sub, BigQuery or Cloud Storage; those sinks need a deployed project and are covered in [CLOUD.md](CLOUD.md#other-ways-to-generate-cloud-telemetry).

## 7. Tests

```bash
# Unit tests (no cloud access needed)
uv run pytest src/demo/tests/unit/

# End-to-end pipeline test: real agents, gate and MCP servers with a scripted model
LOCAL_MODE=true uv run pytest src/demo/tests/e2e/

# Lint
uv run --extra lint ruff check .

# Integration tests (need Application Default Credentials and a project)
uv run pytest src/demo/tests/integration/
```

On Windows PowerShell, run the end-to-end test as `$env:LOCAL_MODE = "true"; uv run pytest src/demo/tests/e2e/`.

CI runs lint, the unit tests and the end-to-end test on every pull request to `main`; see [ARCHITECTURE.md](ARCHITECTURE.md#8-testing--ci) for what each layer covers.
