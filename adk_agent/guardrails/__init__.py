"""
Deterministic guardrails around the investigation agents.

The model decides what to investigate and how to summarize it; these callbacks
decide what it is allowed to conclude. Each module is one control family:
- evidence_state: syncs the structured security flags MCP tools return into
  session state, failing closed when evidence is missing or malformed
- security_gate: blocks false-positive closures the evidence does not support,
  pins tickets to the alert, and files the default-deny escalation
- search_privacy: limits what the Google Search model sees and audits its queries
- lifecycle: seeds and resets per-alert state, logs agent start and finish
"""
