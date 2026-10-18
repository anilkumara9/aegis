# Changelog

## v0.1.0 (2026-10-18)

First release — the defensive guard agent.

- **Real CLI agent**: `aegis` drops into an interactive REPL with a
  model-agnostic agent loop (Anthropic + OpenAI providers, env API keys,
  streaming, multi-step tool use). `AEGIS_PROVIDER=mock` for offline mode.
- **Guard inside the loop**: every tool call is screened pre-execution
  (tool allowlist/denylist, dangerous-arg patterns, secret detection,
  egress domain control), high-severity matches escalate to human approval,
  and a kill-switch revokes the session machine-wide. The agent dogfoods
  its own defense.
- **Knowledge base**: 19 YAML packs, 212 techniques, strict-schema
  validated — agent-attack packs (prompt injection, tool-output poisoning,
  credential/egress exfiltration, persistence, privilege escalation,
  supply chain, evasion), depth packs (dark-web intel, APT tradecraft from
  public reporting, ransomware, social engineering, web exploitation,
  network attacks, malware concepts), and completeness packs (hacker tools
  detection catalog, attack methods as defender doctrine, algorithms
  concepts, hacker mindset shaping the system prompt).
- **Tools**: bash (Docker-sandboxed when available), read/write/edit
  (cwd-confined), webfetch, kb_query, scan_trace, respond.
- **Subsystems as CLI commands**: `aegis scan` (offline trace analyzer
  with KB pattern + multi-step chain detection), `aegis guard`
  (`check`/`wrap`/`kill`/`status`; in-process API via `from aegis import
  guard`), `aegis respond` (rotate-keys/kill-session/quarantine-workspace/
  incident-report runbooks — operator-executed, no destructive provider
  actions), `aegis kb`, `aegis hunt` (local-only code audit).
- **Redaction at every return boundary**: tool args and outputs are
  secret-scanned before logging, display, the model, and the audit log —
  including split tokens, env-var indirection, and base64-smuggled secrets.
- **JSONL audit log** of every tool call (`~/.aegis/audit/`).
- **Slash skills** in the REPL: /hunt /guard /scan /respond /kb /help.
- Docs: README, SECURITY.md, docs/SCOPE_AND_LIMITS.md (plain-language
  ceiling + ATT&CK/OWASP cross-check + deliberate omissions).
- Test suite green: KB validation, per-pack positive/negative fixtures,
  adversarial redaction, guard allow/deny/kill-switch/wrap, agent loop
  with planted injection+exfil blocked live via mock provider, playbooks,
  /hunt scoping. No network in tests.
