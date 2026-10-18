# Changelog

## v0.3.0 (2026-10-18)

"Claude-Code-class CLI: model-agnostic, modes, polished TUI, one-command install."

- **Providers**: Google Gemini (`AEGIS_PROVIDER=google`,
  `GOOGLE_API_KEY`/`GEMINI_API_KEY`, default `gemini-2.0-flash`) and local
  models via Ollama (`AEGIS_PROVIDER=ollama`, `AEGIS_OLLAMA_URL`, `--model`
  picks the model) join Anthropic/OpenAI/mock in the provider abstraction.
  Streaming where the API supports it.
- **Modes**: `--mode dev` (default, full tool power, guard-screened) and
  `--mode plan` (read-only). Plan mode is enforced AT THE GUARD LAYER —
  write/edit/bash are hard-denied even if the model requests them. `/mode`
  switches mid-session; the mode shows in the REPL prompt. `/plan` emits a
  hacker-mindset, phase-by-phase attack plan for YOUR OWN code (defensive
  planning, read-only).
- **Polished TUI**: streaming markdown renderer with syntax-highlighted code
  blocks (python/js/ts/bash/json/yaml/…), colorized tool-call blocks,
  inline code/bold rendering, mode-aware prompt, status line. Dumb-terminal
  safe; honors NO_COLOR.
- **Offensive-tooling guard**: primarily-offensive kits (msfconsole/msfvenom,
  mimikatz, Empire, Veil, BeEF, RouterSploit, …) are denied at the guard
  layer in every mode. Dual-use scanner tooling stays allowed on the user's
  own assets, guard-screened. Allowed surface documented in
  `docs/SCOPE_AND_LIMITS.md`.
- **Single-command distribution**: `pip install` exposes a real `aegis`
  console command; new curl-pipeable `install.sh` (isolated venv under
  `~/.aegis`, `~/.local/bin` on PATH, ends with `aegis version`
  verification). README quickstart leads with the one-liner.
- Defensive-only boundary unchanged.

## v0.2.0 (2026-10-18)

"OpenCode interface parity + autonomous defensive team."

- **OpenCode gap analysis**: `docs/OPENCODE_GAP_ANALYSIS.md` — 16-row
  feature table (OpenCode vs Aegis), studied read-only from the reference
  clone; UX patterns rebuilt from scratch, zero copied code.
- **KB completeness audit**: 212 → **252 techniques, 23 packs**. New packs:
  `reconnaissance` (ATT&CK recon/discovery), `identity_attacks` (credential
  access depth), `api_security` (OWASP API Top 10 2023), `llm_model_attacks`
  (OWASP LLM Apps 2025 model layer). Full ATT&CK-tactic + OWASP cross-check
  in `docs/SCOPE_AND_LIMITS.md`, with deliberate omissions listed honestly.
- **REPL upgrades**: persistent conversation sessions (`/sessions`,
  `/resume`, `/rename`), numbered slash-command palette, formatted tool-call
  blocks (⏺/✓/✗ + duration), unified diff previews in the approval flow for
  file edits, @-file mentions.
- **`aegis watch` (SOC-in-a-box)**: continuous local-workspace monitoring
  (`--once`/`--interval`), change-detected rescans, secret + KB-pattern
  detection, alert log, auto-triage (fingerprint dedupe, severity-ranked
  queue), scheduled hunts (`--schedule daily|hourly`), and
  `aegis respond timeline` (chronological incident timeline from audit +
  alerts + triage).
- **241 tests green.** Defensive-only boundary unchanged.

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
