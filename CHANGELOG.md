# Changelog

## v0.7 Lane A (unreleased) — polyglot coding skill system

- **Toolchain detection** (`aegis/polyglot.py`): python/node/rust/go/java/
  c++/c# detection from project files (strong) and extensions (fallback);
  per-language build/test/lint commands with availability checks and
  concrete install hints; real local runs with timeouts; build output
  redacted at capture so secrets never reach reports, context, or logs.
  Stale-`__pycache__` race fixed: Python runs clear disposable bytecode
  caches and set `PYTHONDONTWRITEBYTECODE=1` so edit→test cycles are
  deterministic.
- **Repo maps** (`aegis/repomap.py`, `/repomap`): languages, entry points,
  build system, dependency manifests, test layout, config files.
- **Coding skills**: `/build`, `/test`, `/fix` (drives the agent loop,
  capped at 5 TDD rounds, reports "stuck" honestly with what was tried),
  `/refactor <dir> [target]` (re-runs tests after; green→red reported as
  a regression). All local-only, dev-mode only.
- **TDD loop** (`aegis/tdd.py`): write → run real tests → feed failures
  back → repeat until green or cap; every step logged to on_text, the
  result, and the audit log (`tdd_step`, redacted).
- **Codebase index** (`aegis/index.py`, `/index`, `index_query` tool):
  per-file records (path/language/size/mtime/hash/symbols/imports —
  never file contents), dependency-free polling watcher re-indexing only
  changed files, keyword+symbol retriever, persisted cache under
  `~/.aegis/index/` with mtime-based invalidation. Tradeoffs documented
  in `docs/INDEXING.md` (polling vs watchdog vs rescan vs embeddings).
- **Plugin system** (`aegis/plugins.py`): `~/.aegis/plugins/*.py` +
  `plugins.yaml` discovery; malformed plugins skipped with warnings;
  handler exceptions isolated; core tools win name collisions; plugins
  exposed to the agent loop as tools (REPL boot, non-fatal). Shipped
  example: `examples/plugins/todo_scan.py` (TODO/FIXME scanner, redacts
  secrets in its own output).
- **Secrets**: redaction verified on the new paths — test/build output,
  TDD failure feedback, plugin outputs, and the audit log (fake
  `sk-ant-…` key in fixtures → `[REDACTED:…]` everywhere, never echoed).

## v0.5.0 (2026-10-18) — god-level power + demo-ectomy

Founder order: "upgrade everything more powerfully; god-level super power;
remove unnecessary demo stuff."

- **Demo-ectomy audit**: swept the codebase for stubs, placeholders, and
  half-wired features — all `pass` sites verified as legitimate defensive
  exception handling; every CLI command exercised end to end. Fixed a
  test-ordering dependency (`test_kb.py::test_ids_unique_and_in_range`
  failed standalone): KB authoring-contract registration moved to
  `tests/conftest.py` (imported on every run), frozen `test_kb.py`
  byte-unchanged.
- **Defensive inspection arsenal** (read-only, local-only, guard-screened):
  `ps` (process list), `netconns` (connections), `hash` (SHA-256 +
  integrity baselines), `search` (deep code search). Wired into the agent
  loop.
- **Plan-then-execute**: `/planexec <task>` — the model proposes an explicit
  JSON step plan, the guard screens every step's shape before anything runs,
  and only a fully approved plan executes. A blocked step aborts with an
  explanation instead of failing halfway.
- **Guard hardening vs the 386-technique KB**: reverse-shell and LOLBin
  download-cradle deny patterns (`/dev/tcp`, `mkfifo`, `nc -e`, PowerShell
  IEX+WebClient, certutil, bitsadmin); session taint tracking (sensitive
  reads escalate later outbound calls); live multi-step chain detection in
  the pre-execution path (previously scan-only).
- **Performance**: KB binary cache — load 4.36s → 0.006s with
  mtime-fingerprint invalidation; corrupt cache falls back to full load.
- **Providers**: fixed silent provider errors in the REPL (now surfaced via
  the display channel); MockProvider supports error turns for tests.

## v0.4.0 (2026-10-18) — Godfather Program

"Make the agent the godfather of hacking: supreme defensive knowledge, then
supreme defensive capability."

- **Pillar 1 — expert training team**: panel of 8 domain specialists hired to
  train the agent.
- **8 new KB packs, 96 techniques (AEG-T253–T348)**: `apt_campaigns`
  (named-actor campaign TTPs from public reporting), `web_attack_flows`
  (exploitation workflows & detection), `c2_operations` (C2 operations at
  detection level), `initial_access` (social engineering & initial access),
  `cloud_attacks` (cloud / container / CI-CD attack paths), `agent_attacks`
  (AI-agent attack techniques), `lateral_movement` (network intrusion &
  lateral movement), `cybercrime_economy` (dark-web threat intel & cybercrime
  economy). Every technique: condensed threat-intel note with variants,
  public-report examples, indicators, executable detection patterns,
  mitigations. Defensive-only boundary held (no payloads, no how-tos).
- **38 hacker-mindset doctrine notes folded into `hacker_mindset` as
  AEG-T349–T386**: how APT operators, web attackers, malware operators,
  social engineers, cloud attackers, agent attackers, intruders, and
  cybercriminals think — written for the defender's system prompt.
- **KB now 31 packs / 386 techniques.** New `tests/test_kb_v04.py` extends
  the authoring contract (frozen v0.1 file untouched): ID-range registration,
  depth bar, per-technique positive/negative fixtures, pack-level canonical
  probes, boundary re-check.
- **Pillar 2 — adversary emulation** (`aegis emulate --target <dir>
  [--campaign <name>]`, `/emulate` skill): chains KB techniques into 5-stage
  campaign narratives (recon → initial access → execution → persistence →
  exfil; 3 built-in campaigns) against YOUR OWN local assets, then
  purple-team verifies each stage through the real detection stack —
  COVERED vs GAP per stage. Plan-level narratives + detection verification
  only: nothing executed, markers inert, non-local targets refused.
- **Pillar 3 — attack graphs** (`aegis graph <dir> [--json] [--top N]`):
  read-only analysis of a user-owned system (secrets, .env, Docker-as-root,
  CI configs, …) → RANKED adversary attack paths (KB technique chains in
  kill-chain order), each grounded in target evidence and annotated with the
  defenses that break it. Markdown + JSON.
- **Pillar 4 — MCP client** (`aegis mcp list|call`, `~/.aegis/mcp.json`):
  stdio-transport MCP client; every MCP tool call guard-screened exactly
  like a native tool (allowlist/deny, secret redaction, approval); MCP tools
  registered into the agent loop's tool set. Docs: `docs/MCP_CLIENT.md`.
- **Doctrine cap configurable**: `AEGIS_DOCTRINE_CHARS` env (default fits
  all 44,292 chars / 48 mindset notes; ≈+8,800 input tokens per call —
  see `docs/SCOPE_AND_LIMITS.md` for the cost tradeoff).

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
