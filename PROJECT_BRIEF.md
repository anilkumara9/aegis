# Aegis — Defensive Guard Agent (working title; founder may rename)

**Commissioned:** 2026-10-18 by the founder.
**Trigger:** OpenCode breach disclosed 2026-10-17 — "large scale distillation attack",
1.4% of Console users, stored OpenAI/Anthropic/Google provider API keys exposed from a
legacy system being decommissioned. Co-founder: "whole new world with ai powered hacking."
**Mission:** An agent with deep, in-depth knowledge of the hacking world — every attack
technique — pointed entirely at DEFENSE: when a hostile (possibly AI-powered) hacking
agent comes, Aegis identifies the techniques in play and clears the problems.
Companies deploy it to protect their agents, systems, and secrets.

## Non-negotiable boundary

DEFENSIVE ONLY. This product detects, prevents, audits, and remediates. It NEVER:
- generates exploit payloads, malware, or weaponized attack code of any kind;
- automates unauthorized access, credential theft, or exploitation against any target;
- ships offensive tooling relabeled as "testing" without explicit target authorization.

The technique knowledge base describes attacks at the TTP level (how it works,
indicators, detection, mitigation) — the same level as MITRE ATT&CK, which is public
defensive knowledge. Detection fixtures simulate attack *traces* (tool-call logs),
never live exploits. Any "red team" self-test runs against local fixtures only.

## The product: a real CLI agent (founder order 2026-10-18)

Not a demo, not a toolkit of scripts — a REAL interactive terminal agent like
Claude Code / OpenCode. `aegis` drops the user into a chat REPL; the agent
reasons, calls tools in a loop, streams output, and completes tasks. Its
differentiator: deep, in-depth hacking knowledge wired into its brain, pointed
entirely at defense — when a hostile (possibly AI-powered) hacking agent comes,
Aegis identifies every technique in play and clears the problems.

- Agent loop: model-agnostic (user's own API key via env, e.g. ANTHROPIC_API_KEY /
  OPENAI_API_KEY — same pattern as OpenCode; provider abstraction with
  Anthropic + OpenAI in v1, streaming responses, multi-step tool loop).
- Tool set: bash (with optional Docker sandbox), read/write/edit files, web
  fetch, kb_query (search the technique knowledge base mid-reasoning),
  scan_trace, respond playbooks. Every tool call appended to a JSONL audit log.
- The guard engine lives INSIDE the loop: every tool call passes through
  allowlist/denylist, secret redaction, and egress control BEFORE execution —
  the agent dogfoods its own defense. This is the anti-OpenCode: permissions
  are a real security boundary, and the agent ships sandboxed by default.
- System prompt built from the KB: attack techniques, indicators, mitigations —
  the agent reasons like a defender who has studied every attack.
- Built-in defensive skills (slash commands): /hunt (audit the user's OWN
  codebase/systems for vulnerabilities — defensive auditing of own assets only,
  explicit local scope), /guard (start live monitoring), /scan (analyze a
  trace), /respond (incident runbook), /kb (query technique knowledge).
- The v1 components below (KB, scan, guard, respond) are subsystems of this
  agent — they still ship as standalone CLI commands too.

Acceptance addition: the `aegis` REPL boots, runs a multi-step tool loop
against a real model, blocks a planted prompt-injection + exfiltration attempt
LIVE inside the loop (test with a mock provider), and the audit log captures
every tool call.

## v0.2 scope (founder order 2026-10-18) — "OpenCode interface parity + autonomous defensive team"

Reference: /tmp/opencode-ref — shallow clone of https://github.com/anomalyco/opencode.git
(authorized by the founder for interface/UX analysis). READ-ONLY analysis: study
OpenCode's interface, UI/UX, and architecture, then REBUILD from scratch — never
copy their code verbatim into Aegis.

1. Interface study: TUI structure, screens, keybindings, command palette, session
   management, tool-call display, diff previews, streaming, permission prompts,
   MCP integration, config system. Deliverable: docs/OPENCODE_GAP_ANALYSIS.md
   with a feature-by-feature table vs Aegis.
2. "Have you fed everything" audit: verify the KB (19 packs / 212 techniques)
   against the completeness order; fill genuine gaps at TTP/detection level.
3. Close the highest-value UX gaps in the Aegis REPL toward OpenCode-class UX
   (session persistence/resume, richer tool display, slash-command palette,
   streaming, diff previews — whatever fits Python cleanly; all real, all tested).
4. "Replace an entire hacker team" = autonomous DEFENSIVE security team
   (SOC-in-a-box), strictly defensive, for the user's own assets: `aegis watch`
   (continuous monitoring of a workspace — rescan on change, alert), scheduled
   hunts, auto-triage (dedupe + severity-ranked finding queue), incident
   timeline in `aegis respond`.
5. Tests for everything new, pytest green, commit locally (no push — founder
   pushes with their own token). Defensive-only boundary unchanged.

## v1 scope (what the builder ships)

Repo: `~/workspace/aegis`. Language: Python 3.10+, package `aegis`, CLI `aegis`.
Engineering law: every capability wired into the CLI and covered by real tests —
no stubs, no demo systems, no synthetic-data hand-waving.

### 1. Technique knowledge base (`aegis/kb/`, YAML packs)
Each technique: `id` (AEG-T001…), name, category, description, how-it-works
(defensive TTP level), indicators of compromise, detection rule reference,
severity (critical/high/medium/low), mitigations, references.
Minimum packs (10 techniques each is the bar, depth over count):
- `prompt_injection.yaml` — direct injection, indirect (tool-output) injection,
  instruction smuggling in docs/webpages, multi-turn conditioning, jailbreak
  families relevant to agent harnesses.
- `tool_output_poisoning.yaml` — malicious tool results steering the agent,
  MCP tool-description poisoning ("rug pull" tool updates), tool shadowing /
  name squatting.
- `credential_exfiltration.yaml` — key theft via tool args, exfil via markdown
  image URLs / webhooks, env-var harvesting, prompt-injection-driven secret
  disclosure, the OpenCode-pattern (keys at rest in a console/workspace store).
- `egress_exfiltration.yaml` — DNS tunneling, data smuggled in API calls,
  clipboard/file-write staging, model-distillation-style probing
  (high-volume extraction queries against an agent endpoint).
- `persistence.yaml` — agent memory poisoning, config-file backdoors,
  cron/scheduled-task planting by an agent, skill/plugin trojans.
- `privilege_escalation.yaml` — permission-prompt fatigue/social-engineering
  the human approver, sandbox escape via allowed tools (curl|bash chains),
  overly broad tool grants.
- `supply_chain.yaml` — malicious packages installed by an agent following
  injected instructions, typosquatted MCP servers / skills, compromised
  agent plugins.
- `evasion.yaml` — log tampering, trace deletion, living-off-allowed-tools,
  slow-drip exfiltration under rate limits.

### KB depth order (founder, 2026-10-18)
The KB must carry genuinely deep, in-depth knowledge — dark web, pro hacker-team
tradecraft, the full landscape — at TTP/detection level: how each thing works,
what it looks like in telemetry, how to detect and kill it. NEVER operational
attack instructions, access guides, or payloads. Additional packs:
- `darkweb_threat_intel.yaml` — how stolen credentials/data move through dark
  markets (concepts only, never access guidance), common monetization TTPs,
  the threat-intel indicators defenders monitor.
- `apt_tradecraft.yaml` — pro-team TTPs drawn from PUBLIC threat reporting
  (living-off-the-land binaries, zero-day usage patterns, supply-chain
  operations, long-dwell persistence) — detection level only.
- `ransomware_playbook.yaml` — RaaS affiliate model, double-extortion chain:
  initial access → lateral movement → exfil → encryption, at TTP/detection level.
- `social_engineering.yaml` — pro phishing/BEC/vishing tradecraft families and
  their detectable tells.
- `web_exploitation.yaml` — vuln classes (SQLi, XSS, SSRF, deserialization,
  auth flaws): how each manifests, detection signatures, mitigations.
- `network_attacks.yaml` — lateral movement, C2 beaconing patterns, tunneling —
  detection-focused.
- `malware_concepts.yaml` — loader/dropper/RAT concepts at behavior level for
  detection (no code, no payloads).

Depth bar: every technique entry reads like a condensed threat-intel note —
multiple variants, real-world examples from PUBLIC incident reports (with
references), concrete detection patterns, mitigations. One-line stubs fail
review. The /hunt skill and the agent's system prompt draw on this depth.

### KB completeness order (founder, 2026-10-18) — "take a time, feed EVERYTHING"
Take the time needed — completeness and accuracy over speed. The KB must cover
the hacking world in full: techniques, tools, methods, algorithms, thinking
level, hacker mindset. Additional packs:
- `hacker_tools.yaml` — catalog of well-known offensive tools (recon scanners,
  exploitation frameworks, C2 frameworks, post-exploitation kits, credential
  tools): what each tool IS conceptually, its observable network/host
  signatures, how defenders detect its use. CONCEPTUAL + DETECTION ONLY —
  never usage instructions.
- `attack_methods.yaml` — attacker methodologies: cyber kill chain, ATT&CK
  tactic flow, red-team operation planning at the conceptual level, attack
  graphs — taught as "how defenders map and break the chain."
- `algorithms.yaml` — the algorithms that matter in the hacking world, at
  conceptual level: hashing and why password-cracking works against weak
  schemes (and why modern KDFs resist), crypto-attack concepts, encoding /
  obfuscation / steganography concepts, algorithmic thinking behind
  vulnerability discovery (e.g., fuzzing concepts). Concepts + defensive
  implications, never implementation guides for wrongdoing.
- `hacker_mindset.yaml` — thinking level: how attackers think — target
  selection, path-of-least-resistance reasoning, attacker decision models,
  assumption-challenging, creativity under constraints. Taught explicitly as
  defensive doctrine: "think like an attacker so you can defend like one" —
  threat-modeling frameworks (STRIDE and kin), the defender's anticipation
  playbook. This pack shapes the agent's SYSTEM PROMPT: Aegis must reason
  with an attacker's creativity and a defender's responsibility.

Completeness rule: if a major technique family, tool class, method, or mindset
pattern from the public body of security knowledge is missing, the KB is
incomplete. Cross-check coverage against MITRE ATT&CK's tactic list and OWASP's
top-risk lists and note any deliberate omissions in SCOPE_AND_LIMITS.md.

### 2. Trace scanner (`aegis scan <trace.jsonl>`)
Offline analyzer. Input: JSONL tool-call trace
`{ts, agent, tool, args, output, approval}`. Output: findings list —
matched technique IDs, severity, evidence excerpts, recommended mitigation.
Must catch at minimum: indirect prompt injection in a tool output followed by
a secret-bearing tool call; exfiltration-shaped egress (secret-like strings
in outbound args); permission-escalation chains (read → exec without approval).

### 3. Live guard (`aegis guard`)
Interceptor that wraps agent tool calls in real time:
- allowlist/denylist per tool with arg-pattern rules from the KB;
- secret redaction on tool outputs AND on args (API keys, tokens, private keys —
  real patterns, tested; redaction must apply at every return boundary);
- egress control: outbound domain/IP allowlist, secret-shaped payload blocking;
- approval escalation: high-severity matches pause for human approval;
- kill-switch: one command revokes the session.
Ships with an in-process Python API (`from aegis import guard`) AND a
subprocess wrapper mode, both exercised by tests.

### 4. Responder (`aegis respond`)
Remediation playbooks as code + checklists: `rotate-keys` (provider-by-provider
revocation steps for OpenAI/Anthropic/Google + verification), `kill-session`,
`quarantine-workspace`, `incident-report` (markdown summary from scan findings).
Playbooks never execute destructive provider actions themselves in v1 — they
emit exact operator runbooks and verify state where read-only APIs allow.

### 5. Docs & honesty
- `README.md`: what it is, 60-second quickstart, architecture, honest scope.
- `SECURITY.md`: threat model, what Aegis does NOT defend against, contact.
- `docs/SCOPE_AND_LIMITS.md`: plain-language ceiling — e.g., Aegis cannot
  protect keys already stolen before deployment; cannot see inside encrypted
  channels it doesn't terminate; human-approval fatigue is a residual risk.
- `CHANGELOG.md`, `LICENSE` (MIT, matching founder's other public repos).

## Acceptance bar for v1
- `pytest` green: detection-rule tests against realistic fixtures (each
  technique pack has ≥1 positive and ≥1 negative fixture), redaction tests
  (incl. adversarial cases: split tokens, env-var indirection), guard
  allowlist/denylist + kill-switch tests.
- `aegis scan` demo: a bundled `examples/opencode_pattern_trace.jsonl`
  (indirect injection → key exfiltration chain) produces the expected findings.
- No network calls in tests. No secrets in repo. No placeholder functions.

## Out of scope for v1 (parked, listed in README)
Network IDS integration, eBPF/syscall monitoring, hosted SaaS console,
auto-remediation that touches provider accounts, Windows support.
