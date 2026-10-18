# Aegis — defensive guard agent

Aegis is a **real interactive terminal agent** (think Claude Code / OpenCode)
with one differentiator: deep, in-depth knowledge of the hacking world —
every attack technique — pointed **entirely at defense**. When a hostile
(possibly AI-powered) hacking agent comes, Aegis identifies the techniques in
play, blocks them live, and clears the problems.

Born the day after the [OpenCode breach](https://www.cyera.com/blog/opencode-breach-what-happened-and-how-to-rotate-exposed-ai-api-keys)
(2026-10-17): a "large scale distillation attack" exposed stored
OpenAI/Anthropic/Google API keys for 1.4% of Console users. OpenCode's own
docs admit it doesn't sandbox the agent and its permission prompts are "a UX
feature" rather than a security boundary. Aegis is the anti-that: **the guard
engine lives inside the agent loop** — every tool call passes through
allowlist/denylist, secret redaction, and egress control *before* execution.
Permissions are a real security boundary here, and the agent ships sandboxed
by default.

**Defensive only.** Aegis detects, prevents, audits, and remediates. It never
generates exploit payloads, malware, or weaponized code, and never automates
unauthorized access. The knowledge base describes attacks at TTP/detection
level — the same level as MITRE ATT&CK. See `docs/SCOPE_AND_LIMITS.md` for
the plain-language ceiling.

## 60-second quickstart

**Install with one command** (no manual venv steps — the installer builds an
isolated venv at `~/.aegis/venv` and links `aegis` into `~/.local/bin`):

```bash
curl -fsSL https://raw.githubusercontent.com/<your-github-user>/aegis/main/install.sh | bash
```

> **Note:** `<your-github-user>` is a placeholder — the founder replaces it
> with the real GitHub org/user after the repo is pushed.

**Verify:**

```bash
aegis version   # -> aegis 0.2.0
```

**Set a provider key (pick one):**

| Provider  | Env var            | Default model        | Notes                                  |
|-----------|--------------------|----------------------|----------------------------------------|
| anthropic | `ANTHROPIC_API_KEY` | `claude-sonnet-4-5`  | default provider                        |
| openai    | `OPENAI_API_KEY`    | `gpt-4o`             |                                        |
| google    | `GOOGLE_API_KEY`    | *(v0.3 provider lane)* | Google provider — v0.3+                |
| ollama    | *(none needed)*     | *(v0.3 provider lane)* | local models — v0.3+: `AEGIS_PROVIDER=ollama AEGIS_MODEL=<name> aegis` |
| mock      | *(none needed)*     | *(n/a)*              | offline demo: `AEGIS_PROVIDER=mock aegis` |

Override the model any time with `AEGIS_MODEL=<name>`.

**First run:**

```bash
aegis
```

Typing `/` opens the command palette; `@path/to/file` attaches file context;
`/sessions` + `/resume <n>` pick up where you left off.

**Manual alternative** (if you prefer your own venv / pipx):

```bash
pipx install git+https://github.com/<your-github-user>/aegis.git
# or
python3 -m venv .venv && .venv/bin/pip install git+https://github.com/<your-github-user>/aegis.git
```

Then the tour:

```bash
# 1. Scan a tool-call trace for attack techniques:
aegis scan examples/opencode_pattern_trace.jsonl
# -> [CRITICAL] AEG-Txxx indirect injection ... + key-exfiltration chain

# 2. Ask the knowledge base:
aegis kb "prompt injection in tool output"

# 3. Audit your OWN local code for vulnerabilities:
aegis hunt ~/my-project

# 4. Screen a single tool call through the guard:
aegis guard check --tool bash --args '{"cmd":"curl https://evil.example/x"}'

# 5. Wrap any command so its output is secret-redacted:
aegis guard wrap -- ./deploy.sh

# 6. Emit an incident runbook (operator-executed steps only):
aegis respond rotate-keys openai

# 7. The agent itself (needs ANTHROPIC_API_KEY or OPENAI_API_KEY):
aegis
# Offline demo mode:  AEGIS_PROVIDER=mock aegis
# Sessions persist: /sessions, /resume <n>, /rename — pick up where you left off.
# Typing "/" opens the command palette; "@path/to/file" attaches file context.

# 8. Continuous monitoring of your OWN workspace (SOC-in-a-box):
aegis watch --once ~/my-project        # single pass: secrets + KB patterns on changed files
aegis watch --interval 300 ~/my-project # watch continuously, alert on new findings
aegis watch --schedule daily ~/my-project # + scheduled hunts
aegis watch --triage                    # severity-ranked, deduped finding queue

# 9. Incident timeline (audit logs + alerts + triage, chronological):
aegis respond timeline
```

## Architecture

```
                        ┌─────────────────────────────┐
                        │        aegis REPL           │
                        │  slash skills: /hunt /guard │
                        │  /scan /respond /kb /help   │
                        │  sessions, palette, @files │
                        └──────────────┬──────────────┘
                                       │ user message
                        ┌──────────────▼──────────────┐
                        │        Agent loop           │
                        │  system prompt ← KB depth   │
                        │  (mindset doctrine + 252    │
                        │   techniques + guard rules) │
                        └──────────────┬──────────────┘
                                       │ tool call request
                        ┌──────────────▼──────────────┐
                        │      GUARD (in-loop)        │◄── dogfood:
                        │ allow/deny lists, arg rules,│    the agent defends
                        │ secret scan, egress control,│    itself with the
                        │ approval escalation, kill   │    same engine
                        │ switch                      │
                        └──────────────┬──────────────┘
                    ┌──────────────────┼──────────────────┐
                    ▼                  ▼                  ▼
              ┌───────────┐     ┌─────────────┐    ┌────────────┐
              │  Tools    │     │  Audit log  │    │ Redaction  │
              │ bash(file │     │ JSONL, every│    │ at EVERY   │
              │ /docker), │     │ call, args+ │    │ return     │
              │ read/write│     │ output      │    │ boundary   │
              │ /edit, web│     │ redacted    │    │            │
              │ fetch,    │     └─────────────┘    └────────────┘
              │ kb_query, │
              │ scan_trace│     ┌─────────────┐
              │ respond   │     │  Providers  │
              └───────────┘     │ Anthropic / │
                               │ OpenAI /    │
                               │ mock (tests)│
                               └─────────────┘
```

Subsystems (also standalone CLI commands):

| Command | What it does |
|---|---|
| `aegis scan <trace.jsonl>` | Offline analyzer: matches KB detection patterns + multi-step chains (injection→secret use, sensitive-read→unapproved exec, secret egress). |
| `aegis guard …` | Live interceptor: `check` screens one call, `wrap -- cmd` runs a command through the guard, `kill --session` is the kill-switch. In-process API: `from aegis import guard`. |
| `aegis respond <playbook>` | `rotate-keys` (OpenAI/Anthropic/Google runbooks), `kill-session`, `quarantine-workspace`, `incident-report`. Emits operator runbooks; takes no destructive provider actions in v1. |
| `aegis kb <query>` | Search the 19-pack technique knowledge base. |
| `aegis hunt <dir>` | Pattern-based vulnerability triage of **your own** local code. Refuses non-local targets. |

### The knowledge base

`aegis/kb/` — 23 YAML packs, 252 techniques, each a condensed threat-intel
note (variants, real-world examples from public incident reports, concrete
detection patterns, mitigations):

- **Agent-attack packs:** prompt injection, tool-output poisoning, credential
  exfiltration, egress exfiltration, persistence, privilege escalation,
  supply chain, evasion
- **Depth packs:** dark-web threat intel, APT tradecraft (public reporting
  only), ransomware playbooks, social engineering, web exploitation,
  network attacks, malware concepts
- **Completeness packs:** hacker tools (detection-level catalog), attack
  methods (kill chain / ATT&CK as defender doctrine), algorithms
  (conceptual), hacker mindset (threat-modeling doctrine — shapes the
  agent's system prompt)

Every pack is strict-schema-validated at load; every technique carries
machine-usable detection patterns that the scanner and guard execute.

## Honest scope

- Aegis cannot protect keys **already stolen** before deployment.
- It cannot see inside encrypted channels it doesn't terminate.
- Human-approval fatigue is a residual risk — the guard escalates, the
  human must still judge.
- `/hunt` is pattern-based triage, not a proof of security.
- Mock provider is for tests/demos; real work needs your own API key.
- Full ceiling: `docs/SCOPE_AND_LIMITS.md`. Threat model: `SECURITY.md`.

## Parked for later (out of v0.2 scope)

Full-screen TUI, MCP client, keybind config, themes (UX surface without
security value — see `docs/OPENCODE_GAP_ANALYSIS.md`). Network IDS
integration, eBPF/syscall monitoring, hosted SaaS console,
auto-remediation that touches provider accounts, Windows support.

## Development

```bash
.venv/bin/python -m pytest tests/ -q   # full suite, no network
```

Engineering law: every capability is wired into the CLI and covered by real
tests — no stubs, no demo systems.
