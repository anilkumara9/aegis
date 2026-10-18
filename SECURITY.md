# SECURITY.md — Aegis threat model

## What Aegis is

A defensive guard agent: a terminal AI agent whose tool calls are screened
by an in-loop guard (allowlists, secret redaction, egress control, approval
escalation, kill-switch), backed by a 212-technique defensive knowledge
base, an offline trace scanner, and incident-response runbooks.

## Threat model

**Trusted:** the human operator; the local machine Aegis runs on; the model
provider you configured (Anthropic/OpenAI) and your API key handling.

**Untrusted:** everything the agent reads or is told — tool outputs,
webpages, files, docs, chat history, MCP tool descriptions. Aegis assumes
any of these can carry prompt injection or poisoned instructions, which is
why tool *outputs* are scanned and redacted, not just inputs.

**Defended in v1:**
- Prompt injection (direct, indirect via tool output, smuggled in docs)
  steering the agent toward harmful tool calls.
- Credential/secret exfiltration through tool args, outputs, markdown
  URLs, webhooks, env-var indirection, base64 smuggling.
- Egress to non-allowlisted domains; secret-shaped payloads in outbound
  calls.
- Permission-escalation chains (sensitive read → unapproved exec),
  dangerous shell patterns (fork bombs, `rm -rf /`, raw disk writes).
- Persistence and supply-chain tricks executed *through the agent's own
  tools* (config backdoors, skill trojans, malicious packages the agent
  is told to install).

## What Aegis does NOT defend against

- Keys/secrets **already stolen** before Aegis was deployed.
- Attacks that never pass through the guarded agent (direct attacks on
  your infrastructure, the model provider, or other tooling).
- Encrypted channels Aegis doesn't terminate — it can't inspect what it
  can't see.
- A compromised host OS / container runtime underneath the sandbox.
- Social engineering of the *operator* (the approval prompt is only as
  good as the human answering it — approval fatigue is a residual risk).
- Model-level attacks (training-time poisoning, weight tampering) — the
  provider is trusted in v1's model.
- Anything requiring network IDS, eBPF/syscall monitoring, or a hosted
  console — parked, see README.

## Defensive-only boundary

Aegis never generates exploit payloads, malware, or weaponized attack code,
and never automates unauthorized access, credential theft, or exploitation
against any target. The knowledge base is TTP/detection-level knowledge
(how attacks work, what they look like in telemetry, how to stop them) —
the same level as MITRE ATT&CK. `/hunt` audits only your own explicitly
specified local systems and refuses anything non-local.

## Reporting a vulnerability

Found a security issue in Aegis itself? Please report it responsibly.

- **Contact:** _[founder to set: security contact email]_ —
  this placeholder must be replaced before any public release.
- Include: affected version, steps to reproduce against a local fixture,
  and the impact you see. Do not test against anyone else's systems.
- We aim to acknowledge within 72 hours.

## Known limitations (v1)

- Docker sandbox is used when available; without Docker, bash runs on the
  host with guard screening still applied (the REPL says so out loud).
- The mock provider exists for tests/demos only.
- Secret detection is shape-based: novel exfil encodings can evade it;
  the egress allowlist is the backstop, not the pattern list.
