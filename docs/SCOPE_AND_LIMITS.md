# SCOPE_AND_LIMITS.md — the plain-language ceiling

Aegis is a strong defensive layer, not a magic shield. This page says
exactly what it can and cannot do, in plain language.

## The ceiling, plainly

1. **Aegis cannot protect secrets that were already stolen** before you
   deployed it. If keys leaked last month, rotating them (`aegis respond
   rotate-keys`) is the fix — no tool can un-leak them.
2. **Aegis cannot see inside encrypted channels it doesn't terminate.**
   If the agent talks to an attacker-controlled TLS endpoint, Aegis sees
   the domain and the (redacted) shape of the traffic, not the plaintext.
3. **The human approval is only as good as the human.** The guard escalates
   high-severity calls to you. Approval fatigue — clicking "yes" on
   everything — defeats the strongest guard ever built. When in doubt,
   deny, then investigate.
4. **Shape-based detection has edges.** Secret redaction matches known
   secret shapes (plus split-token, env-indirection, and base64 tricks).
   A genuinely novel exfiltration encoding can slip past the patterns —
   which is why the egress domain allowlist exists as the backstop.
5. **`/hunt` is triage, not a proof.** It matches known-dangerous code
   patterns in your own codebase. A clean `/hunt` report is not a clean
   bill of health.
6. **Aegis defends the agent it guards.** Attacks that never pass through
   the guarded loop — direct attacks on your servers, your provider
   account, your colleagues' laptops — are outside its view.
7. **A compromised host underneath Aegis wins.** If the OS or container
   runtime is already owned, no in-agent guard can be trusted. Keep the
   host patched and the Docker daemon sane.

## Allowed security-tool surface (v0.3)

Aegis is a defensive agent, and its tool repertoire is a *defensive* one:

- **Allowed, guard-screened:** operating security tooling on the user's OWN
  explicitly-scoped local assets via the sandboxed bash tool — vulnerability
  scanners, static analyzers, log analyzers, and similar — with the KB guiding
  interpretation of results. Dual-use recon/scanner tools (nmap, sqlmap,
  hydra, …) are NOT blanket-denied, because defenders legitimately need them
  on their own networks; they stay guard-screened, and high-severity usage
  pauses for human approval. The operator is responsible for scope: only ever
  point these at systems you own or are authorized to test.
- **Always denied:** primarily-offensive kits are blocked at the guard layer,
  in every mode, with no override — msfconsole/msfvenom/msfdb, mimikatz /
  pypykatz, Empire/Starkiller, Veil, Shellter, BeEF, RouterSploit, autopwn
  tooling, Cobalt Strike artifacts. This is not a configurable denylist; it
  is part of the defensive-only boundary.
- **Never built:** exploit payload generation, credential-theft automation,
  and attack execution against any target remain out of scope, permanently.

## Coverage cross-check

The KB was cross-checked against MITRE ATT&CK's tactic list and OWASP's
top-risk lists. "Covered" means: the KB teaches the TTP at detection
level (mechanism, telemetry indicators, detection patterns, mitigations)
and the engine acts on it where it passes through the agent.

**MITRE ATT&CK (Enterprise) tactics (v0.2):**

| Tactic | Aegis coverage |
|---|---|
| Reconnaissance | Yes (detection level) — `reconnaissance` pack: external recon + internal discovery TTPs |
| Resource Development | Partial — dark-market infrastructure concepts, compromised tooling; no acquisition tradecraft |
| Initial Access | Yes (detection level) — phishing/vishing, web exploitation, supply chain |
| Execution | Yes — agent-as-execution-vector (injection, tool poisoning), malware behavior |
| Persistence | Yes — agent + host persistence TTPs |
| Privilege Escalation | Yes — incl. agent-specific paths (approval fatigue, sandbox escape) |
| Defense Evasion | Yes — log tampering, LOLBins-style living-off-tools, slow-drip |
| Credential Access | Yes — deepened in v0.2 (`identity_attacks` pack: kerberoasting, DCSync, ticket forgery, spraying, OAuth abuse, …) |
| Discovery | Yes (detection level) — `reconnaissance` pack; AD/scan detection |
| Lateral Movement | Yes (detection level) — network attacks pack |
| Collection | Partial — staging + harvesting TTPs; screen/audio capture thin |
| Command and Control | Yes (detection level) — beaconing, tunneling, RAT behavior |
| Exfiltration | Yes — egress pack is built for this |
| Impact | Partial — ransomware/wiper behaviors at detection level; destructive-impact forensics out of scope |

**OWASP Top 10 for LLM Applications (2025) (v0.2):** all ten risks covered
at detection level. LLM01/02/03/05/06/07/10 by the agent-harness packs and/or
guard enforcement; LLM04 (data poisoning: tool output, memory, RAG) and
LLM08 (vector/embedding weaknesses) and LLM09 (misinformation) by the
`llm_model_attacks` pack. **Training-time** model poisoning remains out of
scope — the trusted-provider assumption is documented in SECURITY.md.

**OWASP Top 10 (web):** covered at vuln-class/detection level by the
`web_exploitation` pack (SQLi, XSS, SSRF, deserialization, auth flaws,
IDOR, XXE, SSTI, path traversal, command injection, CSRF, JWT).
**OWASP API Security Top 10 (2023):** covered by the `api_security` pack
(BOLA, authZ, mass assignment, excessive exposure, rate abuse, BFLA,
SSRF-in-API, misconfiguration, unsafe consumption, inventory/shadow APIs).

## Deliberate omissions (by design, not by accident)

These were left out on purpose, because including them would cross the
defensive-only line or blow up v1's scope:

- **Operational attack instructions, payloads, exploit code, and tool
  usage guides.** The KB describes what attacks look like and how to stop
  them — never how to perform them.
- **Dark-web access guidance.** The `darkweb_threat_intel` pack covers how
  stolen data moves and is monetized *as concepts*, plus the indicators
  defenders monitor. Anything resembling "how to access" was summarized
  at detection level or omitted.
- **Zero-day exploit mechanics.** Covered only as generic behavioral
  detection (how 0-day exploitation looks in telemetry), never as
  vulnerability details that would enable exploitation.
- **APT operational detail beyond public reporting.** The `apt_tradecraft`
  pack is drawn strictly from public threat reports (Mandiant,
  CrowdStrike, CISA, etc.). Non-public tradecraft is out of scope.
- **ICS/OT-specific TTPs** — out of Aegis's agent-focused scope (v0.1+v0.2).
- **Mobile-platform attacks** (sideloading, MDM abuse) — niche for this
  product; residual gap, noted honestly.
- **DDoS depth** (amplification, botnets, L7) — covered at survey level only.
- **OWASP A05 security misconfiguration as a standalone family** — partially
  addressed via the API pack; full treatment deferred.
- **Collection-tactic depth** (screen/audio capture) — thin coverage.
- **Offensive how-to detail** (e.g., step-by-step credential-attack
  tradecraft, tool usage) — deliberately omitted per the defensive-only
  boundary; entries stay at MITRE ATT&CK TTP/detection level.

If you need any of these for legitimate defensive work, they belong in a
later version with explicit scoping — not smuggled into a release.
