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

## Coverage cross-check

The KB was cross-checked against MITRE ATT&CK's tactic list and OWASP's
top-risk lists. "Covered" means: the KB teaches the TTP at detection
level (mechanism, telemetry indicators, detection patterns, mitigations)
and the engine acts on it where it passes through the agent.

**MITRE ATT&CK (Enterprise) tactics:**

| Tactic | Aegis coverage (v1) |
|---|---|
| Reconnaissance | Partial — detection of recon scanning, pretexting tells; active recon tradecraft deliberately shallow |
| Resource Development | Partial — dark-market infrastructure concepts, compromised tooling; no acquisition tradecraft |
| Initial Access | Yes (detection level) — phishing/vishing, web exploitation, supply chain |
| Execution | Yes — agent-as-execution-vector (injection, tool poisoning), malware behavior |
| Persistence | Yes — agent + host persistence TTPs |
| Privilege Escalation | Yes — incl. agent-specific paths (approval fatigue, sandbox escape) |
| Defense Evasion | Yes — log tampering, LOLBins-style living-off-tools, slow-drip |
| Credential Access | Yes — exfiltration pack + dumping-tool detection |
| Discovery | Light — AD/scan detection; not a focus |
| Lateral Movement | Yes (detection level) — network attacks pack |
| Collection | Yes — staging + harvesting TTPs |
| Command and Control | Yes (detection level) — beaconing, tunneling, RAT behavior |
| Exfiltration | Yes — egress pack is built for this |
| Impact | Partial — ransomware/wiper behaviors at detection level; destructive-impact forensics out of scope |

**OWASP Top 10 for LLM Applications (2025):** LLM01 (prompt injection),
LLM02 (sensitive disclosure), LLM03 (supply chain), LLM05 (improper output
handling), LLM06 (excessive agency), LLM07 (system prompt leakage) are
covered by packs and/or enforced in-product by the guard. LLM04
(model poisoning) is covered for *data* poisoning (tool output, memory);
**training-time** model poisoning is out of scope. LLM10 (unbounded
consumption) is partially covered (distillation-probing detection).
**LLM08 (vector and embedding weaknesses) is not covered in v1** —
deliberate omission, see below.

**OWASP Top 10 (web):** covered at vuln-class/detection level by the
`web_exploitation` pack (SQLi, XSS, SSRF, deserialization, auth flaws,
IDOR, XXE, SSTI, path traversal, command injection, CSRF, JWT).

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
- **ICS/OT-specific TTPs** and **mobile-malware specifics** — not in v1.
- **Vector/embedding weaknesses (OWASP LLM08)** — not in v1.
- **Training-time model poisoning** — out of scope; the trusted-provider
  assumption is documented in SECURITY.md.

If you need any of these for legitimate defensive work, they belong in a
later version with explicit scoping — not smuggled into v1.
