# Aegis v0.6 "Unmatched" — Lane B Plan: KB Training Wave 2

Coordinator: Lane B (training-wave-2 planner). Date: 2026-10-19.
Worktree: `~/workspace/aegis-wt-kbcoord`, branch `v06-laneB-coord` (from master `e3514e5`).
Scope of this lane: **plan only**. No pack YAML is written here; the 6–8 trainer
agents will be briefed from this document. The integration lane owns
frozen-contract registration (`tests/conftest.py`, `tests/test_kb.py`) — do not touch those.

## 1. Method

All 31 existing packs (`aegis/kb/*.yaml`) were read in full (topic map + targeted
deep reads of every pack touching a candidate domain: `algorithms`,
`apt_campaigns`, `apt_tradecraft`, `c2_operations`, `cybercrime_economy`,
`darkweb_threat_intel`, `initial_access`, `malware_concepts`, `ransomware_playbook`,
`social_engineering`, `supply_chain`). Keyword sweeps (`SCADA`, `PLC`, `side-channel`,
`rowhammer`, `spectre`, `pickle`, `TPM`, `BMC`) were run across all packs to catch
buried coverage.

## 2. Coverage map

| # | Candidate domain | Already covered (pack: IDs) | Genuinely new | Verdict |
|---|---|---|---|---|
| a | ICS/OT attack concepts | `apt_campaigns` T253 (Volt-Typhoon-style IT→OT pre-positioning); `apt_campaigns` T260 (state wipers, often OT-targeted) — **2 techniques, strategic level only** | Purdue model/IT-OT boundary concepts, OT protocol abuse concepts (Modbus/DNP3/OPC at detection level), engineering-workstation targeting, safety-system (SIS) attack concepts, OT-specific persistence, OT network monitoring/detection, ICS malware family *behaviors* (TRITON/HAVEX-style, behavior-level) | **SELECT** |
| b | Mobile attack techniques | Only incidental mentions (mobile user-agents in `initial_access` T290/T291/T298; mobile apps as API targets in `api_security` T229/T232; traffic interception in `hacker_tools` T178) — **0 dedicated techniques** | Smishing-to-app chains, rogue/sideloaded app concepts, mobile spyware/surveillanceware (Pegasus-class, behavior-level), app-permission abuse, mobile banking trojans (overlay attacks), MDM abuse, jailbreak/root detection-evasion concepts, malicious SDKs/ad-fraud modules, mobile C2 push-notification channels, baseband/SIM-toolkit concepts | **SELECT** |
| c | Cryptographic attack techniques | `algorithms` T193–T196, T201, T202 (password hashing/KDFs, salting, padding oracles + downgrade, encoding-vs-encryption, differential cryptanalysis, PQC) — **6 techniques, defensive-concept angle** | Timing side-channels, weak-RNG / nonce-reuse key compromise, certificate mis-issuance & PKI abuse (detection), TLS-stripping concepts at detection level, hash-collision chosen-prefix attacks (Shattered-class, behavior-level), key-lifecycle theft (HSM/KMS abuse concepts), encrypted-volume / full-disk-encryption attack concepts, SSH key management abuse, crypto-agility failure modes. Angle is **attack TTPs against crypto deployments**, not crypto primitives — distinct from `algorithms`' defensive-concept framing | **SELECT** |
| d | Firmware/hardware attack concepts | `apt_tradecraft` T115 (UEFI/firmware persistence); `malware_concepts` T168 (bootkits) — **2 techniques** | Secure Boot bypass *concepts*, TPM attack concepts (reset/glitch at behavior level), BMC/IPMI out-of-band management abuse, Intel ME / AMD PSP concepts, JTAG/UART debug-interface abuse, evil-maid / cold-boot concepts, hardware implants & interdiction concepts, Rowhammer-class memory attacks (detection), speculative-execution attacks (Spectre/Meltdown-class, detection-level), microcode/firmware-update abuse, hardware supply-chain (counterfeit component concepts) | **SELECT** |
| e | Model serialization / ML supply-chain attacks | `supply_chain` T081 (compromised model artifacts — pickle/.pt at load); `agent_attacks` T318 (LoRA/adapter backdoors), T319 (marketplace squatting); `web_exploitation` T142 (insecure deserialization, generic) — **4 techniques, no serialization-depth** | Pickle-deserialization RCE in ML pipelines (detection), safetensors-vs-pickle format-risk concepts, model-hub poisoning (weight backdoors that survive fine-tuning), ONNX/TF-SavedModel code-execution concepts, weight steganography / hidden-capability models, checkpoint tampering in training pipelines, dataset+model provenance & signing (Sigstore-style) concepts, quantization backdoors, malicious model-card / config-execution concepts, GPU-driver / CUDA supply-chain adjacent risks, inference-server model-loading hardening | **SELECT** |
| f | Vulnerability-research methodology for defenders | `algorithms` T199 (fuzzing), T200 (symbolic execution); `hacker_tools` T172 (vuln scanners), T173 (metasploit-class), T181 (exploit collections as patch intel); `apt_campaigns` T257 (zero-day acquisition pipelines); `attack_methods` T186/T191 (attack graphs, adversary emulation); `attack_methods` T189 (detection engineering) — **~8 techniques of direct relevance, ~45% topical overlap** | Patch-diffing (BinDiff-class) for defenders, crash triage/dedup discipline, root-cause analysis methodology, coordinated disclosure / VDP program design, bug-bounty triage for defenders, patch-verification & regression testing, PoC-for-validation discipline (proving exploitability to prioritize) | **REJECT** — below the >60% bar but the weakest marginal value: its best topics are already the *point* of existing packs, and AI-agent-specific relevance is lower than the 8 selected |
| g | C2 infrastructure detection | `c2_operations` T277–T288 (12 techniques: beacon cadence, domain fronting, DoH C2, dead-drop resolvers, fast-flux, burner domains, process injection, sandbox evasion, living-off-cloud, malleable profiles, P2P lateral C2, channel fallback); `cybercrime_economy` T343 (fast-flux); `darkweb_threat_intel` T102 (bulletproof hosting); `hacker_tools` T174 (C2 frameworks) — **~15 techniques, ~75% topical overlap** | Almost nothing genuinely new; a fresh pack would be a relabeling exercise | **REJECT** — >60% covered, with evidence above |
| h | Insider threat patterns | `cybercrime_economy` T346 (insider-access-as-a-service); `apt_campaigns` T259 (DPRK IT-worker infiltration) — **2 techniques, both "insider as initial access"** | Malicious insider data theft (departing-employee exfiltration), privilege-abuse by rogue admins, sabotage / logic-bomb concepts, credential sharing & account lending, collusion patterns, shadow-IT as insider vector, third-party/contractor insider risk, UEBA detection concepts, **agent-as-insider parallels** (compromised agent behaves like a malicious insider — detection transfer), whistleblower-vs-malicious discrimination for triage | **SELECT** |
| i | Wiper/destruction TTPs | `malware_concepts` T164 (Wipers — 1 family-level technique); `apt_campaigns` T260 (state wipers disguised as ransomware); `ransomware_playbook` T125 (backup destruction) — **3 techniques** | Wiper-vs-ransomware discrimination (decryption path never existed), MBR/partition-table destruction, MFT corruption behaviors, firmware-level destruction, backup/catalog destruction beyond T125's ransomware framing, log-destruction as anti-forensics, data-shredding vs encryption detection differences, destructive OT targeting (behavior-level), wiper staging telemetry (pre-detonation signals), recovery-planning concepts, destructive payload delivery via legitimate admin tools | **SELECT** |
| j | Fraud/BEC operations | `social_engineering` T128 (BEC — 1 technique), T138 (deepfake fraud); `cybercrime_economy` T340 (money mules), T344 (crypto cash-out) — **4 techniques, no operational depth** | BEC kill-chain (recon → compromise → mailbox rules → payment diversion), invoice/vendor fraud operations, payroll-diversion fraud, vendor email compromise (long-dwell), conversation hijacking in existing threads, deepfake voice/video in fraud operations (beyond T138's single-technique view), account-takeover-for-fraud, pig-butchering / romance-fraud operations, payment-fraud detection (wire/SWIFT verification controls), fraud-mule network detection (beyond T340's recruitment angle), business-process controls as the primary defense | **SELECT** |

## 3. Selected domains (8) — one-line rationale each

1. **Model serialization / ML supply-chain attacks** — the single most AI-agent-relevant gap: agents download and load model artifacts constantly, and existing coverage is one technique (T081).
2. **Fraud/BEC operations** — AI agents (voice/video synthesis, scaled pretexting) are the force-multiplier for modern fraud; KB has one BEC technique.
3. **Insider threat patterns** — a compromised agent *is* an insider; classic insider TTPs transfer directly to agent-threat detection.
4. **ICS/OT attack concepts** — strategic blind spot; AI agents with tool access to OT-adjacent systems are an emerging risk surface.
5. **Wiper/destruction TTPs** — destructive misuse is the worst-case AI-agent outcome; existing coverage is family-level only.
6. **Mobile attack techniques** — zero dedicated techniques; agents are increasingly deployed with mobile device control.
7. **Cryptographic attack techniques** — attack-oriented crypto TTPs (side channels, RNG failures, PKI abuse) complement `algorithms`' defensive-concept framing.
8. **Firmware/hardware attack concepts** — below-the-OS persistence is where the deepest agent-threat implants live; 2 techniques exist today.

**Rejected:** (g) C2 infrastructure detection — ~75% covered by `c2_operations` T277–T288 + T102/T343/T174 (evidence in table); (f) vulnerability-research methodology for defenders — ~45% overlap with T199/T200/T172/T173/T181/T257/T186/T191 and lower AI-agent marginal value than the 8 selected.

## 4. ID range assignments

Actual assigned ID space today: **AEG-T001 – AEG-T386, no gaps** (verified by
numeric sort of all `AEG-T\d+` matches across all 31 packs).

> Anomaly note for the integration lane: `identity_attacks.yaml` T238's
> `how_it_works` prose contains a dangling cross-reference
> "(bridge to AEG-T1528-style token abuse)" — **AEG-T1528 is not an assigned
> technique** (likely a typo for a T1xx ID). Trainers must not use or reference
> T1528. Fixing the typo is the integration lane's call, not Lane B's.

New ranges start at **T387**, 12 IDs per pack, no gaps:

| Pack file (category stem) | Domain | ID range |
|---|---|---|
| `ml_serialization_attacks.yaml` | (e) Model serialization / ML supply-chain attacks | AEG-T387 – AEG-T398 |
| `fraud_bec_operations.yaml` | (j) Fraud/BEC operations | AEG-T399 – AEG-T410 |
| `insider_threat_patterns.yaml` | (h) Insider threat patterns | AEG-T411 – AEG-T422 |
| `ics_ot_attacks.yaml` | (a) ICS/OT attack concepts | AEG-T423 – AEG-T434 |
| `wiper_destruction.yaml` | (i) Wiper/destruction TTPs | AEG-T435 – AEG-T446 |
| `mobile_attacks.yaml` | (b) Mobile attack techniques | AEG-T447 – AEG-T458 |
| `crypto_attacks.yaml` | (c) Cryptographic attack techniques | AEG-T459 – AEG-T470 |
| `firmware_hardware_attacks.yaml` | (d) Firmware/hardware attack concepts | AEG-T471 – AEG-T482 |

Total: 96 new techniques, T387–T482. File naming follows existing snake_case convention;
`category` in each technique **must equal the pack filename stem** (loader-enforced).

## 5. Per-domain trainer briefs

### Global rules (all trainers)

- **Defensive-only, absolute.** Describe attacks at TTP/detection level in the
  MITRE ATT&CK style: what the technique is, how it works *conceptually*,
  observable indicators, detection rules, mitigations. **NEVER**: operational
  attack instructions, access guides ("how to get X"), payloads, exploit code,
  step-by-step tool usage, or anything a reader could execute as an attack.
  `how_it_works` explains the *mechanism for detection purposes*, not a procedure.
- Every technique: `id` (from the assigned range), `name`, `category` (= pack stem),
  `description` (≥15 words), `how_it_works` (≥20 words, defensive TTP level),
  `indicators` (list, ≥2), `detection` (dict with `rule` string + `patterns` list of
  ≥2 regexes that **must compile** under `re.IGNORECASE` — keep them simple and
  literal-heavy; avoid exotic constructs), `severity` (critical/high/medium/low),
  `mitigations` (list, ≥2), `references` (list, ≥2 public URLs — MITRE ATT&CK,
  CISA advisories, OWASP, vendor research blogs), `variants`/`examples` optional.
- **≥10 techniques per pack** (12 IDs assigned; use all 12 if quality holds, never fewer than 10).
- Cross-reference existing IDs **only where they exist** (see out-of-scope lists).
  Never invent IDs. Never reference AEG-T1528.
- Dedup check: before writing a technique, re-read the named existing packs/IDs and
  confirm the topic is not already their subject. Overlap of *angle* (e.g. backup
  destruction in ransomware vs wiper contexts) is allowed only if the technique's
  subject is genuinely distinct — say so explicitly in the description.

---

### Brief 1 — `ml_serialization_attacks.yaml` · T387–T398

**Scope (in):** Attacks on ML model artifacts and the model supply chain, framed
for defenders of agent systems that download/load models: unsafe serialization
formats at load time, hub-published backdoored weights, checkpoint/config
execution, provenance and signing, inference-server model-loading hardening.

**Hard out-of-scope (do not duplicate):**
- `supply_chain` T081 (compromised model artifacts at load — the *general* case; your pack goes deeper on *serialization mechanisms and ML-pipeline specifics*)
- `agent_attacks` T318 (LoRA/adapter backdoors — do not redo adapter backdoors; weight-backdoor topics must be about *base-model* artifacts)
- `agent_attacks` T319 (marketplace squatting — skill/plugin marketplaces; yours is model hubs)
- `web_exploitation` T142 (insecure deserialization in web apps — generic; yours is ML-artifact-specific)
- `llm_model_attacks` T213–T217 (extraction/poisoning/RAG — data/model *behavior* attacks, not artifact loading)

**Technique topics (12):**
1. Pickle-deserialization RCE in ML pipelines (why `torch.load`/pickle is code execution; detection: load-path auditing)
2. Safetensors vs pickle: format-risk comparison for defenders (migration as mitigation)
3. Backdoored weights published on model hubs (benchmark-clean, trigger-activated behavior; detection via weight diffing)
4. Checkpoint tampering in training/fine-tune pipelines (CI for ML)
5. ONNX / TF SavedModel code-execution concepts (graph-defined ops as execution surface)
6. Malicious model configs and custom-code execution (e.g. `trust_remote_code`-class patterns, described at policy level)
7. Weight steganography / hidden-capability models (detecting anomalous weight distributions)
8. Quantization backdoors (backdoor surviving quantization; detection via pre/post-quant eval diffs)
9. Model provenance and signing (Sigstore-style signing; verification in the load path)
10. Dataset-to-model poisoning distinction (bridge: poisoning is `llm_model_attacks` T215 — yours is *artifact integrity*)
11. Inference-server model-loading hardening (sandboxed loaders, allowlisted formats, integrity checks)
12. GPU/driver supply-chain adjacent risk (CUDA/cuDNN artifacts; detection via hash pinning)

**Defensive-boundary reminder (this domain):** Describe *why* deserialization is
dangerous (object reconstruction = code execution) and *how defenders detect*
it (load-path telemetry, format allowlists) — **never** show payload construction,
never give pickle-opcode recipes, never demonstrate building a malicious model.
`trust_remote_code`-type discussions stay at policy level ("disable by default"),
never usage instructions.

---

### Brief 2 — `fraud_bec_operations.yaml` · T399–T410

**Scope (in):** Fraud *operations* — the end-to-end tradecraft of financially
motivated social/technical fraud, with emphasis on how AI (synthetic media,
scaled pretexting, agentic workflows) amplifies each stage, and the
business-process controls that defeat them.

**Hard out-of-scope (do not duplicate):**
- `social_engineering` T128 (BEC single technique — yours is the *operational* playbook: stages, mailbox tradecraft, controls)
- `social_engineering` T138 (deepfake fraud — single technique; yours covers deepfake *operations inside fraud workflows*)
- `social_engineering` T127/T135 (spear-phishing families, executive impersonation — the *lures*; yours is what happens *after* the lure lands)
- `cybercrime_economy` T340 (mule recruitment), T344 (crypto cash-out) — the *money-out* layer; yours may reference them as downstream, not re-cover
- `initial_access` T289–T300 (phishing delivery infrastructure — not yours)

**Technique topics (12):**
1. BEC kill-chain: recon → mailbox compromise → payment diversion (stage-by-stage defender breakpoints)
2. Mailbox rule manipulation for fraud concealment (auto-forward/delete rules; detection via rule-change telemetry)
3. Invoice and vendor bank-detail-change fraud (verification controls: out-of-band confirmation)
4. Payroll-diversion fraud (HR self-service abuse; detection patterns)
5. Vendor email compromise with long dwell (aged threads exploited; conversation hijacking)
6. Conversation hijacking inside legitimate threads (detection: thread-anomaly + payment-request correlation)
7. Deepfake voice/video in live fraud operations (beyond T138: *operational* use — verification protocols that survive it)
8. Account takeover for fraud vs for espionage (discriminating indicators)
9. Pig-butchering / romance-investment fraud operations (long-game social engineering; victim-reporting pipelines)
10. Payment-fraud detection controls (wire/SWIFT verification, dual authorization, amount/behavior anomaly)
11. Fraud-mule network *detection* from the victim-enterprise side (distinct from T340's recruitment-economics angle)
12. Business-process controls as primary defense (out-of-band verification, payment-policy design, fraud tabletop exercises)

**Defensive-boundary reminder (this domain):** This pack is about *stopping*
fraud, not committing it. Describe fraud workflows only to the depth needed for
detection and control design. **Never** provide pretext scripts, lure templates,
or instructions for impersonation; deepfake discussion is detection-and-policy
only (artifact analysis, verification protocols), never generation guidance.

---

### Brief 3 — `insider_threat_patterns.yaml` · T411–T422

**Scope (in):** Malicious, compromised, and negligent insider TTPs — the human
trust layer — **plus the agent-as-insider transfer**: a compromised AI agent
with legitimate access behaves like a malicious insider, so insider-detection
discipline applies directly to agent fleets.

**Hard out-of-scope (do not duplicate):**
- `cybercrime_economy` T346 (insider-access-as-a-service — the *market* for insiders; yours is insider *behavior*)
- `apt_campaigns` T259 (DPRK IT-worker infiltration — one campaign; yours is the general pattern class)
- `credential_exfiltration` / `egress_exfiltration` packs (exfil *mechanisms*; yours is the insider *context* around them — reference, don't redo)
- `social_engineering` T137 (helpdesk MFA-reset social engineering — external attacker vs helpdesk; not insider)

**Technique topics (12):**
1. Departing-employee data theft (pre-resignation exfiltration patterns; DLP + HR-process controls)
2. Rogue-administrator privilege abuse (detection: privileged-action baselining)
3. Sabotage and logic-bomb concepts (behavior-level; detection via code-change + access-correlation)
4. Credential sharing and account lending (detection: impossible-travel/concurrent-session analytics)
5. Collusion patterns (two-party fraud; separation-of-duties as mitigation)
6. Shadow IT as insider-created attack surface (discovery and governance)
7. Third-party and contractor insider risk (supply-chain-adjacent; distinct from T346's market angle)
8. Negligent-insider patterns (misconfigurations, accidental exposure — detection without blame framing)
9. UEBA detection concepts for insider threat (behavioral baselining, peer-group analytics)
10. **Agent-as-insider parallels** (compromised agent exhibiting insider TTPs; transferring insider-detection to agent fleets)
11. Privileged-access-workstation and just-in-time elevation concepts (beyond T242's standing-privilege gaps: the *program* design)
12. Whistleblower-vs-malicious discrimination for triage (protecting reporting channels while investigating)

**Defensive-boundary reminder (this domain):** Insider packs can read as
surveillance manuals — keep every technique anchored to *detecting malicious
actions and protecting the organization*, with explicit notes on lawful,
proportionate monitoring and protected reporting channels. Never provide
instructions for evading insider-threat monitoring.

---

### Brief 4 — `ics_ot_attacks.yaml` · T423–T434

**Scope (in):** Operational-technology attack *concepts* for defenders: the
IT/OT boundary, OT protocol abuse at detection level, engineering-workstation
targeting, safety-system concepts, OT monitoring — all at behavior level, all
defensive.

**Hard out-of-scope (do not duplicate):**
- `apt_campaigns` T253 (Volt-Typhoon-style pre-positioning — the *strategic* case; yours is OT *mechanisms*)
- `apt_campaigns` T260 (state wipers — the *campaign* framing; OT-destruction specifics are yours)
- `network_attacks` T151–T160 (IT network attacks; OT protocol specifics are new)
- `malware_concepts` T164 (wipers generally; ICS-targeted destruction *behaviors* are yours — behavior-level only)

**Technique topics (12):**
1. Purdue model and IT/OT boundary concepts (where the trust boundaries actually are)
2. OT protocol abuse concepts (Modbus/DNP3/OPC UA at detection level — unauthenticated function codes as telemetry)
3. Engineering-workstation targeting (the crown-jewel pattern; application allowlisting for EWS)
4. Safety-instrumented-system (SIS) attack concepts (behavior-level; the TRITON-class pattern as defender knowledge)
5. OT-specific persistence concepts (controller logic modification as persistence)
6. ICS malware family *behaviors* (HAVEX/TRITON-class at behavior level — what defenders look for, not how malware is built)
7. OT network monitoring and anomaly detection (baseline physics: process-variable anomaly detection)
8. Remote-access jump-host abuse into OT (detection at the IT/OT boundary)
9. Supply-chain risk in OT (vendor remote-access, firmware updates for controllers — distinct from IT supply chain T073–T084)
10. Destructive OT targeting (behavior-level; recovery and safety implications)
11. OT incident-response concepts (safety-first containment vs IT containment)
12. IT/OT convergence risks (cloud-connected OT, IIoT sensors expanding the attack surface)

**Defensive-boundary reminder (this domain):** OT attacks can cause physical
harm — this is the strictest boundary in the wave. Describe *detection and
protection* only. **Never** provide controller-programming instructions,
protocol-command recipes, SIS-bypass methods, or anything actionable against
real industrial processes. Family behaviors are described as *what defenders
detect*, never as construction guides.

---

### Brief 5 — `wiper_destruction.yaml` · T435–T446

**Scope (in):** Destructive-attack TTPs as a *detection discipline*: how wipers
differ from ransomware in telemetry, staging signals, and recovery implications
— the worst-case payload class for destructive AI-agent misuse.

**Hard out-of-scope (do not duplicate):**
- `malware_concepts` T164 (Wipers — the *family* overview; yours is TTP-level detection)
- `apt_campaigns` T260 (state wipers disguised as ransomware — the *campaign/deception* framing; yours is *mechanism* detection)
- `ransomware_playbook` T117–T126 (the ransomware playbook incl. T125 backup destruction — ransomware-framed; yours is destruction-framed)
- `evasion` T085/T086 (log tampering/deletion — anti-forensics generally; log-destruction *as part of wiper staging* is yours only insofar as it signals imminent destruction)

**Technique topics (12):**
1. Wiper-vs-ransomware discrimination (the decryption path never existed; telemetry differences)
2. MBR/partition-table destruction behaviors (boot-recovery implications)
3. Master file table (MFT) corruption behaviors
4. Firmware-level destruction concepts (bricking below the OS)
5. Backup and recovery-catalog destruction, destruction-framed (beyond T125's ransomware framing: wiper staging order)
6. Log destruction as imminent-destruction signal (anti-forensics *as* early warning)
7. Data-shredding vs encryption: detection differences (entropy/IO telemetry)
8. Destructive payload delivery via legitimate admin tools (living-off-the-land for destruction)
9. Wiper staging telemetry (pre-detonation signals: driver loads, backup enumeration, mass file-touch)
10. Destructive OT targeting behaviors (bridge to `ics_ot_attacks` — reference, don't duplicate)
11. False-flag destruction (ransom-note decoys; attribution caution for defenders)
12. Recovery-planning concepts (immutable backups, bare-metal rebuild playbooks, destruction-specific IR)

**Defensive-boundary reminder (this domain):** Describe destruction *behaviors
for detection* — IO patterns, staging order, telemetry. **Never** provide
destructive commands, disk-wiping procedures, driver-abuse instructions, or
anything executable. Recovery planning is the constructive core of this pack.

---

### Brief 6 — `mobile_attacks.yaml` · T447–T458

**Scope (in):** Mobile-platform attack techniques at detection level: malicious
apps, spyware, permission abuse, mobile-specific C2 and fraud — relevant as
agents gain mobile device presence.

**Hard out-of-scope (do not duplicate):**
- `api_security` T229/T232 (mobile apps as *API* targets — the server side; yours is the *device* side)
- `initial_access` T290/T291/T298 (QR/device-code/mobile-optimized phishing — *delivery*; yours is on-device tradecraft)
- `identity_attacks` T239 (SIM swapping — the *carrier* attack; on-device SIM-toolkit concepts are yours only if distinct)
- `social_engineering` T130 (smishing — the *message*; smishing-to-app *chains* are yours)

**Technique topics (12):**
1. Smishing-to-malicious-app install chains (beyond T130: the full chain to device compromise)
2. Sideloaded and rogue app concepts (outside-store distribution; enterprise detection)
3. Mobile spyware/surveillanceware behaviors (Pegasus-class at behavior level — process/network indicators)
4. App-permission abuse (overprivileged apps as data-collection; permission-audit concepts)
5. Mobile banking trojans and overlay attacks (accessibility-service abuse; detection)
6. MDM/EMM abuse concepts (rogue profiles; detection via profile inventory)
7. Jailbreak/root detection-evasion concepts (why it matters for enterprise trust decisions)
8. Malicious SDKs and ad-fraud modules (supply-chain inside apps)
9. Push-notification C2 channels (detection: notification-service traffic anomalies)
10. Malicious configuration profiles and certificates (enterprise iOS/Android vectors)
11. Baseband and SIM-toolkit attack concepts (detection-level; distinct from T239's port-out fraud)
12. Mobile device forensics readiness (what to collect; lawful-enterprise framing)

**Defensive-boundary reminder (this domain):** Spyware topics stay at
*behavior level* (indicators, network telemetry) — **never** exploitation
instructions, never jailbreak how-tos, never spyware capability-building.
MDM discussion is defensive administration, never bypass instructions.

---

### Brief 7 — `crypto_attacks.yaml` · T459–T470

**Scope (in):** Attack TTPs *against cryptographic deployments* — the operational
failure modes defenders must recognize. This is the **attack complement** to
`algorithms`' defensive-concept framing: same universe, opposite angle.

**Hard out-of-scope (do not duplicate):**
- `algorithms` T193/T194 (password hashing, salting — the *defensive* concepts; yours is *attack* TTPs like offline cracking economics at detection level — keep the angle distinct)
- `algorithms` T195 (padding oracles + downgrade — do not redo; TLS-stripping *concepts* are yours only if framed as network-attack detection, distinct from oracle mechanics)
- `algorithms` T201 (differential cryptanalysis — cipher-selection theory; not yours)
- `algorithms` T202 (PQC transition — not yours)
- `hacker_tools` T177 (hashcat-class tools — tool class; yours is TTP-level)

**Technique topics (12):**
1. Timing side-channel concepts (what leaks, where defenders look — constant-time as mitigation)
2. Weak-RNG and nonce-reuse key compromise (behavior-level; the ECDSA-nonce class as defender knowledge)
3. Certificate mis-issuance and PKI abuse detection (CT-log monitoring as defense)
4. TLS-stripping concepts at detection level (network-attack framing, distinct from T195's oracle mechanics)
5. Hash-collision chosen-prefix attacks (Shattered-class, behavior-level; migration as mitigation)
6. Key-lifecycle theft: HSM/KMS abuse concepts (API-level abuse; detection via key-use telemetry)
7. Encrypted-volume / full-disk-encryption attack concepts (evil-maid-adjacent; detection and mitigation)
8. SSH key-management abuse (sprawl, unrotated keys; inventory as defense)
9. Crypto-agility failure modes (why algorithm transitions fail; inventory-first mitigation)
10. Downgrade-adjacent negotiation abuse in non-TLS protocols (SSH/VPN version negotiation at detection level)
11. Key-escrow and recovery-mechanism abuse (the backdoor-you-built problem; policy framing)
12. Cryptographic inventory (CBOM) as detection prerequisite (you cannot defend what you cannot see)

**Defensive-boundary reminder (this domain):** Concepts of *why* attacks work
(timing leaks, nonce reuse math at high level) plus detection — **never**
implementation guides, never code for exploiting oracles/side channels, never
key-recovery procedures. Keep mathematics at the "defender intuition" level.

---

### Brief 8 — `firmware_hardware_attacks.yaml` · T471–T482

**Scope (in):** Below-the-OS attack concepts for defenders: firmware persistence
beyond T115's single technique, hardware trust roots, physical-access concepts,
microarchitectural attacks at detection level.

**Hard out-of-scope (do not duplicate):**
- `apt_tradecraft` T115 (UEFI/firmware persistence — the *concept*; yours is the broader hardware/firmware *landscape*)
- `malware_concepts` T168 (bootkits — the *malware family*; firmware-attack *concepts* like Secure Boot bypass are yours)
- `persistence` T057 (container-image backdoors — not firmware; no overlap, listed for clarity)
- `supply_chain` T077/T078 (compromised build tooling, poisoned base images — software supply chain; hardware supply-chain *concepts* are yours)

**Technique topics (12):**
1. Secure Boot bypass *concepts* (what the trust chain is; detection via boot-telemetry anomalies)
2. TPM attack concepts (reset/glitch classes at behavior level; what TPM attestation failures mean)
3. BMC/IPMI out-of-band management abuse (the network-reachable firmware layer; segmentation as defense)
4. Intel ME / AMD PSP concepts (the always-on coprocessor as trust consideration; vendor-firmware inventory)
5. JTAG/UART debug-interface abuse (physical-access concepts; fuse/disablement as mitigation)
6. Evil-maid and cold-boot concepts (physical-access attack classes; detection and mitigation)
7. Hardware implants and interdiction concepts (supply-chain-at-the-loading-dock; inspection regimes)
8. Rowhammer-class memory attacks (detection-level: ECC telemetry, refresh-rate mitigations)
9. Speculative-execution attacks (Spectre/Meltdown-class at detection level; patching and isolation)
10. Microcode and firmware-update abuse (signed-update verification; rollback protection)
11. Peripheral/firmware attack surface (NIC/GPU/EC firmware as overlooked persistence)
12. Hardware supply-chain: counterfeit-component concepts (detection via provenance and attestation)

**Defensive-boundary reminder (this domain):** Physical-access and firmware
topics are high-risk for dual use. Describe *trust models, indicators, and
mitigations* — **never** glitching procedures, debug-interface exploitation
steps, implant construction, or bypass instructions. Speculative-execution and
Rowhammer stay at detection/mitigation level.

---

## 6. Doctrine-budget measurement

Measured 2026-10-19 on this worktree (`aegis/kb/__init__.py`):

| Item | Measurement |
|---|---|
| Doctrine source | `KB.doctrine_section()` — iterates **only** the `hacker_mindset` category |
| Doctrine chars, untruncated | **44,292** |
| Doctrine chars at default `AEGIS_DOCTRINE_CHARS=44292` | **44,292** (already exactly at cap) |
| Projected doctrine addition from 8 new packs | **0 chars** — new packs do not feed `doctrine_section()` |
| `technique_index()` cap | **12,000 chars** (hard truncation) |
| Current index chars if uncapped | **69,993** across 30 non-doctrine packs (avg ~2,333/pack; median 2,406) |
| Projected index addition, 8 packs × ~2,333 | **~18,700 chars** → uncapped total ~88,700 vs 12,000 cap |
| Index ordering | **alphabetical by pack** (`packs()` is `sorted`); truncation cuts from the end |

**Implication for the integration lane:** the technique index is *already*
saturated — at 12,000 chars it covers roughly the first 5 packs alphabetically
(`agent_attacks` … `apt_tradecraft`) and truncates everything from
`attack_methods` onward out of the system prompt *today*. Adding 8 packs does
not change the 12,000-char prompt cost, but it **dilutes coverage**: each new
pack's index lines displace ~2,300 chars of existing packs (alphabetical
insertion order decides who survives). New pack stems and their alphabetical
slots: `crypto_attacks` (early — displaces), `firmware_hardware_attacks`,
`fraud_bec_operations`, `ics_ot_attacks`, `insider_threat_patterns`,
`ml_serialization_attacks`, `mobile_attacks`, `wiper_destruction` (late —
likely truncated out entirely at current cap). **Decision needed by integration
lane:** raise `technique_index` cap (e.g. to cover all 38 packs ≈ 89k chars —
expensive per API call), switch truncation to a priority/rotation scheme, or
accept that late-alphabet packs are prompt-invisible (they remain fully
available to `kb_scan`/`kb_query` at runtime regardless).

Per-technique full records are unaffected: they are retrieved on demand via the
KB tools, not embedded in the prompt — so all 96 new techniques are usable
regardless of the index decision.

## 7. Schema & validation reminder for trainers

The loader (`aegis/kb/__init__.py::_validate_entry`) enforces, per technique:
`id` matches `AEG-TNNN` and is unique; `category` **must equal the pack filename
stem**; `severity` ∈ {critical, high, medium, low}; `detection` is a dict with
`rule` (string) + `patterns` (list, **≥2 regexes, each must compile under
`re.IGNORECASE`** — test every pattern in Python before submitting);
`indicators`, `mitigations`, `references` are lists with **≥2 items** each;
`description` ≥ 15 words; `how_it_works` ≥ 20 words; all listed fields non-empty.
`variants` and `examples` (with `summary` + `reference`) are optional but
encouraged, following existing pack style. Use the assigned ID ranges in §4
exactly — T387–T482, no gaps, no reuse, no invented IDs.

## 8. Handoff checklist

- [x] All 31 packs read; coverage map built (§2)
- [x] 8 domains selected with per-domain rationale (§3); 2 rejected with evidence (§2/§3)
- [x] ID space audited (T001–T386, no gaps; T1528 anomaly documented for integration lane) (§4)
- [x] 8 trainer briefs written with scope, hard out-of-scope lists citing existing IDs, 12 technique topics each, domain-specific defensive-boundary reminders (§5)
- [x] Doctrine budget measured; index-saturation decision flagged for integration lane (§6)
- [ ] Trainer agents briefed from this doc (next step — parent/coordinator dispatch)
- [ ] Integration lane: frozen-contract registration, T1528 typo disposition, technique-index cap decision
