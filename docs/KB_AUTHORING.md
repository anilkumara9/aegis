# Aegis KB Authoring Guide (v1)

Every technique entry reads like a **condensed threat-intel note**: how it works
(at TTP/detection level), what it looks like in telemetry, how to detect it, how
to kill it. Depth over count. One-line stubs fail review.

## Hard boundary — DEFENSIVE ONLY

This knowledge base exists so a defensive agent can *recognize and stop*
attacks. Write at the level of MITRE ATT&CK technique pages (public defensive
knowledge): mechanism, observable artifacts, detection, mitigation.

NEVER write:
- step-by-step attack instructions or "how to" operational guides;
- access guides (e.g. how to reach dark-web markets, how to join forums);
- payloads, exploit code, weaponized commands, or tool usage instructions;
- anything that automates unauthorized access, credential theft, or
  exploitation against a target.

If source material you find would cross that line, **summarize it at detection
level** (what it looks like, how defenders spot/stop it) and move on. For
`hacker_tools`, each entry is CONCEPTUAL + DETECTION ONLY: what the tool is,
its observable host/network signatures, how defenders detect its use — never
usage instructions.

## Schema (strict — the loader validates)

```yaml
pack: prompt_injection          # file stem, snake_case
version: "1.0"
techniques:
  - id: AEG-T001                 # exact format, zero-padded, within your assigned range
    name: "Indirect Prompt Injection via Tool Output"
    category: prompt_injection   # == pack stem
    description: >-              # 2-4 sentences, plain language
      ...
    how_it_works: >-            # TTP level: mechanism + attacker workflow in
      ...                       # defensive terms; name the VARIANTS explicitly
    variants:                   # 2+ variants where they exist
      - "..."
    indicators:                 # 3+ observable signs in telemetry/logs/traces
      - "..."
    detection:                  # concrete, actionable
      rule: detect_indirect_injection   # snake_case detector name (aegis.detect registry)
      patterns:                 # 2+ concrete patterns (regex or keyword phrases)
        - "(?i)ignore\\s+(all\\s+)?(previous|prior|above)\\s+instructions"
    severity: critical           # critical | high | medium | low
    mitigations:                # 3+ concrete defensive actions
      - "..."
    examples:                   # real-world, from PUBLIC incident reports
      - summary: "..."
        reference: "https://..."   # real, verified URL
    references:                 # 2+ reputable sources (vendor research, CISA,
      - "https://..."           # OWASP, MITRE, academic papers, major press)
```

Field rules:
- `id`: unique, sequential, inside your assigned range only.
- `severity`: be honest — reserve `critical` for techniques that directly yield
  secrets, code execution, or full compromise.
- `references`: real URLs only. Verify with a web search if unsure. NEVER
  fabricate a URL. If you cannot verify a reference, drop it (2 minimum must
  remain) or drop the example.
- `examples`: public incident reports / disclosed research only. For
  `apt_tradecraft`, draw ONLY from public threat reporting (name the vendor:
  Mandiant, CrowdStrike, CISA, etc.). For `darkweb_threat_intel`: concepts of
  how stolen data moves and is monetized + the indicators defenders monitor —
  never access guidance.
- No real secrets anywhere in the files. If an example needs a secret shape,
  use an obviously-fake placeholder like `sk-ant-PLACEHOLDER` or `[REDACTED]`.

## Depth bar (every entry)

- `description` + `how_it_works` together: a defender reading only this entry
  understands the technique's mechanism, its variants, and where it shows up.
- `indicators`: observable in logs/telemetry/tool-call traces — specific, not
  generic ("unusual activity" is a fail).
- `detection.patterns`: concrete enough that an engineer could implement the
  rule tomorrow.
- `mitigations`: concrete controls, ordered by effectiveness.
- `examples` + `references`: grounded in the public record.

## Output

Write exactly the files assigned to you under `~/workspace/aegis/aegis/kb/`
(one YAML file per pack, filename `<pack>.yaml`). Validate your YAML parses
(e.g. `python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))"`).
