"""Detection engine: KB pattern matching + multi-step chain detectors.

Two layers:
1. Pattern layer — every KB technique carries concrete detection patterns.
   Any tool-call text (tool name, args, output) matching a pattern yields a
   finding for that technique. This keeps all 19 packs live even where no
   bespoke detector exists.
2. Chain layer — cross-call logic for attack *sequences*: indirect injection
   followed by secret use, sensitive-read followed by unapproved exec,
   secret-bearing egress.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..kb import KB, Technique
from . import secrets as sec

_PATTERN_CACHE: dict[str, re.Pattern] = {}


def _compile(pattern: str) -> re.Pattern:
    if pattern not in _PATTERN_CACHE:
        _PATTERN_CACHE[pattern] = re.compile(pattern, re.IGNORECASE)
    return _PATTERN_CACHE[pattern]


def _ev(text: str, limit: int = 300) -> str:
    """Evidence excerpt, secret-redacted at creation: findings must never
    carry raw secrets into audit logs, scan output, or approval prompts."""
    return sec.redact(text[:limit])[0]


@dataclass
class Finding:
    technique_id: str
    technique_name: str
    category: str
    severity: str
    rule: str
    evidence: str
    mitigation: str
    call_index: int = -1

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "category": self.category,
            "severity": self.severity,
            "rule": self.rule,
            "evidence": self.evidence,
            "mitigation": self.mitigation,
            "call_index": self.call_index,
        }


def call_text(call: dict) -> str:
    parts = [str(call.get("tool", ""))]
    args = call.get("args", {})
    try:
        parts.append(json.dumps(args, default=str))
    except Exception:
        parts.append(str(args))
    output = call.get("output")
    if output:
        parts.append(str(output)[:8000])
    return "\n".join(parts)


def pattern_scan(text: str, kb: KB, call_index: int = -1,
                 categories: list[str] | None = None,
                 exclude_techniques: set[str] | None = None) -> list[Finding]:
    """Match KB detection patterns against free text.

    exclude_techniques skips named techniques (e.g. shell-command-syntax
    patterns that are meaningless against source-code file content).
    """
    findings: list[Finding] = []
    for t in kb.techniques:
        if categories and t.category not in categories:
            continue
        if exclude_techniques and t.id in exclude_techniques:
            continue
        for pat in t.detection_patterns:
            m = _compile(pat).search(text)
            if m:
                findings.append(Finding(
                    technique_id=t.id, technique_name=t.name, category=t.category,
                    severity=t.severity, rule=t.detection_rule,
                    evidence=_ev(m.group(0)),
                    mitigation=t.mitigations[0] if t.mitigations else "",
                    call_index=call_index,
                ))
                break  # one finding per technique per text
    return findings


# -- chain detectors ----------------------------------------------------

INJECTION_CATS = ["prompt_injection", "tool_output_poisoning"]
EXFIL_CATS = ["credential_exfiltration", "egress_exfiltration"]
PRIVESC_CATS = ["privilege_escalation"]

SENSITIVE_PATH_RE = re.compile(
    r"(?i)(\.env\b|\.aws/credentials|id_rsa|\.pem\b|secrets?\.ya?ml|"
    r"credentials\.json|netrc|\.gnupg/|keychain|vault\.db|"
    r"\.bash_history|\.zsh_history|/proc/self/environ|authorized_keys|"
    r"\bsecrets?\b)")
EXEC_TOOLS = {"bash", "exec", "shell", "run_command", "terminal"}
NETWORK_TOOLS = {"webfetch", "curl", "http_request", "wget"}


def _best_technique(kb: KB, category: str, *keywords: str) -> Technique | None:
    cands = kb.by_category.get(category, [])
    if not cands:
        return None
    kw = [k.lower() for k in keywords]

    def score(t: Technique) -> tuple:
        name = t.name.lower()
        hits = sum(1 for k in kw if k in name)
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}[t.severity]
        return (-hits, sev_rank, t.id)

    return sorted(cands, key=score)[0]


def chain_indirect_injection_to_secret_use(calls: list[dict], kb: KB,
                                           window: int = 10) -> list[Finding]:
    """Tool output carries injection indicators, then a secret-bearing call."""
    findings: list[Finding] = []
    injected_at: list[int] = []
    for i, call in enumerate(calls):
        output = str(call.get("output", "") or "")
        if output and pattern_scan(output, kb, categories=INJECTION_CATS):
            injected_at.append(i)
    for i in injected_at:
        for j in range(i + 1, min(len(calls), i + 1 + window)):
            later = calls[j]
            text = call_text(later)
            if sec.is_secret_bearing(text):
                t = (_best_technique(kb, "prompt_injection", "indirect")
                     or _best_technique(kb, "tool_output_poisoning", "poison"))
                if t:
                    findings.append(Finding(
                        technique_id=t.id, technique_name=t.name,
                        category=t.category, severity="critical",
                        rule="chain_indirect_injection_to_secret_use",
                        evidence=_ev(f"injection indicators in output of call {i} "
                                  f"({later.get('tool')}); secret-bearing call {j} "
                                  f"({later.get('tool')}) within {window} steps"),
                        mitigation=t.mitigations[0] if t.mitigations else "",
                        call_index=j,
                    ))
                break
    return findings


def chain_sensitive_read_to_unapproved_exec(calls: list[dict], kb: KB,
                                            window: int = 10) -> list[Finding]:
    """Sensitive file read followed by exec without approval."""
    findings: list[Finding] = []
    for i, call in enumerate(calls):
        args_text = json.dumps(call.get("args", {}), default=str)
        if not SENSITIVE_PATH_RE.search(args_text):
            continue
        for j in range(i + 1, min(len(calls), i + 1 + window)):
            later = calls[j]
            if (str(later.get("tool", "")).lower() in EXEC_TOOLS
                    and not later.get("approval")):
                t = (_best_technique(kb, "privilege_escalation", "sandbox", "escape")
                     or _best_technique(kb, "privilege_escalation", "escalation"))
                if t:
                    findings.append(Finding(
                        technique_id=t.id, technique_name=t.name,
                        category=t.category, severity="high",
                        rule="chain_sensitive_read_to_unapproved_exec",
                        evidence=_ev(f"sensitive read at call {i} "
                                  f"({args_text[:120]}); unapproved exec at call {j}"),
                        mitigation=t.mitigations[0] if t.mitigations else "",
                        call_index=j,
                    ))
                break
    return findings


def secret_egress(calls: list[dict], kb: KB) -> list[Finding]:
    """Secret-shaped strings in outbound (network) tool args."""
    findings: list[Finding] = []
    for i, call in enumerate(calls):
        tool = str(call.get("tool", "")).lower()
        args_text = json.dumps(call.get("args", {}), default=str)
        is_network = tool in NETWORK_TOOLS or "http" in args_text.lower()
        if not is_network:
            continue
        hits = sec.find_secrets(args_text)
        refs = sec.find_secret_references(args_text)
        if hits or refs:
            t = (_best_technique(kb, "credential_exfiltration", "exfil")
                 or _best_technique(kb, "egress_exfiltration", "exfil"))
            if t:
                detail = ", ".join(h.kind for h in hits[:3]) or \
                    f"secret refs: {', '.join(refs[:3])}"
                findings.append(Finding(
                    technique_id=t.id, technique_name=t.name,
                    category=t.category, severity="critical",
                    rule="secret_egress",
                    evidence=f"secret-shaped data ({detail}) in outbound args "
                             f"of call {i} ({tool})",
                    mitigation=t.mitigations[0] if t.mitigations else "",
                    call_index=i,
                ))
    return findings


def analyze_trace(calls: list[dict], kb: KB) -> list[Finding]:
    """Full offline analysis: pattern layer + chain layer, deduplicated."""
    findings: list[Finding] = []
    for i, call in enumerate(calls):
        findings.extend(pattern_scan(call_text(call), kb, call_index=i))
    findings.extend(chain_indirect_injection_to_secret_use(calls, kb))
    findings.extend(chain_sensitive_read_to_unapproved_exec(calls, kb))
    findings.extend(secret_egress(calls, kb))
    # Deduplicate on (technique_id, call_index), keep highest severity.
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    best: dict[tuple[str, int], Finding] = {}
    for f in findings:
        key = (f.technique_id, f.call_index)
        if key not in best or sev_rank[f.severity] < sev_rank[best[key].severity]:
            best[key] = f
    return sorted(best.values(),
                  key=lambda f: (sev_rank[f.severity], f.call_index))
