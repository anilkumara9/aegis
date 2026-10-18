"""Slash skills for the REPL: /hunt /guard /scan /respond /kb.

/hunt audits the user's OWN codebase/systems only — the target must be a
local directory that exists. URLs, hosts, and anything non-local are
refused. This is defensive auditing of own assets, never reconnaissance
of someone else's.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .detect import secrets as sec

# Static audit patterns: (kind, regex, kb_hint)
AUDIT_PATTERNS: list[tuple[str, str, str]] = [
    ("hardcoded_secret",
     r"(?i)(password|passwd|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
     "credential_exfiltration"),
    ("dangerous_eval", r"\beval\s*\(", "privilege_escalation"),
    ("dangerous_exec", r"\bexec\s*\(", "privilege_escalation"),
    ("shell_true", r"shell\s*=\s*True", "privilege_escalation"),
    ("os_system", r"\bos\.system\s*\(", "privilege_escalation"),
    ("pickle_loads", r"pickle\.loads?\s*\(", "web_exploitation"),
    ("yaml_unsafe_load", r"yaml\.load\s*\(", "web_exploitation"),
    ("verify_false", r"verify\s*=\s*False", "network_attacks"),
    ("subprocess_untrusted", r"subprocess\.(run|call|Popen)\s*\([^)]*shell",
     "privilege_escalation"),
    ("sql_format", r"(?i)(execute|query)\s*\(.*%s.*%|f['\"].*SELECT",
     "web_exploitation"),
    ("debug_enabled", r"(?i)debug\s*=\s*True", "privilege_escalation"),
    ("weak_crypto", r"\b(md5|sha1|DES)\b", "algorithms"),
    ("jwt_none_alg", r"(?i)algorithms?\s*=\s*\[.*['\"]none['\"]", "web_exploitation"),
]

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist",
              "build", ".aegis"}
_MAX_FILE_BYTES = 200_000
_MAX_FINDINGS = 200


def _looks_remote(target: str) -> bool:
    t = target.strip().lower()
    return (t.startswith(("http://", "https://", "ssh://", "ftp://"))
            or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/|$)", t) is not None
            or re.match(r"^\d{1,3}(\.\d{1,3}){3}", t) is not None)


def _resolve_local_dir(target: str, skill: str) -> tuple[Path | None, str]:
    """Validate a skill target is a local directory. Returns (path, error)."""
    target = (target or "").strip()
    if not target:
        return None, f"usage: {skill} <local-directory>"
    if _looks_remote(target):
        return None, (f"refused: {skill} only works on your OWN local systems. "
                       f"Give me a local directory path.")
    p = Path(target).expanduser()
    if not p.is_dir():
        return None, (f"refused: '{target}' is not a local directory. {skill} "
                       f"works on your own local code only — pass a directory "
                       f"that exists on this machine.")
    return p, ""


def _scan_dir(p: Path) -> tuple[list[dict], int]:
    """Pattern scan of a local dir. Returns (findings, files_scanned).

    Each finding: {kind, rel, lineno, line, hint}. Secrets are never
    returned in the clear.
    """
    findings: list[dict] = []
    files_scanned = 0
    compiled = [(k, re.compile(rx), hint) for k, rx, hint in AUDIT_PATTERNS]
    for root, dirs, files in os.walk(p):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            fp = Path(root) / fn
            try:
                if fp.stat().st_size > _MAX_FILE_BYTES:
                    continue
                text = fp.read_text(encoding="utf-8", errors="strict")
            except Exception:
                continue
            files_scanned += 1
            rel = str(fp.relative_to(p))
            for i, line in enumerate(text.splitlines(), 1):
                for kind, rx, hint in compiled:
                    if rx.search(line):
                        findings.append({"kind": kind, "rel": rel,
                                         "lineno": i,
                                         "line": line.strip()[:160],
                                         "hint": hint})
                        if len(findings) >= _MAX_FINDINGS:
                            break
                if len(findings) >= _MAX_FINDINGS:
                    break
            for hit in sec.find_secrets(text):
                findings.append({"kind": f"secret_material:{hit.kind}",
                                 "rel": rel, "lineno": 0, "line": "REDACTED",
                                 "hint": "credential_exfiltration"})
                if len(findings) >= _MAX_FINDINGS:
                    break
            if len(findings) >= _MAX_FINDINGS:
                break
        if len(findings) >= _MAX_FINDINGS:
            break
    return findings, files_scanned


def _kb_cite(kb, hint: str) -> str:
    if kb is None:
        return ""
    hits = kb.query(hint.replace("_", " "), top_k=1)
    if hits:
        return f" (see {hits[0].id} {hits[0].name})"
    return ""


def hunt(path: str, kb=None) -> str:
    """Audit a LOCAL directory. Returns a markdown report."""
    p, err = _resolve_local_dir(path, "/hunt")
    if p is None:
        return err
    findings, files_scanned = _scan_dir(p)
    lines = [f"# /hunt report: {p}",
             f"Files scanned: {files_scanned}. "
             f"Findings: {len(findings)} (pattern-based triage, not a proof).",
             ""]
    if findings:
        for f in findings:
            loc = f"{f['rel']}:{f['lineno']}" if f["lineno"] else f["rel"]
            lines.append(f"- [{f['kind']}] {loc}{_kb_cite(kb, f['hint'])}\n"
                         f"  `{f['line']}`")
        lines += ["",
                  "Next: investigate each finding, then `respond` playbooks if "
                  "anything is live-compromised. Re-run after fixes."]
    else:
        lines.append("No matches for the built-in audit patterns. This is a "
                     "triage pass, not a clean bill of health — consider a "
                     "deeper review for your threat model.")
    return "\n".join(lines)
    lines = [f"# /hunt report: {p}",
             f"Files scanned: {files_scanned}. "
             f"Findings: {len(findings)} (pattern-based triage, not a proof).",
             ""]
    if findings:
        lines.extend(findings)
        lines += ["",
                  "Next: investigate each finding, then `respond` playbooks if "
                  "anything is live-compromised. Re-run after fixes."]
    else:
        lines.append("No matches for the built-in audit patterns. This is a "
                     "triage pass, not a clean bill of health — consider a "
                     "deeper review for your threat model.")
    return "\n".join(lines)


# Attacker-phase mapping for /plan: pattern kind -> (phase, attacker thought)
_PLAN_PHASES: list[tuple[str, str, set[str]]] = [
    ("Phase 1 — Reconnaissance",
     "What can I learn without touching anything? Secrets in the repo, "
     "entry points, tech stack, debug flags left on.",
     {"hardcoded_secret", "debug_enabled"}),
    ("Phase 2 — Initial access",
     "Where is the front door? Injection points, unsafe deserialization, "
     "auth weaknesses, request forgery.",
     {"sql_format", "pickle_loads", "yaml_unsafe_load", "jwt_none_alg",
      "verify_false"}),
    ("Phase 3 — Execution & privilege escalation",
     "Once I'm in, how do I run code and get more power? Eval, shell, "
     "subprocess, weak crypto guarding secrets.",
     {"dangerous_eval", "dangerous_exec", "shell_true", "os_system",
      "subprocess_untrusted", "weak_crypto"}),
    ("Phase 4 — Persistence & exfiltration",
     "How do I stay, and what do I take? Stored secrets are the exfil "
     "shortcut; every hardcoded credential is a standing invitation.",
     set()),
]


def plan_attack_surface(path: str, kb=None) -> str:
    """Hacker-mindset attack plan for the user's OWN code (defensive).

    Read-only: scans the local directory and lays out how an attacker
    would think about it, phase by phase, so the defender can fix the
    highest-leverage issues first. Never touches anything outside the
    given local directory.
    """
    p, err = _resolve_local_dir(path, "/plan")
    if p is None:
        return err
    findings, files_scanned = _scan_dir(p)
    lines = [f"# /plan — attacker-mindset plan for YOUR code: {p}",
             "",
             "This is defensive planning: think like the attacker so you can "
             "fix like the defender. Phases below follow the attacker's "
             "decision order — the fix-first queue at the end is yours.",
             f"Files scanned: {files_scanned}. Signals: {len(findings)} "
             "(pattern-based triage, not a proof).",
             ""]
    by_kind: dict[str, list[dict]] = {}
    for f in findings:
        base = f["kind"].split(":")[0]
        by_kind.setdefault(base, []).append(f)
    secret_findings = [f for f in findings
                       if f["kind"].startswith("secret_material")]
    for phase, thought, kinds in _PLAN_PHASES:
        phase_hits = [f for k in kinds for f in by_kind.get(k, [])]
        if phase.startswith("Phase 4"):
            phase_hits = secret_findings
        lines.append(f"## {phase}")
        lines.append(f"*{thought}*")
        if not phase_hits:
            lines.append("No signals in this phase from the pattern scan — "
                         "do not read this as 'safe', only as 'unseen'.")
        else:
            for f in phase_hits[:12]:
                loc = (f"{f['rel']}:{f['lineno']}"
                       if f["lineno"] else f["rel"])
                lines.append(f"- [{f['kind']}] {loc}"
                             f"{_kb_cite(kb, f['hint'])}")
            if len(phase_hits) > 12:
                lines.append(f"- …and {len(phase_hits) - 12} more.")
        lines.append("")
    lines.append("## Fix-first queue (defender's cut list)")
    priority = (secret_findings
                + [f for k in ("hardcoded_secret",) for f in by_kind.get(k, [])]
                + [f for k, _, _ in
                    [(k, t, s) for _, t, s in _PLAN_PHASES for k in s]
                    for f in by_kind.get(k, [])])
    seen: set[tuple] = set()
    queue: list[dict] = []
    for f in priority:
        key = (f["kind"], f["rel"], f["lineno"])
        if key not in seen:
            seen.add(key)
            queue.append(f)
    if not queue:
        lines.append("Nothing pattern-matched — start with a manual review "
                     "of auth, input handling, and secret storage.")
    else:
        for i, f in enumerate(queue[:15], 1):
            loc = (f"{f['rel']}:{f['lineno']}" if f["lineno"] else f["rel"])
            lines.append(f"{i}. [{f['kind']}] {loc}{_kb_cite(kb, f['hint'])}")
    lines += ["",
              "Fix in queue order, re-run `/plan` after, and keep the guard "
              "on: planning is read-only, changes belong in dev mode."]
    return "\n".join(lines)


SKILLS = {
    "/hunt": "Audit YOUR OWN local codebase for vulnerabilities: /hunt <dir>",
    "/plan": "Hacker-mindset attack plan for YOUR OWN code (read-only): /plan <dir>",
    "/mode": "Switch dev/plan mode: /mode <dev|plan>",
    "/guard": "Guard session status and kill-switch: /guard [status|kill]",
    "/scan": "Analyze a tool-call trace: /scan <trace.jsonl>",
    "/respond": "Emit an incident runbook: /respond <playbook> [detail]",
    "/kb": "Query the technique knowledge base: /kb <query>",
    "/sessions": "List saved conversation sessions",
    "/resume": "Resume a conversation: /resume <n|id>",
    "/rename": "Rename the current conversation: /rename <title>",
    "/help": "Show help",
    "/exit": "Exit (also /quit)",
}
