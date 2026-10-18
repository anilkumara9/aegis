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


def hunt(path: str, kb=None) -> str:
    """Audit a LOCAL directory. Returns a markdown report."""
    target = (path or "").strip()
    if not target:
        return "usage: /hunt <local-directory>"
    if _looks_remote(target):
        return ("refused: /hunt only audits your OWN local systems. "
                "Give me a local directory path.")
    p = Path(target).expanduser()
    if not p.is_dir():
        return (f"refused: '{target}' is not a local directory. /hunt audits "
                f"your own local code only — pass a directory that exists on "
                f"this machine.")
    findings: list[str] = []
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
            rel = fp.relative_to(p)
            for i, line in enumerate(text.splitlines(), 1):
                for kind, rx, hint in compiled:
                    if rx.search(line):
                        tech = ""
                        if kb is not None:
                            hits = kb.query(hint.replace("_", " "), top_k=1)
                            if hits:
                                tech = f" (see {hits[0].id} {hits[0].name})"
                        findings.append(
                            f"- [{kind}] {rel}:{i}{tech}\n"
                            f"  `{line.strip()[:160]}`")
                        if len(findings) >= _MAX_FINDINGS:
                            break
                if len(findings) >= _MAX_FINDINGS:
                    break
            # secret-shaped material (use the real secret engine)
            for hit in sec.find_secrets(text):
                findings.append(
                    f"- [secret_material:{hit.kind}] {rel} "
                    f"offset {hit.start} — REDACTED in this report")
                if len(findings) >= _MAX_FINDINGS:
                    break
            if len(findings) >= _MAX_FINDINGS:
                break
        if len(findings) >= _MAX_FINDINGS:
            break
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


SKILLS = {
    "/hunt": "Audit YOUR OWN local codebase for vulnerabilities: /hunt <dir>",
    "/guard": "Guard session status and kill-switch: /guard [status|kill]",
    "/scan": "Analyze a tool-call trace: /scan <trace.jsonl>",
    "/respond": "Emit an incident runbook: /respond <playbook> [detail]",
    "/kb": "Query the technique knowledge base: /kb <query>",
    "/help": "Show help",
    "/exit": "Exit (also /quit)",
}
