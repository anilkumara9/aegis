"""Offline tool-call trace analyzer: aegis scan <trace.jsonl>."""

from __future__ import annotations

import json
from pathlib import Path

from .detect import analyze_trace
from .detect.engine import Finding
from .kb import KB

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_trace(path: str | Path) -> list[dict]:
    calls = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                calls.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{n}: invalid JSON: {e}")
    return calls


def scan_calls(calls: list[dict], kb: KB) -> list[Finding]:
    return analyze_trace(calls, kb)


def format_text(findings: list[Finding], total_calls: int) -> str:
    lines = [f"Aegis scan: {total_calls} tool calls, "
             f"{len(findings)} finding(s)"]
    if not findings:
        lines.append("No technique matches. Trace looks clean.")
        return "\n".join(lines)
    for fl in findings:
        lines.append("")
        lines.append(f"[{fl.severity.upper()}] {fl.technique_id} — "
                     f"{fl.technique_name}")
        lines.append(f"  rule: {fl.rule}  call: #{fl.call_index}")
        lines.append(f"  evidence: {fl.evidence}")
        lines.append(f"  mitigate: {fl.mitigation}")
    return "\n".join(lines)


def scan_file(path: str | Path, kb: KB | None = None,
              as_json: bool = False) -> list[Finding]:
    kb = kb or KB.load()
    calls = load_trace(path)
    findings = scan_calls(calls, kb)
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print(format_text(findings, len(calls)))
    return findings
