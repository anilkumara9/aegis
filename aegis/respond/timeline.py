"""Incident timeline: chronological markdown view of audit logs + triage queue.

Additive v0.2 capability for the respond side — reads only, never executes.
The respond command can call build_timeline() to hand the operator a single
chronological picture of what the agent did (audit log) and what the watcher
found (triage queue + watch alerts).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .. import config


def _fmt_ts(ts: float) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(ts)))
    except Exception:
        return "unknown time"


def _describe_audit(rec: dict) -> str:
    event = rec.get("event", "event")
    if event == "tool_call":
        tool = rec.get("tool", "?")
        verdict = rec.get("verdict", "?")
        findings = rec.get("findings") or []
        base = f"tool call `{tool}` → verdict **{verdict}**"
        if findings:
            ids = ", ".join(
                str(f.get("technique_id", "?"))
                for f in findings[:5] if isinstance(f, dict))
            base += f" — {len(findings)} finding(s): {ids}"
        excerpt = str(rec.get("output_excerpt", ""))[:200]
        if excerpt:
            base += f"\n  output: `{excerpt}`"
        return base
    if event == "kill_switch":
        return f"kill-switch fired on session `{rec.get('session', '?')}`"
    detail = {k: v for k, v in rec.items() if k not in ("ts", "session")}
    return f"{event}: {json.dumps(detail, default=str)[:200]}"


def _describe_alert(rec: dict) -> str:
    kind = rec.get("kind", "alert")
    if kind == "new_findings":
        items = rec.get("findings") or []
        head = ", ".join(
            f"[{f.get('severity', '?').upper()}] {f.get('technique_id', '?')} "
            f"@ {f.get('file', '?')}:{f.get('line', '?')}"
            for f in items[:5])
        return (f"watch: {len(items)} new finding(s) in `{rec.get('dir', '?')}`"
                + (f" — {head}" if head else ""))
    if kind == "scheduled_hunt":
        return f"watch: {rec.get('detail', 'scheduled hunt ran')}"
    return f"watch: {kind} — {rec.get('detail', '')}"


def _describe_triage(entry: dict) -> str:
    return (f"watch: triaged **[{entry.get('severity', '?').upper()}]** "
            f"{entry.get('technique_id', '?')} — "
            f"{entry.get('technique_name', '')} "
            f"@ `{entry.get('file', '?')}:{entry.get('line', '?')}` "
            f"(first seen, seen {entry.get('seen_count', 1)}x)")


def collect_events() -> list[tuple[float, str, str]]:
    """Gather (ts, source, description) tuples from every timeline source."""
    events: list[tuple[float, str, str]] = []

    # 1. Audit logs: every *.jsonl in the audit dir (all sessions).
    audit_dir = config.audit_dir()
    if audit_dir.is_dir():
        for path in sorted(audit_dir.glob("*.jsonl")):
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if not isinstance(rec, dict) or "ts" not in rec:
                    continue
                events.append((float(rec["ts"]), f"audit:{path.name}",
                               _describe_audit(rec)))

    # 2. Watch alert log.
    alert_path = config.state_dir() / "watch_alerts.jsonl"
    if alert_path.exists():
        for line in alert_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if not isinstance(rec, dict) or "ts" not in rec:
                continue
            events.append((float(rec["ts"]), "watch:alerts",
                           _describe_alert(rec)))

    # 3. Triage queue (first-seen anchors each finding in time).
    triage_path = config.state_dir() / "triage_queue.jsonl"
    if triage_path.exists():
        for line in triage_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue
            if not isinstance(entry, dict) or not entry.get("first_seen"):
                continue
            events.append((float(entry["first_seen"]), "watch:triage",
                           _describe_triage(entry)))

    events.sort(key=lambda e: e[0])
    return events


def build_timeline() -> str:
    """Chronological markdown timeline from audit logs + watch data."""
    events = collect_events()
    lines = [
        "# Aegis incident timeline",
        f"_Built {time.strftime('%Y-%m-%d %H:%M %Z')}. "
        f"{len(events)} event(s), chronological._",
        "",
    ]
    if not events:
        lines.append("No events yet — no audit records, watch alerts, or "
                     "triaged findings in the state directory.")
        return "\n".join(lines)
    for ts, source, desc in events:
        lines.append(f"## {_fmt_ts(ts)} — {source}")
        lines.append(desc)
        lines.append("")
    lines.append("---")
    lines.append("Sources: `audit/` JSONL session logs, "
                 "`watch_alerts.jsonl`, `triage_queue.jsonl` "
                 f"(state dir: `{config.state_dir()}`).")
    return "\n".join(lines)
