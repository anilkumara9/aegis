"""aegis watch — continuous DEFENSIVE monitoring of your OWN local assets.

SOC-in-a-box lane: watches a local directory, rescans changed/new files on
every pass, alerts on new findings, auto-triages into a severity-ranked
queue, runs scheduled hunts, and feeds the incident timeline.

Hard boundaries (never crossed):
- LOCAL paths only. URLs, remote hosts, and anything non-local are refused
  (same scoping rule as /hunt).
- Detection, alerting, triage, timelines only. No exploit code, no offensive
  tooling, no payloads, no network calls.
- Evidence is secret-redacted at creation — watch state/alerts never carry
  raw secrets.

State lives in config.state_dir():
  watch_state.json    — per-file hashes + schedule entries
  triage_queue.jsonl  — fingerprinted, deduped, severity-ranked queue
  watch_alerts.jsonl  — alert log (also feeds build_timeline())
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from pathlib import Path

from . import config
from . import skills
from .detect import secrets as sec
from .detect.engine import pattern_scan
from .kb import KB

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

STATE_FILE = "watch_state.json"
TRIAGE_FILE = "triage_queue.jsonl"
ALERT_FILE = "watch_alerts.jsonl"

SKIP_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build",
    ".aegis", ".tox", ".mypy_cache",
}
MAX_FILE_BYTES = 200_000

SCHEDULE_SECS = {"hourly": 3600, "daily": 86400}

# Reuse the same static-audit patterns /hunt uses so watch and hunt agree.
_AUDIT_COMPILED = [
    (kind, re.compile(rx), hint) for kind, rx, hint in skills.AUDIT_PATTERNS
]


# -- scoping --------------------------------------------------------------

def resolve_local_dir(target: str) -> Path | None:
    """Return the local dir Path, or None (printing a refusal) if the target
    is remote, non-local, or not an existing directory."""
    target = (target or "").strip()
    if not target:
        print("usage: watch --once|--interval|--schedule <local-directory>")
        return None
    if skills._looks_remote(target):
        print(f"refused: watch only monitors your OWN local machine. "
              f"'{target}' looks remote.")
        return None
    p = Path(target).expanduser().resolve()
    if not p.is_dir():
        print(f"refused: '{target}' is not a local directory on this "
              f"machine. watch monitors your own assets only.")
        return None
    return p


# -- file walking ----------------------------------------------------------

def iter_watch_files(root: Path):
    """Yield text-ish files under root, skipping VCS/deps/huge/binary."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            fp = Path(dirpath) / fn
            try:
                if fp.stat().st_size > MAX_FILE_BYTES or fp.stat().st_size == 0:
                    continue
                data = fp.read_bytes()
            except OSError:
                continue
            if b"\x00" in data:  # binary
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            yield fp, text


def file_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


# -- state -----------------------------------------------------------------

def state_paths():
    d = config.state_dir()
    return (d / STATE_FILE, d / TRIAGE_FILE, d / ALERT_FILE)


def load_state() -> dict:
    state_path, _, _ = state_paths()
    if state_path.exists():
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {"files": {}, "schedules": []}


def save_state(state: dict) -> None:
    state_path, _, _ = state_paths()
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(state_path)


# -- detection ---------------------------------------------------------------

def _kb_technique_id(kb: KB, hint: str) -> str | None:
    try:
        hits = kb.query(hint, top_k=1)
        return hits[0].id if hits else None
    except Exception:
        return None


def detect_file(rel: str, text: str, kb: KB) -> list[dict]:
    """Run secret scan + static audit patterns + KB pattern detection on one
    file's text. Evidence is redacted at creation. Returns finding dicts."""
    findings: list[dict] = []

    # 1. Secret-shaped material (critical: credential exposure at rest).
    secret_tid = (_kb_technique_id(kb, "credential exfiltration hardcoded "
                                  "secret api key at rest")
                  or "WATCH-SECRET-LEAK")
    for hit in sec.find_secrets(text):
        findings.append({
            "technique_id": secret_tid,
            "technique_name": "secret material at rest",
            "category": "credential_exfiltration",
            "severity": "critical",
            "rule": f"watch_secret_scan:{hit.kind}",
            "evidence": sec.redact(
                f"{rel} line {_line_of(text, hit.start)} — "
                f"{hit.kind} redacted")[0],
            "mitigation": "Remove the secret from the file; revoke/rotate "
                          "it; store it in a secret manager or env var.",
            "file": rel, "line": _line_of(text, hit.start),
            "detector": "secrets",
        })

    # 2. Static audit patterns (same set /hunt uses).
    for i, line in enumerate(text.splitlines(), 1):
        for kind, rx, hint in _AUDIT_COMPILED:
            if rx.search(line):
                tid = (_kb_technique_id(kb, hint.replace("_", " "))
                       or f"WATCH-{kind.upper()}")
                findings.append({
                    "technique_id": tid,
                    "technique_name": kind,
                    "category": "audit_pattern",
                    "severity": "high",
                    "rule": f"watch_audit_pattern:{kind}",
                    "evidence": sec.redact(
                        f"{rel}:{i} {line.strip()[:160]}")[0],
                    "mitigation": "Review this line against the KB technique "
                                  "guidance and remediate.",
                    "file": rel, "line": i,
                    "detector": "audit_pattern",
                })
                break  # one finding per kind per line

    # 3. KB detection patterns (prompt-injection indicators, etc.).
    for f in pattern_scan(text, kb):
        findings.append({
            "technique_id": f.technique_id,
            "technique_name": f.technique_name,
            "category": f.category,
            "severity": f.severity,
            "rule": f"watch_kb_pattern:{f.rule}",
            "evidence": sec.redact(f"{rel} — {f.evidence}")[0],
            "mitigation": f.mitigation,
            "file": rel, "line": 0,
            "detector": "kb_pattern",
        })

    return findings


# -- triage ------------------------------------------------------------------

def fingerprint(finding: dict) -> str:
    raw = (f"{finding.get('technique_id', '')}\x00"
           f"{finding.get('file', '')}\x00"
           f"{finding.get('line', 0)}")
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def read_queue() -> list[dict]:
    _, triage_path, _ = state_paths()
    entries: dict[str, dict] = {}
    if triage_path.exists():
        for line in triage_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if isinstance(e, dict) and e.get("fingerprint"):
                entries[e["fingerprint"]] = e
    return list(entries.values())


def write_queue(entries: list[dict]) -> None:
    _, triage_path, _ = state_paths()
    triage_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = triage_path.with_suffix(".tmp")
    tmp.write_text("".join(json.dumps(e) + "\n" for e in entries),
                   encoding="utf-8")
    tmp.replace(triage_path)


def enqueue_findings(findings: list[dict]) -> list[dict]:
    """Fingerprint + dedupe findings into the queue. Returns only the NEW
    entries. Repeats bump seen-count instead of creating duplicates."""
    now = time.time()
    existing = {e["fingerprint"]: e for e in read_queue()}
    new: list[dict] = []
    changed = False
    for f in findings:
        fp = fingerprint(f)
        if fp in existing:
            e = existing[fp]
            e["seen_count"] = e.get("seen_count", 1) + 1
            e["last_seen"] = now
            changed = True
        else:
            e = {
                "fingerprint": fp,
                "technique_id": f.get("technique_id", ""),
                "technique_name": f.get("technique_name", ""),
                "category": f.get("category", ""),
                "severity": f.get("severity", "low"),
                "rule": f.get("rule", ""),
                "evidence": f.get("evidence", ""),
                "mitigation": f.get("mitigation", ""),
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "detector": f.get("detector", ""),
                "status": "open",
                "first_seen": now,
                "last_seen": now,
                "seen_count": 1,
            }
            existing[fp] = e
            new.append(e)
            changed = True
    if changed:
        write_queue(list(existing.values()))
    return new


def ranked_queue() -> list[dict]:
    return sorted(read_queue(),
                  key=lambda e: (SEV_ORDER.get(e.get("severity", "low"), 3),
                                 -e.get("last_seen", 0)))


def print_triage() -> None:
    entries = ranked_queue()
    counts: dict[str, int] = {}
    for e in entries:
        counts[e.get("severity", "low")] = counts.get(
            e.get("severity", "low"), 0) + 1
    print(f"watch triage queue: {len(entries)} open "
          f"({', '.join(f'{k}: {v}' for k, v in sorted(counts.items(), key=lambda kv: SEV_ORDER.get(kv[0], 3)))})")
    for e in entries:
        print(f"[{e.get('severity', 'low').upper()}] {e.get('technique_id')} — "
              f"{e.get('technique_name')} @ {e.get('file')}:{e.get('line')} "
              f"(seen {e.get('seen_count', 1)}x, {e.get('detector')})")


# -- alerting ------------------------------------------------------------------

def log_alert(alert: dict) -> None:
    _, _, alert_path = state_paths()
    alert_path.parent.mkdir(parents=True, exist_ok=True)
    rec = {"ts": time.time()}
    rec.update(alert)
    with open(alert_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, default=str) + "\n")


def alert_banner(new: list[dict], root: Path) -> str:
    lines = [f"!!! [WATCH ALERT] {len(new)} new finding(s) in {root}"]
    for e in sorted(new,
                    key=lambda e: SEV_ORDER.get(e.get("severity", "low"), 3)):
        lines.append(f"  [{e.get('severity', 'low').upper()}] "
                     f"{e.get('technique_id')} — {e.get('technique_name')} "
                     f"@ {e.get('file')}:{e.get('line')}")
    return "\n".join(lines)


# -- scheduled hunts -------------------------------------------------------------

def schedule_add(freq: str, root: Path, state: dict) -> None:
    freq = freq.lower()
    if freq not in SCHEDULE_SECS:
        raise ValueError(f"unknown schedule '{freq}'; choose daily|hourly")
    key = str(root)
    state.setdefault("schedules", [])
    for s in state["schedules"]:
        if s.get("dir") == key and s.get("freq") == freq:
            print(f"already scheduled: {freq} hunt on {key}")
            return
    state["schedules"].append(
        {"dir": key, "freq": freq, "last_run": 0.0})
    print(f"scheduled {freq} hunt on {key}")


def schedule_due(entry: dict, now: float) -> bool:
    freq = entry.get("freq", "daily")
    period = SCHEDULE_SECS.get(freq, SCHEDULE_SECS["daily"])
    return now - float(entry.get("last_run", 0.0)) >= period


def run_due_hunts(root: Path, state: dict, kb: KB) -> list[str]:
    """Run skills.hunt for each schedule matching this dir that is due.
    Returns short status lines."""
    out: list[str] = []
    now = time.time()
    for entry in state.get("schedules", []):
        try:
            scheduled = Path(entry.get("dir", "")).resolve()
        except Exception:
            continue
        if scheduled != root:
            continue
        if not schedule_due(entry, now):
            continue
        report = skills.hunt(str(root), kb)
        entry["last_run"] = now
        lines = [l for l in report.splitlines() if l.startswith("Files scanned")]
        summary = lines[0] if lines else "hunt complete"
        out.append(f"[{entry.get('freq')}] scheduled hunt on {root}: {summary}")
    return out


# -- the pass --------------------------------------------------------------------

def watch_pass(root: Path, kb: KB, state: dict) -> tuple[list[dict], list[str]]:
    """One monitoring pass. Returns (new_findings, status_lines)."""
    files_seen: dict[str, str] = {}
    findings: list[dict] = []
    scanned = 0
    for fp, text in iter_watch_files(root):
        rel = str(fp.relative_to(root))
        h = file_hash(text)
        files_seen[rel] = h
        scanned += 1
        if state.get("files", {}).get(rel) == h:
            continue  # unchanged — no rescan
        findings.extend(detect_file(rel, text, kb))
    state["files"] = files_seen

    new = enqueue_findings(findings)
    status = [f"pass: {scanned} file(s) scanned, "
              f"{len(findings)} finding(s) ({len(new)} new)"]
    if new:
        banner = alert_banner(new, root)
        status.append(banner)
        log_alert({"kind": "new_findings", "dir": str(root),
                   "findings": [
                       {"technique_id": e["technique_id"],
                        "technique_name": e["technique_name"],
                        "severity": e["severity"], "file": e["file"],
                        "line": e["line"]}
                       for e in new]})
    hunt_notes = run_due_hunts(root, state, kb)
    status.extend(hunt_notes)
    for note in hunt_notes:
        log_alert({"kind": "scheduled_hunt", "dir": str(root),
                   "detail": note})
    save_state(state)
    return new, status


# -- CLI ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="aegis watch",
        description="Defensive continuous monitoring of your OWN local "
                    "directories (no remote targets, no network).")
    ap.add_argument("--once", metavar="DIR",
                    help="single monitoring pass over a local directory")
    ap.add_argument("--interval", nargs=2, metavar=("SECONDS", "DIR"),
                    help="loop the pass every SECONDS over a local directory")
    ap.add_argument("--triage", action="store_true",
                    help="print the severity-ranked finding queue")
    ap.add_argument("--schedule", nargs=2, metavar=("daily|hourly", "DIR"),
                    help="record a scheduled hunt for a local directory")
    return ap


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    chosen = [bool(args.once), bool(args.interval), args.triage,
              bool(args.schedule)]
    if sum(chosen) != 1:
        build_parser().print_usage()
        print("choose exactly one of: --once, --interval, --triage, --schedule")
        return 2

    kb = KB.load()

    if args.triage:
        print_triage()
        return 0

    if args.schedule:
        freq, target = args.schedule
        root = resolve_local_dir(target)
        if root is None:
            return 2
        try:
            state = load_state()
            schedule_add(freq, root, state)
            save_state(state)
        except ValueError as e:
            print(f"error: {e}")
            return 2
        return 0

    if args.once:
        root = resolve_local_dir(args.once)
        if root is None:
            return 2
        state = load_state()
        _, status = watch_pass(root, kb, state)
        print("\n".join(status))
        return 0

    # --interval SECONDS DIR
    secs_s, target = args.interval
    root = resolve_local_dir(target)
    if root is None:
        return 2
    try:
        interval = float(secs_s)
        if interval <= 0:
            raise ValueError
    except ValueError:
        print(f"error: interval must be a positive number of seconds, "
              f"got '{secs_s}'")
        return 2
    print(f"watching {root} every {interval:g}s — Ctrl-C to stop")
    try:
        while True:
            state = load_state()
            _, status = watch_pass(root, kb, state)
            print("\n".join(status))
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nwatch stopped.")
    return 0
