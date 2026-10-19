"""Plan-then-execute framework: enforced planning, verification loops,
progress events. (v0.7 Lane C — reasoning upgrades.)

Logical rigor lives here as FRAMEWORK behavior, not as a model hope:

- :class:`TaskPlan` — an explicit step list with per-step status. A plan
  cannot execute until it is approved (REPL prompt, ``--yes``, or a
  programmatic approval callback). Any tool call that deviates from the
  active plan is blocked unless re-approved.
- :func:`verify_plan` — before the agent declares a task DONE, a
  verification pass checks the plan's real outcomes: expected files exist,
  the project's test command passes, and every guard denial is disclosed
  (never hidden). Failures loop back a bounded number of times instead of
  claiming success.
- Progress events — small dicts emitted through a ``progress_callback``
  the REPL/TUI renders. Minimal surface on purpose; Lane E owns display.
"""

from __future__ import annotations

import re
import subprocess
import time
import uuid
from typing import Callable

# -- step / plan status vocabulary -----------------------------------------
PENDING = "pending"
ACTIVE = "active"
DONE = "done"
FAILED = "failed"
DENIED = "denied"
SKIPPED = "skipped"

PROPOSED = "proposed"
APPROVED = "approved"
EXECUTING = "executing"
VERIFIED = "verified"
PLAN_FAILED = "failed"
REJECTED = "rejected"
BLOCKED = "blocked"
INTERRUPTED = "interrupted"

_TERMINAL = {VERIFIED, PLAN_FAILED, REJECTED, BLOCKED}


class PlanStep:
    """One tool step inside a task plan."""

    def __init__(self, tool: str, args: dict, purpose: str = ""):
        self.tool = tool
        self.args = dict(args or {})
        self.purpose = purpose or ""
        self.status = PENDING
        self.error = ""
        self.started_ts: float | None = None
        self.ended_ts: float | None = None

    def to_dict(self) -> dict:
        return {"tool": self.tool, "args": self.args,
                "purpose": self.purpose, "status": self.status,
                "error": self.error}

    @classmethod
    def from_dict(cls, d: dict) -> "PlanStep":
        s = cls(d.get("tool", ""), d.get("args") or {},
                d.get("purpose", ""))
        s.status = d.get("status", PENDING)
        s.error = d.get("error", "")
        return s


class TaskPlan:
    """An approved-execution contract: explicit steps, tracked status.

    Serializes to plain dicts so it can persist in the session store
    (``/resume`` keeps it).
    """

    def __init__(self, task: str, steps: list[PlanStep] | None = None,
                 verify_command: str = ""):
        self.id = uuid.uuid4().hex[:12]
        self.task = task
        self.steps: list[PlanStep] = list(steps or [])
        self.state = PROPOSED
        self.verify_command = verify_command or ""
        self.created = time.time()
        self.updated = self.created
        self.note = ""  # human-readable outcome / failure summary

    # -- accessors ------------------------------------------------------
    def active_step(self) -> PlanStep | None:
        for s in self.steps:
            if s.status == ACTIVE:
                return s
        return None

    def pending_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.status == PENDING]

    def failed_steps(self) -> list[PlanStep]:
        return [s for s in self.steps if s.status == FAILED]

    def is_terminal(self) -> bool:
        return self.state in _TERMINAL

    # -- mutation -------------------------------------------------------
    def touch(self) -> None:
        self.updated = time.time()

    def mark_step(self, index: int, status: str, error: str = "") -> None:
        s = self.steps[index]
        now = time.time()
        if status == ACTIVE and s.status != ACTIVE:
            s.started_ts = now
        if status in (DONE, FAILED, DENIED, SKIPPED):
            s.ended_ts = now
        s.status = status
        s.error = error
        self.touch()

    def insert_step_after_active(self, tool: str, args: dict,
                                 purpose: str) -> PlanStep:
        """Insert an approved deviation as a real plan step."""
        step = PlanStep(tool, args, purpose + " [approved deviation]")
        idx = next((i for i, s in enumerate(self.steps)
                    if s.status == ACTIVE), len(self.steps) - 1)
        self.steps.insert(idx + 1, step)
        self.touch()
        return step

    # -- deviation ------------------------------------------------------
    def check_deviation(self, tool_name: str) -> dict | None:
        """Return a deviation report if ``tool_name`` is not the active
        step's tool, else None. Only meaningful while EXECUTING."""
        if self.state != EXECUTING:
            return None
        active = self.active_step()
        expected = active.tool if active else None
        if expected == tool_name:
            return None
        return {"kind": "deviation", "plan_id": self.id,
                "tool": tool_name, "expected": expected}

    # -- (de)serialization ----------------------------------------------
    def to_dict(self) -> dict:
        return {"id": self.id, "task": self.task, "state": self.state,
                "verify_command": self.verify_command,
                "created": self.created, "updated": self.updated,
                "note": self.note,
                "steps": [s.to_dict() for s in self.steps]}

    @classmethod
    def from_dict(cls, d: dict) -> "TaskPlan":
        p = cls(d.get("task", ""),
                [PlanStep.from_dict(s) for s in d.get("steps", [])],
                d.get("verify_command", ""))
        p.id = d.get("id", p.id)
        p.state = d.get("state", PROPOSED)
        p.created = d.get("created", p.created)
        p.updated = d.get("updated", p.updated)
        p.note = d.get("note", "")
        return p


# -- complexity heuristic ---------------------------------------------------
_ACTION_VERBS = re.compile(
    r"\b(write|create|add|fix|update|refactor|implement|build|test|run|"
    r"install|delete|remove|edit|modify|rename|move|copy|generate|"
    r"migrate|deploy|scaffold|backfill|configure)\b")
_STEP_MARKER = re.compile(r"\bstep\s*\d+|^\s*[-*]\s|\d+\.\s", re.I)


def task_looks_complex(text: str) -> bool:
    """Heuristic: does this task need plan-then-execute?

    True when the user explicitly asks for a plan, numbers steps, chains
    actions with 'then'/'after that', or issues two or more action
    sentences. Conservative by design: plain chat stays a normal turn.
    """
    t = (text or "").strip()
    if not t:
        return False
    low = t.lower()
    if re.search(r"\bplan\b", low):
        return True
    if re.search(r"\bstep\s*\d+\b", low):
        return True
    if re.search(r"\b(and\s+)?then\b|\bafter\s+that\b", low):
        return True
    if _STEP_MARKER.search(t):
        return True
    sentences = [s for s in re.split(r"[.!?\n;]+", t) if s.strip()]
    action_sentences = sum(1 for s in sentences if _ACTION_VERBS.search(s))
    if action_sentences >= 2:
        return True
    if low.count(",") >= 2 and len(_ACTION_VERBS.findall(low)) >= 2:
        return True
    return False


# -- progress events ---------------------------------------------------------
def emit(progress_cb: Callable[[dict], None] | None, kind: str,
         **fields) -> None:
    """Emit one progress event. Never raises: a broken consumer must not
    kill the agent loop."""
    if progress_cb is None:
        return
    try:
        progress_cb({"kind": kind, **fields})
    except Exception:
        pass


# -- verification -------------------------------------------------------------
class VerificationResult:
    def __init__(self, ok: bool, checks: list[dict], denials: list[dict],
                 summary: str):
        self.ok = ok
        self.checks = checks      # [{name, ok, detail}]
        self.denials = denials    # audit records, disclosed not hidden
        self.summary = summary

    def report(self) -> str:
        lines = ["## Verification"]
        for c in self.checks:
            mark = "✓" if c["ok"] else "✗"
            lines.append(f"{mark} {c['name']}: {c['detail']}")
        if self.denials:
            lines.append(f"! {len(self.denials)} guard denial(s) during "
                         "execution — none hidden; details in the audit log.")
            for d in self.denials[:5]:
                lines.append(f"  - denied: {d.get('tool')} "
                             f"({str(d.get('output_excerpt', ''))[:120]})")
        lines.append("verdict: " + ("VERIFIED ✓" if self.ok
                                   else "NOT VERIFIED — do not treat as done"))
        return "\n".join(lines)


def _expected_files(plan: TaskPlan) -> list[str]:
    paths = []
    for s in plan.steps:
        if s.tool in ("write", "edit") and isinstance(s.args, dict):
            p = s.args.get("path")
            if p and p not in paths:
                paths.append(p)
    return paths


def verify_plan(plan: TaskPlan, cwd, audit_records: list[dict],
                run_command: Callable[[str], tuple[int, str]] | None = None,
                timeout: int = 120) -> VerificationResult:
    """Framework verification pass over a finished plan.

    Checks:
    1. every file a write/edit step touched actually exists;
    2. ``plan.verify_command`` (the project's test command) exits 0;
    3. guard denials during the run are collected for disclosure.

    ``run_command`` defaults to a plain subprocess runner; injectable for
    tests. Never claims success it did not measure.
    """
    from pathlib import Path
    checks: list[dict] = []
    ok = True
    base = Path(cwd)

    for p in _expected_files(plan):
        exists = (base / p).exists()
        checks.append({"name": f"file present: {p}", "ok": exists,
                       "detail": "exists" if exists
                       else "MISSING — step claimed to write it"})
        ok = ok and exists

    if plan.verify_command:
        if run_command is None:
            def run_command(cmd: str) -> tuple[int, str]:
                try:
                    r = subprocess.run(
                        cmd, shell=True, cwd=str(base), timeout=timeout,
                        capture_output=True, text=True)
                    tail = (r.stdout + r.stderr)[-1500:]
                    return r.returncode, tail.strip() or "(no output)"
                except subprocess.TimeoutExpired:
                    return 124, f"timed out after {timeout}s"
                except Exception as e:
                    return 127, f"runner error: {e}"
        code, out = run_command(plan.verify_command)
        passed = code == 0
        checks.append({"name": f"tests: {plan.verify_command}",
                       "ok": passed,
                       "detail": "exit 0" if passed
                       else f"exit {code}: {out[:300]}"})
        ok = ok and passed
    else:
        checks.append({"name": "project tests", "ok": True,
                       "detail": "skipped — no verify command configured"})

    denials = [r for r in (audit_records or [])
               if r.get("event") == "tool_call"
               and str(r.get("verdict", "")).lower() in ("deny", "denied")]
    summary = ("all checks passed" if ok else
               f"{sum(1 for c in checks if not c['ok'])} check(s) failed")
    return VerificationResult(ok, checks, denials, summary)
