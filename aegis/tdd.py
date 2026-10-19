"""Test-driven loop helper in the agent flow (v0.7 Lane A).

tdd_loop() orchestrates the write -> run tests -> fix failures cycle:

  1. the agent loop implements (write/edit tools, guard-screened),
  2. THIS helper runs the project's real test suite (polyglot),
  3. failures are fed back into the loop for a fix attempt,
  4. repeat until green or the iteration cap — then report honestly.

Every step is logged three ways: to the loop's on_text stream, into the
returned steps list, and as a redacted `tdd_step` record in the session
audit log. Test output is redacted before the model ever sees it, so a
failing test that echoes a secret can never leak it into context.

Requires DEV mode: in plan mode writes/edits are guard-denied, so the
loop refuses immediately instead of burning iterations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import polyglot
from .detect import secrets as sec

DEFAULT_MAX_ROUNDS = 5


def _audit_step(loop, event: str, **fields: Any) -> None:
    try:
        loop.guard.audit.record({"event": event, **fields})
    except Exception:
        pass


def _say(loop, msg: str) -> None:
    try:
        loop.on_text(msg if msg.endswith("\n") else msg + "\n")
    except Exception:
        pass


def _redact(text: str) -> str:
    out, _ = sec.redact(text or "")
    return out


def tdd_loop(loop, project_dir: str | Path, task: str,
             max_rounds: int = DEFAULT_MAX_ROUNDS,
             test_timeout: int = 300) -> dict:
    """Run write -> test -> fix until green or the cap.

    loop: an AgentLoop (its provider may be a mock in tests).
    Returns {"status", "rounds", "summary"} where status is one of
    "green" | "stuck" | "refused" | "no_tests".
    """
    root = Path(project_dir).expanduser().resolve()
    max_rounds = max(1, int(max_rounds or DEFAULT_MAX_ROUNDS))
    steps: list[dict] = []

    def log(kind: str, detail: str, **extra: Any) -> None:
        steps.append({"kind": kind, "detail": detail, **extra})
        _say(loop, f"[tdd] {kind}: {detail}")
        _audit_step(loop, "tdd_step", kind=kind,
                    detail=_redact(detail)[:2000], **extra)

    if getattr(loop, "mode", "dev") != "dev":
        msg = (f"refused: tdd_loop needs DEV mode (current: "
               f"{getattr(loop, 'mode', '?')}); /mode dev to enable writes")
        log("refused", msg)
        return {"status": "refused", "rounds": steps, "summary": msg}

    hits = polyglot.detect_languages(root)
    if not hits:
        msg = (f"no_tests: no toolchain detected in {root} — cannot run a "
               f"test suite")
        log("no_tests", msg)
        return {"status": "no_tests", "rounds": steps, "summary": msg}

    langs = ", ".join(h.language for h in hits)
    log("start", f"task: {task} | dir: {root} | toolchains: {langs} | "
                 f"max rounds: {max_rounds}")

    last_result = None
    for rnd in range(1, max_rounds + 1):
        if rnd == 1:
            prompt = (
                f"[TDD round {rnd}/{max_rounds}] Implement the following "
                f"task in {root} using write/edit tools. Keep changes "
                f"minimal and focused. Do NOT run the test suite yourself — "
                f"I will run it and report the result.\n\nTask: {task}")
            action = "implement"
        else:
            failed = last_result["summary"] if last_result else "unknown"
            output = last_result["output"] if last_result else ""
            prompt = (
                f"[TDD round {rnd}/{max_rounds}] The test suite FAILED:\n"
                f"{failed}\n\n{output}\n\n"
                f"Fix the failures with read/edit tools. Keep changes "
                f"minimal; do not change unrelated behavior. Do NOT run the "
                f"test suite yourself.")
            action = "fix"
        log(action, f"round {rnd}: agent {action} turn started")
        try:
            loop.run(prompt)
        except Exception as e:  # noqa: BLE001 - loop errors are step data
            log("loop_error", f"round {rnd}: agent turn raised "
                              f"{type(e).__name__}: {e}")
            continue
        log("test", f"round {rnd}: running test suite")
        results = polyglot.run_tests(root, timeout=test_timeout)
        green = bool(results) and all(r.ok for r in results)
        summary = " | ".join(r.summary for r in results) or "no results"
        output = "\n".join(r.steps[0].output for r in results
                           if r.steps) if results else ""
        last_result = {"summary": summary, "output": output}
        log("test_result", f"round {rnd}: {summary}",
            green=green, round=rnd)
        if green:
            msg = f"GREEN after {rnd} round(s): {summary}"
            log("green", msg)
            return {"status": "green", "rounds": steps, "summary": msg}

    tried = "; ".join(f"round {s.get('round', '?')}: "
                      f"{s['detail'][:120]}"
                      for s in steps if s["kind"] == "test_result")
    msg = (f"STUCK after {max_rounds} rounds — still red: "
           f"{last_result['summary'] if last_result else 'no test output'}. "
           f"What was tried: {tried or 'agent turns produced no fix'}. "
           f"Full per-round log is in the session audit log (tdd_step).")
    log("stuck", msg)
    return {"status": "stuck", "rounds": steps, "summary": msg}
