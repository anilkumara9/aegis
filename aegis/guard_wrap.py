"""Subprocess wrapper mode: `aegis guard wrap -- <cmd> [args...]`.

Screens an external command through the guard before running it:
denylist/allowlist, dangerous-arg patterns, secret-shaped payloads, and
egress domain rules all apply. Stdout/stderr are redacted before display.
The (redacted) invocation is audit-logged. Returns the command's exit code.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from . import guard as guard_mod
from .detect import secrets as sec
from .guard import GuardDenied, Policy, SessionRevoked, create_session
from .kb import KB


def wrap(argv: list[str], policy: Policy | None = None,
         kb: KB | None = None, session_id: str | None = None,
         approval_callback=None) -> int:
    if not argv:
        print("aegis guard wrap: no command given", file=sys.stderr)
        return 2
    kb = kb or KB.load()
    policy = policy or Policy(name="wrap")
    if approval_callback is not None:
        policy.approval_callback = approval_callback
    session = create_session(policy, kb, session_id=session_id)
    cmd_text = " ".join(argv)
    tool = Path(argv[0]).name
    args = {"cmd": cmd_text, "argv": argv}
    try:
        verdict = session.check_call("bash", args)
    except SessionRevoked as e:
        print(f"GUARD: {e}", file=sys.stderr)
        return 126
    if verdict.decision == "deny":
        print(f"GUARD DENIED: {verdict.reason}", file=sys.stderr)
        _audit(session, tool, args, "deny", verdict, "")
        return 126
    if verdict.decision == "needs_approval":
        if not session.resolve(verdict):
            print("GUARD: operator denied this command", file=sys.stderr)
            _audit(session, tool, args, "denied", verdict, "")
            return 126
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=300)
        out = (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        print(f"GUARD: command not found: {argv[0]}", file=sys.stderr)
        return 127
    except Exception as e:
        print(f"GUARD: execution failed: {e}", file=sys.stderr)
        return 1
    redacted, _ = sec.redact(out)
    if len(redacted) > 40000:
        redacted = redacted[:40000] + "\n...[truncated]"
    sys.stdout.write(redacted)
    _audit(session, tool, args,
           "allow" if verdict.decision == "allow" else "approved",
           verdict, redacted)
    return proc.returncode


def _audit(session, tool, args, decision, verdict, output):
    args_text, _ = sec.redact(json.dumps(args, default=str))
    try:
        red_args = json.loads(args_text)
    except Exception:
        red_args = {"_raw": args_text}
    session.audit.tool_call(
        f"wrap:{tool}", red_args if isinstance(red_args, dict) else {"_raw": args_text},
        decision,
        [f.to_dict() for f in verdict.findings],
        output_excerpt=output[:2000])
