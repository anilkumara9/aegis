"""Agent loop: model-agnostic reasoning loop with the guard INSIDE.

Every tool call the model requests passes through the guard session
(allowlist/denylist, arg patterns, secret scan, egress control, approval
escalation) BEFORE execution. Tool outputs are redacted before the model
or the audit log sees them. This is the dogfood: the agent defends itself
with the same engine it offers others.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable

from . import config, guard as guard_mod
from . import session as session_mod
from .audit import AuditLog
from .detect import secrets as sec
from .kb import KB
from .providers import Provider, ToolCall
from .tools import ToolContext
from .tools.registry import TOOLS


def build_system_prompt(kb: KB, mode: str = "dev") -> str:
    mode_section = (
        "## Mode: PLAN (read-only)\n"
        "You are in PLAN mode. You may investigate freely: read files, query "
        "your technique knowledge, fetch web pages, analyze traces. You "
        "CANNOT write, edit, or execute anything — the guard denies those "
        "tools at the enforcement layer, so do not attempt them. When the "
        "user needs changes, describe them precisely: exact file paths, "
        "exact diffs, exact commands to run. Think like an attacker studying "
        "the target, but act only as the defender's planner."
        if mode == "plan" else
        "## Mode: DEV (full power)\n"
        "You are in DEV mode with full tool power. Every call is still "
        "guard-screened: dangerous patterns are denied, secrets redacted, "
        "egress controlled, high-severity calls paused for human approval."
    )
    return "\n\n".join([
        "# Aegis — defensive security agent",
        ("You are Aegis, a defensive cybersecurity agent. You have deep, "
         "in-depth knowledge of the hacking world — every attack technique — "
         "pointed ENTIRELY at defense. You detect attack techniques, block "
         "them, and help remediate. You NEVER help attack anyone: no exploit "
         "payloads, no unauthorized-access assistance, no weaponized code. "
         "Security auditing is only ever performed on the user's OWN "
         "explicitly-specified local systems."),
        mode_section,
        kb.doctrine_section(),
        kb.technique_index(),
        ("## Your defenses (always on)\n"
         "- Every tool call you make is screened by your guard engine: tool "
         "allowlist/denylist, dangerous-argument patterns, secret detection, "
         "and egress domain control. A denied call returns a GUARD message — "
         "do NOT try to work around it; explain and continue safely.\n"
         "- Secrets in tool arguments or outputs are redacted before you see "
         "them. If you see [REDACTED:...], treat the value as unknown and "
         "never ask for it or try to reconstruct it.\n"
         "- High-severity matches pause for the human operator's approval.\n"
         "- Use kb_query to consult your technique knowledge mid-reasoning; "
         "cite technique IDs (AEG-Txxx) when you identify attack activity.\n"
         "- When you find a compromise, use the respond tool to emit the "
         "exact operator runbook."),
        ("## Tools\n"
         "Call tools with JSON arguments. Prefer read-only investigation "
         "first. Keep commands minimal and reversible."),
    ])


def _summarize_args(args: dict) -> str:
    """Compact one-line summary of redacted tool args for display."""
    text, _ = sec.redact(json.dumps(args or {}, default=str))
    try:
        parsed = json.loads(text)
    except Exception:
        return text[:300]
    if not isinstance(parsed, dict):
        return str(parsed)[:300]
    parts = []
    for k, v in parsed.items():
        s = str(v)
        if len(s) > 60:
            s = s[:57] + "..."
        parts.append(f"{k}={s}")
    return ", ".join(parts)[:300]


class AgentLoop:
    def __init__(self, provider: Provider, kb: KB,
                 guard_session: guard_mod.GuardSession,
                 cwd: Path | None = None,
                 approval_callback: Callable | None = None,
                 on_text: Callable[[str], None] | None = None,
                 max_iterations: int | None = None,
                 # -- additive v0.2 UX hooks (all default off) ----------------
                 conversation_id: str | None = None,
                 history: list[dict] | None = None,
                 on_tool_start: Callable[[str, str], None] | None = None,
                 on_tool_end: Callable[[str, str, float, str], None] | None = None):
        self.provider = provider
        self.kb = kb
        self.guard = guard_session
        self.cwd = Path(cwd or ".").resolve()
        self.approval_callback = approval_callback
        self.on_text = on_text or (lambda s: None)
        self.max_iterations = max_iterations or config.MAX_AGENT_ITERATIONS
        self.ctx = ToolContext(guard_session=guard_session, kb=kb, cwd=self.cwd,
                               approval_callback=approval_callback)
        self.system = build_system_prompt(kb, guard_session.policy.mode)
        self.tool_specs = [t.spec() for t in TOOLS.values()]
        # Display callbacks for tool-call blocks: additive, never required.
        self.on_tool_start = on_tool_start or (lambda name, summary: None)
        self.on_tool_end = (on_tool_end or
                            (lambda name, verdict, ms, excerpt: None))
        # Conversation persistence: None = legacy stateless mode (each run()
        # starts fresh, exactly as before). Set conversation_id and/or
        # history to get multi-turn context with per-turn persistence.
        self.conversation_id: str | None = None
        self.history: list[dict] | None = None
        if history is not None:
            self.history = [dict(m) for m in history]
        if conversation_id is not None:
            if not self.attach_conversation(conversation_id, keep_existing=True):
                # Brand-new persisted session: create the store record and
                # start from the given history (or empty).
                session_mod.new_session(conversation_id)
                self.conversation_id = conversation_id
                if self.history is None:
                    self.history = []

    def set_mode(self, mode: str) -> None:
        """Switch dev/plan mode mid-session.

        The guard policy is the enforcement point; the system prompt is
        rebuilt so the model reasons correctly about its capabilities.
        """
        mode = mode.lower()
        if mode not in ("dev", "plan"):
            raise ValueError(f"unknown mode '{mode}' (want dev|plan)")
        self.guard.policy.mode = mode
        self.system = build_system_prompt(self.kb, mode)

    @property
    def mode(self) -> str:
        return self.guard.policy.mode

    def attach_conversation(self, conversation_id: str,
                            keep_existing: bool = False) -> bool:
        """Attach (or re-attach) a persisted conversation session.

        History from the store is loaded into the loop so a resumed
        session continues where it left off. Returns False when the
        session does not exist.
        """
        rec = session_mod.load_session(conversation_id)
        if rec is None:
            return False
        stored = [dict(m) for m in rec.get("messages", [])]
        if keep_existing and self.history:
            self.history = self.history + stored
        else:
            self.history = stored
        self.conversation_id = conversation_id
        return True

    # -- single user turn ------------------------------------------------
    def run(self, user_message: str) -> str:
        base = list(self.history) if self.history is not None else []
        messages = base + [{"role": "user", "content": user_message}]
        result = self._run_turn(messages)
        # Persist the turn (user + assistant + tool messages) into the
        # conversation store and into the in-memory history.
        turn = messages[len(base):]
        if self.history is not None:
            self.history.extend(turn)
        if self.conversation_id:
            for m in turn:
                extra = {k: v for k, v in m.items()
                         if k not in ("role", "content")}
                session_mod.save_message(self.conversation_id,
                                         m.get("role", ""), m.get("content", ""),
                                         extra=extra or None)
        return result

    def _run_turn(self, messages: list[dict]) -> str:
        final_text: list[str] = []
        for _ in range(self.max_iterations):
            text, tool_calls, error = self._one_step(messages)
            if error:
                messages.append({"role": "assistant", "content": text})
                return "".join(final_text) + f"\n[provider error: {error}]"
            final_text.append(text)
            if not tool_calls:
                # Text-only turn: keep the assistant reply in the transcript
                # so persisted/resumed history stays complete.
                messages.append({"role": "assistant", "content": text})
                return "".join(final_text)
            assistant_msg: dict = {"role": "assistant", "content": text,
                                   "tool_calls": []}
            for tc in tool_calls:
                result = self._guarded_execute(tc)
                # Transcript keeps redacted args: never persist secrets in
                # conversation state.
                redacted_args_text, _ = sec.redact(json.dumps(tc.args, default=str))
                try:
                    redacted_args = json.loads(redacted_args_text)
                    redacted_args = redacted_args if isinstance(redacted_args, dict) else {}
                except Exception:
                    redacted_args = {}
                assistant_msg["tool_calls"].append(
                    {"id": tc.id, "name": tc.name, "args": redacted_args})
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "name": tc.name, "content": result})
            messages.insert(len(messages) - len(tool_calls), assistant_msg)
        self.on_text("\n[max iterations reached]\n")
        return "".join(final_text) + "\n[max iterations reached]"

    def _one_step(self, messages: list[dict]):
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        error = ""
        for kind, payload in self.provider.stream(messages, self.tool_specs,
                                                  self.system):
            if kind == "text":
                text_parts.append(str(payload))
                self.on_text(str(payload))
            elif kind == "tool_call":
                tool_calls.append(payload)
            elif kind == "error":
                error = str(payload)
                self.on_text(f"\n[provider error: {error}]\n")
                break
            elif kind == "done":
                break
        return "".join(text_parts), tool_calls, error

    # -- guarded execution -------------------------------------------------
    def _guarded_execute(self, tc: ToolCall) -> str:
        t0 = time.perf_counter()
        try:
            self.on_tool_start(tc.name, _summarize_args(tc.args))
        except Exception:
            pass
        tool = TOOLS.get(tc.name)
        if tool is None:
            self._audit(tc, "deny", [], "unknown tool")
            result = f"GUARD DENIED: unknown tool '{tc.name}'"
            self._tool_end(tc, "deny", t0, "unknown tool")
            return result
        verdict = self.guard.check_call(tc.name, tc.args)
        if verdict.decision == "deny":
            self._audit(tc, "deny", verdict.findings,
                        f"denied: {verdict.reason}")
            result = (f"GUARD DENIED: {verdict.reason}. Do not attempt to work "
                    f"around this. Explain what you were trying to do and "
                    f"continue safely.")
            self._tool_end(tc, "deny", t0, verdict.reason)
            return result
        if verdict.decision == "needs_approval":
            approved = self._ask_approval(tc, verdict)
            if not approved:
                self._audit(tc, "denied", verdict.findings, "operator denied")
                result = ("GUARD: the human operator denied this call. "
                        "Continue with a safer alternative or stop.")
                self._tool_end(tc, "denied", t0, "operator denied")
                return result
        try:
            raw = tool.run(tc.args, self.ctx)
        except Exception as e:
            raw = f"error: tool execution failed: {e}"
        redacted, _ = sec.redact(raw)
        self._audit(tc, verdict.decision if verdict.decision == "allow" else "approved",
                    verdict.findings, redacted)
        self._tool_end(tc, "allow" if verdict.decision == "allow" else "approved",
                       t0, redacted)
        return redacted

    def _tool_end(self, tc: ToolCall, verdict: str, t0: float,
                  output: str) -> None:
        duration_ms = (time.perf_counter() - t0) * 1000
        try:
            self.on_tool_end(tc.name, verdict, duration_ms, str(output)[:500])
        except Exception:
            pass

    def _ask_approval(self, tc: ToolCall, verdict) -> bool:
        cb = self.approval_callback or self.guard.policy.approval_callback
        if cb is None:
            return False
        try:
            return bool(cb(verdict.findings, tc.name, tc.args))
        except TypeError:
            return bool(cb(verdict.findings))

    def _audit(self, tc: ToolCall, decision: str, findings, output: str) -> None:
        args_text, _ = sec.redact(json.dumps(tc.args, default=str))
        try:
            args = json.loads(args_text)
        except Exception:
            args = {"_raw": args_text}
        self.guard.audit.tool_call(
            tc.name, args if isinstance(args, dict) else {"_raw": args_text},
            decision,
            [f.to_dict() if hasattr(f, "to_dict") else f for f in findings],
            output_excerpt=output[:2000])
