"""Agent loop: model-agnostic reasoning loop with the guard INSIDE.

Every tool call the model requests passes through the guard session
(allowlist/denylist, arg patterns, secret scan, egress control, approval
escalation) BEFORE execution. Tool outputs are redacted before the model
or the audit log sees them. This is the dogfood: the agent defends itself
with the same engine it offers others.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from . import config, guard as guard_mod
from .audit import AuditLog
from .detect import secrets as sec
from .kb import KB
from .providers import Provider, ToolCall
from .tools import ToolContext
from .tools.registry import TOOLS


def build_system_prompt(kb: KB) -> str:
    return "\n\n".join([
        "# Aegis — defensive security agent",
        ("You are Aegis, a defensive cybersecurity agent. You have deep, "
         "in-depth knowledge of the hacking world — every attack technique — "
         "pointed ENTIRELY at defense. You detect attack techniques, block "
         "them, and help remediate. You NEVER help attack anyone: no exploit "
         "payloads, no unauthorized-access assistance, no weaponized code. "
         "Security auditing is only ever performed on the user's OWN "
         "explicitly-specified local systems."),
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


class AgentLoop:
    def __init__(self, provider: Provider, kb: KB,
                 guard_session: guard_mod.GuardSession,
                 cwd: Path | None = None,
                 approval_callback: Callable | None = None,
                 on_text: Callable[[str], None] | None = None,
                 max_iterations: int | None = None):
        self.provider = provider
        self.kb = kb
        self.guard = guard_session
        self.cwd = Path(cwd or ".").resolve()
        self.approval_callback = approval_callback
        self.on_text = on_text or (lambda s: None)
        self.max_iterations = max_iterations or config.MAX_AGENT_ITERATIONS
        self.ctx = ToolContext(guard_session=guard_session, kb=kb, cwd=self.cwd,
                               approval_callback=approval_callback)
        self.system = build_system_prompt(kb)
        self.tool_specs = [t.spec() for t in TOOLS.values()]

    # -- single user turn ------------------------------------------------
    def run(self, user_message: str) -> str:
        messages = [{"role": "user", "content": user_message}]
        final_text: list[str] = []
        for _ in range(self.max_iterations):
            text, tool_calls, error = self._one_step(messages)
            if error:
                return "".join(final_text) + f"\n[provider error: {error}]"
            final_text.append(text)
            if not tool_calls:
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
                break
            elif kind == "done":
                break
        return "".join(text_parts), tool_calls, error

    # -- guarded execution -------------------------------------------------
    def _guarded_execute(self, tc: ToolCall) -> str:
        tool = TOOLS.get(tc.name)
        if tool is None:
            self._audit(tc, "deny", [], "unknown tool")
            return f"GUARD DENIED: unknown tool '{tc.name}'"
        verdict = self.guard.check_call(tc.name, tc.args)
        if verdict.decision == "deny":
            self._audit(tc, "deny", verdict.findings,
                        f"denied: {verdict.reason}")
            return (f"GUARD DENIED: {verdict.reason}. Do not attempt to work "
                    f"around this. Explain what you were trying to do and "
                    f"continue safely.")
        if verdict.decision == "needs_approval":
            approved = self._ask_approval(tc, verdict)
            if not approved:
                self._audit(tc, "denied", verdict.findings, "operator denied")
                return ("GUARD: the human operator denied this call. "
                        "Continue with a safer alternative or stop.")
        try:
            raw = tool.run(tc.args, self.ctx)
        except Exception as e:
            raw = f"error: tool execution failed: {e}"
        redacted, _ = sec.redact(raw)
        self._audit(tc, verdict.decision if verdict.decision == "allow" else "approved",
                    verdict.findings, redacted)
        return redacted

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
