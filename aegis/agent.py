"""Agent loop: model-agnostic reasoning loop with the guard INSIDE.

Every tool call the model requests passes through the guard session
(allowlist/denylist, arg patterns, secret scan, egress control, approval
escalation) BEFORE execution. Tool outputs are redacted before the model
or the audit log sees them. This is the dogfood: the agent defends itself
with the same engine it offers others.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Callable

from . import config, guard as guard_mod
from . import planning as planning_mod
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
                 on_tool_end: Callable[[str, str, float, str], None] | None = None,
                 # -- additive v0.7 Lane C reasoning hooks (all default off
                 #    except verify_plans; existing callers unaffected) ------
                 plan_approval_callback: Callable[[dict], bool] | None = None,
                 auto_approve_plans: bool = False,
                 progress_callback: Callable[[dict], None] | None = None,
                 verify_plans: bool = True,
                 verify_max_retries: int = 2,
                 verify_command: str = ""):
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
        # v0.7 Lane C: enforced planning / verification / progress.
        self.plan_approval_callback = plan_approval_callback
        self.auto_approve_plans = auto_approve_plans
        self.progress_callback = progress_callback
        self.verify_plans = verify_plans
        self.verify_max_retries = max(0, verify_max_retries)
        self.verify_command = verify_command or ""
        self.active_plan: planning_mod.TaskPlan | None = None
        self.last_plan: planning_mod.TaskPlan | None = None
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
        # v0.7 Lane C: restore the persisted task plan so /resume keeps it.
        # A plan caught mid-execution is marked interrupted — its pending
        # steps survive and can be re-run, but nothing auto-resumes.
        try:
            pd = session_mod.load_plan(conversation_id)
            self.active_plan = (planning_mod.TaskPlan.from_dict(pd)
                                if pd else None)
            if (self.active_plan is not None
                    and self.active_plan.state == planning_mod.EXECUTING):
                self.active_plan.state = planning_mod.INTERRUPTED
                self.active_plan.note = (
                    "interrupted: session resumed mid-execution; "
                    "re-run the task to continue the pending steps")
                for s in self.active_plan.steps:
                    if s.status == planning_mod.ACTIVE:
                        s.status = planning_mod.PENDING
                self._persist_plan()
        except Exception:
            self.active_plan = None
        return True

    # -- single user turn ------------------------------------------------
    def run(self, user_message: str, plan_first: bool = False) -> str:
        base = list(self.history) if self.history is not None else []
        messages = base + [{"role": "user", "content": user_message}]
        if plan_first:
            result = self._run_plan_first(messages, user_message)
        else:
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

    # -- plan-then-execute ---------------------------------------------------
    # For complex tasks: the model proposes an explicit step plan, the guard
    # screens every step's shape BEFORE anything runs, and only a fully
    # approved plan executes. A denied step aborts the run with an explanation
    # instead of failing halfway through a half-built change.
    _PLAN_PROMPT = (
        "Break the task below into concrete tool steps. Respond with ONLY a "
        "JSON array, no prose, no fences:\n"
        '[{{"tool": "<tool name>", "args": {{<tool args>}}, '
        '"purpose": "<one line on why this step>"}}]\n'
        "Use only these tools: {tools}. Keep args minimal and exact. "
        "Prefer read-only investigation steps before any write or execute "
        "step. Task: {task}"
    )

    def _propose_plan(self, user_message: str):
        """Ask the model for a JSON step plan. Returns (steps, error)."""
        prompt = self._PLAN_PROMPT.format(
            tools=", ".join(sorted(TOOLS)), task=user_message)
        text_parts: list[str] = []
        for kind, payload in self.provider.stream(
                [{"role": "user", "content": prompt}],
                self.tool_specs, self.system):
            if kind == "text":
                text_parts.append(str(payload))
            elif kind == "error":
                return None, str(payload)
            elif kind == "done":
                break
        raw = "".join(text_parts)
        start, end = raw.find("["), raw.rfind("]")
        if start < 0 or end <= start:
            return None, "model did not return a step plan"
        try:
            steps = json.loads(raw[start:end + 1])
        except Exception as e:
            return None, f"unparsable step plan: {e}"
        if not isinstance(steps, list) or not steps:
            return None, "empty step plan"
        clean = []
        for i, s in enumerate(steps):
            if not isinstance(s, dict) or s.get("tool") not in TOOLS:
                return None, f"plan step {i}: unknown tool {s.get('tool')!r}"
            args = s.get("args") or {}
            if not isinstance(args, dict):
                return None, f"plan step {i}: args must be an object"
            clean.append({"tool": s["tool"], "args": args,
                          "purpose": str(s.get("purpose", ""))[:200]})
        return clean, ""

    # -- v0.7 Lane C: enforced plan-then-execute ---------------------------
    def _persist_plan(self) -> None:
        if self.conversation_id and self.active_plan is not None:
            try:
                session_mod.save_plan(self.conversation_id,
                                      self.active_plan.to_dict())
            except Exception:
                pass

    def _approve_plan(self, plan: "planning_mod.TaskPlan") -> bool:
        """Approval gate: no execution starts unapproved.

        REPL wires an interactive prompt; CLI --yes sets auto_approve_plans.
        Library default (no callback): auto-approve, preserving the v0.5
        behavior that existing callers rely on.
        """
        if self.auto_approve_plans:
            return True
        cb = self.plan_approval_callback
        if cb is None:
            self.on_text("[plan-then-execute] no approval callback "
                         "configured — auto-approving (library default).\n")
            return True
        try:
            return bool(cb({"kind": "plan", "plan": plan.to_dict()}))
        except Exception as e:
            self.on_text(f"[plan-then-execute] approval callback failed "
                         f"({e}) — treating as denied.\n")
            return False

    def _check_deviation(self, tc: ToolCall
                     ) -> tuple[str | None, "planning_mod.PlanStep | None"]:
        """Enforce no-deviation while a plan is EXECUTING.

        Returns (block_message, approved_step). A tool call that is not the
        active plan step is blocked unless the approval callback re-approves
        it — the approved call is inserted into the plan as a real step so
        the plan always reflects what ran.
        """
        plan = self.active_plan
        if plan is None:
            return None, None
        report = plan.check_deviation(tc.name)
        if report is None:
            return None, None
        allowed = False
        cb = self.plan_approval_callback
        if cb is not None and not self.auto_approve_plans:
            try:
                allowed = bool(cb(report))
            except Exception:
                allowed = False
        elif self.auto_approve_plans:
            allowed = True
        planning_mod.emit(self.progress_callback, "deviation",
                          plan_id=plan.id, tool=tc.name,
                          expected=report["expected"], approved=allowed)
        if not allowed:
            self._audit(
                tc, "deny", [],
                f"plan deviation blocked: '{tc.name}' is not the active "
                f"plan step (expected '{report['expected']}')")
            return ("PLAN DEVIATION BLOCKED: this call is not part of the "
                    f"approved plan (expected step tool "
                    f"'{report['expected']}', got '{tc.name}'). Nothing was "
                    "executed. Approve an updated plan to proceed."), None
        step = plan.insert_step_after_active(tc.name, tc.args,
                                             "approved mid-run deviation")
        step.status = planning_mod.ACTIVE
        self._persist_plan()
        return None, step

    def _run_verify_command(self, cmd: str) -> tuple[int, str]:
        """Run the plan's verify command, guard-screened first.

        The command comes from operator configuration (CLI flag /
        constructor), never from the model — so an explicit --yes covers
        the approval, an interactive session prompts, and anything else
        fails the check honestly instead of running blind.
        """
        verdict = self.guard.check_call("bash", {"cmd": cmd})
        if verdict.decision == "deny":
            return 126, f"verify command denied by the guard: {verdict.reason}"
        if verdict.decision == "needs_approval":
            approved = (self.auto_approve_plans
                        or self.guard.resolve(verdict))
            if not approved:
                return 126, ("verify command needs operator approval — run "
                             "it yourself; verification cannot auto-pass")
        try:
            r = subprocess.run(cmd, shell=True, cwd=str(self.cwd),
                               timeout=120, capture_output=True, text=True)
            tail = (r.stdout + r.stderr)[-1500:]
            return r.returncode, tail.strip() or "(no output)"
        except subprocess.TimeoutExpired:
            return 124, "verify command timed out after 120s"
        except Exception as e:
            return 127, f"verify runner error: {e}"

    def _execute_plan_step(self, plan: "planning_mod.TaskPlan", index: int,
                           tag: str, messages: list[dict]) -> str:
        """Execute one plan step with status tracking + progress events."""
        step = plan.steps[index]
        plan.mark_step(index, planning_mod.ACTIVE)
        self._persist_plan()
        planning_mod.emit(self.progress_callback, "step", plan_id=plan.id,
                          index=index + 1, total=len(plan.steps),
                          status=planning_mod.ACTIVE, tool=step.tool,
                          label=step.purpose)
        tc = ToolCall(tag, step.tool, step.args)
        result = self._guarded_execute(tc)
        if (result.startswith("GUARD DENIED")
                or result.startswith("PLAN DEVIATION BLOCKED")
                or result.startswith("error:")):
            plan.mark_step(index, planning_mod.FAILED, result[:300])
            status = planning_mod.FAILED
        else:
            plan.mark_step(index, planning_mod.DONE)
            status = planning_mod.DONE
        self._persist_plan()
        planning_mod.emit(self.progress_callback, "step", plan_id=plan.id,
                          index=index + 1, total=len(plan.steps),
                          status=status, tool=step.tool, label=step.purpose)
        messages.append({"role": "tool", "tool_call_id": tc.id,
                         "name": tc.name, "content": result})
        return result

    def _verify_with_retries(self, plan: "planning_mod.TaskPlan",
                             messages: list[dict]) -> "planning_mod.VerificationResult":
        """Verification loop: verify, and on failure re-run failed steps
        (bounded by verify_max_retries) instead of claiming success."""
        attempt = 0
        result = None
        while True:
            attempt += 1
            planning_mod.emit(self.progress_callback, "verify",
                              plan_id=plan.id, status="start", attempt=attempt)
            result = planning_mod.verify_plan(
                plan, self.cwd, self.guard.audit.read_all(),
                run_command=self._run_verify_command)
            planning_mod.emit(
                self.progress_callback, "verify", plan_id=plan.id,
                status="pass" if result.ok else "fail", attempt=attempt,
                checks=result.checks)
            if result.ok or attempt > self.verify_max_retries:
                break
            failed = plan.failed_steps()
            if failed:
                self.on_text(f"[verification] attempt {attempt} failed — "
                             f"re-running {len(failed)} failed step(s).\n")
                for s in failed:
                    self._execute_plan_step(plan, plan.steps.index(s),
                                            f"plan-retry-{attempt}", messages)
            else:
                # No step failed but the checks did (e.g. a flaky test
                # command): re-run the verification pass itself, bounded.
                self.on_text(f"[verification] attempt {attempt} failed — "
                             f"re-checking (attempt {attempt + 1}).\n")
        return result

    def _run_plan_first(self, messages: list[dict], user_message: str) -> str:
        steps, error = self._propose_plan(user_message)
        if error or not steps:
            self.on_text(f"\n[plan-then-execute] planning failed ({error}); "
                         "falling back to a normal turn.\n")
            return self._run_turn(messages)
        plan = planning_mod.TaskPlan(
            user_message,
            [planning_mod.PlanStep(s["tool"], s["args"], s["purpose"])
             for s in steps],
            verify_command=self.verify_command)
        self.active_plan = plan
        self._persist_plan()
        planning_mod.emit(
            self.progress_callback, "plan_proposed", plan_id=plan.id,
            task=user_message,
            steps=[{"tool": s.tool, "purpose": s.purpose}
                   for s in plan.steps])
        # Guard screens the plan's shape before anything executes.
        screened = []
        blocked = False
        self.on_text("\n[plan-then-execute] proposed plan:\n")
        for i, s in enumerate(plan.steps):
            verdict = self.guard.check_call(s.tool, s.args)
            ok = self.guard.resolve(verdict)
            screened.append(ok)
            mark = "✓" if ok else "✗"
            self.on_text(f"  {mark} step {i + 1}: {s.tool} — "
                         f"{s.purpose or '(no purpose given)'} "
                         f"[{verdict.decision}]\n")
            if not ok:
                blocked = True
        plan_note = ("Plan proposed and guard-screened: " +
                     "; ".join(f"step{i + 1} {s.tool}"
                               for i, s in enumerate(plan.steps)))
        messages.append({"role": "assistant",
                         "content": f"[plan-then-execute] {plan_note}"})
        if blocked:
            plan.state = planning_mod.BLOCKED
            plan.note = "a plan step was denied by the guard"
            self._persist_plan()
            planning_mod.emit(self.progress_callback, "plan_blocked",
                              plan_id=plan.id, reason=plan.note)
            self.on_text("[plan-then-execute] plan blocked by the guard — "
                         "nothing executed. Adjust the task and retry.\n")
            self.last_plan = plan
            return ("Plan blocked by the guard; nothing was executed. "
                    "See the per-step verdicts above.")
        # Approval gate: execution cannot start unapproved.
        if not self._approve_plan(plan):
            plan.state = planning_mod.REJECTED
            plan.note = "operator did not approve the plan"
            self._persist_plan()
            planning_mod.emit(self.progress_callback, "plan_rejected",
                              plan_id=plan.id)
            self.on_text("[plan-then-execute] plan not approved — "
                         "nothing executed.\n")
            self.last_plan = plan
            return "Plan not approved; nothing was executed."
        plan.state = planning_mod.APPROVED
        self._persist_plan()
        planning_mod.emit(self.progress_callback, "plan_approved",
                          plan_id=plan.id)
        # Execute approved steps sequentially; each is re-screened live.
        plan.state = planning_mod.EXECUTING
        self._persist_plan()
        planning_mod.emit(self.progress_callback, "task", plan_id=plan.id,
                          status="start", task=plan.task)
        outputs = []
        for i, s in enumerate(plan.steps):
            result = self._execute_plan_step(plan, i, f"plan-{i + 1}",
                                            messages)
            outputs.append(f"--- step {i + 1} ({s.tool}) ---\n{result}")
        self.on_text("[plan-then-execute] all steps executed.\n")
        # Verification loop: check real outcomes before declaring done.
        verified: bool | None = None
        if self.verify_plans:
            vresult = self._verify_with_retries(plan, messages)
            report = vresult.report()
            self.on_text("\n" + report + "\n")
            if vresult.ok:
                plan.state = planning_mod.VERIFIED
            else:
                plan.state = planning_mod.PLAN_FAILED
            plan.note = vresult.summary
            verified = vresult.ok
        else:
            report = "[verification skipped]"
            plan.state = planning_mod.VERIFIED
            plan.note = "verification skipped (verify_plans=False)"
        self._persist_plan()
        planning_mod.emit(self.progress_callback, "task", plan_id=plan.id,
                          status="failed" if verified is False else "done",
                          task=plan.task)
        self.last_plan = plan
        self.active_plan = None
        return "\n\n".join(outputs) + "\n\n" + report

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
        # v0.7 Lane C: while a plan is executing, any tool call outside
        # the approved plan is blocked (or re-approved) before the guard.
        # An approved deviation becomes a real plan step whose outcome is
        # tracked like any other step.
        dev_block, dev_step = self._check_deviation(tc)
        if dev_block is not None:
            return dev_block
        result = self._guarded_execute_inner(tc)
        if dev_step is not None and self.active_plan is not None:
            if (result.startswith("GUARD DENIED")
                    or result.startswith("error:")):
                dev_step.status = planning_mod.FAILED
                dev_step.error = result[:300]
            else:
                dev_step.status = planning_mod.DONE
            self.active_plan.touch()
            self._persist_plan()
        return result

    def _guarded_execute_inner(self, tc: ToolCall) -> str:
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
        # Feed the live chain-detection window (redacted output only).
        try:
            self.guard.note_result(tc.name, redacted)
        except Exception:
            pass
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
