"""Live guard: in-process tool-call interceptor.

Every tool call passes through here BEFORE execution:
  allowlist/denylist -> arg-pattern rules -> secret scan -> egress control
  -> severity escalation. Redaction applies at every return boundary
  (args before logging, outputs before the model/audit log ever sees them).

In-process API:
    from aegis import guard
    sess = guard.create_session(policy)
    verdict = sess.check_call("bash", {"cmd": "ls"})
    guard.kill_session(sess.id)   # kill-switch, also honored cross-process
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from . import config
from .audit import AuditLog
from .detect import secrets as sec
from .detect.engine import (
    Finding, SENSITIVE_PATH_RE, chain_indirect_injection_to_secret_use,
    chain_sensitive_read_to_unapproved_exec, pattern_scan, secret_egress,
)
from .kb import KB

EXEC_TOOLS = {"bash", "exec", "shell", "run_command", "terminal"}
WRITE_TOOLS = {"write", "edit"}
NETWORK_TOOLS = {"webfetch", "curl", "http_request", "wget"}
URL_RE = re.compile(r"https?://([^/\s:]+)")

# Plan mode (read-only) denies these at the guard layer — hard deny, not
# a prompt suggestion. Read-only tools (read, kb_query, webfetch,
# scan_trace, respond) stay available.
PLAN_DENIED_TOOLS = WRITE_TOOLS | EXEC_TOOLS

# Primarily-offensive kits: denied outright, always. Dual-use recon/scanner
# tooling (nmap, sqlmap, hydra, …) is NOT blanket-denied — defenders need it
# on their own assets — but stays guard-screened and approval-gated, and the
# operator is responsible for scope. See docs/SCOPE_AND_LIMITS.md.
OFFENSIVE_TOOL_PATTERNS = [
    r"\bmsfconsole\b", r"\bmsfvenom\b", r"\bmsfdb\b", r"\bmsfrpc\b",
    r"\bmimikatz\b", r"\bpypykatz\b", r"\bsekurlsa\b",
    r"\bempire\b", r"\bstarkiller\b",
    r"\bveil\b", r"\bshellter\b",
    r"\bbeef-xss\b", r"\bbeef\b",
    r"\broutersploit\b",
    r"\bautopwn\b",
    r"\bcobalt\s*strike\b",
]

_OFFENSIVE_RES = [re.compile(p, re.IGNORECASE) for p in OFFENSIVE_TOOL_PATTERNS]

# Built-in deny patterns: never allow, regardless of policy.
BUILTIN_DENY_ARG_PATTERNS = [
    r":\(\)\s*\{\s*:\|\:&\s*\}\s*;",          # fork bomb
    r"\brm\s+-rf\s+/(?![\w/])",            # rm -rf / (not /tmp/...)
    r"\bmkfs\b",                              # filesystem format
    r"\bdd\s+.*\bof=/dev/",                   # dd to raw device
    r">\s*/dev/sd[a-z]",                      # raw disk write
    # -- reverse shells / download cradles (unambiguous) -------------------
    r"/dev/tcp/",                              # bash /dev/tcp reverse shell
    r"\bmkfifo\b",                            # named-pipe backpipe shells
    r"\b(nc|ncat|netcat)\b[^|;&]*\s-[a-z]*e\b",  # netcat -e shell
    r"powershell[^|;&]*(IEX|Invoke-Expression)[^|;&]*Net\.WebClient",
    r"\bcertutil\b[^|;&]*-urlcache",          # LOLBin download
    r"\bbitsadmin\b[^|;&]*/transfer",         # LOLBin download
]


class GuardDenied(Exception):
    """Raised when the guard denies a tool call."""


class SessionRevoked(Exception):
    """Raised when the session was killed via the kill-switch."""


@dataclass
class Policy:
    """Guard policy. Everything is deny-by-default where it matters."""
    allowed_tools: set[str] | None = None      # None = all except denied
    denied_tools: set[str] = field(default_factory=set)
    deny_arg_patterns: list[str] = field(default_factory=list)
    egress_allowlist: list[str] | None = None  # None = any egress needs approval
    approval_callback: Callable[[list[Finding]], bool] | None = None
    name: str = "default"
    mode: str = "dev"  # "dev" = full power; "plan" = read-only

    def to_dict(self) -> dict:
        return {
            "allowed_tools": sorted(self.allowed_tools) if self.allowed_tools else None,
            "denied_tools": sorted(self.denied_tools),
            "deny_arg_patterns": self.deny_arg_patterns,
            "egress_allowlist": self.egress_allowlist,
            "name": self.name,
            "mode": self.mode,
        }


@dataclass
class Verdict:
    decision: str  # "allow" | "deny" | "needs_approval"
    findings: list[Finding]
    redacted_args: dict
    reason: str = ""


def _session_path(session_id: str):
    config.ensure_state_dirs()
    return config.sessions_dir() / f"{session_id}.json"


def _read_session_state(session_id: str) -> dict:
    p = _session_path(session_id)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {}


def _write_session_state(session_id: str, state: dict) -> None:
    _session_path(session_id).write_text(json.dumps(state), encoding="utf-8")


def kill_session(session_id: str) -> None:
    """Kill-switch: revoke a session. Honored by every live session object
    and every process on this machine."""
    state = _read_session_state(session_id)
    state.update({"revoked": True, "revoked_at": time.time()})
    _write_session_state(session_id, state)


def is_revoked(session_id: str) -> bool:
    return bool(_read_session_state(session_id).get("revoked"))


class GuardSession:
    def __init__(self, session_id: str, policy: Policy, kb: KB):
        self.id = session_id
        self.policy = policy
        self.kb = kb
        self.audit = AuditLog(session_id)
        self._deny_res = [re.compile(p, re.IGNORECASE)
                          for p in BUILTIN_DENY_ARG_PATTERNS + policy.deny_arg_patterns]
        # Taint tracking: a read of a sensitive path taints the session —
        # any later network-bound call is treated as a potential exfil
        # channel and escalated. _recent_calls is a rolling window of
        # (tool, redacted args, output excerpt) used for LIVE chain
        # detection (previously only available offline via `aegis scan`).
        self._tainted = False
        self._recent_calls: list[dict] = []
        # Preserve an existing kill-switch revocation across re-attachment.
        state = _read_session_state(session_id)
        state.update({"revoked": bool(state.get("revoked", False)),
                      "policy": policy.to_dict(),
                      "created": state.get("created", time.time())})
        _write_session_state(session_id, state)

    def _assert_live(self) -> None:
        if is_revoked(self.id):
            raise SessionRevoked(f"session {self.id} has been kill-switched")

    def note_result(self, tool: str, output_excerpt: str = "") -> None:
        """Record a completed tool call for live chain detection.

        Called by the agent loop after execution with the (already
        redacted) output excerpt. Rolling window of 20; in-memory only.
        """
        self._recent_calls.append({
            "tool": tool, "args": {}, "output": (output_excerpt or "")[:2000],
            "approval": False,
        })
        del self._recent_calls[:-20]

    def _egress_domains(self, args_text: str) -> list[str]:
        return URL_RE.findall(args_text)

    def check_call(self, tool: str, args: dict[str, Any]) -> Verdict:
        """Pre-execution gate. Never executes anything itself."""
        self._assert_live()
        findings: list[Finding] = []
        args_text = json.dumps(args, default=str)
        tool_l = tool.lower()

        # 1. allowlist / denylist
        if tool_l in self.policy.denied_tools:
            return Verdict("deny", findings, {}, f"tool '{tool}' is denied by policy")
        if (self.policy.allowed_tools is not None
                and tool_l not in self.policy.allowed_tools):
            return Verdict("deny", findings, {},
                           f"tool '{tool}' not on the allowlist")

        # 1b. plan mode: read-only, enforced here at the guard layer — a
        # model that "forgets" it is in plan mode still cannot write/execute.
        if self.policy.mode == "plan" and tool_l in PLAN_DENIED_TOOLS:
            return Verdict("deny", findings, {},
                           f"plan mode is read-only: tool '{tool}' is disabled. "
                           f"Describe the change instead, or switch to dev mode.")

        # 1c. primarily-offensive kits are never allowed through the loop.
        for rx in _OFFENSIVE_RES:
            if rx.search(args_text) or rx.search(tool):
                return Verdict("deny", findings, {},
                               "offensive tooling is blocked: Aegis is defensive-only. "
                               "See docs/SCOPE_AND_LIMITS.md for the allowed "
                               "security-tool surface.")

        # 2. arg-pattern deny rules (built-in + policy)
        for rx in self._deny_res:
            m = rx.search(args_text)
            if m:
                return Verdict("deny", findings, {},
                               f"denied arg pattern matched: {m.group(0)[:80]}")

        # 3. KB pattern scan on the call (pre-execution indicators)
        findings.extend(pattern_scan(f"{tool}\n{args_text}", self.kb))

        # 3b. taint tracking: reading a sensitive path taints the session.
        # A later network-bound call from a tainted session is treated as
        # a potential exfil channel and escalated for human approval —
        # even when the payload isn't secret-shaped (encoded exfil).
        if tool_l in ("read", "search", "hash") and SENSITIVE_PATH_RE.search(args_text):
            self._tainted = True
        is_network = tool_l in NETWORK_TOOLS or bool(URL_RE.search(args_text))
        if self._tainted and is_network:
            t = self._kb_best("credential_exfiltration", "exfil")
            findings.append(Finding(
                technique_id=t.id if t else "AEG-POLICY",
                technique_name=t.name if t else "Tainted session egress",
                category=t.category if t else "policy",
                severity="high", rule="guard_taint_escalation",
                evidence=("session previously read a sensitive path; "
                          f"outbound '{tool}' call requires approval"),
                mitigation=(t.mitigations[0] if t and t.mitigations else
                            "Approve the destination or clear the session.")))

        # 3c. live chain detection: injection indicators in an EARLIER
        # call's output followed by a secret-bearing CURRENT call.
        # (Chains were previously only caught offline by `aegis scan`.)
        window = self._recent_calls + [{
            "tool": tool, "args": args, "output": "", "approval": False,
        }]
        try:
            findings.extend(
                chain_indirect_injection_to_secret_use(window, self.kb))
        except Exception:
            pass

        # 4. secret-shaped payload in a network-bound call -> deny outright
        is_network = tool_l in NETWORK_TOOLS or bool(URL_RE.search(args_text))
        secret_hits = sec.find_secrets(args_text)
        secret_refs = sec.find_secret_references(args_text)
        if is_network and (secret_hits or secret_refs or sec.suspicious_token(args_text)):
            t = self._kb_best("credential_exfiltration", "exfil")
            if t:
                findings.append(Finding(
                    technique_id=t.id, technique_name=t.name, category=t.category,
                    severity="critical", rule="guard_secret_egress_block",
                    evidence=("secret-shaped payload in outbound call "
                              f"'{tool}': " +
                              ", ".join(h.kind for h in secret_hits[:3])),
                    mitigation=t.mitigations[0] if t.mitigations else ""))

        # 5. egress domain allowlist
        for domain in self._egress_domains(args_text):
            allowed = self.policy.egress_allowlist
            if allowed is None:
                findings.append(Finding(
                    technique_id="AEG-POLICY", technique_name="Egress approval required",
                    category="policy", severity="high", rule="guard_egress_approval",
                    evidence=f"outbound to {domain} (no egress allowlist configured)",
                    mitigation="Approve the destination or add it to the egress allowlist."))
            elif not any(domain == d or domain.endswith("." + d) for d in allowed):
                return Verdict("deny", findings, {},
                               f"egress to '{domain}' not on allowlist")

        # 6. severity escalation: critical/high -> human approval
        needs_approval = any(f.severity in ("critical", "high") for f in findings)

        # Redact args for logging/display (never log raw secrets).
        redacted_text, _ = sec.redact(args_text)
        try:
            redacted_args: dict = json.loads(redacted_text)
            if not isinstance(redacted_args, dict):
                redacted_args = {"_raw": redacted_text}
        except Exception:
            redacted_args = {"_raw": redacted_text}

        if needs_approval:
            return Verdict("needs_approval", findings, redacted_args,
                           "high-severity match requires human approval")
        return Verdict("allow", findings, redacted_args, "")

    def resolve(self, verdict: Verdict) -> bool:
        """Resolve a needs_approval verdict via the approval callback."""
        if verdict.decision == "allow":
            return True
        if verdict.decision == "deny":
            return False
        cb = self.policy.approval_callback
        if cb is None:
            return False  # no approver configured -> deny by default
        return bool(cb(verdict.findings))

    def _kb_best(self, category: str, *keywords: str):
        cands = self.kb.by_category.get(category, [])
        if not cands:
            return None

        def score(t):
            name = t.name.lower()
            hits = sum(1 for k in keywords if k.lower() in name)
            sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}[t.severity]
            return (-hits, sev, t.id)

        return sorted(cands, key=score)[0]


def create_session(policy: Policy | None = None, kb: KB | None = None,
                   session_id: str | None = None) -> GuardSession:
    kb = kb or KB.load()
    return GuardSession(session_id or uuid.uuid4().hex[:12],
                        policy or Policy(), kb)


def get_session(session_id: str, kb: KB | None = None) -> GuardSession:
    """Re-attach to a session (policy reconstructed as default; revocation
    state is read live from disk)."""
    kb = kb or KB.load()
    return GuardSession(session_id, Policy(), kb)
