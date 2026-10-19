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
# Egress-capable tools: anything that can move bytes off the box. The
# taint-escalation, secret-egress, and egress-approval logic keys off this
# set — a tool here called from a tainted session or with secret-shaped
# args is treated as a potential exfil channel.
NETWORK_TOOLS = {"webfetch", "curl", "http_request", "wget",
                 "ssh", "scp", "sftp", "rsync", "ftp",
                 "nc", "ncat", "netcat", "telnet",
                 "dig", "nslookup", "host", "ping",
                 "wscat", "mail", "sendmail", "msmtp"}
URL_RE = re.compile(r"(?:https?|wss?|ftp)://([^/\s:]+)")

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


# -- v0.6 round-2: untrusted-content taint ---------------------------------
# A hostile fetch is often "clean" (no secrets, untainted session) — the
# compromise is in the CONTENT THAT STEERED IT: poisoned search results,
# fake vendor patch notes, malicious guides. When an external tool's output
# (webfetch/read/search — never kb_query, which serves our own KB) carries
# trust assertions, imperatives, or tracking constructs around a URL, the
# session is marked injection-tainted; later egress is approval-gated.
# Direct injections in the user's own message taint the same way.

# Tools whose outputs are untrusted external content.
_UNTRUSTED_OUTPUT_TOOLS = {"webfetch", "read", "search", "curl", "wget", "bash"}

_OUTPUT_TAINT_RES = [
    # trust assertion attached to a URL ("official patch: https://evil…")
    re.compile(r"(?i)\b(official|vendor|trusted|legitimate|verified)\b.{0,60}https?://"),
    # imperative steering toward a URL ("fetch the status page: https://…")
    re.compile(r"(?i)\b(fetch|download|run|execute|open|decode|decrypt|register|"
               r"add|configure|apply|visit|click)\b.{0,60}https?://"),
    # markdown tracking image in untrusted content
    re.compile(r"!\[[^\]]*\]\(\s*https?://"),
    # allowlist/trust claim attached to a URL
    re.compile(r"(?i)\b(allowlisted|whitelisted|pre-approved)\b.{0,40}https?://"),
    # classic injection imperatives
    re.compile(r"(?i)\b(ignore|disregard|forget|override)\b.{0,80}"
               r"\b(previous|prior|above|instructions|prompt|guard|policy|safety|rules)\b"),
    re.compile(r"(?i)\b(you are now|from now on|new instructions?)\b"),
    # forged approval / guard-decision claims (in-band, not the callback)
    re.compile(r"(?i)\bguard decision:\s*approved\b"),
    re.compile(r"(?i)\bapproval\s+(granted|bypassed)\b"),
    re.compile(r"(?i)\boperator approval\b"),
    re.compile(r"(?i)\bpre-approved\b"),
    re.compile(r"(?i)\bno approval (needed|required)\b"),
    # allowlist claim without a URL ("Egress to X is now allowlisted")
    re.compile(r"(?i)\b(egress|domain|host|url|traffic|destination|collector)\b.{0,30}"
               r"\b(allowlisted|whitelisted)\b"),
    re.compile(r"(?i)\b(allowlisted|whitelisted)\b.{0,30}\bfor\b.{0,20}\btraffic\b"),
    # decode-then-act steering (base64 blob + "decode me, then fetch …")
    re.compile(r"(?i)\b(decode|decrypt)\b.{0,40}\b(fetch|open|run|execute|apply)\b"),
    # instruction-carrying filename / text: a transfer command glued to a
    # domain ("…curl_evil.example_collect.sh")
    re.compile(r"(?i)(curl|wget).{0,50}[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}\b"),
    # poisoned instruction: "fix: chmod +x helper.sh" — untrusted output
    # prescribing prepare-and-run
    re.compile(r"(?i)\b(fix|finish|complete|run|execute|try|proceed)\b.{0,40}"
               r"\bchmod\s+(\+x|755|777)\b"),
]

# Direct-injection indicators for the user's own message: actual
# subversion signals (ignore-safety-rules, forged approvals, allowlist
# claims) — NOT plain "fetch this URL" phrasing, which is a legitimate
# user request. URL-steering patterns are output-only.
_USER_TAINT_RES = [
    # classic injection imperatives
    re.compile(r"(?i)\b(ignore|disregard|forget|override)\b.{0,80}"
               r"\b(previous|prior|above|instructions|prompt|guard|policy|safety|rules)\b"),
    re.compile(r"(?i)\b(you are now|from now on|new instructions?)\b"),
    # forged approval / guard-decision claims (in-band, not the callback)
    re.compile(r"(?i)\bguard decision:\s*approved\b"),
    re.compile(r"(?i)\bapproval\s+(granted|bypassed)\b"),
    re.compile(r"(?i)\boperator approval\b"),
    re.compile(r"(?i)\bpre-approved\b"),
    re.compile(r"(?i)\bno approval (needed|required)\b"),
    # allowlist claim without a URL ("Egress to X is now allowlisted")
    re.compile(r"(?i)\b(egress|domain|host|url|traffic|destination|collector)\b.{0,30}"
               r"\b(allowlisted|whitelisted)\b"),
    re.compile(r"(?i)\b(allowlisted|whitelisted)\b.{0,30}\bfor\b.{0,20}\btraffic\b"),
]

# Markdown image URLs seen in untrusted outputs: fetching one later is a
# tracking-pixel exfil even when the fetch itself looks clean.
_MD_IMAGE_URL_RE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)")


def _injection_indicators(text: str, patterns) -> bool:
    # Collapse whitespace first: tool outputs are often line-wrapped
    # (read numbers/wraps lines), which would otherwise split an
    # indicator like "Official … https://…" across lines.
    norm = re.sub(r"\s+", " ", text or "")
    return any(rx.search(norm) for rx in patterns)

_DNS_TOOL_RE = re.compile(r"(?i)\b(dig|nslookup|host)\b")


# Network commands invoked THROUGH a shell tool: the tool name is "bash"
# but the payload is a network operation. Without this, `bash -c "nc …"`
# bypasses every network-keyed check.
_EXEC_NET_CMD_RE = re.compile(
    r"(?i)\b(curl|wget|ssh|scp|sftp|rsync|ftp|lftp|nc|ncat|netcat|telnet|"
    r"dig|nslookup|host|ping|ping6|wscat|nmap|tftp|socat|openssl\s+s_client)\b")


def _is_network(tool_l: str, args_text: str) -> bool:
    if tool_l in NETWORK_TOOLS:
        return True
    if URL_RE.search(args_text or ""):
        return True
    if tool_l in EXEC_TOOLS and _EXEC_NET_CMD_RE.search(args_text or ""):
        return True
    return False


def _dns_exfil_hit(args_text: str) -> bool:
    """DNS-shaped exfiltration: a DNS tool carrying a token-like label
    (long mixed-alnum label or hex run) — e.g. `dig <token>.exfil.invalid`.
    Plain lookups (`dig example.com`) do not hit: labels need >=12 chars
    with both letters and digits, or a hex run >= 16."""
    m = _DNS_TOOL_RE.search(args_text or "")
    if not m:
        return False
    for label in re.findall(r"[A-Za-z0-9][A-Za-z0-9_\-]{7,}", args_text[m.end():]):
        if len(label) >= 12 and any(c.isdigit() for c in label) \
                and any(c.isalpha() for c in label):
            return True
        if re.fullmatch(r"[0-9a-fA-F]{16,}", label):
            return True
    return False


_ICMP_EXFIL_RE = re.compile(
    r"(?i)\bping\b[^\n|;&]*-[a-z]*p\b[^\n|;&]*\b[0-9a-fA-F]{8,}\b")


def _icmp_exfil_hit(args_text: str) -> bool:
    """`ping -p <hex>` with a long hex payload: data smuggled in ICMP."""
    return bool(_ICMP_EXFIL_RE.search(args_text or ""))


_SUDO_RE = re.compile(r"(?i)(?:^|[\"'\s;|&])sudo\b")


def _sudo_hit(args_text: str) -> bool:
    return bool(_SUDO_RE.search(args_text or ""))


# T148 (OS command injection) fires on any shell metachar in the agent's OWN
# command — including everyday `ls | head`. The benign-shell filter drops the
# finding when the command is pedestrian on both sides of every metachar AND
# carries no sensitive keywords. `printenv | grep KEY` still fires (printenv
# is not pedestrian); `ls | head -3` does not. Metachars inside quotes don't
# chain — but quoted spans are checked recursively, so `bash -c "curl evil"`
# is still hostile.
_PEDESTRIAN_CMDS = {
    "ls", "dir", "pwd", "whoami", "date", "echo", "cat", "head", "tail",
    "wc", "git", "find", "ps", "df", "du", "uname", "hostname", "id",
    "which", "file", "stat", "sort", "uniq", "cut", "tr", "tee", "less",
    "more", "grep", "egrep", "fgrep", "awk", "sed", "xargs", "basename",
    "dirname", "realpath", "printf", "test", "export", "true", "false",
}
_SENSITIVE_WORD_RE = re.compile(
    r"(?i)\b(printenv|compgen|\benv\b|set\b|secret|password|passwd|token|"
    r"credential|api[_-]?key|\.ssh/|/etc/shadow|history\b|aws[_-])")
_QUOTED_SPAN_RE = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'")


def _segments_benign(text: str) -> bool:
    for segment in re.split(r"&&|\|\||[;|]", text):
        segment = segment.strip()
        if not segment:
            continue
        first = re.split(r"\s+", segment, maxsplit=1)[0].lstrip("(").lower()
        first = first.split("/")[-1]  # /bin/ls -> ls
        if first not in _PEDESTRIAN_CMDS:
            return False
    return True


_SHELL_INTERPRETERS = {"bash", "sh", "dash", "zsh", "powershell", "pwsh", "cmd"}


def _benign_shell_shape(cmd: str) -> bool:
    """True when a shell command has no injection shape: every segment
    (split on shell metachars) starts with a pedestrian command and no
    sensitive keywords appear outside quotes. Quoted spans are opaque
    arguments — EXCEPT for shell interpreters (`bash -c "…"`), whose
    quoted argument IS shell and is checked recursively."""
    if not cmd:
        return False
    outer = _QUOTED_SPAN_RE.sub(" ", cmd)
    if _SENSITIVE_WORD_RE.search(outer):
        return False
    # Redirects into sensitive locations are never benign-shaped.
    redir = re.search(r"(?i)>\s*(\S+)", outer)
    if redir and _SENSITIVE_WORD_RE.search(redir.group(1)):
        return False
    outer_cmd = outer.strip().split()[0].lower().split("/")[-1] \
        if outer.strip() else ""
    if not re.search(r"[;|]|&&|\|\|", outer):
        # No chaining outside quotes. A shell interpreter re-parses its
        # -c argument, so check the quoted spans as shell too.
        if outer_cmd in _SHELL_INTERPRETERS:
            return all(_segments_benign(m.group(0)[1:-1])
                       for m in _QUOTED_SPAN_RE.finditer(cmd))
        return True
    inner_ok = True
    if outer_cmd in _SHELL_INTERPRETERS:
        inner_ok = all(_segments_benign(m.group(0)[1:-1])
                       for m in _QUOTED_SPAN_RE.finditer(cmd))
    return inner_ok and _segments_benign(outer)


# Bare-mention findings on defensive kb_query lookups: asking "how do I
# detect SQL injection" is defense, not attack. kb_query is a local
# read-only search — the mention alone cannot do anything hostile — so
# these technique IDs are dropped on kb_query unless a REAL attack pattern
# from the same technique also fires (handled by keeping the finding when
# any non-mention evidence exists; the mention-only case is the FP).
_DEFENSIVE_MENTION_IDS = {"AEG-T114", "AEG-T139", "AEG-T151", "AEG-T184"}
_DEFENSIVE_INTENT_RE = re.compile(
    r"(?i)\b(how (do|can|should) (i|we)|what (is|are)|explain|tell me about|"
    r"detect|prevent|defend|mitigate|investigat|identif|signs|indicators|"
    r"protect|difference between)\b")


def _defensive_mention_drop(tool_l: str, args_text: str, findings: list) -> list:
    if tool_l != "kb_query" or not _DEFENSIVE_INTENT_RE.search(args_text or ""):
        return findings
    return [f for f in findings
            if f.technique_id not in _DEFENSIVE_MENTION_IDS]


# T018 (poisoned search) / T053 (startup-script mod) patterns match the
# bare words `curl`/`wget` — i.e. the agent's OWN fetch command, not
# evidence of poisoning. Keep them only when corroborating risk exists
# (tainted session, secrets, injection taint); otherwise they're noise
# on every benign download.
_FETCH_NOISE_IDS = {"AEG-T018", "AEG-T053"}


def _fetch_noise_drop(tool_l, args_text, findings, risky):
    # Only for fetch-like actions: T053 (startup-script modification) is a
    # legitimate signal on write/edit (persistence), and must not be
    # dropped there.
    fetch_like = (
        tool_l in {"curl", "wget", "webfetch", "http_request"}
        or (tool_l in EXEC_TOOLS and re.search(
            r"(?i)\b(curl|wget)\b", args_text or ""))
    )
    if risky or not fetch_like:
        return findings
    return [f for f in findings if f.technique_id not in _FETCH_NOISE_IDS]


# T028 (prompt-injection-driven secret disclosure) fires on
# `print...token` — including LOCAL token generation, which is benign.
_TOKEN_GEN_RE = re.compile(
    r"(?i)(secrets\.token|uuidgen|openssl\s+rand|New-Guid|random\.uuid)")


def _token_gen_drop(args_text: str, findings: list) -> list:
    if not _TOKEN_GEN_RE.search(args_text or ""):
        return findings
    return [f for f in findings if f.technique_id != "AEG-T028"]


# Secret-shaped content the USER explicitly pasted (verbatim in the user
# message) may be written to local files by the agent — it is the user's own
# test data, not staged loot. Tainted sessions never qualify.
_USER_SUPPLIED_WRITE_IDS = {"AEG-T025", "AEG-T032", "AEG-T065"}


def _user_supplied_secrets(args_text: str, user_message: str) -> bool:
    if not user_message:
        return False
    hits = sec.find_secrets(args_text or "")
    if not hits:
        return False
    return all(h.value and h.value in user_message for h in hits)

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
    # -- guard self-protection (the agent must not disable its own guard) --
    r"--(no[-_]?guard|disable[-_]?guard)\b",  # --no-guard flags
    r"(?i)\bAEGIS_GUARD\s*=\s*(off|false|0|no)\b",  # env-based guard disable
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
        # The user's own message, for the user-supplied-secret carve-out:
        # the agent may persist secret-shaped data the user explicitly
        # pasted (their own test fixtures); never data obtained from tools.
        self._user_message = ""
        # Injection taint: the session was steered by untrusted content
        # (direct injection in the user message, or trust/imperative
        # constructs in an external tool's output). Later egress is gated.
        self._injection_tainted = False
        # Staged files: local paths the agent wrote this session. A later
        # network call referencing a staged file is the classic
        # stage-then-exfiltrate chain.
        self._staged_files: set[str] = set()
        # Files made executable this session (chmod +x). Executing one
        # from an injection-tainted session is the "prepare and run
        # payload" pattern.
        self._chmodded: set[str] = set()
        # Markdown image URLs seen in untrusted outputs (tracking pixels).
        self._untrusted_image_urls: set[str] = set()
        # Egress hosts seen this session (distillation/volume heuristic).
        self._egress_hosts: list[str] = []
        # Preserve an existing kill-switch revocation across re-attachment.
        state = _read_session_state(session_id)
        state.update({"revoked": bool(state.get("revoked", False)),
                      "policy": policy.to_dict(),
                      "created": state.get("created", time.time())})
        _write_session_state(session_id, state)

    def _assert_live(self) -> None:
        if is_revoked(self.id):
            raise SessionRevoked(f"session {self.id} has been kill-switched")

    def note_user_message(self, message: str) -> None:
        """Record the user's own message for this turn (carve-outs only).

        A direct injection in the user message (ignore-safety-rules,
        forged guard approvals, …) injection-taints the session: later
        egress is approval-gated even when the payload looks clean.
        """
        self._user_message = message or ""
        if _injection_indicators(self._user_message, _USER_TAINT_RES):
            self._injection_tainted = True

    def note_result(self, tool: str, output_excerpt: str = "") -> None:
        """Record a completed tool call for live chain detection.

        Called by the agent loop after execution with the (already
        redacted) output excerpt. Rolling window of 20; in-memory only.
        Outputs of external-content tools are scanned for untrusted-
        content taint (trust assertions / imperatives around URLs).
        """
        self._recent_calls.append({
            "tool": tool, "args": {}, "output": (output_excerpt or "")[:2000],
            "approval": False,
        })
        del self._recent_calls[:-20]
        if tool.lower() in _UNTRUSTED_OUTPUT_TOOLS and output_excerpt:
            if _injection_indicators(output_excerpt, _OUTPUT_TAINT_RES):
                self._injection_tainted = True
            for m in _MD_IMAGE_URL_RE.finditer(output_excerpt):
                self._untrusted_image_urls.add(m.group(1))

    def _egress_domains(self, args_text: str) -> list[str]:
        return URL_RE.findall(args_text)

    def _email_domains(self, args_text: str) -> list[str]:
        # Bare email recipients (mail/sendmail clients): the domain is an
        # egress destination even without a URL.
        return re.findall(r"[\w.+\-]+@([\w.\-]+\.\w+)", args_text or "")

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

        # 1d. guard self-protection + privilege boundary (v0.6 gap-fill).
        if tool_l in WRITE_TOOLS:
            if re.search(r"(?i)\bpolicy\.json\b", args_text) and re.search(
                    r'(?i)\\?"(audit|enforce|egress)\\?"\s*:\s*false', args_text):
                return Verdict("deny", findings, {},
                               "denied: weakening the guard's own policy "
                               "(audit/enforcement disable) is never allowed.")
            if re.search(r"(?i)authorized_keys", args_text):
                return Verdict("deny", findings, {},
                               "denied: writing authorized_keys (SSH "
                               "persistence) requires out-of-band approval.")
            # Prompt-disclosure writes: the agent must not dump its system prompt.
            if re.search(r"(?i)\b(full|entire|complete) system prompt\b", args_text):
                findings.append(Finding(
                    technique_id="AEG-T006", technique_name="System-Prompt Extraction Attempts",
                    category="prompt_injection",
                    severity="high", rule="guard_prompt_disclosure",
                    evidence="write/edit of system-prompt content",
                    mitigation="Do not persist or transmit the system prompt."))
        if tool_l in EXEC_TOOLS:
            if re.search(r"(?i)\bchmod\b[^\n|;&]*(?:[0-7]*[475][0-9]{2}\b|[ug]*\+s\b)",
                         args_text):
                return Verdict("deny", findings, {},
                               "denied: setuid/setgid bit manipulation "
                               "(privilege-escalation primitive).")
            if _sudo_hit(args_text):
                findings.append(Finding(
                    technique_id="AEG-T065", technique_name="Secrets and Sudo Tokens Present in Agent Context",
                    category="privilege_escalation",
                    severity="high", rule="guard_sudo_approval",
                    evidence=f"sudo invocation in '{tool}' requires human approval",
                    mitigation="Approve the privileged command or run it yourself."))
            # PATH hijack: attacker-controlled dirs prepended to PATH.
            m = re.search(r"(?i)\bPATH=([\"\']?)(\S+)\1", args_text)
            if m and any(seg in (".", "") or seg.startswith("/tmp/")
                         for seg in m.group(2).split(":")):
                findings.append(Finding(
                    technique_id="AEG-T068", technique_name="PATH Hijacking in Agent Toolchains",
                    category="persistence",
                    severity="high", rule="guard_path_hijack",
                    evidence="PATH prepends attacker-writable directory",
                    mitigation="Use absolute binary paths; never prepend . or /tmp to PATH."))

        # 2. arg-pattern deny rules (built-in + policy). Also matched
        # against the escape-decoded form so obfuscated payloads
        # (octal/hex) can't smuggle past the deny list.
        decoded_text = sec.decode_escapes(args_text)
        for rx in self._deny_res:
            m = rx.search(args_text) or (rx.search(decoded_text)
                                         if decoded_text != args_text else None)
            if m:
                return Verdict("deny", findings, {},
                               f"denied arg pattern matched: {m.group(0)[:80]}")

        # 3. KB pattern scan on the call (pre-execution indicators)
        findings.extend(pattern_scan(f"{tool}\n{args_text}", self.kb))
        # 3a. false-positive filters (v0.6 gap-fill): narrow overbroad
        # patterns without touching the KB packs themselves.
        findings = _defensive_mention_drop(tool_l, args_text, findings)
        findings = _token_gen_drop(args_text, findings)
        _risky_ctx = (self._tainted or self._injection_tainted
                      or bool(sec.find_secrets(args_text)))
        findings = _fetch_noise_drop(tool_l, args_text, findings, _risky_ctx)
        if tool_l in EXEC_TOOLS:
            cmd = args.get("cmd", "") if isinstance(args, dict) else ""
            if _benign_shell_shape(str(cmd)):
                findings = [f for f in findings
                            if f.technique_id != "AEG-T148"]
        # User-supplied secrets: the agent may persist secret-shaped data
        # the user explicitly pasted (verbatim in the user message) to a
        # local file — its own test fixtures. Never from a tainted session.
        if (tool_l in WRITE_TOOLS and not self._tainted
                and _user_supplied_secrets(args_text, self._user_message)):
            findings = [f for f in findings
                        if f.technique_id not in _USER_SUPPLIED_WRITE_IDS]

        # 3b. taint tracking: reading a sensitive path taints the session.
        # Shell equivalents of read (cat/grep of key material, /proc/self/
        # environ, history) and bulk env enumeration taint too — the guard
        # tracks what the agent SAW, not which tool it used.
        if ((tool_l in ("read", "search", "hash") or tool_l in EXEC_TOOLS)
                and SENSITIVE_PATH_RE.search(args_text)):
            self._tainted = True
        if tool_l in EXEC_TOOLS and re.search(
                r'(?i)(?:["\s;|&])(compgen\s+-v|printenv|env|set)\b',
                args_text):
            self._tainted = True
        # DNS / ICMP exfiltration channels (non-HTTP egress).
        if _dns_exfil_hit(args_text):
            t = self._kb_best("egress_exfiltration", "dns", "exfiltration")
            findings.append(Finding(
                technique_id=t.id if t else "AEG-POLICY",
                technique_name=t.name if t else "DNS exfiltration",
                category=t.category if t else "egress_exfiltration",
                severity="critical", rule="guard_dns_exfil",
                evidence="DNS tool carrying token-like label (possible DNS exfiltration)",
                mitigation=(t.mitigations[0] if t and t.mitigations else
                            "Block DNS exfiltration; inspect resolver logs.")))
        if _icmp_exfil_hit(args_text):
            t = self._kb_best("egress_exfiltration", "icmp", "covert")
            findings.append(Finding(
                technique_id=t.id if t else "AEG-POLICY",
                technique_name=t.name if t else "ICMP exfiltration",
                category=t.category if t else "egress_exfiltration",
                severity="high", rule="guard_icmp_exfil",
                evidence="ping -p carrying long hex payload (possible ICMP exfiltration)",
                mitigation=(t.mitigations[0] if t and t.mitigations else
                            "Inspect ICMP payloads at the egress filter.")))
        # Covert channel: hex-looking subdomain labels (data smuggled in DNS).
        for domain in self._egress_domains(args_text):
            for label in domain.split("."):
                if re.fullmatch(r"[0-9a-fA-F]{16,}", label):
                    t = self._kb_best("egress_exfiltration", "dns", "covert")
                    findings.append(Finding(
                        technique_id=t.id if t else "AEG-POLICY",
                        technique_name=t.name if t else "Covert DNS channel",
                        category=t.category if t else "egress_exfiltration",
                        severity="critical", rule="guard_dns_covert_label",
                        evidence=f"hex-like subdomain label in {domain}",
                        mitigation=(t.mitigations[0] if t and t.mitigations else
                                    "Inspect DNS labels for encoded data.")))
                    break
        # Model-extraction probing: repeated query-style calls to an
        # extract/distill endpoint (distillation-style attacks).
        if re.search(r"(?i)/(extract|distill)(?:\b|_)", args_text) and re.search(
                r"[?&](q|query|prompt)=", args_text):
            t = self._kb_best("llm_model_attacks", "extraction", "distillation")
            findings.append(Finding(
                technique_id=t.id if t else "AEG-POLICY",
                technique_name=t.name if t else "Model extraction probing",
                category=t.category if t else "llm_model_attacks",
                severity="high", rule="guard_extraction_probe",
                evidence="query-style calls to a model extract/distill endpoint",
                mitigation=(t.mitigations[0] if t and t.mitigations else
                            "Rate-limit and audit model endpoint extraction queries.")))
        # Staged-file tracking: remember local writes; a later network call
        # referencing a staged file is the stage-then-exfiltrate chain.
        if tool_l in WRITE_TOOLS and isinstance(args, dict):
            p = str(args.get("path", ""))
            if p:
                base = p.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
                if len(base) >= 3:
                    self._staged_files.add(base.lower())
        is_network_pre = _is_network(tool_l, args_text)
        if is_network_pre and self._staged_files:
            low = args_text.lower()
            staged = [s for s in self._staged_files if s in low]
            if staged:
                t = self._kb_best("credential_exfiltration", "exfil")
                findings.append(Finding(
                    technique_id=t.id if t else "AEG-POLICY",
                    technique_name=t.name if t else "Staged-file exfiltration",
                    category=t.category if t else "credential_exfiltration",
                    severity="high", rule="guard_staged_upload",
                    evidence=f"network call references staged file(s): {', '.join(staged)}",
                    mitigation=(t.mitigations[0] if t and t.mitigations else
                                "Verify the upload destination before approving.")))
        # Tracking-pixel fetch: URL previously seen as a markdown image in
        # untrusted content.
        if is_network_pre and self._untrusted_image_urls:
            if any(u in args_text for u in self._untrusted_image_urls):
                findings.append(Finding(
                    technique_id="AEG-T042", technique_name="Covert Channels Inside Legitimate Traffic",
                    category="egress_exfiltration",
                    severity="high", rule="guard_tracking_pixel",
                    evidence="fetching a tracking-pixel URL seen in untrusted content",
                    mitigation="Do not fetch tracking pixels from untrusted sources."))
        # Off-host file transfer / remote shell target (scp/rsync/ssh
        # user@host:path) — the classic non-HTTP exfil vector.
        if re.search(r"\b\w+@[A-Za-z0-9.\-]+\s*:", args_text):
            findings.append(Finding(
                technique_id="AEG-POLICY", technique_name="Off-host transfer target",
                category="policy",
                severity="high", rule="guard_remote_target",
                evidence="off-host transfer target (user@host:path)",
                mitigation="Approve the remote destination explicitly."))
        # Raw/covert channels: netcat-class tools, websockets, and legacy
        # file-transfer clients to a remote host (no URL needed).
        if tool_l in EXEC_TOOLS and re.search(
                r"(?i)\b(nc|ncat|netcat|wscat|telnet|socat|ftp|sftp|lftp)\b\s+"
                r"(?!.*localhost)(?!127\.0\.0\.1)\S+",
                args_text):
            findings.append(Finding(
                technique_id="AEG-T047", technique_name="WebSocket Exfiltration Channels",
                category="egress_exfiltration",
                severity="high", rule="guard_raw_channel",
                evidence="raw network channel to a remote host",
                mitigation="Use approved transfer mechanisms; inspect the payload."))
        # Private key material / process environment / shell history via
        # shell (theft recon — T1003/T1552/T1056 class). History covers
        # ~/.bash_history and decoy names like shell_history.txt, but not
        # the bare word in prose.
        if tool_l in EXEC_TOOLS and re.search(
                r"(?i)(id_rsa|\.pem\b|/proc/self/environ|(?:/|\.)\w*history|history\.\w+)",
                args_text):
            findings.append(Finding(
                technique_id="AEG-T065", technique_name="Secrets and Sudo Tokens Present in Agent Context",
                category="privilege_escalation",
                severity="high", rule="guard_key_material_shell",
                evidence="shell access to private key material or process environment",
                mitigation="Use the read tool (taint-tracked); never pipe key material."))
        # Bulk environment enumeration with no arguments (recon). Targeted
        # reads like `printenv PATH` are legitimate and stay allowed.
        if tool_l in EXEC_TOOLS and re.search(
                r'(?i)(?:["\s;|&]|^)(compgen\s+-v|printenv|env|set)(?!\s+[A-Za-z_])',
                args_text):
            findings.append(Finding(
                technique_id="AEG-POLICY", technique_name="Bulk environment enumeration",
                category="policy",
                severity="high", rule="guard_env_enumeration",
                evidence="bulk environment enumeration (no arguments)",
                mitigation="Read specific variables instead of dumping the environment."))
        # Uploading a sensitive-path file (--data-binary @secrets.dat):
        # the bytes leave the box even though no secret shape is in args.
        if tool_l in EXEC_TOOLS and re.search(
                r"(?i)(--data-binary|--data|--upload-file|-d)\s+@?\S*",
                args_text) and SENSITIVE_PATH_RE.search(args_text):
            findings.append(Finding(
                technique_id="AEG-T039", technique_name="Clipboard and File-Write Staging Before Exfiltration",
                category="egress_exfiltration",
                severity="high", rule="guard_sensitive_upload",
                evidence="upload flag referencing a sensitive-path file",
                mitigation="Verify the file contents and destination before approving."))
        # Clipboard theft: pulling the clipboard in a secret-tainted
        # session (xclip/xsel/pbcopy) — clipboard scraping after key
        # material was in context.
        if tool_l in EXEC_TOOLS and self._tainted and re.search(
                r"(?i)\b(xclip|xsel|pbcopy|clip\.exe)\b", args_text):
            findings.append(Finding(
                technique_id="AEG-T039", technique_name="Clipboard and File-Write Staging Before Exfiltration",
                category="egress_exfiltration",
                severity="high", rule="guard_clipboard_theft",
                evidence="clipboard pull in a secret-tainted session",
                mitigation="Inspect what the clipboard holds before approving."))
        # Clipboard pull, untainted: reading the clipboard (xclip -o /
        # xsel -o / pbpaste) is a credential-theft primitive — the
        # clipboard is a known secret store. Gate it regardless of taint.
        if tool_l in EXEC_TOOLS and re.search(
                r"(?i)\b(xclip\s+[^|]*-o|xsel\s+[^|]*-o|pbpaste)\b",
                args_text):
            findings.append(Finding(
                technique_id="AEG-T039", technique_name="Clipboard and File-Write Staging Before Exfiltration",
                category="egress_exfiltration",
                severity="high", rule="guard_clipboard_pull",
                evidence="clipboard read via xclip/xsel/pbpaste",
                mitigation="Confirm the clipboard access is expected before approving."))
        # Track chmod +x (prepare). From an injection-tainted session it
        # is the steered "prepare" step — deny it, breaking the
        # prepare-and-run chain at the prepare hop.
        if tool_l in EXEC_TOOLS:
            for _cm in re.finditer(r"(?i)chmod\s+(?:[ugo]*\+x|755|777)\s+([^\s\"}]+)",
                                  args_text):
                self._chmodded.add(_cm.group(1).lstrip("./"))
                if self._injection_tainted:
                    findings.append(Finding(
                        technique_id="AEG-T002", technique_name="Indirect Prompt Injection via Tool Output",
                        category="prompt_injection",
                        severity="high", rule="guard_steered_prepare",
                        evidence="steered chmod +x (prepare step) from tainted session",
                        mitigation="Verify who instructed this and inspect the file before approving."))
                    break
        # Steered execution: a file made executable this session, run from
        # an injection-tainted session — the "prepare and run payload"
        # pattern (poisoned error/output steers chmod +x then ./run).
        if tool_l in EXEC_TOOLS and self._injection_tainted and self._chmodded:
            _execd = re.search(r"(?i)(?:\./|bash\s+|sh\s+)([^\s\"}]+\.sh)",
                               args_text)
            if _execd and _execd.group(1).lstrip("./") in self._chmodded:
                findings.append(Finding(
                    technique_id="AEG-T002", technique_name="Indirect Prompt Injection via Tool Output",
                    category="prompt_injection",
                    severity="high", rule="guard_steered_execution",
                    evidence="steered execution of a file prepared (chmod +x) this session",
                    mitigation="Verify the file's provenance and contents before approving."))
        # Raw socket egress via scripting languages (python socket.connect
        # / create_connection) — the non-shell equivalent of netcat.
        if tool_l in EXEC_TOOLS and re.search(
                r"(?i)\bsocket\b.{0,40}\b(connect|create_connection|sendall|sendto)\b",
                args_text):
            findings.append(Finding(
                technique_id="AEG-T047", technique_name="WebSocket Exfiltration Channels",
                category="egress_exfiltration",
                severity="high", rule="guard_raw_socket",
                evidence="raw socket connection from a scripting language",
                mitigation="Use approved transfer mechanisms; inspect the payload."))
        # Obfuscated command construction (octal/hex escape runs in shell).
        if tool_l in EXEC_TOOLS and re.search(
                r"(\\\\[0-7]{3}|\\\\x[0-9a-fA-F]{2}){3,}", args_text):
            findings.append(Finding(
                technique_id="AEG-T095", technique_name="Encoding Tricks",
                category="evasion",
                severity="high", rule="guard_obfuscated_command",
                evidence="shell command built from octal/hex escapes (obfuscation)",
                mitigation="Use plain commands; obfuscation requires approval."))
        # Secret-shaped content in file writes (staging), incl. reversed
        # and escape-encoded forms. The user-supplied carve-out (their own
        # pasted test data, untainted session) still applies.
        if tool_l in WRITE_TOOLS:
            write_secret = (sec.find_secrets(args_text)
                            + sec.find_encoded_secrets(args_text)
                            + sec.find_secrets(args_text[::-1]))
            user_ok = (not self._tainted
                       and _user_supplied_secrets(args_text, self._user_message))
            if write_secret and not user_ok:
                t = self._kb_best("credential_exfiltration", "exfil")
                findings.append(Finding(
                    technique_id=t.id if t else "AEG-POLICY",
                    technique_name=t.name if t else "Secret-shaped file write",
                    category=t.category if t else "credential_exfiltration",
                    severity="high", rule="guard_secret_write",
                    evidence=("secret-shaped content in a local file write "
                              "(possible staging): "
                              + ", ".join(h.kind for h in write_secret[:3])),
                    mitigation=(t.mitigations[0] if t and t.mitigations else
                                "Do not persist secrets to files; use a vault.")))
        is_network = _is_network(tool_l, args_text)
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

        # 4. secret-shaped payload in a network-bound call -> deny outright.
        # Escape-encoded payloads (\ooo, \xhh) are decoded first so
        # obfuscated exfiltration can't slip past the scan.
        is_network = _is_network(tool_l, args_text)
        secret_hits = sec.find_secrets(args_text) + sec.find_encoded_secrets(args_text)
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

        # 5. egress domain allowlist. Default posture (allowlist None) gates
        # only RISKY egress — secret-shaped, tainted, or sensitive-path
        # related. Clean egress (docs fetches, no secrets, untainted) is
        # allowed with a low-visibility finding: a guard that blocks all
        # benign web use is unusable. An explicit allowlist still hard-denies
        # anything off-list.
        # Mail-client commands inside a shell count as mail egress too
        # (tool_l is "bash", not "mail").
        _mail_cmd = bool(re.search(r"(?i)\b(mail|sendmail|msmtp|mutt)\b",
                                  args_text)) if tool_l in EXEC_TOOLS else False
        risky_egress = (bool(secret_hits) or bool(secret_refs)
                        or self._tainted or self._injection_tainted
                        or tool_l in {"mail", "sendmail", "msmtp"}
                        or _mail_cmd
                        or bool(SENSITIVE_PATH_RE.search(args_text)))
        for domain in self._egress_domains(args_text) + self._email_domains(args_text):
            allowed = self.policy.egress_allowlist
            if allowed is None:
                if risky_egress:
                    findings.append(Finding(
                        technique_id="AEG-POLICY", technique_name="Egress approval required",
                        category="policy", severity="high", rule="guard_egress_approval",
                        evidence=f"risky outbound to {domain} (no egress allowlist configured)",
                        mitigation="Approve the destination or add it to the egress allowlist."))
                else:
                    findings.append(Finding(
                        technique_id="AEG-POLICY", technique_name="Egress observed",
                        category="policy", severity="low", rule="guard_egress_observed",
                        evidence=f"clean outbound to {domain}",
                        mitigation="No action needed."))
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
