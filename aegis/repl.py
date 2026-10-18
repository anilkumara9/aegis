"""Interactive REPL: `aegis` — the terminal agent."""

from __future__ import annotations

import sys
from pathlib import Path

from . import config, guard as guard_mod
from .agent import AgentLoop
from .guard import Policy
from .kb import KB
from .providers import get_provider
from .skills import SKILLS, hunt
from .tools.registry import TOOL_NAMES

BANNER = r"""
    _    _____ ____ ___ ____
   / \  | ____/ ___|_ _/ ___|
  / _ \ |  _|| |  _ | |\___ \
 / ___ \| |__| |_| || | ___) |
/_/   \_\_____\____|___|____/   defensive guard agent v0.1.0

Deep hacking knowledge, pointed entirely at defense.
Type /help for skills. Every tool call is guard-screened and audit-logged.
"""


def interactive_approval(findings, tool="", args=None) -> bool:
    print("\n[!] GUARD: high-severity match — human approval required")
    print(f"    tool: {tool}")
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else f
        print(f"    [{d.get('severity', '?').upper()}] "
              f"{d.get('technique_id', '?')} {d.get('technique_name', '?')}")
        print(f"      evidence: {str(d.get('evidence', ''))[:200]}")
    try:
        ans = input("    Approve this call? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = "n"
    return ans == "y"


def run_repl(provider_name: str = "", model: str = "") -> int:
    kb = KB.load()
    try:
        provider = get_provider(provider_name, model)
    except ValueError as e:
        print(f"error: {e}")
        print("Set AEGIS_PROVIDER=mock for offline mode, or export "
              "ANTHROPIC_API_KEY / OPENAI_API_KEY.")
        return 2
    policy = Policy(allowed_tools=set(TOOL_NAMES),
                    approval_callback=interactive_approval,
                    egress_allowlist=None,  # any egress pauses for approval
                    name="repl")
    session = guard_mod.create_session(policy, kb)
    loop = AgentLoop(provider, kb, session, cwd=Path.cwd(),
                     approval_callback=interactive_approval,
                     on_text=lambda s: (sys.stdout.write(s), sys.stdout.flush()))
    print(BANNER)
    print(f"provider: {provider.name}  model: {getattr(provider, 'model', '?')}")
    print(f"session: {session.id}  audit: {session.audit.path}")
    print(f"KB: {kb.count()} techniques across {len(kb.packs())} packs\n")

    while True:
        try:
            line = input("aegis> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nbye.")
            break
        if not line:
            continue
        if line.startswith("/"):
            if _handle_slash(line, loop, session, kb):
                break
            continue
        print()
        try:
            loop.run(line)
        except guard_mod.SessionRevoked as e:
            print(f"\n[!] {e}\nSession killed. Restart aegis for a new session.")
            break
        except Exception as e:
            print(f"\n[agent error: {e}]")
        print()
    return 0


def _handle_slash(line: str, loop: AgentLoop,
                  session: guard_mod.GuardSession, kb: KB) -> bool:
    """Returns True to exit the REPL."""
    parts = line.split(None, 1)
    cmd, rest = parts[0].lower(), (parts[1] if len(parts) > 1 else "")
    if cmd in ("/exit", "/quit"):
        print("bye.")
        return True
    if cmd == "/help":
        for k, v in SKILLS.items():
            print(f"  {k:10s} {v}")
        return False
    if cmd == "/kb":
        if not rest:
            print("usage: /kb <query>")
        else:
            from .tools.knowledge import KBQueryTool
            from .tools import ToolContext
            print(KBQueryTool().run(
                {"query": rest},
                ToolContext(session, kb, Path.cwd())))
        return False
    if cmd == "/scan":
        if not rest:
            print("usage: /scan <trace.jsonl>")
        else:
            from .scan import scan_file
            try:
                scan_file(rest, kb)
            except Exception as e:
                print(f"error: {e}")
        return False
    if cmd == "/respond":
        if not rest:
            print("usage: /respond <playbook> [detail]")
        else:
            from .respond.playbooks import PLAYBOOKS, run_playbook
            from .tools import ToolContext
            pb, _, detail = rest.partition(" ")
            if pb not in PLAYBOOKS:
                print(f"unknown playbook. Choose from: {', '.join(PLAYBOOKS)}")
            else:
                print(run_playbook(pb, ToolContext(session, kb, Path.cwd()),
                                   detail))
        return False
    if cmd == "/hunt":
        print(hunt(rest, kb))
        return False
    if cmd == "/guard":
        sub = (rest or "status").lower()
        if sub == "kill":
            guard_mod.kill_session(session.id)
            print(f"session {session.id} revoked. Exiting.")
            return True
        print(f"session: {session.id}")
        print(f"policy: {session.policy.name} "
              f"(tools: {len(session.policy.allowed_tools or [])} allowed)")
        print(f"revoked: {guard_mod.is_revoked(session.id)}")
        print(f"audit log: {session.audit.path}")
        return False
    print(f"unknown command '{cmd}'. /help for skills.")
    return False
