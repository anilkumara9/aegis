"""Interactive REPL: `aegis` — the terminal agent."""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

from . import __version__, config, guard as guard_mod
from . import session as session_mod
from . import tui
from .agent import AgentLoop
from .guard import Policy
from .kb import KB
from .providers import get_provider
from .skills import SKILLS, build, emulate, fix, hunt, index_cmd, \
    plan_attack_surface, refactor, repomap_cmd, test_suite
from .tools import safe_path
from .tools.registry import TOOL_NAMES

BANNER = r"""
    _    _____ ____ ___ ____
   / \  | ____/ ___|_ _/ ___|
  / _ \ |  _|| |  _ | |\___ \
 / ___ \| |__| |_| || | ___) |
/_/   \_\_____\____|___|____/   defensive guard agent v{__version__}

Deep hacking knowledge, pointed entirely at defense.
Type /help for skills. Every tool call is guard-screened and audit-logged.
"""


def interactive_approval(findings, tool="", args=None, cwd=None) -> bool:
    print("\n[!] GUARD: high-severity match — human approval required")
    print(f"    tool: {tool}")
    # File modifications: show the operator a unified diff BEFORE the prompt.
    if cwd is not None and isinstance(args, dict) and tool in ("write", "edit"):
        try:
            from . import diffx
            if tool == "write" and "path" in args:
                print(diffx.diff_for_write(args.get("path", ""),
                                          args.get("content", ""), Path(cwd)))
            elif tool == "edit" and "path" in args:
                print(diffx.diff_for_edit(args.get("path", ""),
                                          args.get("old_text", ""),
                                          args.get("new_text", ""), Path(cwd)))
        except Exception as e:
            print(f"    (diff preview unavailable: {e})")
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


# -- tool-call display blocks -------------------------------------------
def _print_tool_start(name: str, args_summary: str) -> None:
    print(f"\n{tui.cyan('⏺')} {tui.bold(name)}({tui.dim(args_summary)})",
          flush=True)


def _print_tool_end(name: str, verdict: str, duration_ms: float,
                    output_excerpt: str) -> None:
    ms = f"{duration_ms:.0f}"
    if verdict in ("allow", "approved"):
        print(tui.green(f"✓ {verdict}") + tui.dim(f" {ms}ms"))
    elif verdict == "deny":
        print(tui.red("✗ DENIED") + f": {output_excerpt[:220]}")
    else:
        print(tui.red(f"✗ DENIED ({verdict})") + f": {output_excerpt[:220]}")


# -- @-file mentions ------------------------------------------------------
_MENTION_RE = re.compile(r"(?<!\w)@([^\s@]+)")
_MENTION_MAX_BYTES = 200_000


def expand_mentions(line: str, cwd: Path) -> str:
    """Expand `@path/to/file` tokens into the file's contents.

    Only local files inside the working directory; missing files or
    escape attempts are left untouched (never an error — a typo'd
    mention should not kill the turn).
    """
    def _sub(m: re.Match) -> str:
        raw = m.group(1).rstrip(".,;:!?\"')]")
        trail = m.group(1)[len(raw):]
        try:
            p = safe_path(Path(cwd).resolve(), raw)
        except PermissionError:
            return m.group(0)
        if not p.is_file():
            return m.group(0)
        try:
            if p.stat().st_size > _MENTION_MAX_BYTES:
                return f"[file {raw}: too large, skipped]"
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return m.group(0)
        return f'<file path="{raw}">\n{text[:20000]}\n</file>{trail}'

    return _MENTION_RE.sub(_sub, line)


# -- slash-command palette ------------------------------------------------
def _show_palette(filt: str, loop: AgentLoop,
                  session: guard_mod.GuardSession, kb: KB) -> bool:
    """Numbered slash-command palette (dumb-terminal friendly).

    Returns True to exit the REPL.
    """
    filt = (filt or "").strip().lower()
    items = [(k, v) for k, v in SKILLS.items()
             if not filt or filt in k.lower() or filt in v.lower()]
    if not items:
        print(f"no commands match '{filt}'. /help for skills.")
        return False
    print("\nSlash commands:")
    for i, (k, v) in enumerate(items, 1):
        print(f"  {i:2d}. {k:10s} {v}")
    try:
        pick = input("pick # (Enter cancels): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not pick or pick in ("q", "quit", "cancel"):
        return False
    if not pick.isdigit() or not 1 <= int(pick) <= len(items):
        print("cancelled.")
        return False
    chosen = items[int(pick) - 1][0]
    print(f"> {chosen}")
    return _handle_slash(chosen, loop, session, kb)


# -- REPL -----------------------------------------------------------------
def run_repl(provider_name: str = "", model: str = "",
             mode: str = "dev") -> int:
    kb = KB.load()
    try:
        provider = get_provider(provider_name, model)
    except ValueError as e:
        print(f"error: {e}")
        print("Set AEGIS_PROVIDER=mock for offline mode, or export "
              "ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY (or GEMINI_API_KEY); "
              "for local models use AEGIS_PROVIDER=ollama with --model <name> "
              "(ollama pull <name> first).")
        return 2
    cwd = Path.cwd()
    mode = (mode or "dev").lower()
    if mode not in ("dev", "plan"):
        print(f"error: unknown mode '{mode}' (want dev|plan)")
        return 2

    def approval_cb(findings, tool="", args=None):
        return interactive_approval(findings, tool, args, cwd=cwd)

    # v0.7 Lane A: discover plugins and expose them as agent-loop tools.
    # Non-fatal by design: a broken plugin dir must never stop the REPL.
    plugin_names: list[str] = []
    try:
        from . import plugins as plugins_mod
        from .tools.registry import TOOLS
        _specs, _warns = plugins_mod.discover()
        for _w in _warns:
            print(f"[plugins] warning: {_w}")
        _added, _collide = plugins_mod.register_plugin_tools(TOOLS, _specs)
        for _w in _collide:
            print(f"[plugins] warning: {_w}")
        plugin_names = _added
        if plugin_names:
            print(f"[plugins] loaded: {', '.join(plugin_names)}")
    except Exception as e:  # noqa: BLE001 - plugin boot must never be fatal
        print(f"[plugins] discovery failed ({type(e).__name__}: {e}); "
              f"continuing without plugins.")

    policy = Policy(allowed_tools=set(TOOL_NAMES) | set(plugin_names),
                    approval_callback=approval_cb,
                    egress_allowlist=None,  # any egress pauses for approval
                    name="repl",
                    mode=mode)
    session = guard_mod.create_session(policy, kb)
    conv = session_mod.new_session(session.id)
    loop = AgentLoop(provider, kb, session, cwd=cwd,
                     approval_callback=approval_cb,
                     on_text=lambda s: (sys.stdout.write(s), sys.stdout.flush()),
                     conversation_id=conv["id"],
                     on_tool_start=_print_tool_start,
                     on_tool_end=_print_tool_end)
    print(BANNER.format(__version__=__version__))
    print(tui.status_line(
        f"provider: {provider.name}  model: {getattr(provider, 'model', '?')}  "
        f"mode: {loop.mode}"))
    if loop.mode == "plan":
        print("PLAN mode: read-only. Writes, edits and command execution are "
              "denied at the guard layer. /mode dev to switch.")
    print(f"session: {session.id}  audit: {session.audit.path}")
    print(f"KB: {kb.count()} techniques across {len(kb.packs())} packs")
    _print_recent_sessions(conv["id"])
    print()

    while True:
        try:
            line = input(f"aegis[{loop.mode}]> ").strip()
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
        renderer = tui.StreamingRenderer()
        prev_on_text = loop.on_text
        loop.on_text = renderer.feed
        try:
            loop.run(expand_mentions(line, cwd))
        except guard_mod.SessionRevoked as e:
            print(f"\n[!] {e}\nSession killed. Restart aegis for a new session.")
            break
        except Exception as e:
            print(f"\n[agent error: {e}]")
        finally:
            loop.on_text = prev_on_text
            renderer.flush()
        print()
    return 0


def _print_recent_sessions(current_id: str, limit: int = 5) -> None:
    recent = [s for s in session_mod.list_sessions() if s["id"] != current_id]
    if not recent:
        print("No saved conversations yet — this chat will be saved as you go.")
        return
    print("Recent conversations (/resume <n> to continue):")
    for i, s in enumerate(recent[:limit], 1):
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(s["updated"]))
        print(f"  {i}. {s['title'][:50]}  [{s['id']}]  {when}  "
              f"({len(s['messages'])} msgs)")


def _handle_slash(line: str, loop: AgentLoop,
                  session: guard_mod.GuardSession, kb: KB) -> bool:
    """Returns True to exit the REPL."""
    parts = line.split(None, 1)
    cmd, rest = parts[0].lower(), (parts[1] if len(parts) > 1 else "")
    if cmd in ("/exit", "/quit"):
        print("bye.")
        return True
    # Palette: "/" alone opens it; an unknown /command filters it.
    if cmd == "/":
        return _show_palette("", loop, session, kb)
    if cmd not in SKILLS:
        return _show_palette(cmd[1:], loop, session, kb)
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
    if cmd == "/plan":
        print(plan_attack_surface(rest, kb))
        return False
    if cmd == "/emulate":
        parts = (rest or "").split(None, 1)
        print(emulate(parts[0] if parts else "",
                      parts[1] if len(parts) > 1 else None, kb))
        return False
    if cmd == "/mode":
        want = (rest or "").strip().lower()
        if want not in ("dev", "plan"):
            print(f"mode: {loop.mode}  (usage: /mode <dev|plan>)")
            return False
        try:
            loop.set_mode(want)
        except ValueError as e:
            print(f"error: {e}")
            return False
        print(f"mode -> {loop.mode}")
        if loop.mode == "plan":
            print("PLAN mode: read-only. write/edit/bash are denied at the "
                  "guard layer.")
        return False
    if cmd == "/planexec":
        if not rest:
            print("usage: /planexec <task> — the model proposes a step plan, "
                  "the guard screens every step, then the approved plan runs")
        else:
            loop.run(rest, plan_first=True)
        return False
    if cmd == "/build":
        print(build(rest, kb))
        return False
    if cmd == "/test":
        print(test_suite(rest, kb))
        return False
    if cmd == "/fix":
        print(fix(rest, loop, kb))
        return False
    if cmd == "/refactor":
        print(refactor(rest, loop, kb))
        return False
    if cmd == "/repomap":
        print(repomap_cmd(rest or ".", kb))
        return False
    if cmd == "/index":
        print(index_cmd(rest or ".", kb))
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
    if cmd == "/sessions":
        sessions = session_mod.list_sessions()
        if not sessions:
            print("no saved conversations.")
        else:
            for i, s in enumerate(sessions, 1):
                when = time.strftime("%Y-%m-%d %H:%M",
                                     time.localtime(s["updated"]))
                cur = "  <-- current" if s["id"] == loop.conversation_id else ""
                print(f"  {i}. {s['title'][:50]}  [{s['id']}]  {when}  "
                      f"({len(s['messages'])} msgs){cur}")
        return False
    if cmd == "/resume":
        if not rest:
            print("usage: /resume <n|id>")
            return False
        rec = session_mod.resolve_session(rest)
        if rec is None:
            print(f"no conversation matches '{rest}'. /sessions to list.")
            return False
        if loop.attach_conversation(rec["id"]):
            print(f"resumed '{rec['title']}' [{rec['id']}] "
                  f"({len(rec['messages'])} messages restored)")
        else:
            print(f"could not load conversation '{rest}'")
        return False
    if cmd == "/rename":
        cid = getattr(loop, "conversation_id", None)
        if not rest:
            print("usage: /rename <title>")
        elif not cid:
            print("no active conversation to rename.")
        elif session_mod.rename_session(cid, rest):
            print(f"renamed to '{rest.strip()[:80]}'")
        else:
            print("rename failed.")
        return False
    print(f"unknown command '{cmd}'. /help for skills.")
    return False
