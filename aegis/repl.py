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
from .skills import SKILLS, emulate, hunt, plan_attack_surface
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
    _pause_card_for_approval()
    print()
    print(tui.bold("[!] GUARD: high-severity match — human approval required"))
    if tool:
        print(f"    tool: {tui.cyan(tool)}")
    if isinstance(args, dict) and args:
        if tool == "bash" and args.get("cmd"):
            # Show the EXACT command being approved (redacted, truncated).
            print("    command:")
            for ln in tui._redact(str(args["cmd"])).splitlines()[:10]:
                print(f"      {tui.yellow(ln[:300])}")
        elif tool not in ("write", "edit"):
            print(f"    args: {tui.dim(tui._redact(repr(args)[:300]))}")
    # File modifications: show the operator a colored unified diff with
    # line numbers BEFORE the prompt. diffx emits plain text (color=False
    # avoids its own isatty probe); tui.render_diff adds color + numbers.
    if cwd is not None and isinstance(args, dict) and tool in ("write", "edit"):
        try:
            from . import diffx
            if tool == "write" and "path" in args:
                raw = diffx.diff_for_write(args.get("path", ""),
                                           args.get("content", ""),
                                           Path(cwd), color=False)
            elif tool == "edit" and "path" in args:
                raw = diffx.diff_for_edit(args.get("path", ""),
                                          args.get("old_text", ""),
                                          args.get("new_text", ""),
                                          Path(cwd), color=False)
            else:
                raw = ""
            if raw:
                print(tui.render_diff(raw))
        except Exception as e:
            print(f"    (diff preview unavailable: {e})")
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else f
        print(f"    {tui.red('[' + str(d.get('severity', '?')).upper() + ']')} "
              f"{d.get('technique_id', '?')} {d.get('technique_name', '?')}")
        print(f"      evidence: {tui.dim(str(d.get('evidence', ''))[:200])}")
    try:
        ans = input(tui.bold("    Approve this call? [y/N] ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        ans = "n"
    _resume_card()
    return ans == "y"


# -- usage tracking (status bar) ------------------------------------------
class UsageTracker:
    """Provider wrapper: accumulates ("usage", ...) events, passes all
    others through untouched. Lets the status bar count tokens without
    touching AgentLoop. Attribute access proxies to the wrapped provider.
    """

    def __init__(self, provider):
        object.__setattr__(self, "_provider", provider)
        self.input_tokens = 0
        self.output_tokens = 0
        self.estimated = False

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_provider"), name)

    def stream(self, messages, tools, system):
        for kind, payload in self._provider.stream(messages, tools, system):
            if kind == "usage" and isinstance(payload, dict):
                self.input_tokens += int(payload.get("input_tokens", 0) or 0)
                self.output_tokens += int(payload.get("output_tokens", 0) or 0)
                self.estimated = (self.estimated
                                  or bool(payload.get("estimated")))
            yield kind, payload


# -- tool-call display cards ----------------------------------------------
# AgentLoop calls _print_tool_start/_print_tool_end around every tool
# execution (signatures are its contract — keep them). The active card is
# tracked so approval prompts can freeze/resume its spinner.
_active_card: tui.ToolCard | None = None


def _pause_card_for_approval() -> None:
    if _active_card is not None:
        _active_card.pause_for_approval()


def _resume_card() -> None:
    if _active_card is not None:
        _active_card.resume()


def _stop_active_card() -> None:
    global _active_card
    card, _active_card = _active_card, None
    if card is not None:
        card.abort()


def _print_tool_start(name: str, args_summary: str) -> None:
    global _active_card
    _active_card = tui.ToolCard(name, args_summary)
    _active_card.start()


def _print_tool_end(name: str, verdict: str, duration_ms: float,
                    output_excerpt: str) -> None:
    global _active_card
    card, _active_card = _active_card, None
    if card is None:
        # Defensive fallback: never lose the verdict line.
        ms = f"{duration_ms:.0f}"
        mark = (tui.green("✓") if verdict in ("allow", "approved")
                else tui.red("✗"))
        print(f"{mark} {name}: {verdict} {tui.dim(ms + 'ms')}")
        return
    card.finish(verdict, duration_ms, output_excerpt)


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

    Fuzzy-filters on "name + description"; descriptions are aligned in a
    column. Returns True to exit the REPL.
    """
    items = [(k, v) for k, v in SKILLS.items()]
    filt = (filt or "").strip()
    if filt:
        # Name matches rank before description matches.
        ranked = []
        for kv in items:
            sn = tui.fuzzy_score(filt, kv[0])
            if sn is not None:
                ranked.append(((0, sn), kv))
                continue
            sd = tui.fuzzy_score(filt, kv[0] + " " + kv[1])
            if sd is not None:
                ranked.append(((1, sd), kv))
        ranked.sort(key=lambda p: p[0])
        items = [kv for _, kv in ranked]
    if not items:
        print(f"no commands match '{filt}'. /help for skills.")
        return False
    width = max(len(k) for k, _ in items)
    print("\nSlash commands:")
    for i, (k, v) in enumerate(items, 1):
        print(f"  {tui.dim(f'{i:2d}.')} {tui.cyan(k.ljust(width))}  "
              f"{tui.dim(v)}")
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


# -- keyboard: multiline input, bracketed paste ---------------------------
_PASTE_START = "\x1b[200~"
_PASTE_END = "\x1b[201~"


def _enable_bracketed_paste() -> None:
    """Ask the terminal to bracket pastes (best effort, TTY only)."""
    try:
        if sys.stdout.isatty():
            sys.stdout.write("\x1b[?2004h")
            sys.stdout.flush()
    except Exception:
        pass


def _disable_bracketed_paste() -> None:
    try:
        if sys.stdout.isatty():
            sys.stdout.write("\x1b[?2004l")
            sys.stdout.flush()
    except Exception:
        pass


def _read_user_line(prompt: str) -> str:
    """Read one logical input line.

    Backslash-continuation: a trailing ``\\`` joins the next line.
    Bracketed-paste markers are stripped. Raises EOFError /
    KeyboardInterrupt from input() unchanged.
    """
    chunks: list[str] = []
    p = prompt
    while True:
        line = input(p)
        line = line.replace(_PASTE_START, "").replace(_PASTE_END, "")
        if line.endswith("\\") and not line.endswith("\\\\"):
            chunks.append(line[:-1])
            p = "... "
            continue
        chunks.append(line)
        break
    return "\n".join(chunks)


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

    policy = Policy(allowed_tools=set(TOOL_NAMES),
                    approval_callback=approval_cb,
                    egress_allowlist=None,  # any egress pauses for approval
                    name="repl",
                    mode=mode)
    session = guard_mod.create_session(policy, kb)
    conv = session_mod.new_session(session.id)
    tracked = UsageTracker(provider)
    loop = AgentLoop(tracked, kb, session, cwd=cwd,
                     approval_callback=approval_cb,
                     on_text=lambda s: (sys.stdout.write(s), sys.stdout.flush()),
                     conversation_id=conv["id"],
                     on_tool_start=_print_tool_start,
                     on_tool_end=_print_tool_end)
    status = tui.SessionStatus(
        model=getattr(tracked, "model", "?") or "?",
        session_id=conv["id"],
        provider_name=getattr(tracked, "name", ""))
    print(BANNER.format(__version__=__version__))
    print(tui.status_line(
        f"provider: {tracked.name}  model: {status.model}  "
        f"mode: {loop.mode}"))
    if loop.mode == "plan":
        print("PLAN mode: read-only. Writes, edits and command execution are "
              "denied at the guard layer. /mode dev to switch.")
    print(f"session: {session.id}  audit: {session.audit.path}")
    print(f"KB: {kb.count()} techniques across {len(kb.packs())} packs")
    _print_recent_sessions(conv["id"])
    print(status.render())
    print()

    _enable_bracketed_paste()
    try:
        while True:
            try:
                line = _read_user_line(f"aegis[{loop.mode}]> ").strip()
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
            except KeyboardInterrupt:
                # Graceful interrupt: cancel the turn, keep the session.
                _stop_active_card()
                print("\n[cancelled — turn interrupted, session kept]")
            except guard_mod.SessionRevoked as e:
                _stop_active_card()
                print(f"\n[!] {e}\nSession killed. "
                      "Restart aegis for a new session.")
                break
            except Exception as e:
                _stop_active_card()
                print(f"\n[agent error: {e}]")
            finally:
                loop.on_text = prev_on_text
                renderer.flush()
            status.sync(tracked.input_tokens, tracked.output_tokens,
                        tracked.estimated)
            status.bump_iteration()
            print(status.render())
            print()
    finally:
        _disable_bracketed_paste()
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
        width = max(len(k) for k in SKILLS)
        for k, v in SKILLS.items():
            print(f"  {tui.cyan(k.ljust(width))}  {tui.dim(v)}")
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
