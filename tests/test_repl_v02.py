"""v0.2 REPL lane: session store, resume, palette, tool display, diffs, mentions."""

import json
import uuid

import pytest

from aegis import diffx, guard as guard_mod
from aegis import session as session_mod
from aegis.agent import AgentLoop
from aegis.guard import Policy, create_session
from aegis.providers import MockProvider
from aegis.repl import _handle_slash, _show_palette, expand_mentions
from aegis.skills import SKILLS
from aegis.tools.registry import TOOL_NAMES

FAKE = "<redacted>"


def _sid(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _loop(script, kb, cwd, **kw):
    provider = MockProvider(script)
    policy = Policy(name="repl-v02-test",
                    allowed_tools=set(TOOL_NAMES),
                    **{k: v for k, v in kw.items() if k != "loop_kw"})
    session = create_session(policy, kb)
    loop_kw = kw.get("loop_kw", {})
    loop = AgentLoop(provider, kb, session, cwd=cwd, **loop_kw)
    return provider, session, loop


# -- session store --------------------------------------------------------
def test_new_load_roundtrip():
    sid = _sid("rt")
    rec = session_mod.new_session(sid)
    assert rec["id"] == sid
    loaded = session_mod.load_session(sid)
    assert loaded["id"] == sid
    assert loaded["messages"] == []


def test_title_from_first_user_message_and_persistence():
    sid = _sid("title")
    session_mod.save_message(sid, "user", "hello world, please audit this code")
    session_mod.save_message(sid, "assistant", "on it")
    # Simulate a process restart: re-read from disk.
    rec = session_mod.load_session(sid)
    assert rec["title"].startswith("hello world")
    assert [m["role"] for m in rec["messages"]] == ["user", "assistant"]
    assert rec["messages"][0]["content"] == "hello world, please audit this code"


def test_messages_secrets_redacted_in_store():
    sid = _sid("redact")
    secret = "hunter2secretvalue"
    rec = session_mod.save_message(sid, "user",
                                   f"password = '{secret}' please check")
    assert secret not in json.dumps(rec["messages"])


def test_list_sessions_newest_first_and_rename_delete():
    a, b = _sid("la"), _sid("lb")
    session_mod.new_session(a, title="alpha")
    session_mod.new_session(b, title="beta")
    session_mod.save_message(b, "user", "touch")  # b updated later
    ids = [s["id"] for s in session_mod.list_sessions()]
    assert ids.index(b) < ids.index(a)
    assert session_mod.rename_session(b, "beta renamed")
    assert session_mod.load_session(b)["title"] == "beta renamed"
    assert not session_mod.rename_session(b, "   ")
    assert session_mod.delete_session(a)
    assert session_mod.load_session(a) is None
    assert not session_mod.delete_session(a)


def test_resolve_session_number_id_prefix():
    s1, s2 = _sid("rs1"), _sid("rs2")
    session_mod.new_session(s1, title="one")
    session_mod.new_session(s2, title="two")
    sessions = session_mod.list_sessions()
    one = [s for s in sessions if s["id"] == s1][0]
    idx = sessions.index(one) + 1
    assert session_mod.resolve_session(str(idx), sessions)["id"] == s1
    assert session_mod.resolve_session(s2, sessions)["id"] == s2
    assert session_mod.resolve_session(s2[:12], sessions)["id"] == s2
    assert session_mod.resolve_session("nope-zzz", sessions) is None
    assert session_mod.resolve_session("", sessions) is None


# -- conversation persistence in the agent loop ----------------------------
def test_run_persists_and_resumes(kb, tmp_path):
    sid = _sid("conv")
    seen = []

    def capture(msgs):
        seen.append(len(msgs))
        return {"text": "hi there"}

    _, _, loop1 = _loop([capture], kb, tmp_path, loop_kw={"conversation_id": sid})
    assert loop1.history == []
    loop1.run("first message")
    assert len(loop1.history) == 2  # user + assistant
    assert seen == [1]
    rec = session_mod.load_session(sid)
    assert len(rec["messages"]) == 2

    def capture2(msgs):
        seen.append(len(msgs))
        return {"text": "welcome back"}

    _, _, loop2 = _loop([capture2], kb, tmp_path,
                        loop_kw={"conversation_id": sid})
    assert len(loop2.history) == 2  # restored from disk
    loop2.run("second message")
    assert seen == [1, 3]  # resumed history + new user message
    assert len(session_mod.load_session(sid)["messages"]) == 4


def test_legacy_loop_stays_stateless(kb, tmp_path):
    _, _, loop = _loop([{"text": "ok"}], kb, tmp_path)
    loop.run("hello")
    assert loop.history is None
    assert loop.conversation_id is None


def test_attach_conversation_unknown_id(kb, tmp_path):
    _, _, loop = _loop([], kb, tmp_path)
    assert loop.attach_conversation("does-not-exist") is False
    assert loop.conversation_id is None


# -- tool-call display callbacks -------------------------------------------
def test_tool_callbacks_fire_on_allow(kb, tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    events = []
    script = [
        {"text": "reading ",
         "tool_calls": [{"name": "read", "args": {"path": "a.txt"}}]},
        {"text": "done"},
    ]
    _, _, loop = _loop(
        script, kb, tmp_path,
        loop_kw={"on_tool_start": lambda n, s: events.append(("start", n, s)),
                 "on_tool_end": lambda n, v, ms, e: events.append(("end", n, v))})
    loop.run("read it")
    assert events[0][0] == "start" and events[0][1] == "read"
    assert "path=a.txt" in events[0][2]
    assert events[1][0] == "end" and events[1][1] == "read"
    assert events[1][2] == "allow"


def test_tool_callbacks_fire_on_deny(kb, tmp_path):
    events = []
    script = [{"text": "trying ",
               "tool_calls": [{"name": "read", "args": {"path": "a.txt"}}]},
              {"text": "blocked"}]
    provider = MockProvider(script)
    policy = Policy(name="deny-test", allowed_tools=set(), denied_tools={"read"})
    session = create_session(policy, kb)
    loop = AgentLoop(
        provider, kb, session, cwd=tmp_path,
        on_tool_start=lambda n, s: events.append(("start", n)),
        on_tool_end=lambda n, v, ms, e: events.append(("end", n, v, e)))
    loop.run("read it")
    assert [e[0] for e in events] == ["start", "end"]
    assert events[1][2] == "deny"
    assert events[1][3]  # reason excerpt present


def test_tool_args_summary_redacts_secrets():
    from aegis.agent import _summarize_args
    s = _summarize_args({"path": "a.txt",
                         "content": "password = 'hunter2secretvalue'"})
    assert "hunter2secretvalue" not in s
    assert "path=a.txt" in s


# -- diffx ------------------------------------------------------------------
def test_diff_for_write_existing(tmp_path):
    (tmp_path / "f.txt").write_text("line1\nline2\nline3\n")
    out = diffx.diff_for_write("f.txt", "line1\nline2 changed\nline3\n",
                               tmp_path, color=False)
    assert "--- diff: f.txt" in out
    assert "-line2" in out
    assert "+line2 changed" in out


def test_diff_for_write_new_file(tmp_path):
    out = diffx.diff_for_write("new.txt", "hello\n", tmp_path, color=False)
    assert "(new file)" in out
    assert "+hello" in out


def test_diff_for_edit(tmp_path):
    (tmp_path / "e.txt").write_text("aaa\nbbb\n")
    out = diffx.diff_for_edit("e.txt", "bbb", "BBB", tmp_path, color=False)
    assert "-bbb" in out
    assert "+BBB" in out


def test_diff_for_edit_missing_old_text(tmp_path):
    (tmp_path / "e.txt").write_text("aaa\n")
    out = diffx.diff_for_edit("e.txt", "zzz", "q", tmp_path, color=False)
    assert "old_text not found" in out


def test_diff_for_write_no_changes(tmp_path):
    (tmp_path / "s.txt").write_text("same\n")
    assert "no changes" in diffx.diff_for_write("s.txt", "same\n",
                                                tmp_path, color=False)


def test_diff_path_escape_refused(tmp_path):
    out = diffx.diff_for_write("../evil.txt", "x", tmp_path, color=False)
    assert out.startswith("(no diff:")


# -- slash commands: sessions / resume / rename -----------------------------
def _repl_loop(kb, tmp_path, **loop_kw):
    provider = MockProvider([{"text": "ok"}])
    policy = Policy(name="repl-test", allowed_tools=set(TOOL_NAMES))
    session = create_session(policy, kb)
    loop = AgentLoop(provider, kb, session, cwd=tmp_path, **loop_kw)
    return loop, session


def test_sessions_resume_rename(kb, tmp_path, capsys):
    sid1 = _sid("c1")
    loop, session = _repl_loop(kb, tmp_path, conversation_id=sid1)
    loop.run("hello first")
    sid2 = _sid("c2")
    session_mod.save_message(sid2, "user", "second convo")
    session_mod.save_message(sid2, "assistant", "reply")

    assert _handle_slash("/sessions", loop, session, kb) is False
    out = capsys.readouterr().out
    assert sid1 in out and sid2 in out and "<-- current" in out

    assert _handle_slash(f"/resume {sid2}", loop, session, kb) is False
    out = capsys.readouterr().out
    assert "resumed" in out
    assert loop.conversation_id == sid2
    assert len(loop.history) == 2

    assert _handle_slash("/rename my renamed chat", loop, session, kb) is False
    assert session_mod.load_session(sid2)["title"] == "my renamed chat"

    assert _handle_slash("/resume nope-zzz", loop, session, kb) is False
    assert "no conversation matches" in capsys.readouterr().out
    assert _handle_slash("/rename", loop, session, kb) is False
    assert "usage" in capsys.readouterr().out


# -- palette -----------------------------------------------------------------
def test_palette_pick_number(kb, tmp_path, capsys, monkeypatch):
    loop, session = _repl_loop(kb, tmp_path)
    idx = list(SKILLS).index("/help") + 1
    monkeypatch.setattr("builtins.input", lambda *a, **k: str(idx))
    assert _show_palette("", loop, session, kb) is False
    assert "/hunt" in capsys.readouterr().out  # /help printed the list


def test_palette_filter_and_cancel(kb, tmp_path, capsys, monkeypatch):
    loop, session = _repl_loop(kb, tmp_path)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "")
    assert _handle_slash("/xyz-no-such", loop, session, kb) is False
    assert "no commands match" in capsys.readouterr().out
    assert _handle_slash("/hu", loop, session, kb) is False  # filter, cancelled
    assert "/hunt" in capsys.readouterr().out


def test_bare_slash_opens_palette(kb, tmp_path, capsys, monkeypatch):
    loop, session = _repl_loop(kb, tmp_path)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "q")
    assert _handle_slash("/", loop, session, kb) is False
    assert "Slash commands:" in capsys.readouterr().out


def test_existing_slash_commands_still_work(kb, tmp_path, capsys):
    loop, session = _repl_loop(kb, tmp_path)
    assert _handle_slash("/help", loop, session, kb) is False
    assert "/sessions" in capsys.readouterr().out  # new entries listed too
    assert _handle_slash("/guard", loop, session, kb) is False
    assert "session:" in capsys.readouterr().out
    assert _handle_slash("/exit", loop, session, kb) is True


# -- @-mentions ---------------------------------------------------------------
def test_expand_mentions(tmp_path):
    (tmp_path / "notes.md").write_text("# hello\nbody")
    out = expand_mentions("check @notes.md please", tmp_path)
    assert "<file path=\"notes.md\">" in out
    assert "# hello" in out
    assert "check " in out and " please" in out


def test_expand_mentions_missing_and_escape_untouched(tmp_path):
    assert expand_mentions("see @missing.txt", tmp_path) == "see @missing.txt"
    assert expand_mentions("see @../evil.txt", tmp_path) == "see @../evil.txt"
    assert expand_mentions("mail me@x.com", tmp_path) == "mail me@x.com"
