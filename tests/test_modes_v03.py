"""v0.3 modes: plan mode is read-only AT THE GUARD LAYER.

The critical property: even when the model explicitly requests a write in
plan mode, the guard denies it pre-execution. This is enforcement, not a
prompt suggestion.
"""

import pytest

from aegis import guard as guard_mod
from aegis.agent import AgentLoop, build_system_prompt
from aegis.guard import Policy, create_session
from aegis.providers import MockProvider
from aegis.skills import SKILLS, plan_attack_surface
from aegis.tools.registry import TOOL_NAMES


def _loop(script, kb, cwd, **policy_kw):
    provider = MockProvider(script)
    policy_kw.setdefault("allowed_tools", set(TOOL_NAMES))
    policy = Policy(name="mode-test", **policy_kw)
    session = create_session(policy, kb)
    loop = AgentLoop(provider, kb, session, cwd=cwd)
    return provider, session, loop


def test_plan_mode_denies_writes_at_guard_layer(kb, tmp_path):
    sess = create_session(Policy(name="t", mode="plan"), kb)
    for tool, args in [
        ("write", {"path": "x.txt", "content": "pwned"}),
        ("edit", {"path": "x.txt", "old_text": "a", "new_text": "b"}),
        ("bash", {"cmd": "ls"}),
    ]:
        v = sess.check_call(tool, args)
        assert v.decision == "deny", (tool, v.decision)
        assert "plan mode" in v.reason.lower()


def test_plan_mode_allows_read_only_tools(kb, tmp_path):
    sess = create_session(Policy(name="t", mode="plan"), kb)
    for tool, args in [
        ("read", {"path": "x.txt"}),
        ("kb_query", {"query": "prompt injection"}),
        ("webfetch", {"url": "https://example.com"}),
        ("scan_trace", {"path": "t.jsonl"}),
    ]:
        v = sess.check_call(tool, args)
        assert v.decision in ("allow", "needs_approval"), (tool, v.decision)


def test_plan_mode_holds_when_model_requests_write(kb, tmp_path):
    """The model 'forgets' plan mode and tries to write anyway."""
    (tmp_path / "victim.txt").write_text("original")
    script = [
        {"text": "I'll just write the file. ",
         "tool_calls": [{"name": "write",
                         "args": {"path": "victim.txt",
                                  "content": "MODEL WROTE THIS"}}]},
        {"text": "done."},
    ]
    _, session, loop = _loop(script, kb, tmp_path, mode="plan")
    loop.run("change victim.txt")
    # The write never executed: file untouched, audit shows the deny.
    assert (tmp_path / "victim.txt").read_text() == "original"
    calls = [e for e in session.audit.read_all() if e["event"] == "tool_call"]
    assert calls and calls[0]["verdict"] == "deny"
    assert calls[0]["tool"] == "write"


def test_dev_mode_allows_write(kb, tmp_path):
    script = [
        {"text": "Writing. ",
         "tool_calls": [{"name": "write",
                         "args": {"path": "out.txt", "content": "hello"}}]},
        {"text": "done."},
    ]
    _, _, loop = _loop(script, kb, tmp_path, mode="dev")
    loop.run("write out.txt")
    assert (tmp_path / "out.txt").read_text() == "hello"


def test_set_mode_switches_enforcement_and_prompt(kb, tmp_path):
    _, session, loop = _loop([], kb, tmp_path, mode="dev")
    assert loop.mode == "dev"
    assert "DEV (full power)" in loop.system
    loop.set_mode("plan")
    assert loop.mode == "plan"
    assert session.policy.mode == "plan"
    assert "PLAN (read-only)" in loop.system
    v = session.check_call("bash", {"cmd": "ls"})
    assert v.decision == "deny"
    loop.set_mode("dev")
    assert "DEV (full power)" in loop.system
    with pytest.raises(ValueError):
        loop.set_mode("yolo")


def test_build_system_prompt_modes(kb):
    dev = build_system_prompt(kb, "dev")
    plan = build_system_prompt(kb, "plan")
    assert "DEV (full power)" in dev
    assert "PLAN (read-only)" in plan
    assert "cannot write" in plan.lower() or "CANNOT write" in plan


def test_offensive_tooling_denied_in_both_modes(kb):
    for mode in ("dev", "plan"):
        sess = create_session(Policy(name="t", mode=mode), kb)
        v = sess.check_call("bash", {"cmd": "msfconsole -q -x 'use exploit/x'"})
        assert v.decision == "deny"
        v = sess.check_call("bash", {"cmd": "mimikatz.exe privilege::debug"})
        assert v.decision == "deny"


def test_offensive_tooling_reason_in_dev_mode(kb):
    sess = create_session(Policy(name="t", mode="dev"), kb)
    v = sess.check_call("bash", {"cmd": "msfvenom -p windows/x64/meterpreter"})
    assert v.decision == "deny"
    assert "defensive-only" in v.reason


def test_plan_skill_phased_report(kb, tmp_path):
    (tmp_path / "app.py").write_text(
        'API_KEY = "sk-live-1234567890abcdef"\n'
        "import subprocess\n"
        "subprocess.run(user_input, shell=True)\n"
        "eval(request.args.get('code'))\n")
    report = plan_attack_surface(str(tmp_path), kb)
    assert "Phase 1" in report
    assert "Phase 3" in report
    assert "Fix-first queue" in report
    assert "defensive planning" in report
    assert "sk-live-1234567890abcdef" not in report  # secrets never echoed


def test_plan_skill_refuses_remote_and_missing(kb):
    assert "refused" in plan_attack_surface("https://evil.example", kb)
    assert "refused" in plan_attack_surface("/no/such/dir/xyz", kb)
    assert "usage" in plan_attack_surface("", kb)


def test_skills_registry_has_mode_and_plan():
    assert "/plan" in SKILLS
    assert "/mode" in SKILLS
    assert "read-only" in SKILLS["/plan"]
