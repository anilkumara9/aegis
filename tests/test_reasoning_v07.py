"""v0.7 Lane C: reasoning upgrades.

- Enforced plan-then-execute: no approval -> no execution; deviations from
  the active plan are blocked unless re-approved.
- Verification loops: a "done" claim with failing tests retries (bounded)
  instead of claiming success; persistent failure is reported honestly.
- Progress events: emitted in order, minimal dict shape for Lane E.
- Plan state persists in the session store (/resume keeps it).
- /commit works on a REAL temp git repo (founder steering).
"""

import json
import subprocess
import sys

from aegis import gitcommit
from aegis import session as session_mod
from aegis.agent import AgentLoop
from aegis.guard import Policy, create_session
from aegis.planning import (EXECUTING, PlanStep, TaskPlan,
                            task_looks_complex)
from aegis.providers import MockProvider, ToolCall
from aegis.tools.registry import TOOL_NAMES


def _loop(script, kb, cwd, policy_kw=None, **loop_kw):
    seen: list[str] = []
    events: list[dict] = []
    provider = MockProvider(script)
    pkw = {"allowed_tools": set(TOOL_NAMES), "name": "reasoning-test"}
    pkw.update(policy_kw or {})
    policy = Policy(**pkw)
    session = create_session(policy, kb)
    loop = AgentLoop(provider, kb, session, cwd=cwd,
                     on_text=seen.append,
                     progress_callback=events.append, **loop_kw)
    return provider, session, loop, seen, events


def _plan_json(*steps):
    return json.dumps([{"tool": t, "args": a, "purpose": p}
                       for t, a, p in steps])


# -- plan enforcement ------------------------------------------------------
def test_plan_blocked_without_approval(kb, tmp_path):
    steps = _plan_json(("write", {"path": "x.txt", "content": "hi"}, "write"))
    _, session, loop, seen, events = _loop(
        [{"text": steps}], kb, tmp_path,
        plan_approval_callback=lambda info: False)
    result = loop.run("write the file", plan_first=True)
    assert "not approved" in result
    assert not (tmp_path / "x.txt").exists()
    calls = [e for e in session.audit.read_all()
             if e["event"] == "tool_call"]
    assert calls == []  # nothing executed
    assert loop.last_plan is not None and loop.last_plan.state == "rejected"
    kinds = [e["kind"] for e in events]
    assert kinds[0] == "plan_proposed"
    assert "plan_rejected" in kinds


def test_plan_approved_executes_progress_in_order(kb, tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    steps = _plan_json(("read", {"path": "a.txt"}, "read it"),
                       ("write", {"path": "b.txt", "content": "copy"},
                        "write copy"))
    _, _, loop, _, events = _loop(
        [{"text": steps}], kb, tmp_path,
        plan_approval_callback=lambda info: True)
    result = loop.run("copy a.txt to b.txt", plan_first=True)
    assert (tmp_path / "b.txt").read_text() == "copy"
    assert "step 1 (read)" in result and "step 2 (write)" in result
    kinds = [e["kind"] for e in events]
    assert kinds == ["plan_proposed", "plan_approved", "task",
                     "step", "step", "step", "step",
                     "verify", "verify", "task"]
    step_events = [e for e in events if e["kind"] == "step"]
    assert [(e["index"], e["total"], e["status"]) for e in step_events] == [
        (1, 2, "active"), (1, 2, "done"),
        (2, 2, "active"), (2, 2, "done")]
    assert all(s.status == "done" for s in loop.last_plan.steps)
    assert loop.last_plan.state == "verified"
    assert "VERIFIED" in result


def test_deviation_blocked_unless_reapproved(kb, tmp_path):
    _, session, loop, _, events = _loop(
        [], kb, tmp_path,
        plan_approval_callback=lambda info: False)
    plan = TaskPlan("t", [PlanStep("read", {"path": "a.txt"}, "read it")])
    plan.state = EXECUTING
    plan.mark_step(0, "active")
    loop.active_plan = plan
    result = loop._guarded_execute(ToolCall("d-1", "bash", {"cmd": "echo hi"}))
    assert "PLAN DEVIATION BLOCKED" in result
    denies = [e for e in session.audit.read_all()
              if e["event"] == "tool_call" and e["verdict"] == "deny"]
    assert len(denies) == 1
    dev = [e for e in events if e["kind"] == "deviation"]
    assert dev and dev[0]["approved"] is False
    assert dev[0]["expected"] == "read"


def test_deviation_approved_gets_inserted(kb, tmp_path):
    def approve(info):
        return info.get("kind") == "deviation"
    _, _, loop, _, events = _loop([], kb, tmp_path,
                                  plan_approval_callback=approve)
    plan = TaskPlan("t", [PlanStep("read", {"path": "a.txt"}, "read it")])
    plan.state = EXECUTING
    plan.mark_step(0, "active")
    loop.active_plan = plan
    result = loop._guarded_execute(ToolCall("d-1", "bash", {"cmd": "echo hi"}))
    assert "PLAN DEVIATION BLOCKED" not in result
    assert len(plan.steps) == 2  # deviation became a real plan step
    assert plan.steps[1].status == "done"  # and its outcome was tracked
    dev = [e for e in events if e["kind"] == "deviation"]
    assert dev and dev[0]["approved"] is True


# -- verification loops ----------------------------------------------------
def _flaky_checker(tmp_path, fail_times: int):
    """A 'test command' that fails `fail_times` times, then passes."""
    counter = tmp_path / "counter.txt"
    checker = tmp_path / "check.py"
    checker.write_text(
        "import sys, pathlib\n"
        f"p = pathlib.Path({str(counter)!r})\n"
        "n = int(p.read_text()) if p.exists() else 0\n"
        "p.write_text(str(n + 1))\n"
        f"sys.exit(0 if n >= {fail_times} else 1)\n")
    return f"{sys.executable} {checker}", counter


def test_verification_retries_failing_tests(kb, tmp_path):
    steps = _plan_json(("write", {"path": "out.txt", "content": "data"},
                        "write output"))
    verify_cmd, counter = _flaky_checker(tmp_path, fail_times=1)
    _, _, loop, _, events = _loop(
        [{"text": steps}], kb, tmp_path,
        policy_kw={"approval_callback": lambda findings: True},
        plan_approval_callback=lambda info: True,
        verify_command=verify_cmd, verify_max_retries=2)
    result = loop.run("produce the output", plan_first=True)
    assert loop.last_plan.state == "verified"
    assert "VERIFIED" in result
    assert int(counter.read_text()) == 2  # failed once, retried, passed
    verify_events = [e for e in events if e["kind"] == "verify"]
    assert [e["status"] for e in verify_events] == ["start", "fail",
                                                   "start", "pass"]


def test_verification_persistent_failure_reported_honestly(kb, tmp_path):
    steps = _plan_json(("write", {"path": "out.txt", "content": "data"},
                        "write output"))
    verify_cmd, counter = _flaky_checker(tmp_path, fail_times=99)
    _, _, loop, _, _ = _loop(
        [{"text": steps}], kb, tmp_path,
        policy_kw={"approval_callback": lambda findings: True},
        plan_approval_callback=lambda info: True,
        verify_command=verify_cmd, verify_max_retries=2)
    result = loop.run("produce the output", plan_first=True)
    assert loop.last_plan.state == "failed"
    assert "NOT VERIFIED" in result
    assert "VERIFIED ✓" not in result
    # Bounded: 1 initial attempt + 2 retries.
    assert int(counter.read_text()) == 3


def test_verification_discloses_guard_denials(tmp_path):
    # Denials during a run must appear in the verification report — never
    # hidden. And no denials means no false disclosure.
    from aegis.planning import verify_plan
    plan = TaskPlan("t", [PlanStep("write", {"path": "f.txt"}, "")])
    plan.steps[0].status = "done"
    (tmp_path / "f.txt").write_text("x")
    audit = [{"event": "tool_call", "tool": "bash", "verdict": "deny",
              "output_excerpt": "denied: evil pattern"}]
    vr = verify_plan(plan, tmp_path, audit)
    assert vr.ok  # the plan itself still verified
    assert "1 guard denial(s)" in vr.report()
    vr2 = verify_plan(plan, tmp_path, [])
    assert "guard denial" not in vr2.report()


def test_cli_planexec_without_yes_denies(kb, tmp_path, monkeypatch):
    import aegis.cli as cli
    from aegis import providers as prov_mod
    script = [{"text": _plan_json(
        ("write", {"path": "x.txt", "content": "hi"}, "write it"))}]
    monkeypatch.setattr(prov_mod, "get_provider",
                        lambda name="", model="": MockProvider(script))
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["planexec", "write the file"])
    assert rc == 2  # plan proposed, not approved, nothing executed
    assert not (tmp_path / "x.txt").exists()


def test_cli_planexec_yes_executes_and_verifies(kb, tmp_path, monkeypatch):
    import aegis.cli as cli
    from aegis import providers as prov_mod
    script = [{"text": _plan_json(
        ("write", {"path": "x.txt", "content": "hi"}, "write it"))}]
    monkeypatch.setattr(prov_mod, "get_provider",
                        lambda name="", model="": MockProvider(script))
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["planexec", "write the file", "--yes"])
    assert rc == 0
    assert (tmp_path / "x.txt").read_text() == "hi"


# -- plan persistence ------------------------------------------------------
def test_plan_persists_across_resume(kb, tmp_path):
    steps = _plan_json(("write", {"path": "p.txt", "content": "x"},
                        "write it"))
    _, session, loop, _, _ = _loop(
        [{"text": steps}], kb, tmp_path,
        plan_approval_callback=lambda info: True)
    conv = session_mod.new_session("resume-plan-test")
    loop.conversation_id = conv["id"]
    loop.history = []
    loop.run("write it", plan_first=True)
    assert loop.last_plan.state == "verified"

    loop2 = AgentLoop(MockProvider([]), kb, session, cwd=tmp_path,
                      on_text=lambda s: None)
    assert loop2.attach_conversation(conv["id"]) is True
    assert loop2.active_plan is not None
    assert loop2.active_plan.state == "verified"
    assert [s.status for s in loop2.active_plan.steps] == ["done"]
    assert loop2.active_plan.task == "write it"


# -- complexity heuristic --------------------------------------------------
def test_task_looks_complex():
    assert task_looks_complex("write a parser, then add tests for it")
    assert task_looks_complex("plan the migration of auth to OAuth")
    assert task_looks_complex("step 1: scan the repo. step 2: fix findings.")
    assert task_looks_complex("create the table, add the index, backfill rows")
    assert not task_looks_complex("what is SQL injection?")
    assert not task_looks_complex("hello")
    assert not task_looks_complex("")


# -- /commit on a REAL git repo --------------------------------------------
def _init_repo(path):
    path.mkdir(parents=True, exist_ok=True)
    for args in (["init"], ["config", "user.email", "t@t.test"],
                 ["config", "user.name", "t"]):
        subprocess.run(["git"] + args, cwd=path, check=True,
                       capture_output=True)
    return path


def _commit_all(path, msg="init"):
    subprocess.run(["git", "add", "-A"], cwd=path, check=True,
                   capture_output=True)
    subprocess.run(["git", "commit", "-m", msg], cwd=path, check=True,
                   capture_output=True)


def test_commit_flow_real_repo(tmp_path):
    repo = _init_repo(tmp_path / "repo")
    (repo / "agent.py").write_text("x = 1\n")
    _commit_all(repo)
    (repo / "agent.py").write_text("x = 1\ny = 2\n")
    res = gitcommit.commit_flow(repo, paths=["agent.py"],
                                approve=lambda m: True,
                                on_text=lambda s: None)
    assert res["ok"], res
    assert res["message"].startswith("chore(")
    assert "agent.py" in res["message"]
    assert "+1" in res["message"] and "-0" in res["message"]
    log = subprocess.run(["git", "log", "--format=%H %s", "-1"], cwd=repo,
                         capture_output=True, text=True).stdout
    assert res["sha"] in log
    assert "agent.py" in log  # message reflects the diff


def test_commit_refuses_clean_tree(tmp_path):
    repo = _init_repo(tmp_path / "repo")
    (repo / "a.txt").write_text("hi\n")
    _commit_all(repo)
    res = gitcommit.commit_flow(repo, paths=["a.txt"],
                                approve=lambda m: True)
    assert not res["ok"]
    assert "nothing to commit" in res["error"]


def test_commit_outside_repo(tmp_path):
    res = gitcommit.commit_flow(tmp_path, paths=["a.txt"])
    assert not res["ok"]
    assert "not a git repo" in res["error"]


def test_commit_never_blind_adds(tmp_path):
    repo = _init_repo(tmp_path / "repo")
    (repo / "a.txt").write_text("a\n")
    (repo / "b.txt").write_text("b\n")
    _commit_all(repo)
    (repo / "a.txt").write_text("a2\n")
    (repo / "b.txt").write_text("b2\n")
    res = gitcommit.commit_flow(repo, paths=["a.txt"],
                                approve=lambda m: True,
                                on_text=lambda s: None)
    assert res["ok"], res
    assert res["staged"] == ["a.txt"]
    # b.txt must still be unstaged/uncommitted.
    status = subprocess.run(["git", "status", "--porcelain"], cwd=repo,
                            capture_output=True, text=True).stdout
    assert "b.txt" in status
    last = subprocess.run(["git", "show", "--name-only", "--format="],
                          cwd=repo, capture_output=True, text=True).stdout
    assert "a.txt" in last and "b.txt" not in last


def test_commit_aborts_on_secret_in_diff(tmp_path):
    repo = _init_repo(tmp_path / "repo")
    (repo / "app.py").write_text("x = 1\n")
    _commit_all(repo)
    secret = "ghp_abcdefghij1234567890abcdefghij12"
    (repo / "app.py").write_text(f'token = "{secret}"\n')
    res = gitcommit.commit_flow(repo, paths=["app.py"],
                                approve=lambda m: True,
                                on_text=lambda s: None)
    assert not res["ok"]
    assert "secret" in res["error"].lower()
    assert secret not in res["error"]  # values never echoed
    # Nothing was committed.
    log = subprocess.run(["git", "log", "--oneline"], cwd=repo,
                         capture_output=True, text=True).stdout
    assert len(log.strip().splitlines()) == 1


def test_commit_diff_display_is_redacted(tmp_path):
    repo = _init_repo(tmp_path / "repo")
    (repo / "app.py").write_text("x = 1\n")
    _commit_all(repo)
    secret = "ghp_abcdefghij1234567890abcdefghij12"
    (repo / "app.py").write_text(f'token = "{secret}"\n')
    subprocess.run(["git", "add", "--", "app.py"], cwd=repo, check=True,
                   capture_output=True)
    shown = gitcommit.redacted_diff(gitcommit.staged_diff_text(repo))
    assert secret not in shown
    assert "[REDACTED:" in shown
    hits = gitcommit.find_staged_secrets(gitcommit.staged_diff_text(repo))
    assert hits and hits[0]["kind"] == "github_token"
    assert all("value" not in h for h in hits)


def test_commit_message_from_diff_multi_file(tmp_path):
    repo = _init_repo(tmp_path / "repo")
    (repo / "docs").mkdir()
    (repo / "docs" / "a.md").write_text("a\n")
    (repo / "docs" / "b.md").write_text("b\n")
    _commit_all(repo)
    (repo / "docs" / "a.md").write_text("a\nmore\n")
    (repo / "docs" / "b.md").write_text("b\nmore\n")
    res = gitcommit.commit_flow(repo, paths=["docs/a.md", "docs/b.md"],
                                approve=lambda m: True,
                                on_text=lambda s: None)
    assert res["ok"], res
    assert res["message"].startswith("docs(docs):")
    assert "2 file(s) changed" in res["message"]
