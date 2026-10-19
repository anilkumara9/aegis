"""v0.7 Lane D: coding proving ground harness tests.

Verifies the CODING eval battery itself — real execution, real scoring:
- schema validity of every evals/COD-*.yaml
- the full battery passes with the known-good scripted solutions
- a deliberately broken solution FAILS (scoring is real, not self-graded)
- hidden-test timeouts are handled, not hung
- fixtures are hermetic (nothing written outside /tmp, temp dirs removed)
- secret-shaped fixture strings are redacted in all surfaced output
- guard denials on coding turns surface as failures
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest
import yaml

import aegis.config as _config

# Deterministic, offline: never let the eval shell out to docker.
_config.SANDBOX = "local"

import os
os.environ["AEGIS_SANDBOX"] = "local"

from aegis import eval_coding
from aegis.eval_coding import (
    CodingTask,
    HiddenTest,
    load_coding_tasks,
    render_coding_section,
    run_coding_battery,
    run_coding_task,
    splice_coding_section,
)

EVALS_DIR = Path(__file__).resolve().parent.parent / "evals"
ID_RE = re.compile(r"^COD-\d+$")
FAKE_KEY = "sk_test_F4K3F4K3F4K3F4K3"  # fake, pattern-matching only


@pytest.fixture(scope="module")
def tasks():
    return load_coding_tasks(EVALS_DIR)


@pytest.fixture(scope="module")
def kb():
    from aegis.kb import KB
    return KB.load()


def test_coding_evals_directory_nonempty(tasks):
    assert tasks, "no COD-*.yaml tasks found in evals/"


def test_ids_unique_and_wellformed(tasks):
    ids = [t.id for t in tasks]
    assert len(ids) == len(set(ids)), "duplicate coding task ids"
    for i in ids:
        assert ID_RE.match(i), f"bad coding task id format: {i!r}"


def test_schema_validity(tasks):
    for t in tasks:
        assert t.name, f"{t.id}: name required"
        assert t.language in eval_coding.LANGUAGES, \
            f"{t.id}: unknown language {t.language!r}"
        assert t.task_type in eval_coding.TASK_TYPES, \
            f"{t.id}: unknown task_type {t.task_type!r}"
        assert t.description.strip(), f"{t.id}: description required"
        assert t.prompt.strip(), f"{t.id}: prompt required"
        assert t.script, f"{t.id}: script must be non-empty"
        for n, turn in enumerate(t.script):
            assert isinstance(turn, dict), f"{t.id} turn {n}: must be a mapping"
            for tc in turn.get("tool_calls") or []:
                assert isinstance(tc.get("name"), str) and tc["name"], \
                    f"{t.id} turn {n}: tool_call needs a name"
                assert isinstance(tc.get("args") or {}, dict), \
                    f"{t.id} turn {n}: args must be a mapping"
        assert t.hidden_tests, f"{t.id}: hidden_tests must be non-empty"
        for ht in t.hidden_tests:
            assert ht.run, f"{t.id}: hidden test needs a run command"
            assert ht.timeout_s > 0, f"{t.id}: hidden test needs a timeout"
        assert isinstance(t.enforced, bool), \
            f"{t.id}: enforced must be bool"
        if t.enforced:
            assert not t.known_fail_reason.strip(), \
                f"{t.id}: enforced tasks must not carry a fail reason"
        else:
            assert t.known_fail_reason.strip(), \
                f"{t.id}: non-enforced tasks must document known_fail_reason"
        for f in t.files + t.hidden_files:
            assert f.get("path") and isinstance(f.get("content", ""), str), \
                f"{t.id}: file entries need path + content"
        if t.task_type == "refactor":
            assert t.require_changed, \
                f"{t.id}: refactor tasks must name require_changed files"
        if t.task_type == "add_tests":
            assert t.new_test_file and t.min_new_tests > 0, \
                f"{t.id}: add_tests tasks need new_test_file + min_new_tests"


def test_raw_yaml_matches_loaded_fields(tasks):
    raw = yaml.safe_load((EVALS_DIR / "COD-001.yaml").read_text())
    t = next(x for x in tasks if x.id == "COD-001")
    assert t.name == raw["name"]
    assert t.language == raw["language"]
    assert t.task_type == raw["task_type"]
    assert t.enforced == raw["enforced"]


def test_language_type_coverage(tasks):
    by_lang: dict[str, set[str]] = {}
    for t in tasks:
        by_lang.setdefault(t.language, set()).add(t.task_type)
    assert "python" in by_lang and "javascript" in by_lang, \
        "battery must cover python and javascript"
    for core in ("write", "debug", "refactor", "add_tests"):
        assert core in by_lang["python"], f"python missing {core}"
        assert core in by_lang["javascript"], f"javascript missing {core}"
    # Go/Rust are UNBUILT in this environment (no toolchains, no network):
    # they must not appear as simulated passes.
    assert "go" not in by_lang and "rust" not in by_lang, \
        "go/rust must be UNBUILT, never simulated"


def test_full_battery_passes_with_known_good_solutions(kb):
    """The REAL battery: 11 tasks through the real AgentLoop + real guard,
    scored by actually executing hidden tests. Enforced tasks must pass;
    enforced:false tasks are recorded, never failed (genuine guard
    false positives live there — see COD-001/005/006/011)."""
    battery = run_coding_battery(EVALS_DIR, kb)
    problems = []
    for r in battery.results:
        if r.task.enforced and r.status != "pass":
            problems.append(f"{r.task.id} ({r.task.name}): {r.status} — "
                            f"{r.detail}")
    assert not problems, "enforced battery failures:\n" + "\n".join(problems)
    assert not battery.enforced_failures()


def test_former_guard_false_positives_now_pass(kb):
    """v0.7 integration fixed the guard FP class this battery found
    (shell-syntax KB patterns firing on benign code writes): COD-001,
    COD-005, COD-006 and COD-011 now PASS. If any of them fails again,
    the FP class has regressed — see tests/test_guard_write_fp_v07.py."""
    battery = run_coding_battery(EVALS_DIR, kb)
    for tid in ("COD-001", "COD-005", "COD-006", "COD-011"):
        r = next(r for r in battery.results if r.task.id == tid)
        assert r.status == "pass", f"{tid}: {r.status} — {r.detail}"
    assert not battery.enforced_failures()


def test_battery_is_deterministic(kb, tasks):
    t = next(x for x in tasks if x.id == "COD-002")
    r1 = run_coding_task(t, kb)
    r2 = run_coding_task(t, kb)
    assert (r1.status, r2.status) == ("pass", "pass")


def test_broken_solution_fails(kb, tasks):
    """Scoring is real: a wrong fix must FAIL the hidden tests."""
    t = next(x for x in tasks if x.id == "COD-002")
    bad = dataclasses.replace(t, script=[
        {"text": "Wrong fix.",
         "tool_calls": [{"name": "edit", "args": {
             "path": "stats.py",
             "old_text": "    return sum(nums) / (len(nums) + 1)",
             "new_text": "    return sum(nums) / (len(nums) + 2)"}}]},
    ])
    r = run_coding_task(bad, kb)
    assert r.status == "fail", f"broken solution scored {r.status}"
    assert r.hidden and not r.hidden[0]["ok"]


def test_noop_refactor_fails_require_changed(kb, tasks):
    """A refactor that changes nothing must fail the require_changed gate."""
    t = next(x for x in tasks if x.id == "COD-003")
    noop = dataclasses.replace(t, script=[{"text": "Doing nothing."}])
    r = run_coding_task(noop, kb)
    assert r.status == "fail"
    assert "unchanged" in r.detail


def test_hidden_test_timeout_is_handled(kb):
    t = CodingTask(
        id="COD-TIMEOUT", name="timeout probe", language="python",
        task_type="write", description="d", prompt="d", files=[],
        hidden_files=[], script=[{"text": "noop"}],
        hidden_tests=[HiddenTest(run=["sleep", "30"], timeout_s=1,
                                 name="sleeper")],
        require_changed=[], min_new_tests=0, new_test_file="",
        enforced=False, known_fail_reason="timeout probe")
    r = run_coding_task(t, kb)
    assert r.status == "timeout", f"expected timeout, got {r.status}"
    assert r.hidden and r.hidden[0]["timed_out"]


def test_missing_toolchain_skips_honestly(kb, monkeypatch):
    import shutil
    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which",
        lambda exe, *a, **k: None if exe == "node" else real_which(exe, *a, **k))
    t = CodingTask(
        id="COD-SKIP", name="skip probe", language="javascript",
        task_type="write", description="d", prompt="d", files=[],
        hidden_files=[], script=[{"text": "noop"}],
        hidden_tests=[HiddenTest(run=["node", "--version"])],
        require_changed=[], min_new_tests=0, new_test_file="",
        enforced=True, known_fail_reason="")
    r = run_coding_task(t, kb)
    assert r.status == "skipped"
    assert "node" in r.detail


def test_guard_denial_on_coding_turn_is_a_failure(kb):
    """Benign coding turns must not trip the guard; a denial fails the task."""
    t = CodingTask(
        id="COD-DENY", name="denial probe", language="python",
        task_type="write", description="d", prompt="d", files=[],
        hidden_files=[], script=[{
            "text": "Hostile call that must be denied.",
            "tool_calls": [{"name": "bash",
                            "args": {"cmd": "rm -rf / --no-preserve-root"}}]}],
        hidden_tests=[HiddenTest(run=["true"])],
        require_changed=[], min_new_tests=0, new_test_file="",
        enforced=False, known_fail_reason="denial probe")
    r = run_coding_task(t, kb)
    assert r.status == "fail", f"expected fail, got {r.status}"
    assert "guard denied" in r.detail


def test_fixtures_are_hermetic(kb, tasks, tmp_path):
    """Nothing is written outside /tmp: repo tree unchanged by a run."""
    repo = Path(__file__).resolve().parent.parent
    before = {p.relative_to(repo) for p in repo.rglob("*") if p.is_file()
              and ".git" not in p.parts}
    t = next(x for x in tasks if x.id == "COD-004")
    r = run_coding_task(t, kb)
    assert r.status == "pass"
    after = {p.relative_to(repo) for p in repo.rglob("*") if p.is_file()
             and ".git" not in p.parts}
    assert before == after, \
        f"eval run wrote outside /tmp: {sorted(str(p) for p in after - before)}"


def test_secrets_redacted_in_surfaced_output(kb):
    """A secret-shaped string echoed by a hidden test must appear only as
    [REDACTED:...] in results, details, and the scorecard section."""
    t = CodingTask(
        id="COD-REDACT", name="redaction probe", language="python",
        task_type="write", description="d", prompt="d",
        files=[{"path": "config.py",
                "content": f'KEY = "{FAKE_KEY}"\n'}],
        hidden_files=[], script=[{"text": "noop"}],
        hidden_tests=[HiddenTest(
            run=["sh", "-c", f"echo LEAK={FAKE_KEY}; exit 1"],
            timeout_s=10, name="leaker")],
        require_changed=[], min_new_tests=0, new_test_file="",
        enforced=False, known_fail_reason="redaction probe")
    r = run_coding_task(t, kb)
    assert r.status == "fail"
    blob = r.detail + str(r.hidden)
    assert FAKE_KEY not in blob, "raw secret leaked into eval output"
    assert "[REDACTED:" in blob, "expected a redaction marker in output"

    battery = run_coding_battery(EVALS_DIR, kb)
    section = render_coding_section(battery, "2026-10-19 00:00 UTC")
    assert FAKE_KEY not in section, "raw secret leaked into scorecard"
    # COD-005 stages the fake key as a fixture; the section must not echo it.
    assert "COD-005" in section


def test_scorecard_section_renders_and_splices(tmp_path):
    battery = run_coding_battery(EVALS_DIR)
    section = render_coding_section(battery, "2026-10-19 00:00 UTC")
    assert "<!-- CODING-EVAL-SECTION -->" in section
    assert "<!-- /CODING-EVAL-SECTION -->" in section
    assert "## Coding proving ground" in section
    assert "| python |" in section
    assert "COD-001" in section

    base = tmp_path / "SCORECARD.md"
    base.write_text("# Aegis Guard Eval Scorecard\n\nbody\n")
    merged = splice_coding_section(base, section)
    assert merged.count("<!-- CODING-EVAL-SECTION -->") == 1
    assert "# Aegis Guard Eval Scorecard" in merged
    # Idempotent: splicing twice keeps exactly one section.
    base.write_text(merged)
    merged2 = splice_coding_section(base, section)
    assert merged2.count("<!-- CODING-EVAL-SECTION -->") == 1


def test_eval_cli_suite_coding_runs_battery():
    """`aegis eval --suite coding` runs the real battery end to end."""
    from aegis.cli import main
    rc = main(["eval", "--suite", "coding"])
    assert rc == 0, "coding suite should exit 0 when all enforced tasks pass"
    staged = (Path(__file__).resolve().parent.parent
              / "docs" / "SCORECARD_CODING.md")
    assert staged.exists(), "cmd_eval must stage docs/SCORECARD_CODING.md"
    text = staged.read_text(encoding="utf-8")
    assert FAKE_KEY not in text
