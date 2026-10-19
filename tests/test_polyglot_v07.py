"""v0.7 Lane A: polyglot toolchain detection, repomap, coding skills,
TDD loop. Fixture mini-projects are created at test time (python, node,
go, rust): python/node toolchains run for real; go/rust prove detection
+ missing-tool reporting (toolchains not installed here)."""

import json

import pytest

from aegis import polyglot, repomap
from aegis import skills as skills_mod
from aegis import tdd as tdd_mod
from aegis.agent import AgentLoop
from aegis.guard import Policy, create_session
from aegis.providers import MockProvider
from aegis.tools.registry import TOOL_NAMES

FAKE_KEY = "sk-ant-fake0123456789abcdef"


# -- fixture mini-projects -------------------------------------------------

def _py_project(root, buggy=False):
    (root / "pyproject.toml").write_text(
        '[project]\nname = "calc"\nversion = "0.1.0"\n')
    body = "return a - b" if buggy else "return a + b"
    (root / "calc.py").write_text(f"def add(a, b):\n    {body}\n")
    (root / "test_calc.py").write_text(
        "import unittest\nfrom calc import add\n\n"
        "class TAdd(unittest.TestCase):\n"
        "    def test_add(self):\n"
        "        self.assertEqual(add(2, 3), 5)\n")
    return root


def _node_project(root):
    (root / "package.json").write_text(json.dumps({
        "name": "hello", "version": "1.0.0",
        "scripts": {"test": "node run_tests.js",
                    "build": "node -e \"console.log('build ok')\""}}))
    (root / "index.js").write_text("console.log('hello');\n")
    (root / "run_tests.js").write_text(
        "function add(a, b) { return a + b; }\n"
        "const assert = require('assert');\n"
        "assert.strictEqual(add(2, 3), 5);\n"
        "console.log('1 test passed');\n")
    return root


def _go_project(root):
    (root / "go.mod").write_text("module example.com/hello\n\ngo 1.21\n")
    (root / "main.go").write_text(
        "package main\n\nimport \"fmt\"\n\nfunc Add(a, b int) int { return a + b }\n\n"
        "func main() { fmt.Println(Add(2, 3)) }\n")
    (root / "main_test.go").write_text(
        "package main\n\nimport \"testing\"\n\n"
        "func TestAdd(t *testing.T) {\n"
        "    if Add(2, 3) != 5 { t.Fatal(\"bad\") }\n}\n")
    return root


def _rust_project(root):
    (root / "Cargo.toml").write_text(
        '[package]\nname = "hello"\nversion = "0.1.0"\nedition = "2021"\n')
    src = root / "src"
    src.mkdir()
    (src / "main.rs").write_text(
        "fn add(a: i32, b: i32) -> i32 { a + b }\n\n"
        "fn main() { println!(\"{}\", add(2, 3)); }\n\n"
        "#[cfg(test)]\nmod tests {\n"
        "    use super::*;\n"
        "    #[test]\n    fn adds() { assert_eq!(add(2, 3), 5); }\n}\n")
    return root


def _loop(script, kb, cwd, mode="dev"):
    provider = MockProvider(script)
    policy = Policy(name="polyglot-test", allowed_tools=set(TOOL_NAMES),
                    mode=mode)
    session = create_session(policy, kb)
    return provider, session, AgentLoop(provider, kb, session, cwd=cwd)


# -- detection ---------------------------------------------------------------

def test_detect_python_project(tmp_path):
    _py_project(tmp_path)
    hits = polyglot.detect_languages(tmp_path)
    assert hits and hits[0].language == "python"
    assert hits[0].strong and "pyproject.toml" in hits[0].via


def test_detect_node_project(tmp_path):
    _node_project(tmp_path)
    hits = polyglot.detect_languages(tmp_path)
    assert hits[0].language == "node" and hits[0].strong


def test_detect_go_project(tmp_path):
    _go_project(tmp_path)
    hits = polyglot.detect_languages(tmp_path)
    assert hits[0].language == "go"
    assert hits[0].build_system == "go modules"


def test_detect_rust_project(tmp_path):
    _rust_project(tmp_path)
    hits = polyglot.detect_languages(tmp_path)
    assert hits[0].language == "rust"
    assert hits[0].build_system == "cargo"


def test_detect_extension_fallback(tmp_path):
    (tmp_path / "hello.rs").write_text("fn main() {}\n")
    hits = polyglot.detect_languages(tmp_path)
    assert any(h.language == "rust" and not h.strong for h in hits)


def test_detect_nothing(tmp_path):
    assert polyglot.detect_languages(tmp_path) == []
    assert "No known project files" in \
        polyglot.toolchain_report(tmp_path)


# -- missing tools -------------------------------------------------------------

@pytest.mark.skipif(polyglot.available("go"),
                    reason="go installed here; nothing missing to report")
def test_missing_tool_reporting_go(tmp_path):
    _go_project(tmp_path)
    missing = polyglot.missing_tools(tmp_path)
    go = [m for m in missing if m["binary"] == "go"]
    assert go and go[0]["hint"]  # concrete install hint
    results = polyglot.run_tests(tmp_path)
    assert len(results) == 1
    step = results[0].steps[0]
    assert step.skipped_missing and "go" in step.skipped_missing
    assert not results[0].ok


@pytest.mark.skipif(polyglot.available("cargo"),
                    reason="cargo installed here; nothing missing to report")
def test_missing_tool_reporting_rust(tmp_path):
    _rust_project(tmp_path)
    missing = polyglot.missing_tools(tmp_path)
    assert any(m["binary"] == "cargo" and m["hint"] for m in missing)
    results = polyglot.run_build(tmp_path)
    assert not results[0].ok
    assert "cargo" in results[0].steps[0].skipped_missing


# -- real runs: python (unittest fallback) and node ------------------------------

def test_python_build_and_test_real(tmp_path):
    _py_project(tmp_path)
    builds = polyglot.run_build(tmp_path)
    assert len(builds) == 1 and builds[0].ok, builds[0].summary
    tests = polyglot.run_tests(tmp_path)
    assert len(tests) == 1 and tests[0].ok, tests[0].summary
    assert "GREEN" in tests[0].summary


def test_python_failing_suite_is_red(tmp_path):
    _py_project(tmp_path, buggy=True)
    tests = polyglot.run_tests(tmp_path)
    assert not tests[0].ok
    assert "RED" in tests[0].summary


def test_node_build_and_test_real(tmp_path):
    _node_project(tmp_path)
    builds = polyglot.run_build(tmp_path)
    assert builds and builds[0].ok, builds[0].summary
    tests = polyglot.run_tests(tmp_path)
    assert tests and tests[0].ok, tests[0].summary
    assert "GREEN" in tests[0].summary


def test_toolchain_report_marks_available(tmp_path):
    _py_project(tmp_path)
    report = polyglot.toolchain_report(tmp_path)
    assert "python" in report and "pytest" in report or "unittest" in report


# -- repomap ---------------------------------------------------------------------

def test_repomap_python_project(tmp_path):
    _py_project(tmp_path)
    m = repomap.repo_map(tmp_path)
    assert m["exists"]
    langs = {l["language"]: l["files"] for l in m["languages"]}
    assert langs.get("python", 0) >= 2
    assert m["build_system"] == "pyproject"
    assert any("pyproject.toml" in c for c in m["config_files"])
    assert m["test_layout"]["test_files"] >= 1
    text = repomap.render_repo_map(tmp_path)
    assert "python" in text and "pyproject" in text


def test_repomap_missing_dir(tmp_path):
    m = repomap.repo_map(tmp_path / "nope")
    assert m.get("error")


# -- skills ------------------------------------------------------------------------

def test_skill_build_and_test(tmp_path):
    _py_project(tmp_path)
    out = skills_mod.build(str(tmp_path))
    assert "BUILD OK" in out
    out = skills_mod.test_suite(str(tmp_path))
    assert "TESTS GREEN" in out


def test_skill_refuses_nonlocal():
    assert "refused" in skills_mod.build("https://evil.example/x")
    assert "refused" in skills_mod.test_suite("evil.example/x")


def test_skill_fix_needs_loop(tmp_path):
    _py_project(tmp_path)
    assert "needs a live agent session" in skills_mod.fix(str(tmp_path))


def test_skill_fix_refused_in_plan_mode(kb, tmp_path):
    _py_project(tmp_path, buggy=True)
    _, _, loop = _loop([], kb, tmp_path, mode="plan")
    assert "dev mode" in skills_mod.fix(str(tmp_path), loop)


def test_skill_fix_already_green(kb, tmp_path):
    _py_project(tmp_path)
    _, _, loop = _loop([], kb, tmp_path)
    assert "already GREEN" in skills_mod.fix(str(tmp_path), loop)


def test_skill_fix_drives_loop_to_green(kb, tmp_path):
    _py_project(tmp_path, buggy=True)
    script = [
        {"text": "Fixing the bug. ",
         "tool_calls": [{"name": "edit",
                         "args": {"path": "calc.py",
                                  "old_text": "return a - b",
                                  "new_text": "return a + b"}}]},
    ]
    _, _, loop = _loop(script, kb, tmp_path)
    out = skills_mod.fix(str(tmp_path), loop)
    assert "**GREEN**" in out
    assert (tmp_path / "calc.py").read_text() == \
        "def add(a, b):\n    return a + b\n"


def test_skill_refactor_reruns_tests(kb, tmp_path):
    _py_project(tmp_path)
    # text-only turn: the model changes nothing; tests must re-run green.
    _, _, loop = _loop([{"text": "Already clean, no changes needed."}],
                       kb, tmp_path)
    out = skills_mod.refactor(str(tmp_path), loop)
    assert "Tests before:" in out and "Tests after:" in out
    assert "Refactor clean" in out


def test_skill_repomap_and_index(tmp_path):
    _py_project(tmp_path)
    assert "python" in skills_mod.repomap_cmd(str(tmp_path))
    stats = skills_mod.index_cmd(str(tmp_path))
    assert "Files:" in stats
    q = skills_mod.index_cmd(f"{tmp_path} add")
    assert "calc.py" in q


# -- TDD loop ------------------------------------------------------------------------

def test_tdd_loop_green_via_mock(kb, tmp_path):
    _py_project(tmp_path, buggy=True)
    script = [
        {"text": "Fixing. ",
         "tool_calls": [{"name": "edit",
                         "args": {"path": "calc.py",
                                  "old_text": "return a - b",
                                  "new_text": "return a + b"}}]},
    ]
    _, session, loop = _loop(script, kb, tmp_path)
    res = tdd_mod.tdd_loop(loop, tmp_path, "make add() correct",
                           max_rounds=3)
    assert res["status"] == "green"
    assert "GREEN" in res["summary"]
    assert any(s["kind"] == "test_result" and s.get("green")
               for s in res["rounds"])
    events = [e["event"] for e in session.audit.read_all()]
    assert "tdd_step" in events  # every step logged


def test_tdd_loop_stuck_after_cap(kb, tmp_path):
    _py_project(tmp_path, buggy=True)
    _, _, loop = _loop([], kb, tmp_path)  # mock never fixes anything
    res = tdd_mod.tdd_loop(loop, tmp_path, "make add() correct",
                           max_rounds=2)
    assert res["status"] == "stuck"
    assert "STUCK" in res["summary"]
    assert "What was tried" in res["summary"]
    test_runs = [s for s in res["rounds"] if s["kind"] == "test_result"]
    assert len(test_runs) == 2  # capped, did not loop forever


def test_tdd_loop_refused_in_plan_mode(kb, tmp_path):
    _py_project(tmp_path)
    _, _, loop = _loop([], kb, tmp_path, mode="plan")
    res = tdd_mod.tdd_loop(loop, tmp_path, "x")
    assert res["status"] == "refused"


def test_tdd_loop_no_tests(tmp_path):
    class _Loop:
        mode = "dev"
        guard = type("G", (), {"audit": type(
            "A", (), {"record": lambda self, e: None})()})()
        def on_text(self, s):
            pass
        def run(self, prompt):
            raise AssertionError("must not run with no toolchain")
    res = tdd_mod.tdd_loop(_Loop(), tmp_path, "x")
    assert res["status"] == "no_tests"


# -- secrets: never echoed -------------------------------------------------------------

def test_test_output_redacted(tmp_path):
    _py_project(tmp_path)
    (tmp_path / "test_leak.py").write_text(
        "import unittest\n"
        "class TLeak(unittest.TestCase):\n"
        "    def test_leak(self):\n"
        f"        print('api_key=\"{FAKE_KEY}\" loaded')\n"
        "        self.assertTrue(False, 'boom')\n")
    results = polyglot.run_tests(tmp_path)
    blob = "\n".join(r.steps[0].output for r in results if r.steps)
    assert FAKE_KEY not in blob
    assert "[REDACTED:" in blob
    assert not results[0].ok  # the suite really failed; nothing faked
