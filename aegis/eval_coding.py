"""v0.7 Lane D — coding proving ground: scripted coding eval battery.

Extends ``aegis eval`` (v0.6 proving ground) with CODING tasks across
languages. Same philosophy as ``aegis/eval_runner.py``:

* Each task in ``evals/COD-*.yaml`` drives the REAL ``AgentLoop`` with a
  scripted ``MockProvider`` (deterministic "solution turns") and the REAL
  guard. The mock is the stand-in for the agent under test: a known-good
  script passes the hidden tests, a broken script fails them.
* Scoring comes from ACTUALLY RUNNING a hidden test suite via subprocess
  (timeout-capped, cwd = the task fixture dir under /tmp). Never
  self-graded by the model.
* Fixtures are hermetic: created at eval time under /tmp, file tools are
  confined to the fixture cwd, no network.

Seam into v0.6 (documented merge point: docs/EVAL_CODING_MERGE.md):
  - This module is SELF-CONTAINED — it does not import eval_runner, so it
    works both before and after the v0.6 merge.
  - ``aegis eval --suite coding|security|all`` (see cli.cmd_eval, Lane D
    superset) runs both suites; the coding scorecard section is spliced
    into docs/SCORECARD.md by marker.

Secrets: every string this module surfaces (details, test-output
excerpts, scorecard rows) passes through ``aegis.detect.secrets.redact``
before it is returned, printed, or written. Fixture contents may contain
secret-shaped strings (COD-005 exercises exactly this); they are never
echoed raw.

Task types:
  write      — implement a function/module from a natural-language spec.
  debug      — given broken code + a failing test, make the tests pass.
  refactor   — rewrite for clarity; behavior preserved (original tests
               must still pass AND the file must actually change).
  add_tests  — add tests to untested code; the new tests must exist,
               be collected (>0), and pass.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

# Force the local bash sandbox for deterministic, offline eval runs. This
# must happen before aegis.config is imported (it reads the env at import).
os.environ.setdefault("AEGIS_SANDBOX", "local")

from . import guard as guard_mod  # noqa: E402
from .agent import AgentLoop  # noqa: E402
from .detect import secrets as sec  # noqa: E402
from .kb import KB  # noqa: E402
from .providers import MockProvider  # noqa: E402

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CODING_EVALS_DIR = REPO_ROOT / "evals"

LANGUAGES = ("python", "javascript", "c")
TASK_TYPES = ("write", "debug", "refactor", "add_tests")

ID_RE = re.compile(r"^COD-\d+$")
DENY_VERDICTS = {"deny", "denied"}  # guard intervened on a coding call
PROVIDER_ERROR_MARK = "[provider error:"

# Placeholder expanded to the interpreter running the eval (the one with
# pytest installed). Keeps hidden python tests hermetic without hard-coding
# a venv path.
PY_PLACEHOLDER = "python"


@dataclass
class HiddenTest:
    run: list[str]
    timeout_s: int = 60
    name: str = ""

    def argv(self) -> list[str]:
        return [sys.executable if a == PY_PLACEHOLDER else a
                for a in self.run]


@dataclass
class CodingTask:
    id: str
    name: str
    language: str
    task_type: str
    description: str
    prompt: str
    files: list[dict]          # fixture files staged before the agent runs
    hidden_files: list[dict]  # hidden test/support files staged by the runner
    script: list[dict]         # MockProvider turns (the "solution")
    hidden_tests: list[HiddenTest]
    require_changed: list[str]  # refactor: must differ from fixture original
    min_new_tests: int          # add_tests: new test file must define >= N tests
    new_test_file: str          # add_tests: the test file the agent must add
    enforced: bool
    known_fail_reason: str


@dataclass
class TaskResult:
    task: CodingTask
    status: str  # pass | fail | timeout | skipped | error
    detail: str = ""
    hidden: list[dict] = field(default_factory=list)  # per-test outcomes
    provider_error: bool = False


def _require_yaml() -> None:
    if yaml is None:
        raise RuntimeError("PyYAML is required for the coding eval battery "
                           "(pip install pyyaml)")


def load_coding_tasks(evals_dir: Path | str | None = None) -> list[CodingTask]:
    """Load and minimally parse every evals/COD-*.yaml (schema in tests)."""
    _require_yaml()
    d = Path(evals_dir or DEFAULT_CODING_EVALS_DIR)
    tasks = []
    for path in sorted(d.glob("COD-*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        tasks.append(CodingTask(
            id=str(raw.get("id", "")),
            name=str(raw.get("name", "")),
            language=str(raw.get("language", "")),
            task_type=str(raw.get("task_type", "")),
            description=str(raw.get("description", "")),
            prompt=str(raw.get("prompt", "")),
            files=list(raw.get("files") or []),
            hidden_files=list(raw.get("hidden_files") or []),
            script=list(raw.get("script") or []),
            hidden_tests=[HiddenTest(
                run=list(t.get("run") or []),
                timeout_s=int(t.get("timeout_s") or 60),
                name=str(t.get("name") or ""),
            ) for t in (raw.get("hidden_tests") or [])],
            require_changed=list(raw.get("require_changed") or []),
            min_new_tests=int(raw.get("min_new_tests") or 0),
            new_test_file=str(raw.get("new_test_file") or ""),
            enforced=bool(raw.get("enforced", False)),
            known_fail_reason=str(raw.get("known_fail_reason", "") or ""),
        ))
    return tasks


def _redact(text: str) -> str:
    """Redact secret-shaped spans from anything we surface. Never echoes."""
    return sec.redact(text or "")[0]


def _mock_script(task: CodingTask) -> list[dict]:
    """Script turns stripped of eval-only keys, for MockProvider."""
    turns = []
    for turn in task.script:
        t = {"text": turn.get("text", "")}
        calls = []
        for tc in turn.get("tool_calls") or []:
            calls.append({"name": tc.get("name", ""),
                          "args": dict(tc.get("args") or {})})
        if calls:
            t["tool_calls"] = calls
        turns.append(t)
    return turns


def _tool_available(exe: str) -> bool:
    return shutil.which(exe) is not None


def _language_toolchain(task: CodingTask) -> str | None:
    """Return the missing toolchain executable, or None if runnable."""
    if task.language == "python":
        return None  # hidden tests run on sys.executable itself
    if task.language == "javascript":
        return None if _tool_available("node") else "node"
    if task.language == "c":
        return None if _tool_available("gcc") else "gcc"
    return f"unknown-language:{task.language}"


def _run_hidden_tests(task: CodingTask, fixture_dir: Path) -> list[dict]:
    """Actually execute every hidden test. Real subprocess, timeout-capped."""
    outcomes = []
    for ht in task.hidden_tests:
        argv = ht.argv()
        started = time.time()
        try:
            proc = subprocess.run(
                argv, cwd=str(fixture_dir), capture_output=True, text=True,
                timeout=ht.timeout_s)
            elapsed = time.time() - started
            output = (proc.stdout or "") + (proc.stderr or "")
            outcomes.append({
                "name": ht.name or " ".join(argv[:3]),
                "ok": proc.returncode == 0,
                "timed_out": False,
                "returncode": proc.returncode,
                "elapsed_s": round(elapsed, 2),
                # Redacted excerpt: fixture code may hold secret-shaped
                # strings (COD-005); they must never leak into results.
                "output": _redact(output[-2000:]),
            })
        except subprocess.TimeoutExpired:
            outcomes.append({
                "name": ht.name or " ".join(argv[:3]),
                "ok": False, "timed_out": True, "returncode": None,
                "elapsed_s": ht.timeout_s, "output": "",
            })
        except Exception as exc:  # harness failure, recorded not raised
            outcomes.append({
                "name": ht.name or " ".join(argv[:3]),
                "ok": False, "timed_out": False, "returncode": None,
                "elapsed_s": round(time.time() - started, 2),
                "output": _redact(f"harness error: {exc}"),
            })
    return outcomes


def _count_tests_in_file(path: Path, language: str) -> int:
    """Count test definitions in a newly added test file (real file read)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    if language == "python":
        return len(re.findall(r"^\s*def\s+test_\w+", text, re.M))
    if language == "javascript":
        return len(re.findall(r"\btest\s*\(", text))
    if language == "c":
        return len(re.findall(r"\bTEST\s*\(", text))
    return 0


def run_coding_task(task: CodingTask, kb: KB) -> TaskResult:
    """Run one coding task: real agent loop, then real hidden-test execution.

    The scripted MockProvider is the "agent under test" — its turns write /
    edit the fixture. Scoring is purely the hidden suite's real outcome.
    """
    missing = _language_toolchain(task)
    if missing:
        return TaskResult(task, "skipped",
                          detail=f"toolchain unavailable: {missing}")

    fixture_dir = Path(tempfile.mkdtemp(prefix="aegis-coding-eval-"))
    state_dir = tempfile.mkdtemp(prefix="aegis-coding-state-")
    old_state = os.environ.get("AEGIS_STATE_DIR")
    os.environ["AEGIS_STATE_DIR"] = state_dir
    originals: dict[str, str] = {}
    try:
        for f in task.files:
            p = fixture_dir / f["path"]
            p.parent.mkdir(parents=True, exist_ok=True)
            content = f.get("content", "")
            p.write_text(content, encoding="utf-8")
            originals[f["path"]] = content
        # Hidden files (test suites, support code): staged by the runner,
        # never part of the agent-visible fixture.
        for f in task.hidden_files:
            p = fixture_dir / f["path"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(f.get("content", ""), encoding="utf-8")
        sess = guard_mod.create_session(guard_mod.Policy(), kb,
                                        session_id=uuid.uuid4().hex[:12])
        loop = AgentLoop(MockProvider(_mock_script(task)), kb, sess,
                         cwd=fixture_dir,
                         max_iterations=len(task.script) + 2)
        output = loop.run(task.prompt)
        records = [r for r in sess.audit.read_all()
                   if r.get("event") == "tool_call"]
    except Exception as exc:  # harness failure, not a task verdict
        return TaskResult(task, "error",
                          detail=_redact(f"harness error: {exc}"))
    finally:
        if old_state is None:
            os.environ.pop("AEGIS_STATE_DIR", None)
        else:
            os.environ["AEGIS_STATE_DIR"] = old_state
        shutil.rmtree(state_dir, ignore_errors=True)

    provider_error = PROVIDER_ERROR_MARK in (output or "")
    if provider_error:
        shutil.rmtree(fixture_dir, ignore_errors=True)
        return TaskResult(task, "error", detail="provider error during run",
                          provider_error=True)

    # Benign coding turns must never trip the guard; a denial is a fail —
    # the agent under test produced a call the guard refused.
    denials = [r for r in records
               if str(r.get("verdict", "")).lower() in DENY_VERDICTS]
    if denials:
        shutil.rmtree(fixture_dir, ignore_errors=True)
        return TaskResult(
            task, "fail",
            detail="guard denied {} benign tool call(s): {}".format(
                len(denials),
                _redact(", ".join(
                    f"{r.get('tool')}" for r in denials[:5]))))

    hidden = _run_hidden_tests(task, fixture_dir)

    timed_out = [h for h in hidden if h["timed_out"]]
    if timed_out:
        shutil.rmtree(fixture_dir, ignore_errors=True)
        return TaskResult(
            task, "timeout", hidden=hidden,
            detail="hidden test timed out: " + ", ".join(
                h["name"] for h in timed_out))

    failed = [h for h in hidden if not h["ok"]]
    problems: list[str] = []
    if failed:
        problems.append("hidden test(s) failed: " + ", ".join(
            f"{h['name']} (exit {h['returncode']})" for h in failed))

    # Task-type-specific real checks.
    if task.task_type == "refactor":
        for rel in task.require_changed:
            p = fixture_dir / rel
            if not p.is_file() or p.read_text(encoding="utf-8",
                                             errors="replace") == originals.get(rel, ""):
                problems.append(f"refactor left {rel} unchanged")
    if task.task_type == "add_tests":
        if not task.new_test_file:
            problems.append("add_tests task missing new_test_file")
        else:
            p = fixture_dir / task.new_test_file
            if not p.is_file():
                problems.append(f"new test file {task.new_test_file} not created")
            elif task.new_test_file in originals:
                problems.append(f"{task.new_test_file} was in the fixture, not added")
            else:
                n = _count_tests_in_file(p, task.language)
                if n < task.min_new_tests:
                    problems.append(
                        f"new test file defines {n} tests, "
                        f"need >= {task.min_new_tests}")

    shutil.rmtree(fixture_dir, ignore_errors=True)
    if problems:
        first_fail = next((h for h in failed), None)
        detail = "; ".join(problems)
        if first_fail and first_fail["output"]:
            detail += " | output: " + first_fail["output"][-500:]
        return TaskResult(task, "fail", hidden=hidden,
                          detail=_redact(detail))
    return TaskResult(
        task, "pass", hidden=hidden,
        detail=(f"{len(hidden)} hidden test(s) green in "
                f"{sum(h['elapsed_s'] for h in hidden):.1f}s"))


@dataclass
class CodingBatteryResult:
    results: list[TaskResult]

    def by_language(self) -> dict[str, dict[str, int]]:
        agg: dict[str, dict[str, int]] = {}
        for r in self.results:
            c = agg.setdefault(r.task.language,
                               {"tasks": 0, "pass": 0, "fail": 0,
                                "timeout": 0, "skipped": 0, "error": 0})
            c["tasks"] += 1
            if r.status in c:
                c[r.status] += 1
        return agg

    def by_type(self) -> dict[str, dict[str, int]]:
        agg: dict[str, dict[str, int]] = {}
        for r in self.results:
            c = agg.setdefault(r.task.task_type,
                               {"tasks": 0, "pass": 0, "fail": 0,
                                "timeout": 0, "skipped": 0, "error": 0})
            c["tasks"] += 1
            if r.status in c:
                c[r.status] += 1
        return agg

    def enforced_failures(self) -> list[TaskResult]:
        bad = []
        for r in self.results:
            if not r.task.enforced or r.status == "skipped":
                continue
            if r.status != "pass":
                bad.append(r)
        return bad

    def to_dict(self) -> dict:
        return {
            "tasks": [
                {"id": r.task.id, "name": r.task.name,
                 "language": r.task.language, "task_type": r.task.task_type,
                 "enforced": r.task.enforced,
                 "known_fail_reason": r.task.known_fail_reason,
                 "status": r.status, "detail": r.detail,
                 "hidden": r.hidden}
                for r in self.results
            ],
            "by_language": self.by_language(),
            "by_type": self.by_type(),
        }


def run_coding_battery(evals_dir: Path | str | None = None,
                       kb: KB | None = None) -> CodingBatteryResult:
    """Load every COD-*.yaml task and run the full battery. Deterministic,
    offline, hermetic (/tmp fixtures)."""
    tasks = load_coding_tasks(evals_dir)
    kb = kb or KB.load()
    return CodingBatteryResult([run_coding_task(t, kb) for t in tasks])


def render_coding_section(battery: CodingBatteryResult, timestamp: str) -> str:
    """Markdown CODING section, designed to be appended to docs/SCORECARD.md.

    Wrapped in marker comments so cmd_eval can splice it idempotently.
    """
    total = len(battery.results)
    passed = sum(1 for r in battery.results if r.status == "pass")
    lines = [
        "",
        "---",
        "",
        "<!-- CODING-EVAL-SECTION -->",
        "## Coding proving ground (v0.7 Lane D)",
        "",
        f"Generated: {timestamp} | Tasks: {total} | Pass: {passed}",
        "",
        "### Methodology",
        "",
        "Each task stages a fixture project under `/tmp` and drives the "
        "**real** `AgentLoop` with scripted `MockProvider` solution turns "
        "(the deterministic stand-in for the agent under test) through the "
        "**real** guard. Scoring comes from **actually executing** a hidden "
        "test suite (`subprocess`, timeout-capped, cwd = fixture dir) — "
        "never self-graded by the model. A `pass` requires every hidden "
        "test to exit 0, plus type-specific real checks: `refactor` tasks "
        "must actually change the target file (behavior preserved via the "
        "original tests); `add_tests` tasks must add a new test file "
        "defining a minimum number of collected, passing tests. Every "
        "surfaced string is passed through the secrets redaction layer; "
        "fixture code may contain secret-shaped strings (COD-005) which "
        "appear only as `[REDACTED:...]`.",
        "",
        "### Results by language",
        "",
        "| language | tasks | pass | fail | timeout | skipped | error |",
        "|---|---|---|---|---|---|---|",
    ]
    for lang, c in battery.by_language().items():
        lines.append(f"| {lang} | {c['tasks']} | {c['pass']} | {c['fail']} | "
                     f"{c['timeout']} | {c['skipped']} | {c['error']} |")
    lines += ["", "### Results by task type", "",
              "| task type | tasks | pass | fail | timeout | skipped | error |",
              "|---|---|---|---|---|---|---|"]
    for typ, c in battery.by_type().items():
        lines.append(f"| {typ} | {c['tasks']} | {c['pass']} | {c['fail']} | "
                     f"{c['timeout']} | {c['skipped']} | {c['error']} |")
    lines += ["", "### Tasks", "",
              "| id | language | type | enforced | status | detail |",
              "|---|---|---|---|---|---|"]
    for r in battery.results:
        detail = r.detail.replace("|", "/").replace("\n", " ")
        lines.append(f"| {r.task.id} | {r.task.language} | {r.task.task_type} | "
                     f"{r.task.enforced} | {r.status} | {detail} |")
    fails = [r for r in battery.results
             if r.status in ("fail", "timeout", "error")
             and not r.task.enforced]
    if fails:
        lines += ["", "### Known failures (enforced: false)", ""]
        for r in fails:
            lines.append(f"#### {r.task.id} — {r.task.name}")
            lines.append("")
            lines.append(r.task.known_fail_reason.strip())
            lines.append("")
    lines += ["<!-- /CODING-EVAL-SECTION -->", ""]
    return "\n".join(lines)


def splice_coding_section(scorecard_path: Path, section: str) -> str:
    """Splice the coding section into an existing scorecard by marker.

    Returns the full new scorecard text (idempotent: replaces a previous
    coding section if present, else appends). Does not write — the caller
    owns the file write.
    """
    start, end = "<!-- CODING-EVAL-SECTION -->", "<!-- /CODING-EVAL-SECTION -->"
    new_block = section[section.index(start):section.index(end) + len(end)]
    text = scorecard_path.read_text(encoding="utf-8") if scorecard_path.exists() else ""
    if start in text:
        pre = text[:text.index(start)]
        post = text[text.index(end) + len(end):]
        return pre.rstrip() + "\n" + new_block + "\n" + post.lstrip()
    return text.rstrip() + "\n" + section
