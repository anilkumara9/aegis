"""v0.6 proving ground: eval battery schema validity + enforced verdicts.

Runs the FULL scenario battery (no network): every scenario drives the
real AgentLoop + real guard with a scripted MockProvider, and verdicts are
read from the guard's own audit log.
"""

import os
import re
from pathlib import Path

import pytest
import yaml

import aegis.config as _config

# Deterministic, offline: never let the eval shell out to docker.
_config.SANDBOX = "local"
os.environ["AEGIS_SANDBOX"] = "local"

from aegis import eval_runner
from aegis.eval_runner import (
    CATEGORIES,
    load_scenarios,
    render_scorecard,
    run_battery,
)
from aegis.kb import KB

EVALS_DIR = Path(__file__).resolve().parent.parent / "evals"
ID_RE = re.compile(r"^EVL-\d+$")


@pytest.fixture(scope="module")
def scenarios():
    return load_scenarios(EVALS_DIR)


@pytest.fixture(scope="module")
def kb():
    return KB.load()


def test_evals_directory_nonempty(scenarios):
    assert scenarios, "no scenarios found in evals/"


def test_ids_unique_and_wellformed(scenarios):
    ids = [s.id for s in scenarios]
    assert len(ids) == len(set(ids)), "duplicate scenario ids"
    for i in ids:
        assert ID_RE.match(i), f"bad scenario id format: {i!r}"


def test_schema_validity(scenarios, kb):
    by_id = kb.by_id
    for s in scenarios:
        assert s.name, f"{s.id}: name required"
        assert s.category in CATEGORIES, \
            f"{s.id}: unknown category {s.category!r}"
        assert s.technique_ids, f"{s.id}: technique_ids required"
        for tid in s.technique_ids:
            assert tid in by_id, f"{s.id}: unknown KB technique {tid!r}"
        assert s.description.strip(), f"{s.id}: description required"
        assert s.user_message.strip(), f"{s.id}: user_message required"
        assert s.script, f"{s.id}: script must be non-empty"
        for n, turn in enumerate(s.script):
            assert isinstance(turn, dict), f"{s.id} turn {n}: must be a mapping"
            assert turn.get("text") or turn.get("tool_calls"), \
                f"{s.id} turn {n}: need text and/or tool_calls"
            for tc in turn.get("tool_calls") or []:
                assert isinstance(tc.get("name"), str) and tc["name"], \
                    f"{s.id} turn {n}: tool_call needs a name"
                assert isinstance(tc.get("args") or {}, dict), \
                    f"{s.id} turn {n}: args must be a mapping"
                assert isinstance(tc.get("hostile", True), bool), \
                    f"{s.id} turn {n}: hostile must be bool"
        assert s.expected in ("blocked", "allowed"), \
            f"{s.id}: expected must be blocked|allowed"
        assert isinstance(s.enforced, bool), f"{s.id}: enforced must be bool"
        if s.enforced:
            assert not s.known_miss_reason.strip(), \
                f"{s.id}: enforced scenarios must not carry a miss reason"
        else:
            assert s.known_miss_reason.strip(), \
                f"{s.id}: non-enforced scenarios must document known_miss_reason"
        for f in s.stage:
            assert f.get("path") and isinstance(f.get("content", ""), str), \
                f"{s.id}: stage entries need path + content"


def test_raw_yaml_matches_schema_fields(scenarios):
    # Guards against silent field drops in load_scenarios().
    raw = yaml.safe_load((EVALS_DIR / "EVL-001.yaml").read_text())
    s = next(x for x in scenarios if x.id == "EVL-001")
    assert s.name == raw["name"]
    assert s.expected == raw["expected"]
    assert s.enforced == raw["enforced"]


def test_enforced_battery_matches_expected(kb):
    battery = run_battery(EVALS_DIR, kb)
    problems = []
    for r in battery.results:
        if r.status == "error":
            problems.append(f"{r.scenario.id}: harness error: {r.detail}")
            continue
        if not r.scenario.enforced:
            continue  # recorded, never fails
        want = "caught" if r.scenario.expected == "blocked" else "allowed"
        if r.status != want:
            problems.append(
                f"{r.scenario.id} ({r.scenario.name}): expected {want}, "
                f"got {r.status} — {r.detail}")
    assert not problems, "enforced scenario mismatches:\n" + "\n".join(problems)


def test_known_miss_is_recorded_not_failed(kb):
    battery = run_battery(EVALS_DIR, kb)
    misses = [r for r in battery.results if not r.scenario.enforced]
    assert misses, "seed set should demonstrate the enforced:false path"
    assert not battery.enforced_failures()


def test_scorecard_renders():
    battery = run_battery(EVALS_DIR)
    md = render_scorecard(battery, "2026-10-19 00:00 UTC")
    assert "# Aegis Guard Eval Scorecard" in md
    assert "## Methodology" in md
    assert "EVL-001" in md
