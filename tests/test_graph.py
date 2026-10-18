"""Lane B (attack graphs) — real end-to-end tests, no stubs.

Covers: signal collection on real fixture projects, signal->KB mapping
integrity, kill-chain-ordered path building, the ranking formula, refusal of
non-local targets, and CLI output (markdown + parseable JSON).
"""

import json
import os
import re
import stat
from pathlib import Path

import pytest

from aegis.graph import (
    AttackPath,
    Candidate,
    PathStep,
    STAGES,
    SEV_WEIGHT,
    SIGNAL_TECHNIQUES,
    build_candidates,
    build_paths,
    collect_signals,
    path_defenses,
    run_graph,
    score_path,
    step_plausibility,
    validate_target,
    verify_mapping,
)

FIX = Path(__file__).parent / "fixtures" / "graph"
VULN = FIX / "vulnerable_app"
CLEAN = FIX / "clean_project"

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _graph(fixture, kb, top=5):
    signals, scanned = collect_signals(fixture)
    candidates = build_candidates(signals, kb)
    paths = build_paths(candidates, kb)
    return signals, scanned, candidates, paths


# ---------------------------------------------------------------------------
# Mapping integrity
# ---------------------------------------------------------------------------


def test_mapping_ids_all_resolve(kb):
    ids = verify_mapping(kb)
    assert ids, "expected at least one mapped technique ID"
    assert all(re.fullmatch(r"AEG-T\d{3}", tid) for tid in ids)
    assert all(tid in kb.by_id for tid in ids)
    # every stage in the mapping is a real kill-chain stage
    stages = {stage for _, _, stage in SIGNAL_TECHNIQUES}
    assert stages <= set(STAGES)


def test_mapping_ids_are_validated_at_build(kb):
    signals, _ = collect_signals(VULN)
    # a bogus mapping entry must fail loudly, never silently pass
    import aegis.graph as g
    real = g.SIGNAL_TECHNIQUES
    g.SIGNAL_TECHNIQUES = real + [("hardcoded_secret", "AEG-T999", "exfil")]
    try:
        with pytest.raises(ValueError, match="unknown KB IDs"):
            build_candidates(signals, kb)
    finally:
        g.SIGNAL_TECHNIQUES = real


# ---------------------------------------------------------------------------
# Signal collection
# ---------------------------------------------------------------------------


def test_vulnerable_fixture_yields_strong_signals(kb):
    signals, scanned = collect_signals(VULN)
    kinds = {s.kind for s in signals}
    assert scanned > 0
    assert {"hardcoded_secret", "env_file", "docker_root",
            "dep_manifest", "ci_config"} <= kinds
    secret_sig = next(s for s in signals if s.kind == "hardcoded_secret")
    assert secret_sig.strength == 1.0
    # secret VALUES must never appear in evidence or file fields
    blob = "\n".join(secret_sig.evidence + secret_sig.files)
    assert "sk-test_1234567890abcdef" not in blob
    assert "AKIAIOSFODNN7EXAMPLE" not in blob


def test_clean_fixture_yields_no_signals():
    signals, scanned = collect_signals(CLEAN)
    assert scanned == 2
    assert signals == []


def test_permission_bit_signals(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    f = target / "helper"
    f.write_text("#!/bin/sh\necho hi\n")
    f.chmod(0o4755)  # setuid
    g = target / "shared"
    g.write_text("data")
    g.chmod(0o666)  # world-writable
    signals, _ = collect_signals(target)
    kinds = {s.kind for s in signals}
    assert "setuid" in kinds
    assert "world_writable" in kinds


def test_scan_is_read_only(tmp_path, kb):
    target = tmp_path / "proj"
    target.mkdir()
    f = target / "app.py"
    f.write_text("x = 1\n")
    before = (f.read_bytes(), stat.S_IMODE(f.stat().st_mode))
    run_graph(str(target), kb=kb)
    after = (f.read_bytes(), stat.S_IMODE(f.stat().st_mode))
    assert before == after


# ---------------------------------------------------------------------------
# Path building
# ---------------------------------------------------------------------------


def test_paths_reference_only_real_kb_ids(kb):
    _, _, candidates, paths = _graph(VULN, kb)
    assert paths, "vulnerable fixture must produce attack paths"
    for p in paths:
        assert 2 <= len(p.steps) <= 5, "paths must be chains of 2-5 steps"
        ids = p.ids()
        assert len(set(ids)) == len(ids), "no repeated technique in a path"
        for step in p.steps:
            assert step.candidate.tech_id in kb.by_id
            assert re.fullmatch(r"AEG-T\d{3}", step.candidate.tech_id)
        # kill-chain order: stages strictly increase along the path
        idxs = [STAGES.index(s.candidate.stage) for s in p.steps]
        assert idxs == sorted(idxs) and len(set(idxs)) == len(idxs)


def test_ranking_puts_secret_path_above_clean(kb):
    _, _, _, vuln_paths = _graph(VULN, kb)
    _, _, _, clean_paths = _graph(CLEAN, kb)
    assert vuln_paths
    assert clean_paths == []
    vuln_best = max(p.score for p in vuln_paths)
    clean_best = max((p.score for p in clean_paths), default=0.0)
    assert vuln_best > clean_best
    assert SEV_ORDER[vuln_paths[0].max_severity] >= SEV_ORDER["high"]


def test_clean_target_yields_no_high_severity_paths(kb):
    _, _, _, paths = _graph(CLEAN, kb)
    for p in paths:
        assert SEV_ORDER[p.max_severity] < SEV_ORDER["high"]


def test_paths_ranked_descending(kb):
    _, _, _, paths = _graph(VULN, kb)
    scores = [p.score for p in paths]
    assert scores == sorted(scores, reverse=True)


def test_defenses_come_from_kb_mitigations(kb):
    _, _, _, paths = _graph(VULN, kb)
    assert paths
    for p in paths[:3]:
        defenses = path_defenses(p)
        assert defenses, "each path must name breaking defenses"
        all_mits = {m for s in p.steps
                    for m in kb.by_id[s.candidate.tech_id].mitigations}
        for d in defenses:
            assert "] " in d
            assert d.split("] ", 1)[1] in all_mits


# ---------------------------------------------------------------------------
# Ranking formula
# ---------------------------------------------------------------------------


def _fake_step(kb, tech_id, strength=1.0, signal="hardcoded_secret"):
    t = kb.by_id[tech_id]
    cand = Candidate(tech_id=tech_id, stage="exfil",
                     stage_idx=STAGES.index("exfil"),
                     signal_kind=signal, strength=strength,
                     evidence=["e"], files=["f"])
    return PathStep(candidate=cand, name=t.name, severity=t.severity,
                    mitigations=list(t.mitigations))


def test_score_formula_matches_documentation(kb):
    steps = [_fake_step(kb, "AEG-T031"), _fake_step(kb, "AEG-T034")]
    max_sev = max(SEV_WEIGHT[s.severity] for s in steps)
    mean_plaus = sum(step_plausibility(s) for s in steps) / len(steps)
    coverage = len({s.candidate.stage for s in steps}) / len(STAGES)
    expected = 0.5 * max_sev + 0.3 * mean_plaus + 0.2 * coverage
    assert score_path(steps) == pytest.approx(expected)


def test_score_prefers_worse_max_severity(kb):
    crit = [_fake_step(kb, "AEG-T031", strength=0.5)]
    low = [_fake_step(kb, "AEG-T039", strength=1.0)]
    # AEG-T031 is critical, AEG-T039 is medium: max severity dominates
    assert score_path(crit) > score_path(low)


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", [
    "https://example.com",
    "http://192.168.1.10/app",
    "example.com",
    "evil-corp.github.io/repo",
    "192.168.1.1",
    "10.0.0.5:22",
    "ssh://git@github.com/org/repo.git",
    "user@host:/srv/app",
    "",
])
def test_nonlocal_targets_refused(target):
    path, err = validate_target(target)
    assert path is None
    assert err, "refusal must explain itself"


@pytest.mark.parametrize("target", [
    "https://example.com", "example.com", "192.168.1.1", "/does/not/exist",
])
def test_run_graph_refuses_nolocal(target, kb, capsys):
    rc = run_graph(target, kb=kb)
    assert rc == 2
    assert "refused" in capsys.readouterr().err


def test_run_graph_refuses_file_target(kb, tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("x")
    assert run_graph(str(f), kb=kb) == 2


def test_run_graph_rejects_bad_top(kb):
    assert run_graph(str(VULN), kb=kb, top=0) == 2


# ---------------------------------------------------------------------------
# CLI end to end
# ---------------------------------------------------------------------------


def test_cli_markdown_end_to_end(kb, capsys):
    from aegis.cli import main
    rc = main(["graph", str(VULN), "--top", "2"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "# Attack graph" in out
    assert "## Ranked attack paths" in out
    # technique names from the KB appear, with defenses
    assert "AEG-T031" in out
    assert "Defenses that break this path" in out
    assert "score" in out


def test_cli_json_parseable_and_kb_grounded(kb, capsys):
    from aegis.cli import main
    rc = main(["graph", str(VULN), "--json", "--top", "3"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["target"].endswith("vulnerable_app")
    assert doc["files_scanned"] > 0
    assert len(doc["paths"]) == 3
    for i, p in enumerate(doc["paths"], 1):
        assert p["rank"] == i
        assert 2 <= len(p["steps"]) <= 5
        for s in p["steps"]:
            assert s["id"] in kb.by_id
            assert s["name"] == kb.by_id[s["id"]].name
            assert s["why"], "each step must say why it applies to this target"
        assert p["defenses"]


def test_cli_json_clean_target(kb, capsys):
    from aegis.cli import main
    rc = main(["graph", str(CLEAN), "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["paths"] == []
    assert doc["signals"] == []


def test_cli_refusal_exit_code(kb):
    from aegis.cli import main
    assert main(["graph", "https://example.com"]) == 2
