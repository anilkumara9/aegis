"""Pillar 2 — adversary emulation: campaign validity, purple-team controls,
non-local refusal, CLI end-to-end, /emulate skill smoke test.

All tests are real: markers are inert synthetic traces run through the
actual detection stack (detect.engine.pattern_scan + GuardSession).
No network, no execution, no real secrets.
"""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from aegis.emulate import (CAMPAIGNS, STAGES, EmulateError, emulate_dir,
                           verify_stage)
from aegis.guard import GuardSession, Policy
from aegis.kb import KB
from aegis.skills import SKILLS, emulate

FIX = "tests/fixtures/emulate"


def _guard(kb) -> GuardSession:
    return GuardSession("emulate-test", Policy(), kb)


def _muted_kb(kb) -> KB:
    """KB with the whole pattern layer deliberately disabled.

    Simulates a detector outage through the real data path (no
    monkeypatching): every technique keeps its identity, but no pattern
    can fire.
    """
    return KB([replace(t, detection_patterns=[]) for t in kb.techniques])


# -- campaign chain validity -------------------------------------------


def test_campaign_chain_validity(kb):
    assert set(CAMPAIGNS) >= {"credential-theft", "supply-chain",
                              "insider-exfil"}
    for name, camp in CAMPAIGNS.items():
        stages = camp["stages"]
        assert len(stages) == 5, name
        assert [s["stage"] for s in stages] == STAGES, name  # kill-chain order
        for s in stages:
            assert s["technique_id"] in kb.by_id, (name, s["technique_id"])
            assert s["marker"]["tool"] and isinstance(s["marker"]["args"], dict)
            assert "{grounding}" in s["narrative"], (name, s["stage"])


# -- purple-team controls ----------------------------------------------


def test_positive_control_stage_covered(kb, tmp_path):
    sdef = CAMPAIGNS["credential-theft"]["stages"][0]  # recon / AEG-T248
    rec = verify_stage(sdef, kb, _guard(kb), tmp_path, 1)
    assert rec["verdict"] == "COVERED"
    assert sdef["technique_id"] in rec["fired_technique_ids"]
    assert sdef["technique_id"] in rec["pattern_layer_hits"]
    artifact = tmp_path / rec["artifact"]
    assert artifact.exists()
    body = json.loads(artifact.read_text())
    assert body["never_execute"] is True
    assert body["simulated_trace"]["inert"] is True


def test_negative_control_disabled_detector_reports_gap(kb, tmp_path):
    """The verifier is not always-green: with the pattern layer disabled,
    the same stage reports GAP."""
    sdef = CAMPAIGNS["credential-theft"]["stages"][0]
    muted = _muted_kb(kb)
    rec = verify_stage(sdef, muted, _guard(muted), tmp_path, 1)
    assert rec["verdict"] == "GAP", rec
    assert rec["fired_technique_ids"] == []
    assert rec["guard_decision"] == "allow"


def test_every_stage_marker_self_fires(kb, tmp_path):
    """Each stage's own technique must be among the detectors its marker
    trips — otherwise the positive control is vacuous."""
    for name, camp in CAMPAIGNS.items():
        for i, sdef in enumerate(camp["stages"], 1):
            rec = verify_stage(sdef, kb, _guard(kb), tmp_path, i)
            assert rec["verdict"] == "COVERED", (name, sdef["stage"])
            assert sdef["technique_id"] in rec["fired_technique_ids"], \
                (name, sdef["stage"])


def test_end_to_end_gap_with_muted_kb(kb):
    result = json.loads(emulate_dir(f"{FIX}/vuln_app",
                                    campaign="credential-theft",
                                    kb=_muted_kb(kb), as_json=True))
    recon = result["stages"][0]
    assert recon["stage"] == "recon"
    assert recon["verification"]["verdict"] == "GAP"


def test_markers_never_touch_target(kb):
    target = Path(f"{FIX}/vuln_app")
    before = {p.name for p in target.iterdir()}
    emulate_dir(str(target), campaign="supply-chain", kb=kb)
    after = {p.name for p in target.iterdir()}
    assert before == after


# -- grounding ----------------------------------------------------------


def test_narratives_grounded_in_real_files(kb):
    result = json.loads(emulate_dir(f"{FIX}/vuln_app",
                                    campaign="credential-theft",
                                    kb=kb, as_json=True))
    assert result["signals_found"] > 0
    recon = result["stages"][0]
    assert "app.py" in recon["grounded_findings"]
    assert "hardcoded_secret" in recon["grounded_findings"]
    # secret material never leaks into reports: only kind+path+line
    assert "fixture-fake-key" not in json.dumps(result)


def test_clean_target_reports_no_signals(kb):
    result = json.loads(emulate_dir(f"{FIX}/clean_app",
                                    campaign="credential-theft",
                                    kb=kb, as_json=True))
    assert result["signals_found"] == 0
    assert result["files_scanned"] == 1


# -- non-local refusal --------------------------------------------------


@pytest.mark.parametrize("target", [
    "https://evil.example/app",
    "http://evil.example/app",
    "evil.example/app",
    "192.168.1.5/share",
    "/nope-not-here-xyz-123",
])
def test_nonlocal_and_missing_targets_refused(kb, target):
    with pytest.raises(EmulateError, match="(?i)refused|not a local directory"):
        emulate_dir(target, kb=kb)


def test_unknown_campaign_rejected(kb):
    with pytest.raises(EmulateError, match="unknown campaign"):
        emulate_dir(f"{FIX}/vuln_app", campaign="apt29", kb=kb)


# -- CLI end-to-end -----------------------------------------------------


def test_cli_end_to_end_markdown(capsys):
    from aegis.cli import main
    rc = main(["emulate", "--target", f"{FIX}/vuln_app",
               "--campaign", "supply-chain"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "supply-chain" in out
    assert "Stage 1/5" in out and "Stage 5/5" in out
    assert "COVERED" in out
    assert "Covered vs gap" in out


def test_cli_end_to_end_json(capsys):
    from aegis.cli import main
    rc = main(["emulate", "--target", f"{FIX}/vuln_app",
               "--campaign", "insider-exfil", "--json"])
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    assert result["campaign"] == "insider-exfil"
    assert [s["stage"] for s in result["stages"]] == STAGES
    sm = result["summary"]
    assert sm["total"] == 5 and sm["covered"] + sm["gap"] == 5


def test_cli_rejects_bad_input(capsys):
    from aegis.cli import main
    assert main(["emulate", "--target", "https://evil.example/x"]) == 2
    assert main(["emulate", "--target", f"{FIX}/vuln_app",
                 "--campaign", "nope"]) == 2
    err = capsys.readouterr().err
    assert "emulate:" in err


# -- /emulate skill smoke test ------------------------------------------


def test_emulate_skill_smoke(kb):
    assert "/emulate" in SKILLS
    report = emulate(f"{FIX}/vuln_app", "credential-theft", kb)
    assert "credential-theft" in report
    assert "Reconnaissance" in report
    assert "Exfiltration" in report
    assert "COVERED" in report


def test_emulate_skill_refuses_remote(kb):
    assert "refused" in emulate("https://evil.example/app", kb=kb).lower()
    assert "refused" in emulate("evil.example/app", kb=kb).lower()
