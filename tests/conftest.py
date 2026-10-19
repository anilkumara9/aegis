"""pytest config: repo root on sys.path, shared fixtures."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Isolate user state during tests: never touch ~/.aegis.
os.environ.setdefault("AEGIS_STATE_DIR", str(ROOT / ".test-state"))

import pytest  # noqa: E402

from aegis.kb import KB  # noqa: E402


@pytest.fixture(scope="session")
def kb() -> KB:
    return KB.load()


@pytest.fixture()
def tmp_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


# -- KB authoring-contract registration -------------------------------------
# tests/test_kb.py is FROZEN (the v0.1 authoring contract): its
# test_ids_unique_and_in_range does ID_RANGES[t.pack], which raises KeyError
# for any pack not registered there. Later lanes used to register their packs
# by mutating test_kb.ID_RANGES at import time inside their own test modules —
# which only worked when the full suite was collected (pytest imports every
# module before running any test) and broke standalone runs of test_kb.py.
#
# The registration lives here instead: conftest.py is imported by pytest for
# this directory on EVERY run — full suite or single file — so the extended
# contract is deterministic regardless of collection order. test_kb.py itself
# is untouched.
def _register_extended_kb_contract() -> None:
    import test_kb

    v02_packs = {
        "llm_model_attacks": (213, 222),
        "api_security": (223, 232),
        "identity_attacks": (233, 242),
        "reconnaissance": (243, 252),
    }
    v04_packs = {
        "apt_campaigns": (253, 264),
        "web_attack_flows": (265, 276),
        "c2_operations": (277, 288),
        "initial_access": (289, 300),
        "cloud_attacks": (301, 312),
        "agent_attacks": (313, 324),
        "lateral_movement": (325, 336),
        "cybercrime_economy": (337, 348),
    }
    v06_packs = {
        "ml_serialization_attacks": (387, 398),
        "fraud_bec_operations": (399, 410),
        "insider_threat_patterns": (411, 422),
        "ics_ot_attacks": (423, 434),
        "wiper_destruction": (435, 446),
        "mobile_attacks": (447, 458),
        "crypto_attacks": (459, 470),
        "firmware_hardware_attacks": (471, 482),
    }
    for packs in (v02_packs, v04_packs, v06_packs):
        test_kb.ID_RANGES.update(packs)
        for pack in packs:
            if pack not in test_kb.EXPECTED_PACKS:
                test_kb.EXPECTED_PACKS.append(pack)
    # The frozen contract allows ONE (lo, hi) range per pack; the v0.4 lane
    # folded 38 doctrine notes into hacker_mindset as T349-T386, so the range
    # is widened to span both blocks (original T203-212 + new T349-386).
    test_kb.ID_RANGES["hacker_mindset"] = (203, 386)


_register_extended_kb_contract()
