"""KB integrity: all 19 packs load, validate, and meet the depth bar."""

import re

import pytest

from aegis.kb import KB, KBValidationError

EXPECTED_PACKS = [
    "prompt_injection", "tool_output_poisoning", "credential_exfiltration",
    "egress_exfiltration", "persistence", "privilege_escalation",
    "supply_chain", "evasion",
    "darkweb_threat_intel", "apt_tradecraft", "ransomware_playbook",
    "social_engineering", "web_exploitation", "network_attacks",
    "malware_concepts",
    "hacker_tools", "attack_methods", "algorithms", "hacker_mindset",
]

# Expected ID ranges per pack (authoring contract).
ID_RANGES = {
    "prompt_injection": (1, 12), "tool_output_poisoning": (13, 24),
    "credential_exfiltration": (25, 36), "egress_exfiltration": (37, 48),
    "persistence": (49, 60), "privilege_escalation": (61, 72),
    "supply_chain": (73, 84), "evasion": (85, 96),
    "darkweb_threat_intel": (97, 106), "apt_tradecraft": (107, 116),
    "ransomware_playbook": (117, 126), "social_engineering": (127, 138),
    "web_exploitation": (139, 150), "network_attacks": (151, 160),
    "malware_concepts": (161, 170), "hacker_tools": (171, 182),
    "attack_methods": (183, 192), "algorithms": (193, 202),
    "hacker_mindset": (203, 212),
}


def test_kb_loads_and_has_all_packs(kb):
    assert kb.count() >= 190, f"expected >=190 techniques, got {kb.count()}"
    for pack in EXPECTED_PACKS:
        assert pack in kb.packs(), f"missing pack {pack}"


def test_each_pack_meets_minimum(kb):
    cov = kb.coverage()
    for pack in EXPECTED_PACKS:
        lo, hi = ID_RANGES[pack]
        assert cov[pack] >= 10, f"{pack}: only {cov[pack]} techniques"


def test_ids_unique_and_in_range(kb):
    seen = set()
    for t in kb.techniques:
        assert t.id not in seen, f"duplicate {t.id}"
        seen.add(t.id)
        lo, hi = ID_RANGES[t.pack]
        num = int(t.id.split("-T")[1])
        assert lo <= num <= hi, f"{t.id} out of range for pack {t.pack}"


def test_detection_patterns_compile(kb):
    for t in kb.techniques:
        assert t.detection_rule and t.detection_rule.replace("_", "").isalnum(), \
            f"{t.id}: bad rule name"
        assert len(t.detection_patterns) >= 2, f"{t.id}: <2 patterns"
        for p in t.detection_patterns:
            re.compile(p, re.IGNORECASE)  # must not raise


def test_no_operational_attack_content(kb):
    """Defensive-only boundary: no how-to-attack phrasing in the KB."""
    banned = [
        r"(?i)\bstep[- ]by[- ]step\b.*\b(attack|hack|exploit)\b",
        r"(?i)how to (hack|break into|gain unauthorized)",
        r"(?i)download .* from .*onion",
        r"(?i)usage:\s*\w+\s+--target",
    ]
    for t in kb.techniques:
        blob = f"{t.description}\n{t.how_it_works}"
        for rx in banned:
            assert not re.search(rx, blob), f"{t.id}: banned phrasing {rx}"


def test_query_returns_relevant(kb):
    hits = kb.query("prompt injection in tool output", top_k=5)
    assert hits, "query returned nothing"
    cats = {h.category for h in hits}
    assert cats & {"prompt_injection", "tool_output_poisoning"}, \
        f"irrelevant categories: {cats}"


def test_doctrine_and_index_nonempty(kb):
    assert len(kb.doctrine_section()) > 500
    assert "AEG-T" in kb.technique_index()


def test_loader_rejects_bad_pack(tmp_path):
    bad = tmp_path / "badpack.yaml"
    bad.write_text("techniques:\n  - id: NOPE\n")
    with pytest.raises(KBValidationError):
        KB.load(tmp_path)
