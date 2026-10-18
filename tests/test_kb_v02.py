"""v0.2 KB completeness audit: coverage assertions for the gap-fill packs.

New packs (AEG-T213..T252):
  llm_model_attacks  (T213-222) - OWASP Top 10 for LLM Applications 2025,
                                  model-layer families
  api_security       (T223-232) - OWASP API Security Top 10 2023
  identity_attacks   (T233-242) - ATT&CK Credential Access depth
  reconnaissance     (T243-252) - ATT&CK Reconnaissance + Discovery

Contract registration note: tests/test_kb.py is FROZEN (the v0.1 authoring
contract). Its test_ids_unique_and_in_range does ID_RANGES[t.pack], which
raises KeyError for any pack not registered there. Since we must not edit
that file, the new packs are registered here at import time. pytest imports
all test modules during collection before running any test, so the extended
contract is in place for the whole run.
"""

import re

import pytest

from aegis.detect.engine import pattern_scan

NEW_PACKS = {
    "llm_model_attacks": (213, 222),
    "api_security": (223, 232),
    "identity_attacks": (233, 242),
    "reconnaissance": (243, 252),
}

# Contract registration note: tests/test_kb.py is FROZEN (the v0.1 authoring
# contract). The v0.2 packs are registered centrally in tests/conftest.py,
# which pytest imports on every run (full suite or single file) — the old
# import-time mutation of test_kb.ID_RANGES here only worked under full-suite
# collection order and broke standalone runs of test_kb.py.

NEW_IDS = [f"AEG-T{n}" for lo, hi in NEW_PACKS.values() for n in range(lo, hi + 1)]

BENIGN_CORPUS = [
    "Please summarize the meeting notes from yesterday.",
    "The build passed all tests on the main branch.",
    "Refactored the login handler to reduce duplication.",
    "Reminder: team lunch at noon tomorrow.",
    "Updated the README with the new configuration options.",
    "The query returned 42 rows in 120 milliseconds.",
]

# technique id -> canonical positive probe (must match >=1 of its patterns)
POSITIVE_FIXTURES = {
    "AEG-T213": "membership inference confirmed the model had memorized the training record",
    "AEG-T214": "model extraction API abuse cloned the classifier",
    "AEG-T215": "training data poisoning via backdoor in the training set",
    "AEG-T216": "poisoned retrieval corpus hijacked the RAG answers",
    "AEG-T217": "embedding inversion reconstructed source text from vectors",
    "AEG-T218": "the agent's excessive agency led to autonomous harmful actions",
    "AEG-T219": "unbounded consumption attack drove inference costs to the limit",
    "AEG-T220": "weaponized misinformation generated at scale for the fraud campaign",
    "AEG-T221": "insecure output handling let model output inject script into the page",
    "AEG-T222": "cross-agent injection spread through the delegation chain",
    "AEG-T223": "broken object level authorization exposed other users' records",
    "AEG-T224": "missing authentication on the API endpoint allowed anonymous access",
    "AEG-T225": "mass assignment vulnerability let users set the admin flag",
    "AEG-T226": "excessive data exposure in the API response leaked internal fields",
    "AEG-T227": "broken function level authorization exposed the admin endpoint",
    "AEG-T228": "unrestricted resource consumption crashed the API backend",
    "AEG-T229": "shadow APIs discovered outside the inventory",
    "AEG-T230": "graphql introspection revealed the full schema",
    "AEG-T231": "business logic abuse in the checkout workflow allowed price manipulation",
    "AEG-T232": "unsafe consumption of the third-party API injected malicious data",
    "AEG-T233": "password spraying against the VPN portal from distributed IPs",
    "AEG-T234": "kerberoasting attack requested crackable service tickets",
    "AEG-T235": "AS-REP roasting targeted accounts with pre-auth disabled",
    "AEG-T236": "dcsync replication pulled password hashes from the domain controller",
    "AEG-T237": "session hijacking via cookie theft replayed the victim session",
    "AEG-T238": "malicious OAuth app used consent grant abuse to read mailboxes",
    "AEG-T239": "SIM swapping hijacked the victim's phone number for MFA codes",
    "AEG-T240": "golden ticket forged with the krbtgt hash gave domain persistence",
    "AEG-T241": "gMSA password retrieval abused the service account",
    "AEG-T242": "standing admin rights with no just-in-time elevation enabled lateral movement",
    "AEG-T243": "certificate transparency logs revealed unannounced subdomains",
    "AEG-T244": "search engine dorking found exposed credentials in indexed files",
    "AEG-T245": "DNS zone transfer attempt exposed the internal namespace",
    "AEG-T246": "combo lists from breach data reused against the login portal",
    "AEG-T247": "banner grabbing revealed the outdated server version",
    "AEG-T248": "gitleaks scan found hardcoded secrets in public repos",
    "AEG-T249": "people OSINT built a target profile for the phishing campaign",
    "AEG-T250": "cloud asset discovery found an exposed storage bucket",
    "AEG-T251": "internal network discovery enumerated file shares after compromise",
    "AEG-T252": "lookalike domains registered ahead of the phishing wave",
}

# ATT&CK enterprise tactic -> packs providing coverage -> minimum techniques
TACTIC_COVERAGE = {
    "Reconnaissance": (["reconnaissance"], 8),
    "Resource Development": (["reconnaissance", "darkweb_threat_intel", "supply_chain"], 5),
    "Initial Access": (["social_engineering", "apt_tradecraft", "ransomware_playbook",
                        "supply_chain", "reconnaissance"], 8),
    "Execution": (["malware_concepts", "web_exploitation", "apt_tradecraft",
                   "tool_output_poisoning"], 8),
    "Persistence": (["persistence", "apt_tradecraft", "malware_concepts"], 8),
    "Privilege Escalation": (["privilege_escalation", "identity_attacks"], 8),
    "Defense Evasion": (["evasion", "malware_concepts", "apt_tradecraft"], 8),
    "Credential Access": (["identity_attacks", "credential_exfiltration", "hacker_tools"], 8),
    "Discovery": (["reconnaissance", "hacker_tools", "apt_tradecraft"], 5),
    "Lateral Movement": (["network_attacks", "ransomware_playbook", "identity_attacks"], 5),
    "Collection": (["credential_exfiltration", "egress_exfiltration", "reconnaissance"], 5),
    "Command and Control": (["network_attacks", "hacker_tools", "darkweb_threat_intel"], 5),
    "Exfiltration": (["egress_exfiltration", "credential_exfiltration"], 8),
    "Impact": (["ransomware_playbook", "malware_concepts", "network_attacks"], 5),
}

# OWASP Top 10 for LLM Applications 2025 risk -> technique IDs in llm_model_attacks
OWASP_LLM_RISKS = {
    "LLM02": ["AEG-T213", "AEG-T214"],
    "LLM04": ["AEG-T215"],
    "LLM05": ["AEG-T221"],
    "LLM06": ["AEG-T218"],
    "LLM08": ["AEG-T216", "AEG-T217"],
    "LLM09": ["AEG-T220"],
    "LLM10": ["AEG-T219"],
}

# OWASP API Security Top 10 2023 risk -> technique ID in api_security
OWASP_API_RISKS = {
    "API1:2023 BOLA": "AEG-T223",
    "API2:2023 Broken Authentication": "AEG-T224",
    "API3:2023 BOPLA / Mass Assignment": "AEG-T225",
    "API4:2023 Unrestricted Resource Consumption": "AEG-T228",
    "API5:2023 Broken Function Level Authorization": "AEG-T227",
    "API6:2023 Unrestricted Business Flows": "AEG-T231",
    "API7:2023 SSRF-adjacent consumption": "AEG-T232",
    "API8:2023 Security Misconfiguration": "AEG-T229",
    "API9:2023 Improper Inventory Management": "AEG-T229",
    "API10:2023 Unsafe API Consumption": "AEG-T232",
}


def _new_techniques(kb):
    return [t for t in kb.techniques if t.id in POSITIVE_FIXTURES]


def test_new_packs_registered_and_minimum(kb):
    cov = kb.coverage()
    for pack, (lo, hi) in NEW_PACKS.items():
        assert pack in kb.packs(), f"new pack {pack} missing"
        assert cov[pack] >= 10, f"{pack}: only {cov[pack]} techniques"
        ids = sorted(int(t.id.split("-T")[1])
                     for t in kb.techniques if t.pack == pack)
        assert ids == list(range(lo, hi + 1)), \
            f"{pack}: ids {ids} != expected range {lo}-{hi}"


def test_new_ids_sequential_and_present(kb):
    have = {t.id for t in kb.techniques}
    missing = [i for i in NEW_IDS if i not in have]
    assert not missing, f"missing new technique ids: {missing}"


def test_new_technique_depth_bar(kb):
    for t in _new_techniques(kb):
        assert len(t.description.split()) >= 15, f"{t.id}: thin description"
        assert len(t.how_it_works.split()) >= 20, f"{t.id}: thin how_it_works"
        assert len(t.indicators) >= 2, f"{t.id}: <2 indicators"
        assert len(t.detection_patterns) >= 2, f"{t.id}: <2 patterns"
        assert len(t.mitigations) >= 2, f"{t.id}: <2 mitigations"
        assert len(t.references) >= 2, f"{t.id}: <2 references"
        assert t.severity in ("critical", "high", "medium", "low")
        for p in t.detection_patterns:
            re.compile(p, re.IGNORECASE)


def test_attck_tactic_coverage(kb):
    cov = kb.coverage()
    for tactic, (packs, minimum) in TACTIC_COVERAGE.items():
        total = sum(cov.get(p, 0) for p in packs)
        assert total >= minimum, \
            f"ATT&CK tactic '{tactic}': only {total} techniques via {packs}"


def test_owasp_llm_top10_model_layer_covered(kb):
    by_id = kb.by_id
    for risk, ids in OWASP_LLM_RISKS.items():
        for tid in ids:
            assert tid in by_id, f"OWASP {risk}: {tid} missing"
            assert by_id[tid].pack == "llm_model_attacks", \
                f"{tid} not in llm_model_attacks pack"
    # cross-pack LLM risks already covered in v0.1
    assert any(t.id == "AEG-T006" for t in kb.techniques)  # LLM07 system prompt leakage
    assert kb.coverage()["supply_chain"] >= 10  # LLM03 supply chain


def test_owasp_api_top10_covered(kb):
    by_id = kb.by_id
    for risk, tid in OWASP_API_RISKS.items():
        assert tid in by_id, f"OWASP {risk}: {tid} missing"
        assert by_id[tid].pack == "api_security", f"{tid} not in api_security pack"


@pytest.mark.parametrize("tid,probe", list(POSITIVE_FIXTURES.items()))
def test_new_technique_positive_fixture(kb, tid, probe):
    t = kb.by_id[tid]
    matched = [p for p in t.detection_patterns
               if re.search(p, probe, re.IGNORECASE)]
    assert matched, (f"{tid} ({t.name}): positive fixture matched NONE of "
                     f"its patterns: {probe!r}")


@pytest.mark.parametrize("tid", list(POSITIVE_FIXTURES))
def test_new_technique_negative_fixtures(kb, tid):
    t = kb.by_id[tid]
    fps = []
    for text in BENIGN_CORPUS:
        for p in t.detection_patterns:
            if re.search(p, text, re.IGNORECASE):
                fps.append((text, p))
    assert not fps, f"{tid}: false positives on benign text: {fps[:2]}"


@pytest.mark.parametrize("pack,probe", [
    ("llm_model_attacks", "membership inference attack extracted training data"),
    ("api_security", "broken object level authorization exposed other users' records"),
    ("identity_attacks", "kerberoasting attack requested crackable service tickets"),
    ("reconnaissance", "certificate transparency logs revealed unannounced subdomains"),
])
def test_new_pack_positive_probe(kb, pack, probe):
    hits = pattern_scan(probe, kb, categories=[pack])
    assert hits, f"pack '{pack}' matched NONE of its canonical probe"


@pytest.mark.parametrize("pack", list(NEW_PACKS))
def test_new_pack_negative_probes(kb, pack):
    fps = []
    for text in BENIGN_CORPUS:
        hits = pattern_scan(text, kb, categories=[pack])
        fps.extend((text, h.technique_id) for h in hits)
    assert not fps, f"pack '{pack}' false-positives on benign text: {fps[:3]}"


def test_new_techniques_doctrine_safe(kb):
    """New packs must not leak into the hacker_mindset doctrine section."""
    doctrine = kb.doctrine_section()
    for tid in NEW_IDS:
        assert tid not in doctrine, f"{tid} leaked into doctrine section"
    index = kb.technique_index(max_chars=200000)
    for tid in NEW_IDS:
        assert tid in index, f"{tid} missing from technique index"
