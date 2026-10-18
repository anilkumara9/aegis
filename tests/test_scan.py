"""aegis scan CLI-level tests against the bundled example traces."""

from pathlib import Path

from aegis.kb import KB
from aegis.scan import format_text, load_trace, scan_calls, scan_file

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_opencode_pattern_trace_produces_expected_findings(kb: KB):
    calls = load_trace(EXAMPLES / "opencode_pattern_trace.jsonl")
    assert len(calls) == 3
    findings = scan_calls(calls, kb)
    cats = {f.category for f in findings}
    # indirect injection identified ...
    assert cats & {"prompt_injection", "tool_output_poisoning"}, \
        f"injection missed; categories: {cats}"
    # ... and the key-exfiltration chain identified, at critical severity.
    assert cats & {"credential_exfiltration", "egress_exfiltration"}, \
        f"exfiltration missed; categories: {cats}"
    assert any(f.severity == "critical" for f in findings)
    text = format_text(findings, len(calls))
    assert "AEG-T" in text


def test_benign_trace_is_clean(kb: KB):
    calls = load_trace(EXAMPLES / "benign_trace.jsonl")
    findings = scan_calls(calls, kb)
    assert findings == [], \
        f"false positives: {[(f.technique_id, f.evidence) for f in findings]}"


def test_scan_file_json_mode(kb: KB, capsys):
    findings = scan_file(EXAMPLES / "opencode_pattern_trace.jsonl", kb,
                         as_json=True)
    assert findings
    import json
    out = json.loads(capsys.readouterr().out)
    assert isinstance(out, list) and out[0]["technique_id"].startswith("AEG-T")
