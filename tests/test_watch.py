"""Tests for aegis watch (SOC-in-a-box lane): continuous defensive monitoring."""

import json
import time

import pytest

from aegis import config, watch
from aegis.respond.timeline import build_timeline, collect_events


@pytest.fixture()
def state(tmp_path, monkeypatch):
    """Redirect Aegis state dir per-test."""
    monkeypatch.setenv("AEGIS_STATE_DIR", str(tmp_path / "state"))
    return tmp_path / "state"


def _mkfinding(**kw):
    f = {
        "technique_id": "T-WATCH", "technique_name": "test finding",
        "category": "test", "severity": "high", "rule": "test_rule",
        "evidence": "evidence", "mitigation": "mitigate",
        "file": "a.py", "line": 1, "detector": "test",
    }
    f.update(kw)
    return f


# -- task 1: single pass detects a planted secret --------------------------------

SECRET_TEXT = (
    "# config\n"
    'api_key = "sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"\n'
)


def test_once_detects_planted_secret(state, tmp_path, capsys):
    target = tmp_path / "proj"
    target.mkdir()
    (target / "settings.py").write_text(SECRET_TEXT)
    rc = watch.main(["--once", str(target)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "new finding" in out
    queue = watch.read_queue()
    assert queue, "triage queue should hold the secret finding"
    severities = {e["severity"] for e in queue}
    assert "critical" in severities
    assert any(e["file"].endswith("settings.py") for e in queue)
    # evidence must be redacted — raw key material must not leak into state
    blob = (state / "triage_queue.jsonl").read_text()
    assert "sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" not in blob


def test_once_reports_clean_dir(state, tmp_path, capsys):
    target = tmp_path / "clean"
    target.mkdir()
    (target / "main.py").write_text("print('hello')\n")
    rc = watch.main(["--once", str(target)])
    assert rc == 0
    assert "0 finding(s)" in capsys.readouterr().out


def test_once_twice_no_duplicate_queue_entries(state, tmp_path):
    target = tmp_path / "proj2"
    target.mkdir()
    (target / "settings.py").write_text(SECRET_TEXT)
    watch.main(["--once", str(target)])
    n1 = len(watch.read_queue())
    assert n1 >= 1
    watch.main(["--once", str(target)])  # unchanged files: no rescan
    assert len(watch.read_queue()) == n1


def test_local_path_scoping(state, tmp_path):
    target = tmp_path / "proj3"
    target.mkdir()
    assert watch.resolve_local_dir(str(target)) is not None
    assert watch.resolve_local_dir("https://evil.example.com/x") is None
    assert watch.resolve_local_dir("ssh://user@host/path") is None
    assert watch.resolve_local_dir("evil.example.com/x") is None
    assert watch.resolve_local_dir(str(target / "nope")) is None


# -- task 3: triage dedupe + severity ranking -------------------------------------

def test_dedupe_collapses_repeats(state):
    f = _mkfinding()
    new1 = watch.enqueue_findings([f])
    assert len(new1) == 1
    new2 = watch.enqueue_findings([f, f])  # repeats in one batch
    assert new2 == []
    queue = watch.read_queue()
    assert len(queue) == 1
    assert queue[0]["seen_count"] == 3  # 1 + 2 repeats


def test_triage_severity_ranking(state, capsys):
    watch.enqueue_findings([_mkfinding(technique_id="LOW",
                                      technique_name="low one",
                                      severity="low", file="l.py")])
    watch.enqueue_findings([_mkfinding(technique_id="CRIT",
                                      technique_name="crit one",
                                      severity="critical", file="c.py")])
    watch.enqueue_findings([_mkfinding(technique_id="HIGH",
                                      technique_name="high one",
                                      severity="high", file="h.py")])
    watch.enqueue_findings([_mkfinding(technique_id="MED",
                                      technique_name="med one",
                                      severity="medium", file="m.py")])
    watch.main(["--triage"])
    out = capsys.readouterr().out
    idx = [out.index(f"[{s}]") for s in
           ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
    assert idx == sorted(idx), "queue must rank critical→low"
    assert "4 open" in out


# -- task 4: scheduled hunts ------------------------------------------------------

def test_schedule_due_logic():
    now = 1_000_000.0
    assert watch.schedule_due({"freq": "hourly", "last_run": 0.0}, now)
    assert watch.schedule_due({"freq": "hourly", "last_run": now - 3600}, now)
    assert not watch.schedule_due({"freq": "hourly", "last_run": now - 10}, now)
    assert not watch.schedule_due({"freq": "daily", "last_run": now - 3600}, now)
    assert watch.schedule_due({"freq": "daily", "last_run": now - 86400}, now)


def test_schedule_record_and_run(state, tmp_path, capsys):
    target = tmp_path / "proj4"
    target.mkdir()
    (target / "main.py").write_text("x = eval(user_input)\n")
    assert watch.main(["--schedule", "hourly", str(target)]) == 0
    st = watch.load_state()
    assert len(st["schedules"]) == 1
    assert st["schedules"][0]["freq"] == "hourly"
    assert st["schedules"][0]["last_run"] == 0.0
    # --once runs the due hunt and stamps last_run
    assert watch.main(["--once", str(target)]) == 0
    st = watch.load_state()
    assert st["schedules"][0]["last_run"] > 0.0
    assert "scheduled hunt" in capsys.readouterr().out
    # immediate second pass: hunt not due again
    last = st["schedules"][0]["last_run"]
    capsys.readouterr()
    assert watch.main(["--once", str(target)]) == 0
    st = watch.load_state()
    assert st["schedules"][0]["last_run"] == last
    assert "scheduled hunt" not in capsys.readouterr().out


def test_schedule_bad_freq(state, tmp_path, capsys):
    target = tmp_path / "proj5"
    target.mkdir()
    rc = watch.main(["--schedule", "minutely", str(target)])
    assert rc == 2
    assert "unknown schedule" in capsys.readouterr().out


# -- task 5: incident timeline -----------------------------------------------------

def test_timeline_includes_audit_alerts_triage_in_order(state):
    audit_dir = config.audit_dir()
    audit_dir.mkdir(parents=True, exist_ok=True)
    with open(audit_dir / "sess1.jsonl", "w") as fh:
        fh.write(json.dumps({"ts": 100.0, "session": "s1", "event": "tool_call",
                             "tool": "bash", "verdict": "allowed",
                             "output_excerpt": "ok"}) + "\n")
        fh.write(json.dumps({"ts": 300.0, "session": "s1", "event": "tool_call",
                             "tool": "webfetch", "verdict": "blocked"}) + "\n")
    alerts = state / "watch_alerts.jsonl"
    alerts.write_text(json.dumps({"ts": 200.0, "kind": "new_findings",
                                  "dir": "/x",
                                  "findings": [{"technique_id": "AEG-T001",
                                                "technique_name": "t",
                                                "severity": "critical",
                                                "file": "a.py", "line": 1}]})
                      + "\n")
    (state / "triage_queue.jsonl").write_text(
        json.dumps({"fingerprint": "abc", "technique_id": "AEG-T002",
                    "technique_name": "u", "severity": "high", "file": "b.py",
                    "line": 2, "first_seen": 250.0, "last_seen": 250.0,
                    "seen_count": 1}) + "\n")

    md = build_timeline()
    assert "# Aegis incident timeline" in md
    i_bash = md.index("`bash`")
    i_alert = md.index("watch: 1 new finding(s)")
    i_triage = md.index("watch: triaged")
    i_blocked = md.index("`webfetch`")
    assert i_bash < i_alert < i_triage < i_blocked
    events = collect_events()
    assert [e[0] for e in events] == [100.0, 200.0, 250.0, 300.0]


def test_timeline_empty(state):
    md = build_timeline()
    assert "No events yet" in md


# -- boundary: remote refusal ------------------------------------------------------

@pytest.mark.parametrize("target", [
    "https://evil.example.com/repo",
    "http://192.0.2.10/x",
    "ssh://git@github.com/user/repo.git",
    "203.0.113.5/share",
])
def test_remote_path_refused(state, target, capsys):
    rc = watch.main(["--once", target])
    assert rc == 2
    assert "refused" in capsys.readouterr().out


def test_respond_still_exports_timeline():
    from aegis import respond
    assert callable(respond.build_timeline)
    assert "build_timeline" in respond.__all__
