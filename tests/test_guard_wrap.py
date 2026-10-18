"""Subprocess wrapper mode: aegis guard wrap."""

from aegis.guard import Policy
from aegis.guard_wrap import wrap
from aegis.kb import KB

FAKE = "sk-ant-TESTANTHROPICFixture000000000001"


def test_wrap_allows_benign(kb: KB, capsys):
    rc = wrap(["echo", "hello-aegis"], Policy(name="w"), kb)
    assert rc == 0
    assert "hello-aegis" in capsys.readouterr().out


def test_wrap_denies_dangerous(kb: KB):
    rc = wrap(["bash", "-c", "rm -rf /"], Policy(name="w"), kb)
    assert rc == 126


def test_wrap_redacts_secrets_in_output(kb: KB, capsys):
    # Secret-bearing commands need approval; the approver allows it here so
    # we can verify output redaction. Without an approver it is denied.
    rc = wrap(["echo", f"leaked={FAKE}"], Policy(name="w"), kb,
              approval_callback=lambda findings: True)
    assert rc == 0
    out = capsys.readouterr().out
    assert FAKE not in out
    assert "[REDACTED:" in out


def test_wrap_secret_command_needs_approval(kb: KB):
    rc = wrap(["echo", f"leaked={FAKE}"], Policy(name="w"), kb)
    assert rc == 126


def test_wrap_missing_command(kb: KB):
    rc = wrap(["definitely-not-a-real-binary-xyz"], Policy(name="w"), kb)
    assert rc == 127


def test_wrap_audit_logged(kb: KB, tmp_path, monkeypatch):
    import os
    monkeypatch.setenv("AEGIS_STATE_DIR", str(tmp_path / "state"))
    rc = wrap(["echo", "hi"], Policy(name="w"), kb, session_id="wraptest1")
    assert rc == 0
    log = tmp_path / "state" / "audit" / "wraptest1.jsonl"
    assert log.exists()
    assert "wrap:echo" in log.read_text()
