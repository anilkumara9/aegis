"""Responder playbooks: runbooks emitted, no destructive actions."""

import json

import pytest

from aegis import guard as guard_mod
from aegis.guard import Policy, create_session
from aegis.kb import KB
from aegis.respond.playbooks import PLAYBOOKS, run_playbook
from aegis.tools import ToolContext
from pathlib import Path


def _ctx(kb: KB):
    sess = create_session(Policy(name="respond-test"), kb)
    return ToolContext(sess, kb, Path("."))


def test_rotate_keys_openai(kb):
    out = run_playbook("rotate-keys", _ctx(kb), "openai")
    assert "platform.openai.com" in out
    assert "Revoke" in out
    assert "never touches provider accounts" in out


def test_rotate_keys_all_providers(kb):
    out = run_playbook("rotate-keys", _ctx(kb), "")
    assert "OpenAI" in out and "Anthropic" in out and "Google" in out


def test_kill_session_revokes(kb):
    ctx = _ctx(kb)
    sid = ctx.guard_session.id
    out = run_playbook("kill-session", ctx, sid)
    assert "REVOKED" in out
    assert guard_mod.is_revoked(sid)


def test_quarantine_workspace(kb):
    out = run_playbook("quarantine-workspace", _ctx(kb), "/tmp/ws")
    assert "mv /tmp/ws" in out
    assert "forensics" in out.lower()


def test_incident_report_from_findings(kb):
    findings = [
        {"technique_id": "AEG-T001", "technique_name": "X",
         "severity": "critical", "evidence": "e1", "mitigation": "m1"},
        {"technique_id": "AEG-T002", "technique_name": "Y",
         "severity": "high", "evidence": "e2", "mitigation": "m2"},
    ]
    out = run_playbook("incident-report", _ctx(kb), json.dumps(findings))
    assert "critical: 1" in out and "high: 1" in out
    assert "AEG-T001" in out


def test_unknown_playbook_raises(kb):
    with pytest.raises(ValueError):
        run_playbook("nuke-everything", _ctx(kb), "")
