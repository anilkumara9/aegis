"""MCP client tests (Pillar 4). All real: a stdlib-only mock MCP server is
spawned over stdio; the guard really screens every call; a call log on disk
proves denied calls never reached the server process."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from aegis import guard as guard_mod
from aegis.detect import secrets as sec
from aegis.mcp import (MCPClient, MCPError, MCPManager, MCPTool, load_config,
                       mcp_tool_name, register_mcp_tools)
from aegis.tools import ToolContext

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "mcp"
MOCK_SERVER = FIXTURES / "mock_server.py"
FAKE_KEY = "sk-proj-FAKEKEY1234567890abcdefg"


@pytest.fixture()
def mcp_env(tmp_path, monkeypatch):
    """Isolated AEGIS_STATE_DIR + mcp.json pointing at the mock server."""
    state = tmp_path / "aegis-state"
    state.mkdir()
    monkeypatch.setenv("AEGIS_STATE_DIR", str(state))
    log = tmp_path / "mock-calls.jsonl"
    cfg = {"servers": {"mock": {
        "command": sys.executable,
        "args": [str(MOCK_SERVER), str(log)],
        "env": {}}}}
    (state / "mcp.json").write_text(json.dumps(cfg), encoding="utf-8")
    return {"state": state, "log": log, "cfg": cfg}


def _ctx(kb, policy=None, approval=None):
    sess = guard_mod.create_session(policy or guard_mod.Policy(), kb)
    return ToolContext(guard_session=sess, kb=kb, cwd=Path("."),
                       approval_callback=approval)


def _calls(log: Path) -> list[dict]:
    if not log.exists():
        return []
    return [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines()
            if l.strip()]


# -- config -----------------------------------------------------------------

def test_config_loader_reads_state_dir(mcp_env):
    loaded = load_config()
    assert loaded["servers"]["mock"]["command"] == sys.executable
    assert loaded["servers"]["mock"]["args"][0].endswith("mock_server.py")
    assert (mcp_env["state"] / "mcp.json").exists()


def test_config_missing_file_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STATE_DIR", str(tmp_path / "empty"))
    assert load_config() == {"servers": {}}


def test_config_malformed_raises(mcp_env):
    (mcp_env["state"] / "mcp.json").write_text('{"servers": {"x": {}}}',
                                               encoding="utf-8")
    with pytest.raises(MCPError):
        load_config()


# -- protocol ----------------------------------------------------------------

def test_initialize_handshake(mcp_env):
    mgr = MCPManager.from_config()
    client = mgr.client_for("mock")
    try:
        result = client.initialize()
        assert result["protocolVersion"] == "2024-11-05"
        assert result["serverInfo"]["name"] == "aegis-mock-mcp"
    finally:
        mgr.close_all()


def test_tools_list(mcp_env):
    mgr = MCPManager.from_config()
    try:
        tools = mgr.list_server_tools("mock")
        names = {t["name"] for t in tools}
        assert {"echo", "leak_secret", "add"} <= names
        echo = next(t for t in tools if t["name"] == "echo")
        assert echo["inputSchema"]["required"] == ["text"]
    finally:
        mgr.close_all()


def test_unknown_server_raises(mcp_env):
    mgr = MCPManager.from_config()
    with pytest.raises(MCPError):
        mgr.client_for("nope")


# -- guard integration -------------------------------------------------------

def test_call_roundtrip_through_guard(mcp_env, kb):
    mgr = MCPManager.from_config()
    ctx = _ctx(kb)
    try:
        out = mgr.call("mock", "echo", {"text": "hello"}, ctx)
        assert out == "echo: hello"
        calls = _calls(mcp_env["log"])
        assert len(calls) == 1
        assert calls[0]["name"] == "echo"
        assert calls[0]["arguments"] == {"text": "hello"}
    finally:
        mgr.close_all()


def test_guard_denial_never_reaches_server(mcp_env, kb):
    policy = guard_mod.Policy(denied_tools={"mcp__mock__echo"})
    mgr = MCPManager.from_config()
    ctx = _ctx(kb, policy)
    out = mgr.call("mock", "echo", {"text": "hello"}, ctx)
    try:
        assert out.startswith("GUARD DENIED")
        assert "hello" in out or "denied" in out.lower()
        # The server process was never even spawned, let alone called.
        assert mgr._clients == {}
        assert _calls(mcp_env["log"]) == []
    finally:
        mgr.close_all()


def test_guard_denial_by_arg_pattern(mcp_env, kb):
    policy = guard_mod.Policy(deny_arg_patterns=[r"malicious"])
    mgr = MCPManager.from_config()
    ctx = _ctx(kb, policy)
    out = mgr.call("mock", "echo", {"text": "malicious payload"}, ctx)
    try:
        assert out.startswith("GUARD DENIED")
        assert _calls(mcp_env["log"]) == []
    finally:
        mgr.close_all()


def test_needs_approval_path(mcp_env, kb):
    # A URL in args with no egress allowlist -> needs_approval verdict.
    mgr = MCPManager.from_config()
    approved = _ctx(kb, approval=lambda findings: True)
    denied = _ctx(kb, approval=lambda findings: False)
    try:
        args = {"text": "check https://example.com/x"}
        out = mgr.call("mock", "echo", args, approved)
        assert "echo:" in out
        assert len(_calls(mcp_env["log"])) == 1
        out2 = mgr.call("mock", "echo", args, denied)
        assert out2.startswith("GUARD DENIED")
        assert "approval" in out2.lower()
    finally:
        mgr.close_all()


def test_secret_redaction_on_mcp_results(mcp_env, kb):
    mgr = MCPManager.from_config()
    ctx = _ctx(kb)
    try:
        out = mgr.call("mock", "leak_secret", {}, ctx)
        assert FAKE_KEY not in out
        assert "[REDACTED:openai_key]" in out
        # Belt: the raw secret detector agrees nothing leaks.
        assert not sec.is_secret_bearing(out)
    finally:
        mgr.close_all()


# -- registry ----------------------------------------------------------------

def test_register_mcp_tools(mcp_env):
    tools: dict = {}
    names = register_mcp_tools(tools)
    assert "mcp__mock__echo" in names
    assert "mcp__mock__leak_secret" in names
    t = tools["mcp__mock__echo"]
    assert isinstance(t, MCPTool)
    assert t.name == mcp_tool_name("mock", "echo")
    spec = t.spec()
    assert spec["name"] == "mcp__mock__echo"
    assert spec["parameters"]["required"] == ["text"]
    assert "[MCP:mock]" in spec["description"]


def test_mcp_tool_run_through_guard(mcp_env, kb):
    tools: dict = {}
    mgr = MCPManager(load_config()["servers"])
    register_mcp_tools(tools, mgr)
    ctx = _ctx(kb)
    try:
        out = tools["mcp__mock__add"].run({"a": 2, "b": 3}, ctx)
        assert out == "5"
    finally:
        mgr.close_all()


def test_register_with_no_config_is_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STATE_DIR", str(tmp_path / "nostate"))
    tools: dict = {}
    assert register_mcp_tools(tools) == []
    assert tools == {}


# -- CLI ---------------------------------------------------------------------

def test_cli_mcp_list(mcp_env, capsys):
    from aegis.cli import main
    rc = main(["mcp", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "mock" in out
    assert "mcp__mock__echo" in out


def test_cli_mcp_list_server_filter(mcp_env, capsys):
    from aegis.cli import main
    rc = main(["mcp", "list", "--server", "mock"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "mcp__mock__leak_secret" in out


def test_cli_mcp_call(mcp_env, capsys, kb):
    from aegis.cli import main
    rc = main(["mcp", "call", "mock", "echo", "--args", '{"text": "cli-yo"}'])
    assert rc == 0
    out = capsys.readouterr().out
    assert "echo: cli-yo" in out
    calls = _calls(mcp_env["log"])
    assert any(c["name"] == "echo" for c in calls)


def test_cli_mcp_call_bad_json(mcp_env, capsys):
    from aegis.cli import main
    rc = main(["mcp", "call", "mock", "echo", "--args", "{nope"])
    assert rc == 2


def test_cli_mcp_call_unknown_server(mcp_env, capsys):
    from aegis.cli import main
    rc = main(["mcp", "call", "nope", "echo"])
    assert rc == 2
    assert "unknown" in capsys.readouterr().out.lower()
