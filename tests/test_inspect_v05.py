"""v0.5 Lane D: read-only local inspection tools (ps/netconns/hash/search)."""

from pathlib import Path

from aegis.tools import ToolContext
from aegis.tools.inspect import HashTool, NetConnsTool, PsTool, SearchTool
from aegis.tools.registry import TOOLS


def _ctx(tmp_path):
    return ToolContext(guard_session=None, kb=None, cwd=Path(tmp_path))


def test_tools_registered():
    for name in ("ps", "netconns", "hash", "search"):
        assert name in TOOLS, f"{name} not in tool registry"


def test_ps_lists_processes(tmp_path):
    out = PsTool().run({"limit": 5}, _ctx(tmp_path))
    assert "PID" in out and "processes)" in out
    lines = [l for l in out.splitlines() if l.strip() and not l.startswith(" " * 0 + "PID")]
    assert len(lines) >= 2  # header + at least one process


def test_ps_pattern_filter(tmp_path):
    out = PsTool().run({"pattern": "zzznomatchzzz", "limit": 50}, _ctx(tmp_path))
    assert "(0 processes)" in out


def test_netconns_readonly(tmp_path):
    out = NetConnsTool().run({"limit": 5}, _ctx(tmp_path))
    assert "connections)" in out


def test_hash_and_verify(tmp_path, monkeypatch):
    # State dir OUTSIDE the hashed tree so the baseline file itself
    # doesn't pollute verify counts.
    monkeypatch.setenv("AEGIS_STATE_DIR", str(tmp_path / ".." / "hstate"))
    ctx = _ctx(tmp_path)
    (tmp_path / "a.txt").write_text("hello")
    out = HashTool().run({"path": "a.txt"}, ctx)
    assert len(out.splitlines()[0].split()[0]) == 64  # sha256 hex
    assert "baseline stored" in HashTool().run(
        {"path": ".", "mode": "baseline"}, ctx)
    assert "ok=1" in HashTool().run({"path": ".", "mode": "verify"}, ctx)
    (tmp_path / "a.txt").write_text("changed")
    out = HashTool().run({"path": ".", "mode": "verify"}, ctx)
    assert "CHANGED a.txt" in out


def test_hash_confined_to_cwd(tmp_path):
    ctx = _ctx(tmp_path)
    out = HashTool().run({"path": "../.."}, ctx)
    assert out.startswith("error:")


def test_search_finds_pattern(tmp_path):
    (tmp_path / "app.py").write_text("password = 'secret123'\n")
    (tmp_path / "ok.txt").write_text("nothing here\n")
    out = SearchTool().run({"pattern": "password", "limit": 10}, _ctx(tmp_path))
    assert "app.py:1" in out and "1 match" in out


def test_search_bad_pattern(tmp_path):
    out = SearchTool().run({"pattern": "([unclosed"}, _ctx(tmp_path))
    assert out.startswith("error: bad pattern")


def test_search_skips_binary(tmp_path):
    (tmp_path / "bin.dat").write_bytes(b"\x00\x01\x02\xff" * 100)
    out = SearchTool().run({"pattern": ".", "limit": 10}, _ctx(tmp_path))
    assert "bin.dat" not in out
