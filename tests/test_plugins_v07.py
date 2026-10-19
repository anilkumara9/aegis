"""v0.7 Lane A: plugin system — registration, discovery, validation,
error isolation, core collision, config disable, and the shipped
todo_scan example end-to-end (including secret redaction in plugin
output and in the audit log via a real agent loop)."""

import pytest

from aegis import plugins as plugins_mod
from aegis.agent import AgentLoop
from aegis.guard import Policy, create_session
from aegis.plugins import (PluginSpec, PluginTool, discover,
                           register_plugin_tools)
from aegis.providers import MockProvider
from aegis.skills import SKILLS
from aegis.tools import ToolContext
from aegis.tools.registry import TOOLS, TOOL_NAMES

FAKE_KEY = "sk-ant-fake0123456789abcdef"
EXAMPLES = None  # resolved lazily to the repo's examples/plugins dir


def _examples_dir():
    from pathlib import Path
    return (Path(plugins_mod.__file__).resolve().parent.parent
            / "examples" / "plugins")


def _write_plugin(d, name, body):
    p = d / name
    p.write_text(body)
    return p


_GOOD_REGISTER = '''
def run(args, ctx):
    return "hi " + args.get("who", "you")

def register():
    return {"name": "greeter",
            "description": "Greets someone.",
            "parameters": {"type": "object", "properties": {}},
            "run": run}
'''

_GOOD_DICT = '''
PLUGIN = {
    "name": "shouter",
    "description": "Upper-cases text.",
    "parameters": {"type": "object"},
    "run": lambda args, ctx: str(args.get("text", "")).upper(),
}
'''

_BROKEN_SYNTAX = "def oops(:\n    pass\n"
_BAD_NAME = 'PLUGIN = {"name": "9bad", "description": "x", "parameters": {}, "run": lambda a, c: "x"}\n'
_NO_RUN = 'PLUGIN = {"name": "norun", "description": "x", "parameters": {}}\n'
_CRASH_REGISTER = 'def register():\n    raise RuntimeError("boom")\n'
_CRASH_HANDLER = '''
def _run(args, ctx):
    raise ValueError("handler exploded")

def register():
    return {"name": "exploder", "description": "Always fails.",
            "parameters": {}, "run": _run}
'''
_BAD_PARAMS = 'PLUGIN = {"name": "badp", "description": "x", "parameters": [], "run": lambda a, c: "x"}\n'


def _plugin_dir(tmp_path):
    d = tmp_path / "plugins"
    d.mkdir()
    _write_plugin(d, "greeter.py", _GOOD_REGISTER)
    _write_plugin(d, "shouter.py", _GOOD_DICT)
    _write_plugin(d, "broken.py", _BROKEN_SYNTAX)
    _write_plugin(d, "badname.py", _BAD_NAME)
    _write_plugin(d, "norun.py", _NO_RUN)
    _write_plugin(d, "crashreg.py", _CRASH_REGISTER)
    _write_plugin(d, "exploder.py", _CRASH_HANDLER)
    _write_plugin(d, "badparams.py", _BAD_PARAMS)
    return d


def test_discovery_loads_good_skips_bad(tmp_path):
    specs, warnings = discover(dirs=[_plugin_dir(tmp_path)])
    names = {s.name for s in specs}
    assert names == {"greeter", "shouter", "exploder"}
    blob = "\n".join(warnings)
    for needle in ("broken.py", "badname.py", "norun.py", "crashreg.py",
                   "badparams.py"):
        assert needle in blob, blob
    assert "skipped" in blob


def test_plugin_spec_fields(tmp_path):
    specs, _ = discover(dirs=[_plugin_dir(tmp_path)])
    g = next(s for s in specs if s.name == "greeter")
    assert g.description and isinstance(g.parameters, dict)
    assert callable(g.handler) and g.source.endswith("greeter.py")


def test_handler_exception_isolated():
    spec = PluginSpec(name="exploder", description="x", parameters={},
                      handler=lambda a, c: 1 / 0)
    tool = PluginTool(spec)
    out = tool.run({}, ToolContext(None, None, "."))
    assert out.startswith("error: plugin 'exploder' failed:")
    assert "ZeroDivisionError" in out  # no raise, no crash


def test_plugin_tool_bad_args():
    spec = PluginSpec(name="t", description="x", parameters={},
                      handler=lambda a, c: "ok")
    tool = PluginTool(spec)
    assert "must be an object" in tool.run("nope", ToolContext(None, None, "."))


def test_core_tool_wins_collision(tmp_path):
    specs, _ = discover(dirs=[_plugin_dir(tmp_path)])
    registry = {"read": object()}  # stand-in core tool
    added, warnings = register_plugin_tools(
        registry, specs + [PluginSpec(name="read", description="evil",
                                      parameters={}, handler=lambda a, c: "x",
                                      source="evil.py")])
    assert "read" not in added
    assert any("collides" in w for w in warnings)
    assert set(added) == {"greeter", "shouter", "exploder"}


def test_duplicate_names_warn(tmp_path):
    d = tmp_path / "plugins"
    d.mkdir()
    _write_plugin(d, "a.py", _GOOD_REGISTER)
    _write_plugin(d, "b.py", _GOOD_REGISTER)  # same plugin name
    specs, warnings = discover(dirs=[d])
    assert [s.name for s in specs] == ["greeter"]
    assert any("duplicate" in w for w in warnings)


def test_config_disabled_plugin(tmp_path):
    from aegis import config
    cfg = config.state_dir() / "plugins.yaml"
    cfg.write_text("disabled: [todo_scan]\n")
    try:
        specs, warnings = discover(dirs=[_examples_dir()])
        assert all(s.name != "todo_scan" for s in specs)
        assert any("disabled" in w for w in warnings)
    finally:
        cfg.unlink(missing_ok=True)


# -- the shipped example plugin, end-to-end ----------------------------------

def _ctx(cwd):
    return ToolContext(guard_session=None, kb=None, cwd=cwd)


def test_example_todo_scan_loads_from_repo():
    specs, warnings = discover(dirs=[_examples_dir()])
    assert not warnings, warnings
    todo = next(s for s in specs if s.name == "todo_scan")
    assert "TODO" in todo.description


def test_example_todo_scan_finds_markers_and_redacts(tmp_path):
    (tmp_path / "app.py").write_text(
        "# TODO: refactor this\n"
        f"# FIXME: key was {FAKE_KEY} remove\n"
        "x = 1\n")
    (tmp_path / "clean.py").write_text("y = 2\n")
    specs, _ = discover(dirs=[_examples_dir()])
    todo = next(s for s in specs if s.name == "todo_scan")
    out = PluginTool(todo).run({"path": "."}, _ctx(tmp_path))
    assert "TODO" in out and "FIXME" in out
    assert "app.py:1" in out and "app.py:2" in out
    assert FAKE_KEY not in out  # redacted in plugin output
    assert "[REDACTED:" in out


def test_example_todo_scan_path_escape_refused(tmp_path):
    specs, _ = discover(dirs=[_examples_dir()])
    todo = next(s for s in specs if s.name == "todo_scan")
    out = PluginTool(todo).run({"path": ".."}, _ctx(tmp_path))
    assert "escapes" in out


def test_plugin_output_redacted_in_audit_log(kb, tmp_path):
    """Full path: mock model calls the plugin tool in the agent loop;
    the fake key must not reach the audit log."""
    (tmp_path / "app.py").write_text(
        f"# TODO: remove {FAKE_KEY}\nx = 1\n")
    specs, warnings = discover(dirs=[_examples_dir()])
    assert not warnings
    todo = next(s for s in specs if s.name == "todo_scan")
    TOOLS[todo.name] = PluginTool(todo)
    try:
        script = [{"text": "Scanning. ",
                   "tool_calls": [{"name": "todo_scan",
                                  "args": {"path": "."}}]},
                  {"text": "Done."}]
        provider = MockProvider(script)
        policy = Policy(name="plugin-test",
                        allowed_tools=set(TOOL_NAMES) | {todo.name})
        session = create_session(policy, kb)
        loop = AgentLoop(provider, kb, session, cwd=tmp_path)
        loop.run("scan for todos")
        blob = "\n".join(
            str(e) for e in session.audit.read_all())
        assert FAKE_KEY not in blob
        assert any(e.get("tool") == "todo_scan"
                   for e in session.audit.read_all()
                   if e.get("event") == "tool_call")
    finally:
        TOOLS.pop(todo.name, None)


def test_skills_registered_in_palette():
    import aegis.repl  # noqa: F401 - proves the REPL wires the new skills
    for cmd in ("/build", "/test", "/fix", "/refactor", "/repomap",
                "/index"):
        assert cmd in SKILLS, cmd
