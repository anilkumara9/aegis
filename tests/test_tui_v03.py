"""v0.3 TUI: highlighting, streaming fence handling, layout."""

import pytest

from aegis import tui
from aegis.tui import StreamingRenderer, highlight_code, panel, render_inline


@pytest.fixture(autouse=True)
def force_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    tui.set_color(True)
    yield
    tui.set_color(False)


_ANSI_RE = __import__("re").compile(r"\x1b\[[0-9;]*m")


def _plain(s: str) -> str:
    return _ANSI_RE.sub("", s)


def test_highlight_python_keywords():
    out = highlight_code("def foo():\n    return 42  # comment", "python")
    assert "\x1b[" in out  # color applied
    assert "def" in out and "return" in out
    assert "42" in out


def test_highlight_unknown_lang_no_crash():
    out = highlight_code("hello world", "klingon")
    assert "hello world" in out


def test_no_color_returns_plain():
    tui.set_color(False)
    code = "def foo():\n    return 1"
    assert highlight_code(code, "python") == code
    assert render_inline("**bold** `code`") == "**bold** `code`"
    tui.set_color(True)


def test_render_inline_code_and_bold():
    out = render_inline("use `ls -la` for **details**")
    assert "\x1b[" in out
    assert "ls -la" in out and "details" in out


def test_render_inline_heading():
    out = render_inline("## Findings")
    assert "Findings" in out
    assert "##" not in out


def test_streaming_renderer_buffers_fence():
    emitted: list[str] = []
    r = StreamingRenderer(write=emitted.append)
    r.feed("here is code:\n```python\ndef f():\n")
    # fence not closed: code lines must not be emitted yet
    assert not any("def f" in e for e in emitted)
    r.feed("    return 1\n```\ndone\n")
    joined = "".join(emitted)
    assert "def f" in _plain(joined)
    assert "\x1b[" in joined  # highlighted on close
    assert "done" in joined
    r.flush()


def test_streaming_renderer_plain_streams_immediately():
    emitted: list[str] = []
    r = StreamingRenderer(write=emitted.append)
    r.feed("hello ")
    r.feed("world\n")
    assert "".join(emitted) == "hello world\n"
    r.flush()


def test_streaming_renderer_flush_closes_open_fence():
    emitted: list[str] = []
    r = StreamingRenderer(write=emitted.append)
    r.feed("```bash\necho hi\n")
    r.flush()
    assert any("echo hi" in e for e in emitted)


def test_streaming_renderer_split_fence_marker():
    emitted: list[str] = []
    r = StreamingRenderer(write=emitted.append)
    r.feed("text\n``")
    r.feed("`python\nx = 1\n```\nafter\n")
    r.flush()
    joined = "".join(emitted)
    assert "x = 1" in _plain(joined) and "after" in joined


def test_panel_layout():
    p = panel("Status", ["a", "bb"])
    assert "Status" in p
    assert "╭" in p and "╰" in p
    assert "bb" in p
