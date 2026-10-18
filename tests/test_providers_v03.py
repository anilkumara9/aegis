"""Aegis v0.3 — provider lane tests: Google Gemini + Ollama transports.

No network anywhere: urllib.request.urlopen is monkeypatched and SSE/NDJSON
streams are canned. Config env behaviour is verified in isolated subprocesses.
"""

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

from aegis import config
from aegis.providers import (
    GoogleProvider,
    OllamaProvider,
    ToolCall,
    get_provider,
)

ROOT = Path(__file__).resolve().parent.parent

TOOLS = [{
    "name": "bash",
    "description": "run shell",
    "parameters": {"type": "object", "properties": {}},
}]

MSGS = [
    {"role": "user", "content": "hi"},
    {"role": "assistant", "content": "thinking",
     "tool_calls": [{"id": "t1", "name": "bash", "args": {"cmd": "ls"}}]},
    {"role": "tool", "tool_call_id": "t1", "name": "bash", "content": "ok"},
]


class FakeResp:
    """Iterable of bytes, like urllib's response for SSE/NDJSON reads."""

    def __init__(self, lines):
        self._lines = list(lines)

    def __iter__(self):
        return iter(self._lines)


def _patch_urlopen(monkeypatch, lines):
    captured = {}

    def fake_urlopen(req, timeout=120):
        captured["req"] = req
        return FakeResp(lines)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return captured


def _req_headers(req):
    return {k.lower(): v for k, v in req.header_items()}


# -- Google: SSE parsing ---------------------------------------------------

GOOGLE_SSE = [
    b'data: {"candidates":[{"content":{"parts":[{"text":"Hello "}]}}]}\n',
    b"\n",
    b'data: {"candidates":[{"content":{"parts":[{"text":"world"}]}}]}\n',
    b"\n",
    b'data: {"candidates":[{"content":{"parts":[{"functionCall":'
    b'{"name":"bash","args":{"cmd":"ls"}}}]}}]}\n',
    b"\n",
    b"data: [DONE]\n",
    b"\n",
]


def test_google_sse_text_and_function_call_order(monkeypatch):
    _patch_urlopen(monkeypatch, GOOGLE_SSE)
    p = GoogleProvider("g-secret", "gemini-2.0-flash")
    assert p.name == "google"
    events = list(p.stream([{"role": "user", "content": "hi"}], TOOLS, ""))
    assert events[0] == ("text", "Hello ")
    assert events[1] == ("text", "world")
    kind, tc = events[2]
    assert kind == "tool_call"
    assert isinstance(tc, ToolCall)
    assert tc.id == "gem-1"
    assert tc.name == "bash"
    assert tc.args == {"cmd": "ls"}
    assert events[3] == ("done", None)
    assert len(events) == 4  # the [DONE] line yields nothing


def test_google_sse_mixed_parts_single_chunk(monkeypatch):
    lines = [
        b'data: {"candidates":[{"content":{"parts":['
        b'{"text":"ok"},{"functionCall":{"name":"scan","args":{}}}]}}]}\n',
        b"\n",
    ]
    _patch_urlopen(monkeypatch, lines)
    p = GoogleProvider("g-secret", "gemini-2.0-flash")
    events = list(p.stream([], [], ""))
    assert events[0] == ("text", "ok")
    assert events[1][0] == "tool_call"
    assert events[1][1].id == "gem-1"
    assert events[1][1].name == "scan"
    assert events[2] == ("done", None)


# -- Google: request construction ------------------------------------------

def test_google_request_url_header_body(monkeypatch):
    captured = _patch_urlopen(monkeypatch, [b"\n"])
    p = GoogleProvider("g-secret", "gemini-2.0-flash")
    list(p.stream(MSGS, TOOLS, "sys prompt"))

    req = captured["req"]
    assert req.full_url == (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-2.0-flash:streamGenerateContent?alt=sse")
    assert _req_headers(req).get("x-goog-api-key") == "g-secret"

    body = json.loads(req.data.decode())
    assert body["generationConfig"] == {"temperature": 0.2}
    assert body["systemInstruction"] == {"parts": [{"text": "sys prompt"}]}
    assert body["tools"] == [{"functionDeclarations": [{
        "name": "bash", "description": "run shell",
        "parameters": {"type": "object", "properties": {}}}]}]

    contents = body["contents"]
    assert contents[0] == {"role": "user", "parts": [{"text": "hi"}]}
    # assistant with tool_calls -> model parts with text + functionCall
    assert contents[1]["role"] == "model"
    assert contents[1]["parts"][0] == {"text": "thinking"}
    assert contents[1]["parts"][1] == {
        "functionCall": {"name": "bash", "args": {"cmd": "ls"}}}
    # tool result -> user part with functionResponse
    assert contents[2] == {"role": "user", "parts": [{
        "functionResponse": {"name": "bash",
                             "response": {"output": "ok"}}}]}
    # no systemInstruction when system is empty
    captured2 = _patch_urlopen(monkeypatch, [b"\n"])
    list(p.stream(MSGS, TOOLS, ""))
    assert "systemInstruction" not in json.loads(
        captured2["req"].data.decode())


def test_google_missing_key_raises():
    with pytest.raises(ValueError, match="GOOGLE_API_KEY"):
        GoogleProvider("", "gemini-2.0-flash")


def test_google_default_model():
    assert GoogleProvider("k", "").model == "gemini-2.0-flash"


def test_google_request_failure_yields_error(monkeypatch):
    def boom(req, timeout=120):
        raise ConnectionError("down")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    events = list(GoogleProvider("k", "gemini-2.0-flash")
                  .stream([], [], ""))
    assert events[0][0] == "error"
    assert "google request failed" in events[0][1]


# -- Ollama: NDJSON parsing ------------------------------------------------

OLLAMA_LINES = [
    b'{"message":{"content":"Hello "},"done":false}\n',
    b'{"message":{"content":"world","tool_calls":[{"function":'
    b'{"name":"bash","arguments":{"cmd":"ls"}}}]},"done":false}\n',
    b'{"message":{"role":"assistant","content":""},"done":true}\n',
]


def test_ollama_ndjson_content_and_tool_calls(monkeypatch):
    _patch_urlopen(monkeypatch, OLLAMA_LINES)
    p = OllamaProvider("http://localhost:11434", "llama3.2")
    assert p.name == "ollama"
    events = list(p.stream([{"role": "user", "content": "hi"}], TOOLS, ""))
    assert events[0] == ("text", "Hello ")
    assert events[1] == ("text", "world")
    kind, tc = events[2]
    assert kind == "tool_call"
    assert isinstance(tc, ToolCall)
    assert tc.id == "oll-1"
    assert tc.name == "bash"
    assert tc.args == {"cmd": "ls"}
    assert events[3] == ("done", None)
    assert len(events) == 4


def test_ollama_ndjson_string_arguments(monkeypatch):
    lines = [
        b'{"message":{"content":"","tool_calls":[{"function":'
        b'{"name":"scan","arguments":"{\\"path\\": \\"/tmp\\"}"}}]},'
        b'"done":false}\n',
        b'{"done":true}\n',
    ]
    _patch_urlopen(monkeypatch, lines)
    p = OllamaProvider("http://localhost:11434", "llama3.2")
    events = list(p.stream([], [], ""))
    assert events[0][0] == "tool_call"
    assert events[0][1].id == "oll-1"
    assert events[0][1].args == {"path": "/tmp"}
    assert events[1] == ("done", None)


# -- Ollama: request construction ------------------------------------------

def test_ollama_request_url_and_body(monkeypatch):
    captured = _patch_urlopen(monkeypatch, [b'{"done":true}\n'])
    p = OllamaProvider("http://box:11434/", "llama3.2")  # trailing slash ok
    list(p.stream(MSGS, TOOLS, "sys prompt"))

    req = captured["req"]
    assert req.full_url == "http://box:11434/api/chat"
    body = json.loads(req.data.decode())
    assert body["model"] == "llama3.2"
    assert body["stream"] is True
    msgs = body["messages"]
    assert msgs[0] == {"role": "system", "content": "sys prompt"}
    assert msgs[1] == {"role": "user", "content": "hi"}
    am = msgs[2]
    assert am["role"] == "assistant"
    assert am["tool_calls"][0]["id"] == "t1"
    assert am["tool_calls"][0]["type"] == "function"
    assert am["tool_calls"][0]["function"]["name"] == "bash"
    assert json.loads(am["tool_calls"][0]["function"]["arguments"]) == \
        {"cmd": "ls"}
    assert msgs[3]["role"] == "tool"
    assert msgs[3]["content"] == "ok"
    assert body["tools"] == [{"type": "function", "function": {
        "name": "bash", "description": "run shell",
        "parameters": {"type": "object", "properties": {}}}}]


def test_ollama_no_model_error_message():
    p = OllamaProvider("http://localhost:11434", "")
    events = list(p.stream([{"role": "user", "content": "hi"}], [], ""))
    assert events == [("error", "no model set: use --model <name> "
                               "(ollama pull <name> first)")]


def test_ollama_request_failure_yields_error(monkeypatch):
    def boom(req, timeout=120):
        raise ConnectionError("refused")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    events = list(OllamaProvider("http://localhost:11434", "llama3.2")
                  .stream([], [], ""))
    assert events[0][0] == "error"
    assert "ollama request failed" in events[0][1]


# -- get_provider dispatch -------------------------------------------------

def test_get_provider_google(monkeypatch):
    monkeypatch.setattr(config, "GOOGLE_API_KEY", "gk")
    p = get_provider("google", "gemini-2.0-flash")
    assert isinstance(p, GoogleProvider)
    assert p.name == "google"
    assert p.api_key == "gk"


def test_get_provider_google_missing_key(monkeypatch):
    monkeypatch.setattr(config, "GOOGLE_API_KEY", "")
    with pytest.raises(ValueError, match="GOOGLE_API_KEY"):
        get_provider("google", "gemini-2.0-flash")


def test_get_provider_ollama(monkeypatch):
    monkeypatch.setattr(config, "OLLAMA_URL", "http://box:11434")
    p = get_provider("ollama", "llama3.2")
    assert isinstance(p, OllamaProvider)
    assert p.name == "ollama"
    assert p.base_url == "http://box:11434"
    assert p.model == "llama3.2"


def test_get_provider_ollama_empty_model_yields_clear_error(monkeypatch):
    monkeypatch.setattr(config, "OLLAMA_URL", "http://localhost:11434")
    monkeypatch.setattr(config, "MODEL", "")
    p = get_provider("ollama", "")
    assert isinstance(p, OllamaProvider)
    events = list(p.stream([], [], ""))
    assert events == [("error", "no model set: use --model <name> "
                               "(ollama pull <name> first)")]


def test_get_provider_unknown_lists_all_five():
    with pytest.raises(ValueError) as exc:
        get_provider("wat", "x")
    assert "anthropic|openai|google|ollama|mock" in str(exc.value)


# -- config env behaviour (isolated subprocesses) --------------------------

_CONFIG_ENV_KEYS = ("GOOGLE_API_KEY", "GEMINI_API_KEY", "AEGIS_OLLAMA_URL",
                    "AEGIS_PROVIDER", "AEGIS_MODEL")


def _config_attr(overrides: dict, attr: str) -> str:
    env = {k: v for k, v in os.environ.items()
           if k not in _CONFIG_ENV_KEYS}
    env.update(overrides)
    code = ("import sys; sys.path.insert(0, %r); "
            "from aegis import config; print(config.%s)" % (str(ROOT), attr))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True,
                       text=True, env=env, cwd=str(ROOT))
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_config_google_key_takes_precedence():
    assert _config_attr({"GOOGLE_API_KEY": "g1",
                         "GEMINI_API_KEY": "gem1"}, "GOOGLE_API_KEY") == "g1"


def test_config_gemini_key_fallback():
    assert _config_attr({"GEMINI_API_KEY": "gem1"},
                        "GOOGLE_API_KEY") == "gem1"


def test_config_google_key_empty_by_default():
    assert _config_attr({}, "GOOGLE_API_KEY") == ""


def test_config_ollama_url_default_and_override():
    assert _config_attr({}, "OLLAMA_URL") == "http://localhost:11434"
    assert _config_attr({"AEGIS_OLLAMA_URL": "http://box:9999"},
                        "OLLAMA_URL") == "http://box:9999"


@pytest.mark.parametrize("provider,expected", [
    ("anthropic", "claude-sonnet-4-5-20250929"),
    ("openai", "gpt-4o"),
    ("google", "gemini-2.0-flash"),
    ("ollama", ""),  # model must come from --model / AEGIS_MODEL
])
def test_config_model_defaults(provider, expected):
    assert _config_attr({"AEGIS_PROVIDER": provider}, "MODEL") == expected
