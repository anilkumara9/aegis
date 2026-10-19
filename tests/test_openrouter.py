"""Aegis OpenRouter provider tests: free-model guard + transport.

No network anywhere: urllib.request.urlopen is monkeypatched and SSE
streams are canned. The live API was verified separately by hand.
"""

import io
import json
import os
import urllib.request

import pytest

from aegis import config
from aegis.providers import OpenRouterProvider, get_provider


def _sse(*payloads):
    lines = []
    for p in payloads:
        lines.append("data: " + json.dumps(p))
        lines.append("")
    lines.append("data: [DONE]")
    lines.append("")
    return io.BytesIO(("\n".join(lines)).encode())


def _chat_chunk(content=None, tool=None):
    delta = {}
    if content:
        delta["content"] = content
    if tool:
        delta["tool_calls"] = [{
            "index": 0, "id": "call-1", "type": "function",
            "function": {"name": tool[0], "arguments": json.dumps(tool[1])}}]
    return {"choices": [{"delta": delta}]}


class TestFreeModelGuard:
    def test_default_model_is_free(self):
        p = OpenRouterProvider("k", "")
        assert p.model.endswith(":free"), p.model

    def test_explicit_free_model_allowed(self):
        p = OpenRouterProvider("k", "deepseek/deepseek-chat-v3.1:free")
        assert p.model == "deepseek/deepseek-chat-v3.1:free"

    def test_openrouter_free_router_allowed(self):
        p = OpenRouterProvider("k", "openrouter/free")
        assert p.model == "openrouter/free"

    def test_paid_model_blocked(self):
        with pytest.raises(ValueError, match="not free"):
            OpenRouterProvider("k", "openai/gpt-4o")

    def test_paid_model_allowed_with_override(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ALLOW_PAID", "1")
        import importlib
        importlib.reload(config)
        try:
            p = OpenRouterProvider("k", "openai/gpt-4o")
            assert p.model == "openai/gpt-4o"
        finally:
            monkeypatch.delenv("AEGIS_ALLOW_PAID", raising=False)
            importlib.reload(config)

    def test_missing_key(self):
        with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
            OpenRouterProvider("", "")


class TestTransport:
    def test_url_and_headers(self, monkeypatch):
        seen = {}

        class FakeResp(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["headers"] = dict(req.header_items())
            seen["body"] = json.loads(req.data.decode())
            return FakeResp(_sse(_chat_chunk("hello")).getvalue())

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        p = OpenRouterProvider("secret-key", "")
        events = list(p.stream([{"role": "user", "content": "hi"}], [], "sys"))

        assert seen["url"] == "https://openrouter.ai/api/v1/chat/completions"
        lowered = {k.lower(): v for k, v in seen["headers"].items()}
        assert lowered.get("authorization") == "Bearer secret-key"
        assert "http-referer" in lowered  # OpenRouter ranking header
        assert seen["body"]["model"].endswith(":free")
        assert ("text", "hello") in events
        assert ("done", None) in events

    def test_tool_call_roundtrip(self, monkeypatch):
        def fake_urlopen(req, timeout=None):
            stream = _sse(_chat_chunk(tool=("bash", {"cmd": "ls"})))
            stream.__enter__ = lambda s: s
            stream.__exit__ = lambda s, *a: False
            return stream

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        p = OpenRouterProvider("k", "")
        tools = [{"name": "bash", "description": "run",
                  "parameters": {"type": "object", "properties": {}}}]
        events = list(p.stream([{"role": "user", "content": "ls it"}],
                               tools, ""))
        calls = [e[1] for e in events if e[0] == "tool_call"]
        assert len(calls) == 1
        assert calls[0].name == "bash"
        assert calls[0].args == {"cmd": "ls"}

    def test_get_provider_registration(self, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "k2")
        import importlib
        importlib.reload(config)
        try:
            p = get_provider("openrouter", "")
            assert isinstance(p, OpenRouterProvider)
            assert p.model.endswith(":free")
        finally:
            monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
            importlib.reload(config)

    def test_network_error_surfaces(self, monkeypatch):
        def boom(req, timeout=None):
            raise ConnectionError("down")

        monkeypatch.setattr(urllib.request, "urlopen", boom)
        p = OpenRouterProvider("k", "")
        events = list(p.stream([], [], ""))
        assert events[0][0] == "error"
