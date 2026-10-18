"""Provider abstraction: normalized chat + tool-call streaming.

Internal message format:
  {"role": "user", "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id","name","args"}]}
  {"role": "tool", "tool_call_id": str, "name": str, "content": str}

Events yielded by stream(): ("text", str) | ("tool_call", ToolCall) |
("done", None) | ("error", str). Network via stdlib urllib (SSE parsed by
hand); no third-party SDK needed.
"""

from __future__ import annotations

import json
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict


Event = tuple[str, object]  # (kind, payload)


class Provider(ABC):
    name = "base"

    @abstractmethod
    def stream(self, messages: list[dict], tools: list[dict],
               system: str) -> Iterator[Event]:
        """Yield ("text", str) chunks, then ("tool_call", ToolCall),
        then ("done", None)."""


def _sse_events(resp) -> Iterator[tuple[str, str]]:
    """Parse a Server-Sent Events byte stream into (event, data) pairs."""
    event, data_lines = "message", []
    for raw in resp:
        line = raw.decode("utf-8", "ignore").rstrip("\n")
        if not line:
            if data_lines:
                yield event, "\n".join(data_lines)
            event, data_lines = "message", []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].strip())


class AnthropicProvider(Provider):
    name = "anthropic"
    api_url = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str, model: str):
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set")
        self.api_key = api_key
        self.model = model

    def _to_anthropic(self, messages: list[dict]) -> list[dict]:
        out = []
        for m in messages:
            role, content = m["role"], m.get("content", "")
            if role == "assistant" and m.get("tool_calls"):
                blocks = []
                if content:
                    blocks.append({"type": "text", "text": content})
                for tc in m["tool_calls"]:
                    blocks.append({"type": "tool_use", "id": tc["id"],
                                   "name": tc["name"], "input": tc["args"]})
                out.append({"role": "assistant", "content": blocks})
            elif role == "tool":
                out.append({"role": "user", "content": [{
                    "type": "tool_result", "tool_use_id": m["tool_call_id"],
                    "content": content}]})
            else:
                out.append({"role": role, "content": content})
        return out

    def stream(self, messages, tools, system):
        body = {
            "model": self.model, "max_tokens": 4096, "stream": True,
            "system": system,
            "messages": self._to_anthropic(messages),
            "tools": [{"name": t["name"], "description": t["description"],
                       "input_schema": t["parameters"]} for t in tools],
        }
        req = urllib.request.Request(
            self.api_url, data=json.dumps(body).encode(),
            headers={"x-api-key": self.api_key,
                     "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
        try:
            resp = urllib.request.urlopen(req, timeout=120)
        except Exception as e:
            yield ("error", f"anthropic request failed: {e}")
            return
        yield from self._parse(resp)

    def _parse(self, resp) -> Iterator[Event]:
        text_buf: list[str] = []
        tc_id = tc_name = ""
        arg_buf: list[str] = []
        in_tool = False
        for event, data in _sse_events(resp):
            if data == "[DONE]":
                continue
            try:
                obj = json.loads(data)
            except Exception:
                continue
            if event == "content_block_start":
                block = obj.get("content_block", {})
                if block.get("type") == "tool_use":
                    if in_tool:  # flush previous
                        yield ("tool_call", ToolCall(tc_id, tc_name,
                                                    _safe_args("".join(arg_buf))))
                    in_tool = True
                    tc_id = block.get("id", "")
                    tc_name = block.get("name", "")
                    arg_buf = []
            elif event == "content_block_delta":
                delta = obj.get("delta", {})
                if delta.get("type") == "text_delta":
                    text_buf.append(delta.get("text", ""))
                    yield ("text", delta.get("text", ""))
                elif delta.get("type") == "input_json_delta":
                    arg_buf.append(delta.get("partial_json", ""))
            elif event in ("message_stop",):
                break
        if in_tool:
            yield ("tool_call", ToolCall(tc_id, tc_name, _safe_args("".join(arg_buf))))
        yield ("done", None)


class OpenAIProvider(Provider):
    name = "openai"
    api_url = "https://api.openai.com/v1/chat/completions"

    def __init__(self, api_key: str, model: str):
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set")
        self.api_key = api_key
        self.model = model

    def _to_openai(self, messages: list[dict]) -> list[dict]:
        out = []
        for m in messages:
            role = m["role"]
            if role == "assistant" and m.get("tool_calls"):
                out.append({
                    "role": "assistant", "content": m.get("content") or None,
                    "tool_calls": [{
                        "id": tc["id"], "type": "function",
                        "function": {"name": tc["name"],
                                     "arguments": json.dumps(tc["args"])}}
                        for tc in m["tool_calls"]]})
            elif role == "tool":
                out.append({"role": "tool", "tool_call_id": m["tool_call_id"],
                            "content": m.get("content", "")})
            else:
                out.append({"role": role, "content": m.get("content", "")})
        return out

    def stream(self, messages, tools, system):
        body = {
            "model": self.model, "stream": True,
            "messages": ([{"role": "system", "content": system}] if system else [])
            + self._to_openai(messages),
            "tools": [{"type": "function",
                       "function": {"name": t["name"],
                                    "description": t["description"],
                                    "parameters": t["parameters"]}}
                      for t in tools],
        }
        req = urllib.request.Request(
            self.api_url, data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.api_key}",
                     "content-type": "application/json"})
        try:
            resp = urllib.request.urlopen(req, timeout=120)
        except Exception as e:
            yield ("error", f"openai request failed: {e}")
            return
        yield from self._parse(resp)

    def _parse(self, resp) -> Iterator[Event]:
        calls: dict[int, dict] = {}
        for _event, data in _sse_events(resp):
            if data == "[DONE]":
                break
            try:
                obj = json.loads(data)
            except Exception:
                continue
            for choice in obj.get("choices", []):
                delta = choice.get("delta", {})
                if delta.get("content"):
                    yield ("text", delta["content"])
                for tc in delta.get("tool_calls", []):
                    idx = tc.get("index", 0)
                    slot = calls.setdefault(idx, {"id": "", "name": "", "args": ""})
                    slot["id"] += tc.get("id", "")
                    fn = tc.get("function", {})
                    slot["name"] += fn.get("name", "")
                    slot["args"] += fn.get("arguments", "")
        for slot in calls.values():
            if slot["name"]:
                yield ("tool_call", ToolCall(slot["id"], slot["name"],
                                            _safe_args(slot["args"])))
        yield ("done", None)


class MockProvider(Provider):
    """Scripted provider for tests and offline demos. No network.

    script: list of turns; each turn is a dict {"text": str,
    "tool_calls": [{"name": str, "args": dict}]}. Each stream() call pops
    the next turn. A turn may also be a callable(messages) -> turn dict.
    """

    name = "mock"

    def __init__(self, script: list):
        self.script = list(script)
        self.calls = 0
        self.received: list[list[dict]] = []  # messages shown per stream() call

    def stream(self, messages, tools, system):
        self.calls += 1
        self.received.append(messages)
        if not self.script:
            yield ("text", "done.")
            yield ("done", None)
            return
        turn = self.script.pop(0)
        if callable(turn):
            turn = turn(messages)
        text = turn.get("text", "")
        if text:
            yield ("text", text)
        for i, tc in enumerate(turn.get("tool_calls", [])):
            yield ("tool_call", ToolCall(tc.get("id", f"mock-{self.calls}-{i}"),
                                        tc["name"], tc.get("args", {})))
        yield ("done", None)


def _safe_args(raw: str) -> dict:
    try:
        args = json.loads(raw) if raw else {}
    except Exception:
        args = {}
    return args if isinstance(args, dict) else {}


def get_provider(name: str = "", model: str = "") -> Provider:
    from .. import config
    name = (name or config.PROVIDER).lower()
    model = model or config.MODEL
    if name == "anthropic":
        return AnthropicProvider(config.ANTHROPIC_API_KEY, model)
    if name == "openai":
        return OpenAIProvider(config.OPENAI_API_KEY, model)
    if name == "mock":
        return MockProvider([])
    raise ValueError(f"unknown provider '{name}' (want anthropic|openai|mock)")
