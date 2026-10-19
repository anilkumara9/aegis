"""Provider abstraction: normalized chat + tool-call streaming.

Internal message format:
  {"role": "user", "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id","name","args"}]}
  {"role": "tool", "tool_call_id": str, "name": str, "content": str}

Events yielded by stream(): ("text", str) | ("tool_call", ToolCall) |
("usage", {"input_tokens": int, "output_tokens": int, "estimated": bool}) |
("done", None) | ("error", str). Network via stdlib urllib (SSE parsed by
hand); no third-party SDK needed.

The "usage" event is emitted only when token counts are known: providers
surface it when the wire protocol reports usage (exact, estimated=False);
the mock provider emits a chars/4 heuristic (estimated=True). Consumers
must tolerate its absence — it is informational, never required.
"""

from __future__ import annotations

import json
import os
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
        usage_in = usage_out = 0
        for event, data in _sse_events(resp):
            if data == "[DONE]":
                continue
            try:
                obj = json.loads(data)
            except Exception:
                continue
            if event == "message_start":
                u = obj.get("message", {}).get("usage", {})
                usage_in += int(u.get("input_tokens", 0) or 0)
                usage_out += int(u.get("output_tokens", 0) or 0)
            elif event == "message_delta":
                u = obj.get("usage", {})
                usage_out += int(u.get("output_tokens", 0) or 0)
            elif event == "content_block_start":
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
        if usage_in or usage_out:
            yield ("usage", {"input_tokens": usage_in,
                             "output_tokens": usage_out,
                             "estimated": False})
        yield ("done", None)


class OpenAIProvider(Provider):
    name = "openai"
    api_url = "https://api.openai.com/v1/chat/completions"

    def __init__(self, api_key: str, model: str):
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set")
        self.api_key = api_key
        self.model = model

    def _extra_headers(self) -> dict:
        """Hook for subclasses (e.g. OpenRouter) to add request headers."""
        return {}

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
        headers = {"Authorization": f"Bearer {self.api_key}",
                   "content-type": "application/json"}
        headers.update(self._extra_headers())
        req = urllib.request.Request(
            self.api_url, data=json.dumps(body).encode(), headers=headers)
        try:
            resp = urllib.request.urlopen(req, timeout=120)
        except Exception as e:
            yield ("error", f"openai request failed: {e}")
            return
        yield from self._parse(resp)

    def _parse(self, resp) -> Iterator[Event]:
        calls: dict[int, dict] = {}
        usage_in = usage_out = 0
        for _event, data in _sse_events(resp):
            if data == "[DONE]":
                break
            try:
                obj = json.loads(data)
            except Exception:
                continue
            u = obj.get("usage")
            if isinstance(u, dict):
                usage_in += int(u.get("prompt_tokens", 0) or 0)
                usage_out += int(u.get("completion_tokens", 0) or 0)
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
        if usage_in or usage_out:
            yield ("usage", {"input_tokens": usage_in,
                             "output_tokens": usage_out,
                             "estimated": False})
        yield ("done", None)


class OpenRouterProvider(OpenAIProvider):
    """OpenRouter transport (OpenAI-compatible) — FREE models only by default.

    The founder's credits are limited, so this provider refuses any model that
    is not free (id ending in ":free", or the "openrouter/free" router) unless
    AEGIS_ALLOW_PAID=1 is set. Default model is a free, tool-calling-capable
    model verified against the live API.
    """

    name = "openrouter"
    api_url = "https://openrouter.ai/api/v1/chat/completions"
    default_model = "nvidia/nemotron-3-super-120b-a12b:free"

    def __init__(self, api_key: str, model: str):
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY is not set")
        model = model or self.default_model
        if not self._is_free(model):
            from .. import config
            if not config.OPENROUTER_ALLOW_PAID:
                raise ValueError(
                    f"OpenRouter model '{model}' is not free — paid models are "
                    "blocked to protect your credits. Use a ':free' model or "
                    "set AEGIS_ALLOW_PAID=1 to override.")
        self.api_key = api_key
        self.model = model

    @staticmethod
    def _is_free(model: str) -> bool:
        return model == "openrouter/free" or model.endswith(":free")

    def _extra_headers(self) -> dict:
        return {"HTTP-Referer": "https://github.com/anilkumara9/aegis",
                "X-Title": "Aegis defensive agent"}


class GoogleProvider(Provider):
    """Gemini API transport (x-goog-api-key header, SSE stream)."""

    name = "google"
    api_base = "https://generativelanguage.googleapis.com/v1beta/models"
    default_model = "gemini-2.0-flash"

    def __init__(self, api_key: str, model: str):
        if not api_key:
            raise ValueError("GOOGLE_API_KEY (or GEMINI_API_KEY) is not set")
        self.api_key = api_key
        self.model = model or self.default_model

    def _to_google(self, messages: list[dict]) -> list[dict]:
        out = []
        for m in messages:
            role, content = m["role"], m.get("content", "")
            if role == "assistant":
                parts = []
                if content:
                    parts.append({"text": content})
                for tc in m.get("tool_calls", []):
                    parts.append({"functionCall": {
                        "name": tc["name"], "args": tc["args"]}})
                out.append({"role": "model", "parts": parts})
            elif role == "tool":
                out.append({"role": "user", "parts": [{
                    "functionResponse": {"name": m.get("name", ""),
                                         "response": {"output": content}}}]})
            else:
                out.append({"role": "user", "parts": [{"text": content}]})
        return out

    def stream(self, messages, tools, system):
        body = {
            "contents": self._to_google(messages),
            "generationConfig": {"temperature": 0.2},
            "tools": [{"functionDeclarations": [
                {"name": t["name"], "description": t["description"],
                 "parameters": t["parameters"]} for t in tools]}],
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        url = f"{self.api_base}/{self.model}:streamGenerateContent?alt=sse"
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(),
            headers={"x-goog-api-key": self.api_key,
                     "content-type": "application/json"})
        try:
            resp = urllib.request.urlopen(req, timeout=120)
        except Exception as e:
            yield ("error", f"google request failed: {e}")
            return
        yield from self._parse(resp)

    def _parse(self, resp) -> Iterator[Event]:
        calls: list[tuple[str, object]] = []
        n = 0
        usage_in = usage_out = 0
        for _event, data in _sse_events(resp):
            if data == "[DONE]":
                continue
            try:
                obj = json.loads(data)
            except Exception:
                continue
            um = obj.get("usageMetadata")
            if isinstance(um, dict):
                # usageMetadata repeats cumulatively per chunk: keep the max.
                usage_in = max(usage_in,
                               int(um.get("promptTokenCount", 0) or 0))
                usage_out = max(usage_out,
                                int(um.get("candidatesTokenCount", 0) or 0))
            for cand in obj.get("candidates", []):
                for part in cand.get("content", {}).get("parts", []):
                    if part.get("text"):
                        yield ("text", part["text"])
                    fc = part.get("functionCall")
                    if fc:
                        n += 1
                        calls.append((f"gem-{n}", fc.get("name", ""),
                                      fc.get("args", {})))
        for cid, cname, cargs in calls:
            yield ("tool_call", ToolCall(cid, cname,
                                         cargs if isinstance(cargs, dict) else {}))
        if usage_in or usage_out:
            yield ("usage", {"input_tokens": usage_in,
                             "output_tokens": usage_out,
                             "estimated": False})
        yield ("done", None)


class OllamaProvider(Provider):
    """Local Ollama transport (/api/chat, newline-delimited JSON stream)."""

    name = "ollama"

    def __init__(self, base_url: str, model: str):
        self.base_url = (base_url or "http://localhost:11434").rstrip("/")
        self.model = model or ""

    def _to_ollama(self, messages: list[dict]) -> list[dict]:
        out = []
        for m in messages:
            role = m["role"]
            if role == "assistant" and m.get("tool_calls"):
                out.append({
                    "role": "assistant", "content": m.get("content") or "",
                    "tool_calls": [{
                        "id": tc["id"], "type": "function",
                        "function": {"name": tc["name"],
                                     "arguments": json.dumps(tc["args"])}}
                        for tc in m["tool_calls"]]})
            elif role == "tool":
                out.append({"role": "tool",
                            "tool_call_id": m.get("tool_call_id", ""),
                            "content": m.get("content", "")})
            else:
                out.append({"role": role, "content": m.get("content", "")})
        return out

    def stream(self, messages, tools, system):
        if not self.model:
            yield ("error", "no model set: use --model <name> "
                            "(ollama pull <name> first)")
            return
        body = {
            "model": self.model, "stream": True,
            "messages": ([{"role": "system", "content": system}] if system else [])
            + self._to_ollama(messages),
            "tools": [{"type": "function",
                       "function": {"name": t["name"],
                                    "description": t["description"],
                                    "parameters": t["parameters"]}}
                      for t in tools],
        }
        req = urllib.request.Request(
            f"{self.base_url}/api/chat", data=json.dumps(body).encode(),
            headers={"content-type": "application/json"})
        try:
            resp = urllib.request.urlopen(req, timeout=120)
        except Exception as e:
            yield ("error", f"ollama request failed: {e}")
            return
        yield from self._parse(resp)

    def _parse(self, resp) -> Iterator[Event]:
        calls: list[tuple[str, dict]] = []
        usage_in = usage_out = 0
        for raw in resp:
            line = raw.decode("utf-8", "ignore").strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("done"):
                # The final done:true line carries the eval counts.
                usage_in = max(usage_in,
                               int(obj.get("prompt_eval_count", 0) or 0))
                usage_out = max(usage_out,
                                int(obj.get("eval_count", 0) or 0))
                break
            msg = obj.get("message", {})
            if msg.get("content"):
                yield ("text", msg["content"])
            for tc in msg.get("tool_calls", []):
                fn = tc.get("function", {})
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    args = _safe_args(args)
                calls.append((fn.get("name", ""),
                              args if isinstance(args, dict) else {}))
        for i, (cname, cargs) in enumerate(calls, 1):
            yield ("tool_call", ToolCall(f"oll-{i}", cname, cargs))
        if usage_in or usage_out:
            yield ("usage", {"input_tokens": usage_in,
                             "output_tokens": usage_out,
                             "estimated": False})
        yield ("done", None)


class MockProvider(Provider):
    """Scripted provider for tests and offline demos. No network.

    script: list of turns; each turn is a dict {"text": str,
    "tool_calls": [{"name": str, "args": dict}]} or {"error": str} to
    simulate a provider failure. Each stream() call pops the next turn.
    A turn may also be a callable(messages) -> turn dict.
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
            yield from self._estimated_usage(messages, "done.")
            yield ("done", None)
            return
        turn = self.script.pop(0)
        if callable(turn):
            turn = turn(messages)
        if "error" in turn:
            yield ("error", turn["error"])
            return
        text = turn.get("text", "")
        if text:
            yield ("text", text)
        for i, tc in enumerate(turn.get("tool_calls", [])):
            yield ("tool_call", ToolCall(tc.get("id", f"mock-{self.calls}-{i}"),
                                        tc["name"], tc.get("args", {})))
        yield from self._estimated_usage(messages, text)
        yield ("done", None)

    @staticmethod
    def _estimated_usage(messages, text):
        """Rough chars/4 token heuristic, honestly flagged estimated=True."""
        in_chars = sum(len(str(m.get("content", ""))) for m in messages)
        yield ("usage", {"input_tokens": max(1, in_chars // 4),
                         "output_tokens": max(1, len(str(text)) // 4),
                         "estimated": True})


def _safe_args(raw: str) -> dict:
    try:
        args = json.loads(raw) if raw else {}
    except Exception:
        args = {}
    return args if isinstance(args, dict) else {}


_PROVIDER_DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-5-20250929",
    "openai": "gpt-4o",
    "google": "gemini-2.0-flash",
    "openrouter": OpenRouterProvider.default_model,
}


def get_provider(name: str = "", model: str = "") -> Provider:
    from .. import config
    name = (name or config.PROVIDER).lower()
    if not model:
        # An explicit AEGIS_MODEL always wins; otherwise default per the
        # *requested* provider (not the ambient one) so that e.g.
        # AEGIS_PROVIDER=openrouter gets a free model, not anthropic's.
        model = config.MODEL if "AEGIS_MODEL" in os.environ \
            else _PROVIDER_DEFAULT_MODELS.get(name, "")
    if name == "anthropic":
        return AnthropicProvider(config.ANTHROPIC_API_KEY, model)
    if name == "openai":
        return OpenAIProvider(config.OPENAI_API_KEY, model)
    if name == "google":
        return GoogleProvider(config.GOOGLE_API_KEY, model)
    if name == "ollama":
        return OllamaProvider(config.OLLAMA_URL, model)
    if name == "openrouter":
        return OpenRouterProvider(config.OPENROUTER_API_KEY, model)
    if name == "mock":
        return MockProvider([])
    raise ValueError(f"unknown provider '{name}' "
                     f"(want anthropic|openai|google|ollama|openrouter|mock)")
