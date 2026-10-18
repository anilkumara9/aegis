#!/usr/bin/env python3
"""Mock MCP server for Aegis tests. Stdlib only, no network.

Speaks JSON-RPC 2.0 with Content-Length framing over stdio. Usage:
    python mock_server.py <call-log-path>

Every tools/call request is appended (one JSON object per line) to the
call-log path, so tests can assert the guard actually blocked a call
(empty log == the server never saw it).
"""

import json
import os
import sys

LOG_PATH = sys.argv[1] if len(sys.argv) > 1 else os.devnull

# Deliberately fake key: matches the openai_key redaction pattern
# (sk- + 20+ alnum) but is not a real credential.
FAKE_KEY = "sk-proj-FAKEKEY1234567890abcdefg"


def log_call(entry: dict) -> None:
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


TOOLS = [
    {"name": "echo",
     "description": "Echo the 'text' argument back.",
     "inputSchema": {"type": "object",
                     "properties": {"text": {"type": "string"}},
                     "required": ["text"]}},
    {"name": "leak_secret",
     "description": "Returns a response containing a fake secret (for redaction tests).",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "add",
     "description": "Add two numbers.",
     "inputSchema": {"type": "object",
                     "properties": {"a": {"type": "number"},
                                    "b": {"type": "number"}},
                     "required": ["a", "b"]}},
]


def handle_call(name: str, arguments: dict) -> dict:
    if name == "echo":
        return {"content": [{"type": "text",
                             "text": f"echo: {arguments.get('text', '')}"}]}
    if name == "leak_secret":
        return {"content": [{"type": "text",
                             "text": f"here is a fake credential: {FAKE_KEY}"}]}
    if name == "add":
        total = (arguments.get("a") or 0) + (arguments.get("b") or 0)
        return {"content": [{"type": "text", "text": str(total)}]}
    return {"content": [{"type": "text", "text": f"unknown tool: {name}"}],
            "isError": True}


def write_message(payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    sys.stdout.buffer.flush()


def read_message() -> dict | None:
    headers = b""
    while b"\r\n\r\n" not in headers:
        chunk = sys.stdin.buffer.read(1)
        if not chunk:
            return None
        headers += chunk
    head, _, rest = headers.partition(b"\r\n\r\n")
    length = 0
    for line in head.decode("latin-1").split("\r\n"):
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
    body = rest
    while len(body) < length:
        chunk = sys.stdin.buffer.read(length - len(body))
        if not chunk:
            return None
        body += chunk
    return json.loads(body.decode("utf-8"))


def main() -> None:
    while True:
        msg = read_message()
        if msg is None:
            return
        method = msg.get("method")
        req_id = msg.get("id")
        if method == "notifications/initialized":
            continue  # notification: no response
        if method == "initialize":
            write_message({"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "aegis-mock-mcp", "version": "0.1.0"}}})
        elif method == "tools/list":
            write_message({"jsonrpc": "2.0", "id": req_id,
                           "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = msg.get("params", {})
            name = params.get("name", "")
            arguments = params.get("arguments", {})
            log_call({"name": name, "arguments": arguments})
            write_message({"jsonrpc": "2.0", "id": req_id,
                           "result": handle_call(name, arguments)})
        elif req_id is not None:
            write_message({"jsonrpc": "2.0", "id": req_id,
                           "error": {"code": -32601,
                                     "message": f"method not found: {method}"}})


if __name__ == "__main__":
    main()
