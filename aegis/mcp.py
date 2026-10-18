"""MCP client (Pillar 4): connect to MCP servers over stdio and call their
tools THROUGH the guard, exactly like native tools.

Protocol: JSON-RPC 2.0 with Content-Length framing over the server's
stdin/stdout (MCP streamable-HTTP framing applies the same headers;
stdio uses them verbatim). Stdlib only: subprocess + json + select.

Guard contract (core requirement):
  * Every MCP tool call first goes through
    ``GuardSession.check_call(tool=f"mcp__{server}__{tool}", args=args)``.
  * The verdict must be ``allow`` (or ``needs_approval`` resolved by the
    approval callback) BEFORE the call is sent. Denied calls never reach
    the server process — the process is not even spawned for them.
  * Server results pass through secret redaction before returning.

Config: ``<state_dir>/mcp.json`` (``AEGIS_STATE_DIR`` respected):
  {"servers": {"name": {"command": "/path/to/server",
                       "args": ["--flag"], "env": {"KEY": "VAL"}}}}
"""

from __future__ import annotations

import json
import os
import select
import subprocess
from pathlib import Path
from typing import Any

from . import config
from .detect import secrets as sec
from .tools import Tool

MCP_PROTOCOL_VERSION = "2024-11-05"
INITIALIZE_TIMEOUT = 15.0
REQUEST_TIMEOUT = 60.0


class MCPError(Exception):
    """MCP client error: bad config, dead server, protocol violation."""


def config_path() -> Path:
    """MCP config location; honors AEGIS_STATE_DIR like everything else."""
    return config.state_dir() / "mcp.json"


def load_config(path: Path | None = None) -> dict[str, dict]:
    """Load ``{"servers": {...}}``. Missing file -> no servers (MCP optional).

    Each server entry needs ``command`` (str); ``args`` (list of str) and
    ``env`` (dict of str->str) are optional. Raises MCPError on malformed
    config — fail fast rather than half-wiring a server.
    """
    path = path or config_path()
    if not path.exists():
        return {"servers": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise MCPError(f"cannot read MCP config {path}: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("servers", {}), dict):
        raise MCPError(f"MCP config {path} must be "
                       f'{{"servers": {{<name>: {{...}}}}}}')
    servers: dict[str, dict] = {}
    for name, entry in data["servers"].items():
        if not isinstance(entry, dict) or not isinstance(entry.get("command"), str):
            raise MCPError(f'MCP server "{name}" needs a "command" string')
        args = entry.get("args", [])
        env = entry.get("env", {})
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise MCPError(f'MCP server "{name}": "args" must be a list of strings')
        if not isinstance(env, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
            raise MCPError(f'MCP server "{name}": "env" must be a string->string map')
        servers[name] = {"command": entry["command"], "args": args, "env": env}
    return {"servers": servers}


class MCPClient:
    """One spawned MCP server process, speaking JSON-RPC 2.0 over stdio."""

    def __init__(self, name: str, spec: dict):
        self.name = name
        self.spec = spec
        self._id = 0
        self._buf = b""
        env = dict(os.environ)
        env.update(spec["env"])
        try:
            self._proc = subprocess.Popen(
                [spec["command"], *spec["args"]],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env=env)
        except OSError as e:
            raise MCPError(f'MCP server "{name}" failed to start: {e}') from e
        self._stdin = self._proc.stdin
        self._stdout = self._proc.stdout

    # -- framing ----------------------------------------------------------
    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _write_message(self, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
        self._stdin.flush()

    def _read_message(self, timeout: float) -> dict:
        """Read one Content-Length-framed JSON-RPC message."""
        import time
        buf = self._buf
        end = time.monotonic() + timeout
        length: int | None = None
        while True:
            if length is None:
                # Consume headers until the blank line.
                while b"\r\n\r\n" in buf:
                    head, _, rest = buf.partition(b"\r\n\r\n")
                    buf = rest
                    headers = {}
                    for line in head.decode("latin-1").split("\r\n"):
                        if ":" in line:
                            k, v = line.split(":", 1)
                            headers[k.strip().lower()] = v.strip()
                    if "content-length" in headers:
                        length = int(headers["content-length"])
                        break
                    # Defensive: skip any stray non-framed line.
                    continue
            if length is not None and len(buf) >= length:
                body, buf = buf[:length], buf[length:]
                self._buf = buf
                return json.loads(body.decode("utf-8"))
            if time.monotonic() >= end:
                raise MCPError(f'MCP server "{self.name}": read timed out')
            if self._proc.poll() is not None:
                raise MCPError(f'MCP server "{self.name}" exited (code '
                               f'{self._proc.returncode}) while awaiting response')
            r, _, _ = select.select([self._stdout], [], [],
                                    min(1.0, max(0.0, end - time.monotonic())))
            if r:
                chunk = os.read(self._stdout.fileno(), 65536)
                if not chunk:
                    raise MCPError(f'MCP server "{self.name}" closed stdout')
                buf += chunk

    def _request(self, method: str, params: dict | None = None,
                 timeout: float = REQUEST_TIMEOUT) -> Any:
        self._write_message({"jsonrpc": "2.0", "id": self._next_id(),
                             "method": method,
                             **({"params": params} if params is not None else {})})
        msg = self._read_message(timeout)
        if "error" in msg:
            err = msg["error"]
            raise MCPError(f'MCP server "{self.name}" error '
                           f'{err.get("code")}: {err.get("message")}')
        return msg.get("result")

    # -- MCP lifecycle -----------------------------------------------------
    def initialize(self, timeout: float = INITIALIZE_TIMEOUT) -> dict:
        result = self._request("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "aegis", "version": "0.5.0"},
        }, timeout=timeout)
        # Tell the server we're ready; no response expected.
        self._write_message({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result or {}

    def list_tools(self) -> list[dict]:
        result = self._request("tools/list", {})
        tools = (result or {}).get("tools", [])
        return [t for t in tools if isinstance(t, dict) and t.get("name")]

    def call_tool(self, tool: str, arguments: dict | None = None) -> str:
        result = self._request("tools/call",
                               {"name": tool, "arguments": arguments or {}})
        content = (result or {}).get("content", [])
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
            elif isinstance(block, dict):
                parts.append(json.dumps(block))
        text = "\n".join(parts)
        if (result or {}).get("isError"):
            text = f"MCP tool error: {text}" if text else "MCP tool error"
        return text

    def close(self) -> None:
        try:
            if self._proc.poll() is None:
                self._proc.terminate()
                self._proc.wait(timeout=3)
        except Exception:
            pass
        finally:
            try:
                self._proc.kill()
            except Exception:
                pass


def mcp_tool_name(server: str, tool: str) -> str:
    return f"mcp__{server}__{tool}"


class MCPManager:
    """Owns MCP server processes and enforces the guard contract.

    ``call()`` runs the guard FIRST; the server process is only spawned
    (lazily) after the verdict comes back ``allow``/approved. Denied calls
    therefore never reach the server process — they never even create it.
    """

    def __init__(self, servers: dict[str, dict]):
        self.servers = servers
        self._clients: dict[str, MCPClient] = {}

    @classmethod
    def from_config(cls, path: Path | None = None) -> "MCPManager":
        return cls(load_config(path)["servers"])

    def client_for(self, server: str) -> MCPClient:
        """Spawn (once) and initialize the server process. Guard-screened
        callers must have an allow verdict before reaching here."""
        if server not in self.servers:
            raise MCPError(f'unknown MCP server "{server}"')
        client = self._clients.get(server)
        if client is None:
            client = MCPClient(server, self.servers[server])
            try:
                client.initialize()
            except Exception:
                client.close()
                raise
            self._clients[server] = client
        return client

    def list_server_tools(self, server: str) -> list[dict]:
        return self.client_for(server).list_tools()

    def call(self, server: str, tool: str, args: dict, ctx) -> str:
        """Guard-screened MCP tool call. Returns redacted text result."""
        tool_name = mcp_tool_name(server, tool)
        guard = ctx.guard_session
        verdict = guard.check_call(tool_name, args or {})
        if verdict.decision == "deny":
            return (f"GUARD DENIED: {verdict.reason}. Do not attempt to "
                    f"work around this. Continue safely.")
        if verdict.decision == "needs_approval":
            cb = getattr(ctx, "approval_callback", None)
            if not callable(cb) or not cb(verdict.findings):
                return ("GUARD DENIED: MCP tool call needs human approval "
                        "and it was not granted. Continue safely.")
        try:
            client = self.client_for(server)
            raw = client.call_tool(tool, args or {})
        except MCPError as e:
            return f"error: MCP call failed: {e}"
        redacted, _ = sec.redact(raw)
        return redacted

    def close_all(self) -> None:
        for client in self._clients.values():
            client.close()
        self._clients.clear()


class MCPTool(Tool):
    """Native Tool facade for one MCP server tool.

    Registered in the tool registry as ``mcp__<server>__<tool>`` so the
    agent loop's guard check hits the exact MCP tool name; ``run()`` then
    delegates to MCPManager.call, which re-checks (belt and suspenders —
    the guard always sees the real name and args).
    """

    def __init__(self, manager: MCPManager, server: str, tool_spec: dict):
        self.manager = manager
        self.server = server
        self.tool_spec = tool_spec
        self.name = mcp_tool_name(server, tool_spec["name"])
        desc = tool_spec.get("description") or ""
        self.description = f"[MCP:{server}] {desc}".strip()
        schema = tool_spec.get("inputSchema") or {}
        self.parameters = schema if isinstance(schema, dict) else {}

    def run(self, args: dict, ctx) -> str:
        return self.manager.call(self.server, self.tool_spec["name"], args or {}, ctx)


def register_mcp_tools(tools: dict, manager: MCPManager | None = None) -> list[str]:
    """Discover MCP servers from config and register one MCPTool per
    server tool into ``tools``. Failures are non-fatal: MCP is optional,
    a dead server must never break the agent. Returns registered names.
    """
    try:
        manager = manager or MCPManager.from_config()
    except MCPError:
        return []
    registered: list[str] = []
    for server in manager.servers:
        try:
            specs = manager.list_server_tools(server)
        except Exception:
            continue  # dead/misbehaving server: skip, agent still works
        for spec in specs:
            t = MCPTool(manager, server, spec)
            tools[t.name] = t
            registered.append(t.name)
    return registered
