# MCP Client (Pillar 4)

Connect Aegis to MCP (Model Context Protocol) servers over stdio and call
their tools **through the guard**, exactly like native tools. No MCP server
can be reached without passing the guard first.

## Protocol notes

- Transport: the server is a child process; JSON-RPC 2.0 messages travel
  over its stdin/stdout with `Content-Length` headers (`aegis/mcp.py`,
  stdlib only: `subprocess` + `json` + `select`).
- Handshake: `initialize` (protocol version `2024-11-05`,
  `clientInfo: {"name": "aegis", "version": "0.4.0"}`), then the
  `notifications/initialized` notification. The server is initialized
  lazily — only after the guard has approved a first call to it.
- Tool surface: `tools/list` for discovery, `tools/call` for execution.
  Server processes live for the session and are shut down cleanly on exit.
- MCP is **optional**: with no config file, everything works as before.
  A misconfigured or dead server is skipped with a warning — it never
  breaks the agent loop.

## Config format

`~/.aegis/mcp.json` (respects `AEGIS_STATE_DIR`, exactly like sessions and
audit logs):

```json
{
  "servers": {
    "my-tools": {
      "command": "/usr/local/bin/my-mcp-server",
      "args": ["--stdio"],
      "env": {"MY_API_KEY": "…"}
    },
    "notes": {
      "command": "python3",
      "args": ["/home/user/mcp/notes_server.py"],
      "env": {}
    }
  }
}
```

- `command` (required): executable to spawn. `args` / `env` are optional;
  `env` is merged over the current environment.
- Malformed config fails fast with a clear error at startup
  (`aegis mcp list` will tell you).

## Guard behavior (the core contract)

Every MCP tool is registered in the agent loop as
`mcp__<server>__<tool>` (e.g. `mcp__notes__search`). Before any call:

1. `GuardSession.check_call(tool="mcp__<server>__<tool>", args=args)` runs —
   the same allowlist/denylist, arg-pattern, offensive-tooling, secret-egress,
   and severity-escalation checks as native tools. Plan mode denies
   MCP calls the same way it denies other tools (MCP tools are not
   read-only by default; put them on the policy allowlist deliberately).
2. `deny` → the call is refused and **never reaches the server process** —
   the process is not even spawned for a denied call.
   `needs_approval` → resolved via the approval callback; unapproved calls
   are refused the same way.
3. Allowed calls execute, then the result passes through **secret
   redaction** before the agent (or CLI output) ever sees it.

So a policy can do, for example:

```python
Policy(denied_tools={"mcp__notes__delete"})          # block one tool
Policy(allowed_tools={"read", "kb_query", "mcp__notes__search"})  # allowlist mode
```

## CLI

```bash
aegis mcp list                  # all servers and their guard-screened tool names
aegis mcp list --server notes   # one server
aegis mcp call notes search --args '{"q": "hunt report"}'
```

`mcp call` runs under a fresh guard session (`Policy(name="mcp-cli")`);
denials print `GUARD DENIED: <reason>` and return exit code 0 with the
denial message (the refusal is the correct, safe outcome, not a crash).

## In the agent loop

Configured MCP tools appear in the tool registry automatically
(`aegis/tools/registry.py` discovers them at import). The model sees the
server's tool descriptions prefixed `[MCP:<server>]` and their real
`inputSchema`s. Each call goes through the loop's normal
`check_call → approve → run → redact` pipeline — an MCP tool cannot do
anything a native tool of the same name couldn't.

## Defensive boundary

MCP servers are **untrusted code from the guard's perspective**: their
descriptions are treated as data (KB watches for tool-description
poisoning patterns), their outputs are redacted, and the guard — not the
server — decides what runs. Aegis connects MCP servers for *defense*
(log analysis, asset inventory, local tooling). Connecting a server you
do not trust, or granting an MCP tool egress-capable args, is an operator
decision the guard policies are there to constrain.

## Running the mock server (tests)

`tests/fixtures/mcp/mock_server.py` is a stdlib-only mock MCP server:

```bash
python tests/fixtures/mcp/mock_server.py /tmp/mock-calls.jsonl
```

It answers `initialize` / `tools/list` / `tools/call`, exposes `echo`,
`leak_secret` (returns a fake key, for redaction tests), and `add`, and
appends every `tools/call` it receives to the given log file — the tests
assert on that log to prove denied calls never reached it. Full coverage:

```bash
/home/hatch/workspace/aegis/.venv/bin/python -m pytest tests/test_mcp.py -v
```
