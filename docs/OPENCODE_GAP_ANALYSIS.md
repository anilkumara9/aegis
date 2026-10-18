# OpenCode vs Aegis — Gap Analysis (v0.2)

**Date:** 2026-10-18. **Reference:** shallow clone of `https://github.com/anomalyco/opencode.git`
(founder-authorized, interface/UX analysis only). **Method:** read-only study of
OpenCode's TUI component inventory, prompt system, session/dialog architecture,
and config surface. **No OpenCode code was copied into Aegis** — UX patterns are
rebuilt from scratch.

> The security thesis, in one line: OpenCode's own docs admit it "does not
> sandbox the agent" and its permission prompts are "a UX feature" rather than
> a security boundary. Aegis inverts this: the guard engine is *inside* the
> agent loop, so permissions are a real boundary. v0.2 closes the *usability*
> gap while keeping the *security* advantage.

## Feature-by-feature table

| # | Feature | OpenCode (observed) | Aegis v0.1.0 | v0.2 target |
|---|---------|---------------------|--------------|-------------|
| 1 | App shell | Full-screen TUI: session tabs + tabs rail, status bar, dialogs | Line-based REPL (`input()` loop), banner | Keep terminal-native; richer in-flow display (no full TUI rewrite — Python-clean) |
| 2 | Session management | Session list dialog: browse, resume, rename, share; session tabs | Guard session JSON on disk (policy+revocation); conversation history NOT persisted | **Conversation sessions: list/resume/rename/delete, history persisted** |
| 3 | Command palette | `command-palette.tsx`: fuzzy picker over commands | `/help` prints static list | **Slash-command palette: `/` lists numbered commands, filter-as-you-type** |
| 4 | Prompt input | @-file mentions, /slash commands, image attachments, directory completion w/ frecency, history, stash | Plain text + slash commands | **@-file mentions (bonus)**; keep plain-text core |
| 5 | Tool-call display | Message parts w/ collapsible tool calls, per-tool status, shell-output dialog | Tool calls execute silently; only model text streams | **Formatted tool blocks: `⏺ tool(args)` → `✓/✗` + duration + excerpt** |
| 6 | Diff previews | `patch-diff.tsx`; workspace-file-changes dialog for review | None — edits apply without preview | **Unified diff preview in the approval flow for write/edit** |
| 7 | Streaming | Token streaming w/ spinners/shimmer | Text streams via `on_text` callback | Keep; ensure tool blocks don't break the stream |
| 8 | Permission prompts | Inline prompt: allow once / always / reject (UX-only per their docs) | Terminal y/N approval w/ findings listed; deny is enforced pre-execution | Keep enforcement; **add diff preview + allow-always-per-session option** |
| 9 | MCP integration | MCP dialog: add/configure servers, tool list | None (own tool registry) | Out of v0.2 scope (own tools cover the loop; MCP later) |
| 10 | Model picker | Dialog to switch models/providers mid-session | `--provider` flag + env keys at startup | `/model` switch mid-session (small) |
| 11 | Config system | Layered config (global/project), keybind config, themes | `config.py`: state dirs, env keys | Keep minimal; document |
| 12 | Keybindings | Configurable keymap | None (line REPL) | Out of scope for line REPL |
| 13 | Auditability | Session transcripts | **JSONL audit log of every tool call, secrets redacted** | **Aegis leads — extend to incident timeline** |
| 14 | Secret handling | Keys held in Console workspace (breach vector, Oct 2026) | **Redaction at every boundary; keys never in model context** | **Aegis leads** |
| 15 | Sandboxing | None by default (docs recommend Docker/VM) | Docker sandbox option for bash | **Sandbox on by default when Docker present** |
| 16 | Autonomous defense | None (single interactive agent) | `/hunt`, `/scan` on demand | **`aegis watch`: continuous monitoring, scheduled hunts, auto-triage** |

## What v0.2 builds (mapped to table rows)

- **Row 2** — `aegis/session.py`: persistent conversation sessions (list/resume/rename/delete).
- **Row 3** — slash-command palette in `repl.py`.
- **Row 5** — tool-call display blocks via additive `AgentLoop` callbacks.
- **Row 6** — `aegis/diffx.py`: unified diff preview wired into approval.
- **Row 8** — approval shows diff + findings; allow-always-per-session.
- **Row 10** — `/model` mid-session provider switch (small).
- **Row 13** — `aegis respond timeline`: incident timeline from audit + triage.
- **Row 16** — `aegis/watch.py`: SOC-in-a-box (watch, scheduled hunts, triage queue).

## Deliberately out of v0.2

Full-screen TUI (row 1), MCP client (row 9), keybind config (row 12), themes —
UX surface without security value; Python TUI rewrites risk more than they add.
These stay parked; the terminal-native REPL is the product surface.
