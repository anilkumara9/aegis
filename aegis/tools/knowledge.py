"""Knowledge tools: kb_query, scan_trace, respond — the KB wired into the loop."""

from __future__ import annotations

from . import Tool, ToolContext


class KBQueryTool(Tool):
    name = "kb_query"
    description = ("Search Aegis's defensive technique knowledge base mid-reasoning. "
                   "Returns matching techniques with indicators and mitigations.")
    parameters = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "what to look up"},
            "top_k": {"type": "integer", "description": "max results (default 5)"},
        },
        "required": ["query"],
    }

    def run(self, args: dict, ctx: ToolContext) -> str:
        results = ctx.kb.query(args.get("query", ""),
                               top_k=int(args.get("top_k") or 5))
        if not results:
            return "no KB matches."
        out = []
        for t in results:
            out.append(
                f"## {t.id} [{t.severity}] {t.name}\n"
                f"{t.description}\n"
                f"Indicators: {'; '.join(t.indicators[:4])}\n"
                f"Mitigations: {'; '.join(t.mitigations[:3])}")
        return "\n\n".join(out)


class ScanTraceTool(Tool):
    name = "scan_trace"
    description = ("Analyze a JSONL tool-call trace for attack techniques. "
                   "Input: path to a .jsonl trace file.")
    parameters = {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    }

    def run(self, args: dict, ctx: ToolContext) -> str:
        from . import safe_path
        from ..scan import format_text, load_trace, scan_calls
        try:
            p = safe_path(ctx.cwd, args["path"])
        except PermissionError as e:
            return f"error: {e}"
        try:
            calls = load_trace(p)
        except Exception as e:
            return f"error: {e}"
        findings = scan_calls(calls, ctx.kb)
        return format_text(findings, len(calls))


class RespondTool(Tool):
    name = "respond"
    description = ("Generate an incident-response runbook. Playbooks: "
                   "rotate-keys, kill-session, quarantine-workspace, incident-report. "
                   "Emits operator steps only; never touches provider accounts.")
    parameters = {
        "type": "object",
        "properties": {
            "playbook": {"type": "string"},
            "detail": {"type": "string",
                       "description": "extra context (e.g. provider name, findings summary)"},
        },
        "required": ["playbook"],
    }

    def run(self, args: dict, ctx: ToolContext) -> str:
        from ..respond.playbooks import run_playbook
        try:
            return run_playbook(args["playbook"], ctx,
                                detail=args.get("detail", ""))
        except Exception as e:
            return f"error: {e}"
