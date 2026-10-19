"""index_query tool: ranked file retrieval over the codebase index.

Lets the agent pull relevant files per-request (keyword + symbol
matching) instead of loading everything into context. Read-only: it
never returns file contents, only ranked paths with match scores —
the agent then reads the files it actually needs with the read tool.
"""

from __future__ import annotations

from pathlib import Path

from . import Tool, ToolContext, safe_path
from ..index import CodeIndex, query_index


class IndexQueryTool(Tool):
    name = "index_query"
    description = ("Rank files in a local directory by relevance to a "
                   "query (keyword + symbol matching over an incremental "
                   "code index). Returns scored paths only, no file "
                   "contents. Read-only.")
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string",
                     "description": "local directory to search "
                                    "(relative to working directory)"},
            "query": {"type": "string",
                      "description": "what to look for, e.g. a symbol or "
                                     "feature name"},
            "top_k": {"type": "integer",
                      "description": "max files to return (default 8)"},
        },
        "required": ["path", "query"],
    }

    def run(self, args: dict, ctx: ToolContext) -> str:
        raw = (args.get("path") or ".").strip() or "."
        query = (args.get("query") or "").strip()
        if not query:
            return "error: query is empty"
        try:
            top_k = int(args.get("top_k") or 8)
        except (TypeError, ValueError):
            return "error: top_k must be an integer"
        top_k = max(1, min(top_k, 50))
        try:
            target = safe_path(ctx.cwd, raw)
        except PermissionError as e:
            return f"error: {e}"
        if not target.is_dir():
            return f"error: not a directory: {raw}"
        try:
            ranked = query_index(target, query, top_k=top_k)
        except Exception as e:
            return f"error: index query failed: {type(e).__name__}: {e}"
        if not ranked:
            return f"no indexed files match '{query}' under {raw}"
        lines = [f"top {len(ranked)} matches for '{query}' under {raw}:"]
        for score, rel in ranked:
            lines.append(f"- {rel}  (score {score:.0f})")
        lines.append("Use the read tool to inspect the files you need.")
        return "\n".join(lines)
