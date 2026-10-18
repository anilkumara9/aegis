"""File tools: read, write, edit. Confined to the working directory."""

from __future__ import annotations

from . import Tool, ToolContext, safe_path


class ReadTool(Tool):
    name = "read"
    description = "Read a file (relative to working directory)."
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "offset": {"type": "integer", "description": "1-based first line"},
            "limit": {"type": "integer", "description": "max lines"},
        },
        "required": ["path"],
    }

    def run(self, args: dict, ctx: ToolContext) -> str:
        try:
            p = safe_path(ctx.cwd, args["path"])
        except PermissionError as e:
            return f"error: {e}"
        if not p.is_file():
            return f"error: not a file: {args['path']}"
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"error: cannot read: {e}"
        lines = text.splitlines()
        offset = max(int(args.get("offset") or 1), 1)
        limit = int(args.get("limit") or 2000)
        chunk = lines[offset - 1: offset - 1 + limit]
        return "\n".join(f"{i + offset:6d}  {l}" for i, l in enumerate(chunk))


class WriteTool(Tool):
    name = "write"
    description = "Write (create or overwrite) a file, relative to working directory."
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"},
        },
        "required": ["path", "content"],
    }

    def run(self, args: dict, ctx: ToolContext) -> str:
        try:
            p = safe_path(ctx.cwd, args["path"])
        except PermissionError as e:
            return f"error: {e}"
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(args.get("content", ""), encoding="utf-8")
        except Exception as e:
            return f"error: cannot write: {e}"
        return f"wrote {p.stat().st_size} bytes to {args['path']}"


class EditTool(Tool):
    name = "edit"
    description = "Replace exact text in a file (first occurrence)."
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "old_text": {"type": "string"},
            "new_text": {"type": "string"},
        },
        "required": ["path", "old_text", "new_text"],
    }

    def run(self, args: dict, ctx: ToolContext) -> str:
        try:
            p = safe_path(ctx.cwd, args["path"])
        except PermissionError as e:
            return f"error: {e}"
        if not p.is_file():
            return f"error: not a file: {args['path']}"
        text = p.read_text(encoding="utf-8", errors="replace")
        old = args.get("old_text", "")
        if old not in text:
            return "error: old_text not found"
        p.write_text(text.replace(old, args.get("new_text", ""), 1), encoding="utf-8")
        return f"edited {args['path']}"
