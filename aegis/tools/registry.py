"""Tool registry: every tool the agent loop can call."""

from .bash import BashTool
from .files import EditTool, ReadTool, WriteTool
from .index_tool import IndexQueryTool
from .inspect import HashTool, NetConnsTool, PsTool, SearchTool
from .knowledge import KBQueryTool, RespondTool, ScanTraceTool
from .webfetch import WebFetchTool

TOOLS: dict[str, object] = {}
for _cls in (BashTool, ReadTool, WriteTool, EditTool, WebFetchTool,
             KBQueryTool, ScanTraceTool, RespondTool,
             PsTool, NetConnsTool, HashTool, SearchTool, IndexQueryTool):
    _inst = _cls()
    TOOLS[_inst.name] = _inst

TOOL_NAMES = sorted(TOOLS)

# Pillar 4 (MCP): discover configured MCP servers and register one native
# tool per server tool (mcp__<server>__<tool>). Non-fatal by design — MCP is
# optional, and a dead server must never break the agent loop.
try:
    from .. import mcp as _mcp
    _mcp.register_mcp_tools(TOOLS)
except Exception:
    pass

__all__ = ["TOOLS", "TOOL_NAMES"]
