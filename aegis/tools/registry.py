"""Tool registry: every tool the agent loop can call."""

from .bash import BashTool
from .files import EditTool, ReadTool, WriteTool
from .knowledge import KBQueryTool, RespondTool, ScanTraceTool
from .webfetch import WebFetchTool

TOOLS: dict[str, object] = {}
for _cls in (BashTool, ReadTool, WriteTool, EditTool, WebFetchTool,
             KBQueryTool, ScanTraceTool, RespondTool):
    _inst = _cls()
    TOOLS[_inst.name] = _inst

TOOL_NAMES = sorted(TOOLS)

__all__ = ["TOOLS", "TOOL_NAMES"]
