"""webfetch tool: plain HTTP(S) GET with timeout and size cap."""

from __future__ import annotations

import re
import urllib.request

from . import Tool, ToolContext
from .. import config

_TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.DOTALL | re.IGNORECASE)
_HTML_RE = re.compile(r"<[^>]+>")


class WebFetchTool(Tool):
    name = "webfetch"
    description = ("Fetch a URL over HTTP(S) and return its text content. "
                   "Guard-screened: domain allowlist + secret-payload rules apply.")
    parameters = {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    }

    def run(self, args: dict, ctx: ToolContext) -> str:
        url = (args.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            return "error: only http(s) URLs are allowed"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Aegis/0.1"})
            with urllib.request.urlopen(req, timeout=config.WEBFETCH_TIMEOUT) as r:
                raw = r.read(config.WEBFETCH_MAX_BYTES + 1)
        except Exception as e:
            return f"error: fetch failed: {e}"
        if len(raw) > config.WEBFETCH_MAX_BYTES:
            raw = raw[:config.WEBFETCH_MAX_BYTES]
        text = raw.decode("utf-8", "ignore")
        text = _TAG_RE.sub(" ", text)
        text = _HTML_RE.sub(" ", text)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n\n", text)
        return text.strip()[:config.WEBFETCH_MAX_BYTES]
