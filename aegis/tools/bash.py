"""bash tool: shell execution, Docker-sandboxed when available."""

from __future__ import annotations

import shutil
import subprocess

from . import Tool, ToolContext
from .. import config


def _docker_available() -> bool:
    return shutil.which("docker") is not None


class BashTool(Tool):
    name = "bash"
    description = ("Run a shell command. Sandboxed in Docker when available "
                   "(--network none, workdir-only mount). Guard-screened.")
    parameters = {
        "type": "object",
        "properties": {
            "cmd": {"type": "string", "description": "shell command to run"},
            "timeout": {"type": "integer", "description": "seconds (default 60)"},
        },
        "required": ["cmd"],
    }

    def run(self, args: dict, ctx: ToolContext) -> str:
        cmd = (args.get("cmd") or "").strip()
        if not cmd:
            return "error: empty command"
        timeout = int(args.get("timeout") or config.BASH_TIMEOUT)
        use_docker = (config.SANDBOX == "docker"
                      or (config.SANDBOX == "auto" and _docker_available()))
        try:
            if use_docker:
                argv = ["docker", "run", "--rm", "--network", "none",
                        "-v", f"{ctx.cwd}:/work", "-w", "/work",
                        config.DOCKER_IMAGE, "bash", "-c", cmd]
                proc = subprocess.run(argv, capture_output=True, text=True,
                                      timeout=timeout + 30)
                note = "[sandbox: docker]"
            else:
                proc = subprocess.run(cmd, shell=True, capture_output=True,
                                      text=True, timeout=timeout, cwd=str(ctx.cwd))
                note = ("[sandbox: none — docker unavailable, ran on host; "
                        "guard screening still applied]")
        except subprocess.TimeoutExpired:
            return f"error: command timed out after {timeout}s"
        except Exception as e:
            return f"error: execution failed: {e}"
        out = (proc.stdout or "") + (proc.stderr or "")
        if len(out) > 20000:
            out = out[:20000] + "\n...[truncated]"
        return f"{note}\nexit={proc.returncode}\n{out}"
