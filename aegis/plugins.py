"""Plugin system (v0.7 Lane A): formal plugin interface for Aegis.

Plugins are single-file Python modules discovered from plugin
directories (default: ~/.aegis/plugins/*.py) plus an optional YAML
config (~/.aegis/plugins.yaml). Each plugin declares:

    PLUGIN = {
        "name": "todo_scan",                 # [a-z][a-z0-9_]*, unique
        "description": "...",                # shown to the model
        "parameters": {...},                 # JSON-schema-style dict
        "run": callable,                     # run(args: dict, ctx) -> str
    }

or equivalently a module-level ``def register() -> dict`` returning the
same mapping.

Hardening rules (company-grade):
- malformed plugin -> skipped with a warning; core never crashes.
- error isolation: a plugin handler exception is captured and returned
  as an error string; the agent loop keeps running.
- name collisions with core tools -> core wins, plugin skipped.
- secrets: plugin args and outputs pass through the agent loop's
  redaction layer before the model or audit log sees them
  (see agent.AgentLoop._guarded_execute). Plugins that echo file
  content should redact via aegis.detect.secrets themselves.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import config
from .tools import Tool, ToolContext

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

DEFAULT_PLUGIN_DIRNAME = "plugins"
CONFIG_FILENAME = "plugins.yaml"


@dataclass
class PluginSpec:
    name: str
    description: str
    parameters: dict
    handler: Callable
    source: str = ""          # file the plugin was loaded from


class PluginTool(Tool):
    """A discovered plugin exposed as an agent-loop tool.

    Exceptions from the plugin handler are isolated: they become an
    error string, never a crash.
    """

    def __init__(self, spec: PluginSpec):
        self.plugin_spec = spec
        self.name = spec.name
        self.description = spec.description
        self.parameters = spec.parameters

    def run(self, args: dict, ctx: ToolContext) -> str:
        if not isinstance(args, dict):
            return f"error: plugin '{self.name}': args must be an object"
        try:
            out = self.plugin_spec.handler(dict(args), ctx)
        except Exception as e:
            return (f"error: plugin '{self.name}' failed: "
                    f"{type(e).__name__}: {e}")
        return str(out) if out is not None else ""


def _default_plugin_dir() -> Path:
    return config.state_dir() / DEFAULT_PLUGIN_DIRNAME


def _read_config() -> dict:
    """Read ~/.aegis/plugins.yaml. Malformed -> {} (never raises)."""
    p = config.state_dir() / CONFIG_FILENAME
    if not p.is_file():
        return {}
    try:
        import yaml
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def plugin_dirs() -> list[Path]:
    """Plugin directories: config-listed first, then the default."""
    dirs: list[Path] = []
    cfg = _read_config()
    for raw in cfg.get("plugin_dirs", []) or []:
        d = Path(str(raw)).expanduser()
        if d.is_dir() and d not in dirs:
            dirs.append(d)
    default = _default_plugin_dir()
    if default.is_dir() and default not in dirs:
        dirs.append(default)
    return dirs


def _validate(name: str, mapping: dict, source: str
              ) -> tuple[PluginSpec | None, str]:
    """Validate a plugin mapping. Returns (spec, warning)."""
    if not isinstance(mapping, dict):
        return None, f"{source}: register()/PLUGIN must be a dict — skipped"
    pname = mapping.get("name", name)
    if not isinstance(pname, str) or not _NAME_RE.match(pname):
        return None, (f"{source}: bad plugin name {pname!r} "
                      f"(want {_NAME_RE.pattern}) — skipped")
    desc = mapping.get("description", "")
    if not isinstance(desc, str) or not desc.strip():
        return None, f"{source}: plugin '{pname}' needs a description — skipped"
    params = mapping.get("parameters", {})
    if not isinstance(params, dict):
        return None, (f"{source}: plugin '{pname}' parameters must be a "
                      f"dict — skipped")
    handler = mapping.get("run")
    if not callable(handler):
        return None, (f"{source}: plugin '{pname}' needs a callable "
                      f"'run(args, ctx)' — skipped")
    return PluginSpec(name=pname, description=desc.strip(),
                      parameters=params, handler=handler,
                      source=str(source)), ""


def _load_module(path: Path):
    """Import a plugin file in isolation. Raises on failure."""
    mod_name = f"aegis_plugin_{re.sub(r'[^a-zA-Z0-9_]', '_', path.stem)}"
    # unique per path so re-discovery picks up edits
    mod_name += f"_{abs(hash(str(path))) % 10_000_000}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot build import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(mod_name, None)
        raise
    return module


def discover(dirs: "list[str | Path] | None" = None
             ) -> tuple[list[PluginSpec], list[str]]:
    """Discover plugins. Never raises: every failure becomes a warning.

    Returns (specs, warnings). Later directories win on duplicate names;
    duplicates across the same scan keep the first and warn.
    """
    warnings: list[str] = []
    specs: list[PluginSpec] = []
    seen: dict[str, str] = {}
    search = [Path(d).expanduser() for d in dirs] if dirs is not None \
        else plugin_dirs()
    disabled = set(_read_config().get("disabled", []) or [])
    for d in search:
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.py")):
            if path.name.startswith("__"):
                continue
            try:
                module = _load_module(path)
            except Exception as e:
                warnings.append(f"{path.name}: import failed "
                                f"({type(e).__name__}: {e}) — skipped")
                continue
            try:
                if callable(getattr(module, "register", None)):
                    mapping = module.register()
                else:
                    mapping = getattr(module, "PLUGIN", None)
                spec, warn = _validate(path.stem, mapping, path.name)
            except Exception as e:
                warnings.append(f"{path.name}: registration crashed "
                                f"({type(e).__name__}: {e}) — skipped")
                continue
            if warn:
                warnings.append(warn)
                continue
            assert spec is not None
            if spec.name in disabled:
                warnings.append(f"plugin '{spec.name}' disabled by config "
                                f"— skipped")
                continue
            if spec.name in seen:
                warnings.append(f"duplicate plugin name '{spec.name}' in "
                                f"{path.name} (first seen in {seen[spec.name]})"
                                f" — skipped")
                continue
            seen[spec.name] = path.name
            specs.append(spec)
    return specs, warnings


def register_plugin_tools(registry: dict, specs: list[PluginSpec]
                          ) -> tuple[list[str], list[str]]:
    """Expose plugin specs as tools in a tool registry dict.

    Core tools win name collisions: a colliding plugin is skipped with
    a warning. Returns (added_names, warnings).
    """
    added: list[str] = []
    warnings: list[str] = []
    for spec in specs:
        if spec.name in registry:
            warnings.append(f"plugin '{spec.name}' collides with a core "
                            f"tool — skipped")
            continue
        registry[spec.name] = PluginTool(spec)
        added.append(spec.name)
    return added, warnings
