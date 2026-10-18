"""Incident-response playbooks as code.

v1 rule: playbooks EMIT exact operator runbooks. They never execute
destructive provider actions (key revocation, account changes). The one
real local action is kill-session, which revokes the guard session on this
machine via the kill-switch.
"""

from __future__ import annotations

import json
import time

PLAYBOOKS = ["rotate-keys", "kill-session", "quarantine-workspace",
             "incident-report"]


def run_playbook(name: str, ctx=None, detail: str = "") -> str:
    fn = {"rotate-keys": _rotate_keys,
          "kill-session": _kill_session,
          "quarantine-workspace": _quarantine_workspace,
          "incident-report": _incident_report}.get(name)
    if not fn:
        raise ValueError(f"unknown playbook '{name}'. Choose from: "
                         + ", ".join(PLAYBOOKS))
    return fn(ctx, detail or "")


def _header(title: str) -> str:
    return (f"# Aegis incident runbook: {title}\n"
            f"_Generated {time.strftime('%Y-%m-%d %H:%M %Z')}. "
            f"Operator-executed steps — Aegis takes no destructive provider "
            f"actions in v1._\n")


def _rotate_keys(ctx, detail: str) -> str:
    providers = {"openai": "OpenAI", "anthropic": "Anthropic", "google": "Google"}
    want = detail.strip().lower()
    selected = [providers[want]] if want in providers else list(providers.values())
    out = [_header("rotate-keys"),
           "Compromised or possibly-compromised provider API keys must be "
           "revoked and replaced. Do this in the provider dashboard — "
           "Aegis never touches provider accounts.\n"]
    steps = {
        "OpenAI": [
            "Open https://platform.openai.com/api-keys while signed in as the key owner.",
            "Identify every key that was stored in / accessible to the affected workspace.",
            "For each: click the key → Revoke/Delete. Revocation is immediate.",
            "Create replacement keys with the minimum scopes the workload needs.",
            "Update the workload to use the new keys from a secret manager (never plaintext files).",
            "Verify: in Usage dashboard, confirm the old key shows no new activity and the new key does.",
        ],
        "Anthropic": [
            "Open https://console.anthropic.com/settings/keys as the key owner.",
            "Identify every key exposed to the affected workspace.",
            "For each: Revoke the key. Revocation is immediate.",
            "Create replacement keys; restrict workspace access if the console supports it.",
            "Update the workload to use the new keys from a secret manager.",
            "Verify: confirm revoked keys return authentication errors and new keys work.",
        ],
        "Google": [
            "Open https://console.cloud.google.com/apis/credentials for the affected project.",
            "Identify every API key that was stored in / accessible to the affected workspace.",
            "For each: Delete the key (or Regenerate to rotate in place).",
            "Apply API restrictions + application restrictions on replacement keys.",
            "Check IAM & admin activity logs for unexpected usage during the exposure window.",
            "Verify: old keys rejected, new restricted keys serve traffic normally.",
        ],
    }
    for p in selected:
        out.append(f"## {p}")
        out.extend(f"{i + 1}. {s}" for i, s in enumerate(steps[p]))
        out.append("")
    out.append("## After rotation (all providers)\n"
               "1. Search the workspace for lingering copies: config files, .env, "
               "shell history, chat transcripts.\n"
               "2. Rotate anything the old keys could reach (databases, webhooks).\n"
               "3. File the incident report (`respond incident-report`).")
    return "\n".join(out)


def _kill_session(ctx, detail: str) -> str:
    from .. import guard as guard_mod
    sid = detail.strip() or (ctx.guard_session.id if ctx and ctx.guard_session else "")
    out = [_header("kill-session")]
    if sid:
        try:
            guard_mod.kill_session(sid)
            out.append(f"Session `{sid}` REVOKED via kill-switch. All further "
                       f"tool calls on it raise SessionRevoked.\n")
        except Exception as e:
            out.append(f"Kill-switch error for `{sid}`: {e}\n")
    else:
        out.append("No session id given — nothing revoked.\n")
    out.append("## Follow-up\n"
               "1. Revoke provider keys the session could see (`respond rotate-keys`).\n"
               "2. Review the session audit log for what already executed.\n"
               "3. Quarantine the workspace if untrusted content was processed "
               "(`respond quarantine-workspace`).")
    return "\n".join(out)


def _quarantine_workspace(ctx, detail: str) -> str:
    target = detail.strip() or "<workspace-path>"
    return "\n".join([
        _header("quarantine-workspace"),
        f"Target: `{target}`\n",
        "## Steps (operator-executed)",
        "1. Stop the agent/session that touched the workspace "
        "(`respond kill-session`).",
        f"2. Snapshot for forensics BEFORE changing anything:\n"
        f"   `tar -czf /tmp/quarantine-$(date +%F).tgz -C $(dirname {target}) "
        f"$(basename {target})`",
        "3. Disconnect the machine from the network if exfiltration is suspected.",
        f"4. Move (don't delete) the workspace out of reach:\n"
        f"   `mv {target} ~/.aegis/quarantine/`",
        "5. Revoke every secret that ever lived in the workspace "
        "(`respond rotate-keys`).",
        "6. Rebuild the workspace from a known-good source; re-introduce files "
        "only after scanning them.",
        "7. File the incident report (`respond incident-report`).",
    ])


def _incident_report(ctx, detail: str) -> str:
    findings: list[dict] = []
    src = detail.strip()
    if src:
        try:
            maybe = json.loads(src)
            if isinstance(maybe, list):
                findings = maybe
        except Exception:
            pass
        if not findings:
            try:
                from ..scan import load_trace, scan_calls
                kb = ctx.kb if ctx else None
                if kb is None:
                    from ..kb import KB
                    kb = KB.load()
                findings = [f.to_dict() for f in scan_calls(load_trace(src), kb)]
            except Exception as e:
                return f"error: could not parse findings or trace: {e}"
    out = [_header("incident-report"), "## Summary",
           f"{len(findings)} finding(s) recorded.\n"]
    sev_count: dict[str, int] = {}
    for f in findings:
        sev_count[f.get("severity", "?")] = sev_count.get(f.get("severity", "?"), 0) + 1
        out.append(f"- [{f.get('severity', '?').upper()}] "
                   f"{f.get('technique_id', '?')} — {f.get('technique_name', '?')}\n"
                   f"  evidence: {f.get('evidence', '')}\n"
                   f"  mitigation: {f.get('mitigation', '')}")
    out.append("\n## Severity counts\n" +
               "\n".join(f"- {k}: {v}" for k, v in sorted(sev_count.items())))
    out.append("\n## Recommended next actions\n"
               "1. `respond rotate-keys` for any credential findings.\n"
               "2. `respond kill-session` for the offending session.\n"
               "3. `respond quarantine-workspace` if the host may be affected.")
    return "\n".join(out)
