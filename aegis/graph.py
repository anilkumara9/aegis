"""Attack graphs: ranked adversary paths against a user-owned local system.

Defensive-only analysis. The target is walked read-only — nothing is
executed, installed, or modified. Static signals (config files, secret-shaped
material, permission bits, manifests, framework markers) are mapped to real
KB technique IDs, chained into kill-chain-ordered attack paths of 2-5 steps,
and every path is annotated with the defenses that break it (each technique's
own ``mitigations`` field from the KB).

Scope guard: ``graph`` only analyzes LOCAL directories belonging to the user.
URLs, hostnames, IP literals, and remote-style paths are refused outright.

Ranking formula (see :func:`score_path`):
    sev_w(sev) = {critical: 4, high: 3, medium: 2, low: 1}
    step_plausibility_i = sev_w(technique_i) * signal_strength(signal_i)  (0..4)
    path_score = 0.5 * max(sev_w over steps)
               + 0.3 * mean(step_plausibility over steps)
               + 0.2 * stage_coverage
    stage_coverage = (# distinct kill-chain stages on the path) / 8
                     (recon, initial_access, execution, privilege,
                      persistence, lateral, command_control, exfil)

The score is monotonic in worst-case impact (max severity), grounded in how
strongly each step matches the ACTUAL target (signal strength), and rewards
complete end-to-end chains over single-stage fragments. A path through a
hardcoded secret with critical-severity steps therefore outranks one built on
weak dependency-manifest signals; a clean target produces no signals and no
high-severity paths at all.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .detect.secrets import find_secrets, find_secret_references
from .skills import _SKIP_DIRS

# ---------------------------------------------------------------------------
# Kill-chain stages
# ---------------------------------------------------------------------------

STAGES = (
    "recon",
    "initial_access",
    "execution",
    "privilege",
    "persistence",
    "lateral",
    "command_control",
    "exfil",
)
_STAGE_IDX = {s: i for i, s in enumerate(STAGES)}

SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# ---------------------------------------------------------------------------
# Target validation: local directories only
# ---------------------------------------------------------------------------


def looks_remote(target: str) -> bool:
    """True when the target is a URL, hostname, IP literal, or remote path."""
    t = (target or "").strip().lower()
    return (
        t.startswith(("http://", "https://", "ssh://", "ftp://", "\\\\"))
        or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/|$|:)", t) is not None
        or re.match(r"^\d{1,3}(\.\d{1,3}){3}(/|$|:)", t) is not None
        or re.match(r"^[a-z0-9-]+@[^/]+:", t) is not None  # scp-style user@host:
    )


def validate_target(target: str) -> tuple[Path | None, str]:
    """Validate the graph target. Returns (path, error_message)."""
    target = (target or "").strip()
    if not target:
        return None, "usage: aegis graph <local-directory>"
    if looks_remote(target):
        return (
            None,
            "refused: `graph` only analyzes your OWN local systems. "
            "Pass a local directory path, not a URL, hostname, or IP address.",
        )
    p = Path(target).expanduser()
    if not p.exists():
        return None, f"refused: '{target}' does not exist on this machine."
    if not p.is_dir():
        return (
            None,
            f"refused: '{target}' is not a local directory. `graph` works on "
            "your own local code only.",
        )
    return p, ""


# ---------------------------------------------------------------------------
# Static signal collection (read-only; nothing is executed)
# ---------------------------------------------------------------------------

_MAX_FILES = 2000
_MAX_CONTENT_BYTES = 1_000_000


@dataclass
class Signal:
    kind: str
    strength: float  # 0..1, how strongly this signal grounds an attack step
    evidence: list[str] = field(default_factory=list)  # human-readable, NO secret values
    files: list[str] = field(default_factory=list)  # relative paths


SIGNAL_WHY = {
    "hardcoded_secret": "secret-shaped material is committed in source",
    "env_file": ".env file present — environment secrets live alongside code",
    "ci_secret_ref": "shell/CI scripts reference secret-bearing variables",
    "private_key": "private key material stored in the working tree",
    "docker_root": "container image runs as root",
    "docker_present": "containerized workload — image/pipeline attack surface",
    "k8s_manifest": "Kubernetes manifests — RBAC and secret-object surface",
    "world_writable": "world-writable files — any local writer can tamper",
    "setuid": "setuid bit set — privileged-execution boundary present",
    "dep_manifest": "dependency manifests — supply-chain attack surface",
    "ci_config": "CI/CD configuration — build-pipeline secret surface",
    "debug_endpoint": "debug exposure in code — verbose/error surface",
    "web_app": "web application — injection/auth attack surface",
    "auth_surface": "authentication code — credential-abuse surface",
}

_ENV_FILE_RE = re.compile(r"^\.env(\..*)?$", re.IGNORECASE)
_PRIVATE_KEY_NAME_RE = re.compile(r"(?i)(id_rsa|id_ed25519|id_ecdsa|\.pem$|\.key$)")
_PRIVATE_KEY_CONTENT_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_DOCKERFILE_RE = re.compile(r"(?i)^(Dockerfile(\..*)?|docker-compose\.ya?ml)$")
_CI_FILE_RE = re.compile(r"(?i)(\.github/workflows/.*\.ya?ml|\.gitlab-ci\.ya?ml|Jenkinsfile|\.circleci/config\.ya?ml)$")
_DEP_MANIFEST_RE = re.compile(r"(?i)^(requirements.*\.txt|package\.json|composer\.json|go\.mod|Gemfile|Cargo\.toml)$")
_K8S_KIND_RE = re.compile(
    r"(?im)^\s*kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet|Job|CronJob|"
    r"Role|ClusterRole|RoleBinding|ClusterRoleBinding|ServiceAccount|Secret|Ingress)\s*$")
_WEB_FRAMEWORK_RE = re.compile(
    r"(?i)(from\s+flask|import\s+flask|require\(['\"]express['\"]|django|"
    r"from\s+fastapi|rails|springframework|laravel)")
_AUTH_CODE_RE = re.compile(
    r"(?i)(def\s+login|password_verify|verify_password|bcrypt|authenticate\s*\(|"
    r"app\.(post|get)\(\s*['\"]/(login|signin|auth)|session\s*\[\s*['\"]user)")
_DEBUG_RE = re.compile(
    r"(?i)(debug\s*=\s*True|app\.run\([^)]*debug|['\"]/(debug|console|_debug))")
_SECRET_REF_FILE_RE = re.compile(r"(?i)(\.sh$|\.github/workflows/.*\.ya?ml|Jenkinsfile|\.gitlab-ci\.ya?ml)$")


def _add_signal(signals: dict[str, Signal], kind: str, strength: float,
                evidence: str, rel: str) -> None:
    sig = signals.get(kind)
    if sig is None:
        signals[kind] = Signal(kind=kind, strength=strength,
                               evidence=[evidence], files=[rel])
        return
    if evidence not in sig.evidence:
        sig.evidence.append(evidence)
    if rel not in sig.files:
        sig.files.append(rel)


def _looks_text(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(8192)
    except OSError:
        return False
    return b"\x00" not in chunk


def collect_signals(root: Path) -> tuple[list[Signal], int]:
    """Walk *root* read-only and collect security-relevant signals.

    Returns (signals, files_scanned). Secret values are never stored —
    evidence records only the kind of secret-shaped material and its file.
    """
    signals: dict[str, Signal] = {}
    files_scanned = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for fn in sorted(filenames):
            if files_scanned >= _MAX_FILES:
                return list(signals.values()), files_scanned
            fp = Path(dirpath) / fn
            if fp.is_symlink():
                continue  # never follow links out of the target tree
            try:
                st = fp.lstat()
            except OSError:
                continue
            if not fp.is_file():
                continue
            files_scanned += 1
            rel = str(fp.relative_to(root))
            mode = st.st_mode

            # Permission bits apply to any file, text or binary.
            if mode & 0o4000:
                _add_signal(signals, "setuid", 0.9,
                            "setuid bit set", rel)
            if mode & 0o002:
                _add_signal(signals, "world_writable", 0.9,
                            "world-writable file", rel)

            # Filename-driven signals.
            if _ENV_FILE_RE.match(fn):
                _add_signal(signals, "env_file", 0.9, ".env file committed", rel)
            if _PRIVATE_KEY_NAME_RE.search(fn):
                _add_signal(signals, "private_key", 1.0,
                            "private-key filename", rel)
            if _DOCKERFILE_RE.match(fn):
                _add_signal(signals, "docker_present", 0.5,
                            "container definition present", rel)
            if _CI_FILE_RE.search(rel.replace(os.sep, "/")):
                _add_signal(signals, "ci_config", 0.7,
                            "CI/CD configuration present", rel)
            if _DEP_MANIFEST_RE.match(fn):
                _add_signal(signals, "dep_manifest", 0.5,
                            "dependency manifest present", rel)

            # Content-driven signals (text files only, sanely capped).
            if st.st_size > _MAX_CONTENT_BYTES or not _looks_text(fp):
                continue
            try:
                text = fp.read_text(encoding="utf-8", errors="strict")
            except (OSError, UnicodeError):
                continue

            for hit in find_secrets(text):
                _add_signal(signals, "hardcoded_secret", 1.0,
                            f"{hit.kind} material in source", rel)
            if _SECRET_REF_FILE_RE.search(rel.replace(os.sep, "/")):
                for ref in find_secret_references(text):
                    _add_signal(signals, "ci_secret_ref", 0.7,
                                f"secret-bearing variable reference ({ref})", rel)
            if _PRIVATE_KEY_CONTENT_RE.search(text):
                _add_signal(signals, "private_key", 1.0,
                            "private key block in file", rel)
            if fn.lower().startswith("dockerfile"):
                if not re.search(r"(?im)^\s*USER\s+", text):
                    _add_signal(signals, "docker_root", 0.8,
                                "Dockerfile has no USER directive (runs as root)", rel)
                elif re.search(r"(?im)^\s*USER\s+root\b", text):
                    _add_signal(signals, "docker_root", 0.8,
                                "Dockerfile runs as USER root", rel)
            if fn.endswith((".yaml", ".yml")) and _K8S_KIND_RE.search(text):
                _add_signal(signals, "k8s_manifest", 0.7,
                            "Kubernetes workload/RBAC manifest", rel)
            if _WEB_FRAMEWORK_RE.search(text):
                _add_signal(signals, "web_app", 0.5,
                            "web framework marker", rel)
            if _AUTH_CODE_RE.search(text):
                _add_signal(signals, "auth_surface", 0.6,
                            "authentication handling code", rel)
            if _DEBUG_RE.search(text):
                _add_signal(signals, "debug_endpoint", 0.7,
                            "debug exposure in code", rel)
    return list(signals.values()), files_scanned


# ---------------------------------------------------------------------------
# Signal -> KB technique mapping (every ID verified against the loaded KB)
# ---------------------------------------------------------------------------

# (signal_kind, technique_id, kill_chain_stage)
SIGNAL_TECHNIQUES: list[tuple[str, str, str]] = [
    # -- secrets and credentials -------------------------------------------
    ("hardcoded_secret", "AEG-T031", "exfil"),       # config-file harvesting
    ("hardcoded_secret", "AEG-T035", "exfil"),       # secrets in artifacts
    ("hardcoded_secret", "AEG-T248", "recon"),       # secret leakage in repos
    ("hardcoded_secret", "AEG-T034", "exfil"),       # DNS exfil of secrets
    ("env_file", "AEG-T027", "exfil"),               # env-var harvesting
    ("env_file", "AEG-T031", "exfil"),               # config-file harvesting
    ("ci_secret_ref", "AEG-T032", "exfil"),          # CI secret exfil
    ("private_key", "AEG-T328", "lateral"),          # SSH key/agent abuse
    ("private_key", "AEG-T334", "lateral"),          # cred-access -> lateral chaining
    # -- containers / orchestration ----------------------------------------
    ("docker_root", "AEG-T071", "privilege"),        # container breakout
    ("docker_root", "AEG-T309", "privilege"),        # metadata-service abuse
    ("docker_present", "AEG-T078", "initial_access"),  # poisoned base images
    ("docker_present", "AEG-T057", "persistence"),   # container-image backdoors
    ("k8s_manifest", "AEG-T303", "privilege"),       # k8s RBAC escalation
    ("k8s_manifest", "AEG-T312", "exfil"),           # k8s secret-object exfil
    # -- permissions --------------------------------------------------------
    ("world_writable", "AEG-T068", "privilege"),     # PATH hijacking
    ("world_writable", "AEG-T053", "persistence"),   # startup-script modification
    ("setuid", "AEG-T063", "privilege"),             # overly broad grants
    ("setuid", "AEG-T065", "privilege"),             # sudo/secrets in context
    # -- supply chain / CI --------------------------------------------------
    ("dep_manifest", "AEG-T076", "initial_access"),  # dependency confusion
    ("dep_manifest", "AEG-T084", "initial_access"),  # package install hooks
    ("dep_manifest", "AEG-T073", "initial_access"),  # malicious package
    ("ci_config", "AEG-T306", "exfil"),              # CI/CD workflow injection
    ("ci_config", "AEG-T032", "exfil"),              # CI secret exfil
    # -- web / auth surface -------------------------------------------------
    ("debug_endpoint", "AEG-T226", "exfil"),         # excessive data exposure
    ("debug_endpoint", "AEG-T143", "initial_access"),  # broken auth/session
    ("web_app", "AEG-T139", "execution"),            # SQL injection
    ("web_app", "AEG-T148", "execution"),            # OS command injection
    ("auth_surface", "AEG-T143", "initial_access"),  # broken auth/session
    ("auth_surface", "AEG-T265", "initial_access"),  # password-reset chains
    ("auth_surface", "AEG-T233", "initial_access"),  # credential stuffing
]


def verify_mapping(kb) -> list[str]:
    """Check every mapped technique ID resolves in the KB. Returns the IDs."""
    ids = sorted({tid for _, tid, _ in SIGNAL_TECHNIQUES})
    missing = [tid for tid in ids if tid not in kb.by_id]
    if missing:
        raise ValueError(f"graph mapping references unknown KB IDs: {missing}")
    return ids


@dataclass
class Candidate:
    tech_id: str
    stage: str
    stage_idx: int
    signal_kind: str
    strength: float
    evidence: list[str]
    files: list[str]


def build_candidates(signals: list[Signal], kb) -> list[Candidate]:
    """Expand signals into KB-grounded candidates (deduped by technique ID)."""
    verify_mapping(kb)
    by_kind = {s.kind: s for s in signals}
    best: dict[str, Candidate] = {}
    for kind, tid, stage in SIGNAL_TECHNIQUES:
        sig = by_kind.get(kind)
        if sig is None:
            continue
        cur = best.get(tid)
        if cur is None or sig.strength > cur.strength:
            best[tid] = Candidate(
                tech_id=tid, stage=stage, stage_idx=_STAGE_IDX[stage],
                signal_kind=kind, strength=sig.strength,
                evidence=list(sig.evidence), files=list(sig.files))
    return sorted(best.values(), key=lambda c: c.tech_id)


# ---------------------------------------------------------------------------
# Path building and ranking
# ---------------------------------------------------------------------------

_BEAM_WIDTH = 6
_MAX_PATH_LEN = 5


@dataclass
class PathStep:
    candidate: Candidate
    name: str
    severity: str
    mitigations: list[str]


@dataclass
class AttackPath:
    steps: list[PathStep]
    score: float
    max_severity: str

    def ids(self) -> tuple[str, ...]:
        return tuple(s.candidate.tech_id for s in self.steps)


def step_plausibility(step: PathStep) -> float:
    """sev_weight(technique) * signal_strength(signal), in 0..4."""
    return SEV_WEIGHT[step.severity] * step.candidate.strength


def score_path(steps: list[PathStep]) -> float:
    """Path score (documented in the module docstring).

    score = 0.5 * max(sev_weight) + 0.3 * mean(step_plausibility)
            + 0.2 * stage_coverage
    """
    max_sev = max(SEV_WEIGHT[s.severity] for s in steps)
    mean_plaus = sum(step_plausibility(s) for s in steps) / len(steps)
    coverage = len({s.candidate.stage for s in steps}) / len(STAGES)
    return 0.5 * max_sev + 0.3 * mean_plaus + 0.2 * coverage


def build_paths(candidates: list[Candidate], kb) -> list[AttackPath]:
    """Beam-search kill-chain-ordered chains of 2-5 candidates.

    Stages must strictly increase along a path, so every chain reads as
    recon -> ... -> exfil rather than a bag of techniques.
    """
    tech_by_id = kb.by_id

    def to_step(c: Candidate) -> PathStep:
        t = tech_by_id[c.tech_id]
        return PathStep(candidate=c, name=t.name, severity=t.severity,
                        mitigations=list(t.mitigations))

    beam: list[tuple[Candidate, ...]] = [(c,) for c in candidates]
    seen: set[tuple[str, ...]] = set()
    all_paths: list[AttackPath] = []

    def rank_key(path: tuple[Candidate, ...]):
        steps = [to_step(c) for c in path]
        sc = score_path(steps)
        max_sev = max(SEV_WEIGHT[s.severity] for s in steps)
        return (-sc, -max_sev, len(path), tuple(c.tech_id for c in path))

    for _length in range(2, _MAX_PATH_LEN + 1):
        nxt: list[tuple[Candidate, ...]] = []
        for path in beam:
            last_stage = path[-1].stage_idx
            used = {c.tech_id for c in path}
            for c in candidates:
                if c.tech_id in used or c.stage_idx <= last_stage:
                    continue
                key = tuple(x.tech_id for x in (*path, c))
                if key in seen:
                    continue
                seen.add(key)
                nxt.append((*path, c))
        if not nxt:
            break
        nxt.sort(key=rank_key)
        beam = nxt[:_BEAM_WIDTH]
        for path in beam:
            steps = [to_step(c) for c in path]
            all_paths.append(AttackPath(
                steps=steps,
                score=score_path(steps),
                max_severity=max((s.severity for s in steps),
                                 key=lambda s: SEV_WEIGHT[s])))

    # Global ranking: score desc, then max severity desc, shorter first.
    all_paths.sort(key=lambda p: (-p.score,
                                  -SEV_WEIGHT[p.max_severity],
                                  len(p.steps), p.ids()))
    return all_paths


def path_defenses(path: AttackPath, per_step: int | None = 3) -> list[str]:
    """Defenses that break this path, from each technique's mitigations.

    ``per_step=None`` emits every mitigation of every step (used for JSON).
    """
    out: list[str] = []
    seen: set[str] = set()
    for step in path.steps:
        mits = step.mitigations if per_step is None else step.mitigations[:per_step]
        for m in mits:
            if m not in seen:
                seen.add(m)
                out.append(f"[{step.candidate.tech_id}] {m}")
    return out


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def step_why(step: PathStep) -> str:
    """Why this step applies to THIS target (evidence-grounded, no secrets)."""
    c = step.candidate
    why = SIGNAL_WHY.get(c.signal_kind, c.signal_kind)
    ev = "; ".join(c.evidence[:2])
    files = ", ".join(f"`{f}`" for f in c.files[:3])
    more = f" (+{len(c.files) - 3} more)" if len(c.files) > 3 else ""
    return f"{why} ({ev}) in {files}{more}"


def render_markdown(target: Path, files_scanned: int, signals: list[Signal],
                    paths: list[AttackPath], top: int) -> str:
    lines = [f"# Attack graph: `{target}`", "",
             f"Files scanned (read-only): {files_scanned}. "
             f"Signals: {len(signals)}. Candidate paths: {len(paths)}.", ""]
    if signals:
        lines.append("## Signals observed")
        for s in sorted(signals, key=lambda s: (-s.strength, s.kind)):
            files = ", ".join(f"`{f}`" for f in s.files[:4])
            more = f" (+{len(s.files) - 4})" if len(s.files) > 4 else ""
            lines.append(f"- `{s.kind}` (strength {s.strength:.1f}): "
                         f"{'; '.join(s.evidence[:2])} — {files}{more}")
        lines.append("")
    if not paths:
        lines.append("## Attack paths")
        lines.append("No kill-chain paths built from the observed signals. "
                     "This is a triage pass, not a clean bill of health — "
                     "re-run after changes and pair with `aegis hunt`.")
        return "\n".join(lines)
    lines.append("## Ranked attack paths")
    lines.append("Each path is an adversary-shaped chain ordered by kill-chain "
                 "stage; every step is grounded in a signal from THIS target.")
    lines.append("")
    for i, path in enumerate(paths[:top], 1):
        stages = " -> ".join(s.candidate.stage for s in path.steps)
        lines.append(f"### Path {i} — score {path.score:.2f} "
                     f"[max severity: {path.max_severity}]")
        lines.append(f"*Stages: {stages}*")
        lines.append("")
        for j, step in enumerate(path.steps, 1):
            lines.append(f"{j}. **{step.candidate.tech_id}** — {step.name} "
                         f"[{step.severity}] *({step.candidate.stage})*")
            lines.append(f"   Why here: {step_why(step)}")
        lines.append("")
        lines.append("**Defenses that break this path:**")
        for d in path_defenses(path):
            lines.append(f"- {d}")
        lines.append("")
    return "\n".join(lines)


def render_json(target: Path, files_scanned: int, signals: list[Signal],
                paths: list[AttackPath], top: int) -> str:
    doc = {
        "target": str(target),
        "files_scanned": files_scanned,
        "signals": [
            {"kind": s.kind, "strength": s.strength,
             "evidence": s.evidence, "files": s.files}
            for s in signals
        ],
        "paths": [
            {
                "rank": i,
                "score": round(p.score, 4),
                "max_severity": p.max_severity,
                "stages": [s.candidate.stage for s in p.steps],
                "steps": [
                    {
                        "id": s.candidate.tech_id,
                        "name": s.name,
                        "severity": s.severity,
                        "stage": s.candidate.stage,
                        "signal": s.candidate.signal_kind,
                        "signal_strength": s.candidate.strength,
                        "why": step_why(s),
                        "evidence": s.candidate.evidence,
                        "files": s.candidate.files,
                    }
                    for s in p.steps
                ],
                "defenses": path_defenses(p, per_step=None),
            }
            for i, p in enumerate(paths[:top], 1)
        ],
    }
    return json.dumps(doc, indent=2)


def run_graph(target: str, json_mode: bool = False, top: int = 5,
              kb=None, out=None) -> int:
    """Build and print the attack graph. Returns a process exit code."""
    out = out or sys.stdout
    path, err = validate_target(target)
    if path is None:
        print(err, file=sys.stderr)
        return 2
    if top < 1:
        print("refused: --top must be >= 1", file=sys.stderr)
        return 2
    if kb is None:
        from .kb import KB
        kb = KB.load()
    signals, files_scanned = collect_signals(path)
    candidates = build_candidates(signals, kb)
    paths = build_paths(candidates, kb)
    if json_mode:
        out.write(render_json(path, files_scanned, signals, paths, top) + "\n")
    else:
        out.write(render_markdown(path, files_scanned, signals, paths, top) + "\n")
    return 0
