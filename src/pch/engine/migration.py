"""GitHub Actions migration readiness (informational score, not compliance)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from pch.engine.helpers import SCRIPT_TASKS
from pch.model.pipeline import Pipeline
from pch.model.repo import RepoContext

MAPPING_FILE = Path(__file__).parent.parent / "normalize" / "gha_mapping.yaml"


@lru_cache
def load_mapping() -> dict[str, dict]:
    raw = yaml.safe_load(MAPPING_FILE.read_text()) or {}
    return {k.lower(): v or {} for k, v in (raw.get("tasks") or {}).items()}


def pipeline_readiness(p: Pipeline) -> tuple[int, list[str]]:
    """Return (0-100 score, blockers). Signals follow PLAN section 7 MIG."""
    mapping = load_mapping()
    score = 100
    blockers: list[str] = []
    if p.platform == "ado_classic_build":
        score -= 20
        blockers.append("classic build definition must be rewritten as a workflow")
    elif p.platform == "ado_classic_release":
        score -= 30
        blockers.append("classic release definition has no direct equivalent (environments + deployment workflow)")
    if p.uses_task_groups:
        score -= 10
        blockers.append("uses task groups (convert to reusable workflows / composite actions)")
    if p.uses_deployment_groups:
        score -= 15
        blockers.append("uses deployment groups (self-hosted runners / agent-based deploy redesign)")
    gates = [a for s in p.stages for a in s.gates + s.post_approvals if a.kind in ("gate", "servicenow")]
    if gates and p.platform == "ado_classic_release":
        score -= 10
        blockers.append(f"{len(gates)} classic gate(s) must become environment protection rules or scripts")
    unmapped: set[str] = set()
    for s in p.all_steps():
        if not s.task or s.task.split("@")[0].lower() in SCRIPT_TASKS:
            continue
        name = s.task.split("@")[0].lower()
        entry = mapping.get(name)
        if entry is None or entry.get("gha") is None:
            unmapped.add(s.task.split("@")[0])
    if unmapped:
        score -= min(30, 6 * len(unmapped))
        blockers.append("tasks without a GitHub Actions equivalent: " + ", ".join(sorted(unmapped)))
    if p.pool_type in ("self-hosted", "mixed"):
        score -= 10
        blockers.append("uses self-hosted agent pools (needs self-hosted runners)")
    return max(0, score), blockers


def repo_readiness(ctx: RepoContext) -> tuple[int | None, list[str]]:
    if not ctx.pipelines:
        return None, []
    scores, blockers = [], []
    for p in ctx.pipelines:
        s, b = pipeline_readiness(p)
        scores.append(s)
        blockers.extend(b)
    seen: list[str] = []
    for b in blockers:
        if b not in seen:
            seen.append(b)
    return round(sum(scores) / len(scores)), seen
