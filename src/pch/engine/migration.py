"""GitHub Actions migration readiness (informational score, not compliance)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

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
    """Readiness of the Azure DevOps pipelines only: a GitHub Actions workflow is already migrated and does not enter the score."""
    ado = [p for p in ctx.pipelines if p.platform != "gha"]
    if not ado:
        return None, []
    scores: list[int] = []
    blockers: list[str] = []
    for p in ado:
        s, bl = pipeline_readiness(p)
        scores.append(s)
        blockers.extend(bl)
    seen: list[str] = []
    for item in blockers:
        if item not in seen:
            seen.append(item)
    return round(sum(scores) / len(scores)), seen


# --------------------------------------------------------------------------- migration status (ADO -> GitHub Actions, per repo)
STATUS_LABEL = {"ado_only": "ADO only", "in_progress": "In progress (both)", "migrated": "Migrated (GHA only)", "none": "No pipelines"}


def migration_status(platforms: list[str]) -> str:
    """``ado_only`` / ``in_progress`` (ADO and GHA pipelines side by side) / ``migrated`` (GHA only) / ``none``."""
    ado = any(x.startswith("ado_") for x in platforms)
    gha = "gha" in platforms
    return "in_progress" if ado and gha else "migrated" if gha else "ado_only" if ado else "none"


def _deploys(p: Pipeline) -> list[tuple[str | None, str, set[str]]]:
    return [(st.env_name, st.env_tier, set(st.deploy_targets)) for st in p.stages if st.is_deploy]


def retire_candidates(pipelines: list[Pipeline]) -> list[dict[str, str]]:
    """Azure DevOps pipelines that look superseded: a GitHub Actions workflow of the same repo deploys to the same environment name, or to the same
    known tier with an overlapping deploy target. Only a hint (a human confirms before retiring)."""
    gha = [(p, _deploys(p)) for p in pipelines if p.platform == "gha"]
    out: list[dict[str, str]] = []
    for p in pipelines:
        if p.platform == "gha":
            continue
        mine = _deploys(p)
        if not mine:
            continue
        for g, theirs in gha:
            why = ""
            for env, tier, targets in mine:
                for env2, tier2, targets2 in theirs:
                    if env and env2 and env.casefold() == env2.casefold():
                        why = f"workflow '{g.name}' deploys to the same environment ({env2})"
                    elif tier != "unknown" and tier == tier2 and targets & targets2 and not why:
                        why = f"workflow '{g.name}' deploys to the same target ({', '.join(sorted(targets & targets2))}) in {tier}"
                    if why and env and env2:
                        break
            if why:
                out.append({"id": p.id, "name": p.name, "platform": p.platform, "reason": why})
                break
    return out


def migration_summary(pipelines: list[Pipeline]) -> dict[str, Any]:
    """Stored per repo in ``repo_results.external["migration"]``."""
    st = migration_status(sorted({p.platform for p in pipelines}))
    return {"status": st, "retire_candidates": retire_candidates(pipelines) if st == "in_progress" else []}
