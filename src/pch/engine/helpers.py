"""Shared helpers for rule modules."""

from __future__ import annotations

import fnmatch
from typing import Any

from pch.model.pipeline import Pipeline, Stage, Step
from pch.model.repo import RepoContext

SCRIPT_TASKS = {"script", "bash", "powershell", "pwsh"}


def norm_branch(b: str) -> str:
    return b.strip().lstrip("+-").removeprefix("refs/heads/")


def branch_allowed(branch: str, patterns: list[str]) -> bool:
    b = norm_branch(branch)
    return any(fnmatch.fnmatch(b, norm_branch(p)) for p in patterns)


def linked_builds(ctx: RepoContext, p: Pipeline) -> list[Pipeline]:
    if p.platform != "ado_classic_release":
        return []
    return [b for b in ctx.pipelines if b.platform != "ado_classic_release" and b.id in p.linked_build_ids]


def caps_with_builds(ctx: RepoContext, p: Pipeline) -> set[str]:
    """Capabilities of a pipeline plus the CI builds that feed it (for classic releases)."""
    caps = p.capabilities()
    for b in linked_builds(ctx, p):
        caps |= b.capabilities()
    return caps


def strings_of(v: Any) -> list[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, dict):
        return [s for x in v.values() for s in strings_of(x)]
    if isinstance(v, list):
        return [s for x in v for s in strings_of(x)]
    return []


def step_blob(step: Step) -> str:
    return " ".join(strings_of(step.inputs) + [step.inline_script or ""])


def stage_blob(stage: Stage) -> str:
    return " ".join(step_blob(s) for s in stage.steps() if s.enabled)


def prod_stages(p: Pipeline) -> list[Stage]:
    return [s for s in p.stages if s.env_tier == "prod" and s.is_deploy]


def ancestors(p: Pipeline, stage: Stage) -> list[Stage]:
    """Transitive depends_on closure (cycle-safe)."""
    by_name = {s.name: s for s in p.stages}
    seen: dict[str, Stage] = {}
    todo = list(stage.depends_on)
    while todo:
        n = todo.pop()
        if n in seen or n not in by_name:
            continue
        seen[n] = by_name[n]
        todo.extend(by_name[n].depends_on)
    return list(seen.values())


def lookup(mapping: dict[str, Any], key: str) -> Any:
    return mapping.get(key) or mapping.get(key.lower())
