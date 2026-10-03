"""Classic (designer) build definitions -> canonical Pipeline."""

from __future__ import annotations

from typing import Any

from pch.collectors.ado.task_catalog import TaskCatalog
from pch.collectors.redact import SECRET_NAME, value_looks_secret
from pch.model.pipeline import Job, Pipeline, Stage, Step, Variable, VariableGroupRef
from pch.normalize.capabilities import classify_pipeline


def variables_from_dict(raw: dict[str, Any] | None, source: str = "pipeline") -> list[Variable]:
    """Turn the ADO `variables` dict into Variables. Values are inspected, never kept."""
    out: list[Variable] = []
    for name, v in (raw or {}).items():
        val = v.get("value") if isinstance(v, dict) else v
        is_secret = bool(v.get("isSecret")) if isinstance(v, dict) else False
        reason = None
        if not is_secret:
            if SECRET_NAME.search(name) and val not in (None, "") and not str(val).startswith("$("):
                reason = "name looks secret-like and the variable is not marked secret"
            else:
                reason = value_looks_secret(val)
        out.append(Variable(name=name, is_secret=is_secret, secret_like_reason=reason, source=source))
    return out


def expand_step(raw: dict[str, Any], catalog: TaskCatalog, idx: str, group_depth: int = 0) -> tuple[list[Step], bool]:
    """Resolve a classic step (or task group) into canonical Steps. Returns (steps, used_task_group)."""
    task = raw.get("task") or {}
    tid = str(task.get("id", "")).lower()
    if tid in catalog.task_groups and group_depth < 3:
        group = catalog.task_groups[tid]
        steps: list[Step] = []
        for i, inner in enumerate(group.get("tasks", [])):
            sub, _ = expand_step(inner, catalog, f"{idx}.{i}", group_depth + 1)
            for s in sub:
                s.name = f"[{group.get('name')}] {s.name}"
                if not raw.get("enabled", True):
                    s.enabled = False
            steps.extend(sub)
        return steps, True
    name, major, tdef = catalog.resolve(tid, task.get("versionSpec")) if tid else ("script", None, None)
    version = major
    return [
        Step(
            id=idx,
            name=raw.get("displayName") or name,
            task=f"{name}@{major}" if major is not None else name,
            task_version=version,
            inputs=dict(raw.get("inputs") or {}),
            enabled=bool(raw.get("enabled", True)),
            continue_on_error=bool(raw.get("continueOnError", False)),
            condition=raw.get("condition"),
            marketplace=bool(tdef and tdef.marketplace),
            deprecated=bool(tdef and tdef.deprecated),
        )
    ], False


def normalize_build_definition(defn: dict[str, Any], catalog: TaskCatalog, project: str, base_web: str, raw_ref: str = "") -> Pipeline:
    jobs: list[Job] = []
    used_groups = False
    process = defn.get("process") or {}
    for pi, phase in enumerate(process.get("phases", [])):
        steps: list[Step] = []
        for si, raw in enumerate(phase.get("steps", [])):
            sub, grp = expand_step(raw, catalog, f"{pi}.{si}")
            steps.extend(sub)
            used_groups |= grp
        jobs.append(Job(name=phase.get("name", f"phase{pi}"), kind="phase", steps=steps))
    queue = defn.get("queue") or {}
    pool = queue.get("pool") or {}
    hosted = pool.get("isHosted")
    repo = defn.get("repository") or {}
    retention = max([r.get("daysToKeep", 0) for r in defn.get("retentionRules", [])] or [0]) or None
    author = (defn.get("authoredBy") or {}).get("uniqueName") or (defn.get("authoredBy") or {}).get("displayName")
    p = Pipeline(
        platform="ado_classic_build",
        id=str(defn["id"]),
        name=defn.get("name", ""),
        project=project,
        repo=repo.get("name"),
        repo_id=repo.get("id"),
        url=((defn.get("_links") or {}).get("web") or {}).get("href") or f"{base_web}/_build?definitionId={defn['id']}",
        definition_in_source_control=False,
        triggers={"triggers": [t.get("triggerType") for t in defn.get("triggers", [])],
                  "branchFilters": [b for t in defn.get("triggers", []) for b in t.get("branchFilters", [])]},
        variables=variables_from_dict(defn.get("variables")),
        variable_groups=[VariableGroupRef(id=str(g.get("id")), name=g.get("name", "")) for g in defn.get("variableGroups", [])],
        stages=[Stage(name="build", jobs=jobs)],
        retention_days=retention,
        owner=author,
        pool_type="hosted" if hosted else ("self-hosted" if hosted is False else "unknown"),
        uses_task_groups=used_groups,
        raw_ref=raw_ref,
    )
    return classify_pipeline(p)
