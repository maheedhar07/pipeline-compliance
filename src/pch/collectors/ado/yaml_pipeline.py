"""YAML pipelines: parse the expanded (`/preview` finalYaml) definition into the canonical model."""

from __future__ import annotations

import re
from typing import Any

import yaml

from pch.collectors.redact import SECRET_NAME, value_looks_secret
from pch.model.pipeline import Job, Pipeline, Stage, Step, Variable, VariableGroupRef
from pch.normalize.capabilities import classify_pipeline

SCRIPT_KEYS = {"script": "script", "bash": "bash", "powershell": "powershell", "pwsh": "pwsh"}
SKIP_KEYS = {"checkout", "download", "downloadBuild", "getPackage", "publish", "reviewApp", "template"}


def _variables(raw: Any) -> tuple[list[Variable], list[VariableGroupRef]]:
    vars_: list[Variable] = []
    groups: list[VariableGroupRef] = []
    items = raw
    if isinstance(raw, dict):
        items = [{"name": k, "value": v} for k, v in raw.items()]
    for it in items or []:
        if not isinstance(it, dict):
            continue
        if "group" in it:
            groups.append(VariableGroupRef(name=str(it["group"])))
            continue
        name = str(it.get("name", ""))
        val = it.get("value")
        reason = None
        if name:
            if SECRET_NAME.search(name) and val not in (None, "") and not str(val).startswith("$("):
                reason = "name looks secret-like and a literal value is set in YAML"
            else:
                reason = value_looks_secret(val if isinstance(val, str) else None)
            vars_.append(Variable(name=name, is_secret=False, secret_like_reason=reason, source="yaml"))
    return vars_, groups


def _step(raw: dict[str, Any], idx: str) -> Step | None:
    if any(k in raw for k in SKIP_KEYS) and "task" not in raw:
        return None
    enabled = raw.get("enabled", True)
    common = dict(
        id=idx,
        name=raw.get("displayName") or raw.get("name") or "",
        enabled=bool(enabled),
        continue_on_error=str(raw.get("continueOnError", False)).lower() == "true",
        condition=str(raw["condition"]) if "condition" in raw else None,
    )
    if "task" in raw:
        task = str(raw["task"])
        name, _, ver = task.partition("@")
        return Step(
            task=task,
            task_version=ver.split(".")[0] if ver else None,
            inputs=dict(raw.get("inputs") or {}),
            **{**common, "name": common["name"] or name},
        )
    for key, kind in SCRIPT_KEYS.items():
        if key in raw:
            return Step(task=kind, inline_script=str(raw[key]), **{**common, "name": common["name"] or kind})
    return None


def _job(raw: dict[str, Any], idx: str) -> tuple[Job, Any]:
    kind = "deployment" if "deployment" in raw else "job"
    name = raw.get("deployment") or raw.get("job") or idx
    steps_raw: list[dict[str, Any]] = []
    env = raw.get("environment")
    if kind == "deployment":
        strat = raw.get("strategy") or {}
        for mode in ("runOnce", "rolling", "canary"):
            block = strat.get(mode)
            if block:
                for phase in ("preDeploy", "deploy", "routeTraffic", "postRouteTraffic", "on"):
                    sub = block.get(phase)
                    if isinstance(sub, dict) and "steps" in sub:
                        steps_raw.extend(sub["steps"])
                    elif isinstance(sub, dict):
                        for v in sub.values():
                            if isinstance(v, dict):
                                steps_raw.extend(v.get("steps", []))
    else:
        steps_raw = raw.get("steps", [])
    steps = [s for i, r in enumerate(steps_raw) if isinstance(r, dict) and (s := _step(r, f"{idx}.{i}"))]
    pool = raw.get("pool")
    pool_name = pool.get("name") if isinstance(pool, dict) else pool
    vm = pool.get("vmImage") if isinstance(pool, dict) else None
    job = Job(name=str(name), kind=kind, pool=str(vm or pool_name) if (vm or pool_name) else None,
              self_hosted=bool(pool_name and not vm) if (vm or pool_name) else None, steps=steps)
    return job, env


def _env_name(env: Any) -> str | None:
    if isinstance(env, dict):
        return env.get("name")
    if isinstance(env, str):
        return env.split(".")[0]
    return None


def parse_yaml_pipeline(final_yaml: str, defn: dict[str, Any], project: str, base_web: str, raw_ref: str = "") -> Pipeline:
    doc = yaml.safe_load(final_yaml) or {}
    stages: list[Stage] = []
    stage_docs: list[dict[str, Any]] = doc.get("stages") or []
    if not stage_docs:
        jobs_raw = doc.get("jobs") or [{"job": "build", "steps": doc.get("steps", []), "pool": doc.get("pool")}]
        stage_docs = [{"stage": "build", "jobs": jobs_raw}]
    prev: str | None = None
    for si, sd in enumerate(stage_docs):
        name = str(sd.get("stage", f"stage{si}"))
        parsed = [_job(j, f"{name}.{ji}") for ji, j in enumerate(sd.get("jobs", []))]
        jobs = [j for j, _ in parsed]
        envs = [e for _, env in parsed if (e := _env_name(env))]
        if "dependsOn" in sd:
            dep = sd["dependsOn"]
            deps = [dep] if isinstance(dep, str) else list(dep or [])
        else:
            deps = [prev] if prev else []
        stages.append(
            Stage(name=name, env_name=envs[0] if envs else None, depends_on=deps, jobs=jobs, is_deploy=bool(envs))
        )
        prev = name
    vars_, groups = _variables(doc.get("variables"))
    for sd in stage_docs:
        v2, g2 = _variables(sd.get("variables"))
        vars_.extend(v2)
        groups.extend(g2)
    trig = doc.get("trigger")
    branches = trig.get("branches", {}).get("include", []) if isinstance(trig, dict) else (trig if isinstance(trig, list) else [])
    repo = defn.get("repository") or {}
    author = (defn.get("authoredBy") or {}).get("uniqueName")
    retention = max([r.get("daysToKeep", 0) for r in defn.get("retentionRules", [])] or [0]) or None
    pools = [j.self_hosted for st in stages for j in st.jobs if j.self_hosted is not None]
    pool_type = "unknown" if not pools else ("mixed" if len(set(pools)) > 1 else ("self-hosted" if pools[0] else "hosted"))
    p = Pipeline(
        platform="ado_yaml",
        id=str(defn["id"]),
        name=defn.get("name", ""),
        project=project,
        repo=repo.get("name"),
        repo_id=repo.get("id"),
        url=((defn.get("_links") or {}).get("web") or {}).get("href") or f"{base_web}/_build?definitionId={defn['id']}",
        definition_in_source_control=True,
        triggers={"branches": branches, "yamlFilename": (defn.get("process") or {}).get("yamlFilename")},
        variables=vars_,
        variable_groups=groups,
        stages=stages,
        owner=author,
        retention_days=retention,
        pool_type=pool_type,
        artifact_branch_filters=[b for b in branches if isinstance(b, str)],
        raw_ref=raw_ref,
    )
    for st in p.stages:
        if re.search(r"(?i)^build$", st.name):
            st.is_deploy = False
    return classify_pipeline(p)
