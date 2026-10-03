"""Classic release definitions -> canonical Pipeline (one Stage per release environment)."""

from __future__ import annotations

import json
from typing import Any

from pch.collectors.ado.classic_build import expand_step, variables_from_dict
from pch.collectors.ado.task_catalog import TaskCatalog
from pch.model.pipeline import Approval, Job, Pipeline, Stage, Step, VariableGroupRef
from pch.normalize.capabilities import classify_pipeline

COND_TYPES = {1: "event", 2: "environmentState", 3: "artifact", "event": "event", "environmentState": "environmentState", "artifact": "artifact"}


def _approval_from(block: dict[str, Any] | None) -> list[Approval]:
    """preDeployApprovals / postDeployApprovals -> manual Approval (if any non-automated approver)."""
    if not block:
        return []
    manual = [a for a in block.get("approvals", []) if not a.get("isAutomated", False)]
    if not manual:
        return []
    opts = block.get("approvalOptions") or {}
    names = [(a.get("approver") or {}).get("displayName") or (a.get("approver") or {}).get("uniqueName") or "?" for a in manual]
    return [
        Approval(
            kind="manual",
            approvers=names,
            min_approvers=opts.get("requiredApproverCount") or len(manual),
            requester_can_approve=opts.get("releaseCreatorCanBeApprover"),
            timeout_minutes=opts.get("timeoutInMinutes"),
        )
    ]


def _gates_from(block: dict[str, Any] | None, catalog: TaskCatalog) -> list[Approval]:
    if not block:
        return []
    opts = block.get("gatesOptions") or {}
    if not opts.get("isEnabled", bool(block.get("gates"))):
        return []
    out: list[Approval] = []
    for gate in block.get("gates", []):
        for t in gate.get("tasks", []):
            name, _, _ = catalog.resolve(str(t.get("taskId", "")).lower(), t.get("version"))
            blob = json.dumps(t.get("inputs") or {}).lower() + (t.get("name") or "").lower() + name.lower()
            kind = "servicenow" if ("servicenow" in blob or "service-now" in blob) else "gate"
            out.append(Approval(kind=kind, name=t.get("name") or name, timeout_minutes=opts.get("timeout")))
    return out


def _condition_deps(conds: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    deps: list[str] = []
    branches: list[str] = []
    for c in conds or []:
        ctype = COND_TYPES.get(c.get("conditionType"), "event")
        if ctype == "environmentState":
            deps.append(c.get("name", ""))
        elif ctype == "artifact":
            try:
                v = json.loads(c.get("value") or "{}")
                if v.get("sourceBranch"):
                    branches.append(v["sourceBranch"])
            except ValueError:
                pass
    return [d for d in deps if d], branches


def normalize_release_definition(
    defn: dict[str, Any],
    catalog: TaskCatalog,
    project: str,
    base_web: str,
    var_groups_by_id: dict[str, str] | None = None,
    raw_ref: str = "",
) -> Pipeline:
    var_groups_by_id = var_groups_by_id or {}
    stages: list[Stage] = []
    groups: list[VariableGroupRef] = []
    uses_task_groups = uses_dg = False
    variables = variables_from_dict(defn.get("variables"), "release")
    trig_branches = [
        c.get("sourceBranch")
        for t in defn.get("triggers", [])
        for c in t.get("triggerConditions", [])
        if c.get("sourceBranch")
    ]
    for gid in defn.get("variableGroups", []):
        groups.append(VariableGroupRef(id=str(gid), name=var_groups_by_id.get(str(gid), f"group-{gid}")))
    for env in sorted(defn.get("environments", []), key=lambda e: e.get("rank", 0)):
        jobs: list[Job] = []
        for pi, phase in enumerate(env.get("deployPhases", [])):
            steps: list[Step] = []
            if phase.get("phaseType") in (2, "machineGroupBasedDeployment"):
                uses_dg = True
            for si, wt in enumerate(phase.get("workflowTasks", [])):
                raw = {
                    "task": {"id": wt.get("taskId"), "versionSpec": wt.get("version")},
                    "displayName": wt.get("name"),
                    "enabled": wt.get("enabled", True),
                    "continueOnError": wt.get("continueOnError", False),
                    "condition": wt.get("condition") or ("always()" if wt.get("alwaysRun") else None),
                    "inputs": wt.get("inputs") or {},
                }
                sub, grp = expand_step(raw, catalog, f"{env.get('id')}.{pi}.{si}")
                steps.extend(sub)
                uses_task_groups |= grp
            jobs.append(Job(name=phase.get("name", f"phase{pi}"), kind="phase", steps=steps,
                            self_hosted=True if phase.get("phaseType") in (2, "machineGroupBasedDeployment") else None))
        deps, cond_branches = _condition_deps(env.get("conditions", []))
        for g in env.get("variableGroups", []):
            groups.append(VariableGroupRef(id=str(g), name=var_groups_by_id.get(str(g), f"group-{g}"), scope=env.get("name")))
        variables.extend(variables_from_dict(env.get("variables"), "stage"))
        stages.append(
            Stage(
                name=env.get("name", f"env{env.get('id')}"),
                env_name=env.get("name"),
                depends_on=deps,
                jobs=jobs,
                pre_approvals=_approval_from(env.get("preDeployApprovals")),
                post_approvals=_approval_from(env.get("postDeployApprovals")) + _gates_from(env.get("postDeploymentGates"), catalog),
                gates=_gates_from(env.get("preDeploymentGates"), catalog),
                branch_filters=sorted(set(cond_branches + [b for b in trig_branches if b])),
                retention_days=(env.get("retentionPolicy") or {}).get("daysToKeep"),
                is_deploy=True,
            )
        )
    linked = [
        str(((a.get("definitionReference") or {}).get("definition") or {}).get("id"))
        for a in defn.get("artifacts", [])
        if a.get("type") == "Build"
    ]
    modifier = (defn.get("modifiedBy") or defn.get("createdBy") or {})
    p = Pipeline(
        platform="ado_classic_release",
        id=str(defn["id"]),
        name=defn.get("name", ""),
        project=project,
        url=((defn.get("_links") or {}).get("web") or {}).get("href") or f"{base_web}/_release?definitionId={defn['id']}",
        definition_in_source_control=False,
        triggers={"artifact": [t.get("triggerType") for t in defn.get("triggers", [])]},
        variables=variables,
        variable_groups=groups,
        stages=stages,
        linked_build_ids=[i for i in linked if i != "None"],
        owner=modifier.get("uniqueName") or modifier.get("displayName"),
        uses_task_groups=uses_task_groups,
        uses_deployment_groups=uses_dg,
        artifact_branch_filters=sorted(set(trig_branches)),
        pool_type="unknown",
        raw_ref=raw_ref,
    )
    return classify_pipeline(p)
