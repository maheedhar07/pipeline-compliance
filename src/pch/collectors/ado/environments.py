"""YAML environments and their checks (approvals, branch control, ServiceNow/REST gates)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from pch.collectors.ado.client import AdoClient
from pch.model.pipeline import Approval, Pipeline
from pch.model.repo import Environment


async def collect_environments(client: AdoClient, project: str) -> dict[str, Environment]:
    envs = await client.paged(project, "_apis/distributedtask/environments")

    async def checks(e: dict[str, Any]) -> list[dict[str, Any]]:
        data = await client.get_optional(
            project,
            "_apis/pipelines/checks/configurations",
            {"resourceType": "environment", "resourceId": e["id"], "$expand": "settings"},
        )
        return (data or {}).get("value", [])

    results = await asyncio.gather(*(checks(e) for e in envs))
    return {e["name"]: Environment(id=str(e["id"]), name=e["name"], checks=c) for e, c in zip(envs, results, strict=True)}


def check_to_approval(check: dict[str, Any]) -> Approval:
    tname = ((check.get("type") or {}).get("name") or "").lower()
    s = check.get("settings") or {}
    blob = json.dumps(s).lower() + tname
    timeout = check.get("timeout")
    if tname == "approval":
        return Approval(
            kind="manual",
            approvers=[a.get("displayName") or a.get("uniqueName") or "?" for a in s.get("approvers", [])],
            min_approvers=s.get("minRequiredApprovers") or 1,
            requester_can_approve=not bool(s.get("requesterCannotBeApprover", False)),
            timeout_minutes=timeout,
        )
    if tname == "branchcontrol":
        branches = [b.strip() for b in (s.get("allowedBranches") or "").split(",") if b.strip()]
        return Approval(kind="branch_control", branches=[b.removeprefix("refs/heads/") for b in branches], name="Branch control")
    if tname == "businesshours":
        return Approval(kind="business_hours", name="Business hours")
    # VERIFY: ServiceNow integration appears as an Invoke REST API / extension check; detect by content.
    if "servicenow" in blob or "service-now" in blob:
        return Approval(kind="servicenow", name=s.get("displayName") or "ServiceNow change check", timeout_minutes=timeout)
    return Approval(kind="gate", name=s.get("displayName") or tname or "check", timeout_minutes=timeout)


def apply_environment_checks(pipeline: Pipeline, envs: dict[str, Environment]) -> None:
    """Attach environment checks to the YAML stages that deploy to those environments."""
    if pipeline.platform != "ado_yaml":
        return
    for st in pipeline.stages:
        env = envs.get(st.env_name or "")
        if not env:
            continue
        for chk in env.checks:
            a = check_to_approval(chk)
            if a.kind == "manual":
                st.pre_approvals.append(a)
            else:
                st.gates.append(a)
                if a.kind == "branch_control":
                    st.branch_filters = sorted(set(st.branch_filters) | set(a.branches))
