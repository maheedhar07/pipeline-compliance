"""Builders for realistic synthetic Azure DevOps REST payloads (demo mode).

These emit RAW API-shaped JSON (never DB rows or canonical models) so that the real collectors,
normalizers and rules process them exactly as they would live data.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

ORG = "contoso-demo"
WEB = f"https://dev.azure.com/{ORG}"

# (name, major versions available, author, contributionIdentifier)
TASK_DEFS: list[tuple[str, list[int], str, str | None]] = [
    ("SonarQubePrepare", [4, 5], "SonarSource", "SonarSource.sonarqube"),
    ("SonarQubeAnalyze", [4, 5], "SonarSource", "SonarSource.sonarqube"),
    ("SonarQubePublish", [4, 5], "SonarSource", "SonarSource.sonarqube"),
    ("DotNetCoreCLI", [1, 2], "Microsoft Corporation", None),
    ("VSTest", [1, 2], "Microsoft Corporation", None),
    ("PublishTestResults", [2], "Microsoft Corporation", None),
    ("PublishCodeCoverageResults", [1], "Microsoft Corporation", None),
    ("PublishBuildArtifacts", [1], "Microsoft Corporation", None),
    ("PublishPipelineArtifact", [1], "Microsoft Corporation", None),
    ("DownloadPipelineArtifact", [2], "Microsoft Corporation", None),
    ("AzureFunctionApp", [1, 2], "Microsoft Corporation", None),
    ("AzureWebApp", [1], "Microsoft Corporation", None),
    ("AzureRmWebAppDeployment", [3, 4], "Microsoft Corporation", None),
    ("AzureAppServiceManage", [0], "Microsoft Corporation", None),
    ("KubernetesManifest", [0, 1], "Microsoft Corporation", None),
    ("HelmDeploy", [0], "Microsoft Corporation", None),
    ("AzureResourceManagerTemplateDeployment", [3], "Microsoft Corporation", None),
    ("AzureResourceGroupDeployment", [2], "Microsoft Corporation", None),
    ("AzureCLI", [1, 2], "Microsoft Corporation", None),
    ("AzurePowerShell", [4, 5], "Microsoft Corporation", None),
    ("Synapse workspace deployment", [2], "Microsoft DevLabs", "microsoft-devlabs.synapsecicd"),
    ("SqlAzureDacpacDeployment", [1], "Microsoft Corporation", None),
    ("ServiceNow-DevOps-Change", [1], "ServiceNow", "ServiceNow.servicenow-devops"),
    ("Docker", [2], "Microsoft Corporation", None),
    ("Npm", [1], "Microsoft Corporation", None),
    ("NodeTool", [0], "Microsoft Corporation", None),
    ("Maven", [3], "Microsoft Corporation", None),
    ("MSBuild", [1], "Microsoft Corporation", None),
    ("CmdLine", [2], "Microsoft Corporation", None),
    ("PowerShell", [2], "Microsoft Corporation", None),
    ("Bash", [3], "Microsoft Corporation", None),
    ("InvokeRESTAPI", [1], "Microsoft Corporation", None),
    ("TerraformTaskV4", [4], "Microsoft DevLabs", "ms-devlabs.custom-terraform-tasks"),
    ("ManualIntervention", [8], "Microsoft Corporation", None),
    ("replacetokens", [5], "Guillaume Rouchon", "qetza.replacetokens"),
    ("colinsalmcorner-tool", [2], "Colin Dembovsky", "colinsalmcorner.colinsalmcorner-buildtasks"),
]


def task_guid(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, "pch-task-" + name))


def tasks_payload() -> dict[str, Any]:
    items = []
    for name, majors, author, contrib in TASK_DEFS:
        for m in majors:
            items.append({
                "id": task_guid(name), "name": name, "friendlyName": name, "author": author,
                "version": {"major": m, "minor": 0, "patch": 0},
                **({"contributionIdentifier": contrib} if contrib else {}),
            })
    return {"count": len(items), "value": items}


@dataclass
class SD:
    """Step descriptor, rendered either as a classic task, a YAML step, or both."""

    task: str | None = None  # task name
    ver: int | None = 2
    inputs: dict[str, Any] = field(default_factory=dict)
    name: str | None = None
    script: str | None = None
    enabled: bool = True
    coe: bool = False
    condition: str | None = None
    shell: str = "script"  # script | pwsh


def _classic_script_task(sd: SD) -> tuple[str, int, dict[str, Any]]:
    if sd.shell == "pwsh":
        return "PowerShell", 2, {"targetType": "inline", "script": sd.script}
    return "CmdLine", 2, {"script": sd.script}


def classic_step(sd: SD, idx: int) -> dict[str, Any]:
    task: str
    ver: int | None
    inputs: dict[str, Any]
    if sd.script is not None:
        task, ver, inputs = _classic_script_task(sd)
    else:
        task, ver, inputs = sd.task or "", sd.ver, sd.inputs
    spec = f"{ver}.*" if ver is not None else "*"
    return {
        "environment": {}, "enabled": sd.enabled, "continueOnError": sd.coe, "alwaysRun": False,
        "displayName": sd.name or task, "timeoutInMinutes": 0, "retryCountOnTaskFailure": 0,
        "condition": sd.condition or "succeeded()",
        "task": {"id": task_guid(task), "versionSpec": spec, "definitionType": "task"},
        "inputs": inputs,
    }


def classic_workflow_task(sd: SD) -> dict[str, Any]:
    task: str
    ver: int | None
    inputs: dict[str, Any]
    if sd.script is not None:
        task, ver, inputs = _classic_script_task(sd)
    else:
        task, ver, inputs = sd.task or "", sd.ver, sd.inputs
    return {
        "taskId": task_guid(task), "version": f"{ver}.*" if ver is not None else "*", "name": sd.name or task,
        "refName": "", "enabled": sd.enabled, "alwaysRun": False, "continueOnError": sd.coe,
        "timeoutInMinutes": 0, "definitionType": "task", "overrideInputs": {}, "condition": sd.condition or "succeeded()",
        "inputs": inputs,
    }


def yaml_step(sd: SD) -> str:
    """Render a YAML step (as flow-ish text, 6-space indented list item)."""
    lines: list[str] = []
    if sd.script is not None:
        key = "pwsh" if sd.shell == "pwsh" else "script"
        lines.append(f"- {key}: {_q(sd.script)}")
        if sd.name:
            lines.append(f"  displayName: {_q(sd.name)}")
    else:
        t = f"{sd.task}@{sd.ver}" if sd.ver is not None else f"{sd.task}"
        lines.append(f"- task: {t}")
        if sd.name:
            lines.append(f"  displayName: {_q(sd.name)}")
        if sd.inputs:
            lines.append("  inputs:")
            for k, v in sd.inputs.items():
                lines.append(f"    {k}: {_q(v)}")
    if sd.coe:
        lines.append("  continueOnError: true")
    if not sd.enabled:
        lines.append("  enabled: false")
    if sd.condition:
        lines.append(f"  condition: {_q(sd.condition)}")
    return "\n".join(lines)


def _q(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int | float):
        return str(v)
    s = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{s}"'


def indent(text: str, n: int) -> str:
    pad = " " * n
    return "\n".join(pad + line if line else line for line in text.split("\n"))


def web_link(project: str, kind: str, def_id: int) -> dict[str, Any]:
    seg = "_build" if kind == "build" else "_release"
    return {"web": {"href": f"{WEB}/{project}/{seg}?definitionId={def_id}"}}


# ---------------------------------------------------------------- policies / endpoints
T_MIN_REVIEWERS = "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"
T_BUILD = "0609b952-1397-4640-95ec-e00a01b2c241"
T_WORK_ITEM = "40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e"
T_COMMENTS = "c6a1889d-b943-4856-b76f-9e46bb6b0df2"
T_REQ_REVIEWERS = "fd2167ab-b0be-447a-8ec8-39368250530e"


def policy_cfg(pid: int, tid: str, name: str, settings: dict[str, Any], repo_id: str, branch: str = "main") -> dict[str, Any]:
    scope = [{"refName": f"refs/heads/{branch}", "matchKind": "Exact", "repositoryId": repo_id}]
    return {"id": pid, "isEnabled": True, "isDeleted": False, "isBlocking": True,
            "type": {"id": tid, "displayName": name}, "settings": {**settings, "scope": scope}}


def endpoint(eid: str, name: str, scheme: str, scope_level: str, rg: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {"scopeLevel": scope_level, "subscriptionName": "contoso-prod", "environment": "AzureCloud"}
    if rg:
        data["resourceGroupName"] = rg
    return {"id": eid, "name": name, "type": "azurerm", "authorization": {"scheme": scheme, "parameters": {"tenantid": "t"}},
            "data": data, "isShared": False, "isReady": True}
