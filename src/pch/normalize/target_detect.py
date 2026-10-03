"""Infer deploy targets, environment tier and service connections per stage."""

from __future__ import annotations

import re
from typing import Any

from pch.model.pipeline import Pipeline, Stage

TARGET_NAMES = {"functionapp", "webapp", "aks", "adf", "synapse", "sql", "iac"}
SERVICE_CONN_KEYS = (
    "azuresubscription",
    "connectedservicenamearm",
    "connectedservicename",
    "azureresourcemanagerconnection",
    "kubernetesserviceconnection",
    "kubernetesserviceendpoint",
    "azuresubscriptionendpoint",
    "serviceconnection",
    "workspaceserviceconnection",
    "azureserviceconnection",
    "dockerregistryendpoint",
    "dockerregistryserviceconnection",
    "connectedserviceazurerm",
)
ADF_PATH = re.compile(r"ARMTemplateForFactory|adf_publish", re.I)
SYN_PATH = re.compile(r"TemplateForWorkspace", re.I)

_UAT = {"uat", "stg", "stage", "staging", "preprod", "preprd", "pprd", "preproduction", "ppe"}
_PROD = {"prod", "prd", "production"}
_TEST = {"qa", "test", "tst", "sit", "testing", "qat", "systest"}
_DEV = {"dev", "development", "int", "sandbox"}


def tier_from_name(name: str | None) -> str:
    """Name regex classification. UAT is checked before prod so that 'preprod' is not 'prod'."""
    if not name:
        return "unknown"
    low = name.lower()
    if re.search(r"pre[-_ ]?prod", low):
        return "uat"
    tokens = [t for t in re.split(r"[^a-z0-9]+", low) if t]
    # camelCase split ("DeployProd" -> deploy, prod)
    tokens += [t.lower() for t in re.findall(r"[A-Z][a-z]+|[a-z]+|\d+", name)]

    def hit(group: set[str]) -> bool:
        for t in tokens:
            if t in group:
                return True
            base = t.rstrip("0123456789")
            if base in group and base != t:
                return True
            if t.startswith("product") and t != "production":
                continue
            if len(t) > 3 and any(t.startswith(g) and len(g) >= 3 for g in group if g not in {"int", "sit", "qa"}):
                return True
        return False

    for tier, group in (("uat", _UAT), ("prod", _PROD), ("test", _TEST), ("dev", _DEV)):
        if hit(group):
            return tier
    return "unknown"


def detect_env_tier(
    candidates: list[str | None],
    overrides: dict[str, str] | None = None,
) -> str:
    overrides = overrides or {}
    for c in candidates:
        if c and c in overrides:
            return overrides[c]
    for c in candidates:
        t = tier_from_name(c)
        if t != "unknown":
            return t
    return "unknown"


def _strings(v: Any) -> list[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, dict):
        return [s for x in v.values() for s in _strings(x)]
    if isinstance(v, list):
        return [s for x in v for s in _strings(x)]
    return []


def detect_targets(stage: Stage, repo_is_adf: bool = False, repo_is_synapse: bool = False) -> set[str]:
    """Union of deploy:<target> capabilities, refined for ADF / Synapse ARM deployments."""
    targets: set[str] = set()
    for step in stage.steps():
        if not step.enabled:
            continue
        step_targets = {c.split(":", 1)[1] for c in step.capabilities if c.startswith("deploy:")}
        if "iac" in step_targets:
            blob = " ".join(_strings(step.inputs) + [step.inline_script or ""])
            if ADF_PATH.search(blob) or (repo_is_adf and not blob.strip()):
                step_targets.discard("iac")
                step_targets.add("adf")
            elif SYN_PATH.search(blob):
                step_targets.discard("iac")
                step_targets.add("synapse")
        targets |= step_targets & (TARGET_NAMES | {"other"})
    return targets


def detect_service_connections(stage: Stage) -> list[str]:
    seen: list[str] = []
    for step in stage.steps():
        for k, v in step.inputs.items():
            if k.lower() in SERVICE_CONN_KEYS and isinstance(v, str) and v.strip() and v not in seen:
                seen.append(v)
    return seen


def enrich_pipeline(
    p: Pipeline,
    repo_is_adf: bool = False,
    repo_is_synapse: bool = False,
    tier_overrides: dict[str, str] | None = None,
) -> Pipeline:
    """Second normalization pass (needs repo facts + scope): targets, tiers, service connections."""
    for st in p.stages:
        st.deploy_targets = detect_targets(st, repo_is_adf, repo_is_synapse)
        st.service_connections = sorted(set(st.service_connections) | set(detect_service_connections(st)))
        if st.env_tier == "unknown" or (tier_overrides and (st.name in tier_overrides or st.env_name in tier_overrides)):
            st.env_tier = detect_env_tier([st.env_name, st.name], tier_overrides)  # type: ignore[assignment]
        st.is_deploy = bool(st.deploy_targets) or st.env_name is not None or p.platform == "ado_classic_release"
    return p
