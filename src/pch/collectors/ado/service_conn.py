"""Service connections (service endpoints) and their pipeline-permission scope."""

from __future__ import annotations

import asyncio
from typing import Any

from pch.collectors.ado.client import AdoClient
from pch.model.repo import ServiceConnection


def parse_endpoint(ep: dict[str, Any], perms: dict[str, Any] | None) -> ServiceConnection:
    auth = ep.get("authorization") or {}
    scheme = auth.get("scheme", "")
    data = ep.get("data") or {}
    # VERIFY: resource-group scoped ARM connections expose scopeLevel/resourceGroupName in `data`.
    level = data.get("scopeLevel") or ""
    if data.get("resourceGroupName"):
        level = "ResourceGroup"
    all_auth = None
    if perms is not None:
        all_auth = bool((perms.get("allPipelines") or {}).get("authorized", False))
    return ServiceConnection(
        id=str(ep.get("id")),
        name=ep.get("name", ""),
        type=ep.get("type", ""),
        auth_scheme=scheme,
        scope_level=level,
        all_pipelines_authorized=all_auth,
        federated=scheme == "WorkloadIdentityFederation",
    )


async def collect_service_connections(client: AdoClient, project: str) -> dict[str, ServiceConnection]:
    """Returns connections keyed by BOTH id and name (classic tasks reference ids, YAML references names)."""
    eps = await client.paged(project, "_apis/serviceendpoint/endpoints", {"includeDetails": "true"})
    perms = await asyncio.gather(
        *(client.get_optional(project, f"_apis/pipelines/pipelinePermissions/endpoint/{e['id']}") for e in eps)
    )
    out: dict[str, ServiceConnection] = {}
    for ep, pm in zip(eps, perms, strict=True):
        sc = parse_endpoint(ep, pm)
        out[sc.id] = sc
        out[sc.name] = sc
    return out
