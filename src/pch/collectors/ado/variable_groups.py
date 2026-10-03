"""Variable groups: Key Vault linkage only. Values are never read into the model."""

from __future__ import annotations

from pch.collectors.ado.client import AdoClient
from pch.model.repo import VariableGroup


async def collect_variable_groups(client: AdoClient, project: str) -> dict[str, VariableGroup]:
    items = await client.paged(project, "_apis/distributedtask/variablegroups")
    out: dict[str, VariableGroup] = {}
    for g in items:
        has_secrets = any(isinstance(v, dict) and v.get("isSecret") for v in (g.get("variables") or {}).values())
        vg = VariableGroup(id=str(g["id"]), name=g.get("name", ""), key_vault_linked=g.get("type") == "AzureKeyVault", has_secrets=has_secrets)
        out[vg.id] = vg
        out[vg.name] = vg
    return out
