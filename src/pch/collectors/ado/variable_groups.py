"""Variable groups: Key Vault linkage only. Values are never read into the model."""

from __future__ import annotations

from pch.collectors.ado.client import AdoClient
from pch.model.repo import VariableGroup


async def collect_variable_groups(client: AdoClient, project: str) -> dict[str, VariableGroup]:
    items = await client.paged(project, "_apis/distributedtask/variablegroups")
    out: dict[str, VariableGroup] = {}
    for g in items:
        vg = VariableGroup(id=str(g["id"]), name=g.get("name", ""), key_vault_linked=g.get("type") == "AzureKeyVault")
        out[vg.id] = vg
        out[vg.name] = vg
    return out
