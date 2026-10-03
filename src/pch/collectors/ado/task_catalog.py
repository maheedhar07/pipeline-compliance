"""Task GUID -> name/version resolution (cached per scan) and task-group expansion."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pch.collectors.ado.client import AdoClient
from pch.model.pipeline import Pipeline


@dataclass
class TaskDef:
    id: str
    name: str
    major: int | None = None
    marketplace: bool = False
    deprecated: bool = False
    friendly: str = ""


@dataclass
class TaskCatalog:
    by_id: dict[str, TaskDef] = field(default_factory=dict)
    task_groups: dict[str, dict[str, Any]] = field(default_factory=dict)  # id -> task group definition

    def by_name(self, name: str) -> TaskDef | None:
        low = name.lower()
        for d in self.by_id.values():
            if d.name.lower() == low:
                return d
        return None

    def annotate(self, pipeline: Pipeline) -> None:
        """Mark marketplace/deprecated on steps that were parsed without GUID resolution (YAML)."""
        for step in pipeline.all_steps():
            if step.task and "@" in step.task:
                d = self.by_name(step.task.split("@", 1)[0])
                if d is not None:
                    step.marketplace = step.marketplace or d.marketplace
                    step.deprecated = step.deprecated or d.deprecated

    def resolve(self, task_id: str, version_spec: str | None = None) -> tuple[str, str | None, TaskDef | None]:
        """Return (task name, major version string or None if unpinned, definition)."""
        d = self.by_id.get(task_id.lower())
        name = d.name if d else task_id
        major: str | None = None
        if version_spec and version_spec not in ("*", ""):
            head = version_spec.split(".")[0]
            major = head if head.isdigit() else None
        return name, major, d

    @classmethod
    def from_payload(cls, payload: dict[str, Any] | list[Any]) -> TaskCatalog:
        cat = cls()
        items = payload.get("value", []) if isinstance(payload, dict) else payload
        for t in items:
            ver = t.get("version") or {}
            major = ver.get("major")
            author = t.get("author") or ""
            contrib = t.get("contributionIdentifier")
            tid = str(t["id"]).lower()
            existing = cat.by_id.get(tid)
            if existing and (existing.major or 0) >= (major or 0):
                continue
            cat.by_id[tid] = TaskDef(
                id=tid,
                name=t.get("name", tid),
                major=major,
                marketplace=bool(contrib) or (bool(author) and author != "Microsoft Corporation"),
                deprecated=bool(t.get("deprecated")),
                friendly=t.get("friendlyName", ""),
            )
        return cat

    def add_task_groups(self, payload: dict[str, Any] | list[Any]) -> None:
        items = payload.get("value", []) if isinstance(payload, dict) else payload
        for g in items:
            self.task_groups[str(g["id"]).lower()] = g


async def load_task_catalog(client: AdoClient, projects: list[str]) -> TaskCatalog:
    """GET {org}/_apis/distributedtask/tasks (once per scan) + task groups per project."""
    payload = await client.get(None, "_apis/distributedtask/tasks")
    cat = TaskCatalog.from_payload(payload)
    for project in projects:
        tg = await client.get_optional(project, "_apis/distributedtask/taskgroups")
        if tg:
            cat.add_task_groups(tg)
    return cat
