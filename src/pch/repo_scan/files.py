"""Fetch a repo's file tree (and a few small files) through the ADO Items API; no clone."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from pch.collectors.ado.client import AdoClient
from pch.collectors.http import HttpError

CONTENT_PATTERNS = [
    re.compile(r"\.csproj$", re.I),
    re.compile(r"(^|/)package\.json$", re.I),
    re.compile(r"(^|/)requirements[^/]*\.txt$", re.I),
    re.compile(r"(^|/)pyproject\.toml$", re.I),
    re.compile(r"\.sqlproj$", re.I),
]
MAX_CONTENT_FILES = 25


def select_content_paths(paths: list[str]) -> list[str]:
    chosen = [p for p in paths if any(c.search(p) for c in CONTENT_PATTERNS)]
    chosen.sort(key=lambda p: (p.count("/"), p))  # shallow first
    return chosen[:MAX_CONTENT_FILES]


async def fetch_tree(client: AdoClient, project: str, repo_id: str, branch: str) -> list[str] | None:
    """Return all blob paths on `branch`, or None if the repo is empty/disabled/unreadable."""
    try:
        items = await client.paged(
            project,
            f"_apis/git/repositories/{repo_id}/items",
            {"recursionLevel": "Full", "versionDescriptor.version": branch, "versionDescriptor.versionType": "branch", "scopePath": "/"},
        )
    except HttpError as e:
        if e.status in (400, 401, 403, 404):
            return None
        raise
    return [i["path"].lstrip("/") for i in items if i.get("gitObjectType", "blob") == "blob" and not i.get("isFolder")]


async def fetch_file(client: AdoClient, project: str, repo_id: str, branch: str, path: str) -> str | None:
    data: Any = await client.get_optional(
        project,
        f"_apis/git/repositories/{repo_id}/items",
        {"path": "/" + path, "includeContent": "true", "$format": "json",
         "versionDescriptor.version": branch, "versionDescriptor.versionType": "branch"},
    )
    if isinstance(data, dict):
        return data.get("content")
    return None


async def fetch_contents(client: AdoClient, project: str, repo_id: str, branch: str, paths: list[str]) -> dict[str, str]:
    results = await asyncio.gather(*(fetch_file(client, project, repo_id, branch, p) for p in paths))
    return {p: c for p, c in zip(paths, results, strict=True) if c is not None}
