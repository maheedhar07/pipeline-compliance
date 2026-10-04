"""Organisation repo listing and filters (scope.yaml ``github:``)."""

from __future__ import annotations

import fnmatch
import re
from typing import Any
from urllib.parse import quote

from pch.collectors.github.client import GitHubClient
from pch.model.repo import GitHubMeta
from pch.settings import GitHubScope

FULL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+$")  # also guards what ends up in an API path


def meta_from_api(raw: dict[str, Any]) -> GitHubMeta:
    return GitHubMeta(
        default_branch=str(raw.get("default_branch") or ""), archived=bool(raw.get("archived")), fork=bool(raw.get("fork")),
        visibility=str(raw.get("visibility") or ("private" if raw.get("private") else "public")),
        topics=[str(t) for t in raw.get("topics") or []], pushed_at=raw.get("pushed_at") or None,
    )


def _globs(name: str, full: str, patterns: list[str]) -> bool:
    n, f = name.casefold(), full.casefold()
    return any(fnmatch.fnmatchcase(f if "/" in p else n, p.casefold()) for p in patterns)  # "org/repo" patterns match the full name, others the repo name


def repo_matches(raw: dict[str, Any], gs: GitHubScope) -> bool:
    """The scope.yaml filters for one repo of an organisation listing: archived, forks, include/exclude globs on ``repo`` or ``org/repo``, topics."""
    full = str(raw.get("full_name") or "")
    name = str(raw.get("name") or full.rsplit("/", 1)[-1])
    if not FULL_NAME.match(full):
        return False
    if raw.get("archived") and not gs.include_archived:
        return False
    if raw.get("fork") and not gs.include_forks:
        return False
    if gs.include and not _globs(name, full, gs.include):
        return False
    if gs.exclude and _globs(name, full, gs.exclude):
        return False
    if gs.topics_any:
        have = {str(t).casefold() for t in raw.get("topics") or []}
        if not have & {t.casefold() for t in gs.topics_any}:
            return False
    return True


async def list_org_repos(client: GitHubClient, org: str, gs: GitHubScope) -> list[dict[str, Any]]:
    """``GET /orgs/{org}/repos?type=all`` (every page), filtered. Raises on API errors (the caller records a collection error)."""
    raw = await client.paged(f"/orgs/{quote(org, safe='')}/repos", {"type": "all"})
    return [r for r in raw if isinstance(r, dict) and repo_matches(r, gs)]
