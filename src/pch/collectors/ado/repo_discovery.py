"""Repo discovery for one ADO project: Azure Repos repositories plus externally hosted code built by ADO pipelines.

Source code may live on GitHub while every pipeline lives in Azure DevOps. ADO describes that code only through
the pipelines that use it: a build definition has ``repository.type`` ("GitHub", "GitHubEnterprise", "Bitbucket",
"Git", ...), ``repository.id``/``name`` = "org/repo", ``url`` and ``properties.connectedServiceId``; a classic
release may consume a GitHub artifact directly (``artifacts[].type == "GitHub"``).

Repo key and display: grouping stays per ADO project; an external repo's name is its full name ("org/repo"), so
its key is ``Project/org/repo``. Repos are de-duplicated case-insensitively on (provider, full name).
"""

from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from pch.model.repo import PROVIDER_LABEL, RepoProvider

MAX_NAME = 190  # repo_results.repo is Unicode(200); keep headroom

_TYPE_TO_PROVIDER: dict[str, RepoProvider] = {
    "tfsgit": "azure_repos",
    "github": "github",
    "githubenterprise": "github_enterprise",
}


def provider_of(repo_type: str | None) -> RepoProvider | None:
    """Map ADO ``repository.type`` to a provider. None = type absent (undecidable)."""
    if not repo_type:
        return None
    return _TYPE_TO_PROVIDER.get(repo_type.strip().lower(), "other_git")


@dataclass
class RepoEntry:
    """One repository to scan, whatever hosts it."""

    provider: RepoProvider
    id: str  # Azure Repos: repository GUID; external: the id ADO uses in build definitions ("org/repo")
    name: str  # Azure Repos: repo name; external: full name "org/repo"
    url: str = ""
    default_branch: str = ""  # "refs/heads/main" or "main"
    service_connection_id: str | None = None
    disabled: bool = False

    @property
    def external(self) -> bool:
        return self.provider != "azure_repos"

    @property
    def link_key(self) -> tuple[str, str]:
        return (self.provider, (self.name if self.external else self.id).casefold())


def _clean_full_name(raw: Any) -> str:
    n = str(raw or "").strip().strip("/")
    n = re.sub(r"\.git$", "", n, flags=re.I)
    return n


def _web_url(provider: str, full_name: str, url: str) -> str:
    """Browser URL without ``.git`` (https://github.com/org/repo)."""
    u = (url or "").strip()
    parsed = urlparse(u)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return re.sub(r"\.git$", "", f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/"), flags=re.I)
    if provider == "github":
        return f"https://github.com/{full_name}"
    return ""


def _from_repository_block(repo: dict[str, Any]) -> RepoEntry | None:
    provider = provider_of(repo.get("type"))
    if provider is None or provider == "azure_repos":
        return None
    props = repo.get("properties") or {}
    full = _clean_full_name(repo.get("id") or props.get("fullName") or repo.get("name"))
    if not full and repo.get("url"):
        full = _clean_full_name(urlparse(str(repo["url"])).path)
    if not full or len(full) > MAX_NAME:
        return None
    return RepoEntry(
        provider=provider, id=full, name=full, url=_web_url(provider, full, repo.get("url") or ""),
        default_branch=str(repo.get("defaultBranch") or props.get("defaultBranch") or ""),
        service_connection_id=str(props.get("connectedServiceId") or "") or None,
    )


def _from_release_artifact(a: dict[str, Any]) -> RepoEntry | None:
    """Classic release artifact of type GitHub (no build in between): definition id/name is "org/repo"."""
    ref = a.get("definitionReference") or {}
    d = ref.get("definition") or {}
    full = _clean_full_name(d.get("id") or d.get("name"))
    if not full or len(full) > MAX_NAME:
        return None
    conn = (ref.get("connection") or {}).get("id")
    branch = (ref.get("defaultVersionBranch") or ref.get("branch") or {}).get("id") or ""
    return RepoEntry(provider="github", id=full, name=full, url=_web_url("github", full, ""), default_branch=str(branch),
                     service_connection_id=str(conn) if conn else None)


def _artifact_order(release: dict[str, Any]) -> list[dict[str, Any]]:
    arts = [a for a in release.get("artifacts", []) if isinstance(a, dict)]
    return sorted(arts, key=lambda a: not a.get("isPrimary"))  # stable: primary first, then definition order


@dataclass
class Discovery:
    repos: list[RepoEntry]
    builds_by_repo: dict[tuple[str, str], list[dict[str, Any]]]
    releases_by_repo: dict[tuple[str, str], list[dict[str, Any]]]
    unlinked_releases: list[dict[str, Any]]
    unlinked_builds: list[tuple[dict[str, Any], str]] = field(default_factory=list)  # (raw definition, reason): no resolvable repository
    # Items whose code host is not in scope (scope.yaml code_hosts): provider -> {"builds": n, "releases": n}. Not scanned, not orphans.
    out_of_scope: dict[str, dict[str, int]] = field(default_factory=dict)

    def out_of_scope_summary(self, code_hosts: Collection[str]) -> str:
        """One line for a collection error (info): what was left out and why. Empty when nothing was."""
        if not self.out_of_scope:
            return ""
        parts = []
        for prov in sorted(self.out_of_scope):
            c = self.out_of_scope[prov]
            parts.append(f"{c.get('builds', 0)} build definition(s) and {c.get('releases', 0)} release definition(s) hosted on {PROVIDER_LABEL.get(prov, prov)}")
        return f"info: out of scope (code_hosts={sorted(code_hosts)}), not scanned: " + "; ".join(parts)


def discover(ado_repos: list[dict[str, Any]], build_defs: list[dict[str, Any]], release_defs: list[dict[str, Any]],
             code_hosts: Collection[str] | None = None, known_github: Collection[str] = ()) -> Discovery:
    """Repos = Azure Repos repositories + external repos referenced by build definitions + GitHub repos used directly
    as classic release artifacts; with build definitions and releases linked to them.

    ``code_hosts`` (scope.yaml; None = every host) limits the scan to those hosts: a repo, build definition or release whose
    code lives elsewhere is counted in ``Discovery.out_of_scope`` instead of being scanned or reported as unlinked.
    ``known_github`` are "org/repo" names from scope.yaml: they become repos even when no pipeline references them (so a
    "repo without pipelines" is visible); ignored unless ``github`` is in scope."""
    hosts = None if code_hosts is None else set(code_hosts)

    def allowed(provider: str) -> bool:
        return hosts is None or provider in hosts

    out_of_scope: dict[str, dict[str, int]] = {}

    def skip(provider: str, what: str) -> None:
        counts = out_of_scope.setdefault(provider, {})
        counts[what] = counts.get(what, 0) + 1

    entries: dict[tuple[str, str], RepoEntry] = {}
    for r in ado_repos if allowed("azure_repos") else []:
        e = RepoEntry(provider="azure_repos", id=r["id"], name=r["name"], url=r.get("webUrl") or "",
                      default_branch=r.get("defaultBranch") or "", disabled=bool(r.get("isDisabled")))
        entries[e.link_key] = e
    builds_by_repo: dict[tuple[str, str], list[dict[str, Any]]] = {}
    build_repo: dict[str, tuple[str, str]] = {}
    skipped_builds: dict[str, str] = {}  # build definition id -> provider that is out of scope
    unlinked_builds: list[tuple[dict[str, Any], str]] = []
    for b in sorted(build_defs, key=lambda d: int(d["id"]) if str(d.get("id", "")).isdigit() else 0):
        repo = b.get("repository") or {}
        ext = _from_repository_block(repo)
        prov = ext.provider if ext is not None else provider_of(repo.get("type"))
        if (ext is not None or repo.get("id")) and not allowed(prov or "azure_repos"):
            skip(prov or "azure_repos", "builds")
            skipped_builds[str(b["id"])] = prov or "azure_repos"
            continue
        if ext is not None:
            key = ext.link_key
            if key not in entries:
                entries[key] = ext
            elif not entries[key].service_connection_id and ext.service_connection_id:
                entries[key].service_connection_id = ext.service_connection_id
        elif repo.get("id") and provider_of(repo.get("type")) in (None, "azure_repos"):
            key = ("azure_repos", str(repo["id"]).casefold())
        else:
            unlinked_builds.append((b, f"build definition has no resolvable repository (type {repo.get('type') or 'unknown'}, name {str(repo.get('name') or repo.get('id') or 'none')[:80]})"))
            continue
        builds_by_repo.setdefault(key, []).append(b)
        build_repo[str(b["id"])] = key
    releases_by_repo: dict[tuple[str, str], list[dict[str, Any]]] = {}
    unlinked: list[dict[str, Any]] = []
    for rel in release_defs:
        rkey: tuple[str, str] | None = None
        skipped: str | None = None
        for a in _artifact_order(rel):
            if a.get("type") == "Build":
                bid = str(((a.get("definitionReference") or {}).get("definition") or {}).get("id"))
                if bid in build_repo:
                    rkey = build_repo[bid]
                elif bid in skipped_builds:
                    skipped = skipped_builds[bid]
            elif a.get("type") == "GitHub":
                ext = _from_release_artifact(a)
                if ext is not None and not allowed(ext.provider):
                    skipped = ext.provider
                elif ext is not None:
                    rkey = ext.link_key
                    if rkey not in entries:
                        entries[rkey] = ext
            if rkey is not None or skipped is not None:
                break
        if skipped is not None:
            skip(skipped, "releases")
            continue
        if rkey is None or rkey not in entries:  # e.g. built from a repo in another project: genuinely unlinkable here
            unlinked.append(rel)
        else:
            releases_by_repo.setdefault(rkey, []).append(rel)
    if allowed("github"):
        for name in known_github:
            full = _clean_full_name(name)
            if "/" in full and len(full) <= MAX_NAME and ("github", full.casefold()) not in entries:
                e = RepoEntry(provider="github", id=full, name=full, url=_web_url("github", full, ""))
                entries[e.link_key] = e
    for key, bs in builds_by_repo.items():  # Azure Repos id that is not in this project's repository list (deleted, other project, no access)
        if key not in entries:
            unlinked_builds.extend((b, "repository not found in this project (deleted, in another project or not visible)") for b in bs)
    return Discovery(list(entries.values()), builds_by_repo, releases_by_repo, unlinked, unlinked_builds, out_of_scope)
