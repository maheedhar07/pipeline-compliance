"""Read one GitHub repository (read-only): metadata, file tree, CODEOWNERS and default-branch protection.

Failure model: nothing here raises for a normal GitHub answer. A part that cannot be read becomes an UNKNOWN-driving state with a
precise reason (``RepoFacts.facts_source == "unavailable"`` + ``facts_reason``; ``BranchProtection.available == False`` or
``incomplete``), and one message per failed call in ``RepoRead.errors`` for the scan's collection errors. Never an empty fact.

Endpoints (all GET): ``/repos/{o}/{r}`` (Metadata), ``/repos/{o}/{r}/git/trees/{branch}?recursive=1`` and
``/repos/{o}/{r}/contents/{path}`` (Contents), ``/repos/{o}/{r}/rules/branches/{branch}`` (Metadata),
``/repos/{o}/{r}/rulesets/{id}`` or ``/orgs/{org}/rulesets/{id}`` (bypass actors, best effort),
``/repos/{o}/{r}/branches/{branch}/protection`` (Administration: read).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from pch.collectors.github.client import GitHubClient, RateLimited, UnsafePagination
from pch.collectors.github.discovery import FULL_NAME, meta_from_api
from pch.collectors.github.protection import (
    Bypass,
    ClassicState,
    bypass_labels,
    merge_protection,
    ruleset_key,
)
from pch.collectors.http import HttpError
from pch.model.repo import BranchProtection, GitHubMeta, RepoFacts
from pch.repo_scan.files import select_content_paths
from pch.repo_scan.tests_detect import analyze_repo, detect_tests

CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")  # GitHub's own lookup order
MAX_CONTENT_FILES = 10  # per repo, only when the file names alone do not prove tests exist


@dataclass
class RepoRead:
    facts: RepoFacts
    protection: BranchProtection
    default_branch: str = ""
    owner: str | None = None
    web_url: str = ""
    errors: list[str] = field(default_factory=list)  # one line per failed call (the scan scrubs them into collection errors)


def _q(v: str) -> str:
    return quote(v, safe="")


def reason_for(exc: BaseException, what: str, permission: str = "") -> str:
    """Plain-language reason shown on UNKNOWN findings. Names the missing permission when GitHub says which."""
    if isinstance(exc, RateLimited):
        return f"GitHub rate limit: {what} not read ({exc})"
    if isinstance(exc, HttpError):
        need = exc.headers.get("x-accepted-github-permissions", "")
        hint = f" (token needs: {need})" if need else (f" (token needs {permission})" if permission else "")
        if exc.status == 404:
            return f"GitHub: {what} not found or not visible to the token (HTTP 404){hint}"
        if exc.status in (401, 403):
            return f"GitHub: {what} denied (HTTP {exc.status}){hint}"
        return f"GitHub: {what} failed (HTTP {exc.status})"
    if isinstance(exc, UnsafePagination):
        return f"GitHub: {what} stopped: {exc}"
    return f"GitHub: {what} failed ({type(exc).__name__})"


def default_codeowner(text: str) -> str | None:
    """First owner of the last ``*`` rule (CODEOWNERS: the last matching pattern wins)."""
    owner: str | None = None
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] == "*":
            owner = next((o for o in parts[1:] if o.startswith("@") or "@" in o), None) or owner
    return owner


def _unavailable(reason: str) -> RepoFacts:
    return RepoFacts(facts_source="unavailable", facts_reason=reason)


async def _tree(client: GitHubClient, full: str, branch: str) -> tuple[list[str], bool]:
    """(blob paths, complete?). An empty repository (HTTP 409) is an empty, complete tree."""
    try:
        body = await client.get_json(f"/repos/{full}/git/trees/{_q(branch)}", {"recursive": "1"})
    except HttpError as e:
        if e.status == 409:
            return [], True
        raise
    tree = (body or {}).get("tree") or []
    return [t["path"] for t in tree if isinstance(t, dict) and t.get("type") == "blob" and t.get("path")], not (body or {}).get("truncated")


async def _file(client: GitHubClient, full: str, branch: str, path: str) -> str | None:
    try:
        return await client.get_raw(f"/repos/{full}/contents/{quote(path)}", {"ref": branch})
    except HttpError as e:
        if e.status in (403, 404):
            return None
        raise


async def _protection(client: GitHubClient, full: str, org: str, branch: str, errors: list[str]) -> BranchProtection:
    rules: list[dict[str, Any]] | None = None
    rules_error = ""
    try:
        rules = [r for r in await client.paged(f"/repos/{full}/rules/branches/{_q(branch)}") if isinstance(r, dict)]
    except Exception as e:  # noqa: BLE001 - becomes a reason, never an exception
        rules_error = reason_for(e, "branch rules", "Metadata: read")
        errors.append(rules_error)
    bypass: Bypass = {}
    for key, rule in {ruleset_key(r): r for r in rules or []}.items():
        src_type, src, rid = rule.get("ruleset_source_type"), str(rule.get("ruleset_source") or ""), rule.get("ruleset_id")
        if not isinstance(rid, int):
            bypass[key] = None
            continue
        path = f"/orgs/{_q(src)}/rulesets/{rid}" if src_type == "Organization" else f"/repos/{full}/rulesets/{rid}"
        try:
            detail = await client.get_json(path)
            bypass[key] = bypass_labels((detail or {}).get("bypass_actors"))
        except Exception:  # noqa: BLE001 - bypass actors are best effort: unknown, not an error line per ruleset
            bypass[key] = None
    classic: dict[str, Any] | None = None
    state: ClassicState = "none"
    classic_error = ""
    try:
        classic = await client.get_json(f"/repos/{full}/branches/{_q(branch)}/protection")
        state = "present"
    except HttpError as e:
        if e.status != 404:  # 404 = the branch has no classic protection
            state, classic_error = "unknown", reason_for(e, "classic branch protection", "Administration: read")
            errors.append(classic_error)
    except Exception as e:  # noqa: BLE001
        state, classic_error = "unknown", reason_for(e, "classic branch protection")
        errors.append(classic_error)
    return merge_protection(rules=rules, rules_error=rules_error, bypass=bypass, classic=classic, classic_state=state, classic_error=classic_error)


async def read_repo(client: GitHubClient, full_name: str, *, known: dict[str, Any] | None = None) -> RepoRead:
    """Facts + protection for ``org/repo``. ``known`` is the organisation-listing record when there is one (saves the metadata call)."""
    errors: list[str] = []
    if not FULL_NAME.match(full_name):
        why = f"GitHub: '{full_name[:60]}' is not a valid org/repo name"
        return RepoRead(_unavailable(why), BranchProtection(unavailable_reason=why), errors=[why])
    full = "/".join(_q(x) for x in full_name.split("/"))
    org = full_name.split("/", 1)[0]
    try:
        raw = known if known is not None else await client.get_json(f"/repos/{full}")
    except Exception as e:  # noqa: BLE001
        why = reason_for(e, "repository", "Metadata: read")
        return RepoRead(_unavailable(why), BranchProtection(unavailable_reason=why), errors=[why])
    meta: GitHubMeta = meta_from_api(raw or {})
    branch = meta.default_branch
    web = str((raw or {}).get("html_url") or "")
    if not branch:  # a repository without any branch (never pushed to)
        facts = analyze_repo(None)
        facts.facts_source, facts.github = "github", meta
        return RepoRead(facts, BranchProtection(unavailable_reason="repository has no default branch yet"), "", None, web, errors)

    async def tree_part() -> tuple[RepoFacts, str | None]:
        try:
            paths, complete = await _tree(client, full, branch)
        except Exception as e:  # noqa: BLE001
            why = reason_for(e, "file tree", "Contents: read")
            errors.append(why)
            return _unavailable(why), None
        contents: dict[str, str] = {}
        if paths and not detect_tests(paths, {})[0]:  # file names already prove tests: no content fetch needed
            chosen = select_content_paths(paths)[:MAX_CONTENT_FILES]
            got = await asyncio.gather(*(_file(client, full, branch, p) for p in chosen), return_exceptions=True)
            contents = {p: c for p, c in zip(chosen, got, strict=True) if isinstance(c, str)}
        facts = analyze_repo(paths, contents)
        facts.facts_source, facts.tree_complete = "github", complete
        if not complete:
            facts.facts_reason = "GitHub truncated the file tree (very large repository): test and repository-kind detection is partial"
        listed = {p.casefold() for p in paths}
        candidates = [c for c in CODEOWNERS_PATHS if not complete or c.casefold() in listed]
        owner_text: str | None = None
        for c in candidates:
            try:
                owner_text = await _file(client, full, branch, c)
            except Exception as e:  # noqa: BLE001
                errors.append(reason_for(e, "CODEOWNERS", "Contents: read"))
                break
            if owner_text is not None:
                break
        facts.codeowners = owner_text is not None
        return facts, default_codeowner(owner_text) if owner_text else None

    (facts, owner), protection = await asyncio.gather(tree_part(), _protection(client, full, org, branch, errors))
    facts.github = meta
    return RepoRead(facts, protection, branch, owner, web, errors)

