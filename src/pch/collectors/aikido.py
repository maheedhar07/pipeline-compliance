"""Aikido collector (read-only).

Aikido's public API shape is NOT verified against live docs in this build. Every assumption about
paths and field names is isolated in this module (see the `# VERIFY:` markers) so it can be
adjusted in one place without touching the rest of the code base.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from pch.collectors.http import HttpError, SourceClient
from pch.model.repo import AikidoFacts, AikidoIssue

# VERIFY: OAuth client-credentials token endpoint.
TOKEN_PATH = "/api/oauth/token"
# VERIFY: repository listing endpoint.
REPOS_PATH = "/api/public/v1/repositories/code"
# VERIFY: open issue groups endpoint, filterable by repository / severity / first_detected_at.
ISSUES_PATH = "/api/public/v1/open-issue-groups"


def _parse_dt(v: Any) -> datetime | None:
    if v is None:
        return None
    if isinstance(v, int | float):  # unix seconds
        return datetime.fromtimestamp(v, UTC).replace(tzinfo=None)
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d.astimezone(UTC).replace(tzinfo=None) if d.tzinfo else d


def normalize_repo(raw: dict[str, Any]) -> tuple[str, str]:
    """VERIFY: map a raw repository record to (aikido repo id, repo name)."""
    return str(raw.get("id")), str(raw.get("name") or raw.get("external_repo_name") or "")


def normalize_issue(raw: dict[str, Any]) -> tuple[str | None, AikidoIssue] | None:
    """VERIFY: map a raw open-issue-group to (aikido repo id, AikidoIssue). Returns None if unusable."""
    first = _parse_dt(raw.get("first_detected_at") or raw.get("time_first_detected") or raw.get("created_at"))
    sev = str(raw.get("severity") or raw.get("severity_level") or "").lower()
    if first is None or not sev:
        return None
    repo_id = raw.get("code_repo_id") or raw.get("repo_id") or (raw.get("code_repo") or {}).get("id")
    return (
        str(repo_id) if repo_id is not None else None,
        AikidoIssue(id=str(raw.get("id")), severity=sev, first_detected=first, type=str(raw.get("type") or "")),
    )


class AikidoClient:
    def __init__(self, base_url: str, client_id: str = "", client_secret: str = "", *,
                 transport: httpx.AsyncBaseTransport | None = None, concurrency: int = 8,
                 backoff_base: float = 0.5, max_attempts: int = 4):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self._secret = client_secret
        self._token: str | None = None  # kept in memory only, never persisted
        self.http = SourceClient(self.base_url, transport=transport, concurrency=concurrency,
                                 backoff_base=backoff_base, max_attempts=max_attempts)

    async def aclose(self) -> None:
        await self.http.aclose()

    async def _auth_headers(self) -> dict[str, str]:
        if self._token is None:
            r = await self.http.request("POST", TOKEN_PATH, data={"grant_type": "client_credentials"},
                                        auth=(self.client_id, self._secret))
            self._token = r.json()["access_token"]
        return {"Authorization": f"Bearer {self._token}"}

    async def _paged(self, path: str, params: dict[str, Any] | None = None, max_pages: int = 100) -> list[Any]:
        out: list[Any] = []
        for page in range(max_pages):
            headers = await self._auth_headers()
            r = await self.http.request("GET", path, params={**(params or {}), "page": page, "per_page": 200}, headers=headers)
            body = r.json()
            items = body if isinstance(body, list) else body.get("items") or body.get("data") or []
            out.extend(items)
            if len(items) < 200:
                break
        return out

    async def fetch_all(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """One org-wide fetch per scan: (repositories, open issue groups)."""
        return await self._paged(REPOS_PATH), await self._paged(ISSUES_PATH)

    @staticmethod
    def facts_for(repo_name: str, repos: list[dict[str, Any]], issues: list[dict[str, Any]],
                  override: str | None = None) -> AikidoFacts:
        target = (override or repo_name).lower()
        match = None
        for r in repos:
            rid, name = normalize_repo(r)
            if name.lower() == target or name.lower().endswith("/" + target):
                match = (rid, name)
                break
        if match is None:
            return AikidoFacts(onboarded=False)
        rid, _ = match
        found: list[AikidoIssue] = []
        for raw in issues:
            n = normalize_issue(raw)
            if n and n[0] == rid:
                found.append(n[1])
        return AikidoFacts(onboarded=True, repo_id=rid, open_issues=found)

    async def facts(self, repo_name: str, override: str | None = None) -> AikidoFacts:
        repos, issues = await self.fetch_all()
        return self.facts_for(repo_name, repos, issues, override)


__all__ = ["AikidoClient", "HttpError", "normalize_issue", "normalize_repo"]
