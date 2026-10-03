"""Azure DevOps REST client (read-only): PAT auth, api-version 7.1, continuation-token paging."""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import quote

import httpx

from pch.collectors.http import HttpError, SourceClient

API_VERSION = "7.1"


class AdoClient:
    def __init__(
        self,
        org: str,
        pat: str = "",
        *,
        base_url: str = "https://dev.azure.com",
        vsrm_url: str = "https://vsrm.dev.azure.com",
        transport: httpx.AsyncBaseTransport | None = None,
        concurrency: int = 8,
        timeout: float = 30.0,
        backoff_base: float = 0.5,
        max_attempts: int = 4,
    ):
        self.org = org
        self.base_url = base_url.rstrip("/")
        self.vsrm_url = vsrm_url.rstrip("/")
        token = base64.b64encode(f":{pat}".encode()).decode()
        headers = {"Authorization": f"Basic {token}", "Accept": "application/json"} if pat else {"Accept": "application/json"}
        self.http = SourceClient(
            transport=transport,
            headers=headers,
            concurrency=concurrency,
            timeout=timeout,
            backoff_base=backoff_base,
            max_attempts=max_attempts,
        )

    # ------------------------------------------------------------------ urls
    def org_url(self, project: str | None = None, vsrm: bool = False) -> str:
        base = self.vsrm_url if vsrm else self.base_url
        return f"{base}/{self.org}" + (f"/{quote(project)}" if project else "")

    def web_url(self, project: str, path: str) -> str:
        return f"{self.base_url}/{self.org}/{quote(project)}/{path.lstrip('/')}"

    # ------------------------------------------------------------------ calls
    async def get(self, project: str | None, path: str, params: dict[str, Any] | None = None, vsrm: bool = False) -> Any:
        p = {"api-version": API_VERSION, **(params or {})}
        return await self.http.get_json(f"{self.org_url(project, vsrm)}/{path.lstrip('/')}", p)

    async def post_preview(self, project: str, pipeline_id: str | int) -> Any:
        """The single permitted POST: expand a YAML pipeline without running it (previewRun=true)."""
        r = await self.http.request(
            "POST",
            f"{self.org_url(project)}/_apis/pipelines/{pipeline_id}/preview",
            params={"api-version": API_VERSION},
            json={"previewRun": True},
        )
        return r.json()

    async def get_optional(self, project: str | None, path: str, params: dict[str, Any] | None = None, vsrm: bool = False) -> Any:
        """GET returning None on 404/403 (feature not enabled / no permission)."""
        try:
            return await self.get(project, path, params, vsrm)
        except HttpError as e:
            if e.status in (401, 403, 404):
                return None
            raise

    async def paged(
        self, project: str | None, path: str, params: dict[str, Any] | None = None, vsrm: bool = False, max_pages: int = 200
    ) -> list[Any]:
        """Follow continuationToken (header x-ms-continuationtoken or body field)."""
        items: list[Any] = []
        token: str | None = None
        for _ in range(max_pages):
            p = {"api-version": API_VERSION, **(params or {})}
            if token:
                p["continuationToken"] = token
            resp = await self.http.request("GET", f"{self.org_url(project, vsrm)}/{path.lstrip('/')}", params=p)
            body = resp.json() if resp.content else {}
            items.extend(body.get("value", []) if isinstance(body, dict) else body)
            token = resp.headers.get("x-ms-continuationtoken") or (body.get("continuationToken") if isinstance(body, dict) else None)
            if not token:
                break
        return items

    async def aclose(self) -> None:
        await self.http.aclose()

    # ------------------------------------------------------- convenience lists
    async def projects(self) -> list[dict[str, Any]]:
        return await self.paged(None, "_apis/projects", {"$top": 100})

    async def repositories(self, project: str) -> list[dict[str, Any]]:
        return await self.paged(project, "_apis/git/repositories")
