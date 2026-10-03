"""Shared async HTTP client: retry/backoff (tenacity), Retry-After, 429 handling, concurrency cap."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from pch.collectors.transport import ReadOnlyTransport


class HttpError(Exception):
    def __init__(self, status: int, url: str, body: str = ""):
        super().__init__(f"HTTP {status} for {url}")
        self.status = status
        self.url = url
        self.body = body

    @property
    def not_found(self) -> bool:
        return self.status == 404


class RetryableError(Exception):
    def __init__(self, status: int, url: str, retry_after: float | None = None):
        super().__init__(f"retryable HTTP {status} for {url}")
        self.status = status
        self.url = url
        self.retry_after = retry_after


def _parse_retry_after(value: str | None) -> float | None:
    try:
        return max(0.0, float(value)) if value is not None else None
    except ValueError:
        return None


class SourceClient:
    """Thin wrapper over httpx.AsyncClient. All traffic goes through ReadOnlyTransport."""

    def __init__(
        self,
        base_url: str = "",
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        auth: httpx.Auth | tuple[str, str] | None = None,
        headers: dict[str, str] | None = None,
        concurrency: int = 8,
        timeout: float = 30.0,
        max_attempts: int = 4,
        backoff_base: float = 0.5,
        backoff_max: float = 20.0,
    ):
        inner = transport or httpx.AsyncHTTPTransport(retries=1)
        guarded = inner if isinstance(inner, ReadOnlyTransport) else ReadOnlyTransport(inner)
        self.client = httpx.AsyncClient(
            base_url=base_url, transport=guarded, auth=auth, headers=headers, timeout=timeout, follow_redirects=True
        )
        self.sem = asyncio.Semaphore(concurrency)
        self.max_attempts = max_attempts
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max

    def _wait(self, rs: RetryCallState) -> float:
        exc = rs.outcome.exception() if rs.outcome else None
        if isinstance(exc, RetryableError) and exc.retry_after is not None:
            return min(exc.retry_after, 60.0)
        return wait_exponential(multiplier=self.backoff_base, max=self.backoff_max)(rs) if self.backoff_base else 0.0

    async def request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self.max_attempts),
            wait=self._wait,
            retry=retry_if_exception_type((RetryableError, httpx.TransportError)),
            reraise=True,
        ):
            with attempt:
                async with self.sem:
                    resp = await self.client.request(method, url, **kw)
                if resp.status_code in (429, 502, 503, 504) or resp.status_code == 408:
                    raise RetryableError(resp.status_code, str(resp.url), _parse_retry_after(resp.headers.get("Retry-After")))
                if resp.status_code >= 400:
                    raise HttpError(resp.status_code, str(resp.url), resp.text[:500])
                return resp
        raise RuntimeError("unreachable")  # pragma: no cover

    async def get_json(self, url: str, params: dict[str, Any] | None = None) -> Any:
        r = await self.request("GET", url, params=params)
        return r.json() if r.content else None

    async def get_text(self, url: str, params: dict[str, Any] | None = None) -> str:
        return (await self.request("GET", url, params=params)).text

    async def aclose(self) -> None:
        await self.client.aclose()
