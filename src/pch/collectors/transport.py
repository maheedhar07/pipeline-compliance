"""httpx transports: read-only guard, raw-response recorder (with redaction) and cache replay."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import AsyncIterator
from typing import Any, cast

import httpx

from pch.collectors.redact import redact_json, redact_text
from pch.providers.artifacts import ArtifactStore

log = logging.getLogger(__name__)

# The ONLY non-GET requests that may ever leave this process.
ALLOWED_POSTS = [
    re.compile(r"/_apis/pipelines/\d+/preview$"),  # ADO: expand YAML, previewRun=true (no run is created)
    re.compile(r"/api/oauth/token$"),  # Aikido: OAuth client-credentials token exchange  # VERIFY
    re.compile(r"/api/oauth2/token$"),  # alternative Aikido token path  # VERIFY
]


class MutationBlockedError(RuntimeError):
    """Raised when something tries to send a non-read request."""


def _check_allowed(request: httpx.Request) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if request.method == "POST" and any(p.search(request.url.path) for p in ALLOWED_POSTS):
        if "/preview" in request.url.path:
            try:
                body = json.loads(request.content or b"{}")
            except ValueError:
                body = {}
            if body.get("previewRun") is not True:
                raise MutationBlockedError("preview POST must carry previewRun=true")
        return
    raise MutationBlockedError(f"read-only guard: refusing {request.method} {request.url.path}")


class ResponseTooLargeError(Exception):
    """An upstream response exceeded ``HTTP_MAX_RESPONSE_MB``. Not an httpx error, so it is never retried."""


class _CappedStream(httpx.AsyncByteStream):
    def __init__(self, inner: httpx.AsyncByteStream, limit: int, url: str):
        self.inner, self.limit, self.url, self.seen = inner, limit, url, 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self.inner:
            self.seen += len(chunk)
            if self.seen > self.limit:
                await self.inner.aclose()
                raise ResponseTooLargeError(f"response from {self.url} exceeds the {self.limit // (1024 * 1024)} MB limit")
            yield chunk

    async def aclose(self) -> None:
        await self.inner.aclose()


class SizeLimitTransport(httpx.AsyncBaseTransport):
    """Aborts responses larger than ``max_bytes``: early on Content-Length, else while the body streams.

    Wrap the innermost (network) transport so a recorder above it never buffers more than the cap. The error
    text names the host and path only (no query string).
    """

    def __init__(self, inner: httpx.AsyncBaseTransport, max_bytes: int):
        self.inner = inner
        self.max_bytes = max_bytes

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.handle_async_request(request)
        where = f"{request.url.host}{request.url.path}"
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self.max_bytes:
            await response.aclose()
            raise ResponseTooLargeError(
                f"response from {where} declares {declared} bytes, over the {self.max_bytes // (1024 * 1024)} MB limit"
            )
        response.stream = _CappedStream(cast(httpx.AsyncByteStream, response.stream), self.max_bytes, where)
        return response

    async def aclose(self) -> None:
        await self.inner.aclose()


class ReadOnlyTransport(httpx.AsyncBaseTransport):
    """Rejects any non-GET request, except the documented allowlist."""

    def __init__(self, inner: httpx.AsyncBaseTransport):
        self.inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        _check_allowed(request)
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self.inner.aclose()


def request_key(request: httpx.Request) -> str:
    h = hashlib.sha1(usedforsecurity=False)
    h.update(request.method.encode())
    h.update(str(request.url).encode())
    if request.method == "POST":
        h.update(request.content or b"")
    return h.hexdigest()[:20]


def _safe_url(url: str) -> str:
    """Strip any credentials/query secrets from the URL string kept in the cache."""
    return re.sub(r"(?i)([?&](?:access_token|token|key|password|pat)=)[^&]+", r"\1REDACTED", url)


class RecordingTransport(httpx.AsyncBaseTransport):
    """Caches every response (redacted BEFORE it reaches the store) as ``<host>/<hash>.json`` for `--from-cache`.

    The store is an ArtifactStore (local dir, Azure Blob, ...). A failing store never fails the scan: the first
    failure is logged (error type only) and caching is skipped for that response.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport, store: ArtifactStore):
        self.inner = inner
        self.store = store
        self._warned = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.handle_async_request(request)
        content = b"".join([c async for c in response.stream])  # type: ignore[union-attr]
        await response.stream.aclose()  # type: ignore[union-attr]
        await self._write(request, response, content)
        return httpx.Response(
            status_code=response.status_code,
            headers=[(k, v) for k, v in response.headers.raw if k.lower() not in (b"content-encoding", b"content-length", b"transfer-encoding")],
            content=content,
            request=request,
        )

    @staticmethod
    def build_record(request: httpx.Request, response: httpx.Response, content: bytes) -> bytes:
        """The redacted cache record. Everything persisted passes through here."""
        body: Any
        try:
            body = redact_json(json.loads(content)) if content else None
            kind = "json"
        except ValueError:
            body = redact_text(content.decode("utf-8", "replace")[:200000])
            kind = "text"
        rec = {
            "method": request.method,
            "url": _safe_url(str(request.url)),
            "status": response.status_code,
            "kind": kind,
            "headers": {
                k: v for k, v in response.headers.items() if k.lower() in ("x-ms-continuationtoken", "retry-after", "content-type")
            },
            "body": body,
        }
        return json.dumps(rec).encode()

    async def _write(self, request: httpx.Request, response: httpx.Response, content: bytes) -> None:
        record = self.build_record(request, response, content)
        try:
            await self.store.put(f"{request.url.host}/{request_key(request)}.json", record)
        except Exception as exc:  # noqa: BLE001 - the cache is best effort
            if not self._warned:
                self._warned = True
                log.warning("raw cache write failed (%s); further failures are not logged, --from-cache will be incomplete",
                            type(exc).__name__)

    async def aclose(self) -> None:
        await self.inner.aclose()


class CacheReplayTransport(httpx.AsyncBaseTransport):
    """Serves responses previously recorded by RecordingTransport (pch scan --from-cache)."""

    def __init__(self, store: ArtifactStore):
        self.store = store

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raw = await self.store.get(f"{request.url.host}/{request_key(request)}.json")
        if raw is None:
            return httpx.Response(404, json={"message": "not in cache"}, request=request)
        rec = json.loads(raw)
        headers = dict(rec.get("headers") or {})
        if rec["kind"] == "json":
            return httpx.Response(rec["status"], json=rec["body"], headers=headers, request=request)
        return httpx.Response(rec["status"], text=rec["body"] or "", headers=headers, request=request)
