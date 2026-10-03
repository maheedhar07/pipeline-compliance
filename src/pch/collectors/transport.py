"""httpx transports: read-only guard, raw-response recorder (with redaction) and cache replay."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import httpx

from pch.collectors.redact import redact_json

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
    """Caches every response (redacted) under cache_dir/<host>/<hash>.json for `--from-cache`."""

    def __init__(self, inner: httpx.AsyncBaseTransport, cache_dir: Path):
        self.inner = inner
        self.cache_dir = cache_dir

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.handle_async_request(request)
        content = b"".join([c async for c in response.stream])  # type: ignore[union-attr]
        await response.stream.aclose()  # type: ignore[union-attr]
        self._write(request, response, content)
        return httpx.Response(
            status_code=response.status_code,
            headers=[(k, v) for k, v in response.headers.raw if k.lower() not in (b"content-encoding", b"content-length", b"transfer-encoding")],
            content=content,
            request=request,
        )

    def _write(self, request: httpx.Request, response: httpx.Response, content: bytes) -> None:
        body: Any
        try:
            body = redact_json(json.loads(content)) if content else None
            kind = "json"
        except ValueError:
            body = content.decode("utf-8", "replace")[:200000]
            kind = "text"
        d = self.cache_dir / request.url.host
        d.mkdir(parents=True, exist_ok=True)
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
        (d / f"{request_key(request)}.json").write_text(json.dumps(rec))

    async def aclose(self) -> None:
        await self.inner.aclose()


class CacheReplayTransport(httpx.AsyncBaseTransport):
    """Serves responses previously recorded by RecordingTransport (pch scan --from-cache)."""

    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        f = self.cache_dir / request.url.host / f"{request_key(request)}.json"
        if not f.exists():
            return httpx.Response(404, json={"message": "not in cache"}, request=request)
        rec = json.loads(f.read_text())
        headers = dict(rec.get("headers") or {})
        if rec["kind"] == "json":
            return httpx.Response(rec["status"], json=rec["body"], headers=headers, request=request)
        return httpx.Response(rec["status"], text=rec["body"] or "", headers=headers, request=request)
