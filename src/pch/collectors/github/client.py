"""GitHub REST client (read-only): PAT or GitHub App auth, Link-header paging, rate-limit handling.

Everything goes through ``SourceClient`` (so ``ReadOnlyTransport``, the response-size cap and the raw-cache recorder apply). The only
POST this client can ever send is the GitHub App installation token exchange, allowed on the transport for exactly
``<GITHUB_API_URL>/app/installations/<GITHUB_APP_INSTALLATION_ID>/access_tokens`` (it creates a short-lived token, no GitHub
data is changed). Tokens live in memory only and are registered for log redaction.

Required permissions (fine-grained PAT or GitHub App, READ-ONLY): Metadata, Contents and Administration (the last one only for
classic branch protection: without it protection that comes from classic rules is UNKNOWN, never FAIL). For GitHub Actions (G3): Actions, Environments and
Deployments (read). A token with write access is refused by policy in docs, not by code: GitHub
offers no way to ask a token for its scopes with fine-grained PATs, so the mitigation is to create it read-only.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from pch.collectors.http import HttpError, SourceClient
from pch.logging_setup import register_secret
from pch.providers.errors import ProviderUnavailable

API_VERSION = "2022-11-28"
ACCEPT_JSON = "application/vnd.github+json"
ACCEPT_RAW = "application/vnd.github.raw+json"
TOKEN_REFRESH_MARGIN_S = 300  # renew an installation token when it expires within 5 minutes
APP_EXTRA_HINT = "GITHUB_AUTH=app requires the 'github-app' extra: pip install 'pipeline-compliance[github-app]'"
_LINK = re.compile(r"<([^>]*)>([^<]*)")


RATE_WAIT_HINT = 120.0


class RateLimited(Exception):
    """GitHub's (primary or secondary) rate limit is exhausted for longer than ``max_rate_wait``: fail the item, not the scan."""

    def __init__(self, wait_s: float, secondary: bool = False):
        kind = "secondary rate limit" if secondary else "rate limit"
        super().__init__(f"GitHub {kind} exhausted; retry possible in about {int(wait_s)}s (more than the {int(RATE_WAIT_HINT)}s the scan will wait)")
        self.wait_s = wait_s
        self.secondary = secondary


class UnsafePagination(Exception):
    """A ``Link: rel=next`` URL pointed away from the configured GitHub API host (SSRF guard)."""


def parse_link_next(header: str | None) -> str | None:
    for url, params in _LINK.findall(header or ""):
        if re.search(r'rel\s*=\s*"?next"?', params):
            return url
    return None


def _num(v: str | None) -> int | None:
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def normalize_pem(key: str) -> str:
    """Env vars often carry the PEM on one line with literal ``\\n``."""
    key = key.strip()
    return key.replace("\\n", "\n") if "\\n" in key and "\n" not in key else key


class GitHubAppAuth:
    """Signs the App JWT (RS256, 9 minutes) with PyJWT (optional extra ``github-app``)."""

    def __init__(self, app_id: str, installation_id: str, private_key: str, *, clock: Callable[[], float] = time.time):
        if not (app_id.isdigit() and installation_id.isdigit()):
            raise ValueError("GITHUB_APP_ID and GITHUB_APP_INSTALLATION_ID must be numeric")
        self.app_id, self.installation_id = app_id, installation_id
        self._key = normalize_pem(private_key)
        self._clock = clock
        register_secret(self._key)

    @staticmethod
    def _jwt_module() -> Any:
        try:
            import jwt
        except ImportError:
            raise ProviderUnavailable(APP_EXTRA_HINT) from None
        if not getattr(jwt.algorithms, "has_crypto", False):
            raise ProviderUnavailable(APP_EXTRA_HINT)
        return jwt

    def jwt(self) -> str:
        jwt = self._jwt_module()
        now = int(self._clock())
        token: str = jwt.encode({"iat": now - 60, "exp": now + 540, "iss": self.app_id}, self._key, algorithm="RS256")
        register_secret(token)
        return token


class GitHubClient:
    """Read-only GitHub API client. ``api_url`` is ``https://api.github.com`` or a GHES ``https://host/api/v3``."""

    def __init__(
        self,
        api_url: str = "https://api.github.com",
        *,
        token: str = "",
        app: GitHubAppAuth | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        concurrency: int = 8,
        timeout: float = 30.0,
        backoff_base: float = 0.5,
        max_attempts: int = 4,
        max_rate_wait: float = 120.0,
        max_response_bytes: int | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.api_url = api_url.rstrip("/")
        parts = urlsplit(self.api_url)
        self._origin = (parts.scheme, parts.netloc.lower())
        self._base_path = parts.path.rstrip("/")
        self._static_token = token
        self._app = app
        if token:
            register_secret(token)
        allowed = frozenset({self.token_exchange_url(app.installation_id)}) if app else frozenset()
        self.http = SourceClient(
            transport=transport, concurrency=concurrency, timeout=timeout, backoff_base=backoff_base, max_attempts=max_attempts,
            max_response_bytes=max_response_bytes, allowed_posts=allowed,
            # 429 and 403 are rate limits GitHub reports with Retry-After / X-RateLimit-*; handled here (bounded, per item), not in SourceClient
            retry_statuses=frozenset({408, 502, 503, 504}),
        )
        self.max_rate_wait = max_rate_wait
        self._clock, self._sleep = clock, sleep
        self._app_token: str | None = None
        self._app_expires = 0.0
        self._token_lock = asyncio.Lock()
        self._remaining: int | None = None
        self._reset_at: float | None = None

    def token_exchange_url(self, installation_id: str) -> str:
        return f"{self.api_url}/app/installations/{installation_id}/access_tokens"

    @property
    def configured(self) -> bool:
        return bool(self._static_token or self._app)

    @property
    def is_github_com(self) -> bool:
        return self._origin[1] == "api.github.com"

    async def aclose(self) -> None:
        await self.http.aclose()

    # ------------------------------------------------------------------ auth
    async def _authorization(self) -> dict[str, str]:
        if self._app is None:
            return {"Authorization": f"Bearer {self._static_token}"} if self._static_token else {}
        async with self._token_lock:
            if self._app_token is None or self._app_expires - self._clock() < TOKEN_REFRESH_MARGIN_S:
                r = await self.http.request(
                    "POST", self.token_exchange_url(self._app.installation_id),
                    headers={"Authorization": f"Bearer {self._app.jwt()}", "Accept": ACCEPT_JSON, "X-GitHub-Api-Version": API_VERSION},
                )
                body = r.json()
                token = body.get("token") if isinstance(body, dict) else None
                if not token:
                    raise RuntimeError("GitHub App installation token response contained no token")
                self._app_token = str(token)
                register_secret(self._app_token)
                try:
                    self._app_expires = datetime.fromisoformat(str(body.get("expires_at")).replace("Z", "+00:00")).timestamp()
                except ValueError:
                    self._app_expires = self._clock() + 3000  # installation tokens last 1 hour
        return {"Authorization": f"Bearer {self._app_token}"}

    # ------------------------------------------------------------------ rate limits
    def _note(self, headers: httpx.Headers | dict[str, str]) -> None:
        rem, reset = _num(headers.get("x-ratelimit-remaining")), _num(headers.get("x-ratelimit-reset"))
        if rem is not None:
            self._remaining = rem
        if reset is not None:
            self._reset_at = float(reset)

    async def _gate(self) -> None:
        """Do not send a request into a known-exhausted quota: wait for the reset when it is soon, else fail the item."""
        if self._remaining == 0 and self._reset_at is not None:
            wait = self._reset_at - self._clock() + 1
            if wait > 0:
                if wait > self.max_rate_wait:
                    raise RateLimited(wait)
                await self._sleep(wait)
            self._remaining = None

    def _rate_wait(self, e: HttpError) -> tuple[float, bool] | None:
        """(seconds to wait, secondary?) when the error is a rate limit, else None (a plain 403 is a missing permission)."""
        if e.status not in (403, 429):
            return None
        h = e.headers
        if (ra := _num(h.get("retry-after"))) is not None:
            return float(ra), True
        if _num(h.get("x-ratelimit-remaining")) == 0:
            reset = _num(h.get("x-ratelimit-reset"))
            return (max(0.0, reset - self._clock()) + 1 if reset is not None else 60.0), False
        if "secondary rate limit" in e.body.lower() or "rate limit exceeded" in e.body.lower():
            return 60.0, "secondary" in e.body.lower()
        return None

    # ------------------------------------------------------------------ requests
    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            self._check_same_origin(path)
            return path
        return f"{self.api_url}/{path.lstrip('/')}"

    def _check_same_origin(self, url: str) -> None:
        p = urlsplit(url)
        if (p.scheme, p.netloc.lower()) != self._origin or not (p.path == self._base_path or p.path.startswith(self._base_path + "/")):
            raise UnsafePagination(f"refusing to follow a pagination link to another host ({p.netloc or 'unknown'})")

    async def request(self, path: str, params: dict[str, Any] | None = None, *, accept: str = ACCEPT_JSON) -> httpx.Response:
        url = self._url(path)
        for attempt in range(3):
            await self._gate()
            headers = {"Accept": accept, "X-GitHub-Api-Version": API_VERSION, **(await self._authorization())}
            try:
                resp = await self.http.request("GET", url, params=params, headers=headers)
            except HttpError as e:
                self._note(e.headers)
                rl = self._rate_wait(e)
                if rl is None:
                    raise
                wait, secondary = rl
                if wait > self.max_rate_wait or attempt == 2:
                    raise RateLimited(wait, secondary) from None
                await self._sleep(wait)
                continue
            self._note(resp.headers)
            return resp
        raise RuntimeError("unreachable")  # pragma: no cover

    async def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        r = await self.request(path, params)
        return r.json() if r.content else None

    async def get_raw(self, path: str, params: dict[str, Any] | None = None) -> str:
        """File contents via the raw media type (no base64)."""
        return (await self.request(path, params, accept=ACCEPT_RAW)).text

    async def paged(self, path: str, params: dict[str, Any] | None = None, *, key: str | None = None, max_pages: int = 200) -> list[Any]:
        """All items of a list endpoint. Follows ``Link: rel=next`` only while it stays on the configured API host."""
        items: list[Any] = []
        url: str | None = path
        p: dict[str, Any] | None = {"per_page": 100, **(params or {})}
        for _ in range(max_pages):
            if url is None:
                break
            resp = await self.request(url, p)
            body = resp.json() if resp.content else []
            items.extend((body.get(key, []) if key else []) if isinstance(body, dict) else body)
            url, p = parse_link_next(resp.headers.get("link")), None  # the next URL already carries its query
        return items

    async def rate_limit(self) -> dict[str, Any]:
        """``GET /rate_limit`` (not counted against the quota): the ``core`` bucket as {limit, remaining, reset}."""
        body = await self.get_json("/rate_limit")
        return dict(((body or {}).get("resources") or {}).get("core") or {})
