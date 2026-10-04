"""Authentication/authorisation seam for the dashboard (fails closed).

An ``Authenticator`` turns request headers into a ``Principal`` (or raises ``AuthError``); ``authorize`` decides
whether that principal may use the app. ``AuthMiddleware`` (pure ASGI) applies both to every request except the
explicit public paths and stores the principal on ``request.state.principal``.

Modes (``AUTH_MODE``): ``none`` (local dev; synthetic principal) and ``easyauth`` (App Service Authentication with
Entra ID). To add a mode, implement ``Authenticator`` and register it in ``AUTHENTICATORS``. In-app OIDC is
deliberately not implemented: the platform does the sign-in.

Easy Auth facts this module assumes (# VERIFY: against the App Service docs "Work with user identities in Azure App
Service authentication" when deploying):
  * the platform injects ``X-MS-CLIENT-PRINCIPAL`` (base64 JSON: auth_typ, name_typ, role_typ, claims[{typ,val}]) plus
    ``X-MS-CLIENT-PRINCIPAL-ID`` / ``-NAME``, and strips/overwrites client-supplied ``X-MS-*`` headers *only when
    Authentication is enabled* (hence the WEBSITE_AUTH_ENABLED start-up guard in ``guard.py``);
  * Entra app roles arrive as claims of type ``roles`` (or the long ``.../identity/claims/role`` URI, or whatever
    ``role_typ`` says).
Roles are read from the signed claims only; the ``-ID``/``-NAME`` headers are used solely as a fallback for display/id.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from pch.settings import Settings

MAX_PRINCIPAL_HEADER_BYTES = 16 * 1024
ROLE_CLAIM_TYPES = frozenset({"roles", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"})
ID_CLAIM_TYPES = ("http://schemas.microsoft.com/identity/claims/objectidentifier", "oid", "sub",
                  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")
LOCAL_PRINCIPAL_ID = "local-dev"

# Reachable without a principal. Everything else (pages, JSON API, CSV, openapi/docs) requires authentication.
# The health endpoints are data-free (status [+ version] / generic reason code only).
HEALTH_PATHS = frozenset({"/api/v1/health", "/health/live", "/health/ready"})
PUBLIC_EXACT = HEALTH_PATHS
PUBLIC_PREFIXES = ("/static/",)


def is_public_path(path: str) -> bool:
    return path in PUBLIC_EXACT or path.startswith(PUBLIC_PREFIXES)


@dataclass(frozen=True)
class Principal:
    id: str
    name: str
    roles: tuple[str, ...]
    auth_type: str


class AuthError(Exception):
    """``status`` is 401 (not authenticated / unusable credentials) or 403 (authenticated but not allowed).
    ``reason`` is for logs only and is never sent to the client."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class Authenticator(Protocol):
    mode: str

    def authenticate(self, headers: Mapping[str, str]) -> Principal: ...
    def authorize(self, principal: Principal) -> None: ...
    def is_admin(self, principal: Principal) -> bool: ...  # may change the Settings feature switches (the only write path); fail closed


def _decode_principal(raw: str) -> dict[str, Any]:
    if len(raw) > MAX_PRINCIPAL_HEADER_BYTES:
        raise AuthError(401, "principal header too large")
    try:
        data = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True))
    except (binascii.Error, ValueError, UnicodeDecodeError, RecursionError):
        raise AuthError(401, "principal header is not valid base64 JSON") from None
    if not isinstance(data, dict):
        raise AuthError(401, "principal payload is not an object")
    return data


def parse_client_principal(raw: str, *, fallback_id: str = "", fallback_name: str = "") -> Principal:
    data = _decode_principal(raw)
    claims_raw = data.get("claims")
    if not isinstance(claims_raw, list):
        raise AuthError(401, "principal has no claims list")
    claims: list[tuple[str, str]] = []
    for c in claims_raw:
        if not isinstance(c, dict):
            raise AuthError(401, "malformed claim")
        typ, val = c.get("typ"), c.get("val")
        if isinstance(typ, str) and isinstance(val, str):
            claims.append((typ, val))
    role_typ = data.get("role_typ") if isinstance(data.get("role_typ"), str) else None
    name_typ = data.get("name_typ") if isinstance(data.get("name_typ"), str) else None
    auth_typ = data.get("auth_typ") if isinstance(data.get("auth_typ"), str) else ""

    role_types = set(ROLE_CLAIM_TYPES) | ({role_typ} if role_typ else set())
    roles = tuple(dict.fromkeys(v for t, v in claims if t in role_types and v))

    def first(types: tuple[str, ...]) -> str:
        for want in types:
            for t, v in claims:
                if t == want and v:
                    return v
        return ""

    pid = first(ID_CLAIM_TYPES) or fallback_id.strip()
    if not pid:
        raise AuthError(401, "principal has no identity")
    name = first((name_typ,) if name_typ else ()) or first(("name", "preferred_username", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")) or fallback_name.strip()
    return Principal(id=pid, name=name, roles=roles, auth_type=auth_typ or "unknown")


class NoneAuthenticator:
    """Local development only (guarded: loopback bind, never prod)."""

    mode = "none"

    def authenticate(self, headers: Mapping[str, str]) -> Principal:
        return Principal(id=LOCAL_PRINCIPAL_ID, name="Local developer", roles=(), auth_type="none")

    def authorize(self, principal: Principal) -> None:
        return None

    def is_admin(self, principal: Principal) -> bool:
        return principal.id == LOCAL_PRINCIPAL_ID and principal.auth_type == "none"  # the local developer (dev, loopback only)


class EasyAuthAuthenticator:
    mode = "easyauth"

    def __init__(self, allowed_roles: list[str], allow_any_authenticated: bool, admin_roles: list[str] | None = None):
        self.allowed_roles = frozenset(allowed_roles)
        self.allow_any_authenticated = allow_any_authenticated
        self.admin_roles = frozenset(admin_roles or [])

    def authenticate(self, headers: Mapping[str, str]) -> Principal:
        raw = headers.get("x-ms-client-principal")
        if not raw:
            raise AuthError(401, "no X-MS-CLIENT-PRINCIPAL header")
        return parse_client_principal(
            raw, fallback_id=headers.get("x-ms-client-principal-id", ""), fallback_name=headers.get("x-ms-client-principal-name", ""))

    def is_admin(self, principal: Principal) -> bool:
        """Only a signed role claim counts. No AUTH_ADMIN_ROLES configured: nobody is an admin."""
        return bool(self.admin_roles.intersection(principal.roles))

    def authorize(self, principal: Principal) -> None:
        if self.allowed_roles:
            if not (self.allowed_roles | self.admin_roles).intersection(principal.roles):  # an admin role also grants read access
                raise AuthError(403, "principal lacks an allowed role")
            return
        if not self.allow_any_authenticated:  # defensive: guard.py already refuses to start like this
            raise AuthError(403, "no role allowlist configured")


AUTHENTICATORS: dict[str, Callable[[Settings], Authenticator]] = {
    "none": lambda s: NoneAuthenticator(),
    "easyauth": lambda s: EasyAuthAuthenticator(s.allowed_roles, s.auth_allow_any_authenticated, s.admin_roles),
}


def build_authenticator(s: Settings) -> Authenticator:
    try:
        return AUTHENTICATORS[s.auth_mode](s)
    except KeyError:
        raise AuthError(401, f"unknown AUTH_MODE {s.auth_mode!r}") from None


ASGIApp = Callable[[dict, Callable[[], Awaitable[dict]], Callable[[dict], Awaitable[None]]], Awaitable[None]]


class AuthMiddleware:
    """Pure ASGI. ``deny(scope, send, status)`` renders the 401/403 response (so this module stays template-free)."""

    def __init__(self, app: Any, authenticator: Authenticator, deny: Callable[..., Awaitable[None]], log: Callable[[str], None] | None = None):
        self.app = app
        self.authenticator = authenticator
        self.deny = deny
        self.log = log or (lambda m: None)

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":  # no websocket routes exist: fail closed
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        if is_public_path(scope.get("path", "")):
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        try:
            principal = self.authenticator.authenticate(headers)
            self.authenticator.authorize(principal)
        except AuthError as exc:
            self.log(f"auth denied {exc.status}: {exc.reason}")
            await self.deny(scope, send, exc.status)
            return
        except Exception:  # noqa: BLE001 - any parser bug must deny, never 500 or allow
            self.log("auth denied 401: unexpected error while authenticating")
            await self.deny(scope, send, 401)
            return
        scope.setdefault("state", {})["principal"] = principal
        await self.app(scope, receive, send)
