"""Pure-ASGI hardening layers: security headers + last-resort 500, GET/HEAD-only (plus the feature-switch POSTs), trusted hosts, minimal error pages.

Order (outermost first): SecurityMiddleware -> TrustedHostMiddleware -> MethodGuardMiddleware -> AuthMiddleware -> app.
SecurityMiddleware is outermost so *every* response (401/403/404/405/500, static, rejected hosts) carries the headers.
"""

from __future__ import annotations

import html
import json
import logging
import re
import time
import uuid
from collections.abc import Callable
from typing import Any

from pch.logging_setup import request_id_var
from pch.web.auth import HEALTH_PATHS

log = logging.getLogger("pch.web.security")
access_log = logging.getLogger("pch.web.access")
# An inbound X-Request-ID is adopted only if it looks like an id (no spaces/control chars/log-injection payloads).
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
STATIC_HEADERS: list[tuple[bytes, bytes]] = [
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"same-origin"),
    (b"x-frame-options", b"DENY"),
    (b"permissions-policy", b"accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
]
HSTS = (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
IMMUTABLE = b"public, max-age=31536000, immutable"
VERSIONED = re.compile(r"-\d+\.\d+\.\d+[.\-]")
ALLOWED_METHODS = ("GET", "HEAD")
# The ONLY write surface of the app (ADR-19): the feature-switch forms on the Settings page, which write to the app's own database.
# Every other non-GET/HEAD request is refused here, before authentication. The route itself still requires an admin role, a CSRF token and same-origin.
WRITE_PATH = re.compile(r"^/settings/features/[a-z][a-z0-9_]{0,39}(?:/reset)?$")
GENERIC_500 = ("Something went wrong", "An internal error occurred. Quote the reference below when reporting it.")


def principal_hash(principal: Any) -> str:
    """Stable pseudonym for log lines: never the name / e-mail."""
    import hashlib

    pid = getattr(principal, "id", None)
    return hashlib.sha256(str(pid).encode()).hexdigest()[:12] if pid else "-"


def incoming_request_id(scope: dict) -> str:
    for k, v in scope.get("headers", []):
        if k == b"x-request-id":
            cand = v.decode("latin-1")
            if REQUEST_ID_RE.fullmatch(cand):
                return cand
            break
    return uuid.uuid4().hex


def request_id_of(scope: dict) -> str:
    return str(scope.get("state", {}).get("request_id", "-"))


def _is_api(path: str) -> bool:
    return path.startswith("/api/") or path == "/openapi.json"


def error_page(title: str, message: str, request_id: str) -> bytes:
    """Self-contained minimal page (no data, no nav, no inline script/style)."""
    t, m, r = html.escape(title), html.escape(message), html.escape(request_id)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{t} · Pipeline Compliance Hub</title>"
        '<link rel="stylesheet" href="/static/vendor/tailwind.css"></head>'
        '<body class="bg-slate-50 text-sm text-slate-900"><main class="mx-auto mt-16 max-w-xl rounded-lg border border-slate-200 bg-white p-6 text-center">'
        f'<h1 class="text-lg font-semibold">{t}</h1><p class="mt-2 text-slate-600">{m}</p>'
        f'<p class="mt-3 text-xs text-slate-500">Reference: {r}</p></main></body></html>'
    ).encode()


async def send_error(scope: dict, send: Any, status: int, title: str, message: str, extra: list[tuple[bytes, bytes]] | None = None) -> None:
    rid = request_id_of(scope)
    if _is_api(scope.get("path", "")):
        body, ctype = json.dumps({"detail": message, "request_id": rid}).encode(), b"application/json"
    else:
        body, ctype = error_page(title, message, rid), b"text/html; charset=utf-8"
    headers = [(b"content-type", ctype), (b"content-length", str(len(body)).encode()), *(extra or [])]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body if scope.get("method") != "HEAD" else b""})


async def deny_auth(scope: dict, send: Any, status: int) -> None:
    if status == 403:
        await send_error(scope, send, 403, "Access denied", "Your account is signed in but is not authorised to use this application.")
    else:
        await send_error(scope, send, 401, "Sign-in required", "Authentication is required to use this application.")


class SecurityMiddleware:
    def __init__(self, app: Any, *, hsts: bool, docs_csp: str | None = None, docs_path: str = "/api/docs"):
        self.app = app
        self.hsts = hsts
        self.docs_csp = docs_csp
        self.docs_path = docs_path

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        scope.setdefault("state", {})["request_id"] = incoming_request_id(scope)
        path = scope.get("path", "")
        qs = scope.get("query_string", b"").decode("latin-1")
        started = False
        status = 500  # what the client sees if nothing was sent (the last-resort handler below answers 500)
        t0 = time.perf_counter()
        rid_token = request_id_var.set(scope["state"]["request_id"])

        def decorate(headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
            drop = {b"server", b"content-security-policy", b"cache-control", b"x-request-id"}
            out = [(k, v) for k, v in headers if k.lower() not in drop]
            csp = self.docs_csp if (self.docs_csp and path == self.docs_path) else CSP
            out.append((b"content-security-policy", csp.encode()))
            out.extend(STATIC_HEADERS)
            if self.hsts:
                out.append(HSTS)
            if path.startswith("/static/"):
                versioned = "v=" in qs or bool(VERSIONED.search(path))
                out.append((b"cache-control", IMMUTABLE if versioned else b"no-cache"))
            else:  # authenticated/compliance data (HTML, JSON, CSV) and every error page: never cached
                out.append((b"cache-control", b"no-store"))
            out.append((b"x-request-id", scope["state"]["request_id"].encode()))
            return out

        async def wrapped_send(message: dict) -> None:
            nonlocal started, status
            if message["type"] == "http.response.start":
                started = True
                status = int(message["status"])
                message = {**message, "headers": decorate(list(message.get("headers", [])))}
            await send(message)

        try:
            await self.app(scope, receive, wrapped_send)
        except Exception:  # noqa: BLE001 - last resort: log with correlation id, never leak the exception to the client
            if started:  # Starlette's ServerErrorMiddleware already sent the generic 500 (app handler) and re-raised
                return
            log.exception("unhandled error (request_id=%s)", scope["state"]["request_id"])
            await send_error(scope, wrapped_send, 500, *GENERIC_500)
        finally:
            self._log_request(scope, path, status, (time.perf_counter() - t0) * 1000)
            request_id_var.reset(rid_token)

    @staticmethod
    def _log_request(scope: dict, path: str, status: int, ms: float) -> None:
        """One structured line per request: path WITHOUT the query string, hashed principal (never name/e-mail)."""
        method = scope.get("method", "-")
        method = method if method.isalpha() and len(method) <= 16 else "?"
        path = _CTRL.sub(lambda m: f"\\x{ord(m.group()):02x}", path)[:300]  # no forged log lines via %0A in the path
        fields = {"method": method, "path": path, "status": status, "duration_ms": round(ms, 1),
                  "principal": principal_hash(scope.get("state", {}).get("principal"))}
        quiet = path in HEALTH_PATHS or path.startswith("/static/")  # probes and assets would drown the log
        access_log.log(logging.DEBUG if quiet else logging.INFO, "%s %s %s %.1fms", method, path, status, ms, extra={"pch_fields": fields})


class MethodGuardMiddleware:
    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            method = scope.get("method")
            if method == "POST" and WRITE_PATH.fullmatch(scope.get("path", "")):
                await self.app(scope, receive, send)  # the feature-switch forms; authorised and CSRF-checked by the route
                return
            if method not in ALLOWED_METHODS:
                await send_error(scope, send, 405, "Method not allowed", "This application is read-only except for the feature switches on the Settings page.",
                                 [(b"allow", b"GET, HEAD")])
                return
        await self.app(scope, receive, send)


def hostname_of(raw: str) -> str:
    """Host header -> lowercase hostname without port (IPv6 literals keep their brackets)."""
    raw = raw.strip().lower()
    if raw.startswith("["):
        end = raw.find("]")
        return raw[: end + 1] if end != -1 else raw
    return raw.split(":", 1)[0]


def host_matcher(patterns: list[str]) -> Callable[[str], bool]:
    pats = [p.strip().lower() for p in patterns if p.strip()]
    exact = {p for p in pats if not p.startswith("*.")}
    suffixes = tuple(p[1:] for p in pats if p.startswith("*.") and len(p) > 2)  # "*.a.net" -> ".a.net"

    def ok(host: str) -> bool:
        return bool(host) and (host in exact or (bool(suffixes) and host.endswith(suffixes)))

    return ok


class TrustedHostMiddleware:
    """Reject requests whose Host header is not allow-listed. The exact health path may be called with a loopback
    Host (container HEALTHCHECK); it returns status + version only."""

    LOOPBACK = frozenset({"localhost", "127.0.0.1", "[::1]"})

    def __init__(self, app: Any, hosts: list[str], health_paths: frozenset[str] = HEALTH_PATHS):
        self.app = app
        self.match = host_matcher(hosts)
        self.health_paths = health_paths

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        host = ""
        for k, v in scope.get("headers", []):
            if k == b"host":
                host = hostname_of(v.decode("latin-1"))
                break
        if self.match(host) or (scope.get("path") in self.health_paths and host in self.LOOPBACK):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        await send_error(scope, send, 400, "Invalid host", "The Host header is not allowed.")
