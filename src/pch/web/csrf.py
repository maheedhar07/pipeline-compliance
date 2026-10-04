"""CSRF protection for the one write path of the app (the Settings feature switches).

Three independent checks must all pass (``check_write_request`` / ``verify_token``):

1. a synchronizer token: HMAC-SHA256 (server key) over ``[principal id, action, expiry]``, put in a hidden form field. It is bound to the signed-in
   principal and to one action (``set:<key>`` / ``reset:<key>``), expires after ``TOKEN_TTL_SECONDS`` and is compared in constant time;
2. ``Origin`` (``Referer`` as the fallback) must be present and name the host the request was sent to;
3. ``Sec-Fetch-Site`` must not say the request came from another site.

The key is ``SETTINGS_SIGNING_KEY`` (via the secret provider). Unset: dev/test generate a random per-process key; prod has NO key and writes are
disabled (the Settings page is read-only). A key shorter than ``MIN_KEY_CHARS`` counts as unset.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from pch.settings import Settings

log = logging.getLogger("pch.web.csrf")
TOKEN_TTL_SECONDS = 30 * 60
MIN_KEY_CHARS = 32
KEY_NAME = "SETTINGS_SIGNING_KEY"


@dataclass(frozen=True)
class SigningKey:
    """``key`` is None when writes are disabled; ``reason`` then says why (shown on the page, never a value)."""

    key: bytes | None
    reason: str = ""
    generated: bool = False  # random per-process key (dev/test)


def resolve_signing_key(s: Settings) -> SigningKey:
    """Key from the configured secret provider (registered for log redaction by the provider). Any provider problem fails closed."""
    from pch.providers import ProviderError, get_secret_provider

    value: str | None = None
    problem = ""
    try:
        value = get_secret_provider(s).get(KEY_NAME)
    except ProviderError as exc:
        problem = f"the secret provider could not be read ({type(exc).__name__})"
    except Exception as exc:  # noqa: BLE001 - never let a backend error (or its message) escape; writes just stay disabled
        problem = f"the secret provider could not be read ({type(exc).__name__})"
    if problem:
        log.warning("%s: %s", KEY_NAME, problem)
    elif value and len(value) < MIN_KEY_CHARS:
        problem = f"{KEY_NAME} is shorter than {MIN_KEY_CHARS} characters"
        log.warning(problem)
    elif value:
        return SigningKey(value.encode())
    if s.is_prod:
        return SigningKey(None, problem or f"{KEY_NAME} is not set")
    return SigningKey(secrets.token_bytes(32), generated=True)  # dev/test: usable, but forms do not survive a restart


def _mac(key: bytes, principal_id: str, action: str, expiry: int) -> str:
    msg = json.dumps([principal_id, action, expiry], separators=(",", ":")).encode()  # unambiguous framing, whatever the id contains
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def make_token(key: bytes, principal_id: str, action: str, now: float | None = None) -> str:
    expiry = int((time.time() if now is None else now) + TOKEN_TTL_SECONDS)
    return f"{expiry}.{_mac(key, principal_id, action, expiry)}"


def verify_token(key: bytes, principal_id: str, action: str, token: str | None, now: float | None = None) -> bool:
    if not token or len(token) > 200 or "." not in token:
        return False
    exp_text, _, mac = token.partition(".")
    if not exp_text.isascii() or not exp_text.isdigit() or len(exp_text) > 12:
        return False
    expiry = int(exp_text)
    if expiry < (time.time() if now is None else now):
        return False
    return hmac.compare_digest(mac.encode(), _mac(key, principal_id, action, expiry).encode())


def _host_of(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    return parts.netloc.lower() if parts.scheme in ("http", "https") and "@" not in parts.netloc else ""


def same_origin_problem(headers: Mapping[str, str]) -> str | None:
    """Why this request is not provably same-origin (None when it is). ``headers`` has lower-case names."""
    site = headers.get("sec-fetch-site", "").strip().lower()
    if site and site not in ("same-origin", "none"):
        return "cross-site request (Sec-Fetch-Site)"
    host = headers.get("host", "").strip().lower()
    source = headers["origin"] if "origin" in headers else headers.get("referer", "")  # an Origin header (even "null") is never replaced by Referer
    if not host or not source:
        return "missing Origin/Referer"
    if not (got := _host_of(source)) or got != host:
        return "Origin/Referer does not match the host"
    return None
