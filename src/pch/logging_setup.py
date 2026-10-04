"""Logging for the CLI and the web app: one ``configure_logging(settings)``.

* ``LOG_FORMAT=text|json`` (default text, json when APP_ENV=prod) and ``LOG_LEVEL``.
* JSON lines: ``ts`` (UTC ISO-8601), ``level``, ``logger``, ``message``, ``request_id`` (set by the security
  middleware), ``scan_id`` (set while a scan runs), ``exception`` and any structured ``pch_fields``.
* ``RedactingFilter`` sits on every root handler (console here, Application Insights in ``pch.telemetry``) and scrubs
  secret-like values from the message, its args, structured fields and exception text BEFORE anything is written or
  exported: bearer/basic credentials, ``Authorization`` headers, ``pat/token/password/secret/...`` key=value pairs,
  URLs with credentials (``scheme://user:pass@host``), well-known token formats, and every live secret value that the
  secret provider or settings resolved (``register_secret``; a process-local set that is never logged).
  Over-scrubbing is preferred to leaking.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import sys
import threading
import time
import traceback
from collections.abc import Iterator
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, quote_plus

from pydantic import SecretStr

from pch.collectors.redact import REDACTED, value_looks_secret
from pch.settings import Settings, get_settings

request_id_var: ContextVar[str | None] = ContextVar("pch_request_id", default=None)
scan_id_var: ContextVar[str | None] = ContextVar("pch_scan_id", default=None)

MIN_SECRET_LEN = 6  # shorter values would shred ordinary log text; real credentials are longer
_HANDLER_MARK = "_pch_handler"

# ----------------------------------------------------------------------------- scrubbing
_KEY = (
    r"(?:(?<![A-Za-z])pat(?![A-Za-z])|token|passw(?:or)?d|pwd|secret|api[_-]?key|access[_-]?key|account[_-]?key|"
    r"private[_-]?key|sharedaccesskey|connection[_-]?string|credential|(?<![A-Za-z])sig(?:nature)?(?![A-Za-z]))"
)
_AUTH_HEADER = re.compile(
    r"(?i)(?P<k>\b(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?)(?:(?:bearer|basic|token|negotiate|digest)\s+)?[^\s\"',;]+"
)
_BEARER = re.compile(r"(?i)\b(?P<s>bearer)\s+(?-i:(?=[A-Za-z0-9\-._~+/]*[0-9A-Z]))[A-Za-z0-9\-._~+/]{8,}=*")
_BASIC = re.compile(r"(?i)\b(?P<s>basic)\s+(?-i:(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z0-9]))[A-Za-z0-9+/]{8,}={0,2}")
_URL_CREDS = re.compile(r"(?P<s>(?<![a-zA-Z0-9+.\-])[a-zA-Z][a-zA-Z0-9+.\-]*+://)[^\s/@?#]++@")
# ReDoS: every pattern here must be linear on adversarial input (log lines can contain request paths and upstream
# text). The key word is anchored at a word start (lookbehind), located by a lookahead and consumed possessively.
_KV = re.compile(
    r"(?i)(?<![\w.\-])(?P<k>(?=[\w.\-]*" + _KEY + r")[\w.\-]++[\"']?\s*+[=:]\s*+)"
    r"(?:(?P<q>[\"'])(?P<qv>.*?)(?P=q)|(?P<v>[^\s\"'&;,)\]}]++))"
)
_KNOWN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|"
    r"sk-[A-Za-z0-9_\-]{20,}|eyJ[A-Za-z0-9_\-]{10,}+\.[A-Za-z0-9_\-]{10,}+\.[A-Za-z0-9_\-]*+)"
)
# "/" is excluded so URL paths are not mistaken for tokens (base64 tokens with "/" are still caught by key=value / exact match)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+_\-]{24,}={0,2}")

_exact_lock = threading.Lock()
_exact: set[str] = set()
_exact_sorted: tuple[str, ...] = ()


def register_secret(value: str | SecretStr | None) -> None:
    """Remember a live secret value so any log line containing it (also URL-encoded) is scrubbed. Never logged."""
    if isinstance(value, SecretStr):
        value = value.get_secret_value()
    global _exact_sorted
    if not value or len(value.strip()) < MIN_SECRET_LEN:
        return
    v = value.strip()
    with _exact_lock:
        _exact.update({v, quote(v, safe=""), quote_plus(v)})
        _exact_sorted = tuple(sorted(_exact, key=len, reverse=True))


def clear_registered_secrets() -> None:
    global _exact_sorted
    with _exact_lock:
        _exact.clear()
        _exact_sorted = ()


def registered_secret_count() -> int:
    return len(_exact_sorted)


def scrub(text: str) -> str:
    """Return ``text`` with secret-like values replaced by ``***REDACTED***`` (idempotent)."""
    if not text:
        return text
    for s in _exact_sorted:
        if s in text:
            text = text.replace(s, REDACTED)
    text = _AUTH_HEADER.sub(lambda m: m.group("k") + REDACTED, text)
    text = _URL_CREDS.sub(lambda m: m.group("s") + "***@", text)
    text = _BEARER.sub(lambda m: f"{m.group('s')} {REDACTED}", text)
    text = _BASIC.sub(lambda m: f"{m.group('s')} {REDACTED}", text)
    text = _KNOWN.sub(REDACTED, text)
    text = _KV.sub(lambda m: m.group("k") + (f"{m.group('q')}{REDACTED}{m.group('q')}" if m.group("q") else REDACTED), text)
    return _LONG_TOKEN.sub(lambda m: REDACTED if value_looks_secret(m.group()) else m.group(), text)


def _scrub_obj(v: Any) -> Any:
    if isinstance(v, str):
        return scrub(v)
    if isinstance(v, dict):
        return {k: _scrub_obj(x) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [_scrub_obj(x) for x in v]
    return v


class RedactingFilter(logging.Filter):
    """Scrubs the record in place (message + args are merged first, exception text is rendered and scrubbed).

    Attach it to every *handler* (not logger) so records propagated from any library are covered. Python 3.11 filters
    cannot return a replacement record, hence the in-place edit; scrubbing is idempotent.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 - a bad format string must not break logging
            msg = str(record.msg)
        record.msg, record.args = scrub(msg), ()
        if record.exc_info and record.exc_info[0] is not None:
            record.exc_text = "".join(traceback.format_exception(*record.exc_info))
            record.exc_info = None  # the scrubbed text replaces the live traceback for every handler
        if record.exc_text:
            record.exc_text = scrub(record.exc_text)
            record.exception_text = record.exc_text  # extra attribute, exported by the OpenTelemetry handler
        if record.stack_info:
            record.stack_info = scrub(record.stack_info)
        fields = getattr(record, "pch_fields", None)
        if isinstance(fields, dict):
            record.pch_fields = _scrub_obj(fields)
        return True


class ContextFilter(logging.Filter):
    """Adds ``request_id`` / ``scan_id`` (from contextvars) and a compact ``ctx`` string to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        rid, sid = request_id_var.get(), scan_id_var.get()
        record.request_id, record.scan_id = rid or "-", sid or "-"
        record.ctx = " ".join(p for p in (f"req={rid}" if rid else "", f"scan={sid}" if sid else "") if p) or "-"
        return True


# ----------------------------------------------------------------------------- formatters
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        d: dict[str, Any] = {"ts": ts, "level": record.levelname, "logger": record.name, "message": scrub(record.getMessage())}
        rid = getattr(record, "request_id", None) or request_id_var.get()
        sid = getattr(record, "scan_id", None) or scan_id_var.get()
        if rid and rid != "-":
            d["request_id"] = rid
        if sid and sid != "-":
            d["scan_id"] = sid
        fields = getattr(record, "pch_fields", None)
        if isinstance(fields, dict):
            for k, v in fields.items():
                d.setdefault(k, v)
        exc = record.exc_text or (self.formatException(record.exc_info) if record.exc_info else "")
        if exc:
            d["exception"] = scrub(exc)
        if record.stack_info:
            d["stack"] = scrub(record.stack_info)
        return json.dumps(d, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    converter = time.gmtime  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-7s %(name)s [%(ctx)s] %(message)s", "%Y-%m-%dT%H:%M:%SZ")

    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "ctx"):
            record.ctx = "-"
        return super().format(record)


class _StderrHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Writes to whatever ``sys.stderr`` is *now* (CliRunner / pytest swap it)."""

    def __init__(self) -> None:
        logging.Handler.__init__(self)

    @property
    def stream(self) -> Any:
        return sys.stderr

    @stream.setter
    def stream(self, value: Any) -> None:  # StreamHandler.__init__ is bypassed; keep setter for API compatibility
        pass


# ----------------------------------------------------------------------------- configuration
def effective_format(s: Settings) -> str:
    return s.log_format or ("json" if s.is_prod else "text")


def protect_handlers() -> None:
    """Make sure EVERY root handler (including ones added later by exporters) has the redaction filter."""
    for h in logging.getLogger().handlers:
        if not any(isinstance(f, RedactingFilter) for f in h.filters):
            h.addFilter(RedactingFilter())
        if not any(isinstance(f, ContextFilter) for f in h.filters):
            h.addFilter(ContextFilter())


def register_settings_secrets(s: Settings) -> None:
    """Exact-match scrubbing for the secrets that live in settings (credentials, DB password, App Insights key)."""
    for field in ("ado_pat", "sonar_token", "aikido_client_secret", "servicenow_password", "applicationinsights_connection_string"):
        register_secret(getattr(s, field, None))
    with contextlib.suppress(Exception):
        from sqlalchemy.engine import make_url

        register_secret(make_url(s.database_url).password)


def configure_logging(settings: Settings | None = None, *, stream: Any = None) -> tuple[str, str]:
    """Install the console handler (idempotent). Returns ``(format, level)``. ``stream`` is for tests."""
    s = settings or get_settings()
    fmt, level = effective_format(s), s.log_level
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, _HANDLER_MARK, False):
            root.removeHandler(h)
    handler: logging.Handler = logging.StreamHandler(stream) if stream is not None else _StderrHandler()
    setattr(handler, _HANDLER_MARK, True)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    handler.addFilter(ContextFilter())
    handler.addFilter(RedactingFilter())
    root.addHandler(handler)
    root.setLevel(level)
    # uvicorn must not install its own (unredacted, differently formatted) handlers: its loggers propagate to root.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True
        lg.setLevel(logging.NOTSET)
    if level != "DEBUG":  # client libraries log full request URLs at INFO; alembic logs on every readiness probe
        for name in ("httpx", "httpcore", "alembic", "azure.core.pipeline.policies.http_logging_policy", "azure.identity"):
            logging.getLogger(name).setLevel(logging.WARNING)
    register_settings_secrets(s)
    return fmt, level


def reset_logging() -> None:
    """Remove the handler installed by ``configure_logging`` and restore defaults (tests)."""
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, _HANDLER_MARK, False):
            root.removeHandler(h)
    root.setLevel(logging.WARNING)
    clear_registered_secrets()


@contextlib.contextmanager
def bind_scan(scan_id: str) -> Iterator[None]:
    token = scan_id_var.set(scan_id)
    try:
        yield
    finally:
        scan_id_var.reset(token)
