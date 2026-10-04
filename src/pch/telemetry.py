"""Optional Application Insights export (extra ``azure-monitor``), enabled ONLY by APPLICATIONINSIGHTS_CONNECTION_STRING.

What is exported and how it is kept clean:
  * logs: through the same ``RedactingFilter`` as the console, applied to the OpenTelemetry handler BEFORE export;
  * traces: FastAPI (server), httpx (outbound to ADO / Sonar / ...) and SQLAlchemy spans. Request/response bodies and
    headers are never captured (no hooks, no ``OTEL_INSTRUMENTATION_HTTP_CAPTURE_*``), so ``Authorization`` is not
    recorded; a span processor strips query strings and credentials from URL attributes;
  * cloud role name ``pch-web`` / ``pch-scan`` (``service.name``);
  * sampling: the distro reads ``OTEL_TRACES_SAMPLER`` / ``OTEL_TRACES_SAMPLER_ARG`` (e.g.
    ``microsoft.fixed_percentage`` + ``0.1``, or ``microsoft.rate_limited`` + traces/second). Not set by this app.
Health probes and static assets are excluded from tracing.
"""

from __future__ import annotations

import importlib.util
import logging
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from pch.logging_setup import protect_handlers, register_secret
from pch.providers.errors import ProviderUnavailable
from pch.settings import ConfigError, Settings

log = logging.getLogger("pch.telemetry")

EXTRA_HINT = (
    "APPLICATIONINSIGHTS_CONNECTION_STRING is set but the 'azure-monitor' extra is not installed: "
    "pip install 'pipeline-compliance[azure-monitor]' (or build the image with requirements-azure.lock)"
)
SERVICE_WEB, SERVICE_SCAN = "pch-web", "pch-scan"
EXCLUDED_URLS = "health/live,health/ready,api/v1/health,static/"
URL_ATTRIBUTES = ("http.url", "url.full", "http.target", "url.path")
QUERY_ATTRIBUTES = ("url.query",)


@dataclass(frozen=True)
class TelemetryStatus:
    enabled: bool
    service: str = ""
    detail: str = ""


def connection_string(s: Settings) -> str:
    return s.applicationinsights_connection_string.get_secret_value().strip()


def sdk_available() -> bool:
    try:
        return importlib.util.find_spec("azure.monitor.opentelemetry") is not None
    except (ImportError, ValueError):
        return False


def strip_url(url: str) -> str:
    """Remove userinfo, query string and fragment from a URL; leave non-URLs (paths) minus their query."""
    try:
        p = urlsplit(url)
    except ValueError:
        return "<invalid-url>"
    host = p.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    netloc = host + (f":{p.port}" if p.port else "") if p.netloc else ""
    return urlunsplit((p.scheme, netloc, p.path, "", ""))


# VERIFY: span *events* (``exception.message`` / ``exception.stacktrace`` recorded by the FastAPI/httpx/SQLAlchemy
# instrumentations) are not passed through RedactingFilter; check in Application Insights (exceptions table) that no
# URL query or credential appears there. SQLAlchemy parameters are already excluded (hide_parameters=True in
# pch.store.engine) and URL attributes are rewritten below.
def build_span_sanitizer() -> Any:
    """SpanProcessor that rewrites URL attributes at span start (before any exporter sees them)."""
    from opentelemetry.sdk.trace import SpanProcessor

    class UrlSanitizer(SpanProcessor):  # type: ignore[misc]
        def on_start(self, span: Any, parent_context: Any = None) -> None:
            attrs = getattr(span, "attributes", None) or {}
            for k in URL_ATTRIBUTES:
                v = attrs.get(k)
                if isinstance(v, str) and ("?" in v or "@" in v or "#" in v):
                    span.set_attribute(k, strip_url(v))
            for k in QUERY_ATTRIBUTES:
                if attrs.get(k):
                    span.set_attribute(k, "[removed]")

    return UrlSanitizer()


def _instrument_extras() -> None:
    """httpx and SQLAlchemy are instrumented explicitly when the distro does not already do it."""
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        inst = HTTPXClientInstrumentor()
        if not inst.is_instrumented_by_opentelemetry:
            inst.instrument()
    except ImportError:
        log.warning("opentelemetry-instrumentation-httpx is not installed: outbound HTTP spans are disabled")
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

        sa = SQLAlchemyInstrumentor()
        if not sa.is_instrumented_by_opentelemetry:
            sa.instrument(enable_commenter=False)  # statement text only (bind parameters are never recorded)
    except ImportError:
        log.warning("opentelemetry-instrumentation-sqlalchemy is not installed: DB spans are disabled")


def setup_telemetry(s: Settings, service: str) -> TelemetryStatus:
    """No-op unless the connection string is set. Raises ``ProviderUnavailable`` (a ConfigError) when it is set but the
    extra is missing, or ``ConfigError`` when the SDK rejects the connection string (the value is never echoed)."""
    conn = connection_string(s)
    if not conn:
        return TelemetryStatus(False, service, "disabled (APPLICATIONINSIGHTS_CONNECTION_STRING not set)")
    if not sdk_available():
        raise ProviderUnavailable(EXTRA_HINT)
    register_secret(conn)
    os.environ.setdefault("OTEL_PYTHON_FASTAPI_EXCLUDED_URLS", EXCLUDED_URLS)
    os.environ.setdefault("OTEL_PYTHON_HTTPX_EXCLUDED_URLS", "")
    from azure.monitor.opentelemetry import configure_azure_monitor
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource

    try:
        configure_azure_monitor(
            connection_string=conn,
            resource=Resource.create({SERVICE_NAME: service}),
            span_processors=[build_span_sanitizer()],
            enable_live_metrics=False,
        )
    except ConfigError:
        raise
    except Exception as exc:  # noqa: BLE001 - SDK messages can echo the connection string
        raise ConfigError(f"APPLICATIONINSIGHTS_CONNECTION_STRING could not be used ({type(exc).__name__})") from None
    protect_handlers()  # the OpenTelemetry LoggingHandler was just added to the root logger: redact BEFORE export
    _instrument_extras()
    log.info("Application Insights export enabled (cloud role %s)", service)
    return TelemetryStatus(True, service, f"enabled (cloud role {service})")
