"""Build the (read-only) source clients for live, demo and from-cache runs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from pch.collectors.ado.client import AdoClient
from pch.collectors.aikido import AikidoClient
from pch.collectors.servicenow import ServiceNowClient
from pch.collectors.sonar import SonarClient
from pch.collectors.transport import CacheReplayTransport, RecordingTransport, SizeLimitTransport
from pch.demo import payloads as P
from pch.demo.transport import AIKIDO_HOST, SNOW_HOST, SONAR_HOST, DemoTransport
from pch.providers import ArtifactStore, SecretProvider, get_secret_provider, require_secret
from pch.settings import Settings


@dataclass
class Sources:
    ado: AdoClient
    sonar: SonarClient | None = None
    aikido: AikidoClient | None = None
    snow: ServiceNowClient | None = None

    async def aclose(self) -> None:
        for c in (self.ado, self.sonar, self.aikido, self.snow):
            if c is not None:
                await c.aclose()


def _wrap(inner: httpx.AsyncBaseTransport, record_to: ArtifactStore | None) -> httpx.AsyncBaseTransport:
    return RecordingTransport(inner, record_to) if record_to is not None else inner


def demo_sources(world: dict, *, record_to: ArtifactStore | None = None, concurrency: int = 16) -> Sources:
    """Sources wired to the in-memory demo world (real collectors, fake network)."""
    t = _wrap(DemoTransport(world), record_to)
    kw: dict[str, Any] = {"backoff_base": 0, "max_attempts": 2, "concurrency": concurrency}
    return Sources(
        ado=AdoClient(P.ORG, "demo", transport=t, **kw),
        sonar=SonarClient(f"https://{SONAR_HOST}", "demo", transport=t, **kw),
        aikido=AikidoClient(f"https://{AIKIDO_HOST}", "demo", "demo", transport=t, **kw),
        snow=ServiceNowClient(f"https://{SNOW_HOST}", "demo", "demo", transport=t, **kw),
    )


def cache_sources(cache: ArtifactStore, settings: Settings, *, demo: bool = False) -> Sources:
    """Replay a previous scan's cached raw responses (pch scan --from-cache); ``cache`` is that scan's store view."""
    t = CacheReplayTransport(cache)
    kw: dict[str, Any] = {"backoff_base": 0, "max_attempts": 1}
    if demo:
        return Sources(
            ado=AdoClient(P.ORG, "", transport=t, **kw),
            sonar=SonarClient(f"https://{SONAR_HOST}", transport=t, **kw),
            aikido=AikidoClient(f"https://{AIKIDO_HOST}", "x", "x", transport=t, **kw),
            snow=ServiceNowClient(f"https://{SNOW_HOST}", transport=t, **kw),
        )
    return _live(settings, t, kw, None)  # replay never talks to the real systems: no credentials needed


def live_sources(settings: Settings, *, record_to: ArtifactStore | None = None, secrets: SecretProvider | None = None) -> Sources:
    """Live clients. Credentials come ONLY from the SecretProvider selected by SECRETS_PROVIDER (explicit, no mixing)."""
    inner = SizeLimitTransport(httpx.AsyncHTTPTransport(retries=1), settings.http_max_response_mb * 1024 * 1024)
    provider = secrets or get_secret_provider(settings)
    return _live(settings, _wrap(inner, record_to), {"concurrency": settings.concurrency, "timeout": settings.http_timeout}, provider)


def _live(settings: Settings, transport: httpx.AsyncBaseTransport, kw: dict[str, Any], secrets: SecretProvider | None) -> Sources:
    """``secrets=None`` (cache replay) builds the clients with empty credentials."""
    if not settings.ado_org:
        raise SystemExit("ADO_ORG is not set (see .env.example). Use --demo to run without credentials.")

    def secret(name: str) -> str:
        return require_secret(secrets, name) if secrets is not None else ""

    ado = AdoClient(settings.ado_org, secret("ADO_PAT"), base_url=settings.ado_base_url,
                    vsrm_url=settings.ado_vsrm_url, transport=transport, **kw)
    sonar = SonarClient(settings.sonar_url, secret("SONAR_TOKEN"), transport=transport, **kw) if settings.sonar_url else None
    aikido = (AikidoClient(settings.aikido_url, settings.aikido_client_id, secret("AIKIDO_CLIENT_SECRET"), transport=transport, **kw)
              if settings.aikido_client_id else None)
    snow = (ServiceNowClient(settings.servicenow_url, settings.servicenow_user, secret("SERVICENOW_PASSWORD"), transport=transport, **kw)
            if settings.servicenow_url else None)
    return Sources(ado, sonar, aikido, snow)
