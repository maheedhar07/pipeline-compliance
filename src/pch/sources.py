"""Build the (read-only) source clients for live, demo and from-cache runs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from pch.collectors.ado.client import AdoClient
from pch.collectors.aikido import AikidoClient
from pch.collectors.servicenow import ServiceNowClient
from pch.collectors.sonar import SonarClient
from pch.collectors.transport import CacheReplayTransport, RecordingTransport
from pch.demo import payloads as P
from pch.demo.transport import AIKIDO_HOST, SNOW_HOST, SONAR_HOST, DemoTransport
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


def _wrap(inner: httpx.AsyncBaseTransport, record_to: Path | None) -> httpx.AsyncBaseTransport:
    return RecordingTransport(inner, record_to) if record_to else inner


def demo_sources(world: dict, *, record_to: Path | None = None, concurrency: int = 16) -> Sources:
    """Sources wired to the in-memory demo world (real collectors, fake network)."""
    t = _wrap(DemoTransport(world), record_to)
    kw = {"backoff_base": 0, "max_attempts": 2, "concurrency": concurrency}
    return Sources(
        ado=AdoClient(P.ORG, "demo", transport=t, **kw),
        sonar=SonarClient(f"https://{SONAR_HOST}", "demo", transport=t, **kw),
        aikido=AikidoClient(f"https://{AIKIDO_HOST}", "demo", "demo", transport=t, **kw),
        snow=ServiceNowClient(f"https://{SNOW_HOST}", "demo", "demo", transport=t, **kw),
    )


def cache_sources(cache_dir: Path, settings: Settings, *, demo: bool = False) -> Sources:
    """Replay a previous scan's cached raw responses (pch scan --from-cache)."""
    t = CacheReplayTransport(cache_dir)
    kw = {"backoff_base": 0, "max_attempts": 1}
    if demo:
        return Sources(
            ado=AdoClient(P.ORG, "", transport=t, **kw),
            sonar=SonarClient(f"https://{SONAR_HOST}", transport=t, **kw),
            aikido=AikidoClient(f"https://{AIKIDO_HOST}", "x", "x", transport=t, **kw),
            snow=ServiceNowClient(f"https://{SNOW_HOST}", transport=t, **kw),
        )
    return _live(settings, t, kw)


def live_sources(settings: Settings, *, record_to: Path | None = None) -> Sources:
    inner = httpx.AsyncHTTPTransport(retries=1)
    return _live(settings, _wrap(inner, record_to), {"concurrency": settings.concurrency, "timeout": settings.http_timeout})


def _live(settings: Settings, transport: httpx.AsyncBaseTransport, kw: dict) -> Sources:
    if not settings.ado_org:
        raise SystemExit("ADO_ORG is not set (see .env.example). Use --demo to run without credentials.")
    ado = AdoClient(settings.ado_org, settings.ado_pat.get_secret_value(), base_url=settings.ado_base_url,
                    vsrm_url=settings.ado_vsrm_url, transport=transport, **kw)
    sonar = SonarClient(settings.sonar_url, settings.sonar_token.get_secret_value(), transport=transport, **kw) if settings.sonar_url else None
    aikido = (AikidoClient(settings.aikido_url, settings.aikido_client_id, settings.aikido_client_secret.get_secret_value(), transport=transport, **kw)
              if settings.aikido_client_id else None)
    snow = (ServiceNowClient(settings.servicenow_url, settings.servicenow_user, settings.servicenow_password.get_secret_value(), transport=transport, **kw)
            if settings.servicenow_url else None)
    return Sources(ado, sonar, aikido, snow)
