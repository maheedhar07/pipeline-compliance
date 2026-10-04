"""Liveness / readiness.

* ``/health/live``  : the process answers. No dependencies, so a DB outage never gets the container restarted.
* ``/health/ready`` : the database is reachable AND migrated to head (``db_ready_code``). The artifact store, the
  secret provider and the external sources (ADO, Sonar, ...) are deliberately NOT part of readiness: the dashboard only
  reads the DB, and a readiness probe that fans out to optional dependencies turns one flaky dependency into a
  full outage (cascading failure) as the platform pulls every instance out of rotation at once.

The probe runs in a worker thread with a short time budget and is single-flight + cached for a few seconds, so a hung DB
neither hangs the probe nor accumulates threads under a probe storm. Responses carry a status and a generic reason
code only (never URLs, driver text or exception text).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from pch.store.db import db_ready_code

log = logging.getLogger("pch.web.health")

REASON_TIMEOUT = "db_timeout"


class ReadinessProbe:
    def __init__(self, url: str, timeout_s: float, cache_s: float, check: Callable[[str], tuple[str, str]] = db_ready_code):
        self.url, self.timeout_s, self.cache_s, self.check = url, timeout_s, cache_s, check
        self._cached: tuple[float, str] | None = None  # (monotonic expiry, code)
        self._inflight: asyncio.Task[tuple[str, str]] | None = None

    async def code(self) -> str:
        now = time.monotonic()
        if self._cached and now < self._cached[0]:
            return self._cached[1]
        if self._inflight is None or self._inflight.done():
            self._inflight = asyncio.ensure_future(asyncio.to_thread(self.check, self.url))
        try:
            code, detail = await asyncio.wait_for(asyncio.shield(self._inflight), self.timeout_s)
        except TimeoutError:
            code, detail = REASON_TIMEOUT, f"readiness check exceeded {self.timeout_s}s"
        except Exception as exc:  # noqa: BLE001 - the probe itself must never raise
            code, detail = "db_unreachable", f"readiness check failed ({type(exc).__name__})"
        if code != "ok":
            log.warning("not ready: %s (%s)", code, detail)
        self._cached = (time.monotonic() + self.cache_s, code)
        return code
