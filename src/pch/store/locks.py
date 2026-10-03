"""DB-backed scan lock: one named row in ``scan_locks``. Identical on SQLite, PostgreSQL and SQL Server.

Acquire = INSERT (primary key makes it exclusive); release = DELETE of *our* row. A lock older than
``stale_after`` is taken over with a compare-and-swap UPDATE on the previous holder token, so two
processes can never both take over the same stale lock.
"""

from __future__ import annotations

import logging
import os
import socket
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta

from sqlalchemy import delete, insert, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from pch.store.models import ScanLockRow
from pch.timeutil import utcnow

log = logging.getLogger("pch.lock")
DEFAULT_NAME = "scan"


class ScanLockHeld(RuntimeError):
    """Another scan holds the lock (and it is not stale)."""


def _new_holder() -> str:
    return f"{socket.gethostname()[:100]}:{os.getpid()}:{uuid.uuid4().hex[:12]}"


def acquire(engine: Engine, name: str = DEFAULT_NAME, stale_after: timedelta = timedelta(hours=6), now: datetime | None = None) -> str:
    """Take the lock and return our holder token, or raise ``ScanLockHeld``."""
    holder = _new_holder()
    now = now or utcnow()
    try:
        with engine.begin() as conn:
            conn.execute(insert(ScanLockRow).values(name=name, holder=holder, acquired_at=now))
        return holder
    except IntegrityError:
        pass  # somebody holds it (rolled back by the context manager)
    with engine.begin() as conn:
        row = conn.execute(select(ScanLockRow.holder, ScanLockRow.acquired_at).where(ScanLockRow.name == name)).first()
        if row is None:  # released between our INSERT and SELECT: retry once
            conn.execute(insert(ScanLockRow).values(name=name, holder=holder, acquired_at=now))
            return holder
        old_holder, since = row
        if now - since < stale_after:
            raise ScanLockHeld(f"another scan is running (holder {old_holder}, since {since:%Y-%m-%d %H:%M:%S} UTC)")
        taken = conn.execute(
            update(ScanLockRow).where(ScanLockRow.name == name, ScanLockRow.holder == old_holder).values(holder=holder, acquired_at=now)
        ).rowcount
    if taken != 1:
        raise ScanLockHeld("another scan took over the stale lock first")
    log.warning("took over a stale scan lock from %s (held since %s UTC)", old_holder, since)
    return holder


def release(engine: Engine, holder: str, name: str = DEFAULT_NAME) -> None:
    with engine.begin() as conn:
        conn.execute(delete(ScanLockRow).where(ScanLockRow.name == name, ScanLockRow.holder == holder))


@contextmanager
def scan_lock(engine: Engine, name: str = DEFAULT_NAME, stale_after: timedelta = timedelta(hours=6)) -> Iterator[str]:
    holder = acquire(engine, name, stale_after)
    try:
        yield holder
    finally:
        try:
            release(engine, holder, name)
        except Exception:  # noqa: BLE001 - never mask the scan's own error; the stale timeout recovers it
            log.exception("could not release the scan lock (it expires after the stale timeout)")
