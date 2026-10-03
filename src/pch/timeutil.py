"""Time helpers.

Convention: the *domain* layer (collectors, rules, scoring) works with naive datetimes that are
implicitly UTC. Anything that crosses the persistence boundary is timezone-aware UTC
(``utcnow``); ``UTCDateTime`` treats a naive value as UTC on write and always returns aware UTC.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Timezone-aware current time in UTC."""
    return datetime.now(UTC)


def utcnow_naive() -> datetime:
    """Naive UTC "now" for the domain layer (replacement for the deprecated ``datetime.utcnow``)."""
    return datetime.now(UTC).replace(tzinfo=None)
