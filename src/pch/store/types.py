"""Portable column types."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime
from sqlalchemy.dialects import mssql
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator, TypeEngine


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetimes on every dialect.

    SQLite and SQL Server (``DATETIME2``) do not store a timezone, so values are normalised to UTC on
    write (a naive value is assumed to already be UTC) and returned as aware UTC on read. PostgreSQL
    uses ``TIMESTAMP WITH TIME ZONE``.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> TypeEngine[Any]:
        if dialect.name == "mssql":
            return dialect.type_descriptor(mssql.DATETIME2())
        return dialect.type_descriptor(DateTime(timezone=True))

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        value = value.astimezone(UTC)
        if dialect.name in ("sqlite", "mssql"):
            return value.replace(tzinfo=None)  # stored as naive UTC
        return value

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
