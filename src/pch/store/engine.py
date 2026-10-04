"""Engine factory: every dialect-specific option lives here (and nowhere else)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.engine import URL, Engine, make_url
from sqlalchemy.pool import StaticPool

from pch.settings import Settings, get_settings


def _is_memory(url: URL) -> bool:
    return not url.database or url.database == ":memory:"


def connect_args_for(backend: str, connect_timeout_seconds: int) -> dict[str, Any]:
    """Driver-level connect timeout per dialect (server dialects only)."""
    if backend == "postgresql":
        return {"connect_timeout": connect_timeout_seconds}
    if backend == "mssql":
        return {"timeout": connect_timeout_seconds}
    return {}


def build_engine(url: str | URL, settings: Settings | None = None) -> Engine:
    """Create an engine for ``url`` with per-dialect options from ``settings``. Does not connect."""
    s = settings or get_settings()
    u = make_url(url)
    backend = u.get_backend_name()
    kwargs: dict[str, Any] = {}

    if backend == "sqlite":
        kwargs["connect_args"] = {"check_same_thread": False}
        if _is_memory(u):
            kwargs["poolclass"] = StaticPool  # one shared connection, otherwise every checkout is a fresh empty DB
        elif u.database:
            Path(u.database).parent.mkdir(parents=True, exist_ok=True)
    else:
        # Bounded connection attempt so a hung server cannot park request threads. Parameter names verified against the
        # drivers: psycopg ``connect_timeout`` (libpq, seconds); pyodbc.connect(..., timeout=) sets SQL_ATTR_LOGIN_TIMEOUT.
        # Other dialects get no option (add theirs in connect_args_for).
        timeout_args = connect_args_for(backend, s.db_connect_timeout_seconds)
        if timeout_args:
            kwargs["connect_args"] = timeout_args
        kwargs.update(
            pool_pre_ping=True,
            pool_size=s.db_pool_size,
            max_overflow=s.db_max_overflow,
            pool_recycle=s.db_pool_recycle,
            pool_timeout=s.db_pool_timeout,
        )

    credential = None
    if s.db_auth == "azure_ad":
        from pch.store import azure_sql

        if backend != "mssql":
            raise ValueError("DB_AUTH=azure_ad requires an mssql+pyodbc:// DATABASE_URL")
        # Created eagerly so a missing `azuresql` extra fails at startup with a clear message; no network call happens here.
        credential = azure_sql.default_credential()

    # hide_parameters: DBAPI errors otherwise embed "[parameters: (...)]" (row values) in str(exc), which reaches logs,
    # the scans table (failure reason) and OpenTelemetry exception events.
    engine = create_engine(u, future=True, hide_parameters=True, **kwargs)

    if backend == "sqlite":

        @event.listens_for(engine, "connect")
        def _pragma(dbapi_con: Any, _rec: Any) -> None:  # pragma: no cover - trivial
            cur = dbapi_con.cursor()
            if not _is_memory(u):
                cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    if credential is not None:
        from pch.store import azure_sql

        try:
            azure_sql.install(engine, azure_sql.TokenProvider(credential))
        except Exception:
            engine.dispose()
            raise
    return engine
