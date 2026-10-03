"""Engine/session helpers. SQLite for dev/demo, Postgres via DATABASE_URL."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from pch.store.models import Base

_engines: dict[str, Engine] = {}


def get_engine(url: str) -> Engine:
    if url in _engines:
        return _engines[url]
    if url.startswith("sqlite:///") and ":memory:" not in url:
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
    engine = create_engine(url, future=True, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _pragma(dbapi_con, _):  # pragma: no cover - trivial
            cur = dbapi_con.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()

    Base.metadata.create_all(engine)
    _engines[url] = engine
    return engine


def reset_engines() -> None:
    for e in _engines.values():
        e.dispose()
    _engines.clear()


@contextmanager
def session_scope(url: str) -> Iterator[Session]:
    factory = sessionmaker(get_engine(url), expire_on_commit=False)
    with factory() as s:
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
