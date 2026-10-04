"""Engine cache, schema policy and session helpers.

Schema policy (``ensure_schema``): the schema is only ever created by Alembic migrations.
  * already at head                                   -> nothing to do
  * SQLite and APP_ENV in (dev, test)                 -> ``upgrade head`` automatically (keeps the migration path exercised)
  * ``DB_AUTO_MIGRATE=true`` (any dialect / env)      -> ``upgrade head`` automatically
  * anything else (notably prod)                      -> ``SchemaNotReadyError``; run ``pch db upgrade`` explicitly
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from pch.settings import Settings, get_settings
from pch.store import migrate
from pch.store.engine import build_engine
from pch.store.migrate import SchemaNotReadyError

__all__ = ["SchemaNotReadyError", "db_ready", "db_ready_code", "dispose_engine", "ensure_schema", "get_engine", "get_raw_engine", "reset_engines", "session_scope"]

_raw: dict[str, Engine] = {}
_ready: set[str] = set()
_lock = threading.Lock()


def get_raw_engine(url: str) -> Engine:
    """Cached engine with no schema checks (migrations, readiness probes)."""
    with _lock:
        eng = _raw.get(url)
        if eng is None:
            eng = _raw[url] = build_engine(url)
        return eng


def ensure_schema(engine: Engine, settings: Settings | None = None) -> None:
    s = settings or get_settings()
    st = migrate.db_state(engine)
    if st.at_head:
        return
    auto = s.db_auto_migrate or (engine.dialect.name == "sqlite" and s.app_env in ("dev", "test"))
    if st.unversioned or not auto or (st.current is not None and st.current not in _known_revisions()):
        raise SchemaNotReadyError(migrate.not_ready_reason(st))
    migrate.upgrade(engine, "head")


def _known_revisions() -> set[str]:
    from alembic.script import ScriptDirectory

    return {r.revision for r in ScriptDirectory.from_config(migrate.make_config()).walk_revisions()}


def get_engine(url: str) -> Engine:
    """Engine for ``url`` with the schema verified (or migrated, per policy) on first use."""
    eng = get_raw_engine(url)
    if url not in _ready:
        with _lock:
            if url not in _ready:
                ensure_schema(eng)
                _ready.add(url)
    return eng


def reset_engines() -> None:
    with _lock:
        for e in _raw.values():
            e.dispose()
        _raw.clear()
        _ready.clear()


def dispose_engine(url: str) -> None:
    """Dispose and forget the engine for ``url`` only (application shutdown)."""
    with _lock:
        eng = _raw.pop(url, None)
        _ready.discard(url)
    if eng is not None:
        eng.dispose()


def db_ready_code(url: str) -> tuple[str, str]:
    """``(code, detail)``: code is ``ok`` | ``db_unreachable`` | ``schema_not_ready`` (safe to expose); ``detail`` is for
    logs/CLI only. Never migrates."""
    try:
        st = migrate.db_state(get_raw_engine(url))
    except Exception as exc:  # noqa: BLE001 - reason must not echo the URL/credentials
        return "db_unreachable", f"database unreachable ({type(exc).__name__})"
    if st.at_head:
        return "ok", f"at head {st.head}"
    return "schema_not_ready", migrate.not_ready_reason(st)


def db_ready(url: str) -> tuple[bool, str]:
    """Readiness probe (T6 ``/health/ready``): DB reachable and migrated to head. Never migrates."""
    code, detail = db_ready_code(url)
    return code == "ok", detail


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
