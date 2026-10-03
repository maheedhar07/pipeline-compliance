"""Alembic environment. The connection is normally passed in by ``pch.store.migrate`` (config.attributes);
standalone ``alembic`` use falls back to DATABASE_URL via the engine factory."""

from __future__ import annotations

from alembic import context
from sqlalchemy.engine import Connection

from pch.store.migrate import compare_type
from pch.store.models import Base

config = context.config
target_metadata = Base.metadata

def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True, compare_type=compare_type)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    from pch.settings import get_settings
    from pch.store.engine import build_engine

    engine = build_engine(get_settings().database_url)
    try:
        with engine.begin() as conn:
            _run(conn)
    finally:
        engine.dispose()


def run_migrations_offline() -> None:
    from pch.settings import get_settings

    context.configure(
        url=get_settings().database_url, literal_binds=True, dialect_opts={"paramstyle": "named"},
        target_metadata=target_metadata, render_as_batch=True, compare_type=compare_type,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
