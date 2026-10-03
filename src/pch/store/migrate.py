"""Programmatic Alembic access (no alembic.ini / CWD dependence) plus schema state helpers.

The migration scripts ship inside the package (``pch/store/migrations``). All operations take an
``Engine`` so the same code path works for SQLite, PostgreSQL and SQL Server (including the Azure AD
token hook installed by the engine factory).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.engine import Connection, Engine

from pch.store.models import Base

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
APP_TABLES = frozenset(Base.metadata.tables) - {"alembic_version"}


class SchemaNotReadyError(RuntimeError):
    """The database schema is not at the migration head (message says what to run)."""


@dataclass(frozen=True)
class DbState:
    current: str | None
    head: str
    has_app_tables: bool

    @property
    def at_head(self) -> bool:
        return self.current == self.head

    @property
    def unversioned(self) -> bool:
        """Tables exist but Alembic never ran (database created by the old ``create_all``)."""
        return self.current is None and self.has_app_tables


def make_config(connection: Connection | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("path_separator", "os")
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def head_revision() -> str:
    head = ScriptDirectory.from_config(make_config()).get_current_head()
    if head is None:
        raise RuntimeError("no Alembic head revision found (broken installation)")
    return head


def db_state(engine: Engine) -> DbState:
    with engine.connect() as conn:
        current = MigrationContext.configure(conn).get_current_revision()
        tables = set(inspect(conn).get_table_names())
    return DbState(current, head_revision(), bool(tables & APP_TABLES))


def not_ready_reason(st: DbState) -> str:
    if st.unversioned:
        return (
            "database has tables but no alembic_version (created by an older version). If its schema matches "
            "the initial release, adopt it with `pch db stamp head`; otherwise run `pch db upgrade` on an empty database"
        )
    if st.current is None:
        return f"database is empty (head is {st.head}): run `pch db upgrade`"
    return f"database is at revision {st.current} but head is {st.head}: run `pch db upgrade`"


def upgrade(engine: Engine, revision: str = "head") -> None:
    st = db_state(engine)
    if st.unversioned:
        raise SchemaNotReadyError(not_ready_reason(st))
    with engine.begin() as conn:
        command.upgrade(make_config(conn), revision)


def downgrade(engine: Engine, revision: str) -> None:
    with engine.begin() as conn:
        command.downgrade(make_config(conn), revision)


def stamp(engine: Engine, revision: str = "head") -> None:
    with engine.begin() as conn:
        command.stamp(make_config(conn), revision)


def compare_type(context, inspected_column, metadata_column, inspected_type, metadata_type):  # type: ignore[no-untyped-def]
    """Alembic ``compare_type`` hook: SQL Server stores JSON as NVARCHAR(max), so do not report that as drift."""
    if context.dialect.name == "mssql" and type(metadata_type).__name__ == "JSON":
        return False
    return None  # default comparison
