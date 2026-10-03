"""SQLAlchemy 2.x ORM models. Each scan is an immutable snapshot.

Portability rules (SQLite / PostgreSQL / SQL Server): ``Unicode``/``UnicodeText`` for text (NVARCHAR on
MSSQL), indexed strings <= 450 chars (900-byte index key limit), ``UTCDateTime`` for timestamps,
no reserved-word names, and no JSON-path queries in SQL (JSON is read/written whole and filtered in Python).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Float, ForeignKey, Index, Integer, Unicode, UnicodeText
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from pch.store.types import UTCDateTime


class Base(DeclarativeBase):
    pass


class ScanRow(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(Unicode(40), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    mode: Mapped[str] = mapped_column(Unicode(16), default="live")
    status: Mapped[str] = mapped_column(Unicode(16), default="running")
    repos_total: Mapped[int] = mapped_column(Integer, default=0)
    repos_failed: Mapped[int] = mapped_column(Integer, default=0)
    findings_total: Mapped[int] = mapped_column(Integer, default=0)
    duration_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class RepoResultRow(Base):
    __tablename__ = "repo_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    repo_key: Mapped[str] = mapped_column(Unicode(300), index=True)
    project: Mapped[str] = mapped_column(Unicode(200), index=True)
    repo: Mapped[str] = mapped_column(Unicode(200))
    url: Mapped[str] = mapped_column(UnicodeText, default="")
    owner: Mapped[str | None] = mapped_column(Unicode(200), nullable=True)
    platform_mix: Mapped[list[str]] = mapped_column(JSON, default=list)
    targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    test_state: Mapped[str] = mapped_column(Unicode(32), default="NOT_APPLICABLE")
    test_state_reason: Mapped[str] = mapped_column(UnicodeText, default="")
    coverage: Mapped[float | None] = mapped_column(Float, nullable=True)
    sonar_gate: Mapped[str | None] = mapped_column(Unicode(16), nullable=True)
    aikido_criticals: Mapped[int | None] = mapped_column(Integer, nullable=True)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(Unicode(16), index=True)
    unknowns: Mapped[int] = mapped_column(Integer, default=0)
    critical_fails: Mapped[int] = mapped_column(Integer, default=0)
    high_fails: Mapped[int] = mapped_column(Integer, default=0)
    migration_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    migration_blockers: Mapped[list[str]] = mapped_column(JSON, default=list)
    facts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    pipelines: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    rule_status: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    # column renamed: EXTERNAL is reserved in T-SQL
    external: Mapped[dict[str, Any]] = mapped_column("external_summary", JSON, default=dict)  # sonar/aikido/snow summaries (no secrets)


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_scan_rule", "scan_id", "rule_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    repo_key: Mapped[str] = mapped_column(Unicode(300), index=True)
    rule_id: Mapped[str] = mapped_column(Unicode(40))
    category: Mapped[str] = mapped_column(Unicode(8))
    severity: Mapped[str] = mapped_column(Unicode(10))
    status: Mapped[str] = mapped_column(Unicode(16))
    pipeline_id: Mapped[str | None] = mapped_column(Unicode(64), nullable=True)
    pipeline_name: Mapped[str | None] = mapped_column(UnicodeText, nullable=True)
    stage: Mapped[str | None] = mapped_column(UnicodeText, nullable=True)
    message: Mapped[str] = mapped_column(UnicodeText, default="")
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    link: Mapped[str | None] = mapped_column(UnicodeText, nullable=True)
    waiver: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    original_status: Mapped[str | None] = mapped_column(Unicode(16), nullable=True)


class CollectionErrorRow(Base):
    __tablename__ = "collection_errors"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    source: Mapped[str] = mapped_column(Unicode(32))
    subject: Mapped[str] = mapped_column(Unicode(300))
    message: Mapped[str] = mapped_column(UnicodeText)


class ScanLockRow(Base):
    """Single named row used as a cross-process scan mutex (see ``pch.store.locks``)."""

    __tablename__ = "scan_locks"
    name: Mapped[str] = mapped_column(Unicode(64), primary_key=True)
    holder: Mapped[str] = mapped_column(Unicode(200))
    acquired_at: Mapped[datetime] = mapped_column(UTCDateTime())
