"""SQLAlchemy 2.x ORM models. Each scan is an immutable snapshot."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ScanRow(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    mode: Mapped[str] = mapped_column(String(16), default="live")
    status: Mapped[str] = mapped_column(String(16), default="running")
    repos_total: Mapped[int] = mapped_column(Integer, default=0)
    repos_failed: Mapped[int] = mapped_column(Integer, default=0)
    findings_total: Mapped[int] = mapped_column(Integer, default=0)
    duration_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class RepoResultRow(Base):
    __tablename__ = "repo_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    repo_key: Mapped[str] = mapped_column(String(300), index=True)
    project: Mapped[str] = mapped_column(String(200), index=True)
    repo: Mapped[str] = mapped_column(String(200))
    url: Mapped[str] = mapped_column(String(500), default="")
    owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    platform_mix: Mapped[list[str]] = mapped_column(JSON, default=list)
    targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    test_state: Mapped[str] = mapped_column(String(32), default="NOT_APPLICABLE")
    test_state_reason: Mapped[str] = mapped_column(Text, default="")
    coverage: Mapped[float | None] = mapped_column(Float, nullable=True)
    sonar_gate: Mapped[str | None] = mapped_column(String(16), nullable=True)
    aikido_criticals: Mapped[int | None] = mapped_column(Integer, nullable=True)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    unknowns: Mapped[int] = mapped_column(Integer, default=0)
    critical_fails: Mapped[int] = mapped_column(Integer, default=0)
    high_fails: Mapped[int] = mapped_column(Integer, default=0)
    migration_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    migration_blockers: Mapped[list[str]] = mapped_column(JSON, default=list)
    facts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    pipelines: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    rule_status: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    external: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # sonar/aikido/snow summaries (no secrets)


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_scan_rule", "scan_id", "rule_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    repo_key: Mapped[str] = mapped_column(String(300), index=True)
    rule_id: Mapped[str] = mapped_column(String(40))
    category: Mapped[str] = mapped_column(String(8))
    severity: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(16))
    pipeline_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pipeline_name: Mapped[str | None] = mapped_column(String(300), nullable=True)
    stage: Mapped[str | None] = mapped_column(String(200), nullable=True)
    message: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    link: Mapped[str | None] = mapped_column(String(600), nullable=True)
    waiver: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    original_status: Mapped[str | None] = mapped_column(String(16), nullable=True)


class CollectionErrorRow(Base):
    __tablename__ = "collection_errors"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    source: Mapped[str] = mapped_column(String(32))
    subject: Mapped[str] = mapped_column(String(300))
    message: Mapped[str] = mapped_column(Text)
