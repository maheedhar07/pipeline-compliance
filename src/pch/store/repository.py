"""Persistence helpers for scan snapshots (write once, read many)."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime, timedelta
from typing import Any, TypeVar

from sqlalchemy import ColumnElement, delete, insert, select, update
from sqlalchemy.orm import Session

from pch.store.models import Base, CollectionErrorRow, FindingRow, LineageRow, RepoResultRow, ScanRow
from pch.timeutil import utcnow

log = logging.getLogger("pch.store")
T = TypeVar("T")

# SQL Server allows at most 2100 bound parameters per statement; stay well below it everywhere.
MAX_PARAMS = 2000


def create_scan(s: Session, scan_id: str, mode: str, started: datetime | None = None) -> ScanRow:
    row = ScanRow(id=scan_id, started_at=started or utcnow(), mode=mode, status="running")
    s.add(row)
    s.flush()
    return row


def latest_scan(s: Session) -> ScanRow | None:
    return s.scalars(
        select(ScanRow).where(ScanRow.status == "complete").order_by(ScanRow.started_at.desc()).limit(1)
    ).first()


def get_scan(s: Session, scan_id: str) -> ScanRow | None:
    return s.get(ScanRow, scan_id)


def list_scans(s: Session, limit: int = 50) -> list[ScanRow]:
    return list(s.scalars(select(ScanRow).order_by(ScanRow.started_at.desc()).limit(limit)))


def repo_results(s: Session, scan_id: str) -> list[RepoResultRow]:
    return list(s.scalars(select(RepoResultRow).where(RepoResultRow.scan_id == scan_id)))


def repo_result(s: Session, scan_id: str, repo_key: str) -> RepoResultRow | None:
    return s.scalars(
        select(RepoResultRow).where(RepoResultRow.scan_id == scan_id, RepoResultRow.repo_key == repo_key)
    ).first()


def findings(s: Session, scan_id: str, repo_key: str | None = None, rule_id: str | None = None) -> list[FindingRow]:
    q = select(FindingRow).where(FindingRow.scan_id == scan_id)
    if repo_key:
        q = q.where(FindingRow.repo_key == repo_key)
    if rule_id:
        q = q.where(FindingRow.rule_id == rule_id)
    return list(s.scalars(q))


def collection_errors(s: Session, scan_id: str) -> list[CollectionErrorRow]:
    return list(s.scalars(select(CollectionErrorRow).where(CollectionErrorRow.scan_id == scan_id)))


def lineage_rows(s: Session, scan_id: str) -> list[LineageRow]:
    return list(s.scalars(select(LineageRow).where(LineageRow.scan_id == scan_id)))


def delete_scan(s: Session, scan_id: str) -> None:
    for model in (FindingRow, RepoResultRow, CollectionErrorRow, LineageRow):
        s.execute(delete(model).where(model.scan_id == scan_id))
    s.execute(delete(ScanRow).where(ScanRow.id == scan_id))


def chunked(items: Sequence[T] | Iterable[T], size: int) -> Iterator[list[T]]:
    """Yield lists of at most ``size`` items."""
    buf: list[T] = []
    for it in items:
        buf.append(it)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def insert_rows(s: Session, model: type[Base], rows: Sequence[dict[str, Any]]) -> None:
    """Bulk insert in chunks that respect the 2100-parameter limit (rows x columns per statement)."""
    if not rows:
        return
    ncols = max(1, len(model.__table__.columns))  # type: ignore[attr-defined]
    for chunk in chunked(rows, max(1, MAX_PARAMS // ncols)):
        s.execute(insert(model), chunk)


def select_where_in(s: Session, entity: Any, column: ColumnElement[Any] | Any, values: Sequence[Any]) -> list[Any]:
    """``SELECT entity WHERE column IN (values)`` split into chunks of at most MAX_PARAMS values."""
    out: list[Any] = []
    for chunk in chunked(values, MAX_PARAMS):
        out.extend(s.scalars(select(entity).where(column.in_(chunk))))
    return out


def mark_failed(s: Session, scan_id: str, error: str) -> None:
    s.execute(
        update(ScanRow)
        .where(ScanRow.id == scan_id, ScanRow.status == "running")
        .values(status="failed", finished_at=utcnow(), summary={"error": error[:400]})
    )


def fail_orphaned_scans(s: Session, older_than: timedelta, exclude: str | None = None) -> int:
    """Scans left ``running`` by a crashed process (older than ``older_than``) become ``failed``."""
    cutoff = utcnow() - older_than
    q = select(ScanRow.id).where(ScanRow.status == "running", ScanRow.started_at < cutoff)
    if exclude:
        q = q.where(ScanRow.id != exclude)
    ids = list(s.scalars(q))
    for sid in ids:
        mark_failed(s, sid, "orphaned: the scan process stopped without finishing")
        log.warning("marked orphaned scan %s as failed", sid)
    return len(ids)
