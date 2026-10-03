"""Persistence helpers for scan snapshots (write once, read many)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from pch.store.models import CollectionErrorRow, FindingRow, RepoResultRow, ScanRow


def create_scan(s: Session, scan_id: str, mode: str, started: datetime | None = None) -> ScanRow:
    row = ScanRow(id=scan_id, started_at=started or datetime.utcnow(), mode=mode, status="running")
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


def delete_scan(s: Session, scan_id: str) -> None:
    for model in (FindingRow, RepoResultRow, CollectionErrorRow):
        s.execute(delete(model).where(model.scan_id == scan_id))
    s.execute(delete(ScanRow).where(ScanRow.id == scan_id))
