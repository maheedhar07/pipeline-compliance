"""Retention: ``pch scans prune``.

Selection (``plan_prune``): scans are ranked newest first by ``started_at``. A scan is a candidate when it is outside
the newest ``keep`` scans AND (when given) older than ``older_than_days``; with only one option only that condition
applies. Never candidates, whatever the options say:
  * the latest ``complete`` scan (what the dashboard shows),
  * a ``running`` scan that is not stale (younger than the stale-lock window: it may be live).
A stale ``running`` scan is an orphan of a crashed process and may be pruned.

Execution (``execute_prune``): per scan, artifact-store prefix first, then the DB rows in ONE transaction (children
deleted in chunks, then ``repository.delete_scan``). Artifacts go first so a failure never leaves blobs without a
scan row to find them by; the reverse failure (rows kept, cache gone) only costs ``--from-cache`` for that scan and is
retried by the next prune.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from pch.providers import ArtifactStore
from pch.store import repository as store
from pch.store.db import session_scope
from pch.store.models import CollectionErrorRow, FindingRow, LineageRow, RepoResultRow, ScanRow
from pch.timeutil import utcnow

log = logging.getLogger("pch.retention")
CHUNK = 1000  # rows per DELETE ... WHERE id IN (...): far below SQL Server's 2100-parameter limit


@dataclass(frozen=True)
class Candidate:
    scan_id: str
    status: str
    started_at: datetime


@dataclass
class PruneOutcome:
    scan_id: str
    status: str
    started_at: datetime
    artifacts: int = 0
    rows: int = 0
    error: str = ""


@dataclass
class PruneReport:
    dry_run: bool
    outcomes: list[PruneOutcome] = field(default_factory=list)
    kept_protected: list[str] = field(default_factory=list)

    @property
    def errors(self) -> int:
        return sum(1 for o in self.outcomes if o.error)


def plan_prune(s: Session, keep: int | None, older_than_days: int | None, stale_after: timedelta, now: datetime | None = None) -> tuple[list[Candidate], list[str]]:
    """Returns ``(candidates, protected_ids)``; ``protected_ids`` are scans that matched the criteria but are never deleted."""
    if keep is None and older_than_days is None:
        raise ValueError("nothing to do: give --keep and/or --older-than (or set RETENTION_KEEP_SCANS / RETENTION_MAX_AGE_DAYS)")
    now = now or utcnow()
    rows = s.execute(select(ScanRow.id, ScanRow.status, ScanRow.started_at).order_by(ScanRow.started_at.desc(), ScanRow.id.desc())).all()
    latest_complete = next((r.id for r in rows if r.status == "complete"), None)
    cutoff = now - timedelta(days=older_than_days) if older_than_days is not None else None
    out: list[Candidate] = []
    protected: list[str] = []
    for i, r in enumerate(rows):
        if keep is not None and i < keep:
            continue
        if cutoff is not None and r.started_at >= cutoff:
            continue
        if r.id == latest_complete or (r.status == "running" and now - r.started_at < stale_after):
            protected.append(r.id)
            continue
        out.append(Candidate(r.id, r.status, r.started_at))
    return out, protected


def delete_scan_rows(url: str, scan_id: str, chunk: int = CHUNK) -> int:
    """Delete one scan's rows in a single transaction (children in chunks, then ``delete_scan``). Returns rows removed."""
    total = 0
    with session_scope(url) as s:
        for model in (FindingRow, RepoResultRow, CollectionErrorRow, LineageRow):
            while True:
                ids = list(s.scalars(select(model.id).where(model.scan_id == scan_id).limit(chunk)))
                if not ids:
                    break
                total += getattr(s.execute(delete(model).where(model.id.in_(ids))), "rowcount", 0) or 0
        store.delete_scan(s, scan_id)
        total += 1
    return total


async def execute_prune(url: str, artifacts: ArtifactStore, candidates: list[Candidate], protected: list[str], *, dry_run: bool) -> PruneReport:
    report = PruneReport(dry_run=dry_run, kept_protected=protected)
    for c in candidates:
        o = PruneOutcome(c.scan_id, c.status, c.started_at)
        prefix = f"{c.scan_id}/"
        try:
            if dry_run:
                o.artifacts = len(await artifacts.list(prefix))
            else:
                o.artifacts = await artifacts.delete_prefix(prefix)
                o.rows = delete_scan_rows(url, c.scan_id)
                log.info("pruned scan %s (%d rows, %d artifacts)", c.scan_id, o.rows, o.artifacts)
        except Exception as exc:  # noqa: BLE001 - one bad scan must not stop the rest; retried on the next run
            o.error = type(exc).__name__
            log.error("could not prune scan %s: %s", c.scan_id, o.error)
        report.outcomes.append(o)
    return report
