"""Run history: builds (classic + YAML) and release deployments, for run stats and CRQ correlation."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from pch.collectors.ado.client import AdoClient
from pch.model.pipeline import DeploymentRecord, Pipeline, RunStats, RunSummary

CRQ_RE = re.compile(r"\b(CHG\d{6,9}|CRQ\d{6,12})\b", re.I)


def parse_dt(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d.astimezone(UTC).replace(tzinfo=None) if d.tzinfo else d


def change_refs(*texts: Any, pattern: re.Pattern[str] | None = None) -> list[str]:
    """Change-request numbers found in the texts. ``pattern`` = DEP-005 param ``crq_pattern`` (default: CHG/CRQ numbers)."""
    rx = pattern or CRQ_RE
    out: list[str] = []
    for t in texts:
        if t is None:
            continue
        for m in rx.finditer(str(t)):
            ref = m.group(0).upper()
            if ref not in out:
                out.append(ref)
    return out


def stats_from_builds(builds: list[dict[str, Any]]) -> tuple[RunStats, RunSummary | None]:
    st = RunStats()
    last: RunSummary | None = None
    newest: datetime | None = None
    for b in builds:
        res = (b.get("result") or b.get("status") or "").lower()
        fin = parse_dt(b.get("finishTime"))
        if res in ("succeeded", "partiallysucceeded", "failed", "canceled"):
            st.total += 1
            if res in ("succeeded", "partiallysucceeded"):
                st.succeeded += 1
                if fin and (st.last_success is None or fin > st.last_success):
                    st.last_success = fin
            elif res == "failed":
                st.failed += 1
        if fin and (newest is None or fin > newest):
            newest = fin
            last = RunSummary(status=res or "unknown", finished=fin, branch=b.get("sourceBranch"),
                              url=((b.get("_links") or {}).get("web") or {}).get("href"))
    return st, last


async def collect_build_runs(client: AdoClient, project: str, p: Pipeline, since: datetime, crq: re.Pattern[str] | None = None) -> list[dict[str, Any]]:
    """Collect completed builds (run stats, last run, prod deployments). Returns the raw items for the lineage view."""
    items = await client.paged(
        project, "_apis/build/builds",
        {"definitions": p.id, "minTime": since.strftime("%Y-%m-%dT%H:%M:%SZ"), "statusFilter": "completed", "$top": 200},
    )
    p.run_stats_90d, p.last_run = stats_from_builds(items)
    prod_names = [s.name for s in p.stages if s.env_tier == "prod"]
    if p.platform == "ado_yaml" and prod_names:
        for b in items:
            res = (b.get("result") or "").lower()
            if res not in ("succeeded", "partiallysucceeded"):
                continue
            p.deployments_90d.append(
                DeploymentRecord(
                    id=str(b.get("id")),
                    stage_name=prod_names[0],
                    env_tier="prod",
                    completed_at=parse_dt(b.get("finishTime")),
                    status=res,
                    change_refs=change_refs(b.get("parameters"), b.get("buildNumber"), b.get("tags"), b.get("triggerInfo"), pattern=crq),
                    requested_by=(b.get("requestedFor") or {}).get("uniqueName"),
                )
            )
    return items


async def collect_release_runs(client: AdoClient, project: str, p: Pipeline, since: datetime, crq: re.Pattern[str] | None = None) -> None:
    items = await client.paged(
        project, "_apis/release/deployments",
        {"definitionId": p.id, "minStartedTime": since.strftime("%Y-%m-%dT%H:%M:%SZ"), "$top": 200},
        vsrm=True,
    )
    st = RunStats()
    newest: datetime | None = None
    for d in items:
        status = (d.get("deploymentStatus") or "").lower()
        completed = parse_dt(d.get("completedOn"))
        if status in ("succeeded", "partiallysucceeded", "failed"):
            st.total += 1
            if status.startswith(("succeeded", "partially")):
                st.succeeded += 1
                if completed and (st.last_success is None or completed > st.last_success):
                    st.last_success = completed
            else:
                st.failed += 1
        if completed and (newest is None or completed > newest):
            newest = completed
            p.last_run = RunSummary(status=status, finished=completed)
        env_name = (d.get("releaseEnvironment") or {}).get("name") or ""
        stage = p.stage(env_name)
        if stage is not None and stage.env_tier == "prod" and status.startswith(("succeeded", "partially")):
            rel = d.get("release") or {}
            p.deployments_90d.append(
                DeploymentRecord(
                    id=str(d.get("id")),
                    stage_name=env_name,
                    env_tier="prod",
                    completed_at=completed,
                    status=status,
                    # VERIFY: the CRQ number is expected in the release name/description or a release variable.
                    change_refs=change_refs(rel.get("name"), rel.get("description"), d.get("description"), rel.get("variables"), pattern=crq),
                    requested_by=(d.get("requestedFor") or {}).get("uniqueName"),
                )
            )
    p.run_stats_90d = st


def since_days(now: datetime, days: int = 90) -> datetime:
    return now - timedelta(days=days)
