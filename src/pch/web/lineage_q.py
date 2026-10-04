"""Data access for the Lineage tab, its JSON API and the CSV/Excel exports (one source of truth).

Lineage documents are stored whole (``lineage.doc``); list pages filter in Python after loading the scan's rows (no JSON
path SQL, portable across SQLite / PostgreSQL / SQL Server). Pre-L2 scans simply have no lineage rows.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from pch.model.lineage import DEPLOY_STATUS_LABEL, LDeploy, LPipeline, LRelease, LStage, RepoLineage
from pch.model.repo import PROVIDER_LABEL
from pch.store import repository as store
from pch.web.queries import TARGET_LABEL, TARGETS

TIERS = ["dev", "test", "uat", "prod", "unknown"]
STATUS_ORDER = ["succeeded", "partial", "in_progress", "pending", "failed", "canceled", "never", "unknown"]
ORPHAN_REPO_REASON = "GitHub repo known from scope.yaml or an Azure DevOps reference, but no Azure DevOps pipeline or release builds it (a GitHub repo named nowhere is invisible to this scan)"
MAX_CHIPS = 8


@dataclass
class LRow:
    key: str
    lin: RepoLineage


@dataclass
class LineageData:
    rows: list[LRow]
    orphans: list[dict[str, Any]]  # unlinked pipelines / releases (from the scan)
    has_data: bool  # the scan has lineage rows at all (False for scans made before L2)


def load(s: Session, scan_id: str) -> LineageData:
    rows: list[LRow] = []
    orphans: list[dict[str, Any]] = []
    stored = store.lineage_rows(s, scan_id)
    for r in stored:
        if r.kind == "orphan":
            orphans.extend(dict(o) for o in (r.doc or {}).get("orphans", []))
        else:
            rows.append(LRow(r.repo_key, RepoLineage.model_validate(r.doc)))
    rows.sort(key=lambda x: (x.lin.repo.project.lower(), x.lin.repo.name.lower()))
    return LineageData(rows, orphans, bool(stored))


def _haystack(lin: RepoLineage) -> str:
    bits: list[str] = [lin.repo.key, lin.repo.service_connection or ""]
    bits += [p.name for p in lin.pipelines] + [r.name for r in lin.releases]
    for st in lin.all_stages():
        bits += [st.name, st.env_name or "", *st.service_connections, *[t.name or "" for t in st.targets]]
    return "\n".join(bits).lower()


def apply_filters(data: LineageData, *, project: str | None = None, provider: str | None = None, q: str | None = None, target: str | None = None,
                  tier: str | None = None, has_prod: str | None = None, orphans_only: bool = False) -> LineageData:
    """Rows and orphans matching the filters. ``has_prod``: "yes" / "no" / empty."""

    def keep(lin: RepoLineage) -> bool:
        if project and lin.repo.project != project:
            return False
        if provider and lin.repo.provider != provider:
            return False
        if target and target not in lin.targets:
            return False
        if tier and not any(st.env_tier == tier for st in lin.all_stages()):
            return False
        if has_prod == "yes" and not lin.has_prod:
            return False
        if has_prod == "no" and lin.has_prod:
            return False
        if orphans_only and not lin.is_empty:
            return False
        return not (q and q.lower() not in _haystack(lin))

    rows = [r for r in data.rows if keep(r.lin)]
    orphans = [o for o in data.orphans if (not project or o.get("project") == project) and (not q or q.lower() in f"{o.get('name', '')} {o.get('reason', '')}".lower())]
    if provider or target or tier or has_prod:
        orphans = []  # unlinked items have no repo, provider, target or tier: they do not match those filters
    return LineageData(rows, orphans, data.has_data)


def chips(lin: RepoLineage) -> list[dict[str, str]]:
    """Compact chain summary: every stage (pipelines first, then releases) with its last-deploy status."""
    stages: list[LStage] = lin.all_stages()
    return [{"name": st.name, "tier": st.env_tier, "status": st.last_deploy.status} for st in stages][:MAX_CHIPS]


def repo_doc(lin: RepoLineage) -> dict[str, Any]:
    d = lin.model_dump(mode="json")
    d["summary"] = {
        "pipelines": len(lin.pipelines), "releases": len(lin.releases), "stages": len(lin.all_stages()), "targets": lin.targets, "tiers": lin.tiers, "has_prod": lin.has_prod,
        "empty": lin.is_empty, "chips": chips(lin), "more_chips": max(0, len(lin.all_stages()) - MAX_CHIPS),
        "yaml": sum(1 for p in lin.pipelines if p.kind == "yaml"), "classic": sum(1 for p in lin.pipelines if p.kind == "classic_build"),
    }
    return d


def orphan_items(data: LineageData) -> list[dict[str, Any]]:
    """Orphans section: unlinked pipelines/releases plus repos without any pipeline or release."""
    out = [dict(o) for o in data.orphans]
    for r in data.rows:
        if r.lin.is_empty:
            out.append({"type": "repo", "project": r.lin.repo.project, "id": "", "name": r.lin.repo.name, "url": r.lin.repo.url, "reason": ORPHAN_REPO_REASON, "key": r.key})
    out.sort(key=lambda o: (o["project"].lower(), {"pipeline": 0, "release": 1, "repo": 2}.get(o["type"], 3), o["name"].lower()))
    return out


def summary(data: LineageData) -> dict[str, Any]:
    lins = [r.lin for r in data.rows]
    stages = [st for lin in lins for st in lin.all_stages()]
    return {
        "repos": len(lins), "pipelines": sum(len(x.pipelines) for x in lins), "releases": sum(len(x.releases) for x in lins), "stages": len(stages),
        "with_prod": sum(1 for x in lins if x.has_prod), "empty_repos": sum(1 for x in lins if x.is_empty), "orphans": len(data.orphans),
        "by_project": dict(sorted(Counter(x.repo.project for x in lins).items())),
        "by_provider": {PROVIDER_LABEL.get(k, k): v for k, v in sorted(Counter(x.repo.provider for x in lins).items())},
        "by_target": {TARGET_LABEL.get(t, t): sum(1 for x in lins if t in x.targets) for t in TARGETS if any(t in x.targets for x in lins)},
        "by_tier": {t: sum(1 for st in stages if st.env_tier == t) for t in TIERS if any(st.env_tier == t for st in stages)},
        "by_status": {DEPLOY_STATUS_LABEL[k]: v for k in STATUS_ORDER if (v := sum(1 for st in stages if st.last_deploy.status == k))},
    }


def options(data: LineageData) -> dict[str, Any]:
    lins = [r.lin for r in data.rows]
    return {
        "projects": sorted({x.repo.project for x in lins}), "providers": sorted({x.repo.provider for x in lins}), "provider_labels": PROVIDER_LABEL,
        "targets": [t for t in TARGETS if any(t in x.targets for x in lins)], "tiers": [t for t in TIERS[:4] if any(t in x.tiers for x in lins)],
    }


def lineage_page(s: Session, scan_id: str, **filters: Any) -> dict[str, Any]:
    full = load(s, scan_id)
    data = apply_filters(full, **filters)
    return {"has_data": full.has_data, "repos": [repo_doc(r.lin) for r in data.rows], "orphans": orphan_items(data), "summary": summary(data), "options": options(full)}


def lineage_repo(s: Session, scan_id: str, project: str, repo: str) -> dict[str, Any] | None:
    key = f"{project}/{repo}"
    for r in store.lineage_rows(s, scan_id):
        if r.kind == "repo" and r.repo_key == key:
            return repo_doc(RepoLineage.model_validate(r.doc))
    return None


# --------------------------------------------------------------------------- flat export (CSV / Excel)
# (key, header, width). The ORDER IS THE CONTRACT (documented in README "Lineage export columns"): append, never reorder.
COLUMNS: list[tuple[str, str, int]] = [
    ("project", "project", 16), ("repo", "repo", 34), ("provider", "provider", 14), ("default_branch", "default_branch", 14), ("repo_service_connection", "repo_service_connection", 22),
    ("pipeline_kind", "pipeline_kind", 14), ("pipeline_id", "pipeline_id", 11), ("pipeline_name", "pipeline_name", 30), ("pipeline_url", "pipeline_url", 40),
    ("definition_path", "definition_path", 26), ("yaml_repo", "yaml_repo", 24), ("yaml_in_other_repo", "yaml_in_other_repo", 12), ("defined_in_repo", "defined_in_repo", 26),
    ("ci_trigger", "ci_trigger", 26), ("pr_trigger", "pr_trigger", 18), ("schedules", "schedules", 22), ("artifacts", "artifacts", 26),
    ("upstream_pipelines", "upstream_pipelines", 28), ("downstream_pipelines", "downstream_pipelines", 30),
    ("ci_last_run_status", "ci_last_run_status", 14), ("ci_last_run_number", "ci_last_run_number", 16), ("ci_last_run_time_utc", "ci_last_run_time_utc", 18),
    ("release_kind", "release_kind", 14), ("release_id", "release_id", 11), ("release_name", "release_name", 28), ("release_url", "release_url", 40),
    ("release_source", "release_source", 32), ("release_trigger", "release_trigger", 26),
    ("stage_order", "stage_order", 9), ("stage", "stage", 18), ("environment", "environment", 22), ("tier", "tier", 9), ("depends_on", "depends_on", 18),
    ("deploy_targets", "deploy_targets", 18), ("target_resources", "target_resources", 40), ("service_connections", "service_connections", 28), ("approvals_gates", "approvals_gates", 36),
    ("last_deploy_status", "last_deploy_status", 16), ("last_deploy_version", "last_deploy_version", 18), ("last_deploy_artifact_version", "last_deploy_artifact_version", 20),
    ("last_deploy_time_utc", "last_deploy_time_utc", 18), ("last_deploy_by", "last_deploy_by", 20), ("last_deploy_url", "last_deploy_url", 40),
]
DATE_COLUMNS = {"ci_last_run_time_utc", "last_deploy_time_utc"}
HEADERS = [c[1] for c in COLUMNS]
ORPHAN_COLUMNS: list[tuple[str, str, int]] = [("type", "type", 10), ("project", "project", 16), ("name", "name", 34), ("id", "id", 11), ("url", "url", 44), ("reason", "reason", 70)]


def _j(items: list[str]) -> str:
    return "; ".join(i for i in items if i)


def _status(d: LDeploy | None) -> str:
    return d.status if d else ""


def _pipeline_cols(p: LPipeline) -> dict[str, Any]:
    lr = p.last_run
    return {
        "pipeline_kind": p.kind, "pipeline_id": p.id, "pipeline_name": p.name, "pipeline_url": p.url, "definition_path": p.definition_path, "yaml_repo": p.yaml_repo or "",
        "yaml_in_other_repo": "yes" if p.yaml_in_other_repo else "no", "defined_in_repo": p.adopted_from or "",
        "ci_trigger": p.trigger.ci_summary(), "pr_trigger": p.trigger.pr_summary(), "schedules": _j(p.trigger.schedules), "artifacts": _j(p.artifacts),
        "upstream_pipelines": _j([u.name + (f" ({u.detail})" if u.detail else "") for u in p.upstream]),
        "downstream_pipelines": _j([d.name + (f" [{d.repo_key}]" if d.repo_key else "") for d in p.downstream]),
        "ci_last_run_status": _status(lr), "ci_last_run_number": (lr.version or "") if lr else "", "ci_last_run_time_utc": lr.finished if lr else None,
    }


def _release_cols(r: LRelease) -> dict[str, Any]:
    src = _j([f"{a.type}: {a.name}" + (f"@{a.branch}" if a.branch else "") + (" (primary)" if a.primary and len(r.sources) > 1 else "") for a in r.sources])
    trig = _j([("CD on " + (", ".join(r.cd_branches) if r.cd_branches else "any branch")) if r.cd_enabled else "no CD trigger", *[f"schedule {s}" for s in r.schedules]])
    return {"release_kind": "classic_release", "release_id": r.id, "release_name": r.name, "release_url": r.url, "release_source": src, "release_trigger": trig}


def _stage_cols(order: int, st: LStage) -> dict[str, Any]:
    d = st.last_deploy
    return {
        "stage_order": order, "stage": st.name, "environment": st.env_name or "", "tier": st.env_tier, "depends_on": _j(st.depends_on),
        "deploy_targets": _j(sorted({t.kind for t in st.targets})), "target_resources": _j([t.label() for t in st.targets if t.name or t.detail]),
        "service_connections": _j(st.service_connections), "approvals_gates": _j([*st.approvals, *st.gates]),
        "last_deploy_status": d.status, "last_deploy_version": d.version or "", "last_deploy_artifact_version": d.artifact_version or "",
        "last_deploy_time_utc": d.finished, "last_deploy_by": d.triggered_by or "", "last_deploy_url": d.url or "",
    }


def flat_rows(lins: list[RepoLineage]) -> Iterator[list[Any]]:
    """One row per repo -> pipeline -> release/deploy-stage path. A repo without pipelines/releases still gets a row."""

    def row(base: dict[str, Any], *parts: dict[str, Any]) -> list[Any]:
        merged: dict[str, Any] = {**base}
        for p in parts:
            merged.update(p)
        return [merged.get(k, "") for k, _, _ in COLUMNS]

    for lin in lins:
        rp = lin.repo
        base = {"project": rp.project, "repo": rp.name, "provider": rp.provider, "default_branch": rp.default_branch, "repo_service_connection": rp.service_connection or ""}
        if lin.is_empty:
            yield row(base)
            continue
        linked: set[tuple[str, str | None]] = set()
        for p in lin.pipelines:
            pc = _pipeline_cols(p)
            emitted = False
            for i, st in enumerate(p.stages, 1):
                yield row(base, pc, {"release_kind": "yaml_stages"}, _stage_cols(i, st))
                emitted = True
            for rel in lin.releases:
                if p.id in rel.source_pipeline_ids and (rel.adopted_from == p.adopted_from):
                    linked.add((rel.id, rel.adopted_from))
                    rc = _release_cols(rel)
                    if not rel.stages:
                        yield row(base, pc, rc)
                    for i, st in enumerate(rel.stages, 1):
                        yield row(base, pc, rc, _stage_cols(i, st))
                    emitted = True
            if not emitted:
                yield row(base, pc)
        for rel in lin.releases:
            if (rel.id, rel.adopted_from) in linked:
                continue
            rc = _release_cols(rel)
            if not rel.stages:
                yield row(base, rc)
            for i, st in enumerate(rel.stages, 1):
                yield row(base, rc, _stage_cols(i, st))


def filter_text(filters: dict[str, Any]) -> str:
    return "; ".join(f"{k}={v}" for k, v in filters.items() if v) or "none"


def summary_rows(scan: Any, data: LineageData, filters: dict[str, Any], n_rows: int, generated: datetime) -> list[list[Any]]:
    """Rows of the Excel "Summary" sheet. ``["#", title]`` is a section heading."""
    sm = summary(data)
    out: list[list[Any]] = [
        ["#", "Pipeline Compliance Hub: lineage export (read-only report)"],
        ["Scan", scan.id], ["Scan started (UTC)", scan.started_at.replace(tzinfo=None)], ["Scan mode", scan.mode], ["Generated (UTC)", generated],
        ["Filters", filter_text(filters)], ["Rows in the Lineage sheet", n_rows], ["Orphans (unlinked pipelines/releases)", sm["orphans"]],
        ["Source", "Azure DevOps only. GitHub repos without Azure DevOps pipelines are invisible. People: display name of whoever triggered the last deployment only."],
        [], ["#", "Totals"],
        ["Repositories", sm["repos"]], ["Pipelines (CI/build)", sm["pipelines"]], ["Classic releases", sm["releases"]], ["Stages / environments", sm["stages"]],
        ["Repos with a successful prod deployment", sm["with_prod"]], ["Repos without any pipeline or release", sm["empty_repos"]],
    ]
    for title, key in (("Repositories by project", "by_project"), ("Repositories by code host", "by_provider"), ("Repositories by deploy target", "by_target"),
                       ("Stages by environment tier", "by_tier"), ("Stages by last deployment status", "by_status")):
        out += [[], ["#", title], *[[k, v] for k, v in sm[key].items()]]
    return out


def orphan_rows(items: list[dict[str, Any]]) -> list[list[Any]]:
    return [[o.get(k, "") for k, _, _ in ORPHAN_COLUMNS] for o in items]


def scan_date(started: datetime) -> str:
    return started.strftime("%Y-%m-%d")
