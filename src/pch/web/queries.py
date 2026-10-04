"""Data access for the dashboard and the JSON API (one source of truth for both)."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from pch.engine.migration import STATUS_LABEL as MIGRATION_LABEL
from pch.engine.migration import migration_status
from pch.engine.reasons import empty_reasons
from pch.engine.registry import CATEGORY_NAMES, RuleMeta, all_rules
from pch.model.findings import SEVERITY_ORDER
from pch.model.repo import PROVIDER_LABEL
from pch.store import repository as store
from pch.store.models import CollectionErrorRow, FindingRow, RepoResultRow, ScanRow
from pch.timeutil import utcnow
from pch.web.tables import sort_rows, text_key

STATUS_RANK = {"NON_COMPLIANT": 0, "AT_RISK": 1, "COMPLIANT": 2, "NOT_SCANNED": 3}
FINDING_RANK = {"FAIL": 0, "WARN": 1, "UNKNOWN": 2, "WAIVED": 3, "PASS": 4, "NOT_APPLICABLE": 5}  # nosec B105 - status rank map, not a password
SEV_RANK = {s.value: i for i, s in enumerate(SEVERITY_ORDER)}
PLATFORM_BADGE = {"ado_yaml": "ADO YAML", "ado_classic_build": "ADO Classic", "ado_classic_release": "ADO Classic", "gha": "GitHub Actions"}
PLATFORM_LABEL = {"ado_classic_build": "Classic build", "ado_classic_release": "Classic release", "ado_yaml": "YAML", "gha": "GitHub Actions"}
TARGETS = ["functionapp", "webapp", "aks", "adf", "synapse", "sql", "iac"]
TARGET_LABEL = {"functionapp": "Function App", "webapp": "Web App", "aks": "AKS", "adf": "Data Factory", "synapse": "Synapse", "sql": "SQL (dacpac)", "iac": "IaC"}
TARGET_RULE_CODE = {"functionapp": "FA", "webapp": "WA", "aks": "AKS", "adf": "ADF", "synapse": "SYN", "sql": "SQL", "iac": "IAC"}
TEST_STATES = ["TESTS_OK", "TESTS_LOW_COVERAGE", "TESTS_NO_COVERAGE", "TESTS_NOT_RUN", "NO_TESTS", "UNKNOWN", "NOT_APPLICABLE"]
SORTABLE = {"project", "repo", "owner", "provider", "platforms", "targets", "test_state", "coverage", "sonar_gate", "aikido_criticals", "score", "status",
            "critical_fails", "high_fails", "unknowns", "migration_score", "migration_status"}
NO_OWNER = "(no owner)"  # the owner filter value / label for repos without an owner
MIGRATION_RANK = {"ado_only": 0, "in_progress": 1, "migrated": 2, "none": 3}


def rule_index() -> dict[str, RuleMeta]:
    return {r.id: r for r in all_rules()}


def resolve_scan(s: Session, scan_id: str | None) -> ScanRow | None:
    if scan_id:
        row = store.get_scan(s, scan_id)
        if row:
            return row
    return store.latest_scan(s)


def humanize_age(delta: timedelta) -> str:
    """"just now", "5 min ago", "3 h ago", "2 d ago" (a future time, e.g. clock skew, counts as "just now")."""
    secs = max(0, int(delta.total_seconds()))
    if secs < 90:
        return "just now"
    if secs < 90 * 60:
        return f"{round(secs / 60)} min ago"
    if secs < 48 * 3600:
        return f"{round(secs / 3600)} h ago"
    return f"{secs // 86400} d ago"


def freshness(s: Session, stale_hours: int, now: datetime | None = None) -> dict[str, Any]:
    """How current the data is, for the header and the warning banner (a broken schedule must be visible).

    ``state``: ``none`` (no scans) | ``ok`` | ``stale`` (latest complete scan older than ``stale_hours``, or none complete) |
    ``failed`` (the newest scan failed, so the data shown is older than the last attempt)."""
    now = now or utcnow()
    newest = next(iter(store.list_scans(s, 1)), None)
    if newest is None:
        return {"state": "none"}
    done = store.latest_scan(s)
    out: dict[str, Any] = {"state": "ok", "stale_hours": stale_hours, "scan_id": None, "age_text": None, "mode": None, "age_hours": None, "failed_reason": None}
    if done is not None:
        when = done.finished_at or done.started_at
        age = now - when
        out.update(scan_id=done.id, mode=done.mode, age_text=humanize_age(age), age_hours=round(age.total_seconds() / 3600, 1))
        if age > timedelta(hours=stale_hours):
            out["state"] = "stale"
    else:
        out["state"] = "stale"
    if newest.status == "failed" and (done is None or newest.started_at > done.started_at):
        out["state"] = "failed"
        err = (newest.summary or {}).get("error")
        out["failed_reason"] = str(err)[:160] if err else None
        out["failed_age_text"] = humanize_age(now - (newest.finished_at or newest.started_at))
    return out


def project_of(repo_key: str) -> str:
    return repo_key.split("/", 1)[0]


def platform_kinds(row: RepoResultRow) -> list[str]:
    return sorted({("gha" if p == "gha" else "classic" if "classic" in p else "yaml") for p in row.platform_mix})


def provider_of_row(r: RepoResultRow) -> str:
    """Hosting provider of the repo (azure_repos | github | github_enterprise | other_git); scans before L1 are Azure Repos."""
    return ((r.external or {}).get("repo") or {}).get("provider") or "azure_repos"


def multi_host(s: Session, scan: ScanRow | None) -> bool:
    """More than one code host in the scan: only then are provider badges and the "Code hosted on" filter shown."""
    if scan is None:
        return False
    prov = (scan.summary or {}).get("providers")
    if prov is None:  # scans made before G1 did not record it
        prov = sorted({provider_of_row(r) for r in store.repo_results(s, scan.id)})
    return len(prov) > 1


WHY_TOP = 3  # reasons shown in compact tables


def reasons_of_row(r: RepoResultRow) -> dict[str, Any]:
    """The persisted ``{"items", "fail", "warn", "unknown"}`` (scans made before G1 have none: empty)."""
    got = (r.external or {}).get("reasons")
    return got if isinstance(got, dict) and "items" in got else empty_reasons()


def row_dict(r: RepoResultRow) -> dict[str, Any]:
    kinds = platform_kinds(r)
    prov = provider_of_row(r)
    rs = reasons_of_row(r)
    return {
        "key": r.repo_key, "project": r.project, "repo": r.repo, "owner": r.owner, "url": r.url,
        "provider": prov, "provider_label": PROVIDER_LABEL.get(prov, prov),
        "platforms": [PLATFORM_LABEL.get(p, p) for p in r.platform_mix], "platform_kinds": kinds or ["none"],
        "targets": r.targets, "test_state": r.test_state, "coverage": r.coverage, "sonar_gate": r.sonar_gate,
        "aikido_criticals": r.aikido_criticals, "score": r.score, "status": r.status, "unknowns": r.unknowns,
        "critical_fails": r.critical_fails, "high_fails": r.high_fails, "migration_score": r.migration_score,
        "migration_status": migration_status(list(r.platform_mix)), "migration_label": MIGRATION_LABEL[migration_status(list(r.platform_mix))],
        "reasons": rs["items"], "reason_counts": {"fail": rs["fail"], "warn": rs["warn"], "unknown": rs["unknown"]},
        "why": rs["items"][:WHY_TOP], "why_more": max(0, len(rs["items"]) - WHY_TOP),
    }


# ------------------------------------------------------------------ repos
def _repo_sort_value(r: dict[str, Any], sort: str) -> Any:
    """Sort value of a repo row; ``None`` (unknown / not applicable) sorts last in both directions."""
    if sort == "status":
        return STATUS_RANK.get(r["status"], 9)
    if sort in ("platforms", "targets"):
        return len(r[sort])
    if sort == "migration_status":
        return MIGRATION_RANK.get(r["migration_status"], 9)
    return text_key(r[sort])


def repos(s: Session, scan_id: str, *, project: str | None = None, status: str | None = None, test_state: str | None = None,
          platform: str | None = None, target: str | None = None, sonar: str | None = None, q: str | None = None,
          provider: str | None = None, rule: str | None = None, owner: str | None = None, migration: str | None = None,
          sort: str = "status", direction: str = "asc") -> list[dict[str, Any]]:
    results = store.repo_results(s, scan_id)
    if rule:  # repos where this rule fails (the "Top reasons" drill-down)
        results = [r for r in results if (r.rule_status or {}).get(rule) == "FAIL"]
    rows = [row_dict(r) for r in results]

    def keep(r: dict[str, Any]) -> bool:
        if project and r["project"] != project:
            return False
        if status and r["status"] != status:
            return False
        if provider and r["provider"] != provider:
            return False
        if test_state and r["test_state"] != test_state:
            return False
        if platform and platform not in r["platform_kinds"]:
            return False
        if target and target not in r["targets"]:
            return False
        if sonar and (r["sonar_gate"] or "none") != sonar:
            return False
        if owner and (r["owner"] or NO_OWNER) != owner:
            return False
        if migration and r["migration_status"] != migration:
            return False
        if q and q.lower() not in f"{r['repo']} {r['owner'] or ''} {r['project']}".lower():
            return False
        return True

    rows = [r for r in rows if keep(r)]
    sort = sort if sort in SORTABLE else "status"
    secondary = (lambda r: (r["score"] if r["score"] is not None else 101, r["project"].lower(), r["repo"].lower())) if sort == "status" else (lambda r: (r["project"].lower(), r["repo"].lower()))
    return sort_rows(rows, lambda r: _repo_sort_value(r, sort), direction, secondary)


def reasons_text(items: list[dict[str, Any]]) -> str:
    """Semicolon-separated reasons for CSV/XLSX cells (``<RULE-ID> <short title>: <message>``)."""
    return "; ".join(i["text"] for i in items)


def csv_rows(rows: list[dict[str, Any]]) -> list[list[Any]]:
    head = ["project", "repo", "provider", "owner", "platforms", "targets", "test_state", "coverage", "sonar_gate", "aikido_criticals", "score", "status", "critical_fails", "high_fails", "unknowns", "migration_score", "reasons"]
    out: list[list[Any]] = [head]
    for r in rows:
        out.append([r["project"], r["repo"], r["provider"], r["owner"] or "", "+".join(r["platforms"]), "+".join(r["targets"]), r["test_state"],
                    "" if r["coverage"] is None else round(r["coverage"], 1), r["sonar_gate"] or "", "" if r["aikido_criticals"] is None else r["aikido_criticals"],
                    "" if r["score"] is None else r["score"], r["status"], r["critical_fails"], r["high_fails"], r["unknowns"],
                    "" if r["migration_score"] is None else r["migration_score"], reasons_text(r["reasons"])])
    return out


# ------------------------------------------------------------------ rule stats
def policy_effects(s: Session, scan_id: str) -> dict[str, Any]:
    """What policy.yaml did in this scan (``{"disabled": [...], "severity": {id: {from, to}}}``); empty for older scans."""
    row = store.get_scan(s, scan_id)
    return dict((row.summary or {}).get("policy") or {}) if row else {}


def rule_stats(s: Session, scan_id: str, rows: list[RepoResultRow] | None = None) -> list[dict[str, Any]]:
    """Per-rule status counts across repos (worst finding per repo/rule)."""
    rows = rows if rows is not None else store.repo_results(s, scan_id)
    eff = policy_effects(s, scan_id)
    disabled = set(eff.get("disabled", []))
    sev_over = eff.get("severity", {})
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for r in rows:
        for rid, st in (r.rule_status or {}).items():
            counts[rid][st] += 1
    out = []
    for meta in all_rules():
        c = counts.get(meta.id, Counter())
        scored = c["PASS"] + c["FAIL"] + c["WARN"]
        out.append({
            "id": meta.id, "title": meta.title, "category": meta.category, "category_name": meta.category_name,
            "severity": sev_over.get(meta.id, {}).get("to", meta.severity.value), "severity_default": sev_over[meta.id]["from"] if meta.id in sev_over else None,
            "disabled": meta.id in disabled, "scope": meta.scope, "pass": c["PASS"], "fail": c["FAIL"], "warn": c["WARN"], "unknown": c["UNKNOWN"], "waived": c["WAIVED"],
            "applicable": scored + c["UNKNOWN"] + c["WAIVED"],
            "pass_rate": round(100 * (c["PASS"] + 0.5 * c["WARN"]) / scored, 1) if scored else None,
        })
    return out


def rules_table(stats: list[dict[str, Any]], *, category: str | None = None, severity: str | None = None, failing: str | None = None, q: str | None = None,
                sort: str = "default", direction: str = "asc") -> list[dict[str, Any]]:
    """Filter and sort the rule catalog rows. ``default`` keeps the catalog order (grouped by category on the page)."""
    rows = [r for r in stats
            if (not category or r["category"] == category) and (not severity or r["severity"] == severity) and (failing != "1" or r["fail"])
            and (not q or q.lower() in f"{r['id']} {r['title']}".lower())]
    if sort == "default":
        return rows if direction == "asc" else rows[::-1]
    sev_rank = {"severity": lambda r: SEV_RANK.get(r["severity"], 9)}
    key = sev_rank.get(sort, lambda r: text_key(r[sort]))
    return sort_rows(rows, key, direction, lambda r: r["id"])


def rule_detail(s: Session, scan_id: str, rule_id: str) -> dict[str, Any] | None:
    meta = rule_index().get(rule_id)
    if not meta:
        return None
    stats = next(x for x in rule_stats(s, scan_id) if x["id"] == rule_id)
    eff = policy_effects(s, scan_id)
    fs = store.findings(s, scan_id, rule_id=rule_id)
    fs.sort(key=lambda f: (FINDING_RANK.get(f.status, 9), f.repo_key))
    prov = provider_map(s, scan_id)
    return {
        "rule": {"id": meta.id, "title": meta.title, "category": meta.category, "category_name": meta.category_name, "severity": stats["severity"],
                 "severity_default": stats["severity_default"], "disabled": stats["disabled"], "params": meta.params, "scope": meta.scope, "rationale": meta.rationale, "remediation": meta.remediation,
                 "platforms": sorted(meta.platforms or []), "targets": sorted(meta.targets or []), "tiers": sorted(meta.tiers or [])},
        "stats": stats,
        "findings": [finding_dict(f, providers=prov, eff=eff) for f in fs if f.status != "PASS"][:500],
        "passing_repos": sorted({f.repo_key for f in fs if f.status == "PASS"}),
    }


def provider_map(s: Session, scan_id: str) -> dict[str, str]:
    return {r.repo_key: provider_of_row(r) for r in store.repo_results(s, scan_id)}


def finding_dict(f: FindingRow, meta: dict[str, RuleMeta] | None = None, platform: str | None = None, providers: dict[str, str] | None = None,
                 eff: dict[str, Any] | None = None) -> dict[str, Any]:
    meta = meta or rule_index()
    over = ((eff or {}).get("severity") or {}).get(f.rule_id)
    m = meta.get(f.rule_id)
    return {
        "rule_id": f.rule_id, "title": m.title if m else "Collection error", "category": f.category,
        "category_name": CATEGORY_NAMES.get(f.category, "System"), "severity": f.severity, "severity_default": over["from"] if over else None, "status": f.status, "repo_key": f.repo_key,
        "project": project_of(f.repo_key), "provider": (providers or {}).get(f.repo_key, "azure_repos"), "pipeline_id": f.pipeline_id, "pipeline_name": f.pipeline_name, "stage": f.stage, "message": f.message,
        "evidence": f.evidence or {}, "link": f.link, "waiver": f.waiver, "original_status": f.original_status,
        "rationale": m.rationale if m else "", "remediation": m.remediation_for(platform) if m else "",
    }


FINDING_SORT = ("severity", "status", "rule", "category", "repo", "pipeline", "message")


def _finding_order(sort: str, direction: str) -> list[Any]:
    """ORDER BY clauses (portable: CASE ranks, no dialect functions). The default (severity, then status) keeps the worst first."""
    sev = case(SEV_RANK, value=FindingRow.severity, else_=9)
    st = case(FINDING_RANK, value=FindingRow.status, else_=9)
    cols: dict[str, list[Any]] = {
        "severity": [sev, st], "status": [st, sev], "rule": [FindingRow.rule_id], "category": [FindingRow.category, sev],
        "repo": [FindingRow.repo_key], "pipeline": [FindingRow.pipeline_name, FindingRow.stage], "message": [FindingRow.message],
    }
    first = cols.get(sort, cols["severity"])
    keys = [(c.desc() if direction == "desc" else c.asc()) for c in first]
    if sort not in ("severity", "status"):
        keys += [sev, st]
    return [*keys, FindingRow.repo_key, FindingRow.rule_id, FindingRow.id]


def findings_list(s: Session, scan_id: str, *, project: str | None = None, category: str | None = None, rule: str | None = None,
                  status: str | None = None, severity: str | None = None, repo_key: str | None = None, pipeline: str | None = None, stage: str | None = None,
                  limit: int = 200, offset: int = 0, sort: str = "severity", direction: str = "asc") -> dict[str, Any]:
    q = select(FindingRow).where(FindingRow.scan_id == scan_id)
    if project:
        q = q.where(FindingRow.repo_key.startswith(f"{project}/", autoescape=True))  # "%" / "_" are literals, not wildcards
    if category:
        q = q.where(FindingRow.category == category)
    if rule:
        q = q.where(FindingRow.rule_id == rule)
    if status:
        q = q.where(FindingRow.status == status)
    if severity:
        q = q.where(FindingRow.severity == severity)
    if repo_key:
        q = q.where(FindingRow.repo_key == repo_key)
    if pipeline:
        q = q.where(FindingRow.pipeline_name == pipeline)
    if stage:
        q = q.where(FindingRow.stage == stage)
    total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = list(s.scalars(q.order_by(*_finding_order(sort, direction)).offset(offset).limit(limit)))
    meta = rule_index()
    prov = provider_map(s, scan_id)
    eff = policy_effects(s, scan_id)
    return {"total": total, "limit": limit, "offset": offset, "items": [finding_dict(f, meta, providers=prov, eff=eff) for f in rows]}


# ------------------------------------------------------------------ overview
def trend(s: Session) -> list[dict[str, Any]]:
    out = []
    scans = [x for x in store.list_scans(s, 100) if x.status == "complete"]
    scans.sort(key=lambda x: x.started_at)
    agg = {sid: (n, avg) for sid, n, avg in s.execute(select(RepoResultRow.scan_id, func.count(), func.avg(RepoResultRow.score)).group_by(RepoResultRow.scan_id))}
    by: dict[str, Counter[str]] = defaultdict(Counter)
    for sid, st, n in s.execute(select(RepoResultRow.scan_id, RepoResultRow.status, func.count()).group_by(RepoResultRow.scan_id, RepoResultRow.status)):
        by[sid][st] = n
    for sc in scans:
        total = agg.get(sc.id, (0, 0))[0] or 1
        out.append({
            "scan_id": sc.id, "date": sc.started_at.strftime("%Y-%m-%d"), "repos": agg.get(sc.id, (0, 0))[0],
            "compliant_pct": round(100 * by[sc.id]["COMPLIANT"] / total, 1), "at_risk_pct": round(100 * by[sc.id]["AT_RISK"] / total, 1),
            "non_compliant_pct": round(100 * by[sc.id]["NON_COMPLIANT"] / total, 1), "avg_score": round(agg.get(sc.id, (0, 0))[1] or 0, 1),
        })
    return out


def top_reasons(rows: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    """Most common failing rules across repos: ``{rule_id, label, severity, repos}`` (drill-down: /repos?rule=ID, /findings?rule=ID)."""
    cnt: Counter[str] = Counter()
    first: dict[str, dict[str, Any]] = {}
    for r in rows:
        for i in r["reasons"]:
            cnt[i["rule_id"]] += 1
            first.setdefault(i["rule_id"], i)
    ranked = sorted(cnt.items(), key=lambda kv: (-kv[1], SEV_RANK.get(first[kv[0]]["severity"], 9), kv[0]))[:limit]
    return [{"rule_id": rid, "label": first[rid]["label"], "title": first[rid]["title"], "severity": first[rid]["severity"], "repos": n} for rid, n in ranked]


STATUS_KEYS = ("COMPLIANT", "AT_RISK", "NON_COMPLIANT")
SEVERITIES = ("critical", "high", "medium", "low")
MAX_PROJECT_BARS = 30
MAX_OWNER_BARS = 15


def breakdown(rows: list[dict[str, Any]], key: str, limit: int) -> dict[str, Any]:
    """Repos per ``key`` (project / owner) split by compliance status, for the stacked bars: biggest groups first, ``more`` = groups cut off."""
    groups: dict[str, Counter[str]] = defaultdict(Counter)
    for r in rows:
        groups[(r[key] or NO_OWNER) if key == "owner" else r[key]][r["status"]] += 1
    ranked = sorted(groups.items(), key=lambda kv: (-sum(kv[1].values()), kv[0].lower()))
    items = [{"name": name, "total": sum(c.values()), "compliant": c["COMPLIANT"], "at_risk": c["AT_RISK"], "non_compliant": c["NON_COMPLIANT"], "not_scanned": c["NOT_SCANNED"]}
             for name, c in ranked[:limit]]
    return {"items": items, "more": max(0, len(ranked) - limit)}


def noncompliant_list(rows: list[dict[str, Any]], limit: int = 15) -> list[dict[str, Any]]:
    """The worst NON_COMPLIANT repos (lowest score first) with their top reasons."""
    bad = [r for r in rows if r["status"] == "NON_COMPLIANT"]
    bad.sort(key=lambda r: (r["score"] if r["score"] is not None else 101, r["project"], r["repo"]))
    return [{k: r[k] for k in ("key", "project", "repo", "score", "status", "why", "why_more")} for r in bad[:limit]]


def overview(s: Session, scan_id: str) -> dict[str, Any]:
    rows = store.repo_results(s, scan_id)
    row_dicts = [row_dict(r) for r in rows]
    total = len(rows) or 1
    status_counts = Counter(r.status for r in rows)
    crit = s.scalar(select(func.count()).select_from(FindingRow).where(FindingRow.scan_id == scan_id, FindingRow.severity == "critical", FindingRow.status == "FAIL")) or 0
    stats = rule_stats(s, scan_id, rows)
    top = sorted([x for x in stats if x["fail"]], key=lambda x: (-x["fail"], x["id"]))[:10]
    projects = sorted({r.project for r in rows})
    cats = list(CATEGORY_NAMES)
    cell: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for repo_key, category, status, n in s.execute(
        select(FindingRow.repo_key, FindingRow.category, FindingRow.status, func.count()).where(FindingRow.scan_id == scan_id).group_by(FindingRow.repo_key, FindingRow.category, FindingRow.status)
    ):
        cell[(category, project_of(repo_key))][status] += n
    heat = []
    for c in cats:
        line = []
        for p in projects:
            cc = cell.get((c, p), Counter())
            scored = cc["PASS"] + cc["FAIL"] + cc["WARN"]
            line.append({"project": p, "category": c, "rate": round(100 * (cc["PASS"] + 0.5 * cc["WARN"]) / scored, 1) if scored else None, "fails": cc["FAIL"]})
        heat.append({"category": c, "name": CATEGORY_NAMES[c], "cells": line})
    sev = Counter(dict(s.execute(select(FindingRow.severity, func.count()).where(FindingRow.scan_id == scan_id, FindingRow.status == "FAIL").group_by(FindingRow.severity)).tuples().all()))
    mig = Counter(d["migration_status"] for d in row_dicts)
    classic_repos = sum(1 for r in rows if any("classic" in p for p in r.platform_mix))
    classic_pipes = sum(1 for r in rows for p in r.pipelines if p["platform"].startswith("ado_classic"))
    return {
        "kpis": {
            "repos": len(rows), "compliant": status_counts["COMPLIANT"], "compliant_pct": round(100 * status_counts["COMPLIANT"] / total, 1),
            "critical_findings": crit, "no_tests": sum(1 for r in rows if r.test_state == "NO_TESTS"), "classic_repos": classic_repos,
            "classic_pipelines": classic_pipes, "avg_score": round(sum(r.score or 0 for r in rows) / total, 1),
        },
        "status_counts": {k: status_counts.get(k, 0) for k in ("COMPLIANT", "AT_RISK", "NON_COMPLIANT")}, "not_scanned": status_counts.get("NOT_SCANNED", 0),
        "top_rules": top, "heatmap": heat, "projects": projects, "trend": trend(s),
        "top_reasons": top_reasons(row_dicts), "noncompliant": noncompliant_list(row_dicts),
        "by_project": breakdown(row_dicts, "project", MAX_PROJECT_BARS), "by_owner": breakdown(row_dicts, "owner", MAX_OWNER_BARS),
        "severity_counts": {k: sev.get(k, 0) for k in SEVERITIES},
        "migration_states": [{"key": k, "label": MIGRATION_LABEL[k], "repos": mig.get(k, 0)} for k in ("ado_only", "in_progress", "migrated")],
        "no_pipeline_repos": mig.get("none", 0),
    }


# ------------------------------------------------------------------ testing
def testing(s: Session, scan_id: str) -> dict[str, Any]:
    rows = store.repo_results(s, scan_id)
    counts = Counter(r.test_state for r in rows)
    lists = {st: [row_dict(r) | {"reason": r.test_state_reason} for r in rows if r.test_state == st] for st in ("NO_TESTS", "TESTS_NOT_RUN", "TESTS_NO_COVERAGE", "TESTS_LOW_COVERAGE", "UNKNOWN")}
    for v in lists.values():
        v.sort(key=lambda r: (r["project"], r["repo"]))
    buckets: Counter[int] = Counter()
    for r in rows:
        if r.coverage is not None:
            buckets[min(int(r.coverage // 10) * 10, 90)] += 1
    stats = [x for x in rule_stats(s, scan_id, rows) if x["category"] == "TST"]
    return {"counts": {st: counts.get(st, 0) for st in TEST_STATES}, "lists": lists, "coverage_buckets": {f"{b}-{b + 10}": buckets.get(b, 0) for b in range(0, 100, 10)}, "rules": stats, "total": len(rows)}


# ------------------------------------------------------------------ targets
def targets(s: Session, scan_id: str) -> dict[str, Any]:
    rows = store.repo_results(s, scan_id)
    stats_all = {x["id"]: x for x in rule_stats(s, scan_id, rows)}
    out = []
    for t in TARGETS:
        trs = [r for r in rows if t in r.targets]
        code = TARGET_RULE_CODE[t]
        trules: list[dict[str, Any]] = []
        for rid, meta in rule_index().items():
            if rid.startswith(f"TGT-{code}-"):
                c: Counter[str] = Counter(r.rule_status.get(rid, "") for r in trs)
                scored = c["PASS"] + c["FAIL"] + c["WARN"]
                trules.append({"id": rid, "title": meta.title, "severity": meta.severity.value, "pass": c["PASS"], "fail": c["FAIL"], "warn": c["WARN"],
                               "pass_rate": round(100 * (c["PASS"] + 0.5 * c["WARN"]) / scored, 1) if scored else None})
        common: Counter[str] = Counter()
        for r in trs:
            for rid, st in r.rule_status.items():
                if st == "FAIL" and not rid.startswith("TGT-"):
                    common[rid] += 1
        out.append({
            "target": t, "label": TARGET_LABEL[t], "repos": len(trs), "pipelines": sum(1 for r in trs for p in r.pipelines if t in {x for st in p["stages"] for x in st["deploy_targets"]}),
            "avg_score": round(sum(r.score or 0 for r in trs) / len(trs), 1) if trs else None,
            "non_compliant": sum(1 for r in trs if r.status == "NON_COMPLIANT"), "rules": trules,
            "top_failures": [{"id": k, "title": rule_index()[k].title if k in rule_index() else k, "repos": v} for k, v in common.most_common(5)],
        })
    return {"targets": out, "rule_stats": [stats_all[k] for k in stats_all if k.startswith("TGT-")]}


# ------------------------------------------------------------------ migration
def migration(s: Session, scan_id: str, state: str | None = None) -> dict[str, Any]:
    rows = store.repo_results(s, scan_id)
    plat: Counter[str] = Counter()
    for r in rows:
        for p in r.pipelines:
            plat[p["platform"]] += 1
    buckets: Counter[str] = Counter()
    blockers: Counter[str] = Counter()
    for r in rows:
        if r.migration_score is not None:
            buckets[("75-100" if r.migration_score >= 75 else "50-74" if r.migration_score >= 50 else "25-49" if r.migration_score >= 25 else "0-24")] += 1
        for b in r.migration_blockers:
            key = b.split(":")[0] if "tasks without" in b else b
            blockers[key] += 1
    task_gaps: Counter[str] = Counter()
    for r in rows:
        for b in r.migration_blockers:
            if b.startswith("tasks without"):
                for t in b.split(": ", 1)[1].split(", "):
                    task_gaps[t] += 1
    row_dicts = [row_dict(r) for r in rows]
    states = Counter(d["migration_status"] for d in row_dicts)
    state = state if state in MIGRATION_LABEL else None
    retire: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        for c in ((r.external or {}).get("migration") or {}).get("retire_candidates", []):
            retire.setdefault(r.repo_key, []).append(c)
    listed = [d | {"retire": retire.get(d["key"], [])} for d in row_dicts if state is None or d["migration_status"] == state]
    listed.sort(key=lambda d: (d["project"], d["repo"]))
    ready = sorted([row_dict(r) for r in rows if r.migration_score is not None], key=lambda x: (x["migration_score"], x["repo"]))
    return {
        "states": {k: states.get(k, 0) for k in MIGRATION_LABEL}, "state_labels": MIGRATION_LABEL, "state": state, "repos": listed[:300], "repos_more": max(0, len(listed) - 300),
        "retire_total": sum(len(v) for v in retire.values()), "gha_total": plat.get("gha", 0),
        "platforms": {PLATFORM_LABEL.get(k, k): v for k, v in plat.items()}, "classic_total": sum(v for k, v in plat.items() if k.startswith("ado_classic")),
        "yaml_total": plat.get("ado_yaml", 0), "no_pipeline_repos": sum(1 for r in rows if not r.pipelines),
        "buckets": {k: buckets.get(k, 0) for k in ("0-24", "25-49", "50-74", "75-100")},
        "blockers": [{"blocker": k, "repos": v} for k, v in blockers.most_common(10)], "task_gaps": [{"task": k, "repos": v} for k, v in task_gaps.most_common(10)],
        "hardest": ready[:25], "easiest": list(reversed(ready))[:10],
        "avg": round(sum(r["migration_score"] for r in ready) / len(ready), 1) if ready else None,
    }


# ------------------------------------------------------------------ scans
def scans(s: Session, selected: str | None = None) -> dict[str, Any]:
    items = store.list_scans(s, 100)
    sel = selected or (items[0].id if items else None)
    errs = [{"source": e.source, "subject": e.subject, "message": e.message} for e in store.collection_errors(s, sel)] if sel else []
    err_counts = Counter(e["source"] for e in errs)
    return {
        "scans": [{"id": x.id, "started_at": x.started_at.isoformat(timespec="seconds"), "mode": x.mode, "status": x.status, "repos": x.repos_total, "failed": x.repos_failed,
                   "findings": x.findings_total, "duration_s": x.duration_s, "summary": x.summary} for x in items],
        "selected": sel, "errors": errs, "error_counts": dict(err_counts),
    }


# ------------------------------------------------------------------ repo detail
FIX_FIRST = 8
MAX_REPO_TREND = 60


def fix_first(categories: list[dict[str, Any]], eff: dict[str, Any], limit: int = FIX_FIRST) -> dict[str, Any]:
    """FAIL findings of a repo grouped by rule and ordered by severity, then category weight (policy ``scoring.category_weights``, default 1), then rule id.

    One entry per rule (``places`` counts the pipelines / stages it fails in), each with its fix hint."""
    weights = eff.get("category_weights") or {}
    by_rule: dict[str, dict[str, Any]] = {}
    for c in categories:
        for f in c["findings"]:
            if f["status"] != "FAIL":
                continue
            e = by_rule.setdefault(f["rule_id"], {"rule_id": f["rule_id"], "title": f["title"], "severity": f["severity"], "severity_default": f["severity_default"],
                                                  "category": f["category"], "category_name": f["category_name"], "message": f["message"], "remediation": f["remediation"],
                                                  "link": f["link"], "places": 0, "where": []})
            e["places"] += 1
            where = f["pipeline_name"] + (f" / {f['stage']}" if f["stage"] else "") if f["pipeline_name"] else ""
            if where and where not in e["where"] and len(e["where"]) < 3:
                e["where"].append(where)
    ranked = sorted(by_rule.values(), key=lambda e: (SEV_RANK.get(e["severity"], 9), -float(weights.get(e["category"], 1.0)), e["rule_id"]))
    return {"items": ranked[:limit], "total": len(ranked), "shown": min(limit, len(ranked))}


def repo_trend(s: Session, repo_key: str, limit: int = MAX_REPO_TREND) -> list[dict[str, Any]]:
    """Score and status of one repo across the complete scans (oldest first), for the small line chart."""
    q = (select(ScanRow.id, ScanRow.started_at, ScanRow.mode, RepoResultRow.score, RepoResultRow.status, RepoResultRow.critical_fails, RepoResultRow.high_fails)
         .join(RepoResultRow, RepoResultRow.scan_id == ScanRow.id).where(RepoResultRow.repo_key == repo_key, ScanRow.status == "complete")
         .order_by(ScanRow.started_at.desc()).limit(limit))
    rows = [{"scan_id": sid, "date": started.strftime("%Y-%m-%d"), "mode": mode, "score": score, "status": st, "critical_fails": cf, "high_fails": hf}
            for sid, started, mode, score, st, cf, hf in s.execute(q).tuples().all()]
    rows.reverse()
    return rows


def repo_detail(s: Session, scan_id: str, project: str, repo: str) -> dict[str, Any] | None:
    key = f"{project}/{repo}"
    r = store.repo_result(s, scan_id, key)
    if r is None:
        return None
    meta = rule_index()
    platform_hint = "ado_yaml" if any(p["platform"] == "ado_yaml" for p in r.pipelines) else "ado_classic_release"
    pipe_platform = {p["id"]: p["platform"] for p in r.pipelines}
    fs = store.findings(s, scan_id, repo_key=key)
    eff = policy_effects(s, scan_id)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    cat_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for f in fs:
        d = finding_dict(f, meta, pipe_platform.get(f.pipeline_id or "", platform_hint), {key: provider_of_row(r)}, eff)
        groups[f.category].append(d)
        cat_counts[f.category][f.status] += 1
    for lst in groups.values():
        lst.sort(key=lambda d: (FINDING_RANK.get(d["status"], 9), SEV_RANK.get(d["severity"], 9), d["rule_id"], d["stage"] or ""))
    order = [c for c in CATEGORY_NAMES if c in groups] + [c for c in groups if c not in CATEGORY_NAMES]
    categories = []
    for c in order:
        cc = cat_counts[c]
        scored = cc["PASS"] + cc["FAIL"] + cc["WARN"]
        categories.append({"code": c, "name": CATEGORY_NAMES.get(c, "System"), "counts": dict(cc), "rate": round(100 * (cc["PASS"] + 0.5 * cc["WARN"]) / scored, 1) if scored else None, "findings": groups[c]})
    ext = r.external or {}
    facts = r.facts or {}
    retire = {c["id"]: c["reason"] for c in (ext.get("migration") or {}).get("retire_candidates", [])}
    pipelines = [p | {"badge": PLATFORM_BADGE.get(p["platform"], p["platform"]), "retire_reason": retire.get(p["id"])} for p in r.pipelines]
    return {"repo": row_dict(r) | {"reason": r.test_state_reason, "migration_blockers": r.migration_blockers}, "facts": facts,
            "repo_checks_unavailable": facts.get("facts_source") == "unavailable", "repo_checks_reason": facts.get("facts_reason", ""), "pipelines": pipelines,
            "categories": categories, "sonar": ext.get("sonar"), "aikido": ext.get("aikido"), "policies": ext.get("policies"),
            "fix_first": fix_first(categories, eff), "trend": repo_trend(s, key)}


def filter_options(s: Session, scan_id: str) -> dict[str, Any]:
    rows = store.repo_results(s, scan_id)
    return {"projects": sorted({r.project for r in rows}), "providers": sorted({provider_of_row(r) for r in rows}), "provider_labels": PROVIDER_LABEL, "targets": TARGETS, "test_states": TEST_STATES, "statuses": ["NON_COMPLIANT", "AT_RISK", "COMPLIANT", "NOT_SCANNED"]}


def meta_counts(s: Session) -> dict[str, int]:
    return {"scans": s.scalar(select(func.count()).select_from(ScanRow)) or 0, "errors": s.scalar(select(func.count()).select_from(CollectionErrorRow)) or 0}
