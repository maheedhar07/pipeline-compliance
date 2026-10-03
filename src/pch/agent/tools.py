"""Read-only tool functions for a future MCP server / dashboard chat panel (M10 interface).

They read the latest stored scan only; deterministic rules remain the sole source of pass/fail.
"""

from __future__ import annotations

from typing import Any

from pch.store.db import session_scope
from pch.web import queries as Q


def list_findings(db_url: str, *, project: str | None = None, rule: str | None = None, status: str | None = "FAIL",
                  severity: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    with session_scope(db_url) as s:
        scan = Q.resolve_scan(s, None)
        if scan is None:
            return []
        return Q.findings_list(s, scan.id, project=project, rule=rule, status=status, severity=severity, limit=limit)["items"]


def get_repo(db_url: str, project: str, repo: str) -> dict[str, Any] | None:
    with session_scope(db_url) as s:
        scan = Q.resolve_scan(s, None)
        return Q.repo_detail(s, scan.id, project, repo) if scan else None


def explain_rule(rule_id: str) -> dict[str, Any] | None:
    meta = Q.rule_index().get(rule_id.upper())
    if meta is None:
        return None
    return {"id": meta.id, "title": meta.title, "severity": meta.severity.value, "scope": meta.scope,
            "rationale": meta.rationale, "remediation": meta.remediation}
