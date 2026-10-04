"""Why is this repo not compliant? A short, ordered list of reasons computed once per repo and scan from its findings.

Persisted in ``repo_results.external_summary["reasons"]`` (an existing JSON column), so pages, exports and the JSON API
read it instead of recomputing from findings. Only rule ids, titles, severities and finding messages are stored (findings
are already redacted before they reach this point)."""

from __future__ import annotations

import re
from typing import Any

from pch.engine.registry import RuleMeta, all_rules
from pch.engine.scoring import aggregate_rule_status
from pch.model.findings import SEVERITY_ORDER, Finding, Status

LABEL_MAX = 64
MESSAGE_MAX = 220
_SEV_RANK = {s.value: i for i, s in enumerate(SEVERITY_ORDER)}
_PARENS = re.compile(r"\s*\([^)]*\)")


def short_title(title: str, limit: int = LABEL_MAX) -> str:
    """Rule title without parenthetical detail, cut at ``limit`` characters."""
    t = _PARENS.sub("", title).strip() or title
    return t if len(t) <= limit else t[: limit - 1].rstrip() + "…"


def _clip(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def empty_reasons() -> dict[str, Any]:
    return {"items": [], "fail": 0, "warn": 0, "unknown": 0}


def compute_reasons(findings: list[Finding], rules: list[RuleMeta] | None = None) -> dict[str, Any]:
    """``{"items": [...], "fail": n, "warn": n, "unknown": n}``.

    ``items``: one entry per FAILING rule (waived findings are not FAIL), ordered critical, high, medium, low, info and then by
    rule id, each ``{rule_id, title, severity, count, message, text, label}``: ``text`` = ``"<RULE-ID> <short title>: <message>"``,
    ``label`` = ``"<RULE-ID> <short title>"`` (compact display), ``count`` = failing findings of that rule (pipelines / stages).
    ``fail`` / ``warn`` / ``unknown`` count rules by their aggregated status (the worst finding wins, as in scoring)."""
    titles = {m.id: m.title for m in (rules if rules is not None else all_rules())}
    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        if f.category != "SYS":  # COLLECTION-ERROR pseudo findings are not rules
            by_rule.setdefault(f.rule_id, []).append(f)
    items: list[dict[str, Any]] = []
    counts = {"fail": 0, "warn": 0, "unknown": 0}
    for rid, fs in by_rule.items():
        agg = aggregate_rule_status([f.status for f in fs])
        if agg == Status.WARN:
            counts["warn"] += 1
        elif agg == Status.UNKNOWN:
            counts["unknown"] += 1
        elif agg == Status.FAIL:
            counts["fail"] += 1
            failing = sorted((f for f in fs if f.status == Status.FAIL), key=lambda f: (f.pipeline_name or "", f.stage or ""))
            title = short_title(titles.get(rid, rid))
            msg = _clip(failing[0].message or "failed", MESSAGE_MAX)
            items.append({
                "rule_id": rid, "title": title, "severity": failing[0].severity.value, "count": len(failing), "message": msg,
                "text": f"{rid} {title}: {msg}", "label": f"{rid} {title}",
            })
    items.sort(key=lambda i: (_SEV_RANK.get(i["severity"], 9), i["rule_id"]))
    return {"items": items, **counts}
