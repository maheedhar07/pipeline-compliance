"""Per-repo scoring, status derivation and waiver application."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date

from pch.model.findings import (
    Finding,
    RepoStatus,
    Severity,
    Status,
    WaiverInfo,
)
from pch.settings import Policy

CREDIT = {Status.PASS: 1.0, Status.WARN: 0.5, Status.FAIL: 0.0}  # WARN credit is policy.scoring.warn_credit
# Precedence used when one rule yields several findings (pipelines/stages) for one repo.
_PRECEDENCE = [
    Status.FAIL,
    Status.WARN,
    Status.PASS,
    Status.WAIVED,
    Status.UNKNOWN,
    Status.NOT_APPLICABLE,
]


@dataclass
class RepoScore:
    score: float | None
    status: RepoStatus
    unknown: int = 0
    by_rule: dict[str, Status] = field(default_factory=dict)
    failing_rules: list[str] = field(default_factory=list)
    critical_fails: int = 0
    high_fails: int = 0


def apply_waivers(findings: list[Finding], repo_key: str, policy: Policy, today: date | None = None) -> None:
    """Turn FAIL (and WARN) findings into WAIVED while a matching waiver is active. Mutates in place."""
    today = today or date.today()
    short = repo_key.split("/", 1)[-1]
    for w in policy.waivers:
        if w.repo not in (repo_key, short, "*"):
            continue
        expired = w.expires is not None and w.expires < today
        info = WaiverInfo(reason=w.reason, owner=w.owner, expires=w.expires, expired=expired)
        for f in findings:
            if f.rule_id != w.rule and w.rule != "*":
                continue
            if f.status not in (Status.FAIL, Status.WARN):
                continue
            f.waiver = info
            if not expired:
                f.original_status = f.status
                f.status = Status.WAIVED


def aggregate_rule_status(statuses: list[Status]) -> Status:
    present = set(statuses)
    for s in _PRECEDENCE:
        if s in present:
            return s
    return Status.NOT_APPLICABLE


def score_repo(findings: list[Finding], policy: Policy | None = None) -> RepoScore:
    """score = 100 * sum(weight*credit) / sum(weight*applicable), one entry per rule (worst finding wins).

    weight = severity weight x category weight, both from ``policy.scoring`` (defaults: 10/5/3/1/0 and 1)."""
    policy = policy or Policy()
    per_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        per_rule[f.rule_id].append(f)

    num = den = 0.0
    unknown = crit = high = 0
    by_rule: dict[str, Status] = {}
    failing: list[str] = []
    for rule_id, fs in per_rule.items():
        agg = aggregate_rule_status([f.status for f in fs])
        by_rule[rule_id] = agg
        sev = fs[0].severity
        if agg == Status.UNKNOWN:
            unknown += 1
        if agg == Status.FAIL:
            failing.append(rule_id)
            if sev == Severity.CRITICAL:
                crit += 1
            elif sev == Severity.HIGH:
                high += 1
        if agg in CREDIT:
            w = policy.scoring.severity_weight(sev) * policy.scoring.category_weight(fs[0].category)
            num += w * (policy.scoring.warn_credit if agg == Status.WARN else CREDIT[agg])
            den += w
    score = round(100.0 * num / den, 1) if den else None
    if crit:
        status = RepoStatus.NON_COMPLIANT
    elif (score is not None and score < policy.compliant_score_threshold) or high:
        status = RepoStatus.AT_RISK
    else:
        status = RepoStatus.COMPLIANT
    return RepoScore(score, status, unknown, by_rule, sorted(failing), crit, high)
