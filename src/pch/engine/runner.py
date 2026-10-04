"""Rule runner: evaluates the registry against a RepoContext and returns findings."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from pch.engine.registry import RuleMeta, all_rules
from pch.model.findings import Finding, RuleResult, Severity, Status
from pch.model.pipeline import Pipeline, Stage
from pch.model.repo import RepoContext
from pch.settings import Policy

log = logging.getLogger(__name__)


@dataclass
class StageTarget:
    pipeline: Pipeline
    stage: Stage


def _stage_matches(meta: RuleMeta, stage: Stage) -> bool:
    if meta.tiers and stage.env_tier not in meta.tiers:
        return False
    if meta.targets and not (stage.deploy_targets & meta.targets):
        return False
    return True


def _pipeline_matches(meta: RuleMeta, p: Pipeline) -> bool:
    if meta.platforms and p.platform not in meta.platforms:
        return False
    if meta.targets and not (p.deploy_targets & meta.targets):
        return False
    if meta.tiers and not any(s.env_tier in meta.tiers for s in p.stages):
        return False
    return True


def _repo_matches(meta: RuleMeta, ctx: RepoContext) -> bool:
    if meta.platforms and not any(p.platform in meta.platforms for p in ctx.pipelines):
        return False
    if meta.targets and not any(p.deploy_targets & meta.targets for p in ctx.pipelines):
        return False
    return not (meta.tiers and not any(s.env_tier in meta.tiers for p in ctx.pipelines for s in p.stages))


def effective_severity(meta: RuleMeta, policy: Policy) -> Severity:
    """The rule's severity after ``policy.yaml`` ``rules.<ID>.severity`` (scoring and status use this one)."""
    ov = policy.rules.get(meta.id)
    return ov.severity if ov is not None and ov.severity is not None else meta.severity


def rule_enabled(meta: RuleMeta, policy: Policy) -> bool:
    ov = policy.rules.get(meta.id)
    return ov is None or ov.enabled


def policy_effects(policy: Policy, rules: list[RuleMeta] | None = None) -> dict[str, Any]:
    """What policy.yaml did to the catalog, snapshotted into ``scans.summary["policy"]`` so pages can mark it per scan:
    ``{"disabled": [ids], "severity": {id: {"from": default, "to": effective}}}``."""
    disabled: list[str] = []
    severity: dict[str, dict[str, str]] = {}
    for meta in rules if rules is not None else all_rules():
        if not rule_enabled(meta, policy):
            disabled.append(meta.id)
        elif (eff := effective_severity(meta, policy)) != meta.severity:
            severity[meta.id] = {"from": meta.severity.value, "to": eff.value}
    return {"disabled": sorted(disabled), "severity": severity}


def _finding(meta: RuleMeta, ctx: RepoContext, res: RuleResult, p: Pipeline | None, st: Stage | None, severity: Severity) -> Finding:
    return Finding(
        rule_id=meta.id,
        repo_key=ctx.repo.key,
        category=meta.category,
        severity=severity,
        status=res.status,
        message=res.message,
        pipeline_id=p.id if p else None,
        pipeline_name=p.name if p else None,
        stage=st.name if st else None,
        evidence=res.evidence,
        link=res.link or (p.url if p else ctx.repo.url) or None,
    )


def _call(meta: RuleMeta, ctx: RepoContext, policy: Policy, target: object | None) -> RuleResult:
    try:
        if meta.scope == "repo":
            return meta.fn(ctx, policy)
        return meta.fn(ctx, policy, target)
    except Exception as exc:  # a broken rule must never abort a scan
        log.exception("rule %s crashed", meta.id)
        return RuleResult.unknown(f"rule error: {type(exc).__name__}: {exc}")


def evaluate_rule(meta: RuleMeta, ctx: RepoContext, policy: Policy) -> list[Finding]:
    """Findings of one rule. A rule disabled by policy is not evaluated at all (no findings, not scored)."""
    out: list[Finding] = []
    if not rule_enabled(meta, policy):
        return out
    sev = effective_severity(meta, policy)
    if meta.scope == "repo":
        if _repo_matches(meta, ctx):
            res = _call(meta, ctx, policy, None)
            if res.status != Status.NOT_APPLICABLE:
                out.append(_finding(meta, ctx, res, None, None, sev))
    elif meta.scope == "pipeline":
        for p in ctx.pipelines:
            if not _pipeline_matches(meta, p):
                continue
            res = _call(meta, ctx, policy, p)
            if res.status != Status.NOT_APPLICABLE:
                out.append(_finding(meta, ctx, res, p, None, sev))
    else:
        for p in ctx.pipelines:
            if meta.platforms and p.platform not in meta.platforms:
                continue
            for st in p.stages:
                if not _stage_matches(meta, st):
                    continue
                res = _call(meta, ctx, policy, StageTarget(p, st))
                if res.status != Status.NOT_APPLICABLE:
                    out.append(_finding(meta, ctx, res, p, st, sev))
    return out


def evaluate(ctx: RepoContext, policy: Policy, rules: list[RuleMeta] | None = None) -> list[Finding]:
    """Evaluate all (or the given) rules. NOT_APPLICABLE results are dropped."""
    findings: list[Finding] = []
    for meta in rules if rules is not None else all_rules():
        findings.extend(evaluate_rule(meta, ctx, policy))
    return findings
