"""Rule runner: evaluates the registry against a RepoContext and returns findings."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from pch.engine.registry import RuleMeta, all_rules
from pch.model.findings import Finding, RuleResult, Status
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


def _finding(meta: RuleMeta, ctx: RepoContext, res: RuleResult, p: Pipeline | None, st: Stage | None) -> Finding:
    return Finding(
        rule_id=meta.id,
        repo_key=ctx.repo.key,
        category=meta.category,
        severity=meta.severity,
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
    out: list[Finding] = []
    if meta.scope == "repo":
        if _repo_matches(meta, ctx):
            res = _call(meta, ctx, policy, None)
            if res.status != Status.NOT_APPLICABLE:
                out.append(_finding(meta, ctx, res, None, None))
    elif meta.scope == "pipeline":
        for p in ctx.pipelines:
            if not _pipeline_matches(meta, p):
                continue
            res = _call(meta, ctx, policy, p)
            if res.status != Status.NOT_APPLICABLE:
                out.append(_finding(meta, ctx, res, p, None))
    else:
        for p in ctx.pipelines:
            if meta.platforms and p.platform not in meta.platforms:
                continue
            for st in p.stages:
                if not _stage_matches(meta, st):
                    continue
                res = _call(meta, ctx, policy, StageTarget(p, st))
                if res.status != Status.NOT_APPLICABLE:
                    out.append(_finding(meta, ctx, res, p, st))
    return out


def evaluate(ctx: RepoContext, policy: Policy, rules: list[RuleMeta] | None = None) -> list[Finding]:
    """Evaluate all (or the given) rules. NOT_APPLICABLE results are dropped."""
    findings: list[Finding] = []
    for meta in rules if rules is not None else all_rules():
        findings.extend(evaluate_rule(meta, ctx, policy))
    return findings
