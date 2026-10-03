"""HYG: pipeline hygiene."""

from __future__ import annotations

from datetime import timedelta

from pch.engine.registry import rule
from pch.model.findings import RuleResult
from pch.model.pipeline import Pipeline
from pch.model.repo import RepoContext
from pch.settings import Policy


@rule("HYG-001", "Pipeline had a successful run recently (not stale)", "low", "pipeline",
      "Pipelines that have not succeeded in 90 days are likely abandoned and still hold permissions.",
      {"any": "Delete or disable abandoned pipelines; revoke their service connection access."})
def hyg_001(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    st = p.run_stats_90d
    if st is None:
        return RuleResult.unknown("run history was not collected")
    if st.last_success and ctx.now - st.last_success <= timedelta(days=policy.stale_pipeline_days):
        return RuleResult.passed("recent successful run", last_success=st.last_success.isoformat())
    return RuleResult.failed(f"no successful run in the last {policy.stale_pipeline_days} days", total_runs=st.total)


@rule("HYG-002", "Success rate over 90 days is at least 80%", "low", "pipeline",
      "Chronically failing pipelines are ignored by their owners and hide real failures.",
      {"any": "Fix flaky tests/steps or retire the pipeline."})
def hyg_002(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    st = p.run_stats_90d
    if st is None:
        return RuleResult.unknown("run history was not collected")
    if st.total == 0:
        return RuleResult.na("no runs in the period (see HYG-001)")
    rate = st.success_rate or 0.0
    ev = {"success_rate": round(rate, 3), "runs": st.total, "failed": st.failed}
    if rate >= policy.min_success_rate:
        return RuleResult.passed(f"success rate {rate:.0%}", **ev)
    return RuleResult.failed(f"success rate {rate:.0%} < {policy.min_success_rate:.0%}", **ev)


@rule("HYG-003", "An owner is identified", "info", "pipeline",
      "Someone must be reachable when the pipeline needs attention.",
      {"any": "Set the repo owner in config/scope.yaml (owner) or keep a named pipeline author."})
def hyg_003(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    owner = ctx.repo.owner or p.owner
    if owner:
        return RuleResult.passed("owner identified", owner=owner)
    return RuleResult.failed("no owner identified in scope.yaml or on the pipeline")
