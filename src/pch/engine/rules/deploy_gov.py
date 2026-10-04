"""DEP: deployment governance (production stages)."""

from __future__ import annotations

from typing import Any

from pch.collectors.servicenow import change_is_valid, window_covers
from pch.engine.helpers import ancestors, prod_stages
from pch.engine.registry import rule, rule_params
from pch.model.findings import RuleResult
from pch.model.pipeline import Pipeline
from pch.model.repo import RepoContext
from pch.normalize.gha import env_unreadable
from pch.settings import Policy


def _manual(st):
    return [a for a in st.pre_approvals if a.kind == "manual" and (a.approvers or a.min_approvers)]


@rule(
    "DEP-001", "Production deployments require manual approval", "critical", "stage",
    "A human gate before production is the baseline change-management control.",
    {"classic": "Release definition > Production stage > Pre-deployment conditions > enable Pre-deployment approvals with named approvers.",
     "yaml": "Environment > Approvals and checks > add an Approval check on the production environment.",
     "gha": "Repository Settings > Environments > production > enable 'Required reviewers' (a team), and reference the environment from the deploy job."},
    tiers={"prod"},
)
def dep_001(ctx, policy: Policy, t) -> RuleResult:
    st = t.stage
    if not st.is_deploy:
        return RuleResult.na("not a deployment stage")
    if p_unknown(ctx, t):
        return RuleResult.unknown("environment checks were not collected")
    ap = _manual(st)
    if ap:
        return RuleResult.passed("manual approval present", approvers=[x for a in ap for x in a.approvers])
    return RuleResult.failed("no manual pre-deployment approval on a production stage")


def p_unknown(ctx: RepoContext, t, what: str = "all") -> bool:
    if t.pipeline.platform == "gha":
        return bool(t.stage.env_name) and env_unreadable(t.pipeline, t.stage, what)
    return t.pipeline.platform == "ado_yaml" and bool(t.stage.env_name) and t.stage.env_name not in ctx.environments


@rule(
    "DEP-002", "Requester cannot approve their own production deployment", "critical", "stage",
    "Separation of duties: the person who triggers a production release must not be its approver.",
    {"classic": "Pre-deployment approvals > untick 'The user requesting a release can approve it'.",
     "yaml": "Approval check > tick 'Requester cannot approve their own deployments'.",
     "gha": "Environment > Required reviewers > tick 'Prevent self-review'."},
    tiers={"prod"},
)
def dep_002(ctx, policy: Policy, t) -> RuleResult:
    st = t.stage
    if not st.is_deploy:
        return RuleResult.na("not a deployment stage")
    ap = _manual(st)
    if not ap:
        return RuleResult.na("no manual approval (see DEP-001)")
    bad = [a for a in ap if a.requester_can_approve is not False]
    if bad:
        return RuleResult.failed("requester can approve their own deployment")
    return RuleResult.passed("requester cannot approve")


@rule(
    "DEP-003", "Production deployments are gated by a ServiceNow change request", "critical", "stage",
    "Production changes must be backed by an approved ServiceNow CRQ.",
    {"classic": "Add a ServiceNow Change Management gate to the pre-deployment gates of the production stage.",
     "yaml": "Add a ServiceNow check to the production environment, or a ServiceNow-DevOps task before deployment.",
     "gha": "Install the ServiceNow DevOps GitHub App as a custom deployment protection rule on the production environment, or call ServiceNow/servicenow-devops-change before the deploy job."},
    tiers={"prod"},
    params={"servicenow_app_pattern": r"(?i)servicenow|snow"},
)
def dep_003(ctx, policy: Policy, t) -> RuleResult:
    st = t.stage
    if not st.is_deploy:
        return RuleResult.na("not a deployment stage")
    if p_unknown(ctx, t):
        return RuleResult.unknown("environment checks were not collected")
    found = [a for a in st.gates + st.pre_approvals + st.post_approvals if a.kind == "servicenow"]
    if found or "gate:servicenow" in st.capabilities():
        return RuleResult.passed("ServiceNow change gate present", gate=found[0].name if found else "task")
    if p_unknown(ctx, t, "custom"):
        return RuleResult.unknown("custom deployment protection rules of the environment could not be read")
    return RuleResult.failed("no ServiceNow CRQ gate/check on a production stage")


@rule(
    "DEP-004", "Production depends on a lower environment (no direct-to-prod)", "high", "stage",
    "Changes must be promoted through dev/test/UAT before production.",
    {"classic": "Production stage > Pre-deployment conditions > trigger 'After stage' = UAT (not 'After release').",
     "yaml": "Set dependsOn on the production stage to the UAT/test stage.",
     "gha": "Add `needs: <test/uat deploy job>` to the production job (or trigger the production workflow with workflow_run from the lower-environment workflow)."},
    tiers={"prod"},
    params={"lower_tiers": ["dev", "test", "uat"]},
)
def dep_004(ctx, policy: Policy, t) -> RuleResult:
    p, st = t.pipeline, t.stage
    if not st.is_deploy:
        return RuleResult.na("not a deployment stage")
    anc = ancestors(p, st)
    tiers = rule_params(policy, "DEP-004")["lower_tiers"]
    lower = [a.name for a in anc if a.env_tier in tiers]
    if lower:
        return RuleResult.passed("depends on lower environment(s)", lower=lower)
    if p.platform == "gha":  # promotion across workflows: this one runs after a workflow that deployed to a lower environment
        upstream = [q.name for q in ctx.pipelines if q.platform == "gha" and q.name in (p.meta.get("workflow_run") or [])
                    and any(s.is_deploy and s.env_tier in tiers for s in q.stages)]
        if upstream:
            return RuleResult.passed("runs after workflow(s) that deploy to a lower environment (workflow_run)", lower=upstream)
    deployish = [a.name for a in anc if a.is_deploy]
    if deployish:
        return RuleResult.warn("depends on stages whose environment tier is unknown", stages=deployish)
    return RuleResult.failed("production stage has no lower-environment predecessor (direct-to-prod path)", depends_on=st.depends_on)


@rule(
    "DEP-005", "Every prod deployment in the last 90 days maps to an approved ServiceNow CRQ", "high", "repo",
    "Detective control: proves production changes were authorised and inside their change window.",
    {"any": "Put the CRQ number in the release name/description (or a pipeline parameter) and make the CRQ gate mandatory."},
    tiers={"prod"},
    params={"crq_pattern": r"\b(CHG\d{6,9}|CRQ\d{6,12})\b", "window_slack_hours": 2},
)
def dep_005(ctx: RepoContext, policy: Policy) -> RuleResult:
    deps = [(p, d) for p in ctx.pipelines for d in p.deployments_90d if d.env_tier == "prod"]
    if not deps:
        return RuleResult.na("no production deployments in the last 90 days")
    if not ctx.snow.available:
        return RuleResult.unknown("ServiceNow was not queried; cannot correlate deployments")
    slack = rule_params(policy, "DEP-005")["window_slack_hours"]
    ok = 0
    bad: list[dict[str, Any]] = []
    unlinked: list[dict[str, Any]] = []
    for p, d in deps:
        cr = None
        for ref in d.change_refs:
            cr = ctx.snow.changes.get(ref.upper())
            if cr:
                break
        if cr is None and not d.change_refs and d.completed_at:
            for c in ctx.snow.ci_changes:  # fall back to CI + time window
                if window_covers(c, d.completed_at, slack):
                    cr = c
                    break
        if cr is None:
            (bad if d.change_refs or ctx.repo.servicenow_ci else unlinked).append(
                {"deployment": d.id, "pipeline": p.name, "refs": d.change_refs, "reason": "CRQ not found" if d.change_refs else "no CRQ in window"}
            )
            continue
        if not change_is_valid(cr):
            bad.append({"deployment": d.id, "pipeline": p.name, "crq": cr.number, "reason": f"CRQ state '{cr.state}' / approval '{cr.approval}'"})
        elif d.completed_at and not window_covers(cr, d.completed_at, slack):
            bad.append({"deployment": d.id, "pipeline": p.name, "crq": cr.number, "reason": "deployed outside the CRQ window"})
        else:
            ok += 1
    ev: dict[str, Any] = {"deployments": len(deps), "valid": ok, "violations": bad[:20], "unlinked": unlinked[:20]}
    if bad:
        return RuleResult.failed(f"{len(bad)} of {len(deps)} production deployments lack a valid CRQ", **ev)
    if unlinked:
        return RuleResult.unknown(f"{len(unlinked)} deployments could not be linked to a CRQ (no CRQ number, no CI configured)", **ev)
    return RuleResult.passed(f"all {ok} production deployments map to approved CRQs inside their window", **ev)


@rule(
    "DEP-006", "Run retention meets policy for production releases", "medium", "pipeline",
    "Evidence of production changes must be retained (default 365 days).",
    {"classic": "Release definition > Retention: set Days to retain a release to >= 365 for the production stage.",
     "yaml": "Project Settings > Pipelines > Settings > Retention policy; or set retention on the pipeline."},
    tiers={"prod"},
)
def dep_006(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    need = policy.prod_retention_days
    if p.platform == "gha":
        return RuleResult.na("GitHub Actions run and artifact retention is a repository/organisation setting (default 90 days) that is not read; deployment history stays in the Deployments API")
    if p.platform == "ado_classic_release":
        days = [s.retention_days for s in prod_stages(p) if s.retention_days is not None]
        have = min(days) if days else None
    else:
        have = p.retention_days
    if have is None:
        return RuleResult.unknown("retention is not defined on the pipeline (project-level default applies)")
    if have >= need:
        return RuleResult.passed(f"retention {have}d >= {need}d", retention_days=have)
    return RuleResult.failed(f"retention {have}d < {need}d", retention_days=have, required=need)

