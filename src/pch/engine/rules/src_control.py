"""SRC: source and change control."""

from __future__ import annotations

import fnmatch

from pch.engine.helpers import branch_allowed
from pch.engine.registry import rule, rule_params
from pch.model.findings import RuleResult
from pch.model.pipeline import Pipeline
from pch.model.repo import RepoContext
from pch.settings import Policy


@rule(
    "SRC-001", "Default branch requires 2+ reviewers (creator vote excluded, reset on push)", "high", "repo",
    "Peer review on the default branch is the primary preventive control for unreviewed code reaching production.",
    {"any": "Repos > Branches > main > Branch policies: set minimum reviewers to 2, disable 'Allow requestors to approve their own changes', enable 'Reset all approval votes' on new changes."},
    params={"allow_creator_vote": False, "require_reset_on_push": True},
)
def src_001(ctx: RepoContext, policy: Policy) -> RuleResult:
    pol = ctx.policies
    if not pol.available:
        return RuleResult.unknown(pol.unavailable_reason or "branch policies were not collected")
    problems = []
    need = policy.min_reviewers
    if (pol.min_reviewers or 0) < need:
        problems.append(f"minimum reviewers is {pol.min_reviewers or 0}, need >= {need}")
    prm = rule_params(policy, "SRC-001")
    if pol.creator_vote_counts and not prm["allow_creator_vote"]:
        problems.append("creator's own vote counts")
    if not pol.reset_on_push and prm["require_reset_on_push"]:
        problems.append("approvals are not reset on new pushes")
    ev = {"min_reviewers": pol.min_reviewers, "creator_vote_counts": pol.creator_vote_counts, "reset_on_push": pol.reset_on_push}
    if problems:
        return RuleResult.failed("; ".join(problems), **ev)
    return RuleResult.passed("reviewer policy meets the standard", **ev)


@rule(
    "SRC-002", "Default branch has a build validation policy", "high", "repo",
    "Build validation stops changes that do not build or pass tests from merging.",
    {"any": "Add a Build validation branch policy on the default branch pointing at the CI pipeline."},
)
def src_002(ctx: RepoContext, policy: Policy) -> RuleResult:
    if not ctx.policies.available:
        return RuleResult.unknown(ctx.policies.unavailable_reason or "branch policies were not collected")
    if ctx.policies.build_validation:
        return RuleResult.passed("build validation policy present")
    return RuleResult.failed("no build validation policy on the default branch")


@rule(
    "SRC-003", "Linked work item and resolved comments required", "medium", "repo",
    "Work-item linkage gives change traceability; comment resolution prevents ignored review feedback.",
    {"any": "Enable 'Check for linked work items' (required) and 'Check for comment resolution' (required) on the default branch."},
)
def src_003(ctx: RepoContext, policy: Policy) -> RuleResult:
    pol = ctx.policies
    if not pol.available:
        return RuleResult.unknown(pol.unavailable_reason or "branch policies were not collected")
    missing = []
    if not pol.work_item_required:
        missing.append("linked work item")
    if not pol.comment_resolution_required:
        missing.append("comment resolution")
    if missing:
        return RuleResult.failed("missing policy: " + ", ".join(missing), missing=missing)
    return RuleResult.passed("work item linking and comment resolution are required")


@rule(
    "SRC-004", "Pipeline definition is in source control", "high", "pipeline",
    "Pipelines defined in the UI (Classic) have no review, history or diff trail. YAML pipelines are versioned with the code.",
    {"classic": "Export the definition to YAML (Pipelines > ... > Export to YAML) or migrate to GitHub Actions; commit azure-pipelines.yml to the repo.",
     "yaml": "Keep azure-pipelines.yml in the repo, protected by branch policy."},
)
def src_004(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    if p.definition_in_source_control:
        return RuleResult.passed("definition is YAML in the repository", platform=p.platform)
    return RuleResult.failed(f"{p.platform} definition lives only in Azure DevOps (not versioned with the code)", platform=p.platform)


@rule(
    "SRC-005", "Production deploys only artifacts from a protected branch", "high", "stage",
    "Without an artifact-branch filter or branch-control check, any branch build can be deployed to production.",
    {"classic": "Release definition > Artifact > Continuous deployment trigger > Build branch filters: include only main/release/*.",
     "yaml": "Add a 'Branch control' check on the production environment allowing only refs/heads/main and release/*."},
    tiers={"prod"},
)
def src_005(ctx, policy: Policy, t) -> RuleResult:
    p, st = t.pipeline, t.stage
    if not st.is_deploy:
        return RuleResult.na("not a deployment stage")
    if p.platform == "ado_yaml" and st.env_name and st.env_name not in ctx.environments:
        return RuleResult.unknown("environment checks were not collected")
    filters = st.branch_filters
    if not filters:
        return RuleResult.failed("no artifact branch filter / branch-control check: any branch can deploy to production", filters=[])
    bad = [f for f in filters if not branch_allowed(f, policy.approved_branches) and not any(fnmatch.fnmatch(f.removeprefix("refs/heads/"), a) for a in policy.approved_branches)]
    if bad:
        return RuleResult.failed(f"branch filters allow non-protected branches: {bad}", filters=filters, not_approved=bad)
    return RuleResult.passed("only protected branches may deploy", filters=filters)


@rule(
    "SRC-006", "CODEOWNERS or required-reviewer policy covers pipeline files", "low", "repo",
    "Pipeline definitions are privileged code; changes need review from the owning team.",
    {"any": "Add a CODEOWNERS file covering azure-pipelines*.yml, or a Required reviewers policy with path filter /azure-pipelines*.yml."},
)
def src_006(ctx: RepoContext, policy: Policy) -> RuleResult:
    has_yaml = bool(ctx.facts.pipeline_files) or any(p.platform == "ado_yaml" for p in ctx.pipelines)  # externally hosted: ADO YAML pipelines only
    if not has_yaml:
        return RuleResult.na("no YAML pipeline files in the repo")
    if ctx.facts.facts_source == "unavailable":
        return RuleResult.unknown(ctx.facts.facts_reason)  # CODEOWNERS lives in the repository itself
    if ctx.facts.codeowners:
        return RuleResult.passed("CODEOWNERS file present")
    pats = ctx.policies.required_reviewer_paths
    if any(x in ("*", "/*", "/**") or "pipeline" in x.lower() or x.lower().endswith((".yml", ".yaml")) for x in pats):
        return RuleResult.passed("required-reviewer policy covers pipeline files", paths=pats)
    return RuleResult.failed("no CODEOWNERS and no required-reviewer policy for pipeline files", paths=pats)
