"""SRC: source and change control."""

from __future__ import annotations

import fnmatch
from typing import Any

from pch.engine.helpers import branch_allowed
from pch.engine.registry import rule, rule_params
from pch.model.findings import RuleResult
from pch.model.pipeline import Pipeline
from pch.model.repo import BranchProtection, RepoContext
from pch.settings import Policy


def _github_protection(ctx: RepoContext) -> tuple[BranchProtection | None, RuleResult | None]:
    """(protection, early result). protection is None for repos without GitHub branch protection data (ADO policies apply)."""
    pr = ctx.protection
    if pr is None:
        return None, None
    if not pr.available:
        return pr, RuleResult.unknown(pr.unavailable_reason or "GitHub branch protection could not be read")
    return pr, None


def _github_verdict(pr: BranchProtection, problems: list[str], ok: str, **ev: Any) -> RuleResult:
    """PASS when nothing is missing. A control that is not seen while a source could not be read (classic protection needs
    Administration: read) is UNKNOWN with the reason, never FAIL."""
    if not problems:
        return RuleResult.passed(ok, sources=pr.sources, **ev)
    if pr.incomplete:
        return RuleResult.unknown("not visible in the readable sources: " + "; ".join(problems) + " | unreadable: " + "; ".join(pr.incomplete), **ev)
    return RuleResult.failed("; ".join(problems), sources=pr.sources, **ev)


@rule(
    "SRC-001", "Default branch requires 2+ reviewers (creator vote excluded, reset on push)", "high", "repo",
    "Peer review on the default branch is the primary preventive control for unreviewed code reaching production. "
    "Azure Repos: minimum reviewers policy. GitHub: required approving reviews from branch rules or classic protection (the PR author can never approve, "
    "so `allow_creator_vote` has nothing to check there); `require_reset_on_push` is met by dismissing stale approvals or by requiring approval of the most recent push.",
    {"any": "Azure Repos: Branches > main > Branch policies: minimum reviewers 2, disable 'Allow requestors to approve their own changes', enable 'Reset all approval votes'. "
            "GitHub: Settings > Rules (or Branches): require a pull request with 2 approvals and 'Dismiss stale pull request approvals' (or 'Require approval of the most recent reviewable push')."},
    params={"allow_creator_vote": False, "require_reset_on_push": True},
)
def src_001(ctx: RepoContext, policy: Policy) -> RuleResult:
    prm = rule_params(policy, "SRC-001")
    need = policy.min_reviewers
    gh, early = _github_protection(ctx)
    if early is not None:
        return early
    if gh is not None:
        problems = []
        if gh.required_approving_review_count < need:
            problems.append(f"required approving reviews is {gh.required_approving_review_count}, need >= {need}")
        if prm["require_reset_on_push"] and not (gh.dismiss_stale_reviews or gh.require_last_push_approval):
            problems.append("approvals are not reset on new pushes (stale approvals are not dismissed and the last push needs no approval)")
        return _github_verdict(gh, problems, "reviewer policy meets the standard", approvals=gh.required_approving_review_count,
                               dismiss_stale_reviews=gh.dismiss_stale_reviews, require_last_push_approval=gh.require_last_push_approval)
    pol = ctx.policies
    if not pol.available:
        return RuleResult.unknown(pol.unavailable_reason or "branch policies were not collected")
    problems = []
    if (pol.min_reviewers or 0) < need:
        problems.append(f"minimum reviewers is {pol.min_reviewers or 0}, need >= {need}")
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
    "Build validation stops changes that do not build or pass tests from merging. Azure Repos: Build validation policy. GitHub: required status checks "
    "(any, or all of the names in `required_checks`).",
    {"any": "Azure Repos: add a Build validation branch policy on the default branch pointing at the CI pipeline. "
            "GitHub: require status checks (the CI check names) in a branch rule or branch protection."},
    params={"required_checks": []},
)
def src_002(ctx: RepoContext, policy: Policy) -> RuleResult:
    gh, early = _github_protection(ctx)
    if early is not None:
        return early
    if gh is not None:
        want = rule_params(policy, "SRC-002")["required_checks"]
        have = {c.casefold() for c in gh.required_status_checks}
        problems = []
        if not gh.required_status_checks:
            problems.append("no required status checks on the default branch")
        problems += [f"required check '{c}' is not enforced" for c in want if c.casefold() not in have]
        return _github_verdict(gh, problems, "required status checks present", checks=gh.required_status_checks)
    if not ctx.policies.available:
        return RuleResult.unknown(ctx.policies.unavailable_reason or "branch policies were not collected")
    if ctx.policies.build_validation:
        return RuleResult.passed("build validation policy present")
    return RuleResult.failed("no build validation policy on the default branch")


@rule(
    "SRC-003", "Linked work item and resolved comments required", "medium", "repo",
    "Work-item linkage gives change traceability; comment resolution prevents ignored review feedback. "
    "GitHub has no work-item link policy, so for GitHub repos only conversation resolution is assessed.",
    {"any": "Azure Repos: enable 'Check for linked work items' (required) and 'Check for comment resolution' (required) on the default branch. "
            "GitHub: require conversation resolution before merging."},
)
def src_003(ctx: RepoContext, policy: Policy) -> RuleResult:
    gh, early = _github_protection(ctx)
    if early is not None:
        return early
    if gh is not None:
        problems = [] if gh.require_conversation_resolution else ["conversation resolution is not required before merging"]
        return _github_verdict(gh, problems, "conversation resolution is required (work-item links are not assessed on GitHub)")
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
    "Pipeline definitions are privileged code; changes need review from the owning team. Azure Repos: CODEOWNERS or a Required reviewers policy; GitHub: the CODEOWNERS file.",
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


def _github_only(ctx: RepoContext) -> tuple[BranchProtection | None, RuleResult | None]:
    """(protection, early result): NOT_APPLICABLE for Azure Repos; UNKNOWN (with the reason) for an external repo whose protection was not read."""
    pr = ctx.protection
    if pr is None:
        if not ctx.repo.external:
            return None, RuleResult.na("GitHub branch protection rule (Azure Repos policies are not mapped)")
        return None, RuleResult.unknown(ctx.policies.unavailable_reason or "GitHub branch protection was not read")
    if not pr.available:
        return None, RuleResult.unknown(pr.unavailable_reason or "GitHub branch protection could not be read")
    return pr, None


@rule(
    "SRC-007", "Default branch blocks force pushes and deletion", "high", "repo",
    "A force push rewrites the history reviewers approved and deleting the default branch destroys it; both defeat every other source control.",
    {"any": "GitHub: in the branch rule or branch protection enable 'Block force pushes' and 'Restrict deletions' (leave 'Allow force pushes' and 'Allow deletions' off)."},
    params={"require_linear_history": False, "require_signed_commits": False},
)
def src_007(ctx: RepoContext, policy: Policy) -> RuleResult:
    pr, early = _github_only(ctx)
    if pr is None:
        return early or RuleResult.unknown("GitHub branch protection could not be read")
    prm = rule_params(policy, "SRC-007")
    problems = []
    if not pr.block_force_pushes:
        problems.append("force pushes are not blocked")
    if not pr.block_deletions:
        problems.append("deleting the branch is not blocked")
    if prm["require_linear_history"] and not pr.require_linear_history:
        problems.append("linear history is not required")
    if prm["require_signed_commits"] and not pr.require_signed_commits:
        problems.append("signed commits are not required")
    return _github_verdict(pr, problems, "force pushes and deletion are blocked", block_force_pushes=pr.block_force_pushes, block_deletions=pr.block_deletions)


@rule(
    "SRC-008", "Branch protection also applies to administrators (no bypass)", "medium", "repo",
    "If repository administrators or bypass actors can skip the rules, the review and status-check controls only bind people who are not in a hurry.",
    {"any": "GitHub: enable 'Do not allow bypassing the above settings' (classic) or remove bypass actors from the ruleset (or limit them to break-glass roles and waive this rule)."},
)
def src_008(ctx: RepoContext, policy: Policy) -> RuleResult:
    pr, early = _github_only(ctx)
    if pr is None:
        return early or RuleResult.unknown("GitHub branch protection could not be read")
    if not pr.protected:
        return RuleResult.na("the default branch has no protection (see SRC-001)")
    ev = {"enforce_admins": pr.enforce_admins, "bypass_actors": pr.bypass_actors, "sources": pr.sources}
    if pr.admins_can_bypass is None:
        return RuleResult.unknown("cannot tell whether administrators can bypass: " + ("; ".join(pr.incomplete) or "ruleset bypass actors are not readable"), **ev)
    if pr.admins_can_bypass:
        why = "administrators are not subject to the branch protection" if pr.enforce_admins is False else "bypass actors exist: " + ", ".join(pr.bypass_actors)
        return RuleResult.failed(why, **ev)
    return RuleResult.passed("protection also applies to administrators; no bypass actors", **ev)


@rule(
    "SRC-009", "CODEOWNERS file present", "low", "repo",
    "CODEOWNERS names who must review which part of the code and who is reachable for the repository; it also supplies the owner shown in this report.",
    {"any": "GitHub: add .github/CODEOWNERS (or CODEOWNERS / docs/CODEOWNERS) with at least a default `*` owner, and with the param require_code_owner_review also enable 'Require review from Code Owners'."},
    params={"require_code_owner_review": False},
)
def src_009(ctx: RepoContext, policy: Policy) -> RuleResult:
    if ctx.facts.facts_source == "unavailable":
        return RuleResult.unknown(ctx.facts.facts_reason)
    if ctx.facts.facts_source != "github":
        return RuleResult.na("GitHub CODEOWNERS rule (this repository is not read from GitHub)")
    if not ctx.facts.codeowners:
        return RuleResult.failed("no CODEOWNERS file (.github/CODEOWNERS, CODEOWNERS or docs/CODEOWNERS)")
    if rule_params(policy, "SRC-009")["require_code_owner_review"]:
        pr = ctx.protection
        if pr is None or not pr.available:
            return RuleResult.unknown("CODEOWNERS exists; whether code owner review is required could not be read")
        if not pr.require_code_owner_review:
            return _github_verdict(pr, ["code owner review is not required by the branch rules"], "")
    return RuleResult.passed("CODEOWNERS file present")
