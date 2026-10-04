"""GitHub Actions normalisation (G3): workflow -> canonical Pipeline, capabilities from data, environments -> approvals, runs, lineage."""

from datetime import datetime

import pytest

from pch.model.gha import ActionsRead, GhCustomRule, GhEnvironment, WorkflowSource
from pch.model.pipeline import PROTECTED_BRANCHES
from pch.model.repo import RepoRef
from pch.normalize.capabilities import load_catalog
from pch.normalize.gha import (
    WorkflowError,
    apply_environments,
    build_lineage,
    build_pipelines,
    env_unreadable,
    load_workflow_yaml,
    parse_uses,
    parse_workflow,
    reusable_refs,
)
from tests.github_mock import actions_json, actions_text

NOW = datetime(2026, 10, 1)


def wf(name, **kw):
    return parse_workflow(WorkflowSource(path=f".github/workflows/{name}", id=1, text=actions_text(name)), project="P", repo="o/r", **kw)


def test_parse_uses_ref_kinds():
    sha = "a" * 40
    assert parse_uses(f"actions/checkout@{sha}") == (sha, "sha")
    assert parse_uses("actions/checkout@v4") == ("v4", "tag")
    assert parse_uses("actions/checkout@main")[1] == "branch"
    assert parse_uses("./.github/actions/x") == (None, "local")
    assert parse_uses("docker://alpine@sha256:abc")[1] == "sha" and parse_uses("docker://alpine:latest")[1] == "branch"


def test_ci_workflow_capabilities_come_from_data():
    p = wf("ci.yml")
    assert p.platform == "gha" and p.triggers["push_branches"] == ["main"] and p.triggers["pr_branches"] == ["main"] and p.meta["permissions"] == {"contents": "read"}
    caps = p.capabilities()
    assert {"unit-test", "test-results-publish", "coverage-publish", "sast:sonar", "sonar:prepare", "sonar:analyze", "sonar:publish", "artifact:publish", "source-checkout"} <= caps
    checkout = p.all_steps()[0]
    assert checkout.ref_kind == "sha" and not checkout.deprecated and checkout.marketplace
    assert p.meta["secrets_used"] == ["SONAR_TOKEN"] and not p.meta["unresolved"]
    assert not any(v.secret_like_reason for v in p.variables)  # DOTNET_NOLOGO literal is not a secret


def test_deploy_workflow_stages_oidc_and_workflow_run():
    p = wf("deploy.yml")
    assert [s.name for s in p.stages] == ["deploy-test", "deploy-prod"] and p.stages[1].depends_on == ["deploy-test"]
    assert p.stages[0].env_name == "test" and p.stages[1].env_name == "production" and p.stages[1].jobs[0].kind == "deployment"
    assert p.meta["workflow_run"] == ["CI"] and p.triggers["workflow_run_branches"] == ["main"]
    login = [s for s in p.all_steps() if "auth:login" in s.capabilities]
    assert login and all("auth:oidc" in s.capabilities and "auth:secret" not in s.capabilities for s in login)
    assert "deploy:webapp" in p.capabilities() and "slot-swap" in p.stages[1].capabilities() and "smoke-test" in p.stages[0].capabilities()


def test_insecure_workflow_facts():
    p = wf("insecure.yml")
    assert p.meta["permissions"] == "write-all" and p.meta["public_trigger"] and p.stages[0].jobs[0].self_hosted is True
    steps = {s.task: s for s in p.all_steps()}
    assert steps["actions/checkout@v4"].ref_kind == "tag" and steps["azure/login@v1"].deprecated  # v1 < 2
    assert "auth:secret" in steps["azure/login@v1"].capabilities and "auth:oidc" not in steps["azure/login@v1"].capabilities
    sonar = steps["SonarSource/sonarqube-scan-action@main"]
    assert sonar.ref_kind == "branch" and sonar.task_version is None and sonar.continue_on_error
    assert [v.name for v in p.variables if v.secret_like_reason] == ["API_KEY"]


def test_on_key_is_the_string_on_not_boolean():
    assert load_workflow_yaml("on: push\njobs: {}\n")["on"] == "push"
    p = parse_workflow(WorkflowSource(path="w.yml", text="on: [push, workflow_dispatch]\njobs: {}\n"), project="P", repo="o/r")
    assert p.meta["events"] == ["push", "workflow_dispatch"] and not p.meta["callable_only"]


@pytest.mark.parametrize("text", ["a: [", "- 1\n- 2\n", "x: " + "y" * (600 * 1024), "k: &a 1\n" + "".join(f"v{i}: *a\n" for i in range(60))])
def test_unusable_workflow_files_raise(text):
    with pytest.raises(WorkflowError):
        parse_workflow(WorkflowSource(path="w.yml", text=text), project="P", repo="o/r")
    with pytest.raises(WorkflowError):
        parse_workflow(WorkflowSource(path="w.yml", text=None, error="denied"), project="P", repo="o/r")


def test_reusable_workflows_are_flattened_one_level_and_unresolved_are_noted():
    assert reusable_refs(actions_text("caller.yml"))[0] == "./.github/workflows/tests.yml"
    scan_ref = "contoso-platform/workflows/.github/workflows/scan.yml@0123456789abcdef0123456789abcdef01234567"
    p = wf("caller.yml", callees={"./.github/workflows/tests.yml": actions_text("tests.yml"), scan_ref: actions_text("scan.yml"),
                                  "contoso-platform/private-workflows/.github/workflows/gone.yml@v1": None},
          callee_errors={"contoso-platform/private-workflows/.github/workflows/gone.yml@v1": "not found (HTTP 404)"})
    assert "unit-test" in p.stages[0].capabilities() and "sonar:gate-breaker" in p.stages[1].capabilities()
    assert all(s.id.startswith("callee:") for s in p.stages[0].steps())
    assert len(p.meta["unresolved"]) == 1 and "404" in p.meta["unresolved"][0]
    nested = parse_workflow(WorkflowSource(path="w.yml", text="on: push\njobs:\n  a:\n    uses: ./.github/workflows/c.yml\n"), project="P", repo="o/r",
                            callees={"./.github/workflows/c.yml": "on: workflow_call\njobs:\n  x:\n    uses: ./.github/workflows/d.yml\n"})
    assert "nested reusable workflow" in nested.meta["unresolved"][0]
    assert wf("tests.yml").meta["callable_only"]


def test_environment_protection_becomes_approvals():
    prod = GhEnvironment(name="production", required_reviewers=True, reviewers=["team:a"], prevent_self_review=True, wait_timer=15, branch_policy="custom",
                         branch_patterns=["main"], custom_rules=[GhCustomRule(slug="servicenow-devops"), GhCustomRule(slug="other-app", name="Other")])
    p = wf("deploy.yml")
    apply_environments(p, {"production": prod})
    st = p.stage("deploy-prod")
    assert st is not None
    ap = st.pre_approvals[0]
    assert ap.kind == "manual" and ap.requester_can_approve is False and ap.min_approvers == 1 and ap.approvers == ["team:a"]
    assert sorted(a.kind for a in st.gates) == ["branch_control", "gate", "other", "servicenow"] and st.branch_filters == ["main"]
    assert not st.gates[0].kind == "x" and not p.stage("deploy-test").pre_approvals  # the unconfigured environment has no protection
    p2 = wf("deploy.yml")
    apply_environments(p2, {"production": GhEnvironment(name="production", branch_policy="protected", prevent_self_review=None, required_reviewers=True)})
    assert p2.stage("deploy-prod").branch_filters == [PROTECTED_BRANCHES] and p2.stage("deploy-prod").pre_approvals[0].requester_can_approve is True
    p3 = wf("deploy.yml")
    apply_environments(p3, None)
    assert env_unreadable(p3, p3.stage("deploy-prod")) and env_unreadable(p3, p3.stage("deploy-test"))
    p4 = wf("deploy.yml")
    apply_environments(p4, {"production": GhEnvironment(name="production", custom_error="denied", branch_policy="custom", branch_error="denied")})
    s = p4.stage("deploy-prod")
    assert not env_unreadable(p4, s) and env_unreadable(p4, s, "custom") and env_unreadable(p4, s, "branch")


def read(**kw) -> ActionsRead:
    base = dict(
        workflows=[WorkflowSource(path=".github/workflows/ci.yml", id=101, name="CI", text=actions_text("ci.yml"), url="u1"),
                   WorkflowSource(path=".github/workflows/deploy.yml", id=102, name="Deploy", text=actions_text("deploy.yml")),
                   WorkflowSource(path=".github/workflows/bad.yml", id=103, text="a: [")],
        runs=actions_json("runs.json")["workflow_runs"],
    )
    return ActionsRead(**{**base, **kw})


def test_build_pipelines_run_stats_and_unreadable():
    pipes, unreadable = build_pipelines(read(), project="P", repo="o/r", tier_overrides={"production": "prod"})
    assert [p.name for p in pipes] == ["CI", "Deploy"] and len(unreadable) == 1 and "bad.yml" in unreadable[0]
    ci = pipes[0]
    assert (ci.run_stats_90d.total, ci.run_stats_90d.succeeded, ci.run_stats_90d.failed) == (2, 1, 1)  # the in-progress run is not counted
    assert ci.run_stats_90d.last_success == datetime(2026, 9, 30, 9, 10) and ci.last_run.status == "success" and ci.meta["last_run_number"] == 120
    assert pipes[1].stage("deploy-prod").env_tier == "prod" and pipes[1].stage("deploy-test").env_tier == "test" and pipes[1].stage("deploy-prod").is_deploy
    none, _ = build_pipelines(read(runs=None, runs_error="runs denied"), project="P", repo="o/r")
    assert none[0].run_stats_90d is None and "runs denied" in none[0].notes[0]
    trunc, _ = build_pipelines(read(runs=[], runs_truncated=True), project="P", repo="o/r")
    assert trunc[0].run_stats_90d is None
    empty, _ = build_pipelines(read(runs=[]), project="P", repo="o/r")
    assert empty[0].run_stats_90d.total == 0


def test_lineage_for_workflows():
    from pch.model.gha import GhDeployment

    pipes, _ = build_pipelines(read(), project="P", repo="o/r", tier_overrides={"production": "prod"})
    deps = {"production": GhDeployment(environment="production", status="success", id=7001, sha="0123456789abcdef0123456789abcdef01234567", creator="alice", finished="2026-09-30T10:18:00Z"),
            "test": GhDeployment(environment="test", never=True)}
    ref = RepoRef(id="o/r", name="o/r", project="P", provider="github")
    ci, dep = build_lineage(pipes, ref, deps)
    assert ci.kind == "gha" and ci.trigger.ci_branches == ["main"] and ci.trigger.pr_enabled and ci.last_run.status == "succeeded"
    assert [d.name for d in ci.downstream] == ["Deploy"] and dep.upstream[0].kind == "workflow_run" and dep.upstream[0].repo_key == ref.key
    by = {s.name: s for s in dep.stages}
    assert by["deploy-prod"].last_deploy.status == "succeeded" and by["deploy-prod"].last_deploy.triggered_by == "alice" and by["deploy-prod"].last_deploy.artifact_version == "0123456"
    assert by["deploy-test"].last_deploy.status == "never"
    assert ci.artifacts == ["artifact: app"]
    unknown = build_lineage(pipes, ref, {}, collected=True)[1].stages[0].last_deploy
    assert unknown.status == "unknown"


def test_catalog_is_data_and_merged():
    cat = load_catalog()
    names = [n for n, _, _ in cat.tasks]
    assert "actions/checkout" in names and "sonarqubeprepare" in names and "actions/checkout" in cat.deprecated
