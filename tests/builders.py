"""Small builders for rule tests."""

from __future__ import annotations

from datetime import datetime, timedelta

from pch.engine.registry import REGISTRY, load_rules
from pch.engine.runner import evaluate_rule
from pch.model.pipeline import Approval, Job, Pipeline, Stage, Step, VariableGroupRef
from pch.model.repo import (
    AikidoFacts,
    AikidoIssue,
    BranchPolicies,
    RepoContext,
    RepoFacts,
    RepoRef,
    ServiceConnection,
    SnowFacts,
    SonarFacts,
    TestState,
    VariableGroup,
)
from pch.normalize.capabilities import classify_step
from pch.normalize.target_detect import enrich_pipeline
from pch.settings import Policy

NOW = datetime(2026, 10, 1, 12, 0, 0)


def step(task=None, inputs=None, script=None, name=None, **kw) -> Step:
    s = Step(id="s", name=name or (task or "script"), task=task, inputs=inputs or {}, inline_script=script, **kw)
    if task and "@" in task:
        s.task_version = task.split("@")[1]
    return classify_step(s)


def stage(name="Prod", steps=(), tier=None, env=None, **kw) -> Stage:
    return Stage(name=name, env_name=env, env_tier=tier or "unknown", jobs=[Job(name="j", steps=list(steps))], **kw)


def pipe(stages, platform="ado_yaml", id="1", enrich=True, **kw) -> Pipeline:
    p = Pipeline(platform=platform, id=id, name=f"pipe-{id}", project="P", repo="r", stages=list(stages),
                 definition_in_source_control=platform == "ado_yaml", **kw)
    return enrich_pipeline(p) if enrich else p


def ctx(pipelines=(), facts=None, policies=None, sonar=None, aikido=None, snow=None, conns=(), groups=(), envs=None, **kw) -> RepoContext:
    return RepoContext(
        repo=RepoRef(**{"id": "r1", "name": "r", "project": "P", **kw.pop("repo_kw", {})}),
        pipelines=list(pipelines),
        facts=facts or RepoFacts(languages=["dotnet"], kind="application", has_app_code=True),
        policies=policies or BranchPolicies(),
        sonar=sonar, aikido=aikido, snow=snow or SnowFacts(),
        service_connections={c.name: c for c in conns} | {c.id: c for c in conns},
        variable_groups={g.name: g for g in groups} | {g.id: g for g in groups},
        environments=envs or {},
        now=NOW,
        **kw,
    )


def run(rule_id: str, c: RepoContext, policy: Policy | None = None):
    load_rules()
    return evaluate_rule(REGISTRY[rule_id], c, policy or Policy(approved_registries=["contosoacr.azurecr.io"], marketplace_task_allowlist=["SonarQubePrepare", "SonarQubeAnalyze", "SonarQubePublish"]))


def statuses(rule_id: str, c: RepoContext, policy: Policy | None = None) -> list[str]:
    return [f.status.value for f in run(rule_id, c, policy)]


def one(rule_id: str, c: RepoContext, policy: Policy | None = None) -> str:
    st = statuses(rule_id, c, policy)
    assert len(st) == 1, f"{rule_id}: expected exactly one finding, got {st}"
    return st[0]


def manual(requester=False) -> Approval:
    return Approval(kind="manual", approvers=["Alice"], min_approvers=1, requester_can_approve=requester)


__all__ = [
    "AikidoFacts", "AikidoIssue", "BranchPolicies", "ServiceConnection", "SnowFacts", "SonarFacts", "TestState",
    "VariableGroup", "VariableGroupRef", "timedelta", "NOW",
]

# Scope(code_hosts=...) default is ["github"]; tests that exercise Azure Repos repos opt in explicitly.
ALL_HOSTS = ["github", "github_enterprise", "azure_repos", "other_git"]
