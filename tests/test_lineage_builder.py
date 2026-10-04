"""Lineage builder (L2): classic chain, YAML multi-stage chain, GitHub-artifact release, downstream links, templates repo, orphans."""

import json

from pch.collectors.ado.classic_build import normalize_build_definition
from pch.collectors.ado.classic_release import normalize_release_definition
from pch.collectors.ado.lineage_meta import classic_build_meta, parse_yaml_meta
from pch.collectors.ado.yaml_pipeline import parse_yaml_pipeline
from pch.model.lineage import LDeploy, RepoLineage
from pch.model.repo import RepoRef, ServiceConnection
from pch.normalize.lineage import (
    build_repo_lineage,
    link_lineages,
    orphan_build,
    orphan_release,
    stage_targets,
)
from pch.normalize.target_detect import enrich_pipeline

WEB = "https://dev.azure.com/contoso/Payments"
CONNS = {"conn-prod-wif": ServiceConnection(id="conn-prod-wif", name="Payments Prod (WIF)"), "conn-dev": ServiceConnection(id="conn-dev", name="dev-sub"),
         "gh-1": ServiceConnection(id="gh-1", name="github-contoso")}


def ref(name="payments-api", project="Payments", **kw):
    return RepoRef(id="repo-1", name=name, project=project, default_branch="main", **kw)


def classic_chain(fx, catalog, deploys=None):
    b = fx("ado", "build_def_classic_dotnet.json")
    r = fx("ado", "release_def_functionapp.json")
    bp = normalize_build_definition(b, catalog, "Payments", WEB)
    rp = enrich_pipeline(normalize_release_definition(r, catalog, "Payments", WEB, {}))
    enrich_pipeline(bp)
    return build_repo_lineage(ref(), [bp, rp], [b], [r], {}, deploys or {}, {}, CONNS, collected=deploys is not None)


def test_classic_chain_build_release_stages_in_order(fx, catalog):
    deploys = {"ado_classic_release:31": {"Dev": LDeploy(status="succeeded", version="Release-12", artifact_version="20261001.3", triggered_by="Ava Chen"),
                                         "UAT": LDeploy(status="failed", version="Release-11"), "Production": LDeploy(status="never")}}
    lin = classic_chain(fx, catalog, deploys)
    assert [p.name for p in lin.pipelines] == ["payments-api-CI"] and lin.pipelines[0].kind == "classic_build"
    ci = lin.pipelines[0]
    assert ci.trigger.ci_enabled and ci.trigger.ci_branches == ["main"] and ci.definition_path == "\\"
    assert any(a.startswith("artifact:") for a in ci.artifacts)
    rel = lin.releases[0]
    assert rel.source_pipeline_ids == ["12"] and rel.sources[0].type == "Build" and rel.sources[0].primary
    assert rel.cd_enabled and rel.cd_branches == ["main"]
    assert [s.name for s in rel.stages] == ["Dev", "UAT", "Production"]
    assert [s.env_tier for s in rel.stages] == ["dev", "uat", "prod"]
    prod = rel.stages[2]
    assert prod.depends_on == ["UAT"] and "manual approval (min 1)" in prod.approvals
    assert any(g for g in prod.gates)  # ServiceNow / REST gate
    assert prod.service_connections == ["Payments Prod (WIF)"]  # id resolved to the connection NAME
    t = prod.targets[0]
    assert t.kind == "functionapp" and t.name == "orders-fn" and "slot staging" in t.detail
    assert rel.stages[0].last_deploy.triggered_by == "Ava Chen" and prod.last_deploy.status == "never"
    assert not lin.has_prod and lin.targets == ["functionapp"] and lin.tiers == ["dev", "prod", "uat"]
    dumped = json.dumps(lin.model_dump(mode="json"))
    assert "@" not in dumped and "alice" not in dumped.lower()  # no emails/UPNs, approvers are not named


def test_missing_deployment_data_is_unknown_never_a_guess(fx, catalog):
    lin = classic_chain(fx, catalog, None)  # lineage collection off / failed
    assert all(s.last_deploy.status == "unknown" and s.last_deploy.note for s in lin.releases[0].stages)
    assert not lin.has_prod
    only_dev = classic_chain(fx, catalog, {"ado_classic_release:31": {"Dev": LDeploy(status="succeeded")}})  # other stages absent from the result
    assert [s.last_deploy.status for s in only_dev.releases[0].stages] == ["succeeded", "unknown", "unknown"]


def test_has_prod_needs_a_successful_prod_deployment(fx, catalog):
    ok = classic_chain(fx, catalog, {"ado_classic_release:31": {"Production": LDeploy(status="succeeded")}})
    bad = classic_chain(fx, catalog, {"ado_classic_release:31": {"Production": LDeploy(status="failed")}})
    assert ok.has_prod and not bad.has_prod


def test_yaml_multistage_chain(fxt):
    defn = {"id": 21, "name": "orders-func-yaml", "repository": {"id": "repo-2", "name": "orders-func", "type": "TfsGit"}, "process": {"type": 2, "yamlFilename": "azure-pipelines.yml"}}
    text = fxt("ado", "yaml_functionapp.yaml")
    p = enrich_pipeline(parse_yaml_pipeline(text, defn, "Payments", WEB))
    meta = parse_yaml_meta(text)
    deploys = {"ado_yaml:21": {"Dev": LDeploy(status="succeeded", version="20261001.1"), "Prod": LDeploy(status="in_progress", version="20261002.4")}}
    lin = build_repo_lineage(ref("orders-func"), [p], [defn], [], {"21": meta}, deploys, {}, CONNS)
    pl = lin.pipelines[0]
    assert pl.kind == "yaml" and pl.definition_path == "azure-pipelines.yml" and pl.yaml_repo == "orders-func" and not pl.yaml_in_other_repo
    assert pl.trigger.ci_branches == ["main"] and pl.artifacts == ["artifact: drop"]
    assert [s.name for s in pl.stages] == ["Dev", "Prod"]  # the Build stage is the CI part, not a deployment stage
    dev, prod = pl.stages
    assert prod.depends_on == ["Dev"] and prod.env_name == "orders-prod" and prod.env_tier == "prod" and prod.last_deploy.status == "in_progress"
    assert [t.name for t in prod.targets] == ["orders-prod"] and "slot staging" in prod.targets[0].detail
    assert dev.service_connections == ["dev-sub"] and prod.service_connections == ["conn-prod"]  # YAML names; known connections show their display name
    assert not lin.releases


def test_github_artifact_release_without_build(fx, catalog):
    r = fx("ado", "release_def_github_artifact.json")
    rp = enrich_pipeline(normalize_release_definition(r, catalog, "Payments", WEB, {}))
    gh = RepoRef(id="contoso-payments/ledger", name="contoso-payments/ledger", project="Payments", provider="github", service_connection_id="gh-1", url="https://github.com/contoso-payments/ledger")
    lin = build_repo_lineage(gh, [rp], [], [r], {}, {}, {}, CONNS)
    assert not lin.pipelines and lin.releases[0].sources[0].type == "GitHub"
    assert lin.releases[0].sources[0].name == "contoso-payments/ledger" and lin.releases[0].sources[0].branch == "main"
    assert lin.repo.provider == "github" and lin.repo.provider_label == "GitHub" and lin.repo.service_connection == "github-contoso"


def test_yaml_meta_triggers_resources_and_checkouts():
    text = """
trigger:
  branches: {include: [main, release/*], exclude: [wip]}
  paths: {include: [src], exclude: [docs]}
pr:
  branches: {include: [main]}
schedules:
  - cron: "0 3 * * *"
    branches: {include: [main]}
    always: true
resources:
  repositories:
    - {repository: app, type: github, name: contoso/app, ref: refs/heads/main}
    - {repository: tmpl, type: git, name: Platform/templates}
  pipelines:
    - {pipeline: up, source: Upstream CI, trigger: {branches: {include: [main]}}}
    - {pipeline: art, source: Other, project: Shared}
stages:
  - stage: B
    jobs:
      - job: j
        steps:
          - checkout: app
          - publish: out
            artifact: webdrop
          - task: Docker@2
            inputs: {command: buildAndPush, repository: contoso/api}
"""
    m = parse_yaml_meta(text)
    assert m.trigger.ci_branches == ["main", "release/*", "!wip"] and m.trigger.ci_paths == ["src", "!docs"] and m.trigger.pr_branches == ["main"]
    assert m.trigger.schedules == ["0 3 * * * on main"]
    assert m.code_repos() == [("github", "contoso/app")] and m.yaml_in_other_repo() and m.template_repos() == ["Platform/templates"]
    assert [(u.name, u.project) for u in m.upstream] == [("Upstream CI", None), ("Other", "Shared")]
    assert m.upstream[0].detail == "triggers on completion of main" and "no trigger" in m.upstream[1].detail
    assert m.artifacts == ["artifact: webdrop", "image: contoso/api"]
    assert parse_yaml_meta("trigger: none\n").trigger.ci_enabled is False
    assert parse_yaml_meta("stages: []\n").trigger.ci_enabled is True and parse_yaml_meta("stages: []\n").trigger.pr_enabled is None
    assert parse_yaml_meta("stages: []\n", external_pr_default=True).trigger.pr_enabled is True  # GitHub: absent pr = every PR
    assert parse_yaml_meta(": : not yaml [") is None
    selfco = parse_yaml_meta("resources:\n  repositories:\n    - {repository: lib, type: git, name: L}\nsteps:\n  - checkout: self\n  - checkout: lib\n")
    assert not selfco.yaml_in_other_repo()  # self is checked out too: the YAML lives with (some of) the code


def test_classic_build_triggers_and_completion_upstream():
    t, up = classic_build_meta({"triggers": [
        {"triggerType": "continuousIntegration", "branchFilters": ["+refs/heads/main", "-refs/heads/old"], "pathFilters": ["+/src", "-/docs"]},
        {"triggerType": "pullRequest", "branchFilters": ["+refs/heads/main"]},
        {"triggerType": "schedule", "schedules": [{"startHours": 2, "startMinutes": 30, "timeZoneId": "UTC", "daysToBuild": "monday, friday", "branchFilters": ["+refs/heads/main"]}]},
        {"triggerType": "buildCompletion", "definition": {"id": "7", "name": "Core-CI"}, "branchFilters": ["+refs/heads/main"], "requiresSuccessfulBuild": True}]})
    assert t.ci_branches == ["main", "!old"] and t.ci_paths == ["/src", "!/docs"] and t.pr_branches == ["main"]
    assert t.schedules == ["02:30 UTC (monday, friday) on main"]
    assert [(u.kind, u.name, u.pipeline_id) for u in up] == [("classic_completion", "Core-CI", "7")]
    off, _ = classic_build_meta({"triggers": []})
    assert off.ci_enabled is False and off.ci_summary() == "CI off"


def _simple_lin(key, project, pipelines):
    return RepoLineage.model_validate({"repo": {"key": key, "project": project, "name": key.split("/", 1)[1]}, "pipelines": pipelines})


def _pl(pid, name, **kw):
    return {"id": pid, "name": name, "kind": "yaml", "url": f"https://x/{pid}", **kw}


def test_downstream_links_across_repos_and_cross_project():
    a = _simple_lin("P/a", "P", [_pl("1", "Core CI")])
    b = _simple_lin("P/b", "P", [_pl("2", "b-ci", upstream=[{"kind": "yaml_resource", "name": "Core CI", "detail": "triggers on completion"}])])
    c = _simple_lin("Q/c", "Q", [{"id": "9", "name": "c-ci", "kind": "classic_build", "upstream": [{"kind": "classic_completion", "name": "Core CI", "pipeline_id": "1", "project": "P"}]}])
    d = _simple_lin("P/d", "P", [_pl("3", "d-ci", upstream=[{"kind": "yaml_resource", "name": "Nope", "detail": ""}])])
    link_lineages([a, b, c, d])
    assert [(x.name, x.repo_key, x.kind) for x in a.pipelines[0].downstream] == [("b-ci", "P/b", "yaml_resource"), ("c-ci", "Q/c", "classic_completion")]
    assert b.pipelines[0].upstream[0].repo_key == "P/a"
    assert d.pipelines[0].upstream[0].repo_key is None  # unresolvable upstream stays visible, unlinked


def test_pipeline_defined_in_templates_repo_is_adopted_by_the_code_repo():
    tmpl = _simple_lin("P/pipeline-templates", "P", [_pl("5", "app-ci", yaml_repo="pipeline-templates", yaml_in_other_repo=True, code_repos=["contoso/app"])])
    tmpl.releases = [RepoLineage.model_validate({"repo": {"key": "k", "project": "P", "name": "n"}, "releases": [{"id": "70", "name": "app-cd", "source_pipeline_ids": ["5"]}]}).releases[0]]
    app = _simple_lin("P/contoso/app", "P", [])
    link_lineages([tmpl, app])
    assert [(p.id, p.adopted_from) for p in app.pipelines] == [("5", "P/pipeline-templates")] and app.pipelines[0].yaml_repo == "pipeline-templates"
    assert [(r.id, r.adopted_from) for r in app.releases] == [("70", "P/pipeline-templates")]
    assert tmpl.pipelines[0].adopted_from is None
    link_lineages([tmpl, app])  # idempotent
    assert len(app.pipelines) == 1 and len(app.releases) == 1


def test_orphans_have_clear_reasons():
    assert "no artifact source" in orphan_release({"id": 1, "name": "r", "artifacts": []}, "P", WEB, set()).reason
    assert "not a build definition" in orphan_release({"id": 1, "name": "r", "artifacts": [{"type": "Build", "definitionReference": {"definition": {"id": "5", "name": "old-ci"}}}]}, "P", WEB, set()).reason
    assert "could not be resolved" in orphan_release({"id": 1, "name": "r", "artifacts": [{"type": "Build", "definitionReference": {"definition": {"id": "5", "name": "x"}}}]}, "P", WEB, {"5"}).reason
    assert "AzureContainerRepository" in orphan_release({"id": 1, "name": "r", "artifacts": [{"type": "AzureContainerRepository"}]}, "P", WEB, set()).reason
    o = orphan_build({"id": 9, "name": "legacy"}, "P", WEB, "no repo")
    assert o.type == "pipeline" and o.url.endswith("_build?definitionId=9")


def test_target_names_secret_values_are_dropped(fx, catalog):
    rp = enrich_pipeline(normalize_release_definition(fx("ado", "release_def_functionapp.json"), catalog, "Payments", WEB, {}))
    st = rp.stages[0]
    for step in st.steps():
        step.inputs["appName"] = "AKIAIOSFODNN7EXAMPLEKEYKEYKEYKEYKEYKEYKEY1234567890abcdef"
    targets = stage_targets(st)
    assert [t.kind for t in targets] == ["functionapp"] and targets[0].name is None  # the secret-looking value is not shown
