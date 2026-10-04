"""Externally hosted (GitHub) repos built by Azure DevOps pipelines: discovery, linking, facts, rules, scan (L1)."""

import asyncio
import copy
import re
from datetime import datetime

import httpx
import pytest
import respx

from pch.collectors.ado.client import AdoClient
from pch.collectors.ado.repo_discovery import discover, provider_of
from pch.model.repo import BranchPolicies, RepoFacts, TestState, unavailable_reason
from pch.orchestrator import ScanConfig, Scanner
from pch.repo_scan.external import infer_external_kind, unavailable_facts
from pch.repo_scan.tests_detect import classify_test_state
from pch.settings import Policy, RepoOverride, Scope, Waiver
from pch.sources import Sources
from pch.store import repository as store
from pch.store.db import session_scope
from tests.builders import ctx, one, pipe, stage, step

GH_REASON = "GitHub-hosted: repository contents/branch protection need the GitHub reader (not configured)"
NOW = datetime(2026, 10, 1, 12, 0, 0)


def gh_ctx(pipelines=(), **kw):
    """RepoContext of a GitHub-hosted repo: nothing was read from the repo, ADO branch policies do not apply."""
    facts = unavailable_facts("github")
    return ctx(pipelines, facts=facts, policies=BranchPolicies(available=False, unavailable_reason=facts.facts_reason),
               repo_kw={"name": "contoso/r", "provider": "github", "full_name": "contoso/r"}, **kw)


# ------------------------------------------------------------------ discovery + linking
def test_provider_mapping():
    assert provider_of("TfsGit") == "azure_repos" and provider_of("GitHub") == "github"
    assert provider_of("GitHubEnterprise") == "github_enterprise" and provider_of("Bitbucket") == "other_git"
    assert provider_of("Git") == "other_git" and provider_of(None) is None


def test_discover_mixes_azure_and_github(fx):
    azure = [{"id": "repo-1", "name": "payments-api", "defaultBranch": "refs/heads/main", "webUrl": "https://dev.azure.com/o/P/_git/payments-api"}]
    builds = [fx("ado", "build_def_classic_dotnet.json"), fx("ado", "build_def_github_classic.json"), fx("ado", "build_def_github_yaml.json")]
    d = discover(azure, builds, [])
    by_name = {r.name: r for r in d.repos}
    assert set(by_name) == {"payments-api", "contoso-payments/billing-api", "contoso-payments/orders-func"}
    gh = by_name["contoso-payments/billing-api"]
    assert gh.provider == "github" and gh.external and gh.url == "https://github.com/contoso-payments/billing-api"  # no .git
    assert gh.service_connection_id == "0b4e5b1c-7a38-4f6e-9d7c-3c1f6a2b8e11" and gh.default_branch == "refs/heads/main"
    assert not by_name["payments-api"].external
    assert [b["id"] for b in d.builds_by_repo[gh.link_key]] == [41]


def test_discover_dedupes_case_insensitively_and_per_provider(fx):
    a = fx("ado", "build_def_github_classic.json")
    b = copy.deepcopy(fx("ado", "build_def_github_yaml.json"))
    b["repository"]["id"] = b["repository"]["name"] = "CONTOSO-Payments/Billing-API"
    ghe = copy.deepcopy(a)
    ghe["id"] = 99
    ghe["repository"]["type"] = "GitHubEnterprise"
    d = discover([], [a, b, ghe], [])
    names = sorted((r.provider, r.name) for r in d.repos)
    assert names == [("github", "contoso-payments/billing-api"), ("github_enterprise", "contoso-payments/billing-api")]
    gh = next(r for r in d.repos if r.provider == "github")
    assert len(d.builds_by_repo[gh.link_key]) == 2  # both definitions build the same repo


def test_discover_other_git_and_ignored_blocks():
    bb = {"id": 5, "repository": {"id": "ws/repo", "name": "ws/repo", "type": "Bitbucket", "url": "https://bitbucket.org/ws/repo.git"}}
    nameless = {"id": 6, "repository": {"type": "GitHub"}}
    norepo = {"id": 7}
    d = discover([], [bb, nameless, norepo], [])
    assert [(r.provider, r.name, r.url) for r in d.repos] == [("other_git", "ws/repo", "https://bitbucket.org/ws/repo")]


def test_release_links_via_build_artifact_and_direct_github_artifact(fx):
    builds = [fx("ado", "build_def_github_classic.json")]
    via_build = copy.deepcopy(fx("ado", "release_def_functionapp.json"))
    via_build["id"] = 50
    via_build["artifacts"][0]["definitionReference"]["definition"]["id"] = "41"
    direct = fx("ado", "release_def_github_artifact.json")
    orphan = copy.deepcopy(via_build)
    orphan["id"] = 51
    orphan["artifacts"][0]["definitionReference"]["definition"]["id"] = "9999"
    d = discover([], builds, [via_build, direct, orphan])
    keys = {r.name: r for r in d.repos}
    assert set(keys) == {"contoso-payments/billing-api", "contoso-payments/ledger"}  # ledger exists only as a release artifact
    assert [r["id"] for r in d.releases_by_repo[keys["contoso-payments/billing-api"].link_key]] == [50]
    ledger = keys["contoso-payments/ledger"]
    assert [r["id"] for r in d.releases_by_repo[ledger.link_key]] == [43]
    assert ledger.url == "https://github.com/contoso-payments/ledger" and ledger.service_connection_id == "0b4e5b1c-7a38-4f6e-9d7c-3c1f6a2b8e11"
    assert [r["id"] for r in d.unlinked_releases] == [51]  # genuinely unlinkable stays an error


def test_release_prefers_primary_artifact(fx):
    rel = copy.deepcopy(fx("ado", "release_def_github_artifact.json"))
    rel["artifacts"].insert(0, {"type": "Build", "alias": "_b", "isPrimary": False, "definitionReference": {"definition": {"id": "41"}}})
    d = discover([], [fx("ado", "build_def_github_classic.json")], [rel])
    ledger = next(r for r in d.repos if r.name.endswith("/ledger"))
    assert d.releases_by_repo[ledger.link_key]  # the primary (GitHub) artifact decides


# ------------------------------------------------------------------ facts + test state
def test_unavailable_facts_are_not_empty_facts():
    f = unavailable_facts("github")
    assert f.facts_source == "unavailable" and f.facts_reason == GH_REASON == unavailable_reason("github_enterprise")
    assert "another host" not in unavailable_reason("other_git") and "not Azure Repos" in unavailable_reason("other_git")
    assert RepoFacts().facts_source == "ado_items"


def test_external_test_state_unknown_unless_pipeline_proves_tests():
    f = unavailable_facts("github")
    st, reason, _ = classify_test_state(f, [], None)
    assert st == TestState.UNKNOWN and GH_REASON in reason
    testing = pipe([stage("Build", [step("DotNetCoreCLI@2", {"command": "test"})])])
    st, _, _ = classify_test_state(f, [testing], None)
    assert st == TestState.TESTS_NO_COVERAGE  # the pipeline itself proves tests run
    disabled = pipe([stage("Build", [step("DotNetCoreCLI@2", {"command": "test"}, enabled=False)])])
    assert classify_test_state(f, [disabled], None)[0] == TestState.UNKNOWN  # never NO_TESTS / TESTS_NOT_RUN
    # an ADO-hosted repo keeps its semantics
    assert classify_test_state(RepoFacts(), [], None)[0] == TestState.NO_TESTS


def test_infer_external_kind_from_deploy_targets():
    adf = pipe([stage("Prod", [step("script", script="x")], tier="prod")])
    adf.stages[0].deploy_targets = {"adf"}
    assert infer_external_kind([adf]) == "adf"
    adf.stages[0].deploy_targets = {"adf", "functionapp"}
    assert infer_external_kind([adf]) is None
    assert infer_external_kind([]) is None


# ------------------------------------------------------------------ rules: UNKNOWN, never FAIL, for a GitHub-hosted repo
@pytest.mark.parametrize("rule_id", ["SRC-001", "SRC-002", "SRC-003"])
def test_branch_policy_rules_unknown_for_github(rule_id):
    c = gh_ctx([pipe([stage("Build", [step("DotNetCoreCLI@2", {"command": "build"})])])])
    assert one(rule_id, c) == "UNKNOWN"
    # the same rules still FAIL on an Azure Repos repo whose policies were collected
    assert one(rule_id, ctx([], policies=BranchPolicies(available=True))) == "FAIL"


def test_src_unknown_messages_carry_the_reason():
    from tests.builders import run

    assert all(f.message == GH_REASON for f in run("SRC-001", gh_ctx()))


def test_src006_unknown_for_github_yaml_na_without_yaml():
    yaml_pipe = pipe([stage("Build", [step("DotNetCoreCLI@2")])], platform="ado_yaml")
    assert one("SRC-006", gh_ctx([yaml_pipe])) == "UNKNOWN"
    classic = pipe([stage("Build", [step("DotNetCoreCLI@2")])], platform="ado_classic_build")
    from tests.builders import statuses

    assert statuses("SRC-006", gh_ctx([classic])) == []  # not applicable: no YAML pipeline
    # ADO-hosted: FAIL when there is YAML but no CODEOWNERS / reviewer policy
    assert one("SRC-006", ctx([yaml_pipe], policies=BranchPolicies(available=True))) == "FAIL"


def test_tst_rules_unknown_for_github_without_proof_and_normal_with_proof():
    c = gh_ctx([pipe([stage("Build", [step("DotNetCoreCLI@2", {"command": "build"})])])])
    c.facts.test_state, c.facts.test_state_reason = TestState.UNKNOWN, GH_REASON
    assert [one(r, c) for r in ("TST-001", "TST-002", "TST-003")] == ["UNKNOWN"] * 3
    proven = gh_ctx([pipe([stage("Build", [step("DotNetCoreCLI@2", {"command": "test"})])])])
    proven.facts.test_state, proven.facts.test_state_reason = TestState.TESTS_NO_COVERAGE, ""
    assert one("TST-001", proven) == "PASS" and one("TST-002", proven) == "PASS" and one("TST-003", proven) == "FAIL"


def test_tst006_for_github_repos():
    app = pipe([stage("Prod", [step("AzureFunctionApp@2", {"appName": "a"})], tier="prod", env="e")])
    assert app.deploy_targets
    from tests.builders import statuses

    assert statuses("TST-006", gh_ctx([app])) == []  # deploys application targets: not applicable
    assert one("TST-006", gh_ctx([pipe([stage("Build", [step("script", script="echo")])])])) == "UNKNOWN"
    c = gh_ctx([app])
    c.facts.kind = "adf"
    assert one("TST-006", c) == "FAIL"  # an inferred ADF repo is judged by what its pipelines do


# ------------------------------------------------------------------ scope helpers
def test_scope_override_matches_github_names_case_insensitively():
    s = Scope(repos=[RepoOverride(project="Payments", repo="Contoso/Billing-API", owner="o@x")])
    assert s.override_for("Payments", "contoso/billing-api").owner == "o@x"
    assert s.override_for("Other", "contoso/billing-api") is None


def test_waiver_matches_full_and_bare_github_names():
    from pch.engine.scoring import apply_waivers
    from pch.model.findings import Finding, Severity, Status

    def f():
        return Finding(rule_id="SRC-004", repo_key="Payments/contoso/billing-api", category="SRC", severity=Severity.HIGH, status=Status.FAIL)

    for target in ("Payments/contoso/billing-api", "contoso/billing-api"):
        fs = [f()]
        apply_waivers(fs, "Payments/contoso/billing-api", Policy(waivers=[Waiver(rule="SRC-004", repo=target, reason="r", owner="o")]), NOW.date())
        assert fs[0].status == Status.WAIVED
    fs = [f()]
    apply_waivers(fs, "Payments/contoso/billing-api", Policy(waivers=[Waiver(rule="SRC-004", repo="billing-api", reason="r", owner="o")]), NOW.date())
    assert fs[0].status == Status.FAIL  # a bare short name is not a match


# ------------------------------------------------------------------ orchestrator against respx (ADO shapes)
ORG = "https://dev.azure.com/contoso"
VSRM = "https://vsrm.dev.azure.com/contoso"
P = f"{ORG}/Payments/_apis"


def mock_ado(fx, fxt, *, items_calls: list[str], preview_ok=True, extra_builds=(), extra_releases=()):
    azure_build = fx("ado", "build_def_classic_dotnet.json")
    gh_classic = fx("ado", "build_def_github_classic.json")
    gh_yaml = fx("ado", "build_def_github_yaml.json")
    builds = [azure_build, gh_classic, gh_yaml, *extra_builds]
    releases = [fx("ado", "release_def_github_artifact.json"), *extra_releases]
    respx.get(f"{ORG}/_apis/distributedtask/tasks").mock(return_value=httpx.Response(200, json=fx("ado", "tasks.json")))
    respx.get(f"{P}/distributedtask/taskgroups").mock(return_value=httpx.Response(200, json=fx("ado", "taskgroups.json")))
    respx.get(f"{P}/git/repositories").mock(return_value=httpx.Response(200, json={"value": [
        {"id": "repo-1", "name": "payments-api", "defaultBranch": "refs/heads/main", "webUrl": f"{ORG}/Payments/_git/payments-api"}]}))

    def items(request: httpx.Request) -> httpx.Response:
        items_calls.append(request.url.path)
        return httpx.Response(404, json={})

    respx.get(url__regex=rf"{re.escape(P)}/git/repositories/[^/]+/items").mock(side_effect=items)
    respx.get(f"{P}/build/definitions").mock(return_value=httpx.Response(200, json={"value": [{"id": b["id"], "name": b["name"]} for b in builds]}))
    for b in builds:
        respx.get(f"{P}/build/definitions/{b['id']}").mock(return_value=httpx.Response(200, json=b))
    respx.get(f"{VSRM}/Payments/_apis/release/definitions").mock(return_value=httpx.Response(200, json={"value": [{"id": r["id"], "name": r["name"]} for r in releases]}))
    for r in releases:
        respx.get(f"{VSRM}/Payments/_apis/release/definitions/{r['id']}").mock(return_value=httpx.Response(200, json=r))
    final = fxt("ado", "yaml_github_functionapp.yaml")
    if preview_ok:
        respx.post(url__regex=rf"{re.escape(P)}/pipelines/\d+/preview").mock(return_value=httpx.Response(200, json={"finalYaml": final}))
    else:
        respx.post(url__regex=rf"{re.escape(P)}/pipelines/\d+/preview").mock(return_value=httpx.Response(403, json={"message": "no"}))
    respx.get(f"{P}/policy/configurations").mock(return_value=httpx.Response(200, json={"value": [
        {"id": 1, "isEnabled": True, "type": {"id": "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"}, "settings": {"minimumApproverCount": 2, "resetOnSourcePush": True,
         "scope": [{"repositoryId": "repo-1", "refName": "refs/heads/main", "matchKind": "Exact"}]}}]}))
    for path in ("serviceendpoint/endpoints", "distributedtask/variablegroups", "distributedtask/environments", "build/builds"):
        respx.get(f"{P}/{path}").mock(return_value=httpx.Response(200, json={"value": []}))
    respx.get(url__regex=rf"{re.escape(VSRM)}/Payments/_apis/release/deployments").mock(return_value=httpx.Response(200, json={"value": []}))


def scan(tmp_path, scope=None, policy=None):
    db = f"sqlite:///{tmp_path}/ext.db"
    src = Sources(ado=AdoClient("contoso", "x", backoff_base=0, max_attempts=1))
    cfg = ScanConfig(scope=scope or Scope(projects=["Payments"]), policy=policy or Policy(), db_url=db, mode="demo", now=NOW)

    async def go():
        try:
            return await Scanner(src, cfg).run("ext")
        finally:
            await src.aclose()

    asyncio.run(go())
    return db


@respx.mock
def test_scan_includes_github_repos_and_never_fails_on_missing_github_data(fx, fxt, tmp_path):
    items_calls: list[str] = []
    mock_ado(fx, fxt, items_calls=items_calls)
    db = scan(tmp_path)
    with session_scope(db) as s:
        rows = {r.repo_key: r for r in store.repo_results(s, "ext")}
        assert set(rows) == {"Payments/payments-api", "Payments/contoso-payments/billing-api", "Payments/contoso-payments/orders-func", "Payments/contoso-payments/ledger"}
        errs = [e.message for e in store.collection_errors(s, "ext")]
        assert not any("not linked" in m for m in errs)  # the GitHub-artifact release is linked
        gh = rows["Payments/contoso-payments/billing-api"]
        assert gh.url == "https://github.com/contoso-payments/billing-api" and gh.external["repo"]["provider"] == "github"
        assert gh.facts["facts_source"] == "unavailable" and gh.test_state in ("TESTS_NO_COVERAGE", "TESTS_OK", "TESTS_LOW_COVERAGE")
        assert [p["platform"] for p in rows["Payments/contoso-payments/ledger"].pipelines] == ["ado_classic_release"]
        assert any(p["platform"] == "ado_yaml" for p in rows["Payments/contoso-payments/orders-func"].pipelines)
        findings = store.findings(s, "ext")
        for f in findings:
            if f.repo_key.startswith("Payments/contoso-payments/") and f.rule_id in ("SRC-001", "SRC-002", "SRC-003", "SRC-006", "TST-001", "TST-002", "TST-006"):
                assert f.status in ("UNKNOWN", "PASS", "NOT_APPLICABLE"), (f.repo_key, f.rule_id, f.status)
        # TST-003 is a legitimate FAIL here: the pipeline runs tests but publishes no coverage (pipeline/Sonar data, not GitHub data)
        assert {f.status for f in findings if f.repo_key == "Payments/contoso-payments/billing-api" and f.rule_id == "TST-003"} == {"FAIL"}
        assert {f.status for f in findings if f.repo_key == "Payments/contoso-payments/ledger" and f.rule_id == "TST-001"} == {"UNKNOWN"}  # release only: no test proof
        assert {f.status for f in findings if f.repo_key == "Payments/contoso-payments/ledger" and f.rule_id == "SRC-001"} == {"UNKNOWN"}
        assert {f.status for f in findings if f.repo_key == "Payments/payments-api" and f.rule_id == "SRC-001"} == {"PASS"}  # Azure Repos unchanged
    assert not any("contoso-payments" in c for c in items_calls)  # no Items API call for GitHub repos
    assert any("repo-1" in c for c in items_calls)


@respx.mock
def test_scan_yaml_preview_failure_on_github_repo_skips_items_fallback(fx, fxt, tmp_path):
    items_calls: list[str] = []
    mock_ado(fx, fxt, items_calls=items_calls, preview_ok=False)
    db = scan(tmp_path)
    assert not any("contoso-payments" in c for c in items_calls)
    with session_scope(db) as s:
        errs = [(e.source, e.subject, e.message) for e in store.collection_errors(s, "ext")]
        assert any("orders-func" in sub and "fallback does not apply" in m for _, sub, m in errs)
        assert store.get_scan(s, "ext").status == "complete"


@respx.mock
def test_scan_scope_exclude_override_and_waiver_with_slash_names(fx, fxt, tmp_path):
    mock_ado(fx, fxt, items_calls=[])
    scope = Scope(projects=["Payments"], exclude_repos=["Payments/Contoso-Payments/Ledger"],
                  repos=[RepoOverride(project="Payments", repo="contoso-payments/billing-api", owner="team@x.com", sonar_key="k")])
    pol = Policy(waivers=[Waiver(rule="SRC-004", repo="contoso-payments/billing-api", reason="r", owner="o")])
    db = scan(tmp_path, scope, pol)
    with session_scope(db) as s:
        rows = {r.repo_key: r for r in store.repo_results(s, "ext")}
        assert "Payments/contoso-payments/ledger" not in rows
        assert rows["Payments/contoso-payments/billing-api"].owner == "team@x.com"
        src004 = [f for f in store.findings(s, "ext", repo_key="Payments/contoso-payments/billing-api", rule_id="SRC-004")]
        assert src004 and all(f.status == "WAIVED" for f in src004)
