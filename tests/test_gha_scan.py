"""End to end (G3): a scan with the GitHub reader turns workflows into pipelines, runs the whole catalog, derives the migration status,
builds lineage for workflows and stays read-only. Failures are UNKNOWN, never FAIL."""

import asyncio
from pathlib import Path

import httpx
import respx
from fastapi.testclient import TestClient

from pch.collectors.ado.client import AdoClient
from pch.collectors.github.client import GitHubClient
from pch.engine.migration import migration_status, retire_candidates
from pch.orchestrator import ScanConfig, Scanner
from pch.settings import GitHubScope, Policy, Scope
from pch.sources import Sources
from pch.store import repository as store
from pch.store.db import session_scope
from tests.builders import ALL_HOSTS
from tests.github_mock import (
    API,
    PAT,
    actions_text,
    gh,
    link,
    mock_actions,
    mock_contents,
    mock_repo,
    workflow_contents,
)
from tests.test_external_repos import NOW, mock_ado

ORG = "contoso-payments"
BILLING, STANDALONE, LEDGER = f"Payments/{ORG}/billing-api", f"{ORG}/{ORG}/standalone-svc", f"Payments/{ORG}/ledger"


def mock_github(*, ledger_actions_denied=True):
    def page(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json=gh("org_repos_page2.json"))
        return httpx.Response(200, json=gh("org_repos_page1.json"), headers=link(f"{API}/orgs/{ORG}/repos?type=all&per_page=100&page=2"))

    respx.get(f"{API}/orgs/{ORG}/repos").mock(side_effect=page)
    mock_repo(f"{ORG}/billing-api", contents=workflow_contents())
    mock_contents("contoso-platform/workflows", {".github/workflows/scan.yml": actions_text("scan.yml")})
    mock_contents("contoso-platform/private-workflows", {})
    mock_actions(f"{ORG}/billing-api")
    mock_repo(f"{ORG}/orders-func", tree="tree_no_tests.json", classic=403, codeowners=None)
    mock_repo(f"{ORG}/ledger", tree="tree_no_tests.json", codeowners=None)
    mock_actions(f"{ORG}/ledger", workflows=403 if ledger_actions_denied else {"workflows": []}, environments=403, runs=403)
    mock_repo(f"{ORG}/standalone-svc", tree="tree_no_tests.json", rules=[], classic=None, codeowners=None, contents={".github/workflows/ci.yml": actions_text("ci.yml")})
    mock_actions(f"{ORG}/standalone-svc", workflows={"workflows": [{"id": 7, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active"}]}, runs={"workflow_runs": []}, environments={"environments": []})
    mock_actions(f"{ORG}/orders-func", workflows={"workflows": []}, environments={"environments": []}, runs={"workflow_runs": []})


def scan(tmp_path, **kw):
    db = f"sqlite:///{tmp_path}/g3.db"
    src = Sources(ado=AdoClient("contoso", "x", backoff_base=0, max_attempts=1), github=GitHubClient(API, token=PAT, backoff_base=0, max_attempts=1))
    scope = Scope(code_hosts=ALL_HOSTS, projects=["Payments"], github=GitHubScope(orgs=[ORG], exclude=["sandbox-*"]), env_tiers={"production": "prod"})
    cfg = ScanConfig(scope=scope, policy=Policy(), db_url=db, mode="demo", now=NOW)

    async def go():
        try:
            return await Scanner(src, cfg).run("g3")
        finally:
            await src.aclose()

    asyncio.run(go())
    return db


def statuses(s, repo, rule):
    return {f.status for f in store.findings(s, "g3", repo_key=repo, rule_id=rule)}


@respx.mock
def test_scan_turns_workflows_into_pipelines_and_applies_the_catalog(fx, fxt, tmp_path):
    mock_ado(fx, fxt, items_calls=[])
    mock_github()
    db = scan(tmp_path)
    with session_scope(db) as s:
        rows = {r.repo_key: r for r in store.repo_results(s, "g3")}
        b = rows[BILLING]
        assert "gha" in b.platform_mix and any(p["platform"] == "gha" for p in b.pipelines) and "webapp" in b.targets
        mig = b.external["migration"]
        assert mig["status"] == "in_progress"  # ADO pipelines and workflows side by side
        gha_names = {p["name"] for p in b.pipelines if p["platform"] == "gha"}
        assert {"CI", "Deploy", "Insecure", "Release", "Reusable tests"} <= gha_names
        # GHA rules and the audited catalog produce findings on workflows
        fs = {(f.rule_id, f.pipeline_name): f.status for f in store.findings(s, "g3", repo_key=BILLING)}
        assert fs[("SUP-006", "CI")] == "PASS" and fs[("SUP-006", "Insecure")] == "FAIL"
        assert fs[("SEC-007", "Insecure")] == "FAIL" and fs[("SEC-008", "Insecure")] == "FAIL" and fs[("SEC-006", "Insecure")] == "FAIL"
        assert fs[("SEC-003", "Deploy")] == "PASS" and fs[("SEC-003", "Insecure")] == "FAIL"
        for rid in ("DEP-001", "DEP-002", "DEP-003", "DEP-004", "SRC-005"):  # production: reviewers + prevent self-review + ServiceNow app + needs test + branch policy
            assert {f.status for f in store.findings(s, "g3", repo_key=BILLING, rule_id=rid) if f.pipeline_name == "Deploy"} == {"PASS"}, rid
        # the unreadable reusable workflow is noted: rules that would FAIL on its missing steps are UNKNOWN
        assert fs[("SUP-005", "Release")] == "UNKNOWN"
        # failures never FAIL: ledger's Actions API is denied -> collection errors, no pipelines invented
        led = rows[LEDGER]
        assert "gha" not in led.platform_mix
        errs = [e.message for e in store.collection_errors(s, "g3")]
        assert any("workflow list" in m and "403" in m for m in errs) and any("environments" in m for m in errs)
        # GHA-only repo: migrated
        sa = rows[STANDALONE]
        assert sa.external["migration"]["status"] == "migrated" and sa.migration_score is None
        assert "gha" in sa.platform_mix and any(f.pipeline_name == "CI" for f in store.findings(s, "g3", repo_key=STANDALONE))
        hyg = {f.status for f in store.findings(s, "g3", repo_key=STANDALONE, rule_id="HYG-001")}
        assert hyg == {"FAIL"}  # runs were readable and empty: stale
        # lineage: workflows appear as pipelines with workflow_run links and the last deployment of the environment
        from pch.model.lineage import RepoLineage

        doc = RepoLineage.model_validate(next(r.doc for r in store.lineage_rows(s, "g3") if r.repo_key == BILLING))
        wf = {p.name: p for p in doc.pipelines if p.kind == "gha"}
        assert [d.name for d in wf["CI"].downstream] == ["Deploy"] and wf["Deploy"].upstream[0].kind == "workflow_run"
        prod = next(st for st in wf["Deploy"].stages if st.name == "deploy-prod")
        assert prod.last_deploy.status == "succeeded" and prod.env_tier == "prod" and any("manual approval" in a for a in prod.approvals)
        assert next(st for st in wf["Deploy"].stages if st.name == "deploy-test").last_deploy.status == "never"
    assert all(c.request.method == "GET" or "/preview" in c.request.url.path for c in respx.calls)
    assert PAT.encode() not in Path(str(db).removeprefix("sqlite:///")).read_bytes()


@respx.mock
def test_web_migration_tab_repo_badges_and_lineage_export(fx, fxt, tmp_path):
    mock_ado(fx, fxt, items_calls=[])
    mock_github()
    db = scan(tmp_path)
    from pch.web.app import create_app

    with TestClient(create_app(db)) as c:
        data = c.get("/api/v1/migration").json()
        assert data["states"]["in_progress"] >= 1 and data["states"]["migrated"] >= 1 and data["gha_total"] >= 5
        only = c.get("/api/v1/migration?state=migrated").json()
        assert only["repos"] and all(r["migration_status"] == "migrated" for r in only["repos"])
        page = c.get("/migration?state=in_progress")
        assert page.status_code == 200 and "In progress (both)" in page.text and "Migrated (GHA only)" in page.text
        detail = c.get(f"/repos/{BILLING}")
        assert detail.status_code == 200 and "GitHub Actions" in detail.text and "ADO" in detail.text
        csv = c.get("/lineage.csv").text
        assert csv.splitlines()[0].endswith(",platform") and ",gha" in csv
        page = c.get(f"/lineage/{BILLING}", params={"view": "table"})
        assert page.status_code == 200 and "GitHub Actions workflow" in page.text and "Deploy" in page.text
        flow = c.get(f"/lineage/{BILLING}")
        assert flow.status_code == 200 and "GitHub Actions" in flow.text and 'data-flow-node="stage"' in flow.text and "Deploy" in flow.text
        assert any(r["platform_kinds"] == ["gha"] or "gha" in r["platform_kinds"] for r in c.get("/api/v1/repos?platform=gha").json()["repos"])


def test_migration_status_and_retire_candidates():
    assert migration_status(["ado_yaml"]) == "ado_only" and migration_status(["ado_classic_build", "gha"]) == "in_progress"
    assert migration_status(["gha"]) == "migrated" and migration_status([]) == "none"
    from pch.model.pipeline import Pipeline
    from tests.builders import pipe, stage, step

    ado = pipe([stage("Prod", [step("AzureWebApp@1")], tier="prod", env="production")])
    ado2 = pipe([stage("Dev", [step("AzureWebApp@1")], tier="dev", env="dev-env")], id="2")
    ado_other = pipe([stage("Data", [step("AzureFunctionApp@2")], tier="prod", env="data-prod")], id="3")
    gha = Pipeline(platform="gha", id="gha:1", name="Deploy", project="P", repo="r", stages=[stage("deploy", [step("azure/webapps-deploy@v3")], tier="prod", env="Production", is_deploy=True)])
    gha.stages[0].deploy_targets = {"webapp"}
    ado2.stages[0].deploy_targets = {"webapp"}
    got = {c["id"]: c["reason"] for c in retire_candidates([ado, ado2, ado_other, gha])}
    assert "same environment" in got[ado.id] and ado2.id not in got and ado_other.id not in got
    assert retire_candidates([ado, ado2]) == []
