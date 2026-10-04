"""Scan with the GitHub reader: org discovery merged with ADO-referenced repos, grouping keys, real PASS/FAIL, read-only (G2)."""

import asyncio
from pathlib import Path

import httpx
import respx

from pch.collectors.ado.client import AdoClient
from pch.collectors.github.client import GitHubClient
from pch.orchestrator import ScanConfig, Scanner
from pch.settings import GitHubScope, Policy, RepoOverride, Scope
from pch.sources import Sources
from pch.store import repository as store
from pch.store.db import session_scope
from tests.builders import ALL_HOSTS
from tests.github_mock import API, PAT, gh, link, mock_repo
from tests.test_external_repos import NOW, mock_ado

ORG = "contoso-payments"


def mock_github(*, listing=True):
    if listing:
        def page(request: httpx.Request) -> httpx.Response:
            if request.url.params.get("page") == "2":
                return httpx.Response(200, json=gh("org_repos_page2.json"))
            return httpx.Response(200, json=gh("org_repos_page1.json"), headers=link(f"{API}/orgs/{ORG}/repos?type=all&per_page=100&page=2"))

        respx.get(f"{API}/orgs/{ORG}/repos").mock(side_effect=page)
    mock_repo(f"{ORG}/billing-api")  # fully protected by a ruleset (bypass actor exists) + classic protection
    mock_repo(f"{ORG}/orders-func", tree="tree_no_tests.json", classic=403, codeowners=None)  # classic protection not readable
    mock_repo(f"{ORG}/ledger", rules=403, classic=403, tree="tree_no_tests.json", codeowners=None)  # nothing about protection readable
    mock_repo(f"{ORG}/standalone-svc", tree="tree_no_tests.json", rules=[], classic=None, codeowners=None)  # no pipeline anywhere, no protection


def scan(tmp_path, scope, *, github=True, policy=None):
    db = f"sqlite:///{tmp_path}/gh.db"
    src = Sources(ado=AdoClient("contoso", "x", backoff_base=0, max_attempts=1),
                  github=GitHubClient(API, token=PAT, backoff_base=0, max_attempts=1) if github else None)
    cfg = ScanConfig(scope=scope, policy=policy or Policy(), db_url=db, mode="demo", now=NOW)

    async def go():
        try:
            return await Scanner(src, cfg).run("gh")
        finally:
            await src.aclose()

    asyncio.run(go())
    return db


def status(s, repo, rule):
    return {f.status for f in store.findings(s, "gh", repo_key=repo, rule_id=rule)}


@respx.mock
def test_scan_unions_org_listing_ado_references_and_scope(fx, fxt, tmp_path):
    mock_ado(fx, fxt, items_calls=[])
    mock_github()
    scope = Scope(code_hosts=ALL_HOSTS, projects=["Payments"], github=GitHubScope(orgs=[ORG], exclude=["sandbox-*"]),
                  repos=[RepoOverride(project="Payments", repo=f"{ORG}/orders-func", owner="team@x.com")])
    db = scan(tmp_path, scope)
    with session_scope(db) as s:
        rows = {r.repo_key: r for r in store.repo_results(s, "gh")}
        # ADO-referenced repos keep `<project>/<org>/<repo>`; a repo with no ADO pipeline is grouped under its organisation: `<org>/<org>/<repo>`
        assert set(rows) == {"Payments/payments-api", f"Payments/{ORG}/billing-api", f"Payments/{ORG}/orders-func", f"Payments/{ORG}/ledger", f"{ORG}/{ORG}/standalone-svc"}
        assert rows[f"{ORG}/{ORG}/standalone-svc"].project == ORG and rows[f"{ORG}/{ORG}/standalone-svc"].repo == f"{ORG}/standalone-svc"
        assert rows[f"{ORG}/{ORG}/standalone-svc"].url == f"https://github.com/{ORG}/standalone-svc"  # archived / fork / sandbox-* never appear
        assert rows[f"Payments/{ORG}/billing-api"].owner == "@contoso-payments/payments-team"  # CODEOWNERS default rule
        assert rows[f"Payments/{ORG}/orders-func"].owner == "team@x.com"  # scope.yaml wins
        assert rows[f"Payments/{ORG}/billing-api"].facts["facts_source"] == "github"

        b = f"Payments/{ORG}/billing-api"
        assert [status(s, b, r) for r in ("SRC-001", "SRC-002", "SRC-003", "SRC-007", "SRC-009")] == [{"PASS"}] * 5
        assert status(s, b, "SRC-008") == {"FAIL"}  # the ruleset has a bypass actor
        assert status(s, b, "TST-001") == {"PASS"}  # test project in the tree
        prot = rows[b].external["protection"]
        assert prot["required_approving_review_count"] == 2 and prot["required_status_checks"] == ["build", "lint"] and prot["admins_can_bypass"] is True

        o = f"Payments/{ORG}/orders-func"  # classic unreadable: rulesets alone satisfy the controls, the rest is UNKNOWN, never FAIL
        assert status(s, o, "SRC-001") == {"PASS"} and status(s, o, "SRC-007") == {"PASS"}
        led = f"Payments/{ORG}/ledger"
        assert [status(s, led, r) for r in ("SRC-001", "SRC-002", "SRC-003", "SRC-007", "SRC-008")] == [{"UNKNOWN"}] * 5
        msgs = {f.message for f in store.findings(s, "gh", repo_key=led, rule_id="SRC-001")}
        assert any("branch rules" in m and "403" in m for m in msgs)

        sa = f"{ORG}/{ORG}/standalone-svc"  # visible without any pipeline, judged by its repo-level rules
        assert status(s, sa, "SRC-001") == {"FAIL"} and status(s, sa, "SRC-009") == {"FAIL"} and status(s, sa, "TST-001") == {"FAIL"}
        assert status(s, sa, "SRC-008") == set()  # not applicable without protection
        assert not store.findings(s, "gh", repo_key=sa, rule_id="HYG-001")  # pipeline rules do not apply: no pipeline
        assert rows[sa].status in ("NON_COMPLIANT", "AT_RISK")
        errs = [e.message for e in store.collection_errors(s, "gh")]
        assert any("classic branch protection" in m for m in errs)  # orders-func + ledger: one line per failed call

    # report-only: the scan sent nothing but GETs (plus ADO's YAML preview)
    assert all(c.request.method == "GET" or "/preview" in c.request.url.path for c in respx.calls)
    assert PAT.encode() not in Path(str(db).removeprefix("sqlite:///")).read_bytes()  # the token is never persisted
    assert all(c.request.headers.get("authorization") == f"Bearer {PAT}" for c in respx.calls if c.request.url.host == "api.github.com")


@respx.mock
def test_scope_repos_with_a_non_ado_project_group_under_that_name(fx, fxt, tmp_path):
    mock_ado(fx, fxt, items_calls=[])
    mock_github()
    scope = Scope(code_hosts=ALL_HOSTS, projects=["Payments"], github=GitHubScope(orgs=[ORG]),
                  repos=[RepoOverride(project="Platform", repo=f"{ORG}/standalone-svc", owner="p@x.com")])
    db = scan(tmp_path, scope)
    with session_scope(db) as s:
        rows = {r.repo_key: r for r in store.repo_results(s, "gh")}
        assert "Platform/contoso-payments/standalone-svc" in rows and f"{ORG}/{ORG}/standalone-svc" not in rows  # named once, grouped by the entry
        assert rows["Platform/contoso-payments/standalone-svc"].owner == "p@x.com"
        assert len([k for k in rows if k.endswith("standalone-svc")]) == 1


@respx.mock
def test_exclude_repos_and_waivers_use_the_org_grouped_key(fx, fxt, tmp_path):
    from pch.settings import Waiver

    mock_ado(fx, fxt, items_calls=[])
    mock_github()
    scope = Scope(code_hosts=ALL_HOSTS, projects=["Payments"], github=GitHubScope(orgs=[ORG]), exclude_repos=[f"{ORG}/{ORG}/Sandbox-Play"])
    db = scan(tmp_path, scope, policy=Policy(waivers=[Waiver(rule="SRC-001", repo=f"{ORG}/{ORG}/standalone-svc", reason="r", owner="o")]))
    with session_scope(db) as s:
        rows = {r.repo_key for r in store.repo_results(s, "gh")}
        assert f"{ORG}/{ORG}/sandbox-play" not in rows and f"{ORG}/{ORG}/standalone-svc" in rows
        assert status(s, f"{ORG}/{ORG}/standalone-svc", "SRC-001") == {"WAIVED"}


@respx.mock
def test_listing_failure_is_a_collection_error_and_the_scan_continues(fx, fxt, tmp_path):
    mock_ado(fx, fxt, items_calls=[])
    respx.get(f"{API}/orgs/{ORG}/repos").mock(return_value=httpx.Response(404, json={"message": "Not Found"}))
    for n in ("billing-api", "orders-func", "ledger"):
        mock_repo(f"{ORG}/{n}", meta="repo.json")
    scope = Scope(code_hosts=ALL_HOSTS, projects=["Payments"], github=GitHubScope(orgs=[ORG]))
    db = scan(tmp_path, scope)
    with session_scope(db) as s:
        assert store.get_scan(s, "gh").status == "complete"
        assert any(e.source == "github" and "repository listing" in e.subject for e in store.collection_errors(s, "gh"))
        assert {r.repo_key for r in store.repo_results(s, "gh")} >= {f"Payments/{ORG}/billing-api"}  # ADO-referenced repos are still read


@respx.mock
def test_without_a_reader_nothing_changes_and_configured_orgs_are_flagged(fx, fxt, tmp_path):
    mock_ado(fx, fxt, items_calls=[])
    scope = Scope(code_hosts=ALL_HOSTS, projects=["Payments"], github=GitHubScope(orgs=[ORG]))
    db = scan(tmp_path, scope, github=False)
    with session_scope(db) as s:
        rows = {r.repo_key: r for r in store.repo_results(s, "gh")}
        assert f"{ORG}/{ORG}/standalone-svc" not in rows  # still invisible without the reader (ADR-13), but now the scan says so:
        assert any("no GitHub reader is configured" in e.message for e in store.collection_errors(s, "gh"))
        assert rows[f"Payments/{ORG}/billing-api"].facts["facts_source"] == "unavailable"
        assert status(s, f"Payments/{ORG}/billing-api", "SRC-001") == {"UNKNOWN"} and status(s, f"Payments/{ORG}/billing-api", "SRC-007") == {"UNKNOWN"}
        assert rows[f"Payments/{ORG}/billing-api"].external["protection"] is None
    assert not any(c.request.url.host == "api.github.com" for c in respx.calls)


@respx.mock
def test_code_hosts_must_list_the_reader_host(fx, fxt, tmp_path):
    mock_ado(fx, fxt, items_calls=[])
    mock_github(listing=False)
    respx.get(f"{API}/orgs/{ORG}/repos").mock(return_value=httpx.Response(200, json=gh("org_repos_page1.json")))
    scope = Scope(code_hosts=["github_enterprise", "azure_repos", "other_git"], projects=["Payments"], github=GitHubScope(orgs=[ORG]))  # github.com not in scope
    db = scan(tmp_path, scope)
    with session_scope(db) as s:
        assert any("code_hosts does not list 'github'" in e.message for e in store.collection_errors(s, "gh"))
