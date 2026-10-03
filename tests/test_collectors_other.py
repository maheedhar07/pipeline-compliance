from datetime import datetime

import httpx
import pytest
import respx

from pch.collectors.ado.client import AdoClient
from pch.collectors.ado.environments import apply_environment_checks, check_to_approval, collect_environments
from pch.collectors.ado.repo_policies import collect_policy_configurations, policies_for_repo
from pch.collectors.ado.service_conn import collect_service_connections
from pch.collectors.ado.variable_groups import collect_variable_groups
from pch.collectors.aikido import AikidoClient, normalize_issue
from pch.collectors.servicenow import ServiceNowClient, change_is_valid, to_change, window_covers
from pch.collectors.transport import MutationBlockedError
from pch.model.pipeline import Job, Pipeline, Stage

ORG = "https://dev.azure.com/contoso/P"


# ------------------------------------------------------------------ Aikido
@respx.mock
async def test_aikido_oauth_and_facts(fx):
    tok = respx.post("https://app.aikido.dev/api/oauth/token").mock(return_value=httpx.Response(200, json=fx("aikido", "token.json")))
    repos = respx.get("https://app.aikido.dev/api/public/v1/repositories/code").mock(return_value=httpx.Response(200, json=fx("aikido", "repos.json")))
    issues = respx.get("https://app.aikido.dev/api/public/v1/open-issue-groups").mock(return_value=httpx.Response(200, json=fx("aikido", "issues.json")))
    c = AikidoClient("https://app.aikido.dev", "cid", "secret", backoff_base=0)
    f = await c.facts("payments-api")
    f2 = await c.facts("orders-func")
    f3 = await c.facts("unknown-repo")
    f4 = await c.facts("anything", override="payments-api")
    await c.aclose()
    assert tok.call_count == 1  # token cached in memory
    assert repos.called and issues.called
    assert repos.calls[0].request.headers["authorization"] == "Bearer test-token-not-real"
    assert f.onboarded and f.count("critical") == 1 and f.count("high") == 1  # issue 5 has no date, dropped
    assert f2.onboarded and f2.count("medium") == 1  # matched by "Payments/orders-func" suffix, epoch date parsed
    assert not f3.onboarded and f3.open_issues == []
    assert f4.repo_id == "101"


def test_aikido_normalize_issue_variants():
    assert normalize_issue({"id": 1, "severity": "HIGH", "time_first_detected": "2026-01-01T00:00:00Z", "repo_id": 5})[0] == "5"
    assert normalize_issue({"id": 1}) is None
    rid, issue = normalize_issue({"id": 2, "severity": "low", "created_at": "2026-01-01T00:00:00", "code_repo": {"id": 7}})
    assert rid == "7" and issue.severity == "low"


@respx.mock
async def test_aikido_paging():
    respx.post("https://app.aikido.dev/api/oauth/token").mock(return_value=httpx.Response(200, json={"access_token": "t"}))
    page0 = [{"id": i, "name": f"r{i}"} for i in range(200)]

    def handler(request):
        return httpx.Response(200, json=page0 if request.url.params["page"] == "0" else [{"id": 999, "name": "last"}])

    respx.get("https://app.aikido.dev/api/public/v1/repositories/code").mock(side_effect=handler)
    respx.get("https://app.aikido.dev/api/public/v1/open-issue-groups").mock(return_value=httpx.Response(200, json=[]))
    c = AikidoClient("https://app.aikido.dev", "a", "b", backoff_base=0)
    repos, _ = await c.fetch_all()
    await c.aclose()
    assert len(repos) == 201


# -------------------------------------------------------------- ServiceNow
@respx.mock
async def test_servicenow_by_numbers_and_ci(fx):
    route = respx.get("https://snow.example.com/api/now/table/change_request").mock(
        return_value=httpx.Response(200, json=fx("servicenow", "changes.json")))
    c = ServiceNowClient("https://snow.example.com", "u", "p", backoff_base=0)
    got = await c.by_numbers(["CHG0030001", "CHG0030002"])
    ci = await c.by_ci("payments-api", datetime(2026, 9, 1))
    assert await c.by_numbers([]) == {}
    await c.aclose()
    assert set(got) == {"CHG0030001", "CHG0030002", "CHG0030003"}
    q = route.calls[0].request.url.params["sysparm_query"]
    assert q.startswith("numberINCHG0030001,CHG0030002")
    assert "cmdb_ci.nameLIKEpayments-api" in route.calls[1].request.url.params["sysparm_query"]
    assert len(ci) == 3 and ci[1].ci == "payments-api"  # display_value dict flattened


def test_change_validity_and_window(fx):
    crs = {r["number"]: to_change(r) for r in fx("servicenow", "changes.json")["result"]}
    assert change_is_valid(crs["CHG0030001"])
    assert not change_is_valid(crs["CHG0030002"])  # canceled
    assert change_is_valid(crs["CHG0030003"])  # Scheduled state counts as approved-capable
    cr = crs["CHG0030001"]
    assert window_covers(cr, datetime(2026, 9, 10, 12))
    assert window_covers(cr, datetime(2026, 9, 10, 19, 30))  # 2h slack
    assert not window_covers(cr, datetime(2026, 9, 11, 12))


# ---------------------------------------------------------------- policies
@respx.mock
async def test_branch_policies(fx):
    respx.get(f"{ORG}/_apis/policy/configurations").mock(return_value=httpx.Response(200, json=fx("ado", "policies.json")))
    c = AdoClient("contoso", "x", backoff_base=0)
    cfgs = await collect_policy_configurations(c, "P")
    await c.aclose()
    pol = policies_for_repo(cfgs, "repo-1", "main")
    assert pol.available and pol.min_reviewers == 2 and pol.creator_vote_counts is False and pol.reset_on_push
    assert pol.build_validation and pol.work_item_required and pol.comment_resolution_required
    assert pol.required_reviewer_paths == ["/azure-pipelines*.yml"]
    other = policies_for_repo(cfgs, "repo-x", "main")
    assert other.min_reviewers is None and not other.build_validation
    assert policies_for_repo(cfgs, "repo-1", "develop").min_reviewers is None  # different branch


def test_project_wide_and_prefix_scope():
    cfgs = [{"isEnabled": True, "type": {"id": "0609b952-1397-4640-95ec-e00a01b2c241"},
             "settings": {"scope": [{"repositoryId": None, "refName": "refs/heads/release", "matchKind": "Prefix"}]}}]
    assert policies_for_repo(cfgs, "any", "release/1.0").build_validation
    assert not policies_for_repo(cfgs, "any", "main").build_validation


# ------------------------------------------------------- service connections
@respx.mock
async def test_service_connections(fx):
    respx.get(f"{ORG}/_apis/serviceendpoint/endpoints").mock(return_value=httpx.Response(200, json=fx("ado", "endpoints.json")))
    respx.get(f"{ORG}/_apis/pipelines/pipelinePermissions/endpoint/e1").mock(return_value=httpx.Response(200, json=fx("ado", "endpoint_perms_e1.json")))
    respx.get(f"{ORG}/_apis/pipelines/pipelinePermissions/endpoint/e2").mock(return_value=httpx.Response(200, json=fx("ado", "endpoint_perms_e2.json")))
    respx.get(f"{ORG}/_apis/pipelines/pipelinePermissions/endpoint/e3").mock(return_value=httpx.Response(403))
    c = AdoClient("contoso", "x", backoff_base=0)
    sc = await collect_service_connections(c, "P")
    await c.aclose()
    assert sc["e1"] is sc["conn-prod-wif"]
    assert sc["e1"].federated and sc["e1"].all_pipelines_authorized is False and sc["e1"].scope_level == "Subscription"
    assert not sc["e2"].federated and sc["e2"].all_pipelines_authorized is True and sc["e2"].scope_level == "ResourceGroup"
    assert sc["e3"].all_pipelines_authorized is None  # no permission to read -> unknown


@respx.mock
async def test_variable_groups(fx):
    respx.get(f"{ORG}/_apis/distributedtask/variablegroups").mock(return_value=httpx.Response(200, json=fx("ado", "variablegroups.json")))
    c = AdoClient("contoso", "x", backoff_base=0)
    vg = await collect_variable_groups(c, "P")
    await c.aclose()
    assert not vg["payments-common"].key_vault_linked and vg["6"].key_vault_linked
    assert "value" not in vg["5"].model_dump() and vg["6"].has_secrets and not vg["5"].has_secrets


# ------------------------------------------------------------- environments
@respx.mock
async def test_environments_and_checks(fx):
    respx.get(f"{ORG}/_apis/distributedtask/environments").mock(return_value=httpx.Response(200, json=fx("ado", "environments.json")))

    def checks(request):
        rid = request.url.params["resourceId"]
        return httpx.Response(200, json=fx("ado", f"env_checks_{rid}.json"))

    route = respx.get(f"{ORG}/_apis/pipelines/checks/configurations").mock(side_effect=checks)
    c = AdoClient("contoso", "x", backoff_base=0)
    envs = await collect_environments(c, "P")
    await c.aclose()
    assert route.call_count == 2
    assert len(envs["orders-prod"].checks) == 3 and envs["orders-dev"].checks == []

    p = Pipeline(platform="ado_yaml", id="1", name="p", project="P",
                 stages=[Stage(name="Prod", env_name="orders-prod", jobs=[Job(name="j")]), Stage(name="Dev", env_name="orders-dev")])
    apply_environment_checks(p, envs)
    prod = p.stage("Prod")
    assert prod.pre_approvals[0].kind == "manual" and prod.pre_approvals[0].requester_can_approve is False
    assert prod.pre_approvals[0].approvers == ["Alice Lead"]
    kinds = {g.kind for g in prod.gates}
    assert kinds == {"branch_control", "servicenow"}
    assert prod.branch_filters == ["main", "release/*"]
    assert not p.stage("Dev").pre_approvals and not p.stage("Dev").gates


def test_check_type_mapping():
    assert check_to_approval({"type": {"name": "BusinessHours"}}).kind == "business_hours"
    assert check_to_approval({"type": {"name": "TaskCheck"}, "settings": {"displayName": "Azure Monitor"}}).kind == "gate"
    a = check_to_approval({"type": {"name": "Approval"}, "settings": {"approvers": []}})
    assert a.requester_can_approve is True  # requesterCannotBeApprover absent => requester may approve


def test_apply_checks_ignores_classic():
    p = Pipeline(platform="ado_classic_release", id="1", name="p", project="P", stages=[Stage(name="x", env_name="orders-prod")])
    apply_environment_checks(p, {})  # no-op


async def test_no_mutation_possible_via_collectors():
    c = AdoClient("contoso", "x", backoff_base=0)
    with pytest.raises(MutationBlockedError):
        await c.http.request("POST", f"{ORG}/_apis/serviceendpoint/endpoints", json={})
    await c.aclose()
