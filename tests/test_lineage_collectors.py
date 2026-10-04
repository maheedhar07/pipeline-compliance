"""Last-deployment collectors (L2): classic release deployments and YAML environment records, against respx fixtures."""

import httpx
import respx

from pch.collectors.ado.client import AdoClient
from pch.collectors.ado.deployments import (
    EnvRecordCache,
    collect_release_deployments,
    collect_yaml_deployments,
    display_name,
    map_release_status,
    map_result,
    short_sha,
)

VSRM = "https://vsrm.dev.azure.com/contoso/Payments/_apis/release"
ADO = "https://dev.azure.com/contoso/Payments/_apis"


def client():
    return AdoClient("contoso", "x", backoff_base=0, max_attempts=1)


def test_status_mapping_and_pii_helpers():
    assert map_release_status("succeeded", None) == "succeeded"
    assert map_release_status("partiallySucceeded", None) == "partial"
    assert map_release_status("failed", None) == "failed"
    assert map_release_status("inProgress", "PhaseInProgress") == "in_progress"
    assert map_release_status("notDeployed", "PreDeploymentApprovalPending") == "pending"
    assert map_release_status("notDeployed", "Rejected") == "canceled"
    assert map_release_status("weird", None) == "unknown"
    assert map_result("SucceededWithIssues") == "partial" and map_result("abandoned") == "canceled" and map_result("skipped") is None
    assert display_name({"displayName": "Ava Chen", "uniqueName": "ava@contoso.com"}) == "Ava Chen"
    assert display_name({"displayName": "ava@contoso.com"}) is None  # an email/UPN is never kept
    assert display_name(None) is None
    assert short_sha("a" * 40) == "aaaaaaa" and short_sha("20261001.3") == "20261001.3"


@respx.mock
async def test_release_deployments_last_per_environment_with_followup(fx):
    route = respx.get(f"{VSRM}/deployments").mock(side_effect=lambda r: httpx.Response(
        200, json=({"value": [{"id": 700, "release": {"id": 10, "name": "Release-10"}, "releaseEnvironment": {"name": "Production"}, "definitionEnvironmentId": 3,
                               "deploymentStatus": "partiallySucceeded", "startedOn": "2026-09-20T08:00:00Z", "completedOn": "2026-09-20T08:30:00Z",
                               "requestedFor": {"displayName": "Noor Haddad"}}]}
                   if r.url.params.get("definitionEnvironmentId") == "3" else fx("ado", "release_deployments.json"))))
    respx.get(f"{VSRM}/releases").mock(return_value=httpx.Response(200, json=fx("ado", "releases_with_artifacts.json")))
    single = respx.get(f"{VSRM}/releases/10").mock(return_value=httpx.Response(200, json={"id": 10, "artifacts": [
        {"type": "Build", "isPrimary": True, "definitionReference": {"version": {"id": "5010", "name": "20260920.1"}}}]}))
    c = client()
    errors: list[str] = []
    out = await collect_release_deployments(c, "Payments", "31", {"Dev": "1", "UAT": "2", "Production": "3"}, 200, errors.append)
    await c.aclose()
    assert not errors
    dev, uat, prod = out["Dev"], out["UAT"], out["Production"]
    assert (dev.status, dev.version, dev.artifact_version, dev.triggered_by) == ("succeeded", "Release-12", "20261001.3", "Ava Chen")
    assert dev.finished.isoformat() == "2026-10-01T08:09:30" and "releaseId=12" in dev.url
    assert (uat.status, uat.version, uat.artifact_version) == ("failed", "Release-11", "20260930.2")
    assert uat.triggered_by is None  # requestedBy was an email: dropped, never shown
    assert (prod.status, prod.version, prod.artifact_version, prod.triggered_by) == ("partial", "Release-10", "20260920.1", "Noor Haddad")
    assert single.call_count == 1  # only the release outside the listing page needed its own GET
    assert [call.request.url.params.get("definitionEnvironmentId") for call in route.calls] == [None, "3"]  # one listing + one follow-up for the missing stage


@respx.mock
async def test_release_never_deployed_unknown_and_failures_fail_open(fx):
    respx.get(f"{VSRM}/deployments").mock(side_effect=lambda r: httpx.Response(200, json={"value": []}) if r.url.params.get("definitionEnvironmentId") != "2" else httpx.Response(500, text="boom"))
    c = client()
    errors: list[str] = []
    out = await collect_release_deployments(c, "Payments", "31", {"Dev": "1", "UAT": "2"}, 200, errors.append)
    assert out["Dev"].status == "never"  # collected, nothing found
    assert out["UAT"].status == "unknown" and errors and "UAT" in errors[0]  # lookup failed: unknown, not never
    respx.get(f"{VSRM}/deployments").mock(return_value=httpx.Response(403, json={"message": "no"}))
    try:
        await collect_release_deployments(c, "Payments", "31", {"Dev": "1"}, 200, errors.append)
        raised = False
    except Exception:  # the caller turns this into a collection error and shows every stage as unknown
        raised = True
    await c.aclose()
    assert raised


@respx.mock
async def test_yaml_environment_records_mapped_to_definition_and_stage(fx):
    route = respx.get(f"{ADO}/distributedtask/environments/2/environmentdeploymentrecords").mock(return_value=httpx.Response(200, json=fx("ado", "environment_deployment_records.json")))
    respx.get(f"{ADO}/distributedtask/environments/1/environmentdeploymentrecords").mock(return_value=httpx.Response(200, json={"value": []}))
    c = client()
    cache = EnvRecordCache(c, 100)
    builds = [{"id": 501, "buildNumber": "20261001.2", "sourceVersion": "c" * 40, "requestedFor": {"displayName": "Liam Okafor", "uniqueName": "l@contoso.com"}}]
    errors: list[str] = []
    out = await collect_yaml_deployments(c, "Payments", "21", {"Dev": "orders-dev", "Prod": "orders-prod", "Smoke": "ghost-env"}, {"orders-dev": "1", "orders-prod": "2"}, cache, builds, errors.append)
    again = await collect_yaml_deployments(c, "Payments", "21", {"Prod": "orders-prod"}, {"orders-prod": "2"}, cache, builds, errors.append)  # second pipeline/stage: cached
    await c.aclose()
    prod = out["Prod"]
    assert (prod.status, prod.version, prod.artifact_version, prod.triggered_by) == ("succeeded", "20261001.2", "ccccccc", "Liam Okafor")  # the decoy record of another pipeline is ignored
    assert prod.finished.isoformat() == "2026-10-01T09:10:00" and "buildId=501" in prod.url
    assert out["Dev"].status == "never"
    assert out["Smoke"].status == "unknown" and "environment" in out["Smoke"].note
    assert again["Prod"].status == "succeeded" and route.call_count == 1  # one request per environment per scan
    assert not errors


@respx.mock
async def test_yaml_records_failure_and_full_page_are_unknown_not_never(fx):
    respx.get(f"{ADO}/distributedtask/environments/1/environmentdeploymentrecords").mock(return_value=httpx.Response(500, text="x"))
    respx.get(f"{ADO}/distributedtask/environments/2/environmentdeploymentrecords").mock(return_value=httpx.Response(200, json={"value": [
        {"definition": {"id": 99}, "stageName": "Prod", "result": "failed", "startTime": "2026-10-01T09:00:00Z"}, {"definition": {"id": 98}, "stageName": "Prod", "result": "failed", "startTime": "2026-09-01T09:00:00Z"}]}))
    c = client()
    errors: list[str] = []
    out = await collect_yaml_deployments(c, "Payments", "21", {"Dev": "orders-dev", "Prod": "orders-prod"}, {"orders-dev": "1", "orders-prod": "2"}, EnvRecordCache(c, 2), [], errors.append)
    await c.aclose()
    assert out["Dev"].status == "unknown" and errors
    assert out["Prod"].status == "unknown" and "latest 2" in out["Prod"].note  # the page is full of other pipelines: absence proves nothing


@respx.mock
async def test_environment_record_in_progress_and_skipped():
    respx.get(f"{ADO}/distributedtask/environments/2/environmentdeploymentrecords").mock(return_value=httpx.Response(200, json={"value": [
        {"definition": {"id": 21}, "stageName": "Prod", "owner": {"id": 9, "name": "20261003.1"}, "result": None, "startTime": "2026-10-03T09:00:00Z"}]}))
    c = client()
    out = await collect_yaml_deployments(c, "Payments", "21", {"Prod": "orders-prod"}, {"orders-prod": "2"}, EnvRecordCache(c, 100), [], lambda m: None)
    await c.aclose()
    assert out["Prod"].status == "in_progress" and out["Prod"].version == "20261003.1" and out["Prod"].triggered_by is None
