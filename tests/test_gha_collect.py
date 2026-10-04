"""GitHub Actions collection (G3): workflows, reusable workflows, environments, runs and deployments through the read-only client."""

from datetime import datetime

import httpx
import respx

from pch.collectors.github.actions import MAX_REUSABLE, read_actions
from pch.collectors.github.client import GitHubClient
from tests.github_mock import (
    API,
    PAT,
    REPO,
    actions_text,
    link,
    mock_actions,
    mock_contents,
    mock_repo,
    workflow_contents,
)

NOW = datetime(2026, 10, 1, 12, 0, 0)
PLATFORM = "contoso-platform/workflows"


def client() -> GitHubClient:
    return GitHubClient(API, token=PAT, backoff_base=0, max_attempts=1)


def setup(**kw):
    mock_repo(REPO, contents=workflow_contents(), **kw.pop("repo", {}))
    mock_contents(PLATFORM, {".github/workflows/scan.yml": actions_text("scan.yml")})
    mock_contents("contoso-platform/private-workflows", {})  # not visible to the token
    return mock_actions(**kw)


@respx.mock
async def test_reads_workflows_files_reusables_environments_runs_and_deployments():
    routes = setup()
    r = await read_actions(client(), REPO, "main", now=NOW)
    assert [w.path for w in r.workflows] == [f".github/workflows/{n}.yml" for n in ("ci", "deploy", "insecure", "caller", "tests")]  # the dynamic CodeQL workflow has no file
    assert all(w.text for w in r.workflows) and r.workflows[2].state == "disabled_manually" and r.workflows[0].id == 101
    # reusable workflows: same repo (already read, no extra call), another repo on the same host, one that cannot be read
    assert r.reusable["./.github/workflows/tests.yml"] == actions_text("tests.yml")
    assert "SonarSource" in (r.reusable[f"{PLATFORM}/.github/workflows/scan.yml@0123456789abcdef0123456789abcdef01234567"] or "")
    gone = "contoso-platform/private-workflows/.github/workflows/gone.yml@v1"
    assert r.reusable[gone] is None and "404" in r.reusable_errors[gone]
    # environments with protection, branch policies and custom rules
    prod = r.environments["production"]
    assert prod.required_reviewers and prod.reviewers == ["team:payments-approvers", "user:alice"] and prod.prevent_self_review is True and prod.wait_timer == 15
    assert prod.branch_policy == "custom" and prod.branch_patterns == ["main", "tag:v*"] and [c.slug for c in prod.custom_rules] == ["servicenow-devops"]
    assert r.environments["test"].branch_policy == "none" and not r.environments["test"].required_reviewers
    # runs: window filter sent, slimmed records
    assert routes["runs"].calls[0].request.url.params["created"] == ">=2026-07-03" and routes["runs"].calls[0].request.url.params["per_page"] == "100"
    assert len(r.runs or []) == 4 and not r.runs_truncated and (r.runs or [])[0]["actor"] == "alice"
    # last deployment per environment: one with a status, one never deployed
    assert r.deployments["production"].status == "success" and r.deployments["production"].creator == "alice" and r.deployments["production"].id == 7001
    assert r.deployments["test"].never
    assert not r.errors or all("gone.yml" in e for e in r.errors)
    assert all(c.request.method == "GET" for c in respx.calls)  # read-only: nothing but GETs


@respx.mock
async def test_failures_become_reasons_not_exceptions():
    setup(workflows=403, environments=403, runs=500, protection_rules={"production": 403}, branch_policies=403)
    r = await read_actions(client(), REPO, "main", now=NOW, known_paths=[".github/workflows/ci.yml", ".github/workflows/deploy.yml", "README.md"])
    assert not r.listed and "workflow list denied (HTTP 403)" in r.list_error and "Actions: read" in r.list_error
    assert [w.path for w in r.workflows] == [".github/workflows/ci.yml", ".github/workflows/deploy.yml"] and r.workflows[0].text  # the files stay readable through Contents
    assert r.environments is None and "Environments: read" in r.environments_error
    assert r.runs is None and "failed (HTTP 500)" in r.runs_error
    assert set(r.deployments) == {"test", "production"}  # environments named by the workflows are still looked up (the listing was denied)
    assert r.deployments["production"].status == "success"


@respx.mock
async def test_environment_sub_resource_failures_are_isolated():
    setup(protection_rules={"production": 403}, branch_policies=403)
    r = await read_actions(client(), REPO, "main", now=NOW)
    prod = r.environments["production"]
    assert prod.custom_error and "custom deployment protection rules" in prod.custom_error and prod.branch_error and "deployment branch policies" in prod.branch_error
    assert prod.required_reviewers  # the rest of the environment is intact
    assert any("deployment_protection_rules" in str(c.request.url) for c in respx.calls)


@respx.mock
async def test_runs_are_paged_with_a_cap_and_truncation_is_flagged():
    mock_repo(REPO, contents=workflow_contents())
    mock_actions(runs=None)
    base = f"{API}/repos/{REPO}/actions/runs"
    respx.get(base).mock(side_effect=lambda req: httpx.Response(200, json={"workflow_runs": [{"workflow_id": 101, "status": "completed", "conclusion": "success", "updated_at": "2026-09-01T00:00:00Z"}]},
                                                                 headers=link(f"{base}?per_page=100&page=2")))
    r = await read_actions(client(), REPO, "main", now=NOW)
    assert r.runs_truncated and len(r.runs or []) == 5  # MAX_RUN_PAGES pages of one run each


@respx.mock
async def test_reusable_workflow_cap_and_invalid_reference():
    many = "jobs:\n" + "".join(f"  j{i}:\n    uses: ./.github/workflows/w{i}.yml\n" for i in range(MAX_REUSABLE + 2)) + "  bad:\n    uses: ./.github/workflows/../../x.yml\n"
    files = {".github/workflows/many.yml": many, **{f".github/workflows/w{i}.yml": "on: workflow_call\njobs: {}\n" for i in range(MAX_REUSABLE + 2)}}
    mock_repo(REPO, contents=files)
    mock_actions(workflows={"workflows": [{"id": 1, "name": "many", "path": ".github/workflows/many.yml", "state": "active"}]})
    r = await read_actions(client(), REPO, "main", now=NOW)
    skipped = [u for u, t in r.reusable.items() if t is None]
    assert len(skipped) >= 2 and all("more than" in r.reusable_errors[u] for u in skipped[-2:])
    assert any("only 10 were fetched" in e for e in r.errors)


@respx.mock
async def test_invalid_repo_name_makes_no_calls():
    r = await read_actions(client(), "bad name/x", "main", now=NOW)
    assert not r.listed and "not a valid org/repo" in r.list_error and not respx.calls
