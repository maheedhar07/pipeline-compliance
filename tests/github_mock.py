"""respx helpers for the GitHub API (fixtures in tests/fixtures/github). Tokens used in tests are obviously fake and short of any real prefix."""

from __future__ import annotations

import json
from typing import Any

import httpx
import respx

from tests.conftest import load_json, load_text

API = "https://api.github.com"
PAT = "pat-for-tests-only-1234567890"
REPO = "contoso-payments/billing-api"


def gh(name: str) -> Any:
    return load_json("github", name)


def mock_repo(repo: str = REPO, *, meta: Any = "repo.json", tree: Any = "tree.json", rules: Any = "rules_branches.json", ruleset: Any = "ruleset_detail.json",
              classic: Any = "protection_classic.json", codeowners: str | None = "codeowners.txt", contents: dict[str, str] | None = None,
              branch: str = "main") -> dict[str, respx.Route]:
    """Mock every endpoint the reader calls for ``repo``. A fixture name is served as 200; an int is served as that status; None = 404."""
    base = f"{API}/repos/{repo}"

    def resp(spec: Any, default404: bool = True) -> httpx.Response:
        if isinstance(spec, int):
            return httpx.Response(spec, json={"message": "mocked"})
        if spec is None:
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(200, json=gh(spec) if isinstance(spec, str) else spec)

    routes: dict[str, respx.Route] = {}
    routes["meta"] = respx.get(base).mock(side_effect=lambda r: resp(meta))
    routes["tree"] = respx.get(f"{base}/git/trees/{branch}").mock(side_effect=lambda r: resp(tree))
    routes["rules"] = respx.get(f"{base}/rules/branches/{branch}").mock(side_effect=lambda r: resp(rules))
    routes["ruleset"] = respx.get(url__regex=rf"{base}/rulesets/\d+").mock(side_effect=lambda r: resp(ruleset))
    routes["classic"] = respx.get(f"{base}/branches/{branch}/protection").mock(side_effect=lambda r: resp(classic))
    files = {".github/CODEOWNERS": load_text("github", codeowners)} if codeowners else {}
    files.update(contents or {})

    def content(request: httpx.Request) -> httpx.Response:
        path = request.url.path.split("/contents/", 1)[1]
        if path in files:
            return httpx.Response(200, text=files[path])
        return httpx.Response(404, json={"message": "Not Found"})

    routes["contents"] = respx.get(url__regex=rf"{base}/contents/.+").mock(side_effect=content)
    return routes


def link(next_url: str | None) -> dict[str, str]:
    return {"Link": f'<{next_url}>; rel="next", <{next_url}>; rel="last"'} if next_url else {}


def json_body(request: httpx.Request) -> Any:
    return json.loads(request.content or b"null")


# ------------------------------------------------------------------ GitHub Actions (G3). Fixtures live in tests/fixtures/github/actions
def actions_text(name: str) -> str:
    return load_text("github", "actions", name)


def actions_json(name: str) -> Any:
    return load_json("github", "actions", name)


WORKFLOW_FILES = {
    ".github/workflows/ci.yml": "ci.yml", ".github/workflows/deploy.yml": "deploy.yml", ".github/workflows/insecure.yml": "insecure.yml",
    ".github/workflows/caller.yml": "caller.yml", ".github/workflows/tests.yml": "tests.yml",
}


def workflow_contents(files: dict[str, str] | None = None) -> dict[str, str]:
    """``contents=`` for ``mock_repo``: workflow path -> text (default: every fixture workflow)."""
    return {path: actions_text(name) for path, name in (files or WORKFLOW_FILES).items()}


def _spec(spec: Any) -> httpx.Response:
    if isinstance(spec, int):
        return httpx.Response(spec, json={"message": "mocked"})
    if spec is None:
        return httpx.Response(404, json={"message": "Not Found"})
    return httpx.Response(200, json=actions_json(spec) if isinstance(spec, str) else spec)


def mock_actions(repo: str = REPO, *, workflows: Any = "workflows.json", environments: Any = "environments.json", runs: Any = "runs.json",
                 branch_policies: Any = "branch_policies.json", protection_rules: dict[str, Any] | None = None, deployments: Any = "deployments_prod.json",
                 statuses: Any = "statuses_prod.json") -> dict[str, respx.Route]:
    """Mock the Actions / environments / runs / deployments endpoints. A fixture name = 200, an int = that status, None = 404."""
    base = f"{API}/repos/{repo}"
    rules = {"production": "protection_rules.json", "test": "protection_rules_none.json", **(protection_rules or {})}
    routes: dict[str, respx.Route] = {}
    routes["workflows"] = respx.get(f"{base}/actions/workflows").mock(side_effect=lambda r: _spec(workflows))
    routes["environments"] = respx.get(f"{base}/environments").mock(side_effect=lambda r: _spec(environments))
    routes["branch_policies"] = respx.get(url__regex=rf"{base}/environments/[^/]+/deployment-branch-policies").mock(side_effect=lambda r: _spec(branch_policies))

    def prot(request: httpx.Request) -> httpx.Response:
        env = request.url.path.split("/environments/", 1)[1].split("/", 1)[0]
        return _spec(rules.get(env, "protection_rules_none.json"))

    routes["protection_rules"] = respx.get(url__regex=rf"{base}/environments/[^/]+/deployment_protection_rules").mock(side_effect=prot)
    routes["runs"] = respx.get(f"{base}/actions/runs").mock(side_effect=lambda r: _spec(runs))

    def deps(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("environment") == "production":
            return _spec(deployments)
        return httpx.Response(200, json=[])

    routes["deployments"] = respx.get(f"{base}/deployments").mock(side_effect=deps)
    routes["statuses"] = respx.get(url__regex=rf"{base}/deployments/\d+/statuses").mock(side_effect=lambda r: _spec(statuses))
    return routes


def mock_contents(repo: str, files: dict[str, str]) -> respx.Route:
    """Contents API of another repository (cross-repo reusable workflows): path -> text, anything else 404."""
    base = f"{API}/repos/{repo}"

    def content(request: httpx.Request) -> httpx.Response:
        path = request.url.path.split("/contents/", 1)[1]
        return httpx.Response(200, text=files[path]) if path in files else httpx.Response(404, json={"message": "Not Found"})

    return respx.get(url__regex=rf"{base}/contents/.+").mock(side_effect=content)
