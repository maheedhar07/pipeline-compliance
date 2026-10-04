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
