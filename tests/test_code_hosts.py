"""scope.yaml code_hosts (G1): GitHub is the default code host, Azure Repos is opt-in and not even called otherwise."""

import copy

import pytest
import respx
from fastapi.testclient import TestClient

from pch.collectors.ado.repo_discovery import discover
from pch.settings import ConfigError, Scope, load_scope
from pch.store import repository as store
from pch.store.db import session_scope
from tests.builders import ALL_HOSTS
from tests.test_external_repos import mock_ado, scan

AZURE = [{"id": "repo-1", "name": "payments-api", "defaultBranch": "refs/heads/main", "webUrl": "https://dev.azure.com/o/P/_git/payments-api"}]


def test_default_is_github_only_and_validation(tmp_path):
    assert Scope().code_hosts == ["github"] and Scope().hosts() == {"github"}
    assert Scope(code_hosts=["github", "azure_repos", "github"]).code_hosts == ["github", "azure_repos"]
    f = tmp_path / "scope.yaml"
    for body, needle in (("code_hosts: [gitlab]\n", "code_hosts.0"), ("code_hosts: []\n", "code_hosts: Value error, must list at least one")):
        f.write_text(body)
        with pytest.raises(ConfigError) as e:
            load_scope(f, required=False)
        assert needle in str(e.value) and str(f) in str(e.value)


def test_discover_drops_azure_repos_when_not_in_scope(fx):
    builds = [fx("ado", "build_def_classic_dotnet.json"), fx("ado", "build_def_github_classic.json"), fx("ado", "build_def_github_yaml.json")]
    d = discover(AZURE, builds, [fx("ado", "release_def_github_artifact.json")], ["github"])
    assert {r.name for r in d.repos} == {"contoso-payments/billing-api", "contoso-payments/orders-func", "contoso-payments/ledger"}
    assert all(r.provider == "github" for r in d.repos)
    assert d.out_of_scope == {"azure_repos": {"builds": 1}}
    assert d.unlinked_builds == [] and d.unlinked_releases == []  # out of scope is not an orphan
    msg = d.out_of_scope_summary(["github"])
    assert "1 build definition(s)" in msg and "Azure Repos" in msg and msg.startswith("info:")
    everything = discover(AZURE, builds, [fx("ado", "release_def_github_artifact.json")])  # None = every host (template reuse)
    assert {r.provider for r in everything.repos} == {"azure_repos", "github"} and everything.out_of_scope == {}


def test_discover_skips_releases_fed_by_out_of_scope_builds_and_hosts(fx):
    azure_build = fx("ado", "build_def_classic_dotnet.json")
    rel = copy.deepcopy(fx("ado", "release_def_github_artifact.json"))
    rel["artifacts"] = [{"type": "Build", "isPrimary": True, "definitionReference": {"definition": {"id": str(azure_build["id"])}}}]
    d = discover(AZURE, [azure_build], [rel], ["github"])
    assert d.repos == [] and d.unlinked_releases == [] and d.out_of_scope == {"azure_repos": {"builds": 1, "releases": 1}}
    gh_art = fx("ado", "release_def_github_artifact.json")
    only_azure = discover(AZURE, [], [gh_art], ["azure_repos"])  # GitHub release artifact while only Azure Repos is a code host
    assert only_azure.out_of_scope == {"github": {"releases": 1}}


def test_discover_adds_repos_named_in_scope_even_without_pipelines():
    d = discover([], [], [], ["github"], known_github=["contoso/never-built", "payments-api", "Contoso/Never-Built"])
    assert [r.name for r in d.repos] == ["contoso/never-built"] and d.repos[0].url == "https://github.com/contoso/never-built"
    assert discover([], [], [], ["azure_repos"], known_github=["contoso/x"]).repos == []


@respx.mock
def test_scan_does_not_call_azure_repos_api_and_summarises_once(fx, fxt, tmp_path):
    mock_ado(fx, fxt, items_calls=[])
    db = scan(tmp_path, Scope(projects=["Payments"]))
    repo_list_calls = [c for c in respx.calls if c.request.url.path == "/contoso/Payments/_apis/git/repositories"]
    assert repo_list_calls == []
    with session_scope(db) as s:
        rows = {r.repo_key: r for r in store.repo_results(s, "ext")}
        assert set(rows) == {"Payments/contoso-payments/billing-api", "Payments/contoso-payments/orders-func", "Payments/contoso-payments/ledger"}
        assert all(r.external["repo"]["provider"] == "github" for r in rows.values())
        info = [e for e in store.collection_errors(s, "ext") if "code hosts" in e.subject]
        assert len(info) == 1 and info[0].message.startswith("info: out of scope") and "1 build definition(s)" in info[0].message
        assert store.get_scan(s, "ext").summary["providers"] == ["github"]


@respx.mock
def test_scan_with_azure_repos_enabled_still_works(fx, fxt, tmp_path):
    mock_ado(fx, fxt, items_calls=[])
    db = scan(tmp_path, Scope(code_hosts=ALL_HOSTS, projects=["Payments"]))
    with session_scope(db) as s:
        rows = {r.repo_key for r in store.repo_results(s, "ext")}
        assert "Payments/payments-api" in rows
        assert store.get_scan(s, "ext").summary["providers"] == ["azure_repos", "github"]
        assert not [e for e in store.collection_errors(s, "ext") if "code hosts" in e.subject]


@respx.mock
def test_ui_hides_provider_badge_and_filter_with_one_host_and_shows_them_with_two(fx, fxt, tmp_path):
    from pch.web.app import create_app

    mock_ado(fx, fxt, items_calls=[])
    db = scan(tmp_path, Scope(projects=["Payments"]))
    c = TestClient(create_app(db))
    for path in ("/repos", "/lineage"):
        t = c.get(path).text
        assert "Code hosted on" not in t and "Azure Repos" not in t, path
    assert 'title="Code hosted on' not in c.get("/repos").text and 'title="Code hosted on' not in c.get("/findings").text
    respx.reset()
    mock_ado(fx, fxt, items_calls=[])
    two = tmp_path / "two"
    two.mkdir()
    db2 = scan(two, Scope(code_hosts=ALL_HOSTS, projects=["Payments"]))
    c2 = TestClient(create_app(db2))
    assert "Code hosted on" in c2.get("/repos").text and "Code hosted on" in c2.get("/lineage").text
    assert 'title="Code hosted on GitHub"' in c2.get("/repos").text
