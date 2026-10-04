"""GitHub reader: org discovery filters, protection merge, per-repo facts (tree, CODEOWNERS, rules) and failure reasons (G2)."""

import httpx
import pytest
import respx

from pch.collectors.github.client import GitHubClient
from pch.collectors.github.discovery import list_org_repos, repo_matches
from pch.collectors.github.protection import bypass_labels, merge_protection
from pch.collectors.github.reader import default_codeowner, read_repo
from pch.model.repo import TestState
from pch.repo_scan.tests_detect import classify_test_state
from pch.settings import ConfigError, GitHubScope, Scope, load_scope
from tests.github_mock import API, PAT, REPO, gh, link, mock_repo


def client() -> GitHubClient:
    return GitHubClient(API, token=PAT, backoff_base=0, max_attempts=1)


# ------------------------------------------------------------------ discovery filters
def raw(name, **kw):
    return {"name": name, "full_name": f"acme/{name}", "archived": False, "fork": False, "topics": [], **kw}


def names(repos, gs):
    return [r["name"] for r in repos if repo_matches(r, gs)]


def test_discovery_filters():
    repos = [raw("api", topics=["payments"]), raw("web"), raw("old", archived=True), raw("forked", fork=True), raw("sandbox-x", topics=["Payments"])]
    assert names(repos, GitHubScope()) == ["api", "web", "sandbox-x"]  # archived and forks off by default
    assert names(repos, GitHubScope(include_archived=True, include_forks=True)) == ["api", "web", "old", "forked", "sandbox-x"]
    assert names(repos, GitHubScope(include=["a*", "web"])) == ["api", "web"]
    assert names(repos, GitHubScope(include=["ACME/w*"])) == ["web"]  # globs match repo or org/repo, case-insensitively
    assert names(repos, GitHubScope(exclude=["sandbox-*"])) == ["api", "web"]
    assert names(repos, GitHubScope(include=["*"], exclude=["web"])) == ["api", "sandbox-x"]
    assert names(repos, GitHubScope(topics_any=["payments"])) == ["api", "sandbox-x"]  # topics are case-insensitive
    assert names(repos, GitHubScope(topics_any=["nothing"])) == []
    assert not repo_matches({"name": "x", "full_name": "bad name/x"}, GitHubScope())  # never builds an API path from an odd name


@respx.mock
async def test_org_listing_is_paged_and_filtered():
    def page(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json=gh("org_repos_page2.json"))
        return httpx.Response(200, json=gh("org_repos_page1.json"), headers=link(f"{API}/orgs/contoso-payments/repos?type=all&per_page=100&page=2"))

    route = respx.get(f"{API}/orgs/contoso-payments/repos").mock(side_effect=page)
    repos = await list_org_repos(client(), "contoso-payments", GitHubScope(orgs=["contoso-payments"], exclude=["sandbox-*"]))
    assert [r["name"] for r in repos] == ["billing-api", "orders-func", "ledger", "standalone-svc"]  # no archived, no fork, no sandbox
    assert route.calls[0].request.url.params["type"] == "all"


def test_scope_github_block_is_strict(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text("github:\n  orgs: [acme]\n  include: ['a*']\n  topics_any: [x]\n  include_forks: true\n")
    assert load_scope(p).github.orgs == ["acme"] and load_scope(p).github.include_forks
    for bad in ("github: {orgz: [a]}", "github: {orgs: ['a/b']}", "github: {include_archived: maybe}"):
        p.write_text(bad)
        with pytest.raises(ConfigError):
            load_scope(p)
    assert Scope().github.orgs == [] and Scope().github.include_archived is False


# ------------------------------------------------------------------ protection merge
RULES = gh("rules_branches.json")
CLASSIC = gh("protection_classic.json")


def test_merge_rulesets_only():
    p = merge_protection(rules=RULES, bypass={"Repository:contoso-payments/billing-api:11": []}, classic=None, classic_state="none")
    assert p.available and p.protected and not p.incomplete
    assert (p.required_approving_review_count, p.dismiss_stale_reviews, p.require_code_owner_review, p.require_conversation_resolution) == (2, True, True, True)
    assert p.required_status_checks == ["build"] and p.block_force_pushes and p.block_deletions and not p.require_linear_history
    assert p.admins_can_bypass is False and p.enforce_admins is None and p.sources == ["ruleset 11"]


def test_merge_classic_only():
    p = merge_protection(rules=[], classic=CLASSIC, classic_state="present")
    assert p.protected and p.required_approving_review_count == 1 and p.require_last_push_approval and not p.dismiss_stale_reviews
    assert p.required_status_checks == ["lint"] and p.block_force_pushes and p.block_deletions and p.require_linear_history
    assert p.enforce_admins is True and p.admins_can_bypass is False and not p.require_conversation_resolution


def test_merge_takes_the_strictest_of_both_sources():
    p = merge_protection(rules=RULES, bypass={"Repository:contoso-payments/billing-api:11": bypass_labels([{"actor_type": "RepositoryRole", "bypass_mode": "always"}])},
                         classic=CLASSIC, classic_state="present")
    assert p.required_approving_review_count == 2 and p.require_last_push_approval and p.dismiss_stale_reviews  # from either
    assert p.required_status_checks == ["build", "lint"] and p.require_linear_history
    assert p.admins_can_bypass is True and p.bypass_actors == ["RepositoryRole/always"] and p.enforce_admins is True


def test_merge_classic_without_admin_enforcement_means_admins_bypass():
    c = {**CLASSIC, "enforce_admins": {"enabled": False}}
    p = merge_protection(rules=[], classic=c, classic_state="present")
    assert p.enforce_admins is False and p.admins_can_bypass is True


def test_merge_classic_bypass_allowances_count_as_bypass():
    c = {**CLASSIC, "required_pull_request_reviews": {**CLASSIC["required_pull_request_reviews"], "bypass_pull_request_allowances": {"users": [{"login": "x"}], "teams": [], "apps": []}}}
    p = merge_protection(rules=[], classic=c, classic_state="present")
    assert p.admins_can_bypass is True and p.bypass_actors == ["classic-bypass-allowance/users"]


def test_merge_unreadable_classic_is_incomplete_not_empty():
    p = merge_protection(rules=RULES, bypass={"Repository:contoso-payments/billing-api:11": []}, classic_state="unknown", classic_error="classic: HTTP 403")
    assert p.available and p.incomplete == ["classic: HTTP 403"]
    assert p.required_approving_review_count == 2 and p.admins_can_bypass is None  # ruleset has no bypass, classic unknown -> cannot tell
    nothing = merge_protection(rules=None, rules_error="rules: 404", classic_state="unknown", classic_error="classic: 403")
    assert not nothing.available and "rules: 404" in nothing.unavailable_reason and "classic: 403" in nothing.unavailable_reason


def test_merge_no_protection_at_all():
    p = merge_protection(rules=[], classic=None, classic_state="none")
    assert p.available and not p.protected and p.admins_can_bypass is None and p.required_approving_review_count == 0
    only_classic_blind = merge_protection(rules=[], classic_state="unknown", classic_error="403")
    assert only_classic_blind.available and only_classic_blind.incomplete == ["403"]


def test_merge_unreadable_ruleset_bypass_leaves_admin_bypass_open():
    p = merge_protection(rules=RULES, bypass={"Repository:contoso-payments/billing-api:11": None}, classic_state="none")
    assert p.admins_can_bypass is None and not p.incomplete


# ------------------------------------------------------------------ CODEOWNERS
def test_default_codeowner_is_the_last_star_rule():
    assert default_codeowner("# c\n*  @a/team @bob\n/docs/ @d\n") == "@a/team"
    assert default_codeowner("* @first\n*  @second\n") == "@second"
    assert default_codeowner("/docs/ @d\n") is None and default_codeowner("* \n") is None
    assert default_codeowner("*  dev@example.com") == "dev@example.com"


# ------------------------------------------------------------------ reader
@respx.mock
async def test_read_repo_full():
    routes = mock_repo()
    r = await read_repo(client(), REPO, known=gh("org_repos_page1.json")[0])
    f, p = r.facts, r.protection
    assert f.facts_source == "github" and f.tree_complete and f.tests_detected and f.dockerfiles == ["Dockerfile"] and "dotnet" in f.languages
    assert f.codeowners and r.owner == "@contoso-payments/payments-team" and f.github.topics == ["payments", "tier1"] and f.github.visibility == "private"
    assert r.default_branch == "main" and r.web_url == "https://github.com/contoso-payments/billing-api"
    assert p.available and p.required_approving_review_count == 2 and p.required_status_checks == ["build", "lint"] and p.admins_can_bypass is True
    assert not r.errors and not p.incomplete
    assert not routes["meta"].called  # the org listing already had the metadata
    assert routes["tree"].calls[0].request.url.params["recursive"] == "1"
    # CODEOWNERS: the tree says which file exists, so only that one is requested
    assert [c.request.url.path.split("/contents/")[1] for c in routes["contents"].calls] == [".github/CODEOWNERS"]
    assert routes["contents"].calls[0].request.headers["accept"] == "application/vnd.github.raw+json"
    assert routes["ruleset"].call_count == 1  # one ruleset -> one bypass lookup


@respx.mock
async def test_read_repo_fetches_metadata_when_not_listed_and_reads_contents_only_when_needed():
    routes = mock_repo(tree="tree_no_tests.json", contents={"src/Billing.Api.csproj": '<Project><ItemGroup><PackageReference Include="xunit" /></ItemGroup></Project>'}, codeowners=None)
    r = await read_repo(client(), REPO)
    assert routes["meta"].called
    assert r.facts.tests_detected and any("xunit" in s or "test framework" in s for s in r.facts.test_signals)  # found through file contents
    assert not r.facts.codeowners and r.owner is None
    assert [c.request.url.path for c in routes["contents"].calls] == [f"/repos/{REPO}/contents/src/Billing.Api.csproj"]


@respx.mock
async def test_no_content_fetch_when_file_names_already_prove_tests():
    routes = mock_repo()
    await read_repo(client(), REPO)
    assert not any("csproj" in c.request.url.path for c in routes["contents"].calls)  # test project names already prove tests


@respx.mock
async def test_truncated_tree_is_partial_and_tries_every_codeowners_location():
    routes = mock_repo(tree="tree_truncated.json", codeowners=None)
    r = await read_repo(client(), REPO)
    assert r.facts.facts_source == "github" and not r.facts.tree_complete and "truncated" in r.facts.facts_reason
    tried = {c.request.url.path.split("/contents/")[1] for c in routes["contents"].calls if "CODEOWNERS" in c.request.url.path}
    assert tried == {".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}
    # what is not in a partial listing proves nothing: no NO_TESTS
    state, reason, _ = classify_test_state(r.facts, [], None)
    assert state == TestState.UNKNOWN and "truncated" in reason


def test_partial_tree_with_tests_seen_and_no_pipeline_is_tests_not_run():
    from pch.model.repo import RepoFacts

    f = RepoFacts(tests_detected=True, facts_source="github", tree_complete=False, facts_reason="truncated")
    assert classify_test_state(f, [], None)[0] == TestState.TESTS_NOT_RUN  # seen tests are proof even in a partial listing
    full = RepoFacts(tests_detected=False, facts_source="github")
    assert classify_test_state(full, [], None)[0] == TestState.NO_TESTS  # a complete listing can claim it


@respx.mock
async def test_classic_protection_403_is_incomplete_with_the_permission_named():
    mock_repo()
    respx.get(f"{API}/repos/{REPO}/branches/main/protection").mock(return_value=httpx.Response(
        403, json={"message": "Resource not accessible by personal access token"}, headers={"X-Accepted-GitHub-Permissions": "administration=read"}))
    r = await read_repo(client(), REPO)
    p = r.protection
    assert p.available and p.incomplete and "administration=read" in p.incomplete[0]
    assert p.required_approving_review_count == 2  # rulesets still count
    assert any("classic branch protection" in e for e in r.errors)


@respx.mock
async def test_classic_404_means_no_classic_protection_and_no_rules_means_unprotected():
    mock_repo(rules=[], classic=None)
    p = (await read_repo(client(), REPO)).protection
    assert p.available and not p.protected and not p.incomplete


@respx.mock
async def test_unreadable_rules_and_classic_make_protection_unavailable():
    mock_repo(rules=403, classic=403)
    r = await read_repo(client(), REPO)
    assert not r.protection.available and "branch rules" in r.protection.unavailable_reason
    assert r.facts.facts_source == "github"  # the tree is independent of protection


@respx.mock
async def test_repo_not_visible_yields_unavailable_facts_and_protection_with_a_reason():
    mock_repo(meta=None)
    r = await read_repo(client(), REPO)
    assert r.facts.facts_source == "unavailable" and "404" in r.facts.facts_reason and "Metadata" in r.facts.facts_reason
    assert not r.protection.available and r.protection.unavailable_reason == r.facts.facts_reason


@respx.mock
async def test_tree_denied_is_unavailable_not_empty_and_empty_repo_is_empty():
    mock_repo(tree=403)
    r = await read_repo(client(), REPO)
    assert r.facts.facts_source == "unavailable" and "file tree" in r.facts.facts_reason and "Contents" in r.facts.facts_reason
    assert r.protection.available
    mock_repo(tree=409)  # "Git Repository is empty"
    e = await read_repo(client(), REPO)
    assert e.facts.facts_source == "github" and e.facts.file_count == 0 and e.facts.tree_complete


@respx.mock
async def test_rate_limit_during_a_read_becomes_a_reason():
    mock_repo()
    respx.get(f"{API}/repos/{REPO}/git/trees/main").mock(return_value=httpx.Response(403, headers={"Retry-After": "9999"}))
    r = await read_repo(client(), REPO)
    assert r.facts.facts_source == "unavailable" and "rate limit" in r.facts.facts_reason


async def test_invalid_names_never_reach_the_api():
    r = await read_repo(client(), "../etc/passwd")  # no respx: any request would fail loudly
    assert r.facts.facts_source == "unavailable" and "not a valid org/repo" in r.facts.facts_reason
