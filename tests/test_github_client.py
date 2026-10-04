"""GitHub client: headers, Link pagination (same-host only), rate limits, App auth and the read-only guard (G2)."""

import sys
from datetime import UTC, datetime

import httpx
import pytest
import respx

from pch.collectors.github.client import (
    GitHubAppAuth,
    GitHubClient,
    RateLimited,
    UnsafePagination,
    normalize_pem,
    parse_link_next,
)
from pch.collectors.http import HttpError
from pch.collectors.transport import MutationBlockedError, RecordingTransport
from pch.logging_setup import scrub
from pch.providers.errors import ProviderUnavailable
from tests.github_mock import API, PAT, gh, link


def client(**kw) -> GitHubClient:
    kw.setdefault("token", PAT)
    return GitHubClient(kw.pop("api_url", API), backoff_base=0, max_attempts=1, **kw)


# ------------------------------------------------------------------ headers
@respx.mock
async def test_headers_and_rate_limit_probe():
    r = respx.get(f"{API}/rate_limit").mock(return_value=httpx.Response(200, json={"resources": {"core": {"limit": 5000, "remaining": 4990, "reset": 1}}}))
    core = await client().rate_limit()
    h = r.calls[0].request.headers
    assert core["remaining"] == 4990
    assert h["accept"] == "application/vnd.github+json" and h["x-github-api-version"] == "2022-11-28" and h["authorization"] == f"Bearer {PAT}"


@respx.mock
async def test_raw_media_type_for_file_contents():
    r = respx.get(f"{API}/repos/o/r/contents/CODEOWNERS").mock(return_value=httpx.Response(200, text="* @o/team\n"))
    assert await client().get_raw("/repos/o/r/contents/CODEOWNERS", {"ref": "main"}) == "* @o/team\n"
    assert r.calls[0].request.headers["accept"] == "application/vnd.github.raw+json"


# ------------------------------------------------------------------ pagination
def test_link_header_parsing():
    assert parse_link_next('<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"') == "https://api.github.com/x?page=2"
    assert parse_link_next('<https://api.github.com/x?page=1>; rel="prev"') is None and parse_link_next(None) is None


@respx.mock
async def test_pagination_follows_next_links_on_the_same_host():
    def page(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json=gh("org_repos_page2.json"))
        return httpx.Response(200, json=gh("org_repos_page1.json"), headers=link(f"{API}/orgs/o/repos?type=all&per_page=100&page=2"))

    route = respx.get(f"{API}/orgs/o/repos").mock(side_effect=page)
    items = await client().paged("/orgs/o/repos", {"type": "all"})
    assert [i["name"] for i in items] == ["billing-api", "orders-func", "old-service", "ledger", "standalone-svc", "upstream-fork", "sandbox-play"]
    assert route.call_count == 2 and route.calls[0].request.url.params["per_page"] == "100"


@respx.mock
async def test_pagination_refuses_a_link_to_another_host():
    respx.get(f"{API}/orgs/o/repos").mock(return_value=httpx.Response(200, json=[{"a": 1}], headers=link("https://evil.example.com/orgs/o/repos?page=2")))
    evil = respx.get("https://evil.example.com/orgs/o/repos").mock(return_value=httpx.Response(200, json=[]))
    with pytest.raises(UnsafePagination):
        await client().paged("/orgs/o/repos")
    assert not evil.called  # the token never left


@respx.mock
async def test_pagination_ghes_must_stay_under_the_api_path_and_scheme():
    ghes = "https://ghe.example.com/api/v3"
    respx.get(f"{ghes}/orgs/o/repos").mock(return_value=httpx.Response(200, json=[], headers=link("https://ghe.example.com/other/orgs/o/repos?page=2")))
    with pytest.raises(UnsafePagination):
        await client(api_url=ghes).paged("/orgs/o/repos")
    respx.get(f"{ghes}/orgs/p/repos").mock(return_value=httpx.Response(200, json=[], headers=link("http://ghe.example.com/api/v3/orgs/p/repos?page=2")))
    with pytest.raises(UnsafePagination):  # https -> http downgrade
        await client(api_url=ghes).paged("/orgs/p/repos")


# ------------------------------------------------------------------ rate limits
class Clock:
    def __init__(self, now=1000.0):
        self.now, self.slept = now, []

    def __call__(self):
        return self.now

    async def sleep(self, s):
        self.slept.append(s)
        self.now += s


def limited(clock, **kw):
    return client(clock=clock, sleep=clock.sleep, **kw)


@respx.mock
async def test_secondary_rate_limit_retry_after_is_honoured():
    clk = Clock()
    route = respx.get(f"{API}/x").mock(side_effect=[httpx.Response(403, json={"message": "secondary"}, headers={"Retry-After": "5"}), httpx.Response(200, json={"ok": 1})])
    assert await limited(clk).get_json("/x") == {"ok": 1}
    assert clk.slept == [5.0] and route.call_count == 2


@respx.mock
async def test_429_with_retry_after_is_handled_by_the_client():
    clk = Clock()
    respx.get(f"{API}/x").mock(side_effect=[httpx.Response(429, headers={"Retry-After": "2"}), httpx.Response(200, json={"ok": 1})])
    assert await limited(clk).get_json("/x") == {"ok": 1} and clk.slept == [2.0]


@respx.mock
async def test_primary_rate_limit_waits_for_a_near_reset():
    clk = Clock(1000.0)
    respx.get(f"{API}/x").mock(side_effect=[
        httpx.Response(403, json={"message": "API rate limit exceeded"}, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1030"}),
        httpx.Response(200, json={"ok": 1})])
    assert await limited(clk).get_json("/x") == {"ok": 1}
    assert clk.slept == [31.0]


@respx.mock
async def test_far_reset_or_retry_after_fails_the_item_without_sleeping():
    clk = Clock(1000.0)
    respx.get(f"{API}/far").mock(return_value=httpx.Response(403, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "5000"}))
    with pytest.raises(RateLimited) as e:
        await limited(clk).get_json("/far")
    assert e.value.wait_s > 3000 and clk.slept == []
    respx.get(f"{API}/ra").mock(return_value=httpx.Response(403, headers={"Retry-After": "3600"}))
    with pytest.raises(RateLimited):
        await limited(clk).get_json("/ra")
    assert clk.slept == []


@respx.mock
async def test_known_exhausted_quota_is_not_hammered():
    clk = Clock(1000.0)
    c = limited(clk)
    respx.get(f"{API}/a").mock(return_value=httpx.Response(200, json={}, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1010"}))
    b = respx.get(f"{API}/b").mock(return_value=httpx.Response(200, json={}))
    await c.get_json("/a")
    await c.get_json("/b")
    assert clk.slept == [11.0] and b.called  # waited for the reset before the next request
    clk2 = Clock(1000.0)
    c2 = limited(clk2)
    respx.get(f"{API}/c").mock(return_value=httpx.Response(200, json={}, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "9000"}))
    await c2.get_json("/c")
    with pytest.raises(RateLimited):
        await c2.get_json("/b")


@respx.mock
async def test_plain_403_is_a_permission_error_not_a_rate_limit():
    clk = Clock()
    route = respx.get(f"{API}/p").mock(return_value=httpx.Response(403, json={"message": "Resource not accessible"}, headers={"X-Accepted-GitHub-Permissions": "administration=read"}))
    with pytest.raises(HttpError) as e:
        await limited(clk).get_json("/p")
    assert e.value.status == 403 and e.value.headers["x-accepted-github-permissions"] == "administration=read"
    assert route.call_count == 1 and clk.slept == []


# ------------------------------------------------------------------ GitHub App
def _pem() -> tuple[str, str]:
    pytest.importorskip("jwt")
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # throwaway, generated at test time, never written down
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


def test_normalize_pem_accepts_one_line_env_values():
    assert normalize_pem("-----BEGIN X-----\\nabc\\n-----END X-----") == "-----BEGIN X-----\nabc\n-----END X-----"
    assert normalize_pem("a\nb") == "a\nb"


def test_app_jwt_is_rs256_with_short_expiry():
    priv, pub = _pem()  # skips without the github-app extra
    import jwt

    auth = GitHubAppAuth("1234", "42", priv, clock=lambda: 2_000_000_000.0)
    token = auth.jwt()
    assert jwt.get_unverified_header(token)["alg"] == "RS256"
    claims = jwt.decode(token, pub, algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False})
    assert claims["iss"] == "1234" and claims["exp"] - claims["iat"] <= 600 and claims["exp"] > 2_000_000_000
    assert token not in scrub(f"leak {token}")  # registered for log redaction


def test_app_requires_the_extra_with_a_clear_message(monkeypatch):
    monkeypatch.setitem(sys.modules, "jwt", None)  # `import jwt` -> ImportError, as on an install without the extra
    with pytest.raises(ProviderUnavailable, match=r"github-app"):
        GitHubAppAuth("1", "2", "pem").jwt()


def test_app_ids_must_be_numeric():
    with pytest.raises(ValueError):
        GitHubAppAuth("abc", "2", "pem")


@respx.mock
async def test_installation_token_exchange_cached_until_five_minutes_before_expiry():
    priv, pub = _pem()
    import jwt

    expires = datetime(2026, 10, 4, 13, 0, 0, tzinfo=UTC).timestamp()
    now = [expires - 3600]
    exchange = respx.post(f"{API}/app/installations/42/access_tokens").mock(return_value=httpx.Response(201, json=gh("installation_token.json")))
    seen = respx.get(f"{API}/repos/o/r").mock(return_value=httpx.Response(200, json={}))
    c = GitHubClient(API, app=GitHubAppAuth("1234", "42", priv, clock=lambda: now[0]), backoff_base=0, max_attempts=1, clock=lambda: now[0])
    await c.get_json("/repos/o/r")
    await c.get_json("/repos/o/r")
    assert exchange.call_count == 1  # cached
    bearer = exchange.calls[0].request.headers["authorization"].removeprefix("Bearer ")
    assert jwt.decode(bearer, pub, algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False})["iss"] == "1234"
    assert seen.calls[0].request.headers["authorization"] == "Bearer installation-token-for-tests-only-0001"
    now[0] = expires - 200  # inside the 5 minute margin: renewed
    await c.get_json("/repos/o/r")
    assert exchange.call_count == 2
    assert "installation-token-for-tests-only-0001" not in scrub("token installation-token-for-tests-only-0001")
    await c.aclose()


# ------------------------------------------------------------------ read-only guard
async def test_only_the_exact_token_exchange_can_be_posted():
    priv, _ = _pem()
    app = GitHubClient(API, app=GitHubAppAuth("1", "42", priv), backoff_base=0, max_attempts=1)
    for url in (f"{API}/app/installations/43/access_tokens",  # another installation
                f"{API}/app/installations/42/access_tokens/extra",
                f"{API}/repos/o/r/issues",
                f"{API}/graphql",
                "https://evil.example.com/app/installations/42/access_tokens",  # right path, wrong host
                "http://api.github.com/app/installations/42/access_tokens"):  # right host, wrong scheme
        with pytest.raises(MutationBlockedError):
            await app.http.request("POST", url)
    for method in ("PUT", "PATCH", "DELETE"):
        with pytest.raises(MutationBlockedError):
            await app.http.request(method, f"{API}/repos/o/r")
    pat = client()  # a PAT client has no POST allowance at all
    with pytest.raises(MutationBlockedError):
        await pat.http.request("POST", f"{API}/app/installations/42/access_tokens")


async def test_ado_clients_get_no_github_post_allowance():
    from pch.collectors.ado.client import AdoClient

    ado = AdoClient("contoso", "x", backoff_base=0, max_attempts=1)
    with pytest.raises(MutationBlockedError):
        await ado.http.request("POST", f"{API}/app/installations/42/access_tokens")


# ------------------------------------------------------------------ redaction
def test_token_is_scrubbed_from_logs_and_the_raw_cache():
    client()  # registers the PAT
    assert PAT not in scrub(f"calling with {PAT}")
    req = httpx.Request("POST", f"{API}/app/installations/42/access_tokens")
    resp = httpx.Response(201, json=gh("installation_token.json"), request=req)
    rec = RecordingTransport.build_record(req, resp, resp.content).decode()
    assert "installation-token-for-tests-only-0001" not in rec and "REDACTED" in rec
