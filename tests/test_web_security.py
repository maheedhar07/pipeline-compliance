"""T5 web security: auth seam, fail-closed serve guard, headers, hardening, XSS, vendored assets, template hygiene."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import itertools
import json
import re
from datetime import datetime
from pathlib import Path
from typing import get_args

import pytest
from fastapi.testclient import TestClient

from pch.demo.generator import generate_world
from pch.demo.transport import parse_world_time
from pch.orchestrator import ScanConfig, Scanner
from pch.settings import Policy, Scope, Settings
from pch.sources import demo_sources
from pch.store.db import session_scope
from pch.store.models import FindingRow, RepoResultRow
from pch.web import auth as A
from pch.web import queries as Q
from pch.web.app import SortKey, create_app, csv_cell, json_for_script, safe_url
from pch.web.guard import UnsafeServeConfig, assert_safe_to_serve, guard_problems, is_loopback_host
from pch.web.security import CSP
from tests.builders import ALL_HOSTS

WEB = Path(__file__).parent.parent / "src" / "pch" / "web"
STATIC = WEB / "static"
ROLE = "PCH.Reader"
ROLE_URI = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("APP_ENV", "AUTH_MODE", "AUTH_ALLOWED_ROLES", "AUTH_ALLOW_ANY_AUTHENTICATED", "WEBSITE_AUTH_ENABLED", "AUTH_EASYAUTH_ASSUME_ENABLED",
              "AUTH_NONE_ALLOW_CONTAINER_BIND", "ALLOWED_HOSTS", "HOST", "PORT", "WEBSITES_PORT", "FORWARDED_ALLOW_IPS", "DATABASE_URL"):
        monkeypatch.delenv(k, raising=False)


def S(**kw) -> Settings:
    return Settings(_env_file=None, **kw)  # type: ignore[call-arg]


def easy(**kw) -> Settings:
    base = dict(app_env="dev", auth_mode="easyauth", auth_allowed_roles=ROLE, auth_easyauth_assume_enabled=True)
    return S(**{**base, **kw})


def principal_header(roles=(ROLE,), oid="oid-123", name="Ada Lovelace", role_typ="roles", auth_typ="aad", extra=None) -> str:
    claims = [{"typ": "http://schemas.microsoft.com/identity/claims/objectidentifier", "val": oid}, {"typ": "name", "val": name}]
    claims += [{"typ": role_typ, "val": r} for r in roles]
    claims += extra or []
    payload = {"auth_typ": auth_typ, "name_typ": "name", "role_typ": role_typ, "claims": claims}
    return base64.b64encode(json.dumps(payload).encode()).decode()


def hdr(**kw) -> dict[str, str]:
    return {"X-MS-CLIENT-PRINCIPAL": principal_header(**kw)}


# ------------------------------------------------------------------ data
@pytest.fixture(scope="module")
def db(tmp_path_factory) -> str:
    return make_db(tmp_path_factory.mktemp("sec"))


def make_db(tmp: Path) -> str:
    url = f"sqlite:///{tmp}/sec.db"
    w = generate_world(seed=11, repos=40, now=datetime(2026, 10, 1, 12, 0, 0))
    src = demo_sources(w)
    cfg = ScanConfig(scope=Scope(code_hosts=ALL_HOSTS, projects=w["meta"]["projects"]), policy=Policy(approved_registries=["contosoacr.azurecr.io"]), db_url=url, mode="demo", now=parse_world_time(w))

    async def go():
        try:
            await Scanner(src, cfg).run("scan-0")
        finally:
            await src.aclose()

    asyncio.run(go())
    return url


@pytest.fixture(scope="module")
def none_client(db):
    return TestClient(create_app(db, settings=S()), base_url="http://localhost")


@pytest.fixture(scope="module")
def easy_client(db):
    return TestClient(create_app(db, settings=easy()), base_url="http://localhost")


# ------------------------------------------------------------------ principal parsing
def test_parse_valid_principal():
    p = A.parse_client_principal(principal_header(roles=(ROLE, "Other")))
    assert (p.id, p.name, p.roles, p.auth_type) == ("oid-123", "Ada Lovelace", (ROLE, "Other"), "aad")


def test_parse_roles_via_role_typ_and_uri():
    assert A.parse_client_principal(principal_header(role_typ="custom_role")).roles == (ROLE,)
    assert A.parse_client_principal(principal_header(role_typ=ROLE_URI)).roles == (ROLE,)
    # a claim of an unrelated type is never a role, even if its value looks like one
    p = A.parse_client_principal(principal_header(roles=(), extra=[{"typ": "groups", "val": ROLE}, {"typ": "scp", "val": ROLE}]))
    assert p.roles == ()


def test_roles_never_come_from_id_name_headers():
    ea = A.EasyAuthAuthenticator([ROLE], False)
    p = ea.authenticate({"x-ms-client-principal": principal_header(roles=()), "x-ms-client-principal-name": ROLE, "x-ms-client-principal-id": ROLE})
    assert p.roles == ()
    with pytest.raises(A.AuthError) as e:
        ea.authorize(p)
    assert e.value.status == 403


def test_id_name_header_fallbacks():
    raw = base64.b64encode(json.dumps({"auth_typ": "aad", "claims": [{"typ": "roles", "val": ROLE}]}).encode()).decode()
    p = A.parse_client_principal(raw, fallback_id="fid", fallback_name="Fallback")
    assert (p.id, p.name) == ("fid", "Fallback")
    with pytest.raises(A.AuthError):
        A.parse_client_principal(raw)  # no identity at all -> 401


@pytest.mark.parametrize("raw", [
    "!!!not base64!!!", "e30", base64.b64encode(b"not json").decode(), base64.b64encode(b"[1,2]").decode(),
    base64.b64encode(b'{"claims": "x"}').decode(), base64.b64encode(b'{"claims": [1]}').decode(),
    base64.b64encode(b"\xff\xfe\x00").decode(), base64.b64encode(b"[" * 100000 + b"]" * 100000).decode()[:16000],
    "A" * (A.MAX_PRINCIPAL_HEADER_BYTES + 1),
])
def test_parse_malformed_is_401_not_exception(raw):
    with pytest.raises(A.AuthError) as e:
        A.parse_client_principal(raw)
    assert e.value.status == 401


# ------------------------------------------------------------------ 401 / 403 / 200
def test_easyauth_missing_principal_is_401_everywhere(easy_client):
    for path in ("/", "/repos", "/repos.csv", "/api/v1/repos", "/api/v1/overview", "/api/v1/scans", "/openapi.json", "/api/docs", "/nope", "/api/nope"):
        r = easy_client.get(path)
        assert r.status_code == 401, path
        assert "scan-0" not in r.text and "<nav" not in r.text and "Repos scanned" not in r.text  # no data / nav


def test_easyauth_wrong_role_403_without_data(easy_client):
    for path in ("/", "/repos.csv", "/api/v1/repos"):
        r = easy_client.get(path, headers=hdr(roles=("Other.Role",)))
        assert r.status_code == 403, path
        assert "scan-0" not in r.text and "<nav" not in r.text and "Repos scanned" not in r.text and "payments" not in r.text.lower()
    assert easy_client.get("/", headers=hdr(roles=())).status_code == 403


def test_easyauth_allowed_role_200_and_name_shown(easy_client):
    r = easy_client.get("/", headers=hdr())
    assert r.status_code == 200 and "Ada Lovelace" in r.text and 'href="/.auth/logout"' in r.text
    assert easy_client.get("/api/v1/repos", headers=hdr()).status_code == 200
    assert easy_client.get("/repos.csv", headers=hdr()).status_code == 200
    # role match is exact and case sensitive
    assert easy_client.get("/", headers=hdr(roles=("pch.reader",))).status_code == 403


@pytest.mark.parametrize("bad", ["!!!", "e30=", "A" * 20000])
def test_easyauth_malformed_header_is_401_not_500(easy_client, bad):
    assert easy_client.get("/", headers={"X-MS-CLIENT-PRINCIPAL": bad}).status_code == 401


def test_allow_any_authenticated_requires_identity(db):
    c = TestClient(create_app(db, settings=easy(auth_allowed_roles="", auth_allow_any_authenticated=True)), base_url="http://localhost")
    assert c.get("/").status_code == 401
    assert c.get("/", headers=hdr(roles=())).status_code == 200


def test_none_mode_gives_local_dev_principal(none_client):
    r = none_client.get("/")
    assert r.status_code == 200 and "Sign out" not in r.text  # no sign-out link without Easy Auth


def test_unauthenticated_paths_are_limited(easy_client):
    h = easy_client.get("/api/v1/health")
    assert h.status_code == 200 and set(h.json()) == {"status", "version"}
    assert easy_client.get("/static/app.css").status_code == 200
    assert easy_client.get("/static/vendor/MANIFEST.json").status_code == 200
    for path in ("/static", "/api/v1/health/x", "/api/v1/healthz", "//api/v1/health", "/static/../app.py"):
        assert easy_client.get(path).status_code in (401, 404), path
    assert easy_client.get("/static/../../app.py").status_code in (401, 404)


def test_static_dir_contains_only_assets():
    allowed = {".js", ".css", ".json", ".md"}
    names = [p for p in STATIC.rglob("*") if p.is_file()]
    assert names and all(p.suffix in allowed or p.name.endswith("LICENSE") for p in names), [p.name for p in names]


# ------------------------------------------------------------------ guard
def is_ok(s: Settings, host: str) -> bool:
    return not guard_problems(s, host)


@pytest.mark.parametrize("host,loop", [("127.0.0.1", True), ("::1", True), ("[::1]", True), ("localhost", True), ("LOCALHOST", True), ("127.0.0.2", True),
                                       ("0.0.0.0", False), ("::", False), ("", False), ("10.0.0.5", False), ("example.com", False), ("localhost.evil.com", False)])
def test_loopback_detection(host, loop):
    assert is_loopback_host(host) is loop


GUARD_CASES = [
    # (id, settings kwargs, host, ok)
    ("dev-none-loopback", dict(), "127.0.0.1", True),
    ("dev-none-localhost", dict(), "localhost", True),
    ("dev-none-ipv6", dict(), "::1", True),
    ("dev-none-0.0.0.0", dict(), "0.0.0.0", False),
    ("test-none-0.0.0.0", dict(app_env="test"), "0.0.0.0", False),
    ("dev-none-0.0.0.0-container-flag", dict(auth_none_allow_container_bind=True), "0.0.0.0", True),
    ("test-none-0.0.0.0-container-flag", dict(app_env="test", auth_none_allow_container_bind=True), "0.0.0.0", False),
    ("prod-none-loopback", dict(app_env="prod", allowed_hosts="a.azurewebsites.net"), "127.0.0.1", False),
    ("prod-none-container-flag", dict(app_env="prod", auth_none_allow_container_bind=True, allowed_hosts="a.azurewebsites.net"), "0.0.0.0", False),
    ("dev-easy-roles-assume", dict(auth_mode="easyauth", auth_allowed_roles=ROLE, auth_easyauth_assume_enabled=True), "0.0.0.0", True),
    ("dev-easy-roles-platform", dict(auth_mode="easyauth", auth_allowed_roles=ROLE, website_auth_enabled="True"), "0.0.0.0", True),
    ("dev-easy-roles-platform-lower", dict(auth_mode="easyauth", auth_allowed_roles=ROLE, website_auth_enabled=" true "), "0.0.0.0", True),
    ("dev-easy-no-allowlist", dict(auth_mode="easyauth", website_auth_enabled="True"), "0.0.0.0", False),
    ("dev-easy-any-auth", dict(auth_mode="easyauth", auth_allow_any_authenticated=True, website_auth_enabled="True"), "0.0.0.0", True),
    ("dev-easy-roles-and-any", dict(auth_mode="easyauth", auth_allowed_roles=ROLE, auth_allow_any_authenticated=True, website_auth_enabled="True"), "0.0.0.0", False),
    ("dev-easy-platform-off", dict(auth_mode="easyauth", auth_allowed_roles=ROLE, website_auth_enabled="False"), "0.0.0.0", False),
    ("dev-easy-platform-unset", dict(auth_mode="easyauth", auth_allowed_roles=ROLE), "0.0.0.0", False),
    ("dev-easy-platform-garbage", dict(auth_mode="easyauth", auth_allowed_roles=ROLE, website_auth_enabled="1"), "0.0.0.0", False),
    ("prod-easy-ok", dict(app_env="prod", auth_mode="easyauth", auth_allowed_roles=ROLE, website_auth_enabled="True", allowed_hosts="*.azurewebsites.net"), "0.0.0.0", True),
    ("prod-easy-assume", dict(app_env="prod", auth_mode="easyauth", auth_allowed_roles=ROLE, auth_easyauth_assume_enabled=True, allowed_hosts="a.net"), "0.0.0.0", False),
    ("prod-easy-assume-and-platform", dict(app_env="prod", auth_mode="easyauth", auth_allowed_roles=ROLE, auth_easyauth_assume_enabled=True, website_auth_enabled="True", allowed_hosts="a.net"), "0.0.0.0", False),
    ("prod-easy-no-hosts", dict(app_env="prod", auth_mode="easyauth", auth_allowed_roles=ROLE, website_auth_enabled="True"), "0.0.0.0", False),
    ("prod-easy-star-host", dict(app_env="prod", auth_mode="easyauth", auth_allowed_roles=ROLE, website_auth_enabled="True", allowed_hosts="*"), "0.0.0.0", False),
    ("prod-easy-no-allowlist", dict(app_env="prod", auth_mode="easyauth", website_auth_enabled="True", allowed_hosts="a.net"), "0.0.0.0", False),
    ("prod-easy-container-flag", dict(app_env="prod", auth_mode="easyauth", auth_allowed_roles=ROLE, website_auth_enabled="True", allowed_hosts="a.net", auth_none_allow_container_bind=True), "0.0.0.0", False),
]


@pytest.mark.parametrize("kw,host,ok", [c[1:] for c in GUARD_CASES], ids=[c[0] for c in GUARD_CASES])
def test_guard_matrix(kw, host, ok):
    s = S(**kw)
    assert is_ok(s, host) is ok
    if ok:
        assert_safe_to_serve(s, host)
    else:
        with pytest.raises(UnsafeServeConfig) as e:
            assert_safe_to_serve(s, host)
        assert "refusing to start" in str(e.value)


def test_guard_exhaustive_invariants():
    """Every combination of the security-relevant inputs: assert the fail-closed invariants (not a re-implementation)."""
    n = 0
    for env, mode, host, roles, anyauth, platform, assume, cflag, hosts in itertools.product(
            ("dev", "test", "prod"), ("none", "easyauth"), ("127.0.0.1", "::1", "localhost", "0.0.0.0"), ("", ROLE), (False, True),
            ("", "True", "false"), (False, True), (False, True), ("", "a.azurewebsites.net", "*")):
        s = S(app_env=env, auth_mode=mode, auth_allowed_roles=roles, auth_allow_any_authenticated=anyauth, website_auth_enabled=platform,
              auth_easyauth_assume_enabled=assume, auth_none_allow_container_bind=cflag, allowed_hosts=hosts)
        ok, n = is_ok(s, host), n + 1
        if not ok:
            continue
        # anything that starts is provably safe:
        if env == "prod":
            assert mode == "easyauth" and hosts not in ("", "*") and not assume and not cflag
        if mode == "none":
            assert env != "prod" and (is_loopback_host(host) or (cflag and env == "dev"))
        else:
            assert (roles != "") != anyauth  # exactly one authorization policy
            assert platform.lower() == "true" or (assume and env != "prod")
    assert n == 3 * 2 * 4 * 2 * 2 * 3 * 2 * 2 * 3


def test_create_app_calls_guard(db):
    with pytest.raises(UnsafeServeConfig):
        create_app(db, settings=S(app_env="prod", allowed_hosts="a.net"))
    with pytest.raises(UnsafeServeConfig):
        create_app(db, settings=S(), host="0.0.0.0")
    with pytest.raises(UnsafeServeConfig):
        create_app(db, settings=easy(auth_easyauth_assume_enabled=False))


def test_pch_serve_refuses_unsafe_config(db, monkeypatch):
    from typer.testing import CliRunner

    from pch.cli import app as cli
    from pch.settings import reset_settings

    monkeypatch.setenv("APP_ENV", "prod")
    reset_settings()
    try:
        r = CliRunner().invoke(cli, ["serve", "--db", db])
        assert r.exit_code == 2 and "refusing to start" in r.output and "AUTH_MODE=none" in r.output
        monkeypatch.setenv("APP_ENV", "dev")
        reset_settings()
        r = CliRunner().invoke(cli, ["serve", "--db", db, "--host", "0.0.0.0"])
        assert r.exit_code == 2 and "non-loopback" in r.output
    finally:
        monkeypatch.delenv("APP_ENV", raising=False)
        reset_settings()


def test_effective_port_and_settings_helpers(monkeypatch):
    assert S().effective_port == 8000
    assert S(websites_port=8080).effective_port == 8080
    assert S(port=9000, websites_port=8080).effective_port == 9000
    monkeypatch.setenv("WEBSITES_PORT", "8181")
    assert Settings(_env_file=None).effective_port == 8181
    monkeypatch.setenv("PORT", "8282")
    assert Settings(_env_file=None).effective_port == 8282
    assert S(auth_allowed_roles=" A , ,B ").allowed_roles == ["A", "B"]
    assert S(website_auth_enabled="TRUE").easyauth_platform_enabled


def test_doctor_auth_and_guard_checks():
    from pch.doctor import FAIL, OK, WARN, check_auth, check_serve_guard

    assert check_auth(S()).status == WARN and check_serve_guard(S()).status == OK
    good = easy(website_auth_enabled="True", auth_easyauth_assume_enabled=False)
    assert check_auth(good).status == OK
    bad = easy(auth_easyauth_assume_enabled=False)
    c = check_auth(bad)
    assert c.status == FAIL and "WEBSITE_AUTH_ENABLED" in c.detail
    assert check_serve_guard(bad).status == FAIL
    assert check_auth(S(app_env="prod")).status == FAIL


# ------------------------------------------------------------------ headers
REQUIRED = {"x-content-type-options": "nosniff", "referrer-policy": "same-origin", "x-frame-options": "DENY", "cross-origin-opener-policy": "same-origin"}


def assert_secure_headers(r, *, static=False):
    for k, v in REQUIRED.items():
        assert r.headers.get(k) == v, k
    assert r.headers["content-security-policy"] == CSP
    assert "permissions-policy" in r.headers and "server" not in r.headers
    assert r.headers.get("x-request-id")
    if not static:
        assert r.headers["cache-control"] == "no-store"


def test_csp_has_no_unsafe_or_third_party():
    assert "unsafe-inline" not in CSP and "unsafe-eval" not in CSP and "http" not in CSP and "*" not in CSP
    for d in ("default-src 'self'", "script-src 'self'", "style-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'"):
        assert d in CSP


@pytest.mark.parametrize("path", ["/", "/repos", "/api/v1/repos", "/repos.csv", "/api/v1/health", "/nope", "/api/nope", "/repos/No/Such", "/api/v1/repos?sort=bogus"])
def test_headers_on_all_responses(none_client, path):
    assert_secure_headers(none_client.get(path))


def test_headers_on_static_and_cache_policy(none_client):
    r = none_client.get("/static/app.css")
    assert_secure_headers(r, static=True) and r.headers["cache-control"] == "no-cache"
    assert none_client.get("/static/app.js?v=abc").headers["cache-control"] == "public, max-age=31536000, immutable"
    assert none_client.get("/static/vendor/htmx-1.9.12.min.js").headers["cache-control"] == "public, max-age=31536000, immutable"


def test_headers_on_401_403_405(easy_client):
    assert_secure_headers(easy_client.get("/"))
    assert_secure_headers(easy_client.get("/", headers=hdr(roles=())))
    assert_secure_headers(easy_client.post("/", headers=hdr()))
    assert_secure_headers(easy_client.get("/", headers={"Host": "evil.example"}))


def test_hsts_only_in_prod(db):
    prod = S(app_env="prod", auth_mode="easyauth", auth_allowed_roles=ROLE, website_auth_enabled="True", allowed_hosts="*.azurewebsites.net")
    c = TestClient(create_app(db, settings=prod), base_url="https://app.azurewebsites.net")
    r = c.get("/", headers=hdr())
    assert r.status_code == 200 and r.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "strict-transport-security" not in TestClient(create_app(db, settings=S()), base_url="http://localhost").get("/").headers


def test_all_page_templates_reference_only_local_assets(none_client):
    for path in ("/", "/repos", "/findings", "/rules", "/testing", "/targets", "/migration", "/scans"):
        t = none_client.get(path).text
        refs = re.findall(r'(?:src|href)="([^"]+)"', t)
        for ref in refs:
            assert ref.startswith("/") and not ref.startswith("//"), (path, ref)
        assert not re.search(r"<(?:script|link|img|iframe|form)\b[^>]*(?:https?:)?//[a-z0-9.-]+\.[a-z]{2,}", t, re.I), path
        assert "/static/vendor/tailwind.css" in t and "/static/vendor/htmx-1.9.12.min.js" in t and "/static/app.js" in t
    assert 'name="htmx-config"' in none_client.get("/").text and '"allowEval":false' in none_client.get("/").text


# ------------------------------------------------------------------ other hardening
def test_docs_disabled_in_prod_enabled_in_dev(db, none_client):
    assert none_client.get("/api/docs").status_code == 200 and none_client.get("/openapi.json").status_code == 200
    csp = none_client.get("/api/docs").headers["content-security-policy"]
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp and "sha256-" in csp  # hash, not unsafe-inline
    assert none_client.get("/").headers["content-security-policy"] == CSP  # relaxed CSP is scoped to the docs page only
    prod = S(app_env="prod", auth_mode="easyauth", auth_allowed_roles=ROLE, website_auth_enabled="True", allowed_hosts="app.azurewebsites.net")
    c = TestClient(create_app(db, settings=prod), base_url="https://app.azurewebsites.net")
    for path in ("/api/docs", "/openapi.json", "/redoc", "/docs"):
        assert c.get(path, headers=hdr()).status_code == 404, path
    assert "API</a>" not in c.get("/", headers=hdr()).text


def test_trusted_hosts(db):
    prod = S(app_env="prod", auth_mode="easyauth", auth_allowed_roles=ROLE, website_auth_enabled="True", allowed_hosts="app.azurewebsites.net, *.example.org")
    c = TestClient(create_app(db, settings=prod), base_url="https://app.azurewebsites.net")
    assert c.get("/", headers=hdr()).status_code == 200
    assert c.get("/", headers={**hdr(), "Host": "sub.example.org"}).status_code == 200
    assert c.get("/", headers={**hdr(), "Host": "app.azurewebsites.net:8443"}).status_code == 200
    for bad in ("evil.com", "app.azurewebsites.net.evil.com", "example.org", "localhost", "evilapp.azurewebsites.net"):
        r = c.get("/", headers={**hdr(), "Host": bad})
        assert r.status_code == 400 and "scan-0" not in r.text, bad
    # container health probe from inside the container, and nothing else, may use a loopback Host
    assert c.get("/api/v1/health", headers={"Host": "127.0.0.1:8000"}).status_code == 200
    assert c.get("/repos", headers={**hdr(), "Host": "127.0.0.1:8000"}).status_code == 400


def test_none_mode_defaults_to_loopback_hosts(none_client):
    assert none_client.get("/", headers={"Host": "evil.example"}).status_code == 400  # DNS-rebinding guard
    assert none_client.get("/", headers={"Host": "127.0.0.1:8000"}).status_code == 200
    assert none_client.get("/", headers={"Host": "[::1]:8000"}).status_code == 200


@pytest.mark.parametrize("method", ["post", "put", "delete", "patch", "options"])
@pytest.mark.parametrize("path", ["/", "/api/v1/repos", "/repos.csv", "/nope"])
def test_mutating_methods_405(none_client, easy_client, method, path):
    r = getattr(none_client, method)(path)
    assert r.status_code == 405 and r.headers["allow"] == "GET, HEAD"
    r = getattr(easy_client, method)(path, headers=hdr())
    assert r.status_code == 405


def test_head_works(none_client):
    assert none_client.head("/static/app.css").status_code == 200
    assert none_client.head("/repos").status_code in (200, 405)  # router decides; never an error page with data


def test_write_routes_are_an_explicit_allowlist(none_client):
    """The only non-GET routes are the two feature-switch POSTs (ADR-19); anything else must be added here AND to the method guard, with a decision record."""
    writes = {r.path: set(r.methods) for r in none_client.app.routes if (getattr(r, "methods", None) or set()) - {"GET", "HEAD"}}
    assert writes == {"/settings/features/{key}": {"POST"}, "/settings/features/{key}/reset": {"POST"}}


def test_generic_500_no_leak(db, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret-internal-detail /etc/passwd Traceback")

    monkeypatch.setattr(Q, "overview", boom)
    c = TestClient(create_app(db, settings=S()), base_url="http://localhost", raise_server_exceptions=False)
    for path in ("/", "/api/v1/overview"):
        r = c.get(path)
        assert r.status_code == 500, path
        assert "secret-internal-detail" not in r.text and "Traceback" not in r.text and "RuntimeError" not in r.text
        assert r.headers["x-request-id"] in r.text  # correlation id shown to the user
        assert_secure_headers(r)


def test_404_pages_generic_with_correlation_id(none_client):
    r = none_client.get("/repos/<script>alert(1)</script>/x")
    assert r.status_code == 404 and "<script>alert(1)" not in r.text and r.headers["x-request-id"] in r.text
    j = none_client.get("/api/v1/repos/Nope/missing")
    assert j.status_code == 404 and j.json()["detail"] == "not found"


def test_query_validation_is_400_422_never_500(none_client):
    api = [
        ("/api/v1/repos", {"sort": "'; drop table--"}), ("/api/v1/repos", {"dir": "sideways"}), ("/api/v1/repos", {"q": "x" * 5000}),
        ("/api/v1/findings", {"limit": 0}), ("/api/v1/findings", {"limit": 10**9}), ("/api/v1/findings", {"offset": -1}), ("/api/v1/findings", {"offset": "abc"}),
        ("/api/v1/findings", {"offset": 10**12}), ("/api/v1/overview", {"scan": "s" * 500}),
    ]
    for path, params in api:
        r = none_client.get(path, params=params)
        assert r.status_code == 422, (path, params, r.status_code)
        assert "'; drop" not in r.text and "xxxxx" not in r.text  # input not echoed
        assert_secure_headers(r)
    for path, params in [("/repos", {"sort": "bogus"}), ("/findings", {"page": 0}), ("/findings", {"per_page": 7}), ("/repos", {"per_page": "abc"}), ("/repos", {"page": 10**9}),
                         ("/rules", {"sort": "bogus"}), ("/lineage", {"sort": "bogus"}), ("/lineage/P/r", {"view": "cube"}), ("/repos.csv", {"dir": "x"})]:
        assert none_client.get(path, params=params).status_code == 400
    assert none_client.get("/api/v1/findings", params={"limit": 1000, "offset": 0}).status_code == 200
    assert set(get_args(SortKey)) == Q.SORTABLE


def test_websocket_rejected(none_client):
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect), none_client.websocket_connect("/ws"):
        pass


# ------------------------------------------------------------------ XSS
PAYLOADS = ["<img src=x onerror=alert(1)>", "</script><script>alert(1)</script>", '"><svg/onload=alert(1)>', "javascript:alert(1)"]


def test_json_for_script_escaping():
    out = str(json_for_script({"a": "</script><script>alert(1)</script>", "b": "<!-- &     -->", "c": [1, None]}))
    assert "<" not in out and ">" not in out and "&" not in out and " " not in out
    assert json.loads(out)["a"] == "</script><script>alert(1)</script>"  # still valid JSON that round-trips
    assert json.loads(out)["b"] == "<!-- &     -->"


def test_safe_url_and_csv_cell():
    assert safe_url("https://dev.azure.com/o/p") == "https://dev.azure.com/o/p"
    for bad in ("javascript:alert(1)", "data:text/html,x", "//evil.com", "", None, "http://a b", " vbscript:x"):
        assert safe_url(bad) == "#"
    assert csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0" and csv_cell("@SUM(1)") == "'@SUM(1)" and csv_cell("+1") == "'+1"
    assert csv_cell("normal") == "normal" and csv_cell(5) == 5 and csv_cell("") == ""


@pytest.fixture(scope="module")
def xss_db(tmp_path_factory):
    url = make_db(tmp_path_factory.mktemp("xss"))
    with session_scope(url) as s:
        rows = s.query(RepoResultRow).limit(4).all()
        for r, p in zip(rows, PAYLOADS, strict=False):
            old_key = r.repo_key
            r.repo, r.owner, r.url, r.test_state, r.test_state_reason = p, p, p, "NO_TESTS", p
            r.repo_key = f"{r.project}/{p}"
            r.pipelines = [{**x, "name": p, "url": p} for x in r.pipelines]
            for f in s.query(FindingRow).filter(FindingRow.repo_key == old_key).all():
                f.repo_key = r.repo_key
                f.message, f.pipeline_name, f.stage, f.link = PAYLOADS[0], PAYLOADS[1], PAYLOADS[2], PAYLOADS[3]
        first = rows[0].project
    return url, first


def test_xss_escaped_in_html_and_json_blocks(xss_db):
    url, project = xss_db
    c = TestClient(create_app(url, settings=S()), base_url="http://localhost")
    pages = ["/", "/repos", "/findings", "/testing", "/targets", "/migration", "/scans", "/rules", f"/repos?project={project}"]
    repos = c.get("/api/v1/repos").json()["repos"]
    evil = [r for r in repos if r["repo"] in PAYLOADS]
    assert len(evil) >= 2
    for r in (r for r in evil if "/" not in r["repo"]):
        from urllib.parse import quote

        pages.append(f"/repos/{quote(r['project'], safe='')}/{quote(r['repo'], safe='')}")
    seen_json = seen_escaped = 0
    for path in pages:
        r = c.get(path)
        assert r.status_code == 200, path
        t = r.text
        for p in ("<img src=x onerror=alert(1)>", "</script><script>alert(1)", '"><svg/onload', "<svg/onload=alert(1)>"):
            assert p not in t, (path, p)
        assert 'href="javascript:' not in t
        if "&lt;img src=x onerror=alert(1)&gt;" in t:
            seen_escaped += 1
        for blk in re.findall(r'<script type="application/json" id="page-data">(.*?)</script>', t, re.S):
            seen_json += 1
            assert "<" not in blk and ">" not in blk
            json.loads(blk)
        # exactly the executable scripts we expect: external only
        assert not re.findall(r"<script(?![^>]*\bsrc=)(?![^>]*application/json)[^>]*>", t)
    assert seen_json >= 4 and seen_escaped >= 3
    testing = c.get("/testing").text
    assert "\\u003cimg src=x onerror=alert(1)\\u003e" in testing  # present, but inert, inside the JSON block
    # JSON API returns data as JSON (application/json, nosniff): escaping is the client's job and the content type is not HTML
    r = c.get("/api/v1/repos")
    assert r.headers["content-type"].startswith("application/json") and r.headers["x-content-type-options"] == "nosniff"
    csv_text = c.get("/repos.csv").text
    assert "<img" in csv_text  # data intact; formula chars are neutralised separately (csv_cell)


# ------------------------------------------------------------------ vendored assets + template hygiene
def test_vendor_manifest_matches_files():
    manifest = json.loads((STATIC / "vendor" / "MANIFEST.json").read_text())
    names = set()
    for a in manifest["assets"]:
        f = STATIC / "vendor" / a["file"]
        assert f.exists(), a["file"]
        assert hashlib.sha256(f.read_bytes()).hexdigest() == a["sha256"], f"{a['file']} differs from MANIFEST.json"
        assert a["version"] and a["source"].startswith("https://")
        names.add(a["file"])
    shipped = {p.name for p in (STATIC / "vendor").iterdir() if p.suffix in (".js", ".css")}
    assert shipped == names, "every vendored script/stylesheet must be listed in MANIFEST.json"
    assert {"htmx.org", "chart.js"} <= {a["name"] for a in manifest["assets"]}
    base = (WEB / "templates" / "base.html").read_text()
    for ref in re.findall(r"/static/vendor/([\w.\-]+)", base):
        assert ref in names


def test_templates_have_no_inline_script_style_handlers_or_cdn():
    templates = sorted((WEB / "templates").glob("*.html"))
    assert len(templates) >= 10
    for f in templates:
        t = f.read_text()
        for m in re.finditer(r"<script\b([^>]*)>", t, re.I):
            attrs = m.group(1)
            assert re.search(r"\bsrc=", attrs) or 'type="application/json"' in attrs, f"{f.name}: inline executable <script>"
        assert not re.search(r"<style\b", t, re.I), f"{f.name}: <style>"
        assert not re.search(r"\sstyle\s*=", t, re.I), f"{f.name}: style attribute"
        assert not re.search(r"\son[a-z]+\s*=", t, re.I), f"{f.name}: inline event handler"
        assert "javascript:" not in t.lower(), f.name
        assert not re.search(r"(https?:)?//[a-z0-9.-]+\.[a-z]{2,}", t, re.I), f"{f.name}: absolute/CDN URL"
        assert not re.search(r"\|\s*safe\b(?!_)", t) and "Markup" not in t, f"{f.name}: |safe/Markup needs review"
        for m in re.finditer(r'<script type="application/json"[^>]*>(.*?)</script>', t, re.S):
            assert "tojson_safe" in m.group(1), f"{f.name}: JSON block must use tojson_safe"


def test_static_js_has_no_eval_or_html_injection():
    for f in (STATIC / "app.js", STATIC / "theme.js"):
        t = f.read_text()
        for bad in ("eval(", "new Function", "document.write", "innerHTML", "insertAdjacentHTML", "setAttribute(\"style\""):
            assert bad not in t, f"{f.name}: {bad}"


def test_guard_refuses_auth_mode_without_guard_branch():
    s = Settings(_env_file=None, app_env="dev")
    object.__setattr__(s, "auth_mode", "future-mode")  # simulates a mode added to the Literal but not to the guard
    problems = guard_problems(s, "127.0.0.1")
    assert any("has no startup guard rules" in p for p in problems)
    with pytest.raises(UnsafeServeConfig):
        assert_safe_to_serve(s, "127.0.0.1")
