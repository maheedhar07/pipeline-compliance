"""pch doctor: offline GitHub config checks (never values) and the --online probe (G2)."""

import json
import sys

import httpx
import pytest
import respx
from typer.testing import CliRunner

from pch.cli import app
from pch.settings import Settings, reset_settings
from tests.github_mock import API, PAT, gh

GITHUB_ENV = ["GITHUB_API_URL", "GITHUB_AUTH", "GITHUB_TOKEN", "GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY", "APP_ENV"]


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    for k in GITHUB_ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "d"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/x.db")
    monkeypatch.chdir(tmp_path)
    reset_settings()
    (tmp_path / "scope.yaml").write_text("github:\n  orgs: [contoso-payments]\n")
    yield
    reset_settings()


def doctor(tmp_path, *args):
    res = CliRunner().invoke(app, ["doctor", "--scope", str(tmp_path / "scope.yaml"), "--policy", str(tmp_path / "none.yaml"), "--json", *args])
    return res, {c["name"]: c for c in json.loads(res.output)["checks"]}


def test_unconfigured_github_warns_when_orgs_are_in_scope(tmp_path):
    _, c = doctor(tmp_path)
    assert c["github"]["status"] == "WARN" and "will NOT be discovered" in c["github"]["detail"] and "contoso-payments" in c["github"]["detail"]
    (tmp_path / "scope.yaml").write_text("{}\n")
    _, c = doctor(tmp_path)
    assert c["github"]["status"] == "OK" and "not configured" in c["github"]["detail"]


def test_pat_reported_set_never_the_value(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", PAT)
    res, c = doctor(tmp_path)
    assert c["github"]["status"] == "OK" and "GITHUB_TOKEN=set" in c["github"]["detail"] and "auth=pat" in c["github"]["detail"]
    assert PAT not in res.output and "source:github" not in c  # one dedicated row, not the generic source rows


def test_app_mode_checks_ids_key_and_extra(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_AUTH", "app")
    monkeypatch.setenv("GITHUB_APP_ID", "123")
    res, c = doctor(tmp_path)
    d = c["github"]["detail"]
    assert c["github"]["status"] == "FAIL" and "GITHUB_APP_INSTALLATION_ID=missing" in d and "GITHUB_APP_PRIVATE_KEY=missing" in d and "GITHUB_APP_ID=set" in d
    monkeypatch.setenv("GITHUB_APP_INSTALLATION_ID", "9")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN " + "PRIVATE KEY-----\nnot-a-real-key\n-----END " + "PRIVATE KEY-----")  # assembled at runtime: nothing key-shaped is committed
    pytest.importorskip("jwt")
    res, c = doctor(tmp_path)
    assert c["github"]["status"] == "OK" and "extra=installed" in c["github"]["detail"] and "not-a-real-key" not in res.output
    monkeypatch.setitem(sys.modules, "jwt", None)  # an install without the extra
    res, c = doctor(tmp_path)
    assert c["github"]["status"] == "FAIL" and "github-app" in c["github"]["detail"]


def test_default_doctor_is_offline(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", PAT)
    with respx.mock(assert_all_called=False) as m:  # any request would raise: no route is registered
        _, c = doctor(tmp_path)
    assert "github_online" not in c and not m.calls


def test_settings_validation():
    with pytest.raises(ValueError):
        Settings(github_api_url="https://api.github.com/x?y=1")
    with pytest.raises(ValueError):
        Settings(github_app_id="abc")
    with pytest.raises(ValueError):
        Settings(app_env="prod", github_api_url="http://ghe.example.com/api/v3")  # credentials never travel in clear text in prod
    assert Settings(github_api_url="https://ghe.example.com/api/v3/").github_api_url == "https://ghe.example.com/api/v3"
    assert Settings().github_api_url == "https://api.github.com" and Settings().github_auth == "pat"


@respx.mock
def test_online_probe_reports_quota_and_missing_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", PAT)
    respx.get(f"{API}/rate_limit").mock(return_value=httpx.Response(200, json={"resources": {"core": {"limit": 5000, "remaining": 4321, "reset": 1790000000}}}))
    respx.get(f"{API}/orgs/contoso-payments/repos").mock(return_value=httpx.Response(200, json=gh("org_repos_page1.json")[:1]))
    base = f"{API}/repos/contoso-payments/billing-api"
    respx.get(f"{base}/rules/branches/main").mock(return_value=httpx.Response(200, json=[]))
    respx.get(f"{base}/git/trees/main").mock(return_value=httpx.Response(200, json={"tree": []}))
    respx.get(f"{base}/branches/main/protection").mock(return_value=httpx.Response(
        403, json={"message": "Resource not accessible"}, headers={"X-Accepted-GitHub-Permissions": "administration=read"}))
    res, c = doctor(tmp_path, "--online")
    assert c["github_online"]["status"] == "OK" and "4321/5000" in c["github_online"]["detail"]
    perm = c["github_permissions"]
    assert perm["status"] == "WARN" and "classic branch protection=MISSING" in perm["detail"] and "administration=read" in perm["detail"]
    assert "rules/branches=ok" in perm["detail"] and "file tree=ok" in perm["detail"] and "UNKNOWN" in perm["detail"]
    assert PAT not in res.output
    assert all(call.request.method == "GET" for call in respx.calls)


@respx.mock
def test_online_probe_rejected_token_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", PAT)
    respx.get(f"{API}/rate_limit").mock(return_value=httpx.Response(401, json={"message": "Bad credentials"}))
    res, c = doctor(tmp_path, "--online")
    assert res.exit_code == 1 and c["github_online"]["status"] == "FAIL" and "rejected" in c["github_online"]["detail"]


def test_online_without_a_reader_is_skipped(tmp_path):
    _, c = doctor(tmp_path, "--online")
    assert c["github_online"]["status"] == "WARN" and "not configured" in c["github_online"]["detail"]
