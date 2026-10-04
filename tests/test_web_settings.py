"""The Settings page (ADR-19): the app's only write path. Authorisation, CSRF, same-origin, audit, fail-closed modes, and what each switch does to pages and the API."""

import asyncio
import re
import time
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pch import features as F
from pch.demo.generator import generate_world
from pch.demo.transport import parse_world_time
from pch.logging_setup import scrub
from pch.orchestrator import ScanConfig, Scanner
from pch.settings import ConfigError, Policy, Scope, Settings
from pch.sources import demo_sources
from pch.store import repository as store
from pch.store.db import session_scope
from pch.store.models import FeatureAuditRow, FeatureFlagRow, ScanRow
from pch.web import csrf
from pch.web.app import create_app
from pch.web.guard import guard_warnings
from tests.builders import ALL_HOSTS
from tests.test_web_security import ROLE, easy, hdr

ADMIN = "PCH.Admin"
KEY = "k" * 40
HOST = "http://localhost"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("APP_ENV", "AUTH_MODE", "AUTH_ALLOWED_ROLES", "AUTH_ADMIN_ROLES", "SETTINGS_SIGNING_KEY", "WEBSITE_AUTH_ENABLED", "ALLOWED_HOSTS", "DATABASE_URL", "CONFIG_DIR", "SECRETS_PROVIDER"):
        monkeypatch.delenv(k, raising=False)


def scan_into(url: str, sid: str, features=None, repos=10, when=datetime(2026, 10, 1, 12, 0, 0)) -> None:
    w = generate_world(seed=11, repos=repos, now=when)
    src = demo_sources(w, features=features)
    cfg = ScanConfig(scope=Scope(code_hosts=ALL_HOSTS, projects=w["meta"]["projects"]), policy=Policy(approved_registries=["contosoacr.azurecr.io"]), db_url=url, mode="demo",
                     now=parse_world_time(w), **({"features": features} if features else {}))

    async def go():
        try:
            await Scanner(src, cfg).run(sid)
        finally:
            await src.aclose()

    asyncio.run(go())


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    url = f"sqlite:///{tmp_path_factory.mktemp('set')}/set.db"
    scan_into(url, "scan-0")
    return url


@pytest.fixture(autouse=True)
def _reset_flags(db):
    with session_scope(db) as s:
        s.query(FeatureFlagRow).delete()
        s.query(FeatureAuditRow).delete()
    yield


def S(**kw) -> Settings:
    return easy(**{"auth_admin_roles": ADMIN, "settings_signing_key": KEY, **kw})


def client(db, **kw) -> TestClient:
    return TestClient(create_app(db, settings=S(**kw)), base_url=HOST)


def admin(oid="oid-admin", name="Ada Lovelace", **kw) -> dict[str, str]:
    return hdr(roles=(ADMIN,), oid=oid, name=name, **kw)


def token(html: str, action: str) -> str:
    m = re.search(rf'action="{re.escape(action)}">\s*<input type="hidden" name="csrf_token" value="([^"]+)">', html)
    assert m, f"no form for {action}"
    return m.group(1)


def post(c, path, h, *, data=None, origin=HOST, extra=None, content=None, **kw):
    headers = {**h, **({"Origin": origin} if origin else {}), **(extra or {})}
    if content is not None:
        return c.post(path, content=content, headers=headers, **kw)
    return c.post(path, data=data, headers=headers, **kw)


def flip(c, key="migration", value="off", h=None, **kw):
    h = h or admin()
    page = c.get("/settings", headers=h).text
    return post(c, f"/settings/features/{key}", h, data={"csrf_token": token(page, f"/settings/features/{key}"), "value": value}, follow_redirects=False, **kw)


def flags(db):
    with session_scope(db) as s:
        return F.effective_flags(s, F.ALL_ON)


def audit_count(db):
    with session_scope(db) as s:
        return s.query(FeatureAuditRow).count()


# ------------------------------------------------------------------ authorisation
def test_admin_can_change_a_switch_and_it_is_audited(db):
    c = client(db)
    r = flip(c)
    assert r.status_code == 303 and r.headers["location"] == "/settings?flash=saved&k=migration"
    assert flags(db)["migration"] is False
    with session_scope(db) as s:
        (a,) = F.audit_entries(s)
        assert (a.feature_key, a.old_value, a.new_value, a.source, a.actor_display_name) == ("migration", "default", "off", "ui", "Ada Lovelace")
        assert a.actor_id_hash == F.Actor("oid-admin", "x").id_hash and "oid-admin" not in a.actor_id_hash
        assert s.get(FeatureFlagRow, "migration").updated_by == "Ada Lovelace"
    page = c.get(r.headers["location"], headers=admin()).text
    assert "Saved: Azure DevOps to GitHub Actions migration is now off." in page and "changed by Ada Lovelace at" in page and "Reset to default" in page


def test_reader_without_admin_role_gets_403_and_a_read_only_page(db):
    c = client(db)
    page = c.get("/settings", headers=hdr()).text
    assert "Read-only." in page and "csrf_token" not in page and "<form method=\"post\"" not in page and page.count("disabled") >= 5
    r = post(c, "/settings/features/migration", hdr(), data={"csrf_token": "x", "value": "off"})
    assert r.status_code == 403 and "do not have permission" in r.text
    assert flags(db)["migration"] is True and audit_count(db) == 0


def test_no_principal_is_401_and_unlisted_role_is_403(db):
    c = client(db)
    assert post(c, "/settings/features/migration", {}, data={"value": "off"}).status_code == 401
    assert post(c, "/settings/features/migration", hdr(roles=("Other",)), data={"value": "off"}).status_code == 403
    assert c.get("/settings").status_code == 401 and c.get("/settings", headers=hdr(roles=("Other",))).status_code == 403
    assert audit_count(db) == 0


def test_admin_role_alone_grants_read_access_and_a_reader_role_does_not_grant_write(db):
    c = client(db)
    assert c.get("/", headers=hdr(roles=(ADMIN,))).status_code == 200  # no Reader role needed
    assert c.get("/", headers=hdr(roles=(ROLE,))).status_code == 200
    assert 'data-feature="migration"' in c.get("/settings", headers=hdr(roles=(ROLE,))).text


def test_easyauth_with_no_admin_roles_is_read_only_for_everyone(db):
    c = client(db, auth_admin_roles="")
    page = c.get("/settings", headers=hdr(roles=(ROLE, ADMIN))).text
    assert "No administrator role is configured" in page and "csrf_token" not in page
    assert post(c, "/settings/features/migration", hdr(roles=(ROLE, ADMIN)), data={"csrf_token": "x", "value": "off"}).status_code == 403
    assert audit_count(db) == 0


def test_role_claim_must_come_from_the_signed_claims_not_headers(db):
    c = client(db)
    h = {**hdr(roles=(ROLE,)), "X-MS-CLIENT-PRINCIPAL-NAME": ADMIN, "X-MS-CLIENT-PRINCIPAL-ID": ADMIN}
    assert post(c, "/settings/features/migration", h, data={"csrf_token": "x", "value": "off"}).status_code == 403


def test_none_mode_local_principal_is_admin(db):
    c = TestClient(create_app(db, settings=Settings(_env_file=None)), base_url=HOST)  # type: ignore[call-arg]
    assert c.app.state.signing.generated is True  # dev: random per-process key
    page = c.get("/settings").text
    assert "csrf_token" in page and "Read-only." not in page and "random one is used" in page
    r = post(c, "/settings/features/source_sonar", {}, data={"csrf_token": token(page, "/settings/features/source_sonar"), "value": "off"}, follow_redirects=False)
    assert r.status_code == 303 and flags(db)["source_sonar"] is False
    with session_scope(db) as s:
        assert F.audit_entries(s)[0].actor_display_name == "Local developer"


# ------------------------------------------------------------------ CSRF
def good_form(c, key="migration", h=None, value="off"):
    h = h or admin()
    return h, {"csrf_token": token(c.get("/settings", headers=h).text, f"/settings/features/{key}"), "value": value}


@pytest.mark.parametrize("bad", ["missing", "garbage", "tampered", "empty"])
def test_missing_or_bad_token_is_403(db, bad):
    c = client(db)
    h, form = good_form(c)
    form["csrf_token"] = {"garbage": "not-a-token", "tampered": form["csrf_token"][:-1] + ("0" if form["csrf_token"][-1] != "0" else "1"), "empty": ""}.get(bad, "")
    if bad == "missing":
        form.pop("csrf_token")
    r = post(c, "/settings/features/migration", h, data=form)
    assert r.status_code == 403 and "expired or is invalid" in r.text and flags(db)["migration"] is True


def test_expired_token_is_403(db):
    c = client(db)
    old = csrf.make_token(KEY.encode(), "oid-admin", "set:migration", now=time.time() - csrf.TOKEN_TTL_SECONDS - 5)
    assert post(c, "/settings/features/migration", admin(), data={"csrf_token": old, "value": "off"}).status_code == 403
    fresh = csrf.make_token(KEY.encode(), "oid-admin", "set:migration", now=time.time() - csrf.TOKEN_TTL_SECONDS + 60)
    assert post(c, "/settings/features/migration", admin(), data={"csrf_token": fresh, "value": "off"}, follow_redirects=False).status_code == 303


def test_token_of_another_principal_or_action_or_key_is_403(db):
    c = client(db)
    mine = token(c.get("/settings", headers=admin()).text, "/settings/features/migration")
    other = admin(oid="oid-other", name="Grace")
    assert post(c, "/settings/features/migration", other, data={"csrf_token": mine, "value": "off"}).status_code == 403  # bound to the principal
    page = c.get("/settings", headers=admin()).text
    other_key = token(page, "/settings/features/gha_scanning")
    assert post(c, "/settings/features/migration", admin(), data={"csrf_token": other_key, "value": "off"}).status_code == 403  # bound to the key
    # a set-token is no reset-token (and vice versa)
    flip(c)  # now migration is overridden, so a reset form exists
    page = c.get("/settings", headers=admin()).text
    set_tok, reset_tok = token(page, "/settings/features/migration"), token(page, "/settings/features/migration/reset")
    assert post(c, "/settings/features/migration/reset", admin(), data={"csrf_token": set_tok}).status_code == 403
    assert post(c, "/settings/features/migration", admin(), data={"csrf_token": reset_tok, "value": "on"}).status_code == 403
    assert flags(db)["migration"] is False and audit_count(db) == 1


@pytest.mark.parametrize("origin,site,ok", [
    (HOST, None, True), ("https://evil.example", None, False), ("http://localhost.evil.example", None, False), ("null", None, False), (None, None, False),
    (HOST, "cross-site", False), (HOST, "same-site", False), (HOST, "same-origin", True), (HOST, "none", True), ("http://user@localhost", None, False)])
def test_origin_and_fetch_metadata(db, origin, site, ok):
    c = client(db)
    h, form = good_form(c)
    r = post(c, "/settings/features/migration", h, data=form, origin=origin, extra={"Sec-Fetch-Site": site} if site else None, follow_redirects=False)
    assert r.status_code == (303 if ok else 403), (origin, site)
    assert flags(db)["migration"] is (not ok)
    if not ok:
        assert "did not come from this site" in r.text


def test_referer_is_the_fallback_but_origin_wins(db):
    c = client(db)
    h, form = good_form(c)
    assert post(c, "/settings/features/migration", h, data=form, origin=None, extra={"Referer": f"{HOST}/settings"}, follow_redirects=False).status_code == 303
    h, form = good_form(c, value="on")
    assert post(c, "/settings/features/migration", h, data=form, origin="https://evil.example", extra={"Referer": f"{HOST}/settings"}).status_code == 403
    assert post(c, "/settings/features/migration", h, data=form, origin=None, extra={"Referer": "https://evil.example/settings"}).status_code == 403


def test_csrf_failures_write_nothing_and_do_not_leak_the_key(db):
    c = client(db)
    r = post(c, "/settings/features/migration", admin(), data={"csrf_token": "x", "value": "off"})
    assert r.status_code == 403 and KEY not in r.text and audit_count(db) == 0


# ------------------------------------------------------------------ input validation and the method guard
@pytest.mark.parametrize("value", ["ON", "true", "1", "", "on ", "off\n", "maybe"])
def test_value_must_be_exactly_on_or_off(db, value):
    c = client(db)
    h, form = good_form(c)
    form["value"] = value
    assert post(c, "/settings/features/migration", h, data=form).status_code == 400
    assert flags(db)["migration"] is True


def test_missing_value_repeated_fields_wrong_content_type_and_oversize_are_400(db):
    c = client(db)
    h, form = good_form(c)
    assert post(c, "/settings/features/migration", h, data={"csrf_token": form["csrf_token"]}).status_code == 400
    r = post(c, "/settings/features/migration", {**h, "Content-Type": "application/x-www-form-urlencoded"}, content=f"csrf_token={form['csrf_token']}&value=on&value=off")
    assert r.status_code == 400
    r = post(c, "/settings/features/migration", {**h, "Content-Type": "application/json"}, content='{"value": "off"}')
    assert r.status_code == 400
    r = post(c, "/settings/features/migration", {**h, "Content-Type": "application/x-www-form-urlencoded"}, content="value=on&pad=" + "a" * 5000)
    assert r.status_code == 400
    assert flags(db)["migration"] is True and audit_count(db) == 0


def test_unknown_feature_key_is_404(db):
    c = client(db)
    assert post(c, "/settings/features/nope", admin(), data={"csrf_token": "x", "value": "off"}).status_code == 404
    assert post(c, "/settings/features/nope/reset", admin(), data={"csrf_token": "x"}).status_code == 404
    assert post(c, "/settings/features/Migration", admin(), data={"value": "off"}).status_code == 405  # not even a key-shaped path


@pytest.mark.parametrize("method", ["put", "delete", "patch", "options"])
@pytest.mark.parametrize("path", ["/settings/features/migration", "/settings/features/migration/reset", "/settings"])
def test_method_guard_still_blocks_everything_but_the_two_posts(db, method, path):
    c = client(db)
    r = getattr(c, method)(path, headers={**admin(), "Origin": HOST})
    assert r.status_code == 405 and r.headers["allow"] == "GET, HEAD"


@pytest.mark.parametrize("path", ["/settings", "/", "/repos", "/api/v1/repos", "/settings/features", "/settings/features/migration/other", "/settings/features/migration/reset/x",
                                 "/settings/features/mig ration", "/settings/features/../repos", "/nope"])
def test_post_to_any_other_path_is_405(db, path):
    c = client(db)
    r = post(c, path, admin(), data={"value": "off"})
    assert r.status_code == 405 and r.headers["allow"] == "GET, HEAD"


def test_get_on_a_write_route_is_405_never_a_write(db):
    c = client(db)
    assert c.get("/settings/features/migration?value=off", headers=admin()).status_code == 405
    assert flags(db)["migration"] is True


def test_response_headers_on_the_redirect(db):
    r = flip(client(db))
    assert r.status_code == 303 and r.headers["cache-control"] == "no-store" and r.headers["referrer-policy"] == "same-origin" and "form-action 'self'" in r.headers["content-security-policy"]


# ------------------------------------------------------------------ fail closed: prod without a key, provider problems, short keys
def prod(db, **kw) -> TestClient:
    s = S(app_env="prod", allowed_hosts="app.example.com", website_auth_enabled="True", auth_easyauth_assume_enabled=False, **kw)
    return TestClient(create_app(db, settings=s), base_url="https://app.example.com")


def test_prod_without_a_signing_key_is_read_only_with_a_clear_message(db):
    c = prod(db, settings_signing_key="")
    assert c.app.state.signing.key is None
    page = c.get("/settings", headers=admin()).text
    assert "Read-only." in page and "no signing key is configured" in page and "csrf_token" not in page
    r = post(c, "/settings/features/migration", admin(), data={"csrf_token": "x", "value": "off"}, origin="https://app.example.com")
    assert r.status_code == 403 and "disabled on this deployment" in r.text
    assert audit_count(db) == 0


def test_prod_with_a_key_can_write(db):
    c = prod(db)
    page = c.get("/settings", headers=admin()).text
    assert "csrf_token" in page and "random one is used" not in page
    r = post(c, "/settings/features/gha_scanning", admin(), data={"csrf_token": token(page, "/settings/features/gha_scanning"), "value": "off"}, origin="https://app.example.com", follow_redirects=False)
    assert r.status_code == 303 and flags(db)["gha_scanning"] is False


def test_short_key_counts_as_unset(db):
    assert prod(db, settings_signing_key="short").app.state.signing.key is None
    dev = client(db, settings_signing_key="short")
    assert dev.app.state.signing.generated is True and dev.app.state.signing.key != b"short"


def test_guard_warnings_say_why_the_page_is_read_only():
    w = guard_warnings(S(app_env="prod", allowed_hosts="a.example.com", website_auth_enabled="True", settings_signing_key="", auth_admin_roles=""))
    assert any("AUTH_ADMIN_ROLES is empty" in x for x in w) and any("Settings writes are disabled" in x and "SETTINGS_SIGNING_KEY" in x for x in w)
    assert guard_warnings(S(app_env="prod", allowed_hosts="a.example.com", website_auth_enabled="True")) == []
    assert any("ignored with AUTH_MODE=none" in x for x in guard_warnings(Settings(_env_file=None, auth_admin_roles=ADMIN)))  # type: ignore[call-arg]
    assert guard_warnings(Settings(_env_file=None)) == []  # type: ignore[call-arg]


def test_doctor_warns_when_settings_are_read_only(monkeypatch):
    from pch.doctor import check_settings_writes

    c = check_settings_writes(S(app_env="prod", allowed_hosts="a.example.com", website_auth_enabled="True", settings_signing_key="", auth_admin_roles=""))
    assert c.status == "WARN" and "read-only" in c.detail and "Settings writes are disabled" in c.detail
    ok = check_settings_writes(S(app_env="prod", allowed_hosts="a.example.com", website_auth_enabled="True"))
    assert ok.status == "OK" and ADMIN in ok.detail and KEY not in ok.detail


def test_signing_key_comes_from_the_secret_provider_and_is_redacted(tmp_path):
    d = tmp_path / "sec"
    d.mkdir()
    secret = "file-provider-signing-key-0123456789abcdef"
    (d / "SETTINGS_SIGNING_KEY").write_text(secret + "\n")
    s = Settings(_env_file=None, app_env="dev", secrets_provider="file", secrets_dir=d, settings_signing_key="env-value-must-be-ignored-" + "x" * 20)  # type: ignore[call-arg]
    sk = csrf.resolve_signing_key(s)
    assert sk.key == secret.encode() and not sk.generated  # the selected provider only: no silent fallback to the env value
    assert scrub(f"leaked {secret} here") == "leaked ***REDACTED*** here"
    empty = tmp_path / "empty"
    empty.mkdir()
    s2 = Settings(_env_file=None, app_env="prod", allowed_hosts="a.example.com", secrets_provider="file", secrets_dir=empty, settings_signing_key=KEY)  # type: ignore[call-arg]
    assert csrf.resolve_signing_key(s2).key is None  # prod + provider has no key: disabled, not the env value


def test_env_signing_key_is_registered_for_redaction(monkeypatch):
    from pch.logging_setup import clear_registered_secrets

    clear_registered_secrets()
    secret = "env-signing-key-value-0123456789abcdefgh"
    assert csrf.resolve_signing_key(Settings(_env_file=None, settings_signing_key=secret)).key == secret.encode()  # type: ignore[call-arg]
    assert secret not in scrub(f"x {secret} y")


# ------------------------------------------------------------------ tokens and origin checks, unit level
def test_token_roundtrip_and_binding():
    k = b"k" * 32
    t = csrf.make_token(k, "p1", "set:migration", now=1000)
    assert csrf.verify_token(k, "p1", "set:migration", t, now=1000)
    assert not csrf.verify_token(k, "p2", "set:migration", t, now=1000)
    assert not csrf.verify_token(k, "p1", "set:gha_scanning", t, now=1000)
    assert not csrf.verify_token(k, "p1", "reset:migration", t, now=1000)
    assert not csrf.verify_token(b"j" * 32, "p1", "set:migration", t, now=1000)
    exp = 1000 + csrf.TOKEN_TTL_SECONDS
    assert csrf.verify_token(k, "p1", "set:migration", t, now=exp) and not csrf.verify_token(k, "p1", "set:migration", t, now=exp + 1)
    e, _, mac = t.partition(".")
    assert not csrf.verify_token(k, "p1", "set:migration", f"{int(e) + 10_000}.{mac}", now=1000)  # the expiry is covered by the MAC
    assert not csrf.verify_token(k, "p1", "set:migration", f"{int(e) - 1}.{mac}", now=1000)


@pytest.mark.parametrize("tok", [None, "", ".", "a.b", "1.", ".abc", "x" * 500, "٣.abc", "-5.abc", "9" * 40 + ".abc", "12.34.56", "1e3.abc", " 5.abc"])
def test_garbage_tokens_are_false_never_errors(tok):
    assert csrf.verify_token(b"k" * 32, "p", "a", tok, now=1) is False


def test_ids_with_separators_cannot_collide():
    k = b"k" * 32
    a = csrf.make_token(k, 'x","y', "z", now=5)
    assert not csrf.verify_token(k, "x", 'y","z', a, now=5)
    assert not csrf.verify_token(k, "x\x00y", "z", csrf.make_token(k, "x", "y\x00z", now=5), now=5)


@pytest.mark.parametrize("hdrs,problem", [
    ({"host": "a.example", "origin": "https://a.example"}, False), ({"host": "a.example:8443", "origin": "https://a.example:8443"}, False),
    ({"host": "a.example", "origin": "https://b.example"}, True), ({"host": "a.example", "origin": "null"}, True), ({"host": "a.example"}, True), ({"origin": "https://a.example"}, True),
    ({"host": "a.example", "referer": "https://a.example/settings"}, False), ({"host": "a.example", "referer": "https://b.example/"}, True),
    ({"host": "a.example", "origin": "https://b.example", "referer": "https://a.example/"}, True), ({"host": "a.example", "origin": "ftp://a.example"}, True),
    ({"host": "A.Example", "origin": "https://a.EXAMPLE"}, False), ({"host": "a.example", "origin": "https://a.example", "sec-fetch-site": "cross-site"}, True),
    ({"host": "a.example", "origin": "https://a.example", "sec-fetch-site": "same-origin"}, False)])
def test_same_origin_problem(hdrs, problem):
    assert (csrf.same_origin_problem(hdrs) is not None) is problem


# ------------------------------------------------------------------ audit, reset, escaping
def test_reset_to_default_and_noop(db):
    c = client(db)
    assert flip(c).status_code == 303
    page = c.get("/settings", headers=admin()).text
    r = post(c, "/settings/features/migration/reset", admin(), data={"csrf_token": token(page, "/settings/features/migration/reset")}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/settings?flash=reset&k=migration" and flags(db)["migration"] is True
    page = c.get(r.headers["location"], headers=admin()).text
    assert "Reset: Azure DevOps to GitHub Actions migration is back to the default (on)." in page and "default from features.yaml" in page and "Reset to default" not in page
    with session_scope(db) as s:
        assert [(a.old_value, a.new_value) for a in reversed(F.audit_entries(s))] == [("default", "off"), ("off", "default")]
    assert flip(c).status_code == 303 and audit_count(db) == 3
    r = flip(c)  # a stale form asks for what is already stored: nothing is written, no audit row
    assert r.headers["location"] == "/settings?flash=nochange&k=migration" and audit_count(db) == 3


def test_page_shows_only_the_last_20_audit_entries_newest_first(db):
    with session_scope(db) as s:
        for i in range(25):
            F.set_override(s, "source_aikido", bool(i % 2), F.Actor("o", f"User {i}"), "ui")
    page = client(db).get("/settings", headers=admin()).text
    assert page.count("data-audit=") == 20 and "User 24" in page and "User 5" in page and "User 4<" not in page
    assert page.index("User 24") < page.index("User 23")


def test_actor_names_are_escaped_and_email_names_are_not_shown_or_stored(db):
    c = client(db)
    evil = "<img src=x onerror=alert(1)>"
    assert flip(c, h=admin(name=evil)).status_code == 303
    page = c.get("/settings", headers=admin()).text
    assert evil not in page and "&lt;img src=x onerror=alert(1)&gt;" in page
    assert flip(c, key="source_sonar", h=admin(name="ada@example.com")).status_code == 303
    page = c.get("/settings", headers=admin()).text
    assert "ada@example.com" not in page and "unnamed user" in page and "changed by an administrator at" in page
    with session_scope(db) as s:
        assert all("@" not in a.actor_display_name for a in F.audit_entries(s))


def test_flash_parameters_are_never_reflected(db):
    c = client(db)
    page = c.get("/settings?flash=<script>alert(1)</script>&k=<b>x</b>", headers=admin()).text
    assert "<script>alert" not in page and 'id="flash"' not in page
    assert 'id="flash"' not in c.get("/settings?flash=saved&k=nope", headers=admin()).text
    assert 'id="flash"' in c.get("/settings?flash=saved&k=migration", headers=admin()).text


def test_features_yaml_defaults_are_shown_and_an_invalid_file_stops_the_app(db, tmp_path):
    (tmp_path / "features.yaml").write_text("source_aikido: false\n")
    c = client(db, config_dir=tmp_path)
    page = c.get("/settings", headers=admin()).text
    assert re.search(r'data-feature="source_aikido".*?data-role="state"[^>]*>(On|Off)<', page, re.S).group(1) == "Off"
    assert re.search(r'data-feature="source_sonar".*?data-role="state"[^>]*>(On|Off)<', page, re.S).group(1) == "On"
    assert "default from features.yaml" in page
    (tmp_path / "features.yaml").write_text("bogus: true\n")
    with pytest.raises(ConfigError):
        create_app(db, settings=S(config_dir=tmp_path))


def test_settings_page_lists_every_switch_with_its_timing_and_a_gear_nav_item(db):
    page = client(db).get("/settings", headers=admin()).text
    for f in F.FEATURES:
        assert f'data-feature="{f.key}"' in page and f.label in page
    assert page.count("takes effect immediately") == 1 and page.count("takes effect on the next scan") == 4
    assert re.search(r'href="/settings"[^>]*>⚙ Settings</a>\s*</nav>', page)
    assert page.index('href="/lineage') < page.index('href="/settings')  # last nav item


def test_pending_marker_when_a_scan_switch_differs_from_what_the_latest_scan_used(db):
    c = client(db)
    assert "data-role=\"pending\"" not in c.get("/settings", headers=admin()).text
    flip(c, key="source_sonar")
    page = c.get("/settings", headers=admin()).text
    assert page.count('data-role="pending"') == 1 and "the latest scan used on" in page
    flip(c, key="migration")  # a display switch is never "pending"
    assert c.get("/settings", headers=admin()).text.count('data-role="pending"') == 1


# ------------------------------------------------------------------ effects of the Migration switch (immediate, UI + API + exports)
def first_repo(c):
    r = c.get("/api/v1/repos", headers=admin()).json()["repos"][0]
    return r["project"], r["repo"]


def test_migration_switch_hides_it_everywhere_immediately_and_back(db):
    c = client(db)
    h = admin()
    project, repo = first_repo(c)
    on = {"overview": c.get("/", headers=h).text, "repos": c.get("/repos", headers=h).text, "repo": c.get(f"/repos/{project}/{repo}", headers=h).text, "nav": c.get("/rules", headers=h).text}
    assert 'id="migration-card"' in on["overview"] and 'data-col="migration_status"' in on["repos"] and "GitHub Actions readiness" in on["repo"] and 'href="/migration' in on["nav"]
    assert c.get("/migration", headers=h).status_code == 200 and c.get("/api/v1/migration", headers=h).status_code == 200
    assert "migration_score" in c.get("/repos.csv", headers=h).text.splitlines()[0]
    assert "migration_states" in c.get("/api/v1/overview", headers=h).json() and "migration_status" in c.get("/api/v1/repos", headers=h).json()["repos"][0]

    assert flip(c).status_code == 303  # takes effect on the very next request
    off = {"overview": c.get("/", headers=h).text, "repos": c.get("/repos", headers=h).text, "repo": c.get(f"/repos/{project}/{repo}", headers=h).text, "nav": c.get("/rules", headers=h).text}
    assert 'id="migration-card"' not in off["overview"] and "Migration to GitHub Actions" not in off["overview"]
    assert "migration_status" not in off["repos"] and 'name="migration"' not in off["repos"] and "Migration</th>" not in off["repos"]
    assert "GitHub Actions readiness" not in off["repo"] and "candidate to retire" not in off["repo"]
    assert 'href="/migration' not in off["nav"] and "Migration</a>" not in off["nav"] and "⚙ Settings" in off["nav"]
    for path in ("/migration", "/migration?state=migrated", "/api/v1/migration", "/api/v1/migration?state=in_progress"):
        r = c.get(path, headers=h)
        assert r.status_code == 404, path
    assert c.get("/migration", headers=h).headers["content-type"].startswith("text/html") and "Not found" in c.get("/migration", headers=h).text
    assert c.get("/api/v1/migration", headers=h).json()["detail"] == "not found"
    assert "migration" not in c.get("/repos.csv", headers=h).text.splitlines()[0]
    ov, repos, one = c.get("/api/v1/overview", headers=h).json(), c.get("/api/v1/repos", headers=h).json(), c.get(f"/api/v1/repos/{project}/{repo}", headers=h).json()

    def keys(o):
        return {k for k in (o if isinstance(o, dict) else {}) } | {kk for v in (o.values() if isinstance(o, dict) else o if isinstance(o, list) else []) for kk in keys(v)}

    for body in (ov, repos, one):
        assert not [k for k in keys(body) if "migration" in k or k in ("retire_reason", "no_pipeline_repos")], keys(body)
    # filters / sorts on migration are ignored (never an error, never a leak)
    assert c.get("/repos?migration=ado_only&sort=migration_score", headers=h).status_code == 200
    assert len(c.get("/api/v1/repos?migration=migrated", headers=h).json()["repos"]) == len(repos["repos"])
    assert c.get("/api/v1/repos?sort=migration_status", headers=h).status_code == 200

    assert "Reset to default" in c.get("/settings", headers=h).text
    assert flip(c, value="on").status_code == 303 and 'id="migration-card"' in c.get("/", headers=h).text and c.get("/migration", headers=h).status_code == 200


def test_migration_off_from_features_yaml_is_the_default_until_overridden(db, tmp_path):
    (tmp_path / "features.yaml").write_text("migration: false\n")
    c = client(db, config_dir=tmp_path)
    assert c.get("/migration", headers=admin()).status_code == 404
    assert flip(c, value="on").status_code == 303  # the UI override wins over the file
    assert c.get("/migration", headers=admin()).status_code == 200
    page = c.get("/settings", headers=admin()).text
    post(c, "/settings/features/migration/reset", admin(), data={"csrf_token": token(page, "/settings/features/migration/reset")})
    assert c.get("/migration", headers=admin()).status_code == 404  # reset: back to the file's false


def test_a_scan_made_with_migration_off_says_so_on_the_migration_page(tmp_path):
    url = f"sqlite:///{tmp_path}/nm.db"
    scan_into(url, "nm", features={**F.ALL_ON, "migration": False})
    c = TestClient(create_app(url, settings=S()), base_url=HOST)
    r = c.get("/settings", headers=admin())
    assert r.status_code == 200
    # the display switch is on now, the scan did not compute readiness: the page explains it instead of showing silent n/a
    assert "This scan was made while the Migration switch was off" in c.get("/migration", headers=admin()).text


# ------------------------------------------------------------------ rules turned off by a scan switch: shown from the scan's own snapshot
def test_rules_off_by_settings_come_from_the_scans_snapshot_not_the_current_value(tmp_path):
    url = f"sqlite:///{tmp_path}/snap.db"
    scan_into(url, "old-off", features={**F.ALL_ON, "source_aikido": False}, when=datetime(2026, 9, 1, 12, 0, 0))
    scan_into(url, "new-on", when=datetime(2026, 10, 1, 12, 0, 0))
    c = TestClient(create_app(url, settings=S()), base_url=HOST)
    h = admin()
    newest, oldest = c.get("/rules", headers=h).text, c.get("/rules?scan=old-off", headers=h).text
    assert "off (Settings)" not in newest and oldest.count("off (Settings)") == 2  # QLT-006, QLT-007
    assert "off (Settings)" in c.get("/rules/QLT-006?scan=old-off", headers=h).text and "off (Settings)" not in c.get("/rules/QLT-006", headers=h).text
    api = {r["id"]: r for r in c.get("/api/v1/rules?scan=old-off", headers=h).json()["rules"]}
    assert api["QLT-006"]["off_by_settings"] == ["Aikido"] and api["QLT-007"]["off_by_settings"] == ["Aikido"] and api["QLT-001"]["off_by_settings"] == []
    assert api["QLT-006"]["applicable"] == 0
    # switching Aikido off NOW changes nothing about the old scan's view nor the new scan's (the switch applies from the next scan)
    flip(c, key="source_aikido")
    assert "off (Settings)" not in c.get("/rules", headers=h).text and c.get("/rules?scan=old-off", headers=h).text.count("off (Settings)") == 2
    # and flipping it back on does not resurrect verdicts that were never evaluated
    flip(c, key="source_aikido", value="on")
    assert c.get("/rules?scan=old-off", headers=h).text.count("off (Settings)") == 2


def test_scans_without_a_features_snapshot_are_treated_as_everything_on(tmp_path):
    url = f"sqlite:///{tmp_path}/legacy.db"
    scan_into(url, "legacy", features={**F.ALL_ON, "source_sonar": False})
    with session_scope(url) as s:
        row = store.get_scan(s, "legacy")
        row.summary = {k: v for k, v in row.summary.items() if k != "features"}  # a scan from before the switches existed
        s.add(row)
    c = TestClient(create_app(url, settings=S()), base_url=HOST)
    assert "off (Settings)" not in c.get("/rules", headers=admin()).text
    with session_scope(url) as s:
        from pch.web import queries as Q

        assert Q.scan_features(s, "legacy") == F.ALL_ON
        assert isinstance(s.get(ScanRow, "legacy").summary, dict)


# ------------------------------------------------------------------ hygiene
def test_settings_template_has_no_inline_script_style_or_handlers():
    t = (Path(__file__).parent.parent / "src" / "pch" / "web" / "templates" / "settings.html").read_text()
    assert not re.search(r"<script|<style|\sstyle\s*=|\son[a-z]+\s*=|javascript:", t, re.I) and "|safe" not in t


def test_every_post_form_in_templates_is_a_settings_form_with_a_token():
    root = Path(__file__).parent.parent / "src" / "pch" / "web" / "templates"
    for f in root.glob("*.html"):
        for m in re.finditer(r'<form[^>]*method="post"[^>]*>(.*?)</form>', f.read_text(), re.S | re.I):
            assert f.name == "settings.html" and 'name="csrf_token"' in m.group(1), f.name
