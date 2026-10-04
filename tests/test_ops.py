"""T6 operability: redacting structured logging, request ids, health, retention, shutdown, telemetry, doctor."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import signal
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from typer.testing import CliRunner

from pch import doctor, exitcodes, retention, telemetry
from pch.cli import app as cli
from pch.logging_setup import (
    JsonFormatter,
    RedactingFilter,
    configure_logging,
    effective_format,
    register_secret,
    request_id_var,
    scrub,
)
from pch.orchestrator import ScanConfig, Scanner
from pch.providers import FileSecretProvider
from pch.providers.errors import ProviderUnavailable
from pch.providers.secrets import EnvSecretProvider
from pch.scanrun import ScanInterrupted, ScanTimeout, run_guarded
from pch.settings import Policy, Scope, Settings
from pch.store import locks
from pch.store import repository as store
from pch.store.db import get_engine, session_scope
from pch.store.models import CollectionErrorRow, FindingRow, RepoResultRow
from pch.timeutil import utcnow
from pch.web.app import create_app
from pch.web.health import ReadinessProbe
from tests.builders import ALL_HOSTS

ENV_KEYS = ("APP_ENV", "AUTH_MODE", "AUTH_ALLOWED_ROLES", "WEBSITE_AUTH_ENABLED", "AUTH_EASYAUTH_ASSUME_ENABLED", "ALLOWED_HOSTS", "HOST", "PORT",
            "WEBSITES_PORT", "DATABASE_URL", "LOG_FORMAT", "LOG_LEVEL", "APPLICATIONINSIGHTS_CONNECTION_STRING", "RETENTION_KEEP_SCANS",
            "RETENTION_MAX_AGE_DAYS", "SCAN_TIMEOUT_MINUTES", "SECRETS_PROVIDER", "ARTIFACT_STORE", "ADO_ORG", "ADO_PAT")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    from pch.settings import reset_settings

    reset_settings()
    yield
    reset_settings()


def S(**kw) -> Settings:
    return Settings(_env_file=None, **kw)  # type: ignore[call-arg]


def capture(**kw) -> tuple[io.StringIO, logging.Logger]:
    buf = io.StringIO()
    configure_logging(S(**{"log_format": "json", **kw}), stream=buf)
    return buf, logging.getLogger("pch.test")


def lines(buf: io.StringIO) -> list[dict]:
    return [json.loads(x) for x in buf.getvalue().splitlines() if x.strip()]


# ------------------------------------------------------------------ scrubbing
SECRETS = [
    ("Authorization: Bearer " + "abc" + "DEF123456789" + ".xyz-TOKEN", "abc" + "DEF123456789"),
    ("headers={'Authorization': 'Basic dXNlcjpwYXNzd29yZA=='}", "dXNlcjpwYXNzd29yZA"),
    ("got Bearer " + ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "sig_abc-123"]), "eyJhbGciOiJIUzI1NiJ9"),
    ("connect pat=hunter2hunter2 failed", "hunter2hunter2"),
    ("ADO_PAT=hunter2hunter2", "hunter2hunter2"),
    ("config token: s3cr3t-value-123", "s3cr3t-value-123"),
    ('{"password": "correct horse battery", "ok": 1}', "correct horse battery"),
    ("Server=x;Password=Sup3rSecret!;User=a", "Sup3rSecret"),
    ("client_secret=abc123abc123 api_key=k-12345678", "abc123abc123"),
    ("postgresql+psycopg://svc:p%40ss-word@db.example.com:5432/pch", "p%40ss-word"),
    ("mssql+pyodbc://svc:Pa55w0rd!@srv.database.windows.net/db", "Pa55w0rd"),
    ("https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/o/r", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
    ("GET https://x.example/a?sig=AbCdEf123456&sv=1 200", "AbCdEf123456"),
    ("leaked github_pat_11ABCDEFG0abcdefghijklmnopqrstu in text", "github_pat_11ABCDEFG0abcdefghijklmnopqrstu"),
    ("blob key QWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OTBhYmNkZWY= end", "QWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OTBhYmNkZWY"),
]


@pytest.mark.parametrize("text,secret", SECRETS)
def test_scrub_patterns(text, secret):
    out = scrub(text)
    assert secret not in out and out != text
    assert scrub(out) == out  # idempotent


def test_scrub_keeps_ordinary_text():
    for t in ("path=/repos/Proj/Repo status=200", "HTTP 500 for https://dev.azure.com/Payments/_apis/build/definitions/711?api-version=7.1", "scan 20260101-120000-demo complete: 280 repos", "basic information about the sources",
              "request_id=3f2a9c1e5b7d4f60a1b2c3d4e5f60718 GET /api/v1/repos 200 12.3ms", "migration head 0002_scan_locks"):
        assert scrub(t) == t


def test_exact_registered_secrets_are_scrubbed_in_any_shape():
    register_secret("opaque value@XYZ!0001")
    register_secret("short")  # below MIN_SECRET_LEN: ignored, would shred normal text
    assert "opaque" not in scrub("the value was opaque value@XYZ!0001!")
    assert "opaque" not in scrub("encoded opaque%20value%40XYZ%210001")  # url-encoded form
    assert "opaque" not in scrub("form opaque+value%40XYZ%210001")
    assert scrub("a short word") == "a short word"


def test_secret_providers_register_resolved_values(tmp_path):
    (tmp_path / "ADO_PAT").write_text("file-secret-value-777\n")
    assert FileSecretProvider(tmp_path).get("ADO_PAT") == "file-secret-value-777"
    assert "file-secret-value-777" not in scrub("oops file-secret-value-777")
    EnvSecretProvider(S(sonar_token="env-secret-value-888")).get("SONAR_TOKEN")
    assert "env-secret-value-888" not in scrub("oops env-secret-value-888")


def test_settings_secrets_registered_by_configure(monkeypatch):
    configure_logging(S(ado_pat="settings-pat-value-1", database_url="postgresql+psycopg://u:dbpass-value-2@h/d"), stream=io.StringIO())
    out = scrub("x settings-pat-value-1 y dbpass-value-2")
    assert "settings-pat-value-1" not in out and "dbpass-value-2" not in out


def test_filter_scrubs_message_args_exception_and_url():
    buf, log = capture()
    log.warning("calling %s with %s", "https://user:pw12345@host/x?token=AAAA1111", {"password": "hunter2hunter2"})
    try:
        raise RuntimeError("connect to postgresql://svc:dbsecret99@db/x failed, Authorization: Bearer zzzTOKEN123456")
    except RuntimeError:
        log.exception("boom pat=leakyleakyleaky")
    out = buf.getvalue()
    for leak in ("pw12345", "AAAA1111", "hunter2hunter2", "dbsecret99", "zzzTOKEN123456", "leakyleakyleaky"):
        assert leak not in out
    rec = lines(buf)
    assert rec[1]["level"] == "ERROR" and "RuntimeError" in rec[1]["exception"] and "Traceback" in rec[1]["exception"]


def test_filter_survives_bad_format_args():
    buf, log = capture()
    rec = logging.LogRecord("x", logging.WARNING, __file__, 1, "100% broken %s %s pat=abcdef123456", ("only-one",), None)
    assert RedactingFilter().filter(rec)  # logging would normally raise/print a --- Logging error ---
    assert rec.msg.startswith("100% broken") and "abcdef123456" not in rec.msg


def test_json_format_is_valid_with_context():
    buf, log = capture()
    from pch.logging_setup import bind_scan

    token = request_id_var.set("req-abcdef123456")
    try:
        with bind_scan("scan-1"):
            log.info("hello %s", "world", extra={"pch_fields": {"status": 200, "note": "token=abc123abc123"}})
    finally:
        request_id_var.reset(token)
    log.info("outside")
    first, second = lines(buf)
    assert first["message"] == "hello world" and first["level"] == "INFO" and first["logger"] == "pch.test"
    assert first["request_id"] == "req-abcdef123456" and first["scan_id"] == "scan-1" and first["status"] == 200
    assert "abc123abc123" not in first["note"]
    assert first["ts"].endswith("Z") and "T" in first["ts"]
    assert "request_id" not in second and "scan_id" not in second


def test_format_and_level_defaults():
    assert effective_format(S()) == "text" and effective_format(S(app_env="test")) == "text"
    prod = S(app_env="prod", auth_mode="easyauth", allowed_hosts="a.net")
    assert effective_format(prod) == "json" and effective_format(S(app_env="prod", log_format="text")) == "text"
    assert S(log_level="debug").log_level == "DEBUG" and S(log_format="JSON").log_format == "json"
    with pytest.raises(ValueError):
        S(log_level="LOUD")


def test_text_format_has_context_and_redaction():
    buf = io.StringIO()
    configure_logging(S(log_format="text"), stream=buf)
    token = request_id_var.set("req-abcdef123456")
    try:
        logging.getLogger("pch.test").error("token=" + "abcdefgh12345678")
    finally:
        request_id_var.reset(token)
    out = buf.getvalue()
    assert "ERROR" in out and "req=req-abcdef123456" in out and "abcdefgh12345678" not in out


def test_uvicorn_loggers_go_through_the_redacting_handler():
    buf, _ = capture()
    logging.getLogger("uvicorn.access").info('%s - "%s %s HTTP/%s" %d', "1.2.3.4", "GET", "/x?access_token=tok12345678", "1.1", 200)
    assert "tok12345678" not in buf.getvalue() and "uvicorn.access" in buf.getvalue()


def test_configure_is_idempotent():
    buf, log = capture()
    configure_logging(S(log_format="json"), stream=buf)
    log.info("once")
    assert len(lines(buf)) == 1


def test_json_formatter_alone_still_scrubs():
    rec = logging.LogRecord("x", logging.ERROR, __file__, 1, "pat=%s", ("abcdef123456",), None)
    assert "abcdef123456" not in JsonFormatter().format(rec)
    f = RedactingFilter()
    assert f.filter(rec) and rec.args == ()


# ------------------------------------------------------------------ web: request id, access log, health
@pytest.fixture
def db_url(tmp_path):
    url = f"sqlite:///{tmp_path}/ops.db"
    get_engine(url)
    return url


def test_request_id_propagates_and_request_line_is_clean(db_url):
    buf = io.StringIO()
    configure_logging(S(log_format="json"), stream=buf)
    web = create_app(db_url, settings=S())

    @web.get("/_ctx")
    def ctx():  # sync handler runs in a worker thread: the contextvar must follow
        logging.getLogger("pch.ctx").info("inside handler")
        return {}

    c = TestClient(web, base_url="http://localhost")
    r = c.get("/_ctx?token=supersecret123&x=1", headers={"X-Request-ID": "client-req-0001"})
    assert r.headers["x-request-id"] == "client-req-0001"
    inner = next(x for x in lines(buf) if x["logger"] == "pch.ctx")
    access = next(x for x in lines(buf) if x["logger"] == "pch.web.access")
    assert inner["request_id"] == access["request_id"] == "client-req-0001"
    assert access["method"] == "GET" and access["path"] == "/_ctx" and access["status"] == 200 and access["duration_ms"] >= 0
    assert "supersecret123" not in buf.getvalue() and "?" not in access["message"]
    assert access["principal"] != "-" and "Local developer" not in buf.getvalue() and "local-dev" not in buf.getvalue()
    assert request_id_var.get() is None  # reset after the request


@pytest.mark.parametrize("bad", ["short", "has space in it 1234", "x" * 65, "evil\tid-12345678", "a;b=c-12345678", "<script>12345678"])
def test_invalid_inbound_request_id_is_replaced(db_url, bad):
    c = TestClient(create_app(db_url, settings=S()), base_url="http://localhost")
    r = c.get("/api/v1/health", headers={"X-Request-ID": bad})
    rid = r.headers["x-request-id"]
    assert rid != bad and len(rid) == 32 and int(rid, 16) >= 0  # fresh uuid4 hex


def test_request_line_survives_unhandled_error_and_log_forging(db_url):
    buf = io.StringIO()
    configure_logging(S(log_format="json"), stream=buf)
    web = create_app(db_url, settings=S())

    @web.get("/_boom")
    def boom():
        raise RuntimeError("kaboom password=hunter2hunter2")

    c = TestClient(web, base_url="http://localhost", raise_server_exceptions=False)
    assert c.get("/_boom").status_code == 500
    c.get("/nope%0AFAKE%20LINE")
    out = lines(buf)
    acc = [x for x in out if x["logger"] == "pch.web.access"]
    assert acc[0]["status"] == 500
    assert all("\n" not in x["path"] for x in acc) and "hunter2hunter2" not in buf.getvalue()


def test_health_endpoints_ok_and_unauthenticated(db_url):
    easy = S(app_env="dev", auth_mode="easyauth", auth_allowed_roles="PCH.Reader", auth_easyauth_assume_enabled=True)
    c = TestClient(create_app(db_url, settings=easy), base_url="http://localhost")
    for path in ("/health/live", "/health/ready", "/api/v1/health"):
        r = c.get(path)  # no principal header at all
        assert r.status_code == 200 and r.json()["status"] == "ok", path
    assert c.get("/health/live").json() == {"status": "ok"} and c.get("/health/ready").json() == {"status": "ok"}
    assert c.get("/api/v1/repos").status_code == 401  # everything else still needs a principal
    for path in ("/health/live/", "/health/ready/x", "/health"):
        assert c.get(path).status_code in (401, 404, 307)


def test_health_loopback_host_like_api_health(db_url):
    easy = S(app_env="dev", auth_mode="easyauth", auth_allowed_roles="PCH.Reader", auth_easyauth_assume_enabled=True, allowed_hosts="app.example.net")
    c = TestClient(create_app(db_url, settings=easy), base_url="http://app.example.net")
    for path in ("/health/live", "/health/ready", "/api/v1/health"):
        assert c.get(path, headers={"Host": "127.0.0.1:8000"}).status_code == 200
        assert c.get(path, headers={"Host": "evil.example.org"}).status_code == 400
    assert c.get("/api/v1/repos", headers={"Host": "127.0.0.1:8000"}).status_code == 400


def test_ready_503_generic_when_db_unreachable_and_live_unaffected(db_url, monkeypatch):
    from pch.store import migrate

    def down(engine):
        raise OperationalError("SELECT 1", {}, Exception("could not connect to server at postgresql://u:topsecret@internal-host:5432"))

    c = TestClient(create_app(db_url, settings=S(health_ready_cache_seconds=0)), base_url="http://localhost")
    monkeypatch.setattr(migrate, "db_state", down)
    r = c.get("/health/ready")
    assert r.status_code == 503 and r.json() == {"status": "unavailable", "reason": "db_unreachable"}
    for leak in ("topsecret", "internal-host", "postgresql", "OperationalError", "sqlite"):
        assert leak not in r.text
    assert c.get("/health/live").status_code == 200 and c.get("/health/live").json() == {"status": "ok"}


def test_ready_503_when_schema_not_at_head(tmp_path):
    from sqlalchemy import create_engine, text

    url = f"sqlite:///{tmp_path}/old.db"
    get_engine(url)
    eng = create_engine(url)
    with eng.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num='0000_old'"))
    eng.dispose()
    from pch.store.db import reset_engines

    reset_engines()
    code = asyncio.run(ReadinessProbe(url, 2, 0).code())
    assert code == "schema_not_ready"


def test_app_starts_when_db_unreachable_at_startup(monkeypatch, db_url):
    import pch.web.app as webapp

    def refuse(url):
        raise OperationalError("x", {}, Exception("nope"))

    monkeypatch.setattr(webapp, "get_engine", refuse)
    c = TestClient(create_app(db_url, settings=S(health_ready_cache_seconds=0)), base_url="http://localhost")
    assert c.get("/health/live").status_code == 200


def test_readiness_probe_timeout_cache_and_single_flight():
    calls = []

    def hung(url):
        calls.append(url)
        time.sleep(0.6)
        return "ok", ""

    async def go():
        p = ReadinessProbe("sqlite://", 0.1, 5.0, check=hung)
        t0 = time.monotonic()
        first = await asyncio.gather(p.code(), p.code())  # two concurrent probes, one DB check
        took = time.monotonic() - t0
        again = await p.code()  # cached timeout result: no new check, no waiting
        return first, took, again

    first, took, again = asyncio.run(go())
    assert first == ["db_timeout", "db_timeout"] and again == "db_timeout" and len(calls) == 1 and took < 0.5


def test_readiness_probe_caches_success_then_refreshes():
    n = []

    def ok(url):
        n.append(1)
        return "ok", ""

    async def go():
        p = ReadinessProbe("x", 1, 0.05, check=ok)
        a, b = await p.code(), await p.code()
        await asyncio.sleep(0.08)
        return a, b, await p.code()

    assert asyncio.run(go()) == ("ok", "ok", "ok") and len(n) == 2


def test_lifespan_disposes_engine_on_shutdown(db_url, monkeypatch):
    import pch.web.app as webapp

    seen = []
    monkeypatch.setattr(webapp, "dispose_engine", lambda url: seen.append(url))
    with TestClient(create_app(db_url, settings=S()), base_url="http://localhost") as c:
        assert c.get("/health/live").status_code == 200
        assert seen == []
    assert seen == [db_url]


# ------------------------------------------------------------------ retention
def add_scan(url, sid, status, age_days, with_rows=False):
    with session_scope(url) as s:
        row = store.create_scan(s, sid, "live", utcnow() - timedelta(days=age_days, minutes=1))
        row.status = status
        if with_rows:
            s.add(RepoResultRow(scan_id=sid, repo_key=f"p/{sid}", project="p", repo=sid, status="PASS"))
            for i in range(5):
                s.add(FindingRow(scan_id=sid, repo_key=f"p/{sid}", rule_id=f"R-{i}", category="X", severity="low", status="FAIL"))
            s.add(CollectionErrorRow(scan_id=sid, source="ado", subject="s", message="m"))


def ids(url):
    with session_scope(url) as s:
        return {r.id for r in store.list_scans(s, 100)}


@pytest.fixture
def estate(tmp_path):
    url = f"sqlite:///{tmp_path}/pch.db"
    get_engine(url)
    add_scan(url, "s-new", "complete", 1, True)
    add_scan(url, "s-mid", "complete", 20, True)
    add_scan(url, "s-old", "complete", 60, True)
    add_scan(url, "s-older", "failed", 90)
    add_scan(url, "s-run-fresh", "running", 100)  # live scan (started recently per stale window): created with old date but see below
    return url


def plan(url, keep=None, days=None, stale=timedelta(hours=6)):
    with session_scope(url) as s:
        c, p = retention.plan_prune(s, keep, days, stale)
    return {x.scan_id for x in c}, set(p)


def test_plan_keep_and_age_semantics(tmp_path):
    url = f"sqlite:///{tmp_path}/p.db"
    get_engine(url)
    for sid, st, age in (("a", "complete", 1), ("b", "complete", 10), ("c", "complete", 40), ("d", "failed", 50), ("e", "complete", 80)):
        add_scan(url, sid, st, age)
    assert plan(url, keep=2)[0] == {"c", "d", "e"}
    assert plan(url, days=30)[0] == {"c", "d", "e"} and plan(url, days=45)[0] == {"d", "e"}
    assert plan(url, keep=4, days=30)[0] == {"e"}  # BOTH: outside newest 4 AND older than 30 days
    assert plan(url, keep=1, days=30)[0] == {"c", "d", "e"}
    with pytest.raises(ValueError):
        plan(url)


def test_latest_complete_and_live_running_are_never_candidates(tmp_path):
    url = f"sqlite:///{tmp_path}/p.db"
    get_engine(url)
    add_scan(url, "fail-newest", "failed", 0)
    add_scan(url, "latest-ok", "complete", 5)
    add_scan(url, "old-ok", "complete", 50)
    add_scan(url, "orphan", "running", 10)  # 10 days old running = stale orphan -> prunable
    cands, protected = plan(url, keep=1)
    assert "latest-ok" in protected and "latest-ok" not in cands and cands == {"old-ok", "orphan"}
    assert "latest-ok" not in plan(url, days=1)[0]  # even when it is "old": the latest complete scan always survives


def test_running_inside_stale_window_protected_even_when_old_enough(tmp_path):
    url = f"sqlite:///{tmp_path}/p.db"
    get_engine(url)
    add_scan(url, "ok", "complete", 1)
    add_scan(url, "slow", "running", 2)  # 2 days old: live when the stale window is 7 days
    c, p = plan(url, keep=1, stale=timedelta(days=7))
    assert c == set() and p == {"slow"}
    c, p = plan(url, keep=1, stale=timedelta(hours=6))
    assert c == {"slow"}


def run_prune(*args, env=None):
    from pch.settings import reset_settings

    reset_settings()
    return CliRunner().invoke(cli, ["scans", "prune", *args], env=env or {})


def test_cli_prune_dry_run_changes_nothing(estate, tmp_path):
    raw = tmp_path / "raw" / "s-old"
    raw.mkdir(parents=True)
    (raw / "x.json").write_text("{}")
    before = ids(estate)
    r = run_prune("--keep", "1", "--dry-run", "--data-dir", str(tmp_path), "--db", estate)
    assert r.exit_code == 0, r.output
    assert "would delete s-old" in r.output and "(dry run)" in r.output and "s-new" not in r.output.split("kept")[0]
    assert ids(estate) == before and (raw / "x.json").exists()


def test_cli_prune_deletes_rows_and_artifacts_but_not_latest(estate, tmp_path):
    for sid in ("s-old", "s-mid", "s-new"):
        d = tmp_path / "raw" / sid / "host"
        d.mkdir(parents=True)
        (d / "a.json").write_text("{}")
    r = run_prune("--keep", "1", "--data-dir", str(tmp_path), "--db", estate)
    assert r.exit_code == 0, r.output
    assert "deleted s-old" in r.output and "deleted s-mid" in r.output
    assert ids(estate) == {"s-new"} or ids(estate) == {"s-new", "s-run-fresh"}
    assert "s-new" in ids(estate)
    assert not (tmp_path / "raw" / "s-old").exists() and not (tmp_path / "raw" / "s-mid").exists()
    assert (tmp_path / "raw" / "s-new" / "host" / "a.json").exists()
    with session_scope(estate) as s:
        left = {m: s.scalar(select(func.count()).select_from(m).where(m.scan_id != "s-new")) for m in (FindingRow, RepoResultRow, CollectionErrorRow)}
    assert set(left.values()) == {0}  # no orphaned children
    assert run_prune("--keep", "1", "--data-dir", str(tmp_path), "--db", estate).exit_code == 0  # idempotent


def test_cli_prune_older_than_and_env_defaults(estate, tmp_path):
    r = run_prune("--data-dir", str(tmp_path), "--db", estate, env={"RETENTION_MAX_AGE_DAYS": "45", "RETENTION_KEEP_SCANS": "1"})
    assert r.exit_code == 0, r.output
    # keep newest 1 AND older than 45 days: s-old (60 d), s-older (90 d) and the stale `running` one go; s-mid (20 d) stays
    assert ids(estate) == {"s-new", "s-mid"}


def test_cli_prune_requires_a_criterion_and_validates(estate, tmp_path):
    r = run_prune("--data-dir", str(tmp_path), "--db", estate)
    assert r.exit_code == exitcodes.CONFIG and "Nothing to do" in r.output
    assert run_prune("--keep", "0", "--db", estate).exit_code != 0


def test_cli_prune_conflicts_with_scan_lock(estate, tmp_path):
    engine = get_engine(estate)
    holder = locks.acquire(engine)
    try:
        r = run_prune("--keep", "1", "--data-dir", str(tmp_path), "--db", estate)
        assert r.exit_code == exitcodes.LOCK_HELD and "scan is running" in r.output
        assert "s-old" in ids(estate)
        assert run_prune("--keep", "1", "--dry-run", "--data-dir", str(tmp_path), "--db", estate).exit_code == 0  # read-only
    finally:
        locks.release(engine, holder)
    assert run_prune("--keep", "1", "--data-dir", str(tmp_path), "--db", estate).exit_code == 0


def test_prune_reports_artifact_failures_and_continues(estate, tmp_path, monkeypatch):
    class Flaky:
        name = "flaky"

        async def list(self, prefix=""):
            return []

        async def delete_prefix(self, prefix):
            if prefix == "s-old/":
                raise OSError("denied")
            return 0

    with session_scope(estate) as s:
        c, p = retention.plan_prune(s, 1, None, timedelta(hours=6))
    rep = asyncio.run(retention.execute_prune(estate, Flaky(), c, p, dry_run=False))
    assert rep.errors == 1 and "s-old" in ids(estate)  # DB rows kept so the next prune retries
    assert "s-mid" not in ids(estate)


def test_delete_scan_rows_chunked(estate):
    with session_scope(estate) as s:
        for i in range(25):
            s.add(FindingRow(scan_id="s-mid", repo_key="p/x", rule_id=f"Z-{i}", category="X", severity="low", status="FAIL"))
    n = retention.delete_scan_rows(estate, "s-mid", chunk=7)
    assert n == 25 + 5 + 1 + 1 + 1  # findings + repo result + error + scan row
    assert "s-mid" not in ids(estate)


# ------------------------------------------------------------------ shutdown, timeout, signals
def make_cfg(url, **kw):
    return ScanConfig(scope=Scope(code_hosts=ALL_HOSTS, projects=[]), policy=Policy(), db_url=url, mode="demo", **kw)


def run_scan(url, scan_id, **kw):
    class Src:
        ado = None

        async def aclose(self):
            pass

    return asyncio.run(Scanner(Src(), make_cfg(url, **kw)).run(scan_id))  # type: ignore[arg-type]


def test_scan_timeout_marks_failed_with_reason_and_raises(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path}/t.db"
    get_engine(url)

    async def slow(self, scan_id):
        await asyncio.sleep(30)

    monkeypatch.setattr(Scanner, "_run", slow)
    t0 = time.monotonic()
    with pytest.raises(ScanTimeout):
        run_scan(url, "slow-1", timeout_s=0.1)
    assert time.monotonic() - t0 < 5
    with session_scope(url) as s:
        row = store.get_scan(s, "slow-1")
        assert row.status == "failed" and row.summary["error"].startswith("timeout")


def test_cancel_marks_failed_interrupted(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path}/t.db"
    get_engine(url)

    async def boom(self, scan_id):
        raise asyncio.CancelledError()

    monkeypatch.setattr(Scanner, "_run", boom)
    with pytest.raises(asyncio.CancelledError):
        run_scan(url, "cancel-1")
    with session_scope(url) as s:
        row = store.get_scan(s, "cancel-1")
        assert row.status == "failed" and row.summary["error"] == "interrupted"


def test_run_guarded_turns_sigterm_into_scan_interrupted():
    async def work():
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.sleep(30)

    t0 = time.monotonic()
    with pytest.raises(ScanInterrupted) as e:
        asyncio.run(run_guarded(work()))
    assert e.value.signame == "SIGTERM" and time.monotonic() - t0 < 5
    assert signal.getsignal(signal.SIGTERM) in (signal.SIG_DFL, signal.default_int_handler, None) or callable(signal.getsignal(signal.SIGTERM))


def test_run_guarded_plain_result_and_errors():
    async def ok():
        return 7

    async def bad():
        raise KeyError("x")

    assert asyncio.run(run_guarded(ok())) == 7
    with pytest.raises(KeyError):
        asyncio.run(run_guarded(bad()))


def test_cli_sigterm_during_scan_marks_failed_releases_lock_exit_5(tmp_path, monkeypatch):
    d = str(tmp_path / "data")
    assert CliRunner().invoke(cli, ["seed-demo", "--repos", "12", "--data-dir", d]).exit_code == 0

    async def hang(self, scan_id):
        os.kill(os.getpid(), signal.SIGTERM)  # what App Service does on stop
        await asyncio.sleep(30)

    monkeypatch.setattr(Scanner, "_run", hang)
    r = CliRunner().invoke(cli, ["scan", "--demo", "--data-dir", d, "--history", "0"])
    assert r.exit_code == exitcodes.INTERRUPTED, r.output
    url = f"sqlite:///{d}/pch.db"
    with session_scope(url) as s:
        scans = store.list_scans(s)
        assert len(scans) == 1 and scans[0].status == "failed" and scans[0].summary["error"] == "interrupted"
    holder = locks.acquire(get_engine(url))  # lock was released: a new scan could start
    locks.release(get_engine(url), holder)


def test_cli_scan_lock_held_exit_4(tmp_path):
    d = str(tmp_path / "data")
    CliRunner().invoke(cli, ["seed-demo", "--repos", "12", "--data-dir", d])
    url = f"sqlite:///{d}/pch.db"
    engine = get_engine(url)
    holder = locks.acquire(engine)
    try:
        r = CliRunner().invoke(cli, ["scan", "--demo", "--data-dir", d, "--history", "0"])
        assert r.exit_code == exitcodes.LOCK_HELD
    finally:
        locks.release(engine, holder)


def test_exit_codes_are_distinct_constants():
    vals = [exitcodes.OK, exitcodes.FAILED, exitcodes.CONFIG, exitcodes.SCHEMA_NOT_READY, exitcodes.LOCK_HELD, exitcodes.INTERRUPTED]
    assert vals == [0, 1, 2, 3, 4, 5] and set(vals) == set(exitcodes.DESCRIPTIONS)


def test_scan_timeout_setting_default_and_validation():
    assert S().scan_timeout_minutes == 240 and S().graceful_shutdown_seconds == 20
    with pytest.raises(ValueError):
        S(scan_timeout_minutes=0)
    assert S(retention_keep_scans="").retention_keep_scans is None


# ------------------------------------------------------------------ telemetry + doctor
def test_telemetry_disabled_without_connection_string():
    st = telemetry.setup_telemetry(S(), "pch-web")
    assert st.enabled is False and "not set" in st.detail


def test_telemetry_set_but_extra_missing_is_a_clear_config_error(monkeypatch):
    monkeypatch.setattr(telemetry, "sdk_available", lambda: False)
    with pytest.raises(ProviderUnavailable) as e:
        telemetry.setup_telemetry(S(applicationinsights_connection_string="InstrumentationKey=00000000-0000-0000-0000-000000000000"), "pch-web")
    assert "azure-monitor" in str(e.value) and "0000-0000" not in str(e.value)


def test_cli_exits_2_when_app_insights_set_but_extra_missing(monkeypatch):
    monkeypatch.setattr(telemetry, "sdk_available", lambda: False)
    r = CliRunner().invoke(cli, ["scan", "--demo"], env={"APPLICATIONINSIGHTS_CONNECTION_STRING": "InstrumentationKey=abc-secret-key-999"})
    assert r.exit_code == exitcodes.CONFIG and "azure-monitor" in r.output and "abc-secret-key-999" not in r.output


def test_strip_url_removes_query_userinfo_fragment():
    assert telemetry.strip_url("https://u:p@dev.azure.com:443/org/_apis/x?api-version=7&token=abc#frag") == "https://dev.azure.com:443/org/_apis/x"
    assert telemetry.strip_url("/repos?x=1") == "/repos" and telemetry.strip_url("https://h/p") == "https://h/p"


def test_doctor_logging_and_telemetry_checks(monkeypatch):
    s = S(log_level="debug")
    assert doctor.check_logging(s).detail == "format=text, level=DEBUG"
    assert doctor.check_telemetry(s).status == doctor.OK and "disabled" in doctor.check_telemetry(s).detail
    with_ai = S(applicationinsights_connection_string="InstrumentationKey=abc-secret-key-999")
    monkeypatch.setattr(telemetry, "sdk_available", lambda: False)
    c = doctor.check_telemetry(with_ai)
    assert c.status == doctor.FAIL and "extra missing" in c.detail and "abc-secret-key-999" not in c.detail
    monkeypatch.setattr(telemetry, "sdk_available", lambda: True)
    c = doctor.check_telemetry(with_ai)
    assert c.status == doctor.OK and "enabled" in c.detail and "abc-secret" not in c.detail
    names = [x.name for x in doctor.run_checks()]
    assert "logging" in names and "telemetry" in names


# ------------------------------------------------------------------ with the azure-monitor extra
def test_sanitizer_and_httpx_spans_do_not_leak_urls_or_authorization():
    pytest.importorskip("azure.monitor.opentelemetry")
    httpx = pytest.importorskip("httpx")
    pytest.importorskip("opentelemetry.instrumentation.httpx")
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(telemetry.build_span_sanitizer())  # before the exporter, as setup_telemetry does
    tp.add_span_processor(SimpleSpanProcessor(exporter))
    client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"ok": 1})))
    HTTPXClientInstrumentor.instrument_client(client, tracer_provider=tp)
    client.request("GET", "https://u:pw@dev.azure.com/org/_apis/x?api-version=7&token=QUERYSECRET1",
                   headers={"Authorization": "Bearer HEADERSECRET1"}, content=b"BODYSECRET1")
    spans = exporter.get_finished_spans()
    assert spans
    dump = json.dumps([dict(s.attributes) for s in spans], default=str)
    for leak in ("QUERYSECRET1", "HEADERSECRET1", "BODYSECRET1", "pw@", "api-version"):
        assert leak not in dump, leak


def test_logs_pass_through_the_filter_on_the_otel_handler():
    pytest.importorskip("azure.monitor.opentelemetry")
    from opentelemetry.instrumentation.logging.handler import LoggingHandler
    from opentelemetry.sdk._logs import LoggerProvider

    configure_logging(S(log_format="json"), stream=io.StringIO())
    h = LoggingHandler(logger_provider=LoggerProvider())
    logging.getLogger().addHandler(h)
    try:
        from pch.logging_setup import protect_handlers

        protect_handlers()
        assert any(isinstance(f, RedactingFilter) for f in h.filters)
    finally:
        logging.getLogger().removeHandler(h)
