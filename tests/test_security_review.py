"""T7 independent security review: regression tests for every confirmed finding (see docs/SECURITY_REVIEW.md).

Fake credentials are assembled at run time so secret scanners never see a complete literal.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from pch.collectors.http import SourceClient
from pch.collectors.redact import SUSPECTED, redact_json, redact_text
from pch.collectors.transport import MutationBlockedError
from pch.logging_setup import scrub
from pch.orchestrator import ScanConfig, Scanner
from pch.settings import Policy, Scope, Settings
from pch.store.db import session_scope
from pch.store.engine import build_engine
from pch.store.models import CollectionErrorRow, ScanRow
from pch.web import queries as Q
from pch.web.app import create_app

from .test_web_security import S, easy, hdr, make_db

PW = "Zq9" + "xK2mW7" + "pL4v"  # fake credential value, built at run time
BUDGET_S = 2.0  # generous: the unfixed patterns needed minutes for these inputs


def _fast(fn, arg, budget=BUDGET_S):
    t0 = time.perf_counter()
    out = fn(arg)
    dt = time.perf_counter() - t0
    assert dt < budget, f"{fn.__name__} took {dt:.1f}s on {len(arg)} chars (ReDoS)"
    return out


# --------------------------------------------------------------------------- SEC-01: ReDoS in redaction
ADVERSARIAL = {
    "blank-lines": "\n" * 60_000,
    "spaces": " " * 60_000 + "x\n",
    "spaces-then-name": "name: pass" + "\n" * 60_000,
    "key-run": "pass" * 15_000 + "\n",
    "token-run": "token" * 12_000,
    "word-run": "a" * 60_000,
    "dotted-run": "a." * 30_000,
    "kv-run": "token=" * 10_000,
    "quote-run": "token='" * 9_000,
    "jwt-prefix-run": "eyJ" * 20_000,
    "scheme-run": "a." * 15_000 + "://",
    "http-run": "http://" * 9_000,
    "bearer-run": "bearer " + "a" * 60_000,
    "auth-spaces": "authorization" + " " * 60_000,
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_scrub_is_linear_on_adversarial_log_text(name):
    _fast(scrub, ADVERSARIAL[name])


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_redact_text_is_linear_on_adversarial_pipeline_text(name):
    _fast(redact_text, ADVERSARIAL[name])


def test_scrub_still_scrubs_after_the_linear_rewrite():
    cases = [
        f"password={PW}", f"api_key: {PW}", f'{{"client_secret": "{PW}"}}', f"x=token={PW}", f"my.access-token = '{PW}'",
        f"https://user:{PW}@host.example/x", f"Authorization: Bearer {PW}", "projectKey=" + "A" * 3,
    ]
    for c in cases[:-1]:
        assert PW not in scrub(c), c
    assert "***@host.example" in scrub(f"https://user:{PW}@host.example/x")
    assert scrub("see https://example.com/a?b=1 and plain words") == "see https://example.com/a?b=1 and plain words"
    # a secret hiding behind a long run of harmless text is still found
    assert PW not in scrub("a" * 5000 + f" token={PW}")
    assert PW not in scrub(("x." * 3000) + f"password={PW}")


def test_redact_text_still_redacts_after_the_linear_rewrite():
    t = ("\n" * 50) + f"variables:\n  - name: dbPassword\n    value: {PW}\n  - name: Region\n    value: west\n" \
        f"env:\n    API_TOKEN: {PW}\n  \t - 'my-key': {PW}\n  OK: $(API_TOKEN)\n"
    r = redact_text(t)
    assert PW not in r
    assert "west" in r and "$(API_TOKEN)" in r and SUSPECTED in r


# --------------------------------------------------------------------------- SEC-02: raw-cache field-name coverage
def test_redact_json_covers_suffixed_secret_field_names_but_keeps_paging_cursors():
    payload = {"apiToken": PW, "authToken": PW, "id_token": PW, "privateKey": PW, "AWS_SECRET_ACCESS_KEY": PW, "bearerToken": PW,
               "continuationToken": "page-2", "nextPageToken": "page-3", "tokenType": "Bearer", "key": "Proj_repo", "count": 3}
    out = redact_json({"nested": [payload]})["nested"][0]
    for k in ("apiToken", "authToken", "id_token", "privateKey", "AWS_SECRET_ACCESS_KEY", "bearerToken"):
        assert PW not in str(out[k]), k
    assert out["continuationToken"] == "page-2" and out["nextPageToken"] == "page-3"
    assert out["tokenType"] == "Bearer" and out["key"] == "Proj_repo" and out["count"] == 3


# --------------------------------------------------------------------------- SEC-03: persisted error text
def _cfg(db_url: str) -> ScanConfig:
    return ScanConfig(scope=Scope(projects=[]), policy=Policy(), db_url=db_url, mode="demo", now=datetime(2026, 10, 1, 12, 0, 0))


def test_scanner_err_scrubs_before_the_text_is_kept_for_the_database():
    sc = Scanner.__new__(Scanner)
    sc.errors = []
    sc.err("ado", "Proj/repo", ValueError(f"1 validation error ... input_value='password={PW}'"))
    sc.err("sonar", "Proj/repo", f"token={PW}")
    assert PW not in " ".join(m for _, _, m in sc.errors)


def test_failed_scan_reason_is_scrubbed_in_the_scans_table(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path}/f.db"

    async def boom(self, scan_id):
        raise RuntimeError(f"upstream said password={PW}")

    monkeypatch.setattr(Scanner, "_run", boom)
    sc = Scanner.__new__(Scanner)
    sc.cfg = _cfg(url)
    with pytest.raises(RuntimeError):
        asyncio.run(sc.run("s-1"))
    with session_scope(url) as s:
        row = s.get(ScanRow, "s-1")
        assert row.status == "failed" and PW not in str(row.summary)
        assert not s.query(CollectionErrorRow).all()


# --------------------------------------------------------------------------- SEC-04: secrets in repr / SQL errors
def test_settings_repr_does_not_contain_the_database_password():
    s = S(database_url=f"postgresql+psycopg://pch:{PW}@db.example/pch", ado_pat=PW)
    assert PW not in repr(s) and PW not in str(s)
    assert s.database_url.endswith("db.example/pch")  # still usable


def test_sql_error_text_hides_bound_parameters():
    engine = build_engine("sqlite://")
    with pytest.raises(OperationalError) as ei, engine.connect() as c:
        c.execute(text("select :v from table_that_does_not_exist"), {"v": PW})
    assert PW not in str(ei.value)


# --------------------------------------------------------------------------- SEC-05: LIKE wildcards / link encoding
@pytest.fixture(scope="module")
def db(tmp_path_factory):
    return make_db(tmp_path_factory.mktemp("sec7"))


def test_findings_project_filter_treats_wildcards_literally(db):
    with session_scope(db) as s:
        scan = Q.resolve_scan(s, None)
        assert Q.findings_list(s, scan.id)["total"] > 0
        assert Q.findings_list(s, scan.id, project="%")["total"] == 0
        assert Q.findings_list(s, scan.id, project="_")["total"] == 0


def test_u_helper_encodes_path_segments(db):
    app = create_app(db, settings=S())
    env = app.state.templates.env
    out = env.from_string("{{ u('/repos/Pro ject/re#po?x%', q='a b') }}").render(scan_param="s1")
    assert out.startswith("/repos/Pro%20ject/re%23po%3Fx%25?")
    assert "#" not in out and "q=a+b" in out and "scan=s1" in out


# --------------------------------------------------------------------------- auth bypass probes (raw ASGI: no client-side path normalisation)
async def _raw(app, path, method="GET", headers=None, host="app.example.net"):
    h = [(b"host", host.encode())] + [(k.encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "path": path, "raw_path": path.encode(),
             "query_string": b"", "headers": h, "scheme": "https", "server": (host, 443), "client": ("1.2.3.4", 1), "root_path": ""}
    out: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        out.append(m)

    await app(scope, receive, send)
    return next(m["status"] for m in out if m["type"] == "http.response.start")


@pytest.mark.parametrize("path", [
    "/health/live/", "/health/live/../repos", "/health/ready/x", "/health/liveness", "/HEALTH/LIVE", "/api/v1/health/", "/api/v1/health/../repos",
    "/static", "//static/x", "/static/../repos", "/static/../../etc/passwd", "/static/%2e%2e/x", "/static/vendor/../../auth.py",
    "/static/..\\..\\x", "/repos", "/api/v1/repos", "/openapi.json", "/api/docs", "/nope", "/repos/a/b/",
])
@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "POST", "TRACE"])
def test_unauthenticated_requests_never_reach_data(db, path, method):
    app = create_app(db, settings=easy(allowed_hosts="app.example.net"))
    status = asyncio.run(_raw(app, path, method))
    assert status in (400, 401, 404, 405), (method, path, status)


def test_authenticated_user_cannot_traverse_out_of_static(db):
    app = create_app(db, settings=easy(allowed_hosts="app.example.net"))
    for p in ("/static/../../etc/passwd", "/static/%2e%2e/%2e%2e/etc/passwd", "/static/vendor/../../../pyproject.toml"):
        assert asyncio.run(_raw(app, p, headers=hdr())) == 404


def test_forged_unrelated_role_is_denied_and_denied_pages_hold_no_data(db):
    app = create_app(db, settings=easy(allowed_hosts="app.example.net"))
    assert asyncio.run(_raw(app, "/repos", headers=hdr(roles=("Other.Role",)))) == 403
    assert asyncio.run(_raw(app, "/repos", headers=hdr(roles=("pch.reader",)))) == 403  # case-sensitive
    assert asyncio.run(_raw(app, "/repos", headers={"X-MS-CLIENT-PRINCIPAL": "!!!not-base64"})) == 401


# --------------------------------------------------------------------------- read-only transport / redirects
def _client(handler, **kw):
    return SourceClient("https://good.example", transport=httpx.MockTransport(handler), **kw)


@pytest.mark.parametrize("auth_kw", [{"headers": {"Authorization": "Basic QUJD"}}, {"auth": ("tok", "")}])
def test_redirect_to_another_host_does_not_forward_credentials(auth_kw):
    seen: list[tuple[str, str | None]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.url.host, req.headers.get("authorization")))
        return httpx.Response(302, headers={"location": "https://other.example/x"}) if req.url.host == "good.example" else httpx.Response(200, json={})

    asyncio.run(_client(handler, **auth_kw).get_json("/a"))
    assert seen[0][1] is not None and seen[1] == ("other.example", None)


@pytest.mark.parametrize("method,url,body", [
    ("post", "https://x/_apis/pipelines/1/preview", {"previewRun": False}),
    ("post", "https://x/_apis/pipelines/1/preview", None),
    ("POST", "https://x/_apis/pipelines/1/preview/runs", {"previewRun": True}),
    ("POST", "https://x/_apis/pipelines/1/preview/../../runs", {"previewRun": True}),
    ("DELETE", "https://x/a", None), ("PATCH", "https://x/a", None), ("PUT", "https://x/a", None), ("PROPPATCH", "https://x/a", None),
])
def test_read_only_guard_blocks_mutations_in_any_spelling(method, url, body):
    c = _client(lambda r: httpx.Response(200, json={}))
    with pytest.raises(MutationBlockedError):
        asyncio.run(c.request(method, url, json=body))


def test_every_httpx_client_is_built_through_the_read_only_wrapper():
    """Source guard: the only httpx.AsyncClient in the package is SourceClient's, which always wraps in ReadOnlyTransport."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent / "src" / "pch"
    hits = [str(p.relative_to(root)) for p in root.rglob("*.py") if re.search(r"httpx\.(Async)?Client\(|import requests|import aiohttp|urllib\.request", p.read_text())]
    assert hits == ["collectors/http.py"], hits


def test_stale_lock_window_is_longer_than_the_scan_timeout_by_default():
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert timedelta(minutes=s.scan_timeout_minutes) < timedelta(minutes=s.scan_lock_stale_minutes)
