"""FastAPI application factory: server-rendered pages + JSON API (report-only, no mutation endpoints).

Security layers (see pch.web.guard / auth / security): startup guard, security headers, trusted hosts, GET/HEAD only,
authentication + role authorisation on everything except the health endpoints and /static/*.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import logging
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import quote, urlencode

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context
from markupsafe import Markup
from sqlalchemy.exc import InterfaceError, OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException

from pch import __version__
from pch.settings import Settings, get_settings
from pch.store import repository as store
from pch.store.db import dispose_engine, get_engine, session_scope
from pch.web import queries as Q
from pch.web.auth import AuthMiddleware, build_authenticator
from pch.web.guard import assert_safe_to_serve
from pch.web.health import ReadinessProbe
from pch.web.security import (
    CSP,
    GENERIC_500,
    MethodGuardMiddleware,
    SecurityMiddleware,
    TrustedHostMiddleware,
    deny_auth,
    error_page,
)

HERE = Path(__file__).parent
KNOWN_404 = {"no scans yet", "repo not found in this scan", "unknown rule", "not found", "no scans yet: run `pch seed-demo && pch scan --demo`"}
log = logging.getLogger("pch.web")

# Query-parameter types: bounded lengths, whitelisted sort keys, bounded offsets (bad input -> 422/400, never 500).
Text = Annotated[str | None, Query(max_length=200)]
ScanId = Annotated[str | None, Query(max_length=64)]
SortKey = Literal["project", "repo", "owner", "test_state", "coverage", "sonar_gate", "aikido_criticals", "score", "status", "critical_fails", "migration_score"]
Direction = Literal["asc", "desc"]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
Limit = Annotated[int, Query(ge=1, le=1000)]
ProjectPath = Annotated[str, PathParam(max_length=200)]
RepoPath = Annotated[str, PathParam(max_length=200)]
RulePath = Annotated[str, PathParam(max_length=64)]

_JSON_ESCAPES = {ord("<"): "\\u003c", ord(">"): "\\u003e", ord("&"): "\\u0026", 0x2028: "\\u2028", 0x2029: "\\u2029"}


def json_for_script(value: Any) -> Markup:
    """JSON for an inert ``<script type="application/json">`` block. ``<``, ``>``, ``&`` and the JS line separators
    are \\u-escaped so no attacker-influenced string can close the element or start markup; the result is valid JSON."""
    return Markup(json.dumps(value, default=str).translate(_JSON_ESCAPES))  # nosec B704 - JSON with <, >, & and U+2028/9 escaped; covered by tests/test_web_security.py


def safe_url(v: Any) -> str:
    """Only absolute http(s) URLs are rendered as links (external data could carry ``javascript:`` etc.)."""
    u = str(v or "").strip()
    return u if re.match(r"https?://[^\s]+$", u, re.I) else "#"


def csv_cell(v: Any) -> Any:
    """Neutralise spreadsheet formula injection (repo names etc. are attacker-influenced)."""
    if isinstance(v, str) and v and (v[0] in "=+-@\t\r" or v.startswith(("\n",))):
        return "'" + v
    return v


def _docs_csp(html: bytes) -> str:
    """CSP for the dev-only Swagger UI page: its single inline bootstrap script is allowed by hash (no unsafe-inline);
    the UI assets come from jsDelivr. Never served in prod (docs are disabled there)."""
    m = re.search(rb"<script>(.*?)</script>", html, re.S)
    digest = base64.b64encode(hashlib.sha256(m.group(1)).digest()).decode() if m else ""
    return (CSP.replace("script-src 'self'", f"script-src 'self' https://cdn.jsdelivr.net 'sha256-{digest}'")
            .replace("style-src 'self'", "style-src 'self' https://cdn.jsdelivr.net")
            .replace("img-src 'self' data:", "img-src 'self' data: https://fastapi.tiangolo.com"))


def _asset_version() -> str:
    h = hashlib.sha256()
    for rel in ("vendor/tailwind.css", "app.css", "app.js", "theme.js"):
        f = HERE / "static" / rel
        h.update(f.read_bytes() if f.exists() else b"")
    return h.hexdigest()[:10]


def _default_hosts(s: Settings) -> list[str]:
    hosts = s.allowed_host_list
    if hosts or s.auth_mode != "none":
        return hosts
    return ["localhost", "127.0.0.1", "[::1]", "testserver"]  # AUTH_MODE=none: loopback names only (DNS-rebinding guard)


def create_app(db_url: str | None = None, settings: Settings | None = None, host: str | None = None) -> FastAPI:
    s_ = settings or get_settings()
    assert_safe_to_serve(s_, host if host is not None else s_.host)  # fail closed before anything is built
    prod = s_.is_prod
    db_url_ = db_url or s_.database_url

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        # Graceful shutdown (uvicorn drained in-flight requests first): release pooled DB connections.
        dispose_engine(db_url_)
        log.info("shutdown complete")

    app = FastAPI(title="Pipeline Compliance Hub", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None if prod else "/openapi.json", lifespan=lifespan)
    app.state.db_url = db_url_
    # Verify (or, per policy, migrate) the schema at startup: raises SchemaNotReadyError with a clear message in prod.
    # A database that is merely unreachable does not stop the app from starting: /health/live stays 200, /health/ready
    # reports 503 until it is back, and the engine re-checks the schema on the next request.
    try:
        get_engine(db_url_)
    except (OperationalError, InterfaceError) as exc:
        log.error("database unreachable at startup (%s); starting anyway, /health/ready will report 503", type(exc).__name__)
    probe = ReadinessProbe(db_url_, s_.health_ready_timeout_seconds, s_.health_ready_cache_seconds)
    app.state.readiness = probe
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    asset_v = _asset_version()
    docs_enabled = not prod

    def template_context(request: Request) -> dict[str, Any]:
        return {"principal": getattr(request.state, "principal", None), "docs_enabled": docs_enabled, "asset_v": asset_v}

    templates = Jinja2Templates(directory=HERE / "templates", context_processors=[template_context])
    env = templates.env
    app.state.templates = templates
    env.filters["pct"] = lambda v, d=1: "n/a" if v is None else f"{v:.{d}f}%"
    env.filters["tojson_safe"] = json_for_script
    env.filters["safe_url"] = safe_url
    env.globals["TARGET_LABEL"] = Q.TARGET_LABEL
    env.globals["version"] = __version__

    def qs(base: dict[str, Any], **over: Any) -> str:
        d = {k: v for k, v in {**base, **over}.items() if v not in (None, "")}
        return urlencode(d)

    env.globals["qs"] = qs

    @pass_context
    def u(context: Any, path: str, **params: Any) -> str:
        """URL helper that keeps the selected scan across navigation."""
        scan_param = context.get("scan_param") or ""
        d = {k: v for k, v in params.items() if v not in (None, "")}
        if scan_param:
            d["scan"] = scan_param
        # project/repo names are inserted into the path: encode them (a "#", "?" or "%" must not change the target)
        return quote(path, safe="/") + ("?" + urlencode(d) if d else "")

    env.globals["u"] = u

    def ctx(request: Request, s, scan_id: str | None, **extra: Any) -> dict[str, Any]:
        scan = Q.resolve_scan(s, scan_id)
        scans_list = store.list_scans(s, 20)
        return {"request": request, "scan": scan, "scans": scans_list, "scan_param": scan_id or "", **extra}

    def no_data(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "empty.html", {"request": request, "scan": None, "scans": [], "scan_param": ""}, status_code=200)

    # ------------------------------------------------------------------ HTML pages
    @app.get("/", response_class=HTMLResponse)
    def page_overview(request: Request, scan: ScanId = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            return templates.TemplateResponse(request, "overview.html", ctx(request, s, scan, data=Q.overview(s, row.id), nav="overview"))

    def repo_filters(project, status, test_state, platform, target, sonar, q):
        return {"project": project, "status": status, "test_state": test_state, "platform": platform, "target": target, "sonar": sonar, "q": q}

    @app.get("/repos", response_class=HTMLResponse)
    def page_repos(request: Request, scan: ScanId = None, project: Text = None, status: Text = None, test_state: Text = None,
                   platform: Text = None, target: Text = None, sonar: Text = None, q: Text = None,
                   sort: SortKey = "status", dir: Direction = "asc"):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            filters = repo_filters(project, status, test_state, platform, target, sonar, q)
            rows = Q.repos(s, row.id, sort=sort, direction=dir, **filters)
            return templates.TemplateResponse(request, "repos.html", ctx(
                request, s, scan, rows=rows, filters=filters, sort=sort, dir=dir, options=Q.filter_options(s, row.id), nav="repos",
                base={**filters, "scan": scan}))

    @app.get("/repos.csv", response_class=PlainTextResponse)
    def repos_csv(scan: ScanId = None, project: Text = None, status: Text = None, test_state: Text = None,
                  platform: Text = None, target: Text = None, sonar: Text = None, q: Text = None,
                  sort: SortKey = "status", dir: Direction = "asc"):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                raise HTTPException(404, "no scans yet")
            rows = Q.repos(s, row.id, sort=sort, direction=dir, **repo_filters(project, status, test_state, platform, target, sonar, q))
        buf = io.StringIO()
        csv.writer(buf).writerows([[csv_cell(c) for c in r] for r in Q.csv_rows(rows)])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=repos.csv"})

    @app.get("/repos/{project}/{repo}", response_class=HTMLResponse)
    def page_repo(request: Request, project: ProjectPath, repo: RepoPath, scan: ScanId = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            d = Q.repo_detail(s, row.id, project, repo)
            if d is None:
                raise HTTPException(404, "repo not found in this scan")
            return templates.TemplateResponse(request, "repo_detail.html", ctx(request, s, scan, d=d, nav="repos"))

    @app.get("/rules", response_class=HTMLResponse)
    def page_rules(request: Request, scan: ScanId = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            stats = Q.rule_stats(s, row.id)
            return templates.TemplateResponse(request, "rules.html", ctx(request, s, scan, stats=stats, nav="rules"))

    @app.get("/rules/{rule_id}", response_class=HTMLResponse)
    def page_rule(request: Request, rule_id: RulePath, scan: ScanId = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            d = Q.rule_detail(s, row.id, rule_id)
            if d is None:
                raise HTTPException(404, "unknown rule")
            return templates.TemplateResponse(request, "rule_detail.html", ctx(request, s, scan, d=d, nav="rules"))

    @app.get("/findings", response_class=HTMLResponse)
    def page_findings(request: Request, scan: ScanId = None, project: Text = None, category: Text = None, rule: Text = None,
                      status: Text = None, severity: Text = None, repo: Text = None, offset: Offset = 0):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            data = Q.findings_list(s, row.id, project=project, category=category, rule=rule, status=status, severity=severity, repo_key=repo, offset=offset)
            filt = {"project": project, "category": category, "rule": rule, "status": status, "severity": severity, "repo": repo}
            return templates.TemplateResponse(request, "findings.html", ctx(request, s, scan, data=data, filt=filt, offset=offset,
                                                                            options=Q.filter_options(s, row.id), nav="findings", base={**filt, "scan": scan}))

    @app.get("/testing", response_class=HTMLResponse)
    def page_testing(request: Request, scan: ScanId = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            return templates.TemplateResponse(request, "testing.html", ctx(request, s, scan, data=Q.testing(s, row.id), nav="testing"))

    @app.get("/targets", response_class=HTMLResponse)
    def page_targets(request: Request, scan: ScanId = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            return templates.TemplateResponse(request, "targets.html", ctx(request, s, scan, data=Q.targets(s, row.id), nav="targets"))

    @app.get("/migration", response_class=HTMLResponse)
    def page_migration(request: Request, scan: ScanId = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            return templates.TemplateResponse(request, "migration.html", ctx(request, s, scan, data=Q.migration(s, row.id), nav="migration"))

    @app.get("/scans", response_class=HTMLResponse)
    def page_scans(request: Request, scan: ScanId = None, selected: ScanId = None):
        with session_scope(app.state.db_url) as s:
            data = Q.scans(s, selected or scan)
            if not data["scans"]:
                return no_data(request)
            return templates.TemplateResponse(request, "scans.html", ctx(request, s, scan, data=data, nav="scans"))

    # ------------------------------------------------------------------ JSON API
    def api(fn):
        """Run fn(session, scan_row) and return JSON; 404 when there is no data."""

        def run(scan: str | None, *a: Any, **kw: Any):
            with session_scope(app.state.db_url) as s:
                row = Q.resolve_scan(s, scan)
                if not row:
                    raise HTTPException(404, "no scans yet: run `pch seed-demo && pch scan --demo`")
                out = fn(s, row, *a, **kw)
                if out is None:
                    raise HTTPException(404, "not found")
                return JSONResponse({"scan_id": row.id, **out} if isinstance(out, dict) else {"scan_id": row.id, "items": out})

        return run

    @app.get("/api/v1/health")
    def api_health():
        return {"status": "ok", "version": __version__}

    @app.get("/health/live", include_in_schema=False)
    async def health_live():
        return JSONResponse({"status": "ok"})

    @app.get("/health/ready", include_in_schema=False)
    async def health_ready():
        code = await probe.code()
        if code == "ok":
            return JSONResponse({"status": "ok"})
        return JSONResponse({"status": "unavailable", "reason": code}, status_code=503)

    @app.get("/api/v1/overview")
    def api_overview(scan: ScanId = None):
        return api(lambda s, r: Q.overview(s, r.id))(scan)

    @app.get("/api/v1/repos")
    def api_repos(scan: ScanId = None, project: Text = None, status: Text = None, test_state: Text = None,
                  platform: Text = None, target: Text = None, sonar: Text = None, q: Text = None,
                  sort: SortKey = "status", dir: Direction = "asc"):
        return api(lambda s, r: {"repos": Q.repos(s, r.id, sort=sort, direction=dir, **repo_filters(project, status, test_state, platform, target, sonar, q))})(scan)

    @app.get("/api/v1/repos/{project}/{repo}")
    def api_repo(project: ProjectPath, repo: RepoPath, scan: ScanId = None):
        return api(lambda s, r: Q.repo_detail(s, r.id, project, repo))(scan)

    @app.get("/api/v1/rules")
    def api_rules(scan: ScanId = None):
        return api(lambda s, r: {"rules": Q.rule_stats(s, r.id)})(scan)

    @app.get("/api/v1/rules/{rule_id}")
    def api_rule(rule_id: RulePath, scan: ScanId = None):
        return api(lambda s, r: Q.rule_detail(s, r.id, rule_id))(scan)

    @app.get("/api/v1/findings")
    def api_findings(scan: ScanId = None, project: Text = None, category: Text = None, rule: Text = None,
                     status: Text = None, severity: Text = None, repo: Text = None, limit: Limit = 200, offset: Offset = 0):
        return api(lambda s, r: Q.findings_list(s, r.id, project=project, category=category, rule=rule, status=status, severity=severity,
                                                 repo_key=repo, limit=limit, offset=offset))(scan)

    @app.get("/api/v1/testing")
    def api_testing(scan: ScanId = None):
        return api(lambda s, r: Q.testing(s, r.id))(scan)

    @app.get("/api/v1/targets")
    def api_targets(scan: ScanId = None):
        return api(lambda s, r: Q.targets(s, r.id))(scan)

    @app.get("/api/v1/migration")
    def api_migration(scan: ScanId = None):
        return api(lambda s, r: Q.migration(s, r.id))(scan)

    @app.get("/api/v1/scans")
    def api_scans(selected: ScanId = None):
        with session_scope(app.state.db_url) as s:
            return JSONResponse(Q.scans(s, selected))

    # ------------------------------------------------------------------ errors (generic: no tracebacks, no exception text)
    def wants_json(request: Request) -> bool:
        return request.url.path.startswith("/api/") or request.url.path == "/openapi.json"

    def rid(request: Request) -> str:
        return str(getattr(request.state, "request_id", "-"))

    def error_response(request: Request, status: int, title: str, message: str, headers: dict[str, str] | None = None) -> Response:
        if wants_json(request):
            return JSONResponse({"detail": message, "request_id": rid(request)}, status_code=status, headers=headers)
        return templates.TemplateResponse(request, "error.html", {"request": request, "scan": None, "scans": [], "scan_param": "", "title": title,
                                                                 "message": message, "request_id": rid(request)}, status_code=status, headers=headers)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        titles = {404: "Not found", 405: "Method not allowed", 400: "Bad request"}
        msg = exc.detail if exc.status_code == 404 and isinstance(exc.detail, str) and exc.detail in KNOWN_404 else titles.get(exc.status_code, "Request failed")
        return error_response(request, exc.status_code, titles.get(exc.status_code, "Request failed"), msg, dict(getattr(exc, "headers", None) or {}) or None)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Never echo the submitted input; name only the offending parameter.
        fields = sorted({".".join(str(x) for x in e.get("loc", ())[1:]) or "(request)" for e in exc.errors()})
        if wants_json(request):
            return JSONResponse({"detail": "invalid request parameters", "fields": fields, "request_id": rid(request)}, status_code=422)
        return error_response(request, 400, "Bad request", "One or more query parameters are invalid: " + ", ".join(fields))

    @app.exception_handler(Exception)
    async def server_error(request: Request, exc: Exception):
        log.error("unhandled error (request_id=%s)", rid(request), exc_info=exc)
        if wants_json(request):
            return JSONResponse({"detail": GENERIC_500[1], "request_id": rid(request)}, status_code=500)
        return HTMLResponse(error_page(*GENERIC_500, rid(request)).decode(), status_code=500)

    # ------------------------------------------------------------------ dev-only API docs (disabled when APP_ENV=prod)
    docs_csp: str | None = None
    if docs_enabled:
        page = get_swagger_ui_html(openapi_url="/openapi.json", title="Pipeline Compliance Hub API")
        docs_csp = _docs_csp(page.body if isinstance(page.body, bytes) else bytes(page.body))

        @app.get("/api/docs", include_in_schema=False)
        def api_docs():
            return page

    # ------------------------------------------------------------------ middleware (last added = outermost)
    authenticator = build_authenticator(s_)

    async def deny(scope: dict, send: Any, status: int) -> None:
        await deny_auth(scope, send, status)

    app.add_middleware(AuthMiddleware, authenticator=authenticator, deny=deny, log=lambda m: log.warning(m))
    app.add_middleware(MethodGuardMiddleware)
    hosts = _default_hosts(s_)
    if hosts:
        app.add_middleware(TrustedHostMiddleware, hosts=hosts)
    app.add_middleware(SecurityMiddleware, hsts=prod, docs_csp=docs_csp)
    return app
