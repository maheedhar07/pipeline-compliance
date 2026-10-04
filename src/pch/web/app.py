"""FastAPI application factory: server-rendered pages + JSON API (report-only toward every source system).

The only write path is the Settings page (ADR-19): ``POST /settings/features/{key}[/reset]`` changes a feature switch in this app's OWN database.
It needs an admin role, a CSRF token and a same-origin request; everything else is GET/HEAD.

Security layers (see pch.web.guard / auth / security): startup guard, security headers, trusted hosts, GET/HEAD only (plus those two POSTs),
authentication + role authorisation on everything except the health endpoints and /static/*.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import itertools
import json
import logging
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated, Any, Literal
from urllib.parse import parse_qs, quote, urlencode

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context
from markupsafe import Markup
from sqlalchemy.exc import InterfaceError, OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException

from pch import __version__
from pch import features as F
from pch.model.repo import PROVIDER_LABEL
from pch.settings import Settings, get_settings
from pch.store import repository as store
from pch.store.db import dispose_engine, get_engine, session_scope
from pch.timeutil import utcnow_naive
from pch.web import csrf
from pch.web import exports as X
from pch.web import lineage_q as LQ
from pch.web import queries as Q
from pch.web import tables as T
from pch.web.auth import AuthMiddleware, build_authenticator
from pch.web.guard import assert_safe_to_serve, guard_warnings
from pch.web.health import ReadinessProbe
from pch.web.security import (
    CSP,
    GENERIC_500,
    MethodGuardMiddleware,
    SecurityMiddleware,
    TrustedHostMiddleware,
    deny_auth,
    error_page,
    principal_hash,
)

HERE = Path(__file__).parent
# Fixed texts of the Settings write path (never built from input): shown on 400/403 pages.
MSG_NOT_ADMIN = "You do not have permission to change settings."
MSG_WRITES_DISABLED = "Changing settings is disabled on this deployment (no signing key is configured)."
MSG_CROSS_SITE = "This request did not come from this site and was refused."
MSG_FORM_STALE = "The form has expired or is invalid. Open the Settings page again and retry."
MSG_BAD_FORM = "The submitted form is not valid."
SAFE_DETAILS = {MSG_NOT_ADMIN, MSG_WRITES_DISABLED, MSG_CROSS_SITE, MSG_FORM_STALE, MSG_BAD_FORM}
MAX_FORM_BYTES = 4096
FLASH_CODES = {"saved", "reset", "nochange"}
# Output keys that exist only because of the Migration switch; removed everywhere (pages, API, exports) while it is off.
MIGRATION_KEYS = frozenset({"migration_score", "migration_status", "migration_label", "migration_blockers", "retire_reason", "migration_states", "no_pipeline_repos"})
MIGRATION_SORTS = frozenset({"migration_score", "migration_status"})


def strip_migration(obj: Any) -> Any:
    """``obj`` without the migration fields (recursively through dicts and lists)."""
    if isinstance(obj, dict):
        return {k: strip_migration(v) for k, v in obj.items() if k not in MIGRATION_KEYS}
    if isinstance(obj, list):
        return [strip_migration(v) for v in obj]
    return obj


KNOWN_404 = {"no scans yet", "repo not found in this scan", "unknown rule", "not found", "no scans yet: run `pch seed-demo && pch scan --demo`",
             "this scan has no lineage data (it was made before the Lineage tab existed)", "lineage not found for this repo in this scan"}
log = logging.getLogger("pch.web")

# Query-parameter types: bounded lengths, whitelisted sort keys, bounded offsets (bad input -> 422/400, never 500).
Text = Annotated[str | None, Query(max_length=200)]
ScanId = Annotated[str | None, Query(max_length=64)]
SortKey = Literal["project", "repo", "owner", "provider", "platforms", "targets", "test_state", "coverage", "sonar_gate", "aikido_criticals", "score", "status",
                  "critical_fails", "high_fails", "unknowns", "migration_score", "migration_status"]
FindingSort = Literal["severity", "status", "rule", "category", "repo", "pipeline", "message"]
RuleSort = Literal["default", "id", "title", "category", "severity", "scope", "applicable", "pass", "fail", "warn", "unknown", "pass_rate"]
LineageSort = Literal["repo", "project", "status", "score", "pipelines", "releases", "stages", "targets", "prod"]
View = Literal["flow", "table"]
Direction = Literal["asc", "desc"]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
Limit = Annotated[int, Query(ge=1, le=1000)]
ProjectPath = Annotated[str, PathParam(max_length=200)]
RepoPath = Annotated[str, PathParam(max_length=200)]  # routed with {repo:path}: GitHub-hosted repos are "org/repo"
RulePath = Annotated[str, PathParam(max_length=64)]
FeatureKey = Annotated[str, PathParam(max_length=40)]
Short = Annotated[str | None, Query(max_length=8)]  # tiny enumerations from <select> (an empty value means "all"): normalised, never an error
MigState = Annotated[str | None, Query(max_length=16)]  # migration status filter
Flag = Annotated[str | None, Query(max_length=8)]

_JSON_ESCAPES = {ord("<"): "\\u003c", ord(">"): "\\u003e", ord("&"): "\\u0026", 0x2028: "\\u2028", 0x2029: "\\u2029"}


def json_for_script(value: Any) -> Markup:
    """JSON for an inert ``<script type="application/json">`` block. ``<``, ``>``, ``&`` and the JS line separators
    are \\u-escaped so no attacker-influenced string can close the element or start markup; the result is valid JSON."""
    return Markup(json.dumps(value, default=str).translate(_JSON_ESCAPES))  # nosec B704 - JSON with <, >, & and U+2028/9 escaped; covered by tests/test_web_security.py


def safe_url(v: Any) -> str:
    """Only absolute http(s) URLs are rendered as links (external data could carry ``javascript:`` etc.)."""
    u = str(v or "").strip()
    return u if re.match(r"https?://[^\s]+$", u, re.I) else "#"


csv_cell = X.csv_cell  # re-exported: tests and /repos.csv use the one neutralisation rule


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
    feature_defaults = F.load_feature_defaults(s_.config_dir / "features.yaml")  # strict: an invalid file stops the start (ConfigError)
    signing = csrf.resolve_signing_key(s_)  # key=None: the Settings page is read-only (prod without SETTINGS_SIGNING_KEY)
    authenticator = build_authenticator(s_)
    app.state.signing = signing
    for warning in guard_warnings(s_):
        log.warning("settings: %s", warning)
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

    def request_flags(request: Request) -> dict[str, bool]:
        """Effective feature switches (file defaults + database overrides), read once per request so a change applies to the very next page."""
        got = getattr(request.state, "features", None)
        if got is None:
            try:
                with session_scope(app.state.db_url) as db:
                    got = F.effective_flags(db, feature_defaults)
            except Exception as exc:  # noqa: BLE001 - an unreadable overrides table must not break error pages; the defaults apply
                log.warning("feature overrides not readable (%s); using the features.yaml defaults", type(exc).__name__)
                got = dict(feature_defaults)
            request.state.features = got
        return got

    def template_context(request: Request) -> dict[str, Any]:
        return {"principal": getattr(request.state, "principal", None), "docs_enabled": docs_enabled, "asset_v": asset_v, "features": request_flags(request)}

    def require_migration(request: Request) -> None:
        if not request_flags(request)["migration"]:
            raise HTTPException(404, "not found")

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
        return {"request": request, "scan": scan, "scans": scans_list, "scan_param": scan_id or "", "multi_host": Q.multi_host(s, scan),
                "freshness": Q.freshness(s, s_.scan_stale_hours), **extra}

    def no_data(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "empty.html", {"request": request, "scan": None, "scans": [], "scan_param": ""}, status_code=200)

    # ------------------------------------------------------------------ HTML pages
    @app.get("/", response_class=HTMLResponse)
    def page_overview(request: Request, scan: ScanId = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            data = Q.overview(s, row.id)
            return templates.TemplateResponse(request, "overview.html", ctx(request, s, scan, data=data if request_flags(request)["migration"] else strip_migration(data), nav="overview"))

    def repo_filters(project, status, test_state, platform, target, sonar, q, provider=None, rule=None, owner=None, migration=None):
        return {"project": project, "status": status, "test_state": test_state, "platform": platform, "target": target, "sonar": sonar, "q": q, "provider": provider,
                "rule": rule, "owner": owner, "migration": migration}

    def chip_text(name: str, v: Any) -> str:
        labels = {"target": Q.TARGET_LABEL, "provider": PROVIDER_LABEL, "migration": Q.MIGRATION_LABEL}.get(name, {})
        return str(labels.get(v, v)).replace("_", " ")

    def chip_defs(filters: dict[str, Any], names: list[tuple[str, str]]) -> list[tuple[str, str, Any]]:
        return [(n, label, chip_text(n, filters.get(n)) if filters.get(n) else None) for n, label in names]

    REPO_CHIPS = [("project", "Project"), ("provider", "Code host"), ("status", "Status"), ("test_state", "Tests"), ("platform", "Pipelines"), ("target", "Target"),
                  ("sonar", "Sonar gate"), ("owner", "Owner"), ("migration", "Migration"), ("rule", "Rule failing"), ("q", "Search")]

    def table_params(filters: dict[str, Any], scan: str | None, sort: str, dir: str, per_page: int, **extra: Any) -> dict[str, Any]:
        """Everything a table link must carry (filters, scan, sort, page size); ``page`` is added per link."""
        return {**filters, "scan": scan, "sort": sort, "dir": dir, "per_page": per_page, **extra}

    @app.get("/repos", response_class=HTMLResponse)
    def page_repos(request: Request, scan: ScanId = None, project: Text = None, status: Text = None, test_state: Text = None,
                   platform: Text = None, target: Text = None, sonar: Text = None, q: Text = None, provider: Text = None,
                   rule: Text = None, owner: Text = None, migration: MigState = None, sort: SortKey = "status", dir: Direction = "asc",
                   page: T.PageNo = 1, per_page: T.PerPage = T.DEFAULT_PER_PAGE):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            mig = request_flags(request)["migration"]
            if not mig:  # the Migration switch is off: no migration filter or sort (ignored, never an error)
                migration, sort = None, ("status" if sort in MIGRATION_SORTS else sort)
            filters = repo_filters(project, status, test_state, platform, target, sonar, q, provider, rule, owner, migration)
            rows = Q.repos(s, row.id, sort=sort, direction=dir, **filters)
            pg = T.slice_page(rows, page, per_page)
            params = table_params(filters, scan, sort, dir, per_page)
            chips = [c for c in REPO_CHIPS if mig or c[0] != "migration"]
            return templates.TemplateResponse(request, "repos.html", ctx(
                request, s, scan, rows=strip_migration(pg.items) if not mig else pg.items, pg=pg, filters=filters, sort=sort, dir=dir, options=Q.filter_options(s, row.id), nav="repos",
                base={**filters, "scan": scan}, params=params, chips=T.chips("/repos", params, chip_defs(filters, chips)),
                clear=T.clear_url("/repos", params, [n for n, _ in chips])))

    @app.get("/repos.csv", response_class=PlainTextResponse)
    def repos_csv(request: Request, scan: ScanId = None, project: Text = None, status: Text = None, test_state: Text = None,
                  platform: Text = None, target: Text = None, sonar: Text = None, q: Text = None, provider: Text = None,
                  rule: Text = None, owner: Text = None, migration: MigState = None, sort: SortKey = "status", dir: Direction = "asc"):
        mig = request_flags(request)["migration"]
        if not mig:
            migration, sort = None, ("status" if sort in MIGRATION_SORTS else sort)
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                raise HTTPException(404, "no scans yet")
            rows = Q.repos(s, row.id, sort=sort, direction=dir, **repo_filters(project, status, test_state, platform, target, sonar, q, provider, rule, owner, migration))
        buf = io.StringIO()
        csv.writer(buf).writerows([[csv_cell(c) for c in r] for r in Q.csv_rows(rows, migration=mig)])
        return PlainTextResponse(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=repos.csv"})

    @app.get("/repos/{project}/{repo:path}", response_class=HTMLResponse)
    def page_repo(request: Request, project: ProjectPath, repo: RepoPath, scan: ScanId = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            d = Q.repo_detail(s, row.id, project, repo)
            if d is None:
                raise HTTPException(404, "repo not found in this scan")
            lin = LQ.lineage_repo(s, row.id, project, repo)  # compact flow preview (None for scans made before the Lineage tab)
            return templates.TemplateResponse(request, "repo_detail.html", ctx(request, s, scan, d=d if request_flags(request)["migration"] else strip_migration(d), lin=lin, nav="repos"))

    RULE_CHIPS = [("category", "Category"), ("severity", "Severity"), ("failing", "Only"), ("q", "Search")]

    @app.get("/rules", response_class=HTMLResponse)
    def page_rules(request: Request, scan: ScanId = None, category: Text = None, severity: Text = None, failing: Flag = None, q: Text = None,
                   sort: RuleSort = "default", dir: Direction = "asc", page: T.PageNo = 1, per_page: T.PerPage = T.DEFAULT_PER_PAGE):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            filters = {"category": category, "severity": severity, "failing": "1" if failing == "1" else None, "q": q}
            all_stats = Q.rule_stats(s, row.id)
            stats = Q.rules_table(all_stats, sort=sort, direction=dir, **filters)
            pg = T.slice_page(stats, page, per_page)
            params = table_params(filters, scan, sort, dir, per_page)
            shown = {**filters, "failing": "rules with failures" if filters["failing"] else None}
            return templates.TemplateResponse(request, "rules.html", ctx(
                request, s, scan, stats=pg.items, pg=pg, total_rules=len(all_stats), filters=filters, sort=sort, dir=dir, nav="rules", params=params,
                categories=Q.CATEGORY_NAMES, severities=list(Q.SEVERITIES) + ["info"], group=sort in ("default", "category"),
                chips=T.chips("/rules", params, [(n, label, shown.get(n)) for n, label in RULE_CHIPS]),
                clear=T.clear_url("/rules", params, [n for n, _ in RULE_CHIPS])))

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

    FINDING_CHIPS = [("project", "Project"), ("category", "Category"), ("severity", "Severity"), ("status", "Status"), ("rule", "Rule"), ("repo", "Repo"), ("pipeline", "Pipeline"), ("stage", "Stage")]

    @app.get("/findings", response_class=HTMLResponse)
    def page_findings(request: Request, scan: ScanId = None, project: Text = None, category: Text = None, rule: Text = None,
                      status: Text = None, severity: Text = None, repo: Text = None, pipeline: Text = None, stage: Text = None,
                      sort: FindingSort = "severity", dir: Direction = "asc", page: T.PageNo = 1, per_page: T.PerPage = T.DEFAULT_PER_PAGE):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            filt = {"project": project, "category": category, "rule": rule, "status": status, "severity": severity, "repo": repo, "pipeline": pipeline, "stage": stage}
            kw: dict[str, Any] = dict(project=project, category=category, rule=rule, status=status, severity=severity, repo_key=repo, pipeline=pipeline, stage=stage, sort=sort, direction=dir)
            total = Q.findings_list(s, row.id, limit=1, **kw)["total"]
            pg = T.make_page([], total, page, per_page)  # clamp the page against the real total, then fetch exactly that window
            data = Q.findings_list(s, row.id, limit=per_page, offset=(pg.page - 1) * per_page, **kw)
            pg.items = data["items"]
            params = table_params(filt, scan, sort, dir, per_page)
            return templates.TemplateResponse(request, "findings.html", ctx(
                request, s, scan, data=data, pg=pg, filt=filt, sort=sort, dir=dir, options=Q.filter_options(s, row.id), nav="findings", base={**filt, "scan": scan}, params=params,
                chips=T.chips("/findings", params, chip_defs(filt, FINDING_CHIPS)), clear=T.clear_url("/findings", params, [n for n, _ in FINDING_CHIPS])))

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
    def page_migration(request: Request, scan: ScanId = None, state: MigState = None):
        require_migration(request)
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            return templates.TemplateResponse(request, "migration.html", ctx(
                request, s, scan, data=Q.migration(s, row.id, state or None), nav="migration", scan_without_migration=not Q.scan_features(s, row.id)["migration"]))

    @app.get("/scans", response_class=HTMLResponse)
    def page_scans(request: Request, scan: ScanId = None, selected: ScanId = None):
        with session_scope(app.state.db_url) as s:
            data = Q.scans(s, selected or scan)
            if not data["scans"]:
                return no_data(request)
            return templates.TemplateResponse(request, "scans.html", ctx(request, s, scan, data=data, nav="scans"))

    # ------------------------------------------------------------------ lineage (L2)
    def lineage_filters(project, provider, q, target, tier, has_prod, orphans) -> dict[str, Any]:
        return {"project": project, "provider": provider, "q": q, "target": target, "tier": tier, "has_prod": has_prod if has_prod in ("yes", "no") else None,
                "orphans": "1" if orphans == "1" else None}

    def lineage_kwargs(f: dict[str, Any]) -> dict[str, Any]:
        return {**{k: v for k, v in f.items() if k != "orphans"}, "orphans_only": bool(f.get("orphans"))}

    LINEAGE_CHIPS = [("project", "Project"), ("provider", "Code host"), ("target", "Target"), ("tier", "Tier"), ("has_prod", "Prod deployment"), ("orphans", "Orphans only"), ("q", "Search")]

    @app.get("/lineage", response_class=HTMLResponse)
    def page_lineage(request: Request, scan: ScanId = None, project: Text = None, provider: Text = None, q: Text = None, target: Text = None, tier: Text = None,
                     has_prod: Short = None, orphans: Flag = None, sort: LineageSort = "repo", dir: Direction = "asc",
                     page: T.PageNo = 1, per_page: T.PerPage = T.DEFAULT_PER_PAGE):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            f = lineage_filters(project, provider, q, target, tier, has_prod, orphans)
            data = LQ.lineage_page(s, row.id, **lineage_kwargs(f))
            pg = T.slice_page(LQ.sort_repos(data["repos"], sort, dir), page, per_page)
            params = table_params(f, scan, sort, dir, per_page)
            shown = {**f, "has_prod": {"yes": "has one", "no": "none"}.get(f["has_prod"] or ""), "orphans": "yes" if f["orphans"] else None}
            return templates.TemplateResponse(request, "lineage.html", ctx(
                request, s, scan, data=data, filters=f, base={**f, "scan": scan}, nav="lineage", pg=pg, rows=pg.items, sort=sort, dir=dir, params=params,
                chips=T.chips("/lineage", params, [(n, label, chip_text(n, shown.get(n)) if shown.get(n) else None) for n, label in LINEAGE_CHIPS]),
                clear=T.clear_url("/lineage", params, [n for n, _ in LINEAGE_CHIPS])))

    @app.get("/lineage/{project}/{repo:path}", response_class=HTMLResponse)
    def page_lineage_repo(request: Request, project: ProjectPath, repo: RepoPath, scan: ScanId = None, fragment: Flag = None, view: View = "flow"):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            d = LQ.lineage_repo(s, row.id, project, repo)
            if d is None:
                raise HTTPException(404, "lineage not found for this repo in this scan")
            context = ctx(request, s, scan, d=d, nav="lineage", view=view)
            return templates.TemplateResponse(request, "lineage_fragment.html" if fragment == "1" else "lineage_repo.html", context)

    def export_name(started: datetime, project: str | None, ext: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9_-]+", "-", project or "").strip("-")[:40]
        return f"pch-lineage-{slug + '-' if slug else ''}{LQ.scan_date(started)}.{ext}"

    def lineage_export(scan: str | None, f: dict[str, Any], ext: str) -> Response:
        """CSV / Excel of the (filtered) lineage: one row per repo -> pipeline -> release/deploy stage. GET only, never cached (middleware)."""
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                raise HTTPException(404, "no scans yet")
            full = LQ.load(s, row.id)
            meta = SimpleNamespace(id=row.id, started_at=row.started_at, mode=row.mode)
        if not full.has_data:
            raise HTTPException(404, "this scan has no lineage data (it was made before the Lineage tab existed)")
        data = LQ.apply_filters(full, **lineage_kwargs(f))
        lins = [r.lin for r in data.rows]
        comp = {r.key: r.compliance for r in data.rows}
        limit = s_.export_max_rows
        n = sum(1 for _ in itertools.islice(LQ.flat_rows(lins, comp), limit + 1))
        if n > limit:
            raise HTTPException(413, f"The export would contain more than {limit} rows (EXPORT_MAX_ROWS). Narrow the filters (project, provider, search) and try again.")
        headers = {"Content-Disposition": f'attachment; filename="{export_name(meta.started_at, f.get("project"), ext)}"'}
        if ext == "csv":
            return StreamingResponse(X.csv_lines(LQ.HEADERS, LQ.flat_rows(lins, comp)), media_type="text/csv; charset=utf-8", headers=headers)
        shown_filters = {k: v for k, v in f.items() if v}
        body = X.build_xlsx(LQ.COLUMNS, LQ.flat_rows(lins, comp), LQ.summary_rows(meta, data, shown_filters, n, utcnow_naive()), LQ.ORPHAN_COLUMNS, LQ.orphan_rows(LQ.orphan_items(data)))
        return Response(body, media_type=X.XLSX_MIME, headers=headers)

    @app.get("/lineage.csv")
    def lineage_csv(scan: ScanId = None, project: Text = None, provider: Text = None, q: Text = None, target: Text = None, tier: Text = None,
                    has_prod: Short = None, orphans: Flag = None):
        return lineage_export(scan, lineage_filters(project, provider, q, target, tier, has_prod, orphans), "csv")

    @app.get("/lineage.xlsx")
    def lineage_xlsx(scan: ScanId = None, project: Text = None, provider: Text = None, q: Text = None, target: Text = None, tier: Text = None,
                     has_prod: Short = None, orphans: Flag = None):
        return lineage_export(scan, lineage_filters(project, provider, q, target, tier, has_prod, orphans), "xlsx")

    # ------------------------------------------------------------------ Settings: feature switches (the only write path, ADR-19)
    def current_principal(request: Request) -> Any:
        return getattr(request.state, "principal", None)

    def can_change(request: Request) -> bool:
        p = current_principal(request)
        return p is not None and authenticator.is_admin(p)

    def read_only_reason(request: Request) -> str:
        if not can_change(request):
            if s_.auth_mode == "easyauth" and not s_.admin_roles:
                return "No administrator role is configured (AUTH_ADMIN_ROLES is empty), so the switches are read-only for everyone."
            roles = ", ".join(s_.admin_roles)
            return "Only administrators can change these switches" + (f" (app role {roles})." if roles else ".")
        if signing.key is None:
            return "Changes are disabled on this deployment: no signing key is configured (SETTINGS_SIGNING_KEY). Ask the operator."
        return ""

    def token_for(request: Request, action: str, key: str) -> str:
        principal = current_principal(request)
        if principal is None or signing.key is None:  # callers check writability first; never hand out a token otherwise
            return ""
        return csrf.make_token(signing.key, principal.id, f"{action}:{key}", csrf_now())

    def csrf_now() -> float:
        return time.time()

    @app.get("/settings", response_class=HTMLResponse)
    def page_settings(request: Request, scan: ScanId = None, flash: Annotated[str | None, Query(max_length=16)] = None,
                      k: Annotated[str | None, Query(max_length=40)] = None):
        with session_scope(app.state.db_url) as s:
            states = F.effective_states(s, feature_defaults)
            audit = F.audit_entries(s, 20)
            row = Q.resolve_scan(s, scan)
            scan_flags = Q.scan_features(s, row.id) if row else None
            why = read_only_reason(request)
            rows = []
            for st in states:
                seen = scan_flags[st.key] if scan_flags and st.timing == "next_scan" else None  # what the latest scan used
                rows.append({"st": st, "pending": seen is not None and seen != st.enabled, "seen": seen,
                             "set_token": "" if why else token_for(request, "set", st.key), "reset_token": "" if why or not st.overridden else token_for(request, "reset", st.key)})
            message = ""
            if flash in FLASH_CODES and k in F.BY_KEY:
                st = next(x for x in states if x.key == k)
                message = {"saved": f"Saved: {st.label} is now {'on' if st.enabled else 'off'}.", "reset": f"Reset: {st.label} is back to the default ({'on' if st.enabled else 'off'}).",
                           "nochange": f"No change: {st.label} was already set that way."}[flash]
            return templates.TemplateResponse(request, "settings.html", ctx(
                request, s, scan, nav="settings", rows=rows, why=why, message=message, audit=audit,
                admin_hint=", ".join(s_.admin_roles), key_generated=signing.generated))

    async def read_form(request: Request) -> dict[str, str]:
        """The urlencoded body (tiny and bounded). Anything else, or a repeated field, is a 400."""
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
            raise HTTPException(400, MSG_BAD_FORM)
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_FORM_BYTES:
                raise HTTPException(400, MSG_BAD_FORM)
        try:
            parsed = parse_qs(body.decode("ascii"), keep_blank_values=True, max_num_fields=8)
        except (UnicodeDecodeError, ValueError):
            raise HTTPException(400, MSG_BAD_FORM) from None
        if any(len(v) != 1 for v in parsed.values()):
            raise HTTPException(400, MSG_BAD_FORM)
        return {k: v[0] for k, v in parsed.items()}

    async def write_feature(request: Request, key: str, action: str) -> Response:
        """Checks, in order: admin role, known key, writes enabled, same-origin, CSRF token, value. Only then one audited database write."""
        principal = current_principal(request)
        if principal is None or not authenticator.is_admin(principal):
            raise HTTPException(403, MSG_NOT_ADMIN)
        if key not in F.BY_KEY:
            raise HTTPException(404, "not found")
        if signing.key is None:
            raise HTTPException(403, MSG_WRITES_DISABLED)
        if (problem := csrf.same_origin_problem({k.lower(): v for k, v in request.headers.items()})) is not None:
            log.warning("settings write refused: %s (principal %s)", problem, principal_hash(principal))
            raise HTTPException(403, MSG_CROSS_SITE)
        form = await read_form(request)
        if not csrf.verify_token(signing.key, principal.id, f"{action}:{key}", form.get("csrf_token"), csrf_now()):
            log.warning("settings write refused: invalid or expired form token (principal %s)", principal_hash(principal))
            raise HTTPException(403, MSG_FORM_STALE)
        value: bool | None = None
        if action == "set":
            if form.get("value") not in F.VALUES:
                raise HTTPException(400, MSG_BAD_FORM)
            value = form["value"] == "on"
        actor = F.Actor(principal.id, principal.name)

        def write() -> bool:
            with session_scope(app.state.db_url) as s:
                return F.set_override(s, key, value, actor, "ui")

        changed = await run_in_threadpool(write)
        if changed:
            log.info("feature switch changed: %s -> %s (principal %s)", key, "default" if value is None else "on" if value else "off", principal_hash(principal))
        code = ("saved" if action == "set" else "reset") if changed else "nochange"
        return RedirectResponse(f"/settings?{urlencode({'flash': code, 'k': key})}", status_code=303)

    @app.post("/settings/features/{key}", include_in_schema=False)
    async def post_feature_set(request: Request, key: FeatureKey):
        return await write_feature(request, key, "set")

    @app.post("/settings/features/{key}/reset", include_in_schema=False)
    async def post_feature_reset(request: Request, key: FeatureKey):
        return await write_feature(request, key, "reset")

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

    def _strip_response(resp: JSONResponse) -> JSONResponse:
        """A JSON API answer without the migration fields (the Migration switch is off)."""
        return JSONResponse(strip_migration(json.loads(bytes(resp.body))), status_code=resp.status_code)

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
    def api_overview(request: Request, scan: ScanId = None):
        mig = request_flags(request)["migration"]

        def data(s, r):
            d = Q.overview(s, r.id)
            return d if mig else strip_migration(d)

        return api(data)(scan)

    @app.get("/api/v1/repos")
    def api_repos(request: Request, scan: ScanId = None, project: Text = None, status: Text = None, test_state: Text = None,
                  platform: Text = None, target: Text = None, sonar: Text = None, q: Text = None, provider: Text = None,
                  rule: Text = None, owner: Text = None, migration: MigState = None, sort: SortKey = "status", dir: Direction = "asc"):
        mig = request_flags(request)["migration"]
        if not mig:
            migration, sort = None, ("status" if sort in MIGRATION_SORTS else sort)
        out = api(lambda s, r: {"repos": Q.repos(s, r.id, sort=sort, direction=dir, **repo_filters(project, status, test_state, platform, target, sonar, q, provider, rule, owner, migration))})
        return out(scan) if mig else _strip_response(out(scan))

    @app.get("/api/v1/repos/{project}/{repo:path}")
    def api_repo(request: Request, project: ProjectPath, repo: RepoPath, scan: ScanId = None):
        out = api(lambda s, r: Q.repo_detail(s, r.id, project, repo))(scan)
        return out if request_flags(request)["migration"] else _strip_response(out)

    @app.get("/api/v1/rules")
    def api_rules(scan: ScanId = None):
        return api(lambda s, r: {"rules": Q.rule_stats(s, r.id)})(scan)

    @app.get("/api/v1/rules/{rule_id}")
    def api_rule(rule_id: RulePath, scan: ScanId = None):
        return api(lambda s, r: Q.rule_detail(s, r.id, rule_id))(scan)

    @app.get("/api/v1/findings")
    def api_findings(scan: ScanId = None, project: Text = None, category: Text = None, rule: Text = None,
                     status: Text = None, severity: Text = None, repo: Text = None, pipeline: Text = None, stage: Text = None,
                     sort: FindingSort = "severity", dir: Direction = "asc", limit: Limit = 200, offset: Offset = 0):
        return api(lambda s, r: Q.findings_list(s, r.id, project=project, category=category, rule=rule, status=status, severity=severity,
                                                 repo_key=repo, pipeline=pipeline, stage=stage, limit=limit, offset=offset, sort=sort, direction=dir))(scan)

    @app.get("/api/v1/testing")
    def api_testing(scan: ScanId = None):
        return api(lambda s, r: Q.testing(s, r.id))(scan)

    @app.get("/api/v1/targets")
    def api_targets(scan: ScanId = None):
        return api(lambda s, r: Q.targets(s, r.id))(scan)

    @app.get("/api/v1/migration")
    def api_migration(request: Request, scan: ScanId = None, state: MigState = None):
        require_migration(request)
        return api(lambda s, r: Q.migration(s, r.id, state or None))(scan)

    @app.get("/api/v1/lineage")
    def api_lineage(scan: ScanId = None, project: Text = None, provider: Text = None, q: Text = None, target: Text = None, tier: Text = None,
                    has_prod: Short = None, orphans: Flag = None):
        f = lineage_filters(project, provider, q, target, tier, has_prod, orphans)
        return api(lambda s, r: LQ.lineage_page(s, r.id, **lineage_kwargs(f)))(scan)

    @app.get("/api/v1/lineage/{project}/{repo:path}")
    def api_lineage_repo(project: ProjectPath, repo: RepoPath, scan: ScanId = None):
        return api(lambda s, r: LQ.lineage_repo(s, r.id, project, repo))(scan)

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
        titles = {404: "Not found", 405: "Method not allowed", 400: "Bad request", 403: "Forbidden", 413: "Export too large"}
        msg = (exc.detail if (exc.status_code == 404 and isinstance(exc.detail, str) and exc.detail in KNOWN_404)
               or (exc.status_code in (400, 403) and isinstance(exc.detail, str) and exc.detail in SAFE_DETAILS)  # fixed texts of the Settings write path
               or (exc.status_code == 413 and isinstance(exc.detail, str) and exc.detail.startswith("The export would contain"))  # server-built text: row limit + advice
               else titles.get(exc.status_code, "Request failed"))
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
    async def deny(scope: dict, send: Any, status: int) -> None:
        await deny_auth(scope, send, status)

    app.add_middleware(AuthMiddleware, authenticator=authenticator, deny=deny, log=lambda m: log.warning(m))
    app.add_middleware(MethodGuardMiddleware)
    hosts = _default_hosts(s_)
    if hosts:
        app.add_middleware(TrustedHostMiddleware, hosts=hosts)
    app.add_middleware(SecurityMiddleware, hsts=prod, docs_csp=docs_csp)
    return app
