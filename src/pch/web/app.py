"""FastAPI application factory: server-rendered pages + JSON API (report-only, no mutation endpoints)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context

from pch import __version__
from pch.settings import get_settings
from pch.store import repository as store
from pch.store.db import session_scope
from pch.web import queries as Q

HERE = Path(__file__).parent


def create_app(db_url: str | None = None) -> FastAPI:
    app = FastAPI(title="Pipeline Compliance Hub", version=__version__, docs_url="/api/docs", redoc_url=None)
    app.state.db_url = db_url or get_settings().database_url
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    env = templates.env
    env.filters["pct"] = lambda v, d=1: "n/a" if v is None else f"{v:.{d}f}%"
    env.filters["tojson_safe"] = lambda v: json.dumps(v, default=str).replace("</", "<\\/")
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
        return path + ("?" + urlencode(d) if d else "")

    env.globals["u"] = u

    def ctx(request: Request, s, scan_id: str | None, **extra: Any) -> dict[str, Any]:
        scan = Q.resolve_scan(s, scan_id)
        scans_list = store.list_scans(s, 20)
        return {"request": request, "scan": scan, "scans": scans_list, "scan_param": scan_id or "", **extra}

    def no_data(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "empty.html", {"request": request, "scan": None, "scans": [], "scan_param": ""}, status_code=200)

    # ------------------------------------------------------------------ HTML pages
    @app.get("/", response_class=HTMLResponse)
    def page_overview(request: Request, scan: str | None = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            return templates.TemplateResponse(request, "overview.html", ctx(request, s, scan, data=Q.overview(s, row.id), nav="overview"))

    def repo_filters(project, status, test_state, platform, target, sonar, q):
        return {"project": project, "status": status, "test_state": test_state, "platform": platform, "target": target, "sonar": sonar, "q": q}

    @app.get("/repos", response_class=HTMLResponse)
    def page_repos(request: Request, scan: str | None = None, project: str | None = None, status: str | None = None, test_state: str | None = None,
                   platform: str | None = None, target: str | None = None, sonar: str | None = None, q: str | None = None,
                   sort: str = "status", dir: str = "asc"):
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
    def repos_csv(scan: str | None = None, project: str | None = None, status: str | None = None, test_state: str | None = None,
                  platform: str | None = None, target: str | None = None, sonar: str | None = None, q: str | None = None,
                  sort: str = "status", dir: str = "asc"):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                raise HTTPException(404, "no scans yet")
            rows = Q.repos(s, row.id, sort=sort, direction=dir, **repo_filters(project, status, test_state, platform, target, sonar, q))
        buf = io.StringIO()
        csv.writer(buf).writerows(Q.csv_rows(rows))
        return PlainTextResponse(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=repos.csv"})

    @app.get("/repos/{project}/{repo}", response_class=HTMLResponse)
    def page_repo(request: Request, project: str, repo: str, scan: str | None = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            d = Q.repo_detail(s, row.id, project, repo)
            if d is None:
                raise HTTPException(404, f"repo {project}/{repo} not found in scan {row.id}")
            return templates.TemplateResponse(request, "repo_detail.html", ctx(request, s, scan, d=d, nav="repos"))

    @app.get("/rules", response_class=HTMLResponse)
    def page_rules(request: Request, scan: str | None = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            stats = Q.rule_stats(s, row.id)
            return templates.TemplateResponse(request, "rules.html", ctx(request, s, scan, stats=stats, nav="rules"))

    @app.get("/rules/{rule_id}", response_class=HTMLResponse)
    def page_rule(request: Request, rule_id: str, scan: str | None = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            d = Q.rule_detail(s, row.id, rule_id)
            if d is None:
                raise HTTPException(404, f"unknown rule {rule_id}")
            return templates.TemplateResponse(request, "rule_detail.html", ctx(request, s, scan, d=d, nav="rules"))

    @app.get("/findings", response_class=HTMLResponse)
    def page_findings(request: Request, scan: str | None = None, project: str | None = None, category: str | None = None, rule: str | None = None,
                      status: str | None = None, severity: str | None = None, repo: str | None = None, offset: int = 0):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            data = Q.findings_list(s, row.id, project=project, category=category, rule=rule, status=status, severity=severity, repo_key=repo, offset=offset)
            filt = {"project": project, "category": category, "rule": rule, "status": status, "severity": severity, "repo": repo}
            return templates.TemplateResponse(request, "findings.html", ctx(request, s, scan, data=data, filt=filt, offset=offset,
                                                                            options=Q.filter_options(s, row.id), nav="findings", base={**filt, "scan": scan}))

    @app.get("/testing", response_class=HTMLResponse)
    def page_testing(request: Request, scan: str | None = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            return templates.TemplateResponse(request, "testing.html", ctx(request, s, scan, data=Q.testing(s, row.id), nav="testing"))

    @app.get("/targets", response_class=HTMLResponse)
    def page_targets(request: Request, scan: str | None = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            return templates.TemplateResponse(request, "targets.html", ctx(request, s, scan, data=Q.targets(s, row.id), nav="targets"))

    @app.get("/migration", response_class=HTMLResponse)
    def page_migration(request: Request, scan: str | None = None):
        with session_scope(app.state.db_url) as s:
            row = Q.resolve_scan(s, scan)
            if not row:
                return no_data(request)
            return templates.TemplateResponse(request, "migration.html", ctx(request, s, scan, data=Q.migration(s, row.id), nav="migration"))

    @app.get("/scans", response_class=HTMLResponse)
    def page_scans(request: Request, scan: str | None = None, selected: str | None = None):
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

    @app.get("/api/v1/overview")
    def api_overview(scan: str | None = None):
        return api(lambda s, r: Q.overview(s, r.id))(scan)

    @app.get("/api/v1/repos")
    def api_repos(scan: str | None = None, project: str | None = None, status: str | None = None, test_state: str | None = None,
                  platform: str | None = None, target: str | None = None, sonar: str | None = None, q: str | None = None,
                  sort: str = "status", dir: str = "asc"):
        return api(lambda s, r: {"repos": Q.repos(s, r.id, sort=sort, direction=dir, **repo_filters(project, status, test_state, platform, target, sonar, q))})(scan)

    @app.get("/api/v1/repos/{project}/{repo}")
    def api_repo(project: str, repo: str, scan: str | None = None):
        return api(lambda s, r: Q.repo_detail(s, r.id, project, repo))(scan)

    @app.get("/api/v1/rules")
    def api_rules(scan: str | None = None):
        return api(lambda s, r: {"rules": Q.rule_stats(s, r.id)})(scan)

    @app.get("/api/v1/rules/{rule_id}")
    def api_rule(rule_id: str, scan: str | None = None):
        return api(lambda s, r: Q.rule_detail(s, r.id, rule_id))(scan)

    @app.get("/api/v1/findings")
    def api_findings(scan: str | None = None, project: str | None = None, category: str | None = None, rule: str | None = None,
                     status: str | None = None, severity: str | None = None, repo: str | None = None, limit: int = Query(200, le=1000), offset: int = 0):
        return api(lambda s, r: Q.findings_list(s, r.id, project=project, category=category, rule=rule, status=status, severity=severity,
                                                 repo_key=repo, limit=limit, offset=offset))(scan)

    @app.get("/api/v1/testing")
    def api_testing(scan: str | None = None):
        return api(lambda s, r: Q.testing(s, r.id))(scan)

    @app.get("/api/v1/targets")
    def api_targets(scan: str | None = None):
        return api(lambda s, r: Q.targets(s, r.id))(scan)

    @app.get("/api/v1/migration")
    def api_migration(scan: str | None = None):
        return api(lambda s, r: Q.migration(s, r.id))(scan)

    @app.get("/api/v1/scans")
    def api_scans(selected: str | None = None):
        with session_scope(app.state.db_url) as s:
            return JSONResponse(Q.scans(s, selected))

    @app.exception_handler(404)
    async def not_found(request: Request, exc: HTTPException):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": getattr(exc, "detail", "not found")}, status_code=404)
        return templates.TemplateResponse(request, "error.html", {"request": request, "scan": None, "scans": [], "scan_param": "", "message": getattr(exc, "detail", "Not found")}, status_code=404)

    return app
