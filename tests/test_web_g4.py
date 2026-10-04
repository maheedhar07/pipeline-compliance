"""G4: richer overview / repo page / lineage flow / tables (sorting, paging, chips, column chooser) + their safety."""

from __future__ import annotations

import html
import json
import re
from urllib.parse import parse_qs, quote, urlsplit

import pytest
from fastapi.testclient import TestClient

from pch.store.db import session_scope
from pch.store.models import FindingRow, LineageRow, RepoResultRow
from pch.web import queries as Q
from pch.web import tables as T
from pch.web.app import create_app
from tests.test_web_security import PAYLOADS, S

PAGES = ["/", "/repos", "/findings", "/rules", "/lineage", "/testing", "/targets", "/migration", "/scans"]


def make_db(tmp, repos: int = 160) -> str:
    """A scanned demo estate big enough for several pages of every table."""
    import asyncio
    from datetime import datetime

    from pch.demo.generator import generate_world
    from pch.demo.transport import parse_world_time
    from pch.orchestrator import ScanConfig, Scanner
    from pch.settings import Policy, Scope
    from pch.sources import demo_sources
    from tests.builders import ALL_HOSTS

    url = f"sqlite:///{tmp}/g4.db"
    for k, sid in ((1, "scan-1"), (0, "scan-0")):  # two scans: trends have data
        w = generate_world(seed=11, repos=repos, quality_shift=-0.05 * k, now=datetime(2026, 10, 1, 12, 0, 0))
        src = demo_sources(w)
        cfg = ScanConfig(scope=Scope(code_hosts=ALL_HOSTS, projects=w["meta"]["projects"]), policy=Policy(approved_registries=["contosoacr.azurecr.io"]), db_url=url, mode="demo",
                         now=parse_world_time(w))

        async def go(src=src, cfg=cfg, sid=sid):
            try:
                await Scanner(src, cfg).run(sid)
            finally:
                await src.aclose()

        asyncio.run(go())
    return url


@pytest.fixture(scope="module")
def db(tmp_path_factory) -> str:
    url = make_db(tmp_path_factory.mktemp("g4"))
    with session_scope(url) as s:  # the demo scope has no owners: give some repos one
        for i, r in enumerate(s.query(RepoResultRow).order_by(RepoResultRow.repo_key).all()):
            r.owner = f"team-{i % 4}@example.com" if i % 5 else None
    return url


@pytest.fixture(scope="module")
def c(db):
    return TestClient(create_app(db, settings=S()), base_url="http://localhost")


def urls_of(page: str, canvas_id: str) -> list[list[str]]:
    m = re.search(rf"<canvas id=\"{canvas_id}\"[^>]*data-urls='([^']*)'", page)
    assert m, canvas_id
    return json.loads(html.unescape(m.group(1)))


def a_repo(c, **params) -> dict:
    return c.get("/api/v1/repos", params=params).json()["repos"][0]


# ------------------------------------------------------------------ renders
@pytest.mark.parametrize("path", PAGES)
def test_every_view_renders(c, path):
    r = c.get(path)
    assert r.status_code == 200 and "Traceback" not in r.text and "UndefinedError" not in r.text


def test_repo_and_lineage_pages_render_in_both_views(c):
    r = a_repo(c, status="NON_COMPLIANT")
    key = f"{r['project']}/{r['repo']}"
    assert c.get(f"/repos/{key}").status_code == 200
    for view in ("flow", "table"):
        assert c.get(f"/lineage/{key}", params={"view": view}).status_code == 200
    assert c.get(f"/lineage/{key}", params={"view": "cube"}).status_code == 400


# ------------------------------------------------------------------ overview
def test_overview_has_every_new_chart_and_all_are_clickable(c):
    t = c.get("/").text
    for cid in ("donut", "severity", "migration", "byproject", "byowner", "trend", "toprules"):
        urls = urls_of(t, cid)
        assert urls and all(u for ds in urls for u in ds)
        for u in (u for ds in urls for u in ds):
            assert u.startswith("/") and not u.startswith("//"), u
    ov = c.get("/api/v1/overview").json()
    assert {i["name"] for i in ov["by_project"]["items"]} == set(ov["projects"])
    assert set(ov["severity_counts"]) == {"critical", "high", "medium", "low"} and ov["severity_counts"]["critical"] == ov["kpis"]["critical_findings"]
    assert [m["key"] for m in ov["migration_states"]] == ["ado_only", "in_progress", "migrated"]
    assert sum(i["total"] for i in ov["by_owner"]["items"]) <= ov["kpis"]["repos"]
    # project bar segments drill down to the filtered repo list, which honours both filters
    p = ov["by_project"]["items"][0]["name"]
    seg = urls_of(t, "byproject")[2][0]  # dataset 2 = non-compliant, first project
    q = parse_qs(urlsplit(seg).query)
    assert q["project"] == [p] and q["status"] == ["NON_COMPLIANT"]
    rows = c.get("/api/v1/repos", params={"project": p, "status": "NON_COMPLIANT"}).json()["repos"]
    assert len(rows) == ov["by_project"]["items"][0]["non_compliant"]


def test_kpi_tiles_link_to_filtered_lists(c):
    t = c.get("/").text
    for href in ("/repos?status=COMPLIANT", "/findings?severity=critical&amp;status=FAIL", "/repos?test_state=NO_TESTS", "/repos?platform=classic", "/repos?status=NOT_SCANNED"):
        assert f'href="{href}"' in t, href


def test_owner_and_migration_filters(c):
    ov = c.get("/api/v1/overview").json()
    owner = next(i["name"] for i in ov["by_owner"]["items"] if i["name"] != Q.NO_OWNER)
    rows = c.get("/api/v1/repos", params={"owner": owner}).json()["repos"]
    assert rows and all(r["owner"] == owner for r in rows)
    none = c.get("/api/v1/repos", params={"owner": Q.NO_OWNER}).json()["repos"]
    assert all(r["owner"] is None for r in none)
    mig = c.get("/api/v1/repos", params={"migration": "ado_only"}).json()["repos"]
    assert mig and all(r["migration_status"] == "ado_only" for r in mig)


# ------------------------------------------------------------------ repo page
def test_repo_page_fix_first_categories_trend_and_preview(c):
    r = a_repo(c, status="NON_COMPLIANT")
    key = f"{r['project']}/{r['repo']}"
    js = c.get(f"/api/v1/repos/{key}").json()
    ff = js["fix_first"]
    assert ff["items"] and ff["total"] >= len(ff["items"])
    ranks = [Q.SEV_RANK[i["severity"]] for i in ff["items"]]
    assert ranks == sorted(ranks)  # worst severity first
    assert all(i["remediation"] for i in ff["items"] if i["rule_id"] != "COLLECTION-ERROR")
    assert len({i["rule_id"] for i in ff["items"]}) == len(ff["items"])  # one entry per rule
    assert [t["scan_id"] for t in js["trend"]] and all(t["status"] for t in js["trend"])
    page = c.get(f"/repos/{key}").text
    for needle in ('id="fix-first"', "data-score-breakdown", "Score by category", "<b>Fix:</b>", 'data-flow-node="repo"'):
        assert needle in page
    assert "/findings?" in page and "status=FAIL" in page
    assert re.search(r"ADO (YAML|Classic)|GitHub Actions", page)  # platform badges


def test_fix_first_orders_by_severity_then_category_weight():
    def f(rule, sev, cat):
        return {"rule_id": rule, "title": rule, "severity": sev, "severity_default": None, "category": cat, "category_name": cat, "message": "m", "remediation": "r",
                "link": None, "status": "FAIL", "pipeline_name": "p", "stage": None}

    cats = [{"findings": [f("A-1", "high", "SRC"), f("B-1", "high", "DEP"), f("C-1", "critical", "SRC"), f("A-1", "high", "SRC"), {**f("W-1", "low", "SRC"), "status": "WARN"}]}]
    out = Q.fix_first(cats, {"category_weights": {"DEP": 3}})
    assert [i["rule_id"] for i in out["items"]] == ["C-1", "B-1", "A-1"]  # critical, then heavier category first
    assert out["items"][2]["places"] == 2 and out["total"] == 3
    assert [i["rule_id"] for i in Q.fix_first(cats, {})["items"]] == ["C-1", "A-1", "B-1"]  # default weight 1: rule id breaks the tie


def test_category_weights_are_snapshotted_only_when_set():
    from pch.engine.runner import policy_effects
    from pch.settings import Policy

    assert "category_weights" not in policy_effects(Policy())
    assert policy_effects(Policy(scoring={"category_weights": {"DEP": 2}}))["category_weights"] == {"DEP": 2}


# ------------------------------------------------------------------ lineage flow
def test_flow_draws_connected_cards(c):
    docs = c.get("/api/v1/lineage").json()["repos"]
    d = next(x for x in docs if x["summary"]["releases"] and x["summary"]["pipelines"] and x["summary"]["stages"] >= 2)
    t = c.get(f"/lineage/{d['repo']['key']}").text
    for node in ("repo", "pipeline", "release", "stage"):
        assert f'data-flow-node="{node}"' in t, node
    for cls in ("flow-children", "flow-child", "flow-chain", "flow-arrow"):
        assert cls in t
    assert 'role="region"' in t and "tabindex=\"0\"" in t  # scrollable frame is keyboard reachable
    assert re.search(r"aria-current=true[^>]*>Flow<", t) and "view=table" in t  # toggle to the table view
    assert "ADO YAML" in t or "ADO Classic" in t or "GitHub Actions" in t


def test_flow_failing_counts_link_to_filtered_findings(c):
    docs = c.get("/api/v1/lineage").json()["repos"]
    key = next(d["repo"]["key"] for d in docs if d["compliance"] and d["compliance"]["counts"]["fail"])
    t = c.get(f"/lineage/{key}").text
    m = re.search(r'href="(/findings\?[^"]*status=FAIL[^"]*)"[^>]*>(\d+) failing', t)
    assert m
    q = parse_qs(urlsplit(html.unescape(m.group(1))).query)
    assert q["repo"] == [key]
    res = c.get(html.unescape(m.group(1)))
    assert res.status_code == 200 and f"{key}" in res.text  # the target page lists findings of that repo


def test_compact_flow_preview_on_repo_page_links_to_lineage(c):
    docs = c.get("/api/v1/lineage").json()["repos"]
    d = next(x for x in docs if not x["summary"]["empty"])
    key = d["repo"]["key"]
    t = c.get(f"/repos/{key}").text
    assert "Lineage preview" in t and f"/lineage/{quote(key, safe='/')}" in t and "w-40" in t  # compact repo card


# ------------------------------------------------------------------ tables: sort, pagination, validation
SORTS = {
    "/repos": ["project", "repo", "owner", "provider", "platforms", "targets", "test_state", "coverage", "sonar_gate", "aikido_criticals", "score", "status", "critical_fails", "high_fails",
               "unknowns", "migration_score", "migration_status"],
    "/findings": ["severity", "status", "rule", "category", "repo", "pipeline", "message"],
    "/rules": ["default", "id", "title", "category", "severity", "scope", "applicable", "pass", "fail", "warn", "unknown", "pass_rate"],
    "/lineage": ["repo", "project", "status", "score", "pipelines", "releases", "stages", "targets", "prod"],
}


HEADERS = {
    "/repos": {"project", "repo", "owner", "platforms", "targets", "test_state", "coverage", "sonar_gate", "aikido_criticals", "score", "critical_fails", "migration_status", "status"},
    "/findings": set(SORTS["/findings"]), "/rules": {"id", "title", "severity", "scope", "applicable", "pass", "fail", "warn", "unknown", "pass_rate"},
    "/lineage": {"repo", "project", "status", "pipelines", "releases", "stages", "targets", "prod"},
}


@pytest.mark.parametrize("path", sorted(SORTS))
def test_every_sort_key_works_both_ways(c, path):
    for key in SORTS[path]:
        for d in ("asc", "desc"):
            r = c.get(path, params={"sort": key, "dir": d, "per_page": 25})
            assert r.status_code == 200, (path, key, d)
            if key in HEADERS[path]:  # the sorted column's header says so (some API-only keys have no column of their own)
                assert f'data-col="{key}" class=' in r.text and f'aria-sort="{"ascending" if d == "asc" else "descending"}"' in r.text


def test_sort_directions_are_really_ordered(c):
    asc = [r["score"] for r in c.get("/api/v1/repos", params={"sort": "score", "dir": "asc"}).json()["repos"] if r["score"] is not None]
    desc = [r["score"] for r in c.get("/api/v1/repos", params={"sort": "score", "dir": "desc"}).json()["repos"] if r["score"] is not None]
    assert asc == sorted(asc) and desc == sorted(desc, reverse=True)
    rows = c.get("/api/v1/repos", params={"sort": "coverage", "dir": "desc"}).json()["repos"]
    cov = [r["coverage"] for r in rows]
    assert cov.index(None) > max(i for i, v in enumerate(cov) if v is not None) if None in cov else True  # None is last in both directions
    f = c.get("/api/v1/findings", params={"sort": "rule", "dir": "asc", "limit": 300}).json()["items"]
    assert [x["rule_id"] for x in f] == sorted(x["rule_id"] for x in f)
    f = c.get("/api/v1/findings", params={"sort": "rule", "dir": "desc", "limit": 300}).json()["items"]
    assert [x["rule_id"] for x in f] == sorted((x["rule_id"] for x in f), reverse=True)
    default = c.get("/api/v1/findings", params={"limit": 300}).json()["items"]
    assert [Q.SEV_RANK[x["severity"]] for x in default] == sorted(Q.SEV_RANK[x["severity"]] for x in default)
    fails = [r["fail"] for r in c.get("/api/v1/rules").json()["rules"]]
    page = c.get("/rules", params={"sort": "fail", "dir": "desc", "per_page": 100}).text
    first = re.search(r'href="/rules/([A-Z]+-[A-Z0-9-]+)"', page.split("<tbody")[1]).group(1)
    top = max(c.get("/api/v1/rules").json()["rules"], key=lambda r: r["fail"])
    assert fails and first and next(r for r in c.get("/api/v1/rules").json()["rules"] if r["id"] == first)["fail"] == top["fail"]


def test_pagination_total_window_and_filters_preserved(c):
    total = len(c.get("/api/v1/repos").json()["repos"])
    t = c.get("/repos", params={"per_page": 25, "page": 2, "sort": "score", "dir": "desc", "status": "AT_RISK"}).text
    n = len(c.get("/api/v1/repos", params={"status": "AT_RISK"}).json()["repos"])
    assert f"of {n}" in t and "Showing 26" in t or n <= 25
    assert total >= n
    assert 'aria-label="Pagination"' in t and 'aria-label="Rows per page"' in t and 'aria-current="page"' in t
    # every pager link keeps the filters, sort and page size
    pager = t.split('aria-label="Pagination"')[1]
    links = [html.unescape(h) for h in re.findall(r'<a href="(/repos\?[^"]*(?:\?|&amp;)page=\d+[^"]*)"', pager)]
    assert links
    for h in links:
        q = parse_qs(urlsplit(h).query)
        assert q["status"] == ["AT_RISK"] and q["sort"] == ["score"] and q["dir"] == ["desc"] and q["per_page"] == ["25"]
    sizes = {parse_qs(urlsplit(html.unescape(h)).query)["per_page"][0] for h in re.findall(r'<a href="(/repos\?[^"]*per_page=\d+[^"]*)"', pager)}
    assert {"50", "100", "200"} <= sizes
    # a page past the end shows the last page instead of failing
    last = c.get("/repos", params={"per_page": 25, "page": 99999})
    assert last.status_code == 200 and "No repositories match" not in last.text


def test_page_size_changes_the_rows_shown(c):
    def rows(html_: str) -> int:
        return len(re.findall(r'<td data-col="repo"', html_))

    assert rows(c.get("/repos", params={"per_page": 25}).text) == 25
    assert rows(c.get("/repos", params={"per_page": 25, "page": 2}).text) == 25
    assert rows(c.get("/repos", params={"per_page": 200}).text) == min(200, len(c.get("/api/v1/repos").json()["repos"]))
    assert T.PAGE_SIZES == (25, 50, 100, 200)


def test_findings_pagination_matches_total(c):
    api = c.get("/api/v1/findings", params={"status": "FAIL", "limit": 1}).json()
    page = c.get("/findings", params={"status": "FAIL", "per_page": 25, "page": 3}).text
    assert f"of {api['total']}" in page
    assert len(re.findall(r'<td data-col="severity"', page)) == 25
    a = c.get("/api/v1/findings", params={"status": "FAIL", "limit": 25, "offset": 50}).json()["items"]
    first = a[0]
    assert first["rule_id"] in page and first["repo_key"] in page  # page 3 of 25 = offset 50


def test_pagination_math():
    p = T.make_page([], 101, 3, 25)
    assert (p.pages, p.start, p.end, p.has_prev, p.has_next) == (5, 51, 75, True, True)
    assert T.make_page([], 0, 1, 25).start == 0 and T.make_page([], 5, 9, 25).page == 1
    assert T.make_page([], 1000, 20, 25).window() == [1, None, 18, 19, 20, 21, 22, None, 40]
    s = T.slice_page(list(range(60)), 3, 25)
    assert s.items == list(range(50, 60)) and s.total == 60


@pytest.mark.parametrize("path", ["/repos", "/findings", "/rules", "/lineage"])
def test_bad_table_params_are_400_never_500(c, path):
    for params in ({"page": 0}, {"page": -3}, {"page": "x"}, {"page": 10**12}, {"per_page": 0}, {"per_page": 7}, {"per_page": 1000}, {"per_page": "x"}, {"sort": "'; drop table--"}, {"dir": "sideways"}):
        r = c.get(path, params=params)
        assert r.status_code == 400, (path, params, r.status_code)
        assert "drop table" not in r.text
    assert c.get(path, params={"per_page": 200, "page": 1}).status_code == 200


# ------------------------------------------------------------------ chips, exports, column chooser
def test_filter_chips_are_removable_and_clear_all_works(c):
    t = c.get("/repos", params={"project": a_repo(c)["project"], "status": "AT_RISK", "q": "svc", "sort": "score", "per_page": 25, "page": 2}).text
    chips = re.findall(r'data-chip="(\w+)"', t)
    assert chips == ["project", "status", "q"]
    removes = [html.unescape(h) for h in re.findall(r'<a href="(/repos\?[^"]*)" class="flex h-5 w-5[^>]*aria-label="Remove filter', t)]
    assert len(removes) == 3
    for h, gone in zip(removes, chips, strict=True):
        q = parse_qs(urlsplit(h).query)
        assert gone not in q and "page" not in q and q["sort"] == ["score"] and q["per_page"] == ["25"]  # only that filter goes, page resets
        assert len(set(chips) - {gone} & set(q)) == 2
    clear = html.unescape(re.search(r'<a href="([^"]*)"[^>]*>Clear all</a>', t).group(1))
    q = parse_qs(urlsplit(clear).query)
    assert not {"project", "status", "q", "page"} & set(q) and q["sort"] == ["score"]
    assert 'data-chip=' not in c.get("/repos").text and "Clear all" not in c.get("/repos").text
    for path, params, chip in (("/findings", {"severity": "high", "rule": "DEP-001"}, "severity"), ("/rules", {"category": "DEP", "failing": "1"}, "failing"),
                               ("/lineage", {"has_prod": "yes", "q": "x"}, "has_prod")):
        assert f'data-chip="{chip}"' in c.get(path, params=params).text


def test_exports_honour_filters_not_pagination(c):
    t = c.get("/repos", params={"status": "AT_RISK", "per_page": 25, "page": 2}).text
    href = html.unescape(re.search(r'href="(/repos\.csv\?[^"]*)"', t).group(1))
    q = parse_qs(urlsplit(href).query)
    assert q["status"] == ["AT_RISK"] and "page" not in q and "per_page" not in q
    full = c.get(href).text.strip().splitlines()
    assert len(full) - 1 == len(c.get("/api/v1/repos", params={"status": "AT_RISK"}).json()["repos"]) > 0
    assert c.get("/repos.csv", params={"status": "AT_RISK", "page": 2, "per_page": 25}).text.strip().splitlines() == full  # ignored if sent
    lt = c.get("/lineage", params={"per_page": 25, "page": 2}).text
    assert "page=" not in html.unescape(re.search(r'href="(/lineage\.csv[^"]*)"', lt).group(1))


def test_column_chooser_markup_matches_table_columns(c):
    for path, tid in (("/repos", "repos"), ("/findings", "findings"), ("/rules", "rules"), ("/lineage", "lineage")):
        t = c.get(path).text
        assert f'data-col-chooser="{tid}"' in t and f'data-table="{tid}"' in t and "data-col-reset" in t
        toggles = set(re.findall(r'data-col-toggle="(\w+)"', t))
        heads = set(re.findall(r'<th scope="col" data-col="(\w+)"', t))
        assert toggles and toggles <= heads, (tid, toggles - heads)
        cells = set(re.findall(r'<td data-col="(\w+)"', t))
        assert toggles <= cells, (tid, toggles - cells)
    assert 'class="sticky-head"' in c.get("/repos").text
    js = (__import__("pathlib").Path(__file__).parent.parent / "src/pch/web/static/app.js").read_text()
    assert "localStorage" in js and "try {" in js and "pch-cols-" in js


# ------------------------------------------------------------------ safety: hostile names in the flow, charts and tables
@pytest.fixture(scope="module")
def evil(tmp_path_factory):
    url = make_db(tmp_path_factory.mktemp("g4x"), repos=40)
    with session_scope(url) as s:
        rows = s.query(RepoResultRow).order_by(RepoResultRow.repo_key).limit(3).all()
        key0 = rows[0].repo_key
        for r, p in zip(rows, PAYLOADS, strict=False):
            r.owner = p
            r.url = p
        rows[0].repo = PAYLOADS[0]
        rows[0].repo_key = f"{rows[0].project}/{PAYLOADS[0]}"
        for f in s.query(FindingRow).filter(FindingRow.repo_key == key0).all():
            f.repo_key = rows[0].repo_key
            f.pipeline_name, f.stage, f.message = PAYLOADS[1], PAYLOADS[2], PAYLOADS[0]
        for lr in s.query(LineageRow).filter(LineageRow.kind == "repo").all():
            doc = json.loads(json.dumps(lr.doc))
            if lr.repo_key == key0:
                lr.repo_key = rows[0].repo_key
                doc["repo"]["name"], doc["repo"]["key"] = PAYLOADS[0], rows[0].repo_key
            for p in doc["pipelines"]:
                p["name"], p["url"] = PAYLOADS[1], PAYLOADS[3]
                for st in p["stages"]:
                    st["name"], st["env_name"] = PAYLOADS[2], PAYLOADS[0]
                    st["gates"] = [PAYLOADS[2]]
                for dl in p["downstream"]:
                    dl["name"], dl["detail"] = PAYLOADS[0], PAYLOADS[1]
            for r in doc["releases"]:
                r["name"], r["url"] = PAYLOADS[2], PAYLOADS[3]
                for st in r["stages"]:
                    st["name"], st["approvals"] = PAYLOADS[1], [PAYLOADS[2]]
            lr.doc = doc
        owner_project = rows[0].project
    return url, owner_project, rows[0].repo_key


def test_hostile_values_stay_inert_in_flow_charts_and_tables(evil):
    url, project, key = evil
    c = TestClient(create_app(url, settings=S()), base_url="http://localhost")
    pages = ["/", "/repos", "/repos?sort=owner", "/findings", "/findings?sort=pipeline", "/rules", "/lineage", f"/repos?owner={quote(PAYLOADS[0])}",
             f"/findings?pipeline={quote(PAYLOADS[1])}&repo={quote(PAYLOADS[0])}", f"/lineage?q={quote(PAYLOADS[2])}",
             f"/repos/{quote(project, safe='')}/{quote(PAYLOADS[0], safe='')}", f"/lineage/{quote(project, safe='')}/{quote(PAYLOADS[0], safe='')}",
             f"/lineage/{quote(project, safe='')}/{quote(PAYLOADS[0], safe='')}?view=table"]
    flow_seen = chart_seen = False
    for path in pages:
        r = c.get(path)
        assert r.status_code == 200, path
        t = r.text
        for p in ("<img src=x onerror=alert(1)>", "</script><script>alert(1)", '"><svg/onload', "<svg/onload=alert(1)>"):
            assert p not in t, (path, p)
        assert 'href="javascript:' not in t
        assert not re.findall(r"<script(?![^>]*\bsrc=)(?![^>]*application/json)[^>]*>", t)
        for blk in re.findall(r'<script type="application/json" id="page-data">(.*?)</script>', t, re.S):
            assert "<" not in blk and ">" not in blk
            json.loads(blk)
        for raw in re.findall(r"data-urls='([^']*)'", t):
            chart_seen = True
            urls = json.loads(html.unescape(raw))
            assert all(u.startswith("/") and not u.startswith("//") for ds in urls for u in ds)
        if 'data-flow-node="stage"' in t or 'data-flow-node="pipeline"' in t:
            flow_seen = True
            assert "&lt;img src=x onerror=alert(1)&gt;" in t or "&lt;/script&gt;" in t or "&#34;&gt;&lt;svg" in t
    assert flow_seen and chart_seen
    # the hostile owner is a filter value + chip: shown escaped, never as markup
    t = c.get("/repos", params={"owner": PAYLOADS[0]}).text
    assert 'data-chip="owner"' in t and "&lt;img" in t and "<img src=x" not in t


def test_templates_use_only_known_hooks():
    import pathlib

    root = pathlib.Path(__file__).parent.parent / "src/pch/web"
    for name in ("_table.html", "_lineage_flow.html"):
        t = (root / "templates" / name).read_text()
        assert "<style" not in t and not re.search(r"\sstyle\s*=", t) and not re.search(r"\son[a-z]+\s*=", t)
