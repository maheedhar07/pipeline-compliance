import asyncio
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from pch.demo.generator import generate_world
from pch.demo.transport import parse_world_time
from pch.orchestrator import ScanConfig, Scanner
from pch.settings import Policy, Scope
from pch.sources import demo_sources
from pch.web.app import create_app


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("web")
    db = f"sqlite:///{tmp}/web.db"
    base = datetime(2026, 10, 1, 12, 0, 0)
    for k in (1, 0):  # two snapshots so the trend has data
        w = generate_world(seed=11, repos=70, quality_shift=-0.05 * k, now=base - timedelta(days=14 * k))
        src = demo_sources(w)
        cfg = ScanConfig(scope=Scope(projects=w["meta"]["projects"]), policy=Policy(approved_registries=["contosoacr.azurecr.io"]), db_url=db, mode="demo", now=parse_world_time(w))

        async def go(src=src, cfg=cfg, k=k):
            try:
                await Scanner(src, cfg).run(f"scan-{k}")
            finally:
                await src.aclose()

        asyncio.run(go())
    return TestClient(create_app(db))


PAGES = ["/", "/repos", "/findings", "/rules", "/testing", "/targets", "/migration", "/scans"]


@pytest.mark.parametrize("path", PAGES)
def test_pages_render_real_content(client, path):
    r = client.get(path)
    assert r.status_code == 200
    assert "Pipeline Compliance Hub" in r.text
    assert "Traceback" not in r.text and "UndefinedError" not in r.text


def test_overview_content(client):
    t = client.get("/").text
    for needle in ("Repos scanned", "Compliant", "Critical findings", "Repos with no tests", "Classic repos", "Top 10 failing rules", "Heatmap", "Trend across scans"):
        assert needle in t
    assert "new Chart" in t or "pchChart" in t


def test_repos_filters_sort_and_csv(client):
    all_rows = client.get("/api/v1/repos").json()["repos"]
    assert len(all_rows) >= 60
    nt = client.get("/api/v1/repos", params={"test_state": "NO_TESTS"}).json()["repos"]
    assert nt and all(r["test_state"] == "NO_TESTS" for r in nt)
    classic = client.get("/api/v1/repos", params={"platform": "classic"}).json()["repos"]
    assert classic and all("classic" in r["platform_kinds"] for r in classic)
    srt = client.get("/api/v1/repos", params={"sort": "score", "dir": "asc"}).json()["repos"]
    scores = [r["score"] for r in srt if r["score"] is not None]
    assert scores == sorted(scores)
    page = client.get("/repos", params={"project": "Payments", "status": "NON_COMPLIANT"}).text
    assert 'hx-get="/repos"' in page
    csv = client.get("/repos.csv", params={"project": "Payments"})
    assert csv.status_code == 200 and csv.text.startswith("project,repo,owner") and "Payments" in csv.text
    assert "text/csv" in csv.headers["content-type"]


def test_repo_detail_page_and_json(client):
    row = client.get("/api/v1/repos", params={"status": "NON_COMPLIANT"}).json()["repos"][0]
    page = client.get(f"/repos/{row['project']}/{row['repo']}")
    assert page.status_code == 200
    for needle in ("Findings by category", "Test state", "Pipelines", "GitHub Actions readiness", "Fix:"):
        assert needle in page.text
    js = client.get(f"/api/v1/repos/{row['project']}/{row['repo']}").json()
    assert js["categories"] and js["repo"]["status"] == "NON_COMPLIANT"
    fails = [f for c in js["categories"] for f in c["findings"] if f["status"] == "FAIL"]
    assert fails and all(f["remediation"] for f in fails if f["rule_id"] != "COLLECTION-ERROR")
    assert client.get("/repos/Nope/missing").status_code == 404
    assert client.get("/api/v1/repos/Nope/missing").status_code == 404


def test_rules_catalog_and_drilldown(client):
    rules = client.get("/api/v1/rules").json()["rules"]
    assert len(rules) == 53
    failing = next(r for r in rules if r["fail"] > 0)
    page = client.get(f"/rules/{failing['id']}")
    assert page.status_code == 200 and failing["id"] in page.text and "How to fix" in page.text
    d = client.get(f"/api/v1/rules/{failing['id']}").json()
    assert d["findings"] and d["rule"]["remediation"]
    assert client.get("/rules/NOPE-999").status_code == 404


def test_findings_filters(client):
    d = client.get("/api/v1/findings", params={"severity": "critical", "status": "FAIL"}).json()
    assert d["total"] > 0 and all(f["severity"] == "critical" and f["status"] == "FAIL" for f in d["items"])
    p = client.get("/findings", params={"category": "DEP", "status": "FAIL"})
    assert p.status_code == 200 and "DEP-" in p.text


def test_testing_targets_migration_json(client):
    t = client.get("/api/v1/testing").json()
    assert set(t["counts"]) == {"TESTS_OK", "TESTS_LOW_COVERAGE", "TESTS_NO_COVERAGE", "TESTS_NOT_RUN", "NO_TESTS", "NOT_APPLICABLE"} and t["lists"]["NO_TESTS"]
    tg = client.get("/api/v1/targets").json()
    assert {x["target"] for x in tg["targets"]} == {"functionapp", "webapp", "aks", "adf", "synapse", "sql", "iac"}
    assert any(x["rules"] for x in tg["targets"])
    m = client.get("/api/v1/migration").json()
    assert m["classic_total"] > 0 and m["yaml_total"] > 0 and sum(m["buckets"].values()) > 0


def test_scans_and_scan_param(client):
    s = client.get("/api/v1/scans").json()
    assert len(s["scans"]) == 2 and s["scans"][0]["status"] == "complete"
    old = client.get("/api/v1/overview", params={"scan": "scan-1"}).json()
    new = client.get("/api/v1/overview").json()
    assert old["scan_id"] == "scan-1" and new["scan_id"] == "scan-0"
    assert len(new["trend"]) == 2
    assert client.get("/scans", params={"selected": "scan-1"}).status_code == 200
    assert client.get("/", params={"scan": "scan-1"}).status_code == 200


def test_health_and_report_only(client):
    assert client.get("/api/v1/health").json()["status"] == "ok"
    app = client.app
    for route in app.routes:
        methods = getattr(route, "methods", None) or set()
        assert methods <= {"GET", "HEAD"}, f"{route.path} exposes {methods}"  # no mutating endpoints at all


def test_empty_database_shows_guidance(tmp_path):
    c = TestClient(create_app(f"sqlite:///{tmp_path}/empty.db"))
    r = c.get("/")
    assert r.status_code == 200 and "pch seed-demo" in r.text
    assert c.get("/repos").status_code == 200 and c.get("/api/v1/overview").status_code == 404
