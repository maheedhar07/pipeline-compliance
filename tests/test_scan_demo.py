import asyncio
import json
from datetime import datetime

import httpx
import pytest
from typer.testing import CliRunner

from pch.cli import app
from pch.demo.generator import generate_world
from pch.demo.transport import DemoTransport, load_world, parse_world_time, save_world
from pch.engine.registry import all_rules
from pch.orchestrator import ScanConfig, Scanner
from pch.providers import LocalArtifactStore
from pch.settings import Policy, Scope, Waiver
from pch.sources import cache_sources, demo_sources
from pch.store import repository as store
from pch.store.db import session_scope
from tests.builders import ALL_HOSTS

SECRET_VALUE = "S3cr3t-Value-Do-Not-Store-123"


@pytest.fixture(scope="module")
def world():
    return generate_world(seed=7, repos=60, now=datetime(2026, 10, 1, 12, 0, 0))


def run_scan(world, db, record_to=None, policy=None, scope=None):
    src = demo_sources(world, record_to=LocalArtifactStore(record_to) if record_to else None)
    cfg = ScanConfig(scope=scope or Scope(code_hosts=ALL_HOSTS, projects=world["meta"]["projects"], repos=[]), policy=policy or Policy(approved_registries=["contosoacr.azurecr.io"]),
                     db_url=db, mode="demo", now=parse_world_time(world))
    sid = f"t-{abs(hash(db)) % 10000}"

    async def go():
        try:
            return await Scanner(src, cfg).run(sid)
        finally:
            await src.aclose()

    return asyncio.run(go()), sid


def test_world_is_deterministic_and_raw_payloads(world):
    again = generate_world(seed=7, repos=60, now=datetime(2026, 10, 1, 12, 0, 0))
    assert json.dumps(world, sort_keys=True) == json.dumps(again, sort_keys=True)
    pr = world["ado"]["Payments"]
    some = next(iter(pr["build_defs"].values()))
    assert "process" in some and "repository" in some  # raw ADO shapes, not canonical model rows
    assert not any("rule" in k for k in world)


def test_world_shape_280():
    w = generate_world(seed=1, repos=280)
    from pch.collectors.ado.repo_discovery import discover

    assert len(w["ado"]) == 6
    discovered = [r for p in w["ado"].values() for r in discover(p["repos"], list(p["build_defs"].values()), list(p["release_defs"].values())).repos]
    azure = [r for r in discovered if not r.external]
    github = [r for r in discovered if r.provider == "github"]
    assert len(azure) == sum(len(p["repos"]) for p in w["ado"].values()) and len(azure) + len(github) == len(discovered)
    # ~70% of the estate lives on GitHub (repos without any ADO pipeline are invisible to Azure DevOps by definition)
    assert 0.55 < len(github) / 280 < 0.75 and len(azure) > 60 and len(discovered) > 250
    assert all(r.url.startswith("https://github.com/") and not r.url.endswith(".git") and r.service_connection_id for r in github)
    assert not any("/" in r["name"] for p in w["ado"].values() for r in p["repos"])  # Azure Repos names never look like org/repo
    assert sum(1 for p in w["ado"].values() for d in p["release_defs"].values() if d["artifacts"] and d["artifacts"][0]["type"] == "GitHub") >= 5
    kinds = {"classic": 0, "yaml": 0}
    for pr in w["ado"].values():
        for d in pr["build_defs"].values():
            kinds["yaml" if d["process"]["type"] == 2 else "classic"] += 1
    assert kinds["classic"] > kinds["yaml"] * 0.9 and kinds["yaml"] > 60


def test_full_scan_through_real_collectors(world, tmp_path):
    db = f"sqlite:///{tmp_path}/a.db"
    res, sid = run_scan(world, db)
    assert res.repos >= 55 and res.findings > 1000
    rules = {r.id for r in all_rules()}
    with session_scope(db) as s:
        assert store.get_scan(s, sid).status == "complete"
        rows = store.repo_results(s, sid)
        seen = {f.rule_id for f in store.findings(s, sid)}
        assert len(seen & rules) > 40  # the catalog really fires
        assert {r.status for r in rows} <= {"COMPLIANT", "AT_RISK", "NON_COMPLIANT", "NOT_SCANNED"}
        assert any(r.test_state == "NO_TESTS" for r in rows) and any(r.test_state == "TESTS_NOT_RUN" for r in rows)
        assert any(r.migration_score is not None for r in rows)
        assert any(r.sonar_gate for r in rows) and any(r.aikido_criticals is not None for r in rows)


def test_error_tolerance_records_collection_errors(world, tmp_path):
    w = json.loads(json.dumps(world))
    pr = w["ado"]["Payments"]
    pr["faulty_defs"] = [int(k) for k in pr["build_defs"]][:2]  # build definition detail -> HTTP 500
    w["sonar"] = {k: dict(v, error500=True) for k, v in w["sonar"].items()}  # every Sonar call fails
    db = f"sqlite:///{tmp_path}/b.db"
    res, sid = run_scan(w, db)
    assert res.errors > 3 and res.repos > 50  # the scan completed regardless
    with session_scope(db) as s:
        errs = store.collection_errors(s, sid)
        assert any(e.source == "sonar" for e in errs) and any("build definition" in e.subject for e in errs)
        assert any(f.rule_id == "COLLECTION-ERROR" for f in store.findings(s, sid))
        assert store.get_scan(s, sid).status == "complete"


def test_waivers_applied_in_scan(world, tmp_path):
    db0 = f"sqlite:///{tmp_path}/c0.db"
    _, sid0 = run_scan(world, db0)
    with session_scope(db0) as s:
        f = next(x for x in store.findings(s, sid0, rule_id="SRC-004") if x.status == "FAIL")
        repo_key = f.repo_key
    pol = Policy(waivers=[Waiver(rule="SRC-004", repo=repo_key, reason="r", owner="o", expires=datetime(2027, 1, 1).date())])
    db1 = f"sqlite:///{tmp_path}/c1.db"
    _, sid1 = run_scan(world, db1, policy=pol)
    with session_scope(db1) as s:
        fs = [x for x in store.findings(s, sid1, repo_key=repo_key, rule_id="SRC-004")]
        assert fs and all(x.status == "WAIVED" and x.original_status == "FAIL" for x in fs)


def test_cache_has_no_secrets_and_replay_reproduces(world, tmp_path):
    cache = tmp_path / "raw" / "scan1"
    db = f"sqlite:///{tmp_path}/d.db"
    res, sid = run_scan(world, db, record_to=cache)
    files = list(cache.rglob("*.json"))
    assert len(files) > 500
    blob = "\n".join(f.read_text() for f in files)
    assert SECRET_VALUE not in blob  # secret values are redacted before caching
    # the secret value is also absent from the DB
    import sqlite3

    con = sqlite3.connect(tmp_path / "d.db")
    dump = "\n".join(str(r) for t in ("repo_results", "findings") for r in con.execute(f"select * from {t}"))
    assert SECRET_VALUE not in dump
    # replay from cache
    from pch.settings import Settings

    src = cache_sources(LocalArtifactStore(cache), Settings(ado_org="x"), demo=True)
    cfg = ScanConfig(scope=Scope(code_hosts=ALL_HOSTS, projects=world["meta"]["projects"]), policy=Policy(approved_registries=["contosoacr.azurecr.io"]), db_url=f"sqlite:///{tmp_path}/e.db", mode="cache", now=parse_world_time(world))

    async def go():
        try:
            return await Scanner(src, cfg).run("replay")
        finally:
            await src.aclose()

    rep = asyncio.run(go())
    assert rep.repos == res.repos
    assert rep.status_counts == res.status_counts  # reproducible from the cache alone


def test_scan_never_mutates(world, tmp_path):
    """Every request that leaves the scanner is a GET, except the documented preview/token POSTs."""
    seen: list[tuple[str, str]] = []

    class Spy(DemoTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            seen.append((request.method, request.url.path))
            return await super().handle_async_request(request)

    from pch.collectors.ado.client import AdoClient
    from pch.demo import payloads as P
    from pch.sources import Sources

    t = Spy(world)
    src = Sources(ado=AdoClient(P.ORG, "demo", transport=t, backoff_base=0, max_attempts=1))
    cfg = ScanConfig(scope=Scope(code_hosts=ALL_HOSTS, projects=["Payments"]), policy=Policy(), db_url=f"sqlite:///{tmp_path}/spy.db", mode="demo", now=parse_world_time(world))

    async def go():
        try:
            await Scanner(src, cfg).run("spy")
        finally:
            await src.aclose()

    asyncio.run(go())
    methods = {m for m, _ in seen}
    assert methods <= {"GET", "POST"}
    assert all(p.endswith("/preview") for m, p in seen if m == "POST") and any(m == "POST" for m, _ in seen)


def test_cli_seed_and_scan(tmp_path):
    runner = CliRunner()
    d = str(tmp_path / "data")
    r = runner.invoke(app, ["seed-demo", "--repos", "30", "--data-dir", d])
    assert r.exit_code == 0 and (tmp_path / "data/demo/world.json.gz").exists()
    r = runner.invoke(app, ["scan", "--demo", "--data-dir", d, "--history", "1"])
    assert r.exit_code == 0, r.output
    with session_scope(f"sqlite:///{d}/pch.db") as s:
        scans = store.list_scans(s)
        assert len(scans) == 2 and all(x.status == "complete" for x in scans)
        assert scans[0].repos_total >= 15  # default code_hosts=[github]: ~70% of the demo estate
    w = load_world(tmp_path / "data/demo/world.json.gz")
    save_world(w, tmp_path / "w2.json.gz")


def test_scan_without_credentials_fails_cleanly():
    r = CliRunner().invoke(app, ["scan"], env={"ADO_ORG": ""})
    assert r.exit_code == 2 and "ADO_ORG" in r.output


def test_demo_github_estate_is_scanned_through_real_collectors(world, tmp_path):
    """~70% of the demo estate is GitHub-hosted: pipelines/releases live in ADO, the code does not."""
    seen: list[str] = []

    class Spy(DemoTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            seen.append(request.url.path)
            return await super().handle_async_request(request)

    from pch.collectors.ado.client import AdoClient
    from pch.demo import payloads as P
    from pch.sources import Sources

    src = Sources(ado=AdoClient(P.ORG, "demo", transport=Spy(world), backoff_base=0, max_attempts=1))
    db = f"sqlite:///{tmp_path}/gh.db"
    cfg = ScanConfig(scope=Scope(code_hosts=ALL_HOSTS, projects=world["meta"]["projects"]), policy=Policy(approved_registries=["contosoacr.azurecr.io"]), db_url=db, mode="demo", now=parse_world_time(world))

    async def go():
        try:
            return await Scanner(src, cfg).run("gh")
        finally:
            await src.aclose()

    asyncio.run(go())
    with session_scope(db) as s:
        rows = store.repo_results(s, "gh")
        gh = [r for r in rows if r.external["repo"]["provider"] == "github"]
        az = [r for r in rows if r.external["repo"]["provider"] == "azure_repos"]
        assert len(gh) > len(az) > 5 and all("/" in r.repo and r.url.startswith("https://github.com/") for r in gh)
        assert not any("/" in r.repo for r in az)
        errs = [e.message for e in store.collection_errors(s, "gh")]
        # releases consuming GitHub repos (directly or via a build) are linked; only the deliberate demo orphans (L2) are not
        assert sum("not linked" in m for m in errs) <= 2  # the two deliberate demo orphans, nothing else
        assert any(p["platform"] == "ado_classic_release" for r in gh for p in r.pipelines)
        assert any(p["platform"] == "ado_yaml" for r in gh for p in r.pipelines) and any(p["platform"] == "ado_classic_build" for r in gh for p in r.pipelines)
        assert all(r.facts["facts_source"] == "unavailable" for r in gh) and all(r.facts["facts_source"] == "ado_items" for r in az)
        gh_keys = {r.repo_key for r in gh}
        by = {}
        for f in store.findings(s, "gh"):
            if f.repo_key in gh_keys:
                by.setdefault(f.rule_id, set()).add(f.status)
        assert by["SRC-001"] == {"UNKNOWN"} and by["SRC-002"] == {"UNKNOWN"} and by["SRC-003"] == {"UNKNOWN"}
        assert "FAIL" not in by.get("TST-001", set()) and "FAIL" not in by.get("TST-002", set())
        assert {r.test_state for r in gh} <= {"UNKNOWN", "TESTS_OK", "TESTS_LOW_COVERAGE", "TESTS_NO_COVERAGE", "NOT_APPLICABLE"}  # never NO_TESTS / TESTS_NOT_RUN
        assert any(r.test_state == "UNKNOWN" for r in gh)
        assert by["SRC-004"] & {"FAIL", "PASS"}  # pipeline-definition rules evaluate normally
    gh_ids = {r["id"] for p in world["ado"].values() for d in p["build_defs"].values() if d["repository"]["type"] == "GitHub" for r in [d["repository"]]}
    assert gh_ids
    assert not any("/git/repositories/" in p and any(i in p for i in gh_ids) for p in seen)  # no Items API call for GitHub repos
