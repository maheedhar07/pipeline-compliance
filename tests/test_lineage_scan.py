"""Lineage through the real scan path (demo world -> real collectors -> lineage table), including fail-open behaviour."""

import asyncio
from collections import Counter
from datetime import datetime

import httpx
import pytest
from sqlalchemy import func, select

from pch.collectors.ado.client import AdoClient
from pch.demo import payloads as P
from pch.demo.generator import generate_world
from pch.demo.transport import DemoTransport, parse_world_time
from pch.model.lineage import RepoLineage
from pch.orchestrator import ScanConfig, Scanner
from pch.retention import delete_scan_rows
from pch.settings import Policy, Scope
from pch.sources import Sources
from pch.store import repository as store
from pch.store.db import session_scope
from pch.store.models import LineageRow


@pytest.fixture(scope="module")
def world():
    return generate_world(seed=42, repos=280, now=datetime(2026, 10, 1, 12, 0, 0))


def scan(world, db, transport_cls=DemoTransport, scan_id="s1", **cfg_kw):
    src = Sources(ado=AdoClient(P.ORG, "demo", transport=transport_cls(world), backoff_base=0, max_attempts=1))
    cfg = ScanConfig(scope=Scope(projects=world["meta"]["projects"]), policy=Policy(approved_registries=["contosoacr.azurecr.io"]), db_url=db, mode="demo", now=parse_world_time(world), **cfg_kw)

    async def go():
        try:
            return await Scanner(src, cfg).run(scan_id)
        finally:
            await src.aclose()

    return asyncio.run(go())


@pytest.fixture(scope="module")
def demo_db(world, tmp_path_factory):
    db = f"sqlite:///{tmp_path_factory.mktemp('lin')}/lin.db"
    scan(world, db)
    return db


def docs(db, kind="repo"):
    with session_scope(db) as s:
        return [(r, r.doc) for r in store.lineage_rows(s, "s1") if r.kind == kind]


def test_demo_lineage_is_realistic(demo_db):
    rows = docs(demo_db)
    lins = [RepoLineage.model_validate(d) for _, d in rows]
    assert len(lins) > 250
    stages = [s for lin in lins for s in lin.all_stages()]
    assert {"succeeded", "failed", "in_progress", "never", "partial"} <= {s.last_deploy.status for s in stages}  # a mix of outcomes, incl. never deployed
    assert any(s.last_deploy.triggered_by and "@" not in s.last_deploy.triggered_by for s in stages) and not any("@" in (s.last_deploy.triggered_by or "") for s in stages)
    assert any(s.last_deploy.artifact_version for s in stages)
    assert {"functionapp", "webapp", "aks", "adf", "synapse", "sql", "iac"} <= {t.kind for s in stages for t in s.targets}
    assert sum(1 for s in stages for t in s.targets if t.name) > 300  # resource names extracted from task inputs
    pipelines = [p for lin in lins for p in lin.pipelines]
    assert any(p.kind == "yaml" for p in pipelines) and any(p.kind == "classic_build" for p in pipelines)
    assert sum(len(p.downstream) for p in pipelines) >= 10  # YAML resources.pipelines + classic build completion
    assert {d.kind for p in pipelines for d in p.downstream} == {"yaml_resource", "classic_completion"}
    assert sum(1 for p in pipelines if p.yaml_in_other_repo and not p.adopted_from) == 2  # YAML living in a separate repo
    assert sum(1 for p in pipelines if p.adopted_from) == 2  # ...and shown under the code repo too
    assert any(r.sources[0].type == "GitHub" for lin in lins for r in lin.releases)  # GitHub-artifact releases
    assert any(lin.is_empty for lin in lins)  # repos without any pipeline
    # scalar columns agree with the documents
    for r, d in rows:
        lin = RepoLineage.model_validate(d)
        assert (r.repo_key, r.project, r.provider, r.has_prod, r.n_pipelines, r.n_releases) == (lin.repo.key, lin.repo.project, lin.repo.provider, lin.has_prod, len(lin.pipelines), len(lin.releases))
        assert r.targets == "," + ",".join(lin.targets) + ","


def test_demo_orphans(demo_db):
    items = [o for _, d in docs(demo_db, "orphan") for o in d["orphans"]]
    kinds = Counter((o["type"], o["reason"].split(" ")[0]) for o in items)
    assert any(o["type"] == "pipeline" and "no resolvable repository" in o["reason"] for o in items)
    assert any(o["type"] == "pipeline" and "not found in this project" in o["reason"] for o in items)
    assert any(o["type"] == "release" and "no artifact source" in o["reason"] for o in items)
    assert any(o["type"] == "release" and "AzureContainerRepository" in o["reason"] for o in items)
    assert kinds and all(o["url"].startswith("https://") for o in items)


def test_delete_scan_removes_lineage(world, tmp_path):
    db = f"sqlite:///{tmp_path}/d.db"
    scan(generate_world(seed=3, repos=30, now=datetime(2026, 10, 1, 12, 0, 0)), db)
    with session_scope(db) as s:
        assert s.scalar(select(func.count()).select_from(LineageRow)) > 20
    delete_scan_rows(db, "s1", chunk=7)
    with session_scope(db) as s:
        assert s.scalar(select(func.count()).select_from(LineageRow)) == 0


def test_lineage_disabled_makes_no_deployment_calls_and_stages_unknown(world, tmp_path):
    seen: list[str] = []

    class Spy(DemoTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            seen.append(request.url.path)
            return await super().handle_async_request(request)

    db = f"sqlite:///{tmp_path}/off.db"
    scan(generate_world(seed=3, repos=30, now=datetime(2026, 10, 1, 12, 0, 0)), db, Spy, lineage=False)
    assert not any(p.endswith(("/release/releases", "environmentdeploymentrecords")) for p in seen)
    stages = [s for _, d in docs(db) for s in RepoLineage.model_validate(d).all_stages()]
    assert stages and all(s.last_deploy.status == "unknown" for s in stages)


def test_deployment_endpoint_failures_fail_open(tmp_path):
    w = generate_world(seed=3, repos=30, now=datetime(2026, 10, 1, 12, 0, 0))

    class Broken(DemoTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            p, q = request.url.path, request.url.params
            if p.endswith("environmentdeploymentrecords") or (p.endswith("/release/deployments") and "minStartedTime" not in q):
                return httpx.Response(500, text="boom")
            return await super().handle_async_request(request)

    db = f"sqlite:///{tmp_path}/b.db"
    res = scan(w, db, Broken)  # the scan completes
    assert res.repos >= 25
    stages = [s for _, d in docs(db) for s in RepoLineage.model_validate(d).all_stages()]
    deploy_stages = [s for s in stages if s.last_deploy.status != "unknown" or s.env_name or s.name]
    assert deploy_stages and all(s.last_deploy.status == "unknown" for s in stages)  # never "never deployed" when it could not be read
    with session_scope(db) as s:
        errs = [e for e in store.collection_errors(s, "s1") if "lineage" in e.subject]
        assert errs and not any("boom" in e.message and "Traceback" in e.message for e in errs)
        assert store.get_scan(s, "s1").status == "complete"


def test_lineage_requests_are_read_only_gets(world, tmp_path):
    methods: Counter[tuple[str, str]] = Counter()

    class Spy(DemoTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if "release/deployments" in request.url.path or "release/releases" in request.url.path or "environmentdeploymentrecords" in request.url.path:
                methods[(request.method, request.url.path.rsplit("/", 1)[-1] if not request.url.path.rsplit("/", 1)[-1].isdigit() else "{id}")] += 1
            return await super().handle_async_request(request)

    scan(generate_world(seed=3, repos=30, now=datetime(2026, 10, 1, 12, 0, 0)), f"sqlite:///{tmp_path}/ro.db", Spy)
    assert methods and {m for m, _ in methods} == {"GET"}
