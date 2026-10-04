"""Persistence portability suite.

Runs against SQLite (tmp file) by default. Set ``TEST_DATABASE_URL`` to run the same tests against
PostgreSQL / SQL Server (CI ``db-matrix``). The target database must be disposable: it is wiped.
"""

import asyncio
import os
from datetime import UTC, datetime, timedelta, timezone

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import func, insert, inspect, select, text
from typer.testing import CliRunner

from pch.cli import app
from pch.demo.generator import generate_world
from pch.demo.transport import parse_world_time
from pch.orchestrator import ScanConfig, Scanner
from pch.retention import delete_scan_rows
from pch.settings import Policy, Scope, Settings
from pch.sources import demo_sources
from pch.store import locks, migrate
from pch.store import repository as store
from pch.store.db import (
    SchemaNotReadyError,
    db_ready,
    ensure_schema,
    get_engine,
    get_raw_engine,
    reset_engines,
    session_scope,
)
from pch.store.models import Base, CollectionErrorRow, FindingRow, LineageRow, RepoResultRow, ScanRow
from pch.timeutil import utcnow
from tests.builders import ALL_HOSTS

runner = CliRunner()
REMOTE = os.environ.get("TEST_DATABASE_URL")


def _wipe(engine):
    Base.metadata.drop_all(engine)
    with engine.begin() as c:
        c.execute(text("DROP TABLE IF EXISTS alembic_version")) if engine.dialect.name != "mssql" else c.execute(
            text("IF OBJECT_ID('alembic_version', 'U') IS NOT NULL DROP TABLE alembic_version")
        )


@pytest.fixture
def raw_url(tmp_path):
    """URL of an EMPTY database (no tables)."""
    reset_engines()
    url = REMOTE or f"sqlite:///{tmp_path}/portable.db"
    if REMOTE:
        from pch.store.engine import build_engine

        e = build_engine(url)
        _wipe(e)
        e.dispose()
    yield url
    if REMOTE:
        _wipe(get_raw_engine(url))
    reset_engines()


@pytest.fixture
def url(raw_url):
    """URL of a database migrated to head."""
    migrate.upgrade(get_raw_engine(raw_url))
    return raw_url


@pytest.fixture
def engine(url):
    return get_engine(url)


def tables(engine):
    return set(inspect(engine).get_table_names())


# ------------------------------------------------------------------ migrations
def test_upgrade_empty_to_head_and_downgrade_base(raw_url):
    eng = get_raw_engine(raw_url)
    assert migrate.db_state(eng).current is None
    migrate.upgrade(eng)
    st = migrate.db_state(eng)
    assert st.at_head and st.current == migrate.head_revision()
    assert migrate.APP_TABLES <= tables(eng)
    migrate.downgrade(eng, "base")
    assert not (migrate.APP_TABLES & tables(eng))
    migrate.upgrade(eng)  # and back up again
    assert migrate.db_state(eng).at_head


def test_upgrade_from_0001_with_existing_data_keeps_it_and_adds_lineage(raw_url):
    """An existing database (revision 0001, with a scan and repo results) upgrades to head without touching its data."""
    eng = get_raw_engine(raw_url)
    migrate.upgrade(eng, "0001")
    assert migrate.db_state(eng).current == "0001" and "lineage" not in tables(eng)
    with eng.begin() as c:
        c.execute(insert(ScanRow.__table__), [dict(id="old-1", started_at=datetime(2026, 9, 1, 12, 0, 0), mode="live", status="complete", repos_total=1, repos_failed=0, findings_total=0, summary={})])
        c.execute(insert(RepoResultRow.__table__), [dict(scan_id="old-1", repo_key="P/r", project="P", repo="r", url="", platform_mix=[], targets=["aks"], test_state="NO_TESTS", test_state_reason="",
                                                         status="AT_RISK", unknowns=0, critical_fails=0, high_fails=0, migration_blockers=[], facts={}, pipelines=[], rule_status={}, external_summary={})])
    migrate.upgrade(eng)
    assert migrate.db_state(eng).at_head and "lineage" in tables(eng)
    with session_scope(raw_url) as s:
        assert store.get_scan(s, "old-1").status == "complete"
        assert store.repo_result(s, "old-1", "P/r").targets == ["aks"]
        assert store.lineage_rows(s, "old-1") == []  # pre-lineage scans simply have no lineage
        s.add(LineageRow(scan_id="old-1", repo_key="P/r", project="P", doc={"repo": {"key": "P/r"}}))
    migrate.downgrade(eng, "0001")
    assert "lineage" not in tables(eng)
    with session_scope(raw_url) as s:  # downgrade drops only the lineage table
        assert store.repo_result(s, "old-1", "P/r") is not None


def test_models_and_migrations_in_sync(url):
    """Autogenerate against the models must produce NO diff."""
    with get_raw_engine(url).connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": migrate.compare_type})
        diff = compare_metadata(ctx, Base.metadata)
    assert diff == [], diff


# ------------------------------------------------------------------ full demo scan write + read
def test_demo_scan_roundtrip(url):
    world = generate_world(seed=7, repos=12, now=datetime(2026, 10, 1, 12, 0, 0))
    src = demo_sources(world)
    cfg = ScanConfig(scope=Scope(code_hosts=ALL_HOSTS, projects=world["meta"]["projects"]), policy=Policy(approved_registries=["contosoacr.azurecr.io"]),
                     db_url=url, mode="demo", now=parse_world_time(world))

    async def go():
        try:
            return await Scanner(src, cfg).run("portable-demo")
        finally:
            await src.aclose()

    res = asyncio.run(go())
    assert res.repos == 12
    with session_scope(url) as s:
        scan = store.get_scan(s, "portable-demo")
        assert scan.status == "complete" and scan.repos_total == 12
        assert scan.started_at == datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
        assert scan.finished_at.tzinfo is not None and scan.finished_at >= scan.started_at
        rows = store.repo_results(s, "portable-demo")
        assert len(rows) == 12 and all(isinstance(r.facts, dict) and isinstance(r.pipelines, list) for r in rows)
        assert len(store.findings(s, "portable-demo")) == res.findings
        assert store.latest_scan(s).id == "portable-demo"


def test_lineage_roundtrip_unicode_and_delete(url):
    """Lineage documents (JSON incl. unicode and ISO dates) round-trip; a scan's lineage is deleted with it, chunked."""
    from pch.model.lineage import LDeploy, LPipeline, LRepo, LStage, RepoLineage
    from pch.orchestrator import lineage_row_dicts

    lins = {}
    for i in range(450):  # 450 rows x 12 columns: more bound parameters than SQL Server allows in one statement
        key = f"Pröjekt/org/répo-{i}"
        lins[key] = RepoLineage(repo=LRepo(key=key, project="Pröjekt", name=f"org/répo-{i}", provider="github"), pipelines=[LPipeline(
            id=str(i), name="日本語-ci", kind="yaml", stages=[LStage(name="Prod", env_tier="prod", last_deploy=LDeploy(status="succeeded", version="v✓", finished=datetime(2026, 10, 1, 8, 9, 30)))])])
    with session_scope(url) as s:
        store.create_scan(s, "lin1", "demo")
        store.create_scan(s, "lin2", "demo")
        store.insert_rows(s, LineageRow, lineage_row_dicts("lin1", lins, {"Pröjekt": []}))
        store.insert_rows(s, LineageRow, lineage_row_dicts("lin2", {k: lins[k] for k in list(lins)[:3]}, {}))
    with session_scope(url) as s:
        rows = store.lineage_rows(s, "lin1")
        assert len(rows) == 450 and all(r.kind == "repo" and r.has_prod and r.provider == "github" and r.tiers == ",prod," for r in rows)
        back = RepoLineage.model_validate(next(r for r in rows if r.repo_key.endswith("répo-7")).doc)
        assert back.pipelines[0].name == "日本語-ci" and back.pipelines[0].stages[0].last_deploy.finished == datetime(2026, 10, 1, 8, 9, 30)
    delete_scan_rows(url, "lin1", chunk=100)
    with session_scope(url) as s:
        assert store.lineage_rows(s, "lin1") == [] and len(store.lineage_rows(s, "lin2")) == 3
        store.delete_scan(s, "lin2")
    with session_scope(url) as s:
        assert s.scalar(select(func.count()).select_from(LineageRow)) == 0


# ------------------------------------------------------------------ types
def test_datetimes_are_tz_aware_utc_roundtrip(url):
    ist = timezone(timedelta(hours=5, minutes=30))
    cases = {
        "tz-a": (datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=ist), datetime(2026, 1, 1, 21, 34, 5, 123456, tzinfo=UTC)),
        "tz-b": (datetime(2026, 1, 2, 3, 4, 5), datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)),  # naive == UTC
        "tz-c": (datetime(2026, 6, 30, 23, 59, 59, tzinfo=UTC), datetime(2026, 6, 30, 23, 59, 59, tzinfo=UTC)),
    }
    with session_scope(url) as s:
        for sid, (given, _) in cases.items():
            store.create_scan(s, sid, "demo", given)
    with session_scope(url) as s:
        for sid, (_, want) in cases.items():
            got = store.get_scan(s, sid).started_at
            assert got.tzinfo is not None and got.utcoffset() == timedelta(0)
            assert got == want
        assert store.get_scan(s, "tz-a").finished_at is None


def test_json_roundtrip_unicode_and_nesting(url):
    ev = {"名前": "naïve café ✓ 😀", "nested": {"a": [1, 2.5, None, True], "ß": "  quote\"s"}, "empty": {}}
    with session_scope(url) as s:
        store.create_scan(s, "j1", "demo")
        s.add(FindingRow(scan_id="j1", repo_key="Pröjekt/répo", rule_id="X-1", category="SYS", severity="info", status="PASS",
                         message="héllo wörld ✓", evidence=ev, waiver={"owner": "ünï", "reason": "x" * 3000}, pipeline_name="日本語"))
        s.add(RepoResultRow(scan_id="j1", repo_key="Pröjekt/répo", project="Pröjekt", repo="répo", status="PASS", facts=ev, pipelines=[ev], external={"k": "ü"}))
    with session_scope(url) as s:
        f = store.findings(s, "j1")[0]
        assert f.evidence == ev and f.waiver["owner"] == "ünï" and len(f.waiver["reason"]) == 3000
        assert f.message == "héllo wörld ✓" and f.pipeline_name == "日本語" and f.repo_key == "Pröjekt/répo"
        r = store.repo_result(s, "j1", "Pröjekt/répo")
        assert r.facts == ev and r.pipelines == [ev] and r.external == {"k": "ü"}


def test_long_text_and_indexed_key_lengths(url):
    long = "é" * 20000
    key = "P" * 100 + "/" + "r" * 199  # 300 chars = max indexed length
    with session_scope(url) as s:
        store.create_scan(s, "L" * 40, "demo")
        s.add(CollectionErrorRow(scan_id="L" * 40, source="ado", subject=key, message=long))
        s.add(RepoResultRow(scan_id="L" * 40, repo_key=key, project="p" * 200, repo="r" * 200, status="PASS", url=long))
    with session_scope(url) as s:
        assert store.collection_errors(s, "L" * 40)[0].message == long
        assert store.repo_results(s, "L" * 40)[0].url == long


# ------------------------------------------------------------------ bulk + delete
def _finding_dict(i, scan="bulk"):
    return dict(scan_id=scan, repo_key=f"P/r{i % 50}", rule_id=f"R-{i % 7}", category="SYS", severity="low", status="FAIL", message=f"m{i}",
                evidence={"i": i}, pipeline_id=None, pipeline_name=None, stage=None, link=None, waiver=None, original_status=None)


def test_chunked_bulk_insert_over_2100_parameters(url):
    n = 700  # 700 rows x 15 columns = 10.5k bound parameters, far above the 2100 SQL Server limit
    with session_scope(url) as s:
        store.create_scan(s, "bulk", "demo")
        store.insert_rows(s, FindingRow, [_finding_dict(i) for i in range(n)])
    with session_scope(url) as s:
        assert s.scalar(select(func.count()).select_from(FindingRow).where(FindingRow.scan_id == "bulk")) == n
        # ORM unit-of-work path too
        for i in range(n, n + 400):
            s.add(FindingRow(**_finding_dict(i)))
    with session_scope(url) as s:
        assert s.scalar(select(func.count()).select_from(FindingRow)) == n + 400


def test_in_clause_chunking_and_chunked_helper(url):
    with session_scope(url) as s:
        store.create_scan(s, "inq", "demo")
        store.insert_rows(s, FindingRow, [_finding_dict(i, "inq") for i in range(30)])
    with session_scope(url) as s:
        ids = list(s.scalars(select(FindingRow.id).where(FindingRow.scan_id == "inq")))
        rows = store.select_where_in(s, FindingRow, FindingRow.id, ids + list(range(10_000, 15_000)))  # 5030 values
        assert len(rows) == 30
    assert [len(c) for c in store.chunked(range(5), 2)] == [2, 2, 1]


def test_delete_scan_removes_everything_and_only_that_scan(url):
    with session_scope(url) as s:
        for sid in ("keep", "gone"):
            store.create_scan(s, sid, "demo")
            s.add(RepoResultRow(scan_id=sid, repo_key="P/r", project="P", repo="r", status="PASS"))
            s.add(CollectionErrorRow(scan_id=sid, source="ado", subject="x", message="y"))
            store.insert_rows(s, FindingRow, [_finding_dict(i, sid) for i in range(300)])
    with session_scope(url) as s:
        store.delete_scan(s, "gone")
    with session_scope(url) as s:
        assert store.get_scan(s, "gone") is None
        for model in (FindingRow, RepoResultRow, CollectionErrorRow):
            assert s.scalar(select(func.count()).select_from(model).where(model.scan_id == "gone")) == 0
            assert s.scalar(select(func.count()).select_from(model).where(model.scan_id == "keep")) > 0
        assert store.get_scan(s, "keep") is not None


# ------------------------------------------------------------------ scan lock
def test_scan_lock_acquire_conflict_release(engine):
    h1 = locks.acquire(engine)
    with pytest.raises(locks.ScanLockHeld, match="another scan is running"):
        locks.acquire(engine)
    locks.release(engine, "someone-else")  # releasing with a foreign token is a no-op
    with pytest.raises(locks.ScanLockHeld):
        locks.acquire(engine)
    locks.release(engine, h1)
    h2 = locks.acquire(engine)
    assert h2 != h1
    locks.release(engine, h2)


def test_scan_lock_stale_takeover(engine, caplog):
    old = locks.acquire(engine, now=utcnow() - timedelta(hours=7))
    with caplog.at_level("WARNING", logger="pch.lock"):
        new = locks.acquire(engine, stale_after=timedelta(hours=6))
    assert "stale" in caplog.text
    locks.release(engine, old)  # the previous (dead) holder must not free the new owner's lock
    with pytest.raises(locks.ScanLockHeld):
        locks.acquire(engine)
    locks.release(engine, new)


def test_scan_lock_not_stale_inside_window(engine):
    h = locks.acquire(engine, now=utcnow() - timedelta(hours=5))
    with pytest.raises(locks.ScanLockHeld):
        locks.acquire(engine, stale_after=timedelta(hours=6))
    locks.release(engine, h)


def test_scan_lock_released_on_error(engine):
    with pytest.raises(RuntimeError, match="boom"), locks.scan_lock(engine):
        raise RuntimeError("boom")
    locks.release(engine, locks.acquire(engine))  # acquirable again


# ------------------------------------------------------------------ scan failure handling
def _cfg(world, url, **kw):
    return ScanConfig(scope=Scope(code_hosts=ALL_HOSTS, projects=world["meta"]["projects"]), policy=Policy(), db_url=url, mode="demo", now=parse_world_time(world), **kw)


@pytest.fixture(scope="module")
def small_world():
    return generate_world(seed=3, repos=6, now=datetime(2026, 10, 1, 12, 0, 0))


def run(world, cfg, sid):
    src = demo_sources(world)

    async def go():
        try:
            return await Scanner(src, cfg).run(sid)
        finally:
            await src.aclose()

    return asyncio.run(go())


def test_persist_failure_rolls_back_and_marks_scan_failed(url, small_world, monkeypatch):
    real = store.get_scan

    def exploding(s, scan_id):  # called at the very end of persist(), after all rows were added
        real(s, scan_id)
        raise RuntimeError("db went away")

    monkeypatch.setattr(store, "get_scan", exploding)
    with pytest.raises(RuntimeError, match="db went away"):
        run(small_world, _cfg(small_world, url), "atomic-1")
    monkeypatch.undo()
    with session_scope(url) as s:
        scan = real(s, "atomic-1")
        assert scan.status == "failed" and "db went away" in scan.summary["error"] and scan.finished_at is not None
        assert s.scalar(select(func.count()).select_from(RepoResultRow)) == 0  # nothing half-written
        assert s.scalar(select(func.count()).select_from(FindingRow)) == 0
        assert store.latest_scan(s) is None  # failed scans are never shown as results


def test_crash_during_collection_marks_failed(url, small_world, monkeypatch):
    async def boom(self, scan_id):
        raise asyncio.CancelledError()

    monkeypatch.setattr(Scanner, "_run", boom)
    with pytest.raises(asyncio.CancelledError):
        run(small_world, _cfg(small_world, url), "crash-1")
    with session_scope(url) as s:
        assert store.get_scan(s, "crash-1").status == "failed"


def test_orphaned_running_scans_are_failed_on_next_scan(url, small_world):
    with session_scope(url) as s:
        store.create_scan(s, "orphan-old", "live", utcnow() - timedelta(hours=8))
        store.create_scan(s, "running-fresh", "live", utcnow() - timedelta(minutes=5))
    run(small_world, _cfg(small_world, url, stale_after=timedelta(hours=6)), "after-orphan")
    with session_scope(url) as s:
        assert store.get_scan(s, "orphan-old").status == "failed"
        assert "orphaned" in store.get_scan(s, "orphan-old").summary["error"]
        assert store.get_scan(s, "running-fresh").status == "running"  # could still be alive
        assert store.get_scan(s, "after-orphan").status == "complete"


# ------------------------------------------------------------------ schema policy / readiness
def _settings(**kw):
    return Settings(_env_file=None, **kw)


def test_prod_never_auto_migrates_unless_opted_in(raw_url):
    eng = get_raw_engine(raw_url)
    with pytest.raises(SchemaNotReadyError, match="pch db upgrade"):
        ensure_schema(eng, _settings(app_env="prod"))
    assert not (migrate.APP_TABLES & tables(eng))  # untouched
    ensure_schema(eng, _settings(app_env="prod", db_auto_migrate=True))
    assert migrate.db_state(eng).at_head


@pytest.mark.skipif(bool(REMOTE), reason="sqlite-only policy")
def test_sqlite_dev_auto_migrates_but_prod_refuses(tmp_path):
    reset_engines()
    eng = get_raw_engine(f"sqlite:///{tmp_path}/a.db")
    ensure_schema(eng, _settings(app_env="dev"))
    assert migrate.db_state(eng).at_head
    eng2 = get_raw_engine(f"sqlite:///{tmp_path}/b.db")
    with pytest.raises(SchemaNotReadyError):
        ensure_schema(eng2, _settings(app_env="prod"))
    reset_engines()


def test_unversioned_database_gets_stamp_hint(raw_url):
    eng = get_raw_engine(raw_url)
    Base.metadata.create_all(eng)  # what the old code did
    st = migrate.db_state(eng)
    assert st.unversioned
    for env in ("dev", "prod"):
        with pytest.raises(SchemaNotReadyError, match="pch db stamp head"):
            ensure_schema(eng, _settings(app_env=env, db_auto_migrate=True))
    with pytest.raises(SchemaNotReadyError, match="stamp"):
        migrate.upgrade(eng)
    migrate.stamp(eng)
    assert migrate.db_state(eng).at_head
    ensure_schema(eng, _settings(app_env="prod"))


def test_db_ready_and_doctor_check(raw_url, monkeypatch):
    ok, reason = db_ready(raw_url)
    assert not ok and "pch db upgrade" in reason
    migrate.upgrade(get_raw_engine(raw_url))
    ok, reason = db_ready(raw_url)
    assert ok and migrate.head_revision() in reason
    from pch.doctor import check_db_migrations

    monkeypatch.setenv("DATABASE_URL", raw_url)
    c = check_db_migrations(Settings(_env_file=None))
    assert c.status == "OK" and "head" in c.detail
    migrate.downgrade(get_raw_engine(raw_url), "base")
    assert check_db_migrations(Settings(_env_file=None, app_env="prod")).status == "FAIL"


def test_db_ready_unreachable_does_not_leak_url():
    ok, reason = db_ready("sqlite:////nonexistent-dir-xyz/forbidden/p4ssw0rd.db")
    assert not ok and "p4ssw0rd" not in reason


# ------------------------------------------------------------------ CLI
def test_cli_db_commands(raw_url):
    r = runner.invoke(app, ["db", "check", "--db", raw_url])
    assert r.exit_code == 1
    r = runner.invoke(app, ["db", "current", "--db", raw_url])
    assert r.exit_code == 0 and "(none)" in r.output and migrate.head_revision() in r.output
    r = runner.invoke(app, ["db", "upgrade", "--db", raw_url])
    assert r.exit_code == 0, r.output
    r = runner.invoke(app, ["db", "check", "--db", raw_url])
    assert r.exit_code == 0 and "ok" in r.output
    r = runner.invoke(app, ["db", "upgrade", "--revision", "head", "--db", raw_url])
    assert r.exit_code == 0  # idempotent


def test_cli_db_stamp_adopts_create_all_database(raw_url):
    Base.metadata.create_all(get_raw_engine(raw_url))
    r = runner.invoke(app, ["db", "check", "--db", raw_url])
    assert r.exit_code == 1 and "stamp" in r.output
    assert runner.invoke(app, ["db", "stamp", "head", "--db", raw_url]).exit_code == 0
    assert runner.invoke(app, ["db", "check", "--db", raw_url]).exit_code == 0


def test_cli_scan_refuses_second_concurrent_scan(url, tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    from pch.settings import reset_settings

    reset_settings()
    try:
        eng = get_engine(url)
        holder = locks.acquire(eng)
        r = runner.invoke(app, ["scan", "--demo", "--data-dir", str(tmp_path), "--db", url])
        assert r.exit_code == 4 and "already running" in r.output
        locks.release(eng, holder)
    finally:
        reset_settings()


def test_cli_scan_refuses_when_not_at_head_in_prod(raw_url, tmp_path, monkeypatch):
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("DATABASE_URL", raw_url)
    from pch.settings import reset_settings

    reset_settings()
    try:
        r = runner.invoke(app, ["scan", "--demo", "--data-dir", str(tmp_path), "--db", raw_url])
        # demo data is missing in tmp_path, but the schema check must fire first (or equally exit non-zero with a clear reason)
        r2 = runner.invoke(app, ["scan", "--from-cache", "x", "--data-dir", str(tmp_path), "--db", raw_url])
        assert r2.exit_code == 3 and "not ready" in r2.output and "pch db upgrade" in r2.output
        assert r.exit_code != 0
    finally:
        reset_settings()


@pytest.mark.skipif(bool(REMOTE), reason="sqlite-only regression")
def test_cli_scan_uses_database_url_even_with_custom_data_dir(tmp_path, monkeypatch):
    """Regression: --data-dir must not silently switch the scan to a different sqlite DB."""
    from pch.settings import reset_settings

    dburl = f"sqlite:///{tmp_path}/real.db"
    data = tmp_path / "elsewhere"
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("DATABASE_URL", dburl)
    reset_settings()
    reset_engines()
    try:
        assert runner.invoke(app, ["db", "upgrade"]).exit_code == 0
        assert runner.invoke(app, ["seed-demo", "--repos", "12", "--data-dir", str(data)]).exit_code == 0
        r = runner.invoke(app, ["scan", "--demo", "--history", "0", "--data-dir", str(data)])
        assert r.exit_code == 0, r.output
        with session_scope(dburl) as s:
            assert store.latest_scan(s) is not None
        assert not (data / "pch.db").exists()
    finally:
        reset_settings()
        reset_engines()
