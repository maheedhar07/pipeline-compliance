"""Typer CLI: pch scan | serve | db | rules list | seed-demo | doctor."""

from __future__ import annotations

import typer

from pch import exitcodes

app = typer.Typer(help="Pipeline Compliance Hub (report-only)", no_args_is_help=True)
rules_app = typer.Typer(help="Inspect the rule catalog", no_args_is_help=True)
app.add_typer(rules_app, name="rules")


@app.callback()
def main() -> None:
    """Pipeline Compliance Hub: report-only CI/CD compliance scoring."""


def _bootstrap(settings, service: str):
    """Logging (redacting) + optional Application Insights for a long-running command; exits 2 on config errors."""
    from pch.logging_setup import configure_logging
    from pch.settings import ConfigError
    from pch.telemetry import setup_telemetry

    configure_logging(settings)
    try:
        setup_telemetry(settings, service)
    except ConfigError as exc:
        typer.echo(f"Config error: {exc}", err=True)
        raise typer.Exit(exitcodes.CONFIG) from None


@app.command()
def version() -> None:
    """Print the version."""
    from pch import __version__

    typer.echo(__version__)


@rules_app.command("list")
def rules_list(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category prefix, e.g. DEP"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """List every registered rule."""
    import json

    from pch.engine.registry import all_rules

    rules = [r for r in all_rules() if not category or r.category == category.upper()]
    if json_out:
        typer.echo(json.dumps([{"id": r.id, "title": r.title, "severity": r.severity.value, "scope": r.scope, "category": r.category} for r in rules], indent=2))
        return
    typer.echo(f"{'ID':<13}{'SEVERITY':<10}{'SCOPE':<10}TITLE")
    for r in rules:
        typer.echo(f"{r.id:<13}{r.severity.value:<10}{r.scope:<10}{r.title}")
    typer.echo(f"\n{len(rules)} rules")


@rules_app.command("docs")
def rules_docs(
    write: str | None = typer.Option(None, "--write", help="Write the markdown to this path (e.g. docs/RULES.md)"),
    check: bool = typer.Option(False, "--check", help="Exit 1 if --write target is out of date"),
) -> None:
    """Render docs/RULES.md from the rule registry."""
    from pathlib import Path

    from pch.docs import render_rules_md

    text = render_rules_md()
    if not write:
        typer.echo(text)
        return
    target = Path(write)
    if check:
        if not target.exists() or target.read_text() != text:
            typer.echo(f"{write} is out of date: run `pch rules docs --write {write}`", err=True)
            raise typer.Exit(exitcodes.FAILED)
        typer.echo(f"{write} is up to date")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    typer.echo(f"wrote {write}")


# ----------------------------------------------------------------------------- database
db_app = typer.Typer(help="Database migrations (Alembic)", no_args_is_help=True)
app.add_typer(db_app, name="db")


def _open_db(url: str, *, tolerate_unreachable: bool = False):
    """Engine with the schema policy applied; exits with a clear message when the DB is not usable.
    ``tolerate_unreachable`` (``pch serve``): a database that cannot be reached yet is reported by /health/ready
    instead of stopping the container (returns None)."""
    from sqlalchemy.exc import InterfaceError, OperationalError

    from pch.store.azure_sql import AzureSqlUnavailable
    from pch.store.db import SchemaNotReadyError, get_engine

    try:
        return get_engine(url)
    except SchemaNotReadyError as exc:
        typer.echo(f"Database is not ready: {exc}", err=True)
        raise typer.Exit(exitcodes.SCHEMA_NOT_READY) from None
    except (OperationalError, InterfaceError) as exc:
        if tolerate_unreachable:
            typer.echo(f"warning: database is unreachable ({type(exc).__name__}); serving anyway, /health/ready reports 503", err=True)
            return None
        typer.echo(f"Database is unreachable ({type(exc).__name__}). Check DATABASE_URL and network access.", err=True)
        raise typer.Exit(exitcodes.SCHEMA_NOT_READY) from None
    except (AzureSqlUnavailable, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(exitcodes.SCHEMA_NOT_READY) from None


def _raw_db(db: str | None):
    from pch.settings import get_settings
    from pch.store.azure_sql import AzureSqlUnavailable
    from pch.store.db import get_raw_engine

    try:
        return get_raw_engine(db or get_settings().database_url)
    except (AzureSqlUnavailable, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(exitcodes.SCHEMA_NOT_READY) from None


@db_app.command("upgrade")
def db_upgrade(
    revision: str = typer.Option("head", "--revision", "-r", help="Target revision"),
    db: str | None = typer.Option(None, "--db", help="Database URL (default DATABASE_URL)"),
) -> None:
    """Apply migrations up to --revision (default head). Creates the schema on an empty database."""
    from pch.store import migrate

    engine = _raw_db(db)
    try:
        migrate.upgrade(engine, revision)
    except migrate.SchemaNotReadyError as exc:
        typer.echo(f"Cannot upgrade: {exc}", err=True)
        raise typer.Exit(exitcodes.SCHEMA_NOT_READY) from None
    typer.echo(f"database is at {migrate.db_state(engine).current}")


@db_app.command("current")
def db_current(db: str | None = typer.Option(None, "--db")) -> None:
    """Show the database revision and the revision this version of pch expects."""
    from pch.store import migrate

    st = migrate.db_state(_raw_db(db))
    typer.echo(f"current: {st.current or '(none)'}")
    typer.echo(f"head:    {st.head}")


@db_app.command("check")
def db_check(db: str | None = typer.Option(None, "--db")) -> None:
    """Exit 1 unless the database is at the migration head (use as a deploy / readiness gate)."""
    from pch.store import migrate

    st = migrate.db_state(_raw_db(db))
    if not st.at_head:
        typer.echo(f"NOT at head: {migrate.not_ready_reason(st)}", err=True)
        raise typer.Exit(exitcodes.FAILED)
    typer.echo(f"ok: at head {st.head}")


@db_app.command("stamp")
def db_stamp(
    revision: str = typer.Argument("head", help="Revision to record (normally head)"),
    db: str | None = typer.Option(None, "--db"),
) -> None:
    """Record a revision WITHOUT running migrations. Use once to adopt a database created by an older
    version (create_all) whose schema already equals the initial revision. Does not change any table."""
    from pch.store import migrate

    engine = _raw_db(db)
    migrate.stamp(engine, revision)
    typer.echo(f"stamped {revision}")


# ----------------------------------------------------------------------------- demo / scan / serve
DEMO_DIR = "demo"


def _demo_paths(data_dir: str):
    from pathlib import Path

    d = Path(data_dir) / DEMO_DIR
    return d, d / "world.json.gz", d / "scope.yaml", d / "policy.yaml"


@app.command("seed-demo")
def seed_demo(
    repos: int = typer.Option(280, help="Number of synthetic repositories"),
    seed: int = typer.Option(42, help="Random seed (deterministic)"),
    data_dir: str = typer.Option("data", help="Data directory"),
) -> None:
    """Generate synthetic RAW API payloads for ~280 repos (no credentials, no network)."""
    import yaml

    from pch.demo.generator import generate_world
    from pch.demo.transport import save_world

    d, world_f, scope_f, policy_f = _demo_paths(data_dir)
    world = generate_world(seed=seed, repos=repos)
    save_world(world, world_f)
    scope = {"organization": world["meta"]["org"], "projects": world["meta"]["projects"], "repos": world["scope_repos"], "env_tiers": {}, "exclude_repos": []}
    scope_f.write_text(yaml.safe_dump(scope, sort_keys=False))
    classic = [(p, v["repository"]["name"]) for p, pr in world["ado"].items() for v in pr["build_defs"].values() if (v.get("process") or {}).get("type") == 1][:6]
    waivers = []
    if len(classic) >= 3:
        from datetime import date, timedelta

        waivers = [
            {"rule": "SRC-004", "repo": f"{classic[0][0]}/{classic[0][1]}", "reason": "Classic pipeline until GitHub Actions migration (wave 3)", "owner": "platform-governance@example.com", "expires": (date.today() + timedelta(days=120)).isoformat()},
            {"rule": "SUP-005", "repo": f"{classic[1][0]}/{classic[1][1]}", "reason": "SBOM tooling rollout in progress", "owner": "platform-governance@example.com", "expires": (date.today() - timedelta(days=15)).isoformat()},
            {"rule": "QLT-001", "repo": f"{classic[2][0]}/{classic[2][1]}", "reason": "Legacy code base, Sonar onboarding scheduled", "owner": "platform-governance@example.com", "expires": (date.today() + timedelta(days=45)).isoformat()},
        ]
    policy = {
        "coverage_threshold": 80, "sonar_staleness_days": 14, "sonar_quality_gate_name": "Org Quality Gate", "prod_retention_days": 365,
        "marketplace_task_allowlist": ["SonarQubePrepare", "SonarQubeAnalyze", "SonarQubePublish", "ServiceNow-DevOps-Change", "Synapse workspace deployment", "TerraformTaskV4"],
        "approved_registries": ["contosoacr.azurecr.io"], "waivers": waivers,
    }
    policy_f.write_text(yaml.safe_dump(policy, sort_keys=False))
    typer.echo(f"Seeded {repos} repos in {len(world['ado'])} projects -> {world_f}")
    typer.echo("Next: pch scan --demo && pch serve")


@app.command()
def scan(
    demo: bool = typer.Option(False, "--demo", help="Scan the synthetic demo estate (no credentials)"),
    from_cache: str | None = typer.Option(None, "--from-cache", help="Replay the cached raw responses of a previous scan id"),
    cache: bool | None = typer.Option(None, "--cache/--no-cache", help="Cache redacted raw responses in the artifact store (ARTIFACT_STORE; local: data/raw/<scan_id>). Default: on for live, off for demo"),
    history: int = typer.Option(3, help="Demo only: also create N older snapshots so trends have data"),
    data_dir: str = typer.Option("data", help="Data directory"),
    db: str | None = typer.Option(None, "--db", help="Database URL (default DATABASE_URL / sqlite:///data/pch.db)"),
    scope_file: str = typer.Option("config/scope.yaml", "--scope"),
    policy_file: str = typer.Option("config/policy.yaml", "--policy"),
) -> None:
    """Collect, evaluate and store a compliance scan snapshot (read-only)."""
    import asyncio
    import sys
    from datetime import timedelta
    from pathlib import Path

    from pch.orchestrator import ScanConfig, Scanner
    from pch.providers import PrefixedStore, get_artifact_store
    from pch.settings import get_settings, load_policy, load_scope
    from pch.sources import cache_sources, demo_sources, live_sources
    from pch.timeutil import utcnow_naive

    settings = get_settings()
    _bootstrap(settings, "pch-scan")
    # An explicitly configured DATABASE_URL always wins. Only when it is still the built-in default does a
    # non-default --data-dir relocate the sqlite file next to the data.
    from pch.settings import Settings

    default_url = Settings.model_fields["database_url"].default
    if db:
        db_url = db
    elif data_dir != "data" and settings.database_url == default_url:
        db_url = f"sqlite:///{data_dir}/pch.db"
    else:
        db_url = settings.database_url
    data_path = Path(data_dir)
    stale = timedelta(minutes=settings.scan_lock_stale_minutes)
    timeout_s = settings.scan_timeout_minutes * 60.0

    def progress(done: int, total: int) -> None:
        typer.echo(f"  scanned {done}/{total} repos", err=True)

    async def go() -> None:
        artifacts = get_artifact_store(settings, data_path)
        if demo:
            from pch.demo.generator import generate_world
            from pch.demo.transport import load_world, parse_world_time

            d, world_f, scope_f, policy_f = _demo_paths(data_dir)
            if not world_f.exists():
                typer.echo("No demo data found, run `pch seed-demo` first.", err=True)
                raise typer.Exit(exitcodes.FAILED)
            scope, policy = load_scope(scope_f), load_policy(policy_f if policy_f.exists() else policy_file)
            world = load_world(world_f)
            meta = world["meta"]
            now0 = parse_world_time(world)
            snapshots = []
            for k in range(history, 0, -1):  # older, lower-quality snapshots (for the trend chart)
                w = generate_world(meta["seed"], meta["repos"], meta["quality_shift"] - 0.05 * k, now0 - timedelta(days=14 * k))
                snapshots.append((w, now0 - timedelta(days=14 * k)))
            snapshots.append((world, now0))
            for w, now in snapshots:
                scan_id = f"{now:%Y%m%d-%H%M%S}-demo"
                record = PrefixedStore(artifacts, scan_id) if cache else None
                src = demo_sources(w, record_to=record)
                cfg = ScanConfig(scope=scope, policy=policy, db_url=db_url, mode="demo", now=now, stale_after=stale, timeout_s=timeout_s)
                typer.echo(f"Scanning demo estate {scan_id} ...", err=True)
                try:
                    res = await Scanner(src, cfg, progress).run(scan_id)
                finally:
                    await src.aclose()
                typer.echo(f"  {res.repos} repos, {res.findings} findings, {res.errors} collection errors, {res.duration_s}s, {res.status_counts}")
            return
        scope, policy = load_scope(scope_file), load_policy(policy_file)
        now = utcnow_naive()
        if from_cache:
            scan_id, src = f"{now:%Y%m%d-%H%M%S}-cache", cache_sources(PrefixedStore(artifacts, from_cache), settings)
            mode = "cache"
        else:
            scan_id = f"{now:%Y%m%d-%H%M%S}-live"
            src = live_sources(settings, record_to=PrefixedStore(artifacts, scan_id) if cache is not False else None)
            mode = "live"
        cfg = ScanConfig(scope=scope, policy=policy, db_url=db_url, mode=mode, now=now, stale_after=stale, timeout_s=timeout_s)
        try:
            res = await Scanner(src, cfg, progress).run(scan_id)
        finally:
            await src.aclose()
        typer.echo(f"{res.repos} repos, {res.findings} findings, {res.errors} collection errors, {res.duration_s}s, {res.status_counts}")

    if not demo and not from_cache and not settings.ado_org:
        typer.echo("ADO_ORG is not set. Copy .env.example to .env, or try `pch seed-demo && pch scan --demo`.", err=True)
        raise typer.Exit(exitcodes.CONFIG)
    from pch.scanrun import ScanInterrupted, ScanTimeout, run_guarded
    from pch.settings import ConfigError
    from pch.store.locks import ScanLockHeld, scan_lock

    engine = _open_db(db_url)  # refuses to run when the schema is not at head (unless auto-migrate applies)
    try:
        with scan_lock(engine, stale_after=stale):  # released on every exit path, including SIGTERM / timeout
            asyncio.run(run_guarded(go()))
    except ScanInterrupted as exc:
        typer.echo(f"Scan {exc} and marked failed (reason: interrupted); lock released.", err=True)
        raise typer.Exit(exitcodes.INTERRUPTED) from None
    except ScanTimeout as exc:
        typer.echo(f"Scan failed: {exc} (SCAN_TIMEOUT_MINUTES={settings.scan_timeout_minutes}); lock released.", err=True)
        raise typer.Exit(exitcodes.INTERRUPTED) from None
    except ScanLockHeld as exc:
        typer.echo(f"Another scan is already running: {exc}. Not starting a second one.", err=True)
        raise typer.Exit(exitcodes.LOCK_HELD) from None
    except ConfigError as exc:
        typer.echo(f"Config error: {exc}", err=True)
        raise typer.Exit(exitcodes.CONFIG) from None
    sys.stdout.flush()


scans_app = typer.Typer(help="Stored scan snapshots", no_args_is_help=True)
app.add_typer(scans_app, name="scans")


@scans_app.command("prune")
def scans_prune(
    keep: int | None = typer.Option(None, "--keep", min=1, help="Keep the newest N scans (default RETENTION_KEEP_SCANS)"),
    older_than: int | None = typer.Option(None, "--older-than", min=1, help="Only delete scans older than DAYS (default RETENTION_MAX_AGE_DAYS)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print what would be deleted; change nothing"),
    data_dir: str = typer.Option("data", help="Data directory (local artifact store)"),
    db: str | None = typer.Option(None, "--db", help="Database URL (default DATABASE_URL)"),
) -> None:
    """Delete old scans (DB rows + their raw cache in the artifact store). With both options a scan must be outside the
    newest N AND older than DAYS. Never deletes the latest complete scan or a live `running` scan. Holds the scan lock."""
    import asyncio
    from datetime import timedelta
    from pathlib import Path

    from pch import retention
    from pch.providers import ProviderError, get_artifact_store
    from pch.settings import Settings, get_settings
    from pch.store.db import session_scope
    from pch.store.locks import ScanLockHeld, scan_lock

    settings = get_settings()
    _bootstrap(settings, "pch-scan")
    keep = keep if keep is not None else settings.retention_keep_scans
    older_than = older_than if older_than is not None else settings.retention_max_age_days
    if keep is None and older_than is None:
        typer.echo("Nothing to do: pass --keep and/or --older-than, or set RETENTION_KEEP_SCANS / RETENTION_MAX_AGE_DAYS.", err=True)
        raise typer.Exit(exitcodes.CONFIG)
    default_url = Settings.model_fields["database_url"].default
    db_url = db or (f"sqlite:///{data_dir}/pch.db" if data_dir != "data" and settings.database_url == default_url else settings.database_url)
    stale = timedelta(minutes=settings.scan_lock_stale_minutes)
    try:
        artifacts = get_artifact_store(settings, Path(data_dir))
    except ProviderError as exc:
        typer.echo(f"Config error: {exc}", err=True)
        raise typer.Exit(exitcodes.CONFIG) from None
    engine = _open_db(db_url)

    def run() -> retention.PruneReport:
        with session_scope(db_url) as s:
            cands, protected = retention.plan_prune(s, keep, older_than, stale)
        return asyncio.run(retention.execute_prune(db_url, artifacts, cands, protected, dry_run=dry_run))

    try:
        if dry_run:
            report = run()  # read-only: no lock needed
        else:
            with scan_lock(engine, stale_after=stale):  # never races a running scan
                report = run()
    except ScanLockHeld as exc:
        typer.echo(f"A scan is running: {exc}. Not pruning now.", err=True)
        raise typer.Exit(exitcodes.LOCK_HELD) from None
    verb = "would delete" if dry_run else "deleted"
    summary = "would be deleted" if dry_run else "deleted"
    for o in report.outcomes:
        tail = f"error: {o.error}" if o.error else (f"{o.artifacts} artifacts" if dry_run else f"{o.rows} rows, {o.artifacts} artifacts")
        typer.echo(f"{'FAILED ' if o.error else ''}{verb} {o.scan_id}  [{o.status}, {o.started_at:%Y-%m-%d %H:%M} UTC]  {tail}")
    for sid in report.kept_protected:
        typer.echo(f"kept    {sid}  (latest complete or live running scan is never deleted)")
    typer.echo(f"{len(report.outcomes) - report.errors} scan(s) {summary}" + (" (dry run)" if dry_run else "") + (f", {report.errors} failed" if report.errors else ""))
    if report.errors:
        raise typer.Exit(exitcodes.FAILED)


@app.command()
def serve(
    host: str = typer.Option(None, help="Bind address (default HOST, else 127.0.0.1)"),
    port: int = typer.Option(None, help="Port (default PORT, else WEBSITES_PORT, else 8000)"),
    db: str | None = typer.Option(None, "--db"),
) -> None:
    """Start the dashboard (report-only). Refuses to start unless the auth/bind configuration is safe."""
    import os

    import uvicorn

    from pch.settings import ConfigError, get_settings
    from pch.web.app import create_app
    from pch.web.guard import assert_safe_to_serve

    s = get_settings()
    if db:
        os.environ["DATABASE_URL"] = db
        get_settings.cache_clear()
        s = get_settings()
    bind_host, bind_port = host or s.host, port or s.effective_port
    try:
        assert_safe_to_serve(s, bind_host)
    except ConfigError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(exitcodes.CONFIG) from None
    _bootstrap(s, "pch-web")
    # Fail fast (exit 3) when the schema is not at head; a database that is merely unreachable is served as "not ready".
    _open_db(db or s.database_url, tolerate_unreachable=True)
    web = create_app(db or s.database_url, settings=s, host=bind_host)
    # proxy_headers: trust X-Forwarded-* only from FORWARDED_ALLOW_IPS. server_header=False: do not advertise uvicorn.
    # log_config=None: uvicorn's loggers propagate to the root handler (redacting, JSON in prod). The access log is off in
    # prod (the app writes one structured request line). SIGTERM drains in-flight requests for graceful_shutdown_seconds.
    uvicorn.run(web, host=bind_host, port=bind_port, log_config=None, log_level=s.log_level.lower(), access_log=s.access_log_enabled,
                proxy_headers=True, forwarded_allow_ips=s.forwarded_allow_ips, server_header=False,
                timeout_graceful_shutdown=s.graceful_shutdown_seconds, timeout_keep_alive=s.keep_alive_seconds)


@app.command()
def doctor(
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
    scope_file: str | None = typer.Option(None, "--scope", help="Default: <CONFIG_DIR>/scope.yaml"),
    policy_file: str | None = typer.Option(None, "--policy", help="Default: <CONFIG_DIR>/policy.yaml"),
) -> None:
    """Check settings, config files, source credentials (set/missing only), database and data dir. Exit 1 on any FAIL."""
    import json
    from pathlib import Path

    from pch.doctor import FAIL, run_checks, to_dict

    checks = run_checks(Path(scope_file) if scope_file else None, Path(policy_file) if policy_file else None)
    if json_out:
        typer.echo(json.dumps(to_dict(checks), indent=2))
    else:
        w = max(len(c.name) for c in checks)
        for c in checks:
            typer.echo(f"{c.status:<5} {c.name:<{w}}  {c.detail}")
    if any(c.status == FAIL for c in checks):
        raise typer.Exit(exitcodes.FAILED)
