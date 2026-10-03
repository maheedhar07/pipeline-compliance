# Decisions and assumptions

Choices made where `docs/PLAN.md` was ambiguous or silent. Revisit them when real data arrives.

## Scoring and status
- **Per-rule aggregation.** A rule can produce many findings (one per pipeline or stage). For scoring the worst finding per (repo, rule) wins (`FAIL > WARN > PASS > WAIVED > UNKNOWN > NOT_APPLICABLE`), so a repo with five failing pipelines is not penalised five times. All individual findings are still stored and shown.
- **WARN counts as half credit**, WAIVED/UNKNOWN/NOT_APPLICABLE are excluded from numerator and denominator. `info` severity has weight 0.
- **Status** follows PLAN section 8 exactly. WARN never makes a repo NON_COMPLIANT. A repo whose scan crashed is stored as `NOT_SCANNED`.
- **Waivers** match `rule` + `repo` (`Project/repo`, bare repo name or `*`) and convert FAIL/WARN to WAIVED while `expires` is in the future (or empty). Expired waivers leave the finding failing and add an "expired" badge.

## Rules (interpretation of the catalog)
- **TGT-FA-001 / TGT-WA-001** (slot + swap) only apply to `prod` stages. Requiring slots in dev would be noise.
- **SEC-002** only flags a non-Key Vault variable group when it holds secret variables or has "prod" in its name; a plain configuration group (no secrets) does not fail.
- **SEC-003** only evaluates `azurerm` connections; workload identity federation and managed identity pass, service principal secrets fail.
- **QLT-003** returns FAIL when no Sonar project exists for a repo (Sonar was queried and found nothing) and UNKNOWN when Sonar was not queried at all.
- **QLT-001..005** are NOT_APPLICABLE for ADF, Synapse, IaC and docs-only repos (no application code to analyse); Aikido rules still apply except for docs-only repos.
- **TST-003** is NOT_APPLICABLE until tests exist and run (TST-001/002 cover that), so one root cause is not counted three times.
- **TST-005** applies to deployment stages in test/uat/prod (`smoke_check_required_tiers` in policy.yaml).
- **DEP-002** is NOT_APPLICABLE when there is no manual approval at all (DEP-001 already fails).
- **DEP-004**: PASS if any transitive predecessor is a dev/test/uat stage; WARN if predecessors exist but their tier is unknown; FAIL otherwise. YAML stages without `dependsOn` depend on the previous stage (Azure Pipelines semantics), `dependsOn: []` means no dependency.
- **DEP-005**: FAIL when a CRQ is referenced but missing, cancelled/rejected, not approved, or the deployment is outside the CRQ window (+/- 2 h slack). A deployment with no CRQ reference is matched by CI + time window when `servicenow_ci` is configured (FAIL if nothing matches); with no reference and no CI it is UNKNOWN, as PLAN requires. CRQ references are searched in release name/description/variables (classic) or build parameters/number/tags (YAML) with the regex `CHG|CRQ + digits`.
- **DEP-006**: classic releases use the production environment's retention policy; YAML/build pipelines use the build definition retention rules. If undefined it is UNKNOWN (the project-level default is not read).
- **SUP-001** treats any `build`-capability step in a deployment stage as a rebuild. Classic releases must link a build artifact.
- **SUP-004** looks for `:latest`, non-approved `*.azurecr.io` registries and (WARN) the absence of a digest/`$(Build.BuildId)` style immutable tag.
- **MIG** (migration readiness) is a separate informational score (`engine/migration.py`), not a registered rule, so it never affects compliance.

## Collection
- **Release to repo linking** follows the primary Build artifact (`artifacts[].definitionReference.definition.id`) to the build definition's repository. Releases that cannot be linked are skipped with a collection error.
- **YAML expansion** uses `POST .../pipelines/{id}/preview` (previewRun=true). If it is refused, the raw `azure-pipelines.yml` is read through the Items API instead (templates are then not expanded) and an info collection error is recorded.
- **Read-only guard.** All HTTP goes through `ReadOnlyTransport`. Besides GET, only the YAML preview POST and the Aikido OAuth client-credentials token POST (a documented token exchange, not a mutation) are allowed.
- **Sonar project key resolution:** `scope.yaml` override, else `<ADO project>_<repo>`, else `<repo>`.
- **Aikido** and some **ServiceNow / environment-check** details are unverified against live systems; they are isolated and marked `# VERIFY:` in code.
- **Secret handling:** variable values are inspected in memory only. The raw cache is redacted (secret variables, secret-named fields, suspected secret values) and the database stores pipeline definitions without script bodies or secret-looking inputs.
- **Concurrency** defaults to 8 parallel requests for live scans (PLAN) and 16 for the in-memory demo.

## Demo mode
- `pch seed-demo` writes raw API payloads (`data/demo/world.json.gz`) plus a demo `scope.yaml` and `policy.yaml` (with three sample waivers). `pch scan --demo` serves them through an in-memory httpx transport so the REAL collectors, normalizers and rules run.
- `pch scan --demo` also creates 3 older, lower-quality snapshots (`--history`, 14 days apart) so the trend chart has data. Use `--history 0` for a single scan.
- The demo estate is deliberately imperfect (collection failures, disabled repos, preview 403s, Sonar 500s) to exercise error tolerance.

## Dashboard
- Server-rendered; Tailwind, HTMX and Chart.js come from CDNs. Offline use needs vendored copies.
- No authentication in v1 and it binds to 127.0.0.1 by default. For a shared deployment put it behind Entra ID (Azure App Service Easy Auth).
- There are no mutating HTTP routes at all (enforced by a test).

## Configuration (T2)
- **`APP_ENV`** (`dev|test|prod`, default `dev`) is the single profile switch; `settings.is_prod` etc. later milestones hang security policy on it. `get_settings()` stays cached; `reset_settings()` clears it. `host` stays `127.0.0.1` in every profile; the non-loopback bind policy is enforced in T5.
- **YAML models are `extra="forbid"`**; all load failures raise `ConfigError` naming file and field path (input values are never echoed). Missing `scope.yaml`/`policy.yaml` use defaults in dev/test; in prod a missing `scope.yaml` is an error.
- **No org-specific literals in code**: the Sonar gate default is `Sonar way`; the organisation's gate is set in `config/policy.yaml`. The synthetic demo uses a neutral `Org Quality Gate` name. Fixture/demo data still uses the fictional `contoso` org.
- **`pch doctor`** (`pch/doctor.py`) never prints secret values (source credentials are `set`/`missing`; DB URL passwords are masked). `check_db_migrations` is the extension point for the T3 Alembic head check.

## Portable persistence (T3)
- **Alembic is the only way the schema is created.** Migrations live in the package (`pch/store/migrations`, shipped in the wheel); `pch.store.migrate` builds the Alembic `Config` in code and hands it the engine's connection, so there is no `alembic.ini` or CWD dependence and the Azure AD token hook applies to migrations too. `render_as_batch=True` (sqlite) and `compare_type` are set in `env.py`. A test asserts that autogenerate against the models yields no diff.
- **`create_all` is gone.** `get_engine` runs `ensure_schema`: at head -> nothing; SQLite with `APP_ENV` dev/test -> `upgrade head` (so the migration path is exercised constantly, including by the whole test suite); `DB_AUTO_MIGRATE=true` -> `upgrade head`; otherwise `SchemaNotReadyError`. Prod never auto-migrates by default because it needs DDL rights for the app identity and races with concurrent instances. A database that has tables but no `alembic_version` is never auto-migrated; the error points to `pch db stamp head`.
- **Types.** `UTCDateTime` (TypeDecorator) stores naive UTC on sqlite/MSSQL (`DATETIME2`), `timestamptz` on PostgreSQL, and always returns aware UTC. The domain layer (collectors, rules) keeps its existing naive-UTC convention (`pch.timeutil.utcnow_naive`); only the persistence boundary is aware, and a naive value written to the DB is interpreted as UTC. All text is `Unicode`/`UnicodeText` (NVARCHAR on MSSQL); indexed columns are <= 300 chars (limit 450). `repo_results.external` is stored in column `external_summary` because EXTERNAL is reserved in T-SQL. SQLAlchemy `JSON` is used as is (NVARCHAR(max) on MSSQL); a TypeDecorator is not needed for it. No query uses JSON paths, all JSON filtering stays in Python. The Alembic `compare_type` hook ignores JSON vs NVARCHAR on MSSQL.
- **Engine factory** (`store/engine.py`) holds every dialect option: sqlite pragmas (WAL, foreign keys) and `check_same_thread`, `StaticPool` for in-memory sqlite, pool settings for server databases. `DB_AUTH=azure_ad` (`store/azure_sql.py`) injects an Entra token via `do_connect` (`attrs_before={1256: ...}`), cached and refreshed 5 min before expiry; the ODBC string's `Trusted_Connection`/`UID`/`PWD` are stripped (`# VERIFY:` on real Azure SQL).
- **Scan lock** is one row in `scan_locks` (INSERT to acquire, DELETE of our own holder token to release, compare-and-swap UPDATE for stale takeover); no advisory locks. The CLI takes it around the whole `pch scan` run. Orphaned `running` scans older than the stale timeout are marked `failed` when the next scan starts. Results plus `status=complete` are written in one transaction; any exception (including cancellation) marks the scan `failed`.
- **Bulk writes** respect SQL Server's 2100-parameter limit: the ORM flush already uses `insertmanyvalues` (capped at 2099 for mssql), and `insert_rows` / `select_where_in` chunk explicitly.
- **Readiness:** `pch.store.db.db_ready(url) -> (ok, reason)` never migrates and never echoes the URL; T6 uses it for `/health/ready`. `pch doctor` gains a `db_migrations` check.
- **CI:** `db-matrix` runs the portability suite and a CLI end-to-end (`db upgrade`, demo scan, `db check`) against PostgreSQL 16 and SQL Server 2022 service containers. The SQL Server path cannot be run on the dev machine (no Docker); CI is its only coverage.
