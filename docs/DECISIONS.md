# Decisions and assumptions

Choices made where `docs/PLAN.md` was ambiguous or silent. Revisit them when real data arrives.

## Scoring and status
- **Per-rule aggregation.** A rule can produce many findings (one per pipeline or stage). For scoring the worst finding per (repo, rule) wins (`FAIL > WARN > PASS > WAIVED > UNKNOWN > NOT_APPLICABLE`), so a repo with five failing pipelines is not penalised five times. All individual findings are still stored and shown.
- **WARN counts as half credit**, WAIVED/UNKNOWN/NOT_APPLICABLE are excluded from numerator and denominator. `info` severity has weight 0.
- **Status** follows PLAN section 8 exactly. WARN never makes a repo NON_COMPLIANT. A repo whose scan crashed is stored as `NOT_SCANNED`.
- **Waivers** match `rule` + `repo` (`Project/repo`, bare repo name or `*`; GitHub-hosted repos: `Project/org/repo` or `org/repo`) and convert FAIL/WARN to WAIVED while `expires` is in the future (or empty). Expired waivers leave the finding failing and add an "expired" badge.

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
- Server-rendered; Tailwind, HTMX and Chart.js are vendored under `static/vendor` (T5), no CDN at runtime.
- Authentication/authorisation: see "Web security (T5)" below.
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

## Provider seams (T4)
- **Two seams only**: `SecretProvider` and `ArtifactStore` in `pch.providers`, built by `get_secret_provider(settings)` / `get_artifact_store(settings)`. Azure adapters live in their own modules (`azure_keyvault.py`, `azure_blob.py`), import their SDK lazily and raise `ProviderUnavailable` naming the `pip install` command. Errors derive from `ConfigError`, so the CLI prints them and exits 2.
- **Explicit, non-mixing secret resolution.** Selected by `SECRETS_PROVIDER`; the credential env vars are only read by the `env` provider. Resolution happens when live sources are built (`sources._live`), and only for configured sources (non-secret fields such as `ADO_ORG`, `SONAR_URL`, `AIKIDO_CLIENT_ID`, `SERVICENOW_URL` decide that). Behaviour change: a live scan with a configured source and an empty credential now fails with `secret <NAME> was not found...` instead of building a client with an empty credential; `--from-cache` no longer needs credentials at all. `Settings` credential fields are untouched (they are the `env` provider's backing store).
- **App Service default path** is Key Vault references -> env vars -> `env` provider (no Azure code in the app). `azure_keyvault` exists for non-App-Service hosts, rotation without restart (TTL cache, misses uncached) and non-env consumers. DB passwords stay in `DATABASE_URL` (use `DB_AUTH=azure_ad`).
- **Name mapping** `ADO_PAT` -> `ado-pat`, overridable with `KEYVAULT_SECRET_MAP` (JSON). `FileSecretProvider` validates names against `[A-Za-z0-9][A-Za-z0-9_.-]*` without `..`, resolves symlinks (Kubernetes `..data`) and requires the result to stay inside `SECRETS_DIR`; world-readable files warn rather than fail because Kubernetes volumes default to 0644.
- **ArtifactStore is async** (`put/get/list/delete_prefix`) because the transports are. Blocking I/O (local files, the synchronous Azure SDK client) runs in `asyncio.to_thread`; the sync Blob client was chosen over `azure.storage.blob.aio` to avoid the extra aiohttp dependency. Keys are validated (relative, no `..`, no backslash/control chars); `delete_prefix` refuses an empty prefix. `PrefixedStore` gives each scan its own view, so transports only know relative keys. `LocalArtifactStore` writes atomically (temp file + replace, mode 0600).
- **Redaction before `put`**: `RecordingTransport.build_record` is the single place a record is built. Previously non-JSON bodies were cached verbatim; they now pass through `redact_text`. A test drives both stores (local and a fake blob container) with secrets in JSON, in a variable, in YAML text and in the URL query and asserts they never reach any `put`.
- **Cache writes are best-effort**: a store failure logs one warning (error type only) and the scan continues; `--from-cache` then misses (404 -> collection error) for those requests.
- **Azure Blob has no account-key/connection-string/SAS path**, by design (managed identity only).
- **Lockfiles**: `requirements.lock` is unchanged (extras are not in it except postgres); `requirements-azure.lock` adds `azuresql`, `azure-keyvault`, `azure-blob`; the Dockerfile takes `--build-arg PCH_LOCKFILE=...`. CI has an `all-extras` job (full suite with every extra, plus a hash-checked install of the Azure lock), audits both lockfiles, and all runners are pinned to `ubuntu-24.04`.
- **Known limitation**: `pch scan --from-cache` of a *demo* cache through the live path is only approximate (request URLs contain time windows derived from "now"); replay is exact when the scan time is the same, as in the demo test.

## Web security (T5)
- **Why Easy Auth + Entra app roles.** The target is Azure App Service in a Microsoft-only organisation. Sign-in, token handling, session cookies and CSRF-relevant flows are delegated to the platform (no OIDC code or client secrets in the app); authorisation is an Entra *app role* (`PCH.Reader`) assigned to users/groups in the enterprise application ("assignment required" = yes), so access is managed by the identity team, not by app config. Groups were not chosen because group claims overflow (>200) and need Graph calls; app roles arrive directly in the token.
- **Auth seam.** `pch.web.auth`: `Authenticator` (`authenticate(headers) -> Principal`, `authorize(principal)`), registered in `AUTHENTICATORS` (`none`, `easyauth`); `AuthMiddleware` (pure ASGI) stores `Principal(id, name, roles, auth_type)` on `request.state.principal`. A new mode = one class + one registry entry. Roles come only from claims of type `role_typ`, `roles` or the `.../claims/role` URI in the signed principal; `X-MS-CLIENT-PRINCIPAL-ID/-NAME` are fallbacks for id/name only. Role match is exact and case-sensitive. Any parse problem (bad base64/JSON, wrong shapes, >16 KB, no identity) is 401, never 500; unexpected authenticator errors also deny.
- **Header-spoofing guard.** Easy Auth strips/overwrites `X-MS-*` only when enabled, so `easyauth` refuses to start unless `WEBSITE_AUTH_ENABLED` is `True` (`AUTH_EASYAUTH_ASSUME_ENABLED=true` for local tests only, forbidden in prod).
- **Fail-closed matrix** (`pch.web.guard`; `tests/test_web_security.py::test_guard_matrix` plus an exhaustive invariant test over 3 envs x 2 modes x 4 hosts x roles x flags x hosts): refuse when (a) `none` and prod; (b) `none` and non-loopback bind unless dev + `AUTH_NONE_ALLOW_CONTAINER_BIND`; (c) `easyauth` without `AUTH_ALLOWED_ROLES` and without `AUTH_ALLOW_ANY_AUTHENTICATED=true`; (d) both of those set (ambiguous); (e) `easyauth` without `WEBSITE_AUTH_ENABLED=True` unless assume flag outside prod; (f) assume flag or container-bind flag in prod; (g) prod without `ALLOWED_HOSTS` or with `*`. All problems are listed in one error; `pch serve` exits 2.
- **Middleware order** (outermost first): Security (headers, request id, last-resort 500) -> TrustedHost -> MethodGuard (GET/HEAD only) -> Auth -> routes. Unknown paths therefore return 401 to anonymous users (no route enumeration). `AUTH_MODE=none` defaults the Host allowlist to loopback names (DNS-rebinding guard). `/api/v1/health` is unauthenticated and may be called with a loopback Host (container HEALTHCHECK); T6 adds `/health/*` to `PUBLIC_EXACT`.
- **Entry point.** `pch serve` is the supported entry point: it passes the real bind host to `create_app`. Starting the factory directly (`uvicorn pch.web.app:create_app --factory`) validates against `HOST` instead, which cannot see `--host`.
- **CSP.** `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`. Inline `<script>`, `style=""`, `on*=` and `<style>` were removed (tests scan templates). Theme bootstrap is `static/theme.js` (sync, in head); page behaviour is `static/app.js`; page data rides in `<script type="application/json" id="page-data">` blocks (inert; `<`, `>`, `&`, U+2028/9 are `\u`-escaped by `tojson_safe`). Bar widths use `data-w` + CSSOM (`el.style`), which `style-src 'self'` allows. HTMX is configured with `allowEval:false`, `allowScriptTags:false`, `includeIndicatorStyles:false`; indicator CSS is in `app.css`. Dev-only exception: `/api/docs` (Swagger UI) is served with a CSP that allows jsDelivr and the page's single inline script by sha256 hash; it does not exist in prod.
- **Vendored assets.** Tailwind: the Play CDN served v3, so the pinned standalone CLI is v3.4.17 (`darkMode: "class"`, content = templates + `static/*.js` + `web/*.py`); the CLI binary is downloaded on demand into the gitignored `.tools/` after a sha256 check against the release's `sha256sums.txt`. HTMX 1.9.12 and Chart.js 4.4.3 (the versions the templates used) come from the npm tarballs whose sha1/sha512 equal the registry's `dist.shasum`/`dist.integrity`. `static/vendor/MANIFEST.json` + a test pin the sha256 of each file.
- **XSS audit.** No `|safe` or `Markup` on external data remain; `tojson_safe` is the only `Markup` producer and is test-covered. Jinja autoescape handles HTML. External URLs (`url`, `link`) pass through `safe_url` (http/https only, else `#`) and links carry `rel="noopener noreferrer"`. CSV export neutralises formula-leading cells (`csv_cell`).
- **Other.** 404/405/400/500 pages are generic and carry the `X-Request-ID` correlation id; validation errors never echo input. Query params: max lengths, `sort` is a `Literal`, `dir` is `asc|desc`, offsets/limits bounded (422 for the API, 400 for pages). Behaviour change: an invalid `sort`/`dir` used to fall back silently; it is now rejected. `HEAD` is served by Starlette static files only; FastAPI routes answer 405 as before. uvicorn runs with `proxy_headers=True`, `forwarded_allow_ips=FORWARDED_ALLOW_IPS`, `server_header=False`; the port is `--port`, else `PORT`, else `WEBSITES_PORT`, else 8000.
- **Docker/compose.** The image's `CMD` is `pch serve` (no hard-coded host). Compose sets `APP_ENV=dev`, `AUTH_MODE=none`, `AUTH_NONE_ALLOW_CONTAINER_BIND=true`, `HOST=0.0.0.0` and publishes `127.0.0.1:8000` only. On App Service set `HOST=0.0.0.0`.
- **Unverified platform assumptions** are marked `# VERIFY:` in `settings.py`, `auth.py`, `guard.py` and listed in `docs/DEPLOY_AZURE.md`.

## Operability (T6)
- **One logging entry point.** `pch.logging_setup.configure_logging(settings)` (CLI `serve`/`scan`/`scans prune`; the web app inherits it because it runs inside `pch serve`). It installs one root handler (stderr, resolved lazily so CliRunner/pytest can swap it) with `ContextFilter` (request_id / scan_id contextvars) and `RedactingFilter`; uvicorn runs with `log_config=None` so its loggers propagate to that handler. The redaction filter lives on the *handler*, not the loggers, so records from any library are covered, and `protect_handlers()` adds it to handlers added later (the OpenTelemetry one). Python 3.11 filters cannot replace a record, so it edits in place (message+args merged, `exc_info` replaced by scrubbed `exc_text`, which also means the OTel handler exports the scrubbed text as `exception_text` instead of a structured stack). Scrubbing is deliberately aggressive (idempotent regexes + exact-match registry); false positives cost readability, false negatives cost secrets. Values shorter than 6 characters are not registered for exact scrubbing (they would shred ordinary text).
- **Exact-match registry.** `register_secret` is called by every provider `get` (env, file, Key Vault) and by `configure_logging` for the settings credentials, the DB URL password and the App Insights connection string; it is a process-local set, never logged, with URL-encoded variants.
- **Request id reuse.** The existing SecurityMiddleware still owns the id; it now adopts an inbound `X-Request-ID` only when it matches `^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$` and sets the contextvar (reset in `finally`). The same middleware writes the single request log line (path without query, control characters escaped, principal id hashed with SHA-256/12 hex, health + static at DEBUG). Order is unchanged, so every response, including 401/403/400-host and 500s, is logged.
- **Health.** `/health/live` is `async` and dependency-free; `/health/ready` runs `db_ready_code` in a thread with a 2.5 s budget, single-flight (a hung DB cannot pile up threads) and a 5 s result cache. Reason codes are fixed strings. Readiness is DB + migrations at head only (cascading-failure argument in the README). Behaviour change: `create_app`/`pch serve` no longer abort when the DB is merely *unreachable* at start (they log it and serve 503 on readiness; the engine re-verifies the schema on the next request); `SchemaNotReadyError` still aborts with exit 3. `pch scan` on an unreachable DB now exits 3 with a clean message instead of a traceback.
- **Telemetry is an optional extra** and import-guarded; set-without-extra is a `ProviderUnavailable` (exit 2). The distro handles FastAPI/httpx/urllib3/requests; SQLAlchemy is added explicitly. URL query strings/userinfo are removed by a span processor at span start (attributes are immutable at end); bodies and headers are never captured (no hooks); a test asserts that with the real httpx instrumentation. Live metrics are off. Limitations: the sampler is the distro's (`OTEL_TRACES_SAMPLER[_ARG]`); `db.statement` (SQL text with bind placeholders, no values) is exported by the SQLAlchemy instrumentation.
- **Retention semantics.** `--keep N` and `--older-than D` combine with AND (conservative); one option alone applies alone. Rank is over all scans by `started_at`, so failed scans use up keep slots. Never deleted: the latest `complete` scan and a `running` scan inside the stale window. Artifacts are removed before rows (a failed artifact delete leaves the row so the next prune retries; the reverse would orphan blobs). Real runs take the scan lock; dry-runs do not.
- **Interrupts and timeouts.** `run_guarded` converts SIGTERM/SIGINT into cancellation of the scan task; `Scanner.run` records the reason (`interrupted`, `timeout: exceeded N minutes`, or the exception) and re-raises; the lock is released by its context manager; the CLI exits 5. `SCAN_TIMEOUT_MINUTES` is per `Scanner.run` (demo mode with history applies it to each snapshot). A hard SIGKILL is still recovered by the stale-lock / orphan logic (T3).
- **Exit codes** are constants in `pch/exitcodes.py` (0 ok, 1 generic, 2 config, 3 schema/db, 4 lock, 5 interrupted/timeout) and documented in the README.
- **Unverified platform assumptions** (all `# VERIFY`): App Service stop window (~30 s) vs `GRACEFUL_SHUTDOWN_SECONDS`; front-end idle timeout vs `KEEP_ALIVE_SECONDS`; Easy Auth excluded-path syntax; Health check thresholds/app setting names; Container Apps Job / WebJob fields; federated-identity token wiring in ADO.

## Architecture decision records (T1-T7)

Short ADRs for the decisions a team building on this template is most likely to want to revisit. The sections above hold the detail.
Format: context, decision, consequences, how to reverse.

### ADR-01 Supply chain is pinned and verified (T1)
- **Context.** The app holds read tokens for the source systems and runs in a regulated org; an unpinned dependency, action or base image is a path to those tokens.
- **Decision.** GitHub Actions pinned by commit SHA with `permissions: contents: read`; hash-locked `requirements.lock` (core + `postgres`) and `requirements-azure.lock` (all extras) installed with `--require-hashes`; base image pinned by digest; CI runs ruff, mypy, pytest, bandit, `pip-audit` on both lockfiles, gitleaks (checksum-verified binary) and Dependabot (pip, actions, docker).
- **Consequences.** Dependency changes need a lockfile regeneration (two files) and digest bumps are manual or Dependabot PRs. SEC-12 (unpinned dev tools in CI, PEP 517 build backend fetched without hashes) is accepted.
- **Reverse.** Drop `--require-hashes` in the Dockerfile and the pin comments; not recommended.

### ADR-02 Strict, fail-fast configuration with an `APP_ENV` profile (T2, T7)
- **Context.** Silent misconfiguration (a typo in `policy.yaml`, `http://` source URL, a timeout longer than the lock window) turns into a wrong report or an unsafe deployment.
- **Decision.** `Settings` validates everything at construction; YAML models are `extra="forbid"` and errors name file and field path (never the value). `APP_ENV=prod` adds checks: https-only source URLs, `ALLOWED_HOSTS`, no `AUTH_MODE=none`, `scope.yaml` required. `SCAN_TIMEOUT_MINUTES < SCAN_LOCK_STALE_MINUTES` is enforced in every environment. `pch doctor` runs the same checks plus connectivity.
- **Consequences.** A bad value stops startup (exit 2) instead of degrading. On-prem `http://` sources work only outside prod.
- **Reverse.** Remove the prod branch in `Settings._provider_settings`; set `extra="ignore"` on `_Strict` (not recommended).

### ADR-03 Schema only through Alembic migrations, dialect-neutral types (T3)
- **Context.** `create_all` hides drift and cannot evolve a live database; the target set is SQLite, PostgreSQL and Azure SQL.
- **Decision.** Migrations ship inside the package and are driven by `pch db ...` with the engine's own connection. `UTCDateTime`, `Unicode` text, indexed strings of at most 450 characters, no JSON-path SQL. SQLite in dev/test auto-migrates (so the whole suite exercises migrations); everything else requires `pch db upgrade` (or opt-in `DB_AUTO_MIGRATE`). A test fails if models and migrations differ.
- **Consequences.** Every model change needs a revision (see CUSTOMIZING). Downgrade of the initial revision drops all tables.
- **Reverse.** Not practical; a new dialect is added by extending the types and the CI matrix instead.

### ADR-04 Scans run out-of-band behind a database lock (T3, T6, T7)
- **Context.** A scan takes minutes to hours; running it in a web request or on every instance would overload sources and the app.
- **Decision.** `pch scan` is a separate process (scheduled job). A row in `scan_locks` enforces one scan at a time on all dialects, with takeover after `SCAN_LOCK_STALE_MINUTES`; `SCAN_TIMEOUT_MINUTES` cancels a scan and marks it `failed`; results and `complete` are committed in one transaction. T7 made the invariant timeout < stale window a validation error.
- **Consequences.** The deployment needs a scheduler (ADO pipeline, Container Apps Job or WebJob). The web app only reads.
- **Reverse.** Call `Scanner` from an in-process scheduler; keep the lock.

### ADR-05 Provider seams are explicit, non-mixing and optional (T4)
- **Context.** Secrets and raw-cache storage differ per host; cloud SDKs must not be required for the core.
- **Decision.** `SecretProvider` (`env`, `file`, `azure_keyvault`) and `ArtifactStore` (`local`, `azure_blob`) are built by one factory function each (`build_secret_provider`, `build_artifact_store`) from a `Literal` setting; the SDK import is lazy and a missing extra raises `ProviderUnavailable` with the pip command. Providers are never mixed (no silent fallback). Azure Blob has no key/SAS/connection-string path.
- **Consequences.** Adding a provider means a class, a `Literal` value and an `elif` branch (there is no plugin discovery by design). The auth seam uses a dict registry (`AUTHENTICATORS`).
- **Reverse.** Replace the factories with entry-point discovery if a third party must add providers.

### ADR-06 Easy Auth plus Entra app roles, with a fail-closed guard (T5)
- **Context.** Microsoft-only org on App Service; sign-in, sessions and token handling should not live in this app.
- **Decision.** `AUTH_MODE=easyauth` reads `X-MS-CLIENT-PRINCIPAL`, authorizes by exact app-role match, and refuses to start unless `WEBSITE_AUTH_ENABLED=True` (otherwise the headers are forgeable). `none` is loopback-only and forbidden in prod. Every other path returns 401 to anonymous users; only the health endpoints and `/static/` are public.
- **Consequences.** Safety depends on platform behavior the code cannot prove (SEC-08, listed in the go-live gate). Local testing of easyauth needs `AUTH_EASYAUTH_ASSUME_ENABLED`.
- **Reverse.** Add another `Authenticator` to `AUTHENTICATORS` (CUSTOMIZING, Auth).

### ADR-07 No third-party origins at runtime (T5)
- **Context.** A CDN script on a page that shows compliance data is an exfiltration path.
- **Decision.** Tailwind CSS is built with the pinned standalone CLI; HTMX and Chart.js are vendored with sha256 in `MANIFEST.json`; CSP is `default-src 'self'` with no inline script or style.
- **Consequences.** Updating a front-end asset is a manual procedure (CUSTOMIZING, Rebuild CSS). `/api/docs` (dev only) is the one exception.
- **Reverse.** Not recommended.

### ADR-08 Redact before anything is persisted or logged (T4, T6, T7)
- **Context.** Responses and exceptions can contain credentials.
- **Decision.** `RecordingTransport.build_record` redacts (JSON field names incl. suffixes, text patterns) before the artifact store sees a byte; exception text is scrubbed before it reaches the database; a log handler filter scrubs by pattern and by exact registered secret values; SQLAlchemy runs with `hide_parameters=True`; regexes are linear-time (SEC-01).
- **Consequences.** Redaction is best effort for free text and may over-scrub. New collectors must not bypass `SourceClient`.
- **Reverse.** None; it is a security invariant.

### ADR-09 Collection fails open, startup fails closed (T2, T6)
- **Context.** One failing repo or source should not lose a scan, but a misconfigured service must not start.
- **Decision.** Collectors record a collection error and continue; the scan stores them. Startup validation, the serve guard and the migration-head check refuse to start (exit 2/3). `/health/ready` is DB reachability plus migration head only, so a flaky optional dependency cannot take every instance out of rotation.
- **Consequences.** A report can be partial; collection errors are visible in the dashboard and are findings (`COLLECTION-ERROR`).
- **Reverse.** n/a.

### ADR-10 Optional extras with two lockfiles (T1, T4)
- **Context.** The core must be installable without cloud SDKs or the ODBC driver.
- **Decision.** Extras: `postgres`, `azuresql`, `azure-keyvault`, `azure-blob`, `azure-monitor`. `requirements.lock` = core + postgres; `requirements-azure.lock` = everything. The Dockerfile takes `PCH_LOCKFILE`. CI has an `all-extras` job so Azure adapter tests are not skipped.
- **Consequences.** Both lockfiles must be regenerated together.
- **Reverse.** Fold extras into the core dependencies and keep one lockfile.

### ADR-11 Residual-risk hardening: https-only prod, response cap, connect timeout (T7)
- **Context.** The independent review accepted four low risks (SEC-11, SEC-13) as operator-controlled; the owner's rule is to fail safe in live.
- **Decision.** In prod every configured source URL must be `https://`; `SizeLimitTransport` (`HTTP_MAX_RESPONSE_MB`, default 50) sits beneath the recorder and aborts oversize responses (error becomes a collection error, not retried); server engines get `DB_CONNECT_TIMEOUT_SECONDS` (psycopg `connect_timeout`, pyodbc login `timeout`).
- **Consequences.** A legitimately huge upstream response (large pipeline list) needs the cap raised; the failure is visible as a collection error.
- **Reverse.** Raise the caps via settings; remove the prod URL check in `Settings`.

### ADR-12 Documentation is checked against the code (T7)
- **Context.** Template docs rot; stale env-var tables cause misconfiguration.
- **Decision.** The environment-variable table in the README is generated from `Settings` (`pch config reference`); `tests/test_docs.py` fails if a setting is undocumented, the README table or `docs/RULES.md` is stale, `.env.example` omits a setting, or a relative markdown link is broken.
- **Consequences.** Adding a setting means one entry in `src/pch/config_reference.py`, one mention in `.env.example` and a regenerated README.
- **Reverse.** Delete the tests.

### ADR-13 GitHub-hosted code, Azure DevOps pipelines: include the repos, UNKNOWN (never FAIL) for what only GitHub knows (L1)
- **Context.** The owner's code lives on GitHub while every pipeline (YAML and Classic build/release) is in Azure DevOps. The scanner used to iterate only `_apis/git/repositories` and link build definitions by `repository.id`, so GitHub-hosted repos and their releases were silently dropped.
- **Decision.** Per ADO project the set of repos is: Azure Repos repositories, plus external repos referenced by that project's build definitions (`repository.type != "TfsGit"`: `GitHub`, `GitHubEnterprise`, anything else is `other_git`), plus GitHub repos used directly as classic release artifacts (`artifacts[].type == "GitHub"`, no build in between). Grouping stays per ADO project (scope.yaml, waivers and existing URLs are per project). The repo **name is the full name `org/repo`**, so the repo key is `Project/org/repo` and web routes are `/repos/{project}/{repo:path}` (the `u()` helper keeps `/` and encodes everything else). Repos are de-duplicated case-insensitively on (provider, full name) per project; build definitions link by (provider, id), releases via their primary artifact first (Build artifact to build definition to repo, or the GitHub artifact). A release that cannot be linked (for example built from a repo in another project) stays a collection error. `RepoRef` gained `provider`, `full_name`, `service_connection_id` (web URL derived to `https://github.com/org/repo`, no `.git`); the provider is stored in the existing `repo_results.external_summary` JSON, so there is **no schema change** (no migration).
- **Facts are "not collected", not "empty".** For external repos the Items API tree fetch and ADO branch policies are not called. `RepoFacts.facts_source = "unavailable"` with the reason *GitHub-hosted: repository contents/branch protection need the GitHub reader (not configured)*, and `BranchPolicies.available = False` with the same `unavailable_reason`. A future reader returns populated facts with its own `facts_source` and the rules evaluate normally (CUSTOMIZING, "Plug in a GitHub reader").
- **Test state.** New `TestState.UNKNOWN`. For an external repo: if a pipeline effectively runs tests that proves tests exist and the usual semantics apply (`TESTS_OK` / `TESTS_LOW_COVERAGE` / `TESTS_NO_COVERAGE`, coverage from Sonar); otherwise `UNKNOWN`. It is never `NO_TESTS` or `TESTS_NOT_RUN` because that needs the file tree. ADF / Synapse / IaC repos are recognised from what their pipelines deploy (all deploy targets of one such kind) so they stay `NOT_APPLICABLE` and TST-006 applies.
- **YAML expansion** through `pipelines/{id}/preview` still works (ADO fetches the file through the service connection); the Items-API fallback is skipped for external repos and produces an info collection error.
- **Sonar / Aikido matching** for `org/repo`: Sonar keys also try `Project_repo`, `repo` and `org_repo`; Aikido tries `org/repo` then `repo`. `scope.yaml` overrides and `exclude_repos` match the full name case-insensitively (`Project/org/repo`); a waiver `repo` matches `Project/org/repo` or `org/repo` (a bare short name does not).
- **Known limit.** A GitHub repo that no ADO pipeline or release references is invisible to Azure DevOps and therefore not scanned until a GitHub reader enumerates the organisation (the demo shows ~5% of its estate as such repos, absent from the report).
- **Reverse.** Drop the `RepoEntry` discovery of external repos in `orchestrator._run` (Azure Repos behaviour is unchanged).

Rule behaviour for externally hosted (GitHub) repos:

| Rule | Behaviour for a GitHub-hosted repo |
|---|---|
| SRC-001, SRC-002, SRC-003 | **UNKNOWN** (reason above): ADO branch policies do not apply, GitHub branch protection needs the reader |
| SRC-004 | Normal (pipeline definition in ADO / source control) |
| SRC-005 | Normal (release artifact branch filters, environment branch-control checks) |
| SRC-006 | **UNKNOWN** when an ADO YAML pipeline exists (CODEOWNERS lives in the repo); NOT_APPLICABLE when there is no YAML pipeline in ADO (a YAML file in GitHub that no ADO pipeline uses is not assessed) |
| TST-001, TST-002 | PASS when a pipeline effectively runs tests (proof); otherwise **UNKNOWN**; never FAIL |
| TST-003 | Normal when a pipeline runs tests (a missing coverage report is a real FAIL, from pipeline/Sonar data); **UNKNOWN** otherwise |
| TST-004, TST-005 | Normal (pipeline / stage definitions) |
| TST-006 | Normal when the repo is recognised as ADF / Synapse / IaC from its pipelines' deploy targets; NOT_APPLICABLE when pipelines deploy application targets; **UNKNOWN** when neither is known |
| QLT-001..005, QLT-008 | Normal (pipeline + Sonar data). NOT_APPLICABLE for ADF/Synapse/IaC repos works through the inferred kind above |
| QLT-006, QLT-007 | Normal (Aikido); "docs-only" repos cannot be recognised without contents, so they are evaluated |
| SEC-001..005 | Normal (pipeline variables, variable groups, service connections) |
| DEP-001..006 | Normal (stages, approvals, ServiceNow) |
| SUP-001..005 | Normal (pipeline steps) |
| TGT-* | Normal (deploy steps); ADF/Synapse refinement from repo contents is not applied |
| HYG-001..003 | Normal (run history, owner) |
| Migration readiness (MIG) | Normal (pipeline-based) |
