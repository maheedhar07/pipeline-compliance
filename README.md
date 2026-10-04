# Pipeline Compliance Hub

A **report-only** web dashboard that scores the CI/CD pipelines of ~280 repositories against a policy catalog of 53 deterministic rules.
Sources: Azure DevOps (Classic build, Classic release, YAML), SonarQube, Aikido and ServiceNow. GitHub Actions support is planned (interface only today).
It never writes to ADO, GitHub, Sonar, Aikido or ServiceNow, and compliance is decided by Python rules, never by an AI.

* Repo-centric: one row per repo with its build and release pipelines, test state, Sonar gate, Aikido criticals, score and status.
* Understands Function Apps, Web Apps, AKS, Azure Data Factory, Synapse, SQL dacpac and IaC deployments.
* Highlights repos with **no tests** and tests that are **not run**; tracks **ServiceNow CRQ** coverage of production deployments.
* Ships with a realistic demo estate (280 repos) so you can see everything without credentials.

Docs: [plan](docs/PLAN.md) · [rule catalog](docs/RULES.md) · [decisions & assumptions](docs/DECISIONS.md)

## Quick start (demo, no credentials)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pch seed-demo --repos 280      # generate synthetic raw API payloads for 6 projects / 280 repos
pch scan --demo                # run them through the REAL collectors -> normalizers -> rules (about 15 s incl. 3 history snapshots)
pch serve                      # http://127.0.0.1:8000
```

Useful variants: `pch scan --demo --history 0` (single snapshot, about 3 s), `pch scan --demo --cache` (also write the redacted raw cache), `pch rules list`.

## Database

The same code runs on SQLite (default, dev/demo), PostgreSQL and Azure SQL / SQL Server; switching is a config change.

| Target | `DATABASE_URL` | Extra |
|---|---|---|
| SQLite | `sqlite:///data/pch.db` | none |
| PostgreSQL | `postgresql+psycopg://user:pw@host:5432/db` | `pip install '.[postgres]'` |
| SQL Server / Azure SQL (password) | `mssql+pyodbc://user:pw@host:1433/db?driver=ODBC+Driver+18+for+SQL+Server` | `.[azuresql]` + Microsoft ODBC Driver 18 |
| Azure SQL (Entra ID, no password) | `mssql+pyodbc://@srv.database.windows.net:1433/db?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes` with `DB_AUTH=azure_ad` | `.[azuresql]` + ODBC Driver 18 |

`DB_AUTH=azure_ad` fetches an access token with `azure-identity` `DefaultAzureCredential` (managed identity in App Service, `az login` locally), caches it and injects it into each new connection, refreshing it 5 minutes before expiry. The identity needs a database user (`CREATE USER [<app-name>] FROM EXTERNAL PROVIDER`) with `db_datareader`/`db_datawriter`, plus DDL rights (`db_ddladmin`) only for whoever runs `pch db upgrade`. If the extra is missing the app stops at startup with a clear message. Server databases use `pool_pre_ping`, and `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_TIMEOUT` and `DB_POOL_RECYCLE` (default 1800 s, below Azure SQL's ~30 min idle disconnect).

The provided Docker image contains the SQLite and PostgreSQL drivers only; for Azure SQL build an image that also installs the Microsoft ODBC Driver 18 and `pip install '.[azuresql]'` (see `docs/DEPLOY_AZURE.md` once T7 lands).

**Migrations (Alembic, shipped inside the package):**

```bash
pch db upgrade [--revision head]   # create / upgrade the schema (explicit deploy step)
pch db current                     # database revision vs. the revision this build expects
pch db check                       # exit 1 unless at head (CI / deploy gate)
pch db stamp head                  # adopt a database created by an older version (see below)
```

All accept `--db <url>`. The schema is never created implicitly except for SQLite in `APP_ENV=dev|test`, where startup runs `upgrade head` itself. In `prod` (or any non-SQLite database) `pch serve` and `pch scan` **refuse to start** with a clear error if the database is not at head. Set `DB_AUTO_MIGRATE=true` to let them migrate on startup instead; trade-off: convenient for a single instance, but the app identity then needs DDL rights and two instances starting together can race. Prefer running `pch db upgrade` once per release (docker compose does this with a one-shot `migrate` service; on App Service run it as a release step).

**Existing database created by an older version (`create_all`, no `alembic_version` table):** the app reports `database has tables but no alembic_version`. If it was created by the initial release, run `pch db stamp head` once; it records the revision without touching any table. Otherwise start from an empty database.

**Scan lock and failures:** `pch scan` takes a DB lock (table `scan_locks`, identical on all dialects); a concurrent scan exits with code 4. A lock older than `SCAN_LOCK_STALE_MINUTES` (default 360) is taken over with a warning. Scan results are committed in one transaction together with `status=complete`; on any error the scan is marked `failed`, and `running` scans abandoned by a crashed process are marked `failed` on the next scan.

## Providers

The core is cloud-neutral. Exactly two seams (package `pch.providers`) let a deployment swap backends; the Azure adapters are optional extras and the defaults need nothing.

| Seam | Setting | Values | Extra |
|---|---|---|---|
| Secrets (`SecretProvider`) | `SECRETS_PROVIDER` | `env` (default), `file`, `azure_keyvault` | `.[azure-keyvault]` for Key Vault |
| Raw scan cache (`ArtifactStore`) | `ARTIFACT_STORE` | `local` (default, `DATA_DIR/raw`), `azure_blob` | `.[azure-blob]` for Blob |

**Secrets.** Only the credentials of the configured sources are resolved (`ADO_PAT`, `SONAR_TOKEN`, `AIKIDO_CLIENT_SECRET`, `SERVICENOW_PASSWORD`), when the live clients are built. Providers are explicit and never mixed: with `file` or `azure_keyvault` the credential env vars are ignored, so a stale variable can not silently win. A missing secret stops the scan with an error that names it (`secret ADO_PAT was not found via SECRETS_PROVIDER=file`), never its value. Replaying a cache (`--from-cache`) needs no credentials.

* `env`: the Settings values. On Azure App Service the recommended path is to set app settings as Key Vault references (`@Microsoft.KeyVault(SecretUri=...)`); App Service resolves them with the app's managed identity and they arrive as ordinary env vars, so the default provider already works and the app needs no Azure code.
* `file`: `<SECRETS_DIR>/<NAME>` per secret (Kubernetes secret volume, Secrets Store CSI driver). One trailing newline is stripped, names containing separators or `..` and files resolving outside the directory are rejected, world-readable files log a warning.
* `azure_keyvault`: `KEYVAULT_URL` plus `DefaultAzureCredential` (managed identity in Azure, `az login` locally). `ADO_PAT` is read from the secret `ado-pat` (lowercase, `_` becomes `-`); override with `KEYVAULT_SECRET_MAP='{"ADO_PAT":"my-name"}'`. Values are cached in memory for `KEYVAULT_CACHE_TTL_SECONDS` (default 300), misses are never cached, SDK error text is never echoed. The identity needs *Key Vault Secrets User*.
* A database password is part of `DATABASE_URL`, not a provider secret: use `DB_AUTH=azure_ad` (no password) or a Key Vault reference for that app setting.

**Raw cache.** `pch scan` caches the redacted raw API responses (`--cache` / `--no-cache`) so `pch scan --from-cache <scan_id>` can re-evaluate them. Keys are `<scan_id>/<host>/<hash>.json`. Redaction always happens before the store is called (the stores never see an unredacted body, including non-JSON text bodies), and a store failure is logged once and never fails the scan. `local` rejects keys that escape the directory; `azure_blob` needs `ARTIFACT_BLOB_ACCOUNT_URL` and `ARTIFACT_BLOB_CONTAINER` and authenticates only with a managed identity (*Storage Blob Data Contributor* on the container): account keys, SAS tokens and connection strings are deliberately not supported. The demo `world.json.gz` stays on the local file system.

A missing extra raises a clear error, e.g. `Azure Key Vault support needs the 'azure-keyvault' extra: pip install 'pipeline-compliance[azure-keyvault]'`. `pch doctor` reports the provider, `set`/`missing` for every required secret, and does a write/read/delete probe of the artifact store.

## Dependency lockfile

`requirements.lock` pins every runtime dependency (plus the `postgres` extra) with hashes; the Dockerfile installs
from it with `--require-hashes`. Regenerate after editing dependencies in `pyproject.toml`:

```bash
pip install pip-tools
pip-compile --generate-hashes --extra postgres -o requirements.lock pyproject.toml   # add --upgrade to bump
```

`requirements-azure.lock` is the same plus every Azure extra, for the organisation's Azure image (regenerate both together; CI audits both and installs the Azure one with hashes):

```bash
pip-compile --generate-hashes --extra postgres --extra azuresql --extra azure-keyvault --extra azure-blob --extra azure-monitor -o requirements-azure.lock pyproject.toml
docker build --build-arg PCH_LOCKFILE=requirements-azure.lock -t pch:azure .
```

`azuresql` additionally needs the Microsoft ODBC Driver 18 in the image (see Database).

## Docker

```bash
docker compose up --build                                   # dashboard + Postgres on http://127.0.0.1:8000
docker compose run --rm app sh -c "pch seed-demo && pch scan --demo"   # demo data
docker compose run --rm app pch scan                        # real scan (needs .env)
```

The container image runs as a non-root user. Compose runs the app with `APP_ENV=dev`, `AUTH_MODE=none` and `AUTH_NONE_ALLOW_CONTAINER_BIND=true` (the app must listen on `0.0.0.0` inside the container) and publishes the port to `127.0.0.1` only. Never change that mapping: there is no sign-in in this mode.

## Pointing it at your real systems

1. `cp .env.example .env` and fill in the values (the file is gitignored; secrets only ever come from the environment).

   | Variable | Purpose |
   |---|---|
   | `ADO_ORG` | Azure DevOps organization name (`https://dev.azure.com/<org>`) |
   | `ADO_PAT` | Personal access token (read-only scopes below) |
   | `SONAR_URL`, `SONAR_TOKEN` | SonarQube base URL and a user token with *Browse* permission |
   | `AIKIDO_URL`, `AIKIDO_CLIENT_ID`, `AIKIDO_CLIENT_SECRET` | Aikido public API OAuth client credentials |
   | `SERVICENOW_URL`, `SERVICENOW_USER`, `SERVICENOW_PASSWORD` | ServiceNow user with read access to `change_request` |
   | `APP_ENV` | `dev` (default), `test` or `prod`. In `prod` a missing `config/scope.yaml` is an error |
   | `CONCURRENCY`, `HTTP_TIMEOUT` | Parallel requests (1-64) and per-request timeout seconds (>0, <=300) |
   | `DATABASE_URL` | `sqlite:///data/pch.db` (default), `postgresql+psycopg://user:pw@host/db` or an `mssql+pyodbc://` URL, see [Database](#database) |
| `SECRETS_PROVIDER`, `SECRETS_DIR`, `KEYVAULT_*`, `ARTIFACT_STORE`, `ARTIFACT_BLOB_*` | Secret and raw-cache backends, see [Providers](#providers) |
| `DB_AUTH`, `DB_POOL_*`, `DB_AUTO_MIGRATE`, `SCAN_LOCK_STALE_MINUTES` | Database auth mode, pool tuning, auto-migration and scan-lock timeout, see [Database](#database) |

   URLs must be `http(s)` (trailing slashes are stripped). Invalid values stop startup with a clear error. `.env.example` lists every variable.

   **`config/scope.yaml` and `config/policy.yaml`** ship as commented examples with placeholder values (`your-org`, `myorgacr.azurecr.io`); every field is documented inline. They are strictly validated: an unknown or mistyped key is an error such as `config/policy.yaml: waivers.0.expires: ...` (file plus field path). Set your organisation's Sonar quality gate via `sonar_quality_gate_name` (default `Sonar way`).

   **Check your setup with `pch doctor`** (`--json` for machines). It checks that settings load, scope/policy validate, which sources are configured and whether each has its credentials (printed only as `set`/`missing`, never values), that the database answers `SELECT 1`, and that `DATA_DIR` is writable. Output is `OK`/`WARN`/`FAIL` per check; exit code 1 if any check fails.

2. **ADO PAT scopes (all read-only):** Build (Read), Release (Read), Code (Read), Project and Team (Read), Service Connections (Read), Variable Groups (Read), Environment (Read), Task Groups (Read). Do not grant write, manage or execute scopes. The tool also refuses to send any non-GET request except the YAML `preview` call (`previewRun: true`).
3. Edit `config/scope.yaml` (projects, per-repo overrides: `sonar_key`, `aikido_repo`, `owner`, `servicenow_ci`, `coverage_threshold`, environment-name to tier overrides) and `config/policy.yaml` (thresholds, Sonar gate name, Aikido SLAs, approved registries, marketplace allowlist, waivers).
4. `pch scan` (live) or `pch scan --from-cache <scan_id>` to re-evaluate the cached, redacted raw responses of an earlier scan. Then `pch serve`.

Things to check on first contact with real data (all marked `# VERIFY:` in the code): the Aikido endpoint paths/field names (`collectors/aikido.py`), how your CRQ numbers appear in release names/descriptions/pipeline parameters (`collectors/ado/runs.py`), how the ServiceNow integration is attached to environments/release gates, and the resource-group scope fields of service connections.

## How it works

```
ADO / Sonar / Aikido / ServiceNow (read-only HTTP, retry/backoff, 429 aware, 8 parallel)
        |  collectors/*  (ReadOnlyTransport guard, redacted raw cache in data/raw/<scan_id>)
        v
canonical model (Pipeline > Stage > Job > Step, Approval, RepoFacts)    <- normalize/capabilities.yaml (task -> capability tags)
        |  target + environment-tier detection, repo scan, test-state classification
        v
rule engine (53 rules, registry + @rule)  ->  findings  ->  scoring + waivers  ->  snapshot in SQLite/Postgres/Azure SQL
        v
FastAPI + Jinja + HTMX + Chart.js dashboard   and   /api/v1 JSON API
```

Pages: Overview, Repos (filter/sort/CSV), Repo detail, Findings, Rules (+drill-down), Testing, Deploy targets, Migration readiness, Scans. Every number links to the findings behind it. JSON mirrors live under `/api/v1/` (see `/api/docs`).

Scoring: `score = 100 * sum(weight x credit) / sum(weight x applicable)` with critical 10, high 5, medium 3, low 1. A repo is **NON_COMPLIANT** with any critical failure, otherwise **AT_RISK** below 80 or with any high failure, otherwise **COMPLIANT**. Waivers turn failures into WAIVED until they expire.

Test states per repo: `TESTS_OK`, `TESTS_LOW_COVERAGE`, `TESTS_NO_COVERAGE`, `TESTS_NOT_RUN`, `NO_TESTS`, `NOT_APPLICABLE` (ADF / Synapse / IaC / docs repos get the validation rule TST-006 instead).

## Extending

**Add a rule** (one function, no other wiring; the runner, dashboard, API and `docs/RULES.md` pick it up):

```python
# src/pch/engine/rules/hygiene.py  (or a new module in that package)
from pch.engine.registry import rule
from pch.model.findings import RuleResult

@rule("HYG-004", "Pipeline has a description", "low", "pipeline",
      "Descriptions tell responders what a pipeline deploys.",
      {"classic": "Edit the definition and fill in the description.", "yaml": "Add a comment header to the YAML."})
def hyg_004(ctx, policy, p):                  # scope "repo": (ctx, policy); "pipeline": (ctx, policy, p); "stage": (ctx, policy, t)
    return RuleResult.passed("ok") if p.name else RuleResult.failed("unnamed")
```

Then add a PASS and a FAIL test in `tests/test_rules.py` (helpers in `tests/builders.py`), and run `pch rules docs --write docs/RULES.md` (a test fails if the file is stale). Optional filters on the decorator: `platforms=`, `targets=`, `tiers=`.

**Teach it a new task**: add it to `src/pch/normalize/capabilities.yaml` (task -> capability tags, `when:` conditions on inputs, regexes for inline scripts). Deprecated tasks live in `deprecated_tasks.yaml`, GitHub Actions equivalents in `gha_mapping.yaml`. These are data files, not code.

**Add a data source**: write a collector returning plain facts (see `collectors/sonar.py`), put them on `RepoContext`, and use them in rules. Keep unverified API details in one function with a `# VERIFY:` comment.

## Development

```bash
pytest --cov=pch            # unit tests; all HTTP is mocked (respx / in-memory demo transport)
ruff check . && mypy src
```

Collectors are tested against fixtures in `tests/fixtures/` (no live credentials are ever needed). The demo transport (`pch.demo.transport`) lets the whole pipeline run offline.

## Security notes

* Read-only by construction: a transport-level guard rejects non-GET requests (except the documented YAML preview POST and the Aikido OAuth token exchange); a test asserts a full scan sends nothing else, and that the web app exposes no mutating route.
* Secret values are never persisted: raw cache files are redacted before writing, variables are classified in memory (only names and reasons are stored), and stored pipeline JSON omits script bodies and secret-like inputs.
* Web security (T5) is described in the next section; every control fails closed and is covered by `tests/test_web_security.py`.

## Security (web)

**Authentication and authorisation.** `AUTH_MODE=easyauth` (production) expects Azure App Service Authentication ("Easy Auth") with Microsoft Entra ID in front of the app. The app reads `X-MS-CLIENT-PRINCIPAL`, takes roles from its signed claims only, and allows a request only if the user holds a role listed in `AUTH_ALLOWED_ROLES` (for example the Entra app role `PCH.Reader`). No principal -> 401, no allowed role -> 403 (a minimal page, no data), malformed or oversized (>16 KB) header -> 401. Only the health endpoints (`/health/live`, `/health/ready`, `/api/v1/health`: status only) and `/static/*` are reachable without a principal; pages, the JSON API, CSV export and OpenAPI all require one. `AUTH_MODE=none` is for local development: it is refused when `APP_ENV=prod` and when the bind host is not loopback. See `docs/DEPLOY_AZURE.md` and `docs/DECISIONS.md` (T5) for the matrix.

**Fail-closed startup guard** (`pch.web.guard.assert_safe_to_serve`, used by `create_app` and `pch serve`; `pch doctor` reports it as `auth` and `serve_guard`). The app refuses to start when: `AUTH_MODE=none` with `APP_ENV=prod`; `none` on a non-loopback host (except `APP_ENV=dev` + `AUTH_NONE_ALLOW_CONTAINER_BIND=true`, used by docker compose); `easyauth` with neither `AUTH_ALLOWED_ROLES` nor an explicit `AUTH_ALLOW_ANY_AUTHENTICATED=true`; `easyauth` unless `WEBSITE_AUTH_ENABLED=True` (otherwise `X-MS-*` headers are not stripped and can be forged; `AUTH_EASYAUTH_ASSUME_ENABLED=true` overrides this for local testing only and is itself refused in prod); `APP_ENV=prod` without `ALLOWED_HOSTS` (or with `*`).

**Browser hardening.** Strict CSP (`default-src 'self'`, no inline script or style, no third-party origins), `nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, COOP, minimal Permissions-Policy, HSTS in prod, `Cache-Control: no-store` on all data responses, on every response including errors. Only GET/HEAD are served (405 otherwise). `/api/docs` and `/openapi.json` are disabled in prod (in dev the docs page gets its own scoped CSP using a script hash and jsDelivr). Errors are generic with a correlation id (`X-Request-ID`); no tracebacks. `ALLOWED_HOSTS` is enforced (App Service: `<app>.azurewebsites.net` or `*.azurewebsites.net`); uvicorn runs with `proxy_headers=True`, `FORWARDED_ALLOW_IPS` and no `Server` header. Query parameters are bounded and sort keys whitelisted (422/400, never 500). External data is always escaped; JSON data blocks escape `<`, `>`, `&`; only `http(s)` URLs are rendered as links; CSV cells that start with `=`, `+`, `-`, `@` are neutralised.

**Vendored frontend assets (no CDN at runtime).** `src/pch/web/static/vendor/` holds Tailwind (generated, 3.4.17), HTMX 1.9.12 and Chart.js 4.4.3 with `MANIFEST.json` (version, source, sha256); a test recomputes the hashes. Rebuild Tailwind with `scripts/build_css.sh` (pinned standalone CLI, checksum verified; `--check` fails if the committed CSS is stale). To update HTMX/Chart.js: download the npm tarball, compare its `dist.shasum`/`dist.integrity` with the npm registry, copy the dist file, update `MANIFEST.json` and the filename in `templates/base.html`. Page scripts live in `static/app.js`; pages pass data through inert `<script type="application/json">` blocks.

## Operations

**Logging.** `LOG_FORMAT=text|json` (default `text`; `json` when `APP_ENV=prod`) and `LOG_LEVEL` (default `INFO`) apply to the CLI and the web app (`pch.logging_setup.configure_logging`). JSON lines carry `ts` (UTC), `level`, `logger`, `message`, `request_id`, `scan_id` (inside a scan), `exception` and, for requests, `method`, `path` (no query string), `status`, `duration_ms` and `principal` (a hash of the principal id, never the name or e-mail). A redaction filter on every handler scrubs bearer/basic credentials, `Authorization` headers, `pat/token/password/secret/api_key...` pairs, URL credentials (`scheme://user:pass@host`, e.g. DB URLs), well-known token formats and every secret value the secret provider or settings resolved (exact match) from the message, its arguments and exception text before it is written or exported. The request id is the inbound `X-Request-ID` if it matches `[A-Za-z0-9][A-Za-z0-9._-]{7,63}`, else a fresh UUID; it is echoed in the response header and the error pages. uvicorn's own access log (full URLs) is off in prod (`UVICORN_ACCESS_LOG` to override); the app's single structured request line replaces it.

**Health.** `GET /health/live` -> `200 {"status":"ok"}` (process only; no DB, so a DB outage never restarts the container). `GET /health/ready` -> `200 {"status":"ok"}` when the DB is reachable and migrated to head, else `503 {"status":"unavailable","reason":"db_unreachable|db_timeout|schema_not_ready"}` (no URLs or exception text). The probe has a 2.5 s budget (`HEALTH_READY_TIMEOUT_SECONDS`), is single-flight and cached for 5 s (`HEALTH_READY_CACHE_SECONDS`). Readiness deliberately excludes the artifact store, secret provider and external sources: the dashboard only reads the DB, and probing optional dependencies lets one flaky dependency pull every instance out of rotation at once. `/api/v1/health` stays as an alias of live (status + version). All three are unauthenticated and accept a loopback `Host`; the container `HEALTHCHECK` uses `/health/live`. A DB that is merely unreachable at start-up no longer stops `pch serve` (it serves `503` on `/health/ready` until the DB is back); a schema that is not at head still exits 3.

**Application Insights (optional).** `pip install 'pipeline-compliance[azure-monitor]'` (included in `requirements-azure.lock`) and set `APPLICATIONINSIGHTS_CONNECTION_STRING` (a secret: use a Key Vault reference). Unset = nothing is imported or exported. Set without the extra = exit 2 with the install hint. Logs go through the redaction filter before export; traces cover FastAPI, httpx (outbound to ADO/Sonar/...) and SQLAlchemy; request/response bodies and headers are never captured and a span processor strips query strings and URL credentials; the cloud role name is `pch-web` (`pch serve`) or `pch-scan` (`pch scan`, `pch scans prune`). Sampling is the distro's: set `OTEL_TRACES_SAMPLER` and `OTEL_TRACES_SAMPLER_ARG` (for example `microsoft.fixed_percentage` and `0.1`, or `microsoft.rate_limited` and traces per second). `pch doctor` shows `logging` and `telemetry`.

**Retention.** `pch scans prune [--keep N] [--older-than DAYS] [--dry-run]` (defaults `RETENTION_KEEP_SCANS` / `RETENTION_MAX_AGE_DAYS`; neither = error). A scan is deleted when it is outside the newest N scans **and** older than DAYS (with a single option only that condition applies). The latest `complete` scan and any `running` scan inside the stale window are never deleted. For each scan the artifact-store prefix `<scan_id>/` is deleted first, then its DB rows in one transaction (children in chunks, then `delete_scan`). A real run holds the scan lock (exit 4 if a scan is running); `--dry-run` is read-only and takes no lock. Schedule it after the scan, for example `pch scan && pch scans prune --keep 30 --older-than 90`.

**Shutdown and timeouts.** uvicorn drains in-flight requests for `GRACEFUL_SHUTDOWN_SECONDS` (default 20) after SIGTERM; keep-alive is `KEEP_ALIVE_SECONDS` (default 65). On shutdown the app disposes its DB engine. `pch scan` turns SIGTERM/SIGINT into a cancellation: collectors stop, the scan is marked `failed` with reason `interrupted`, the lock is released and the exit code is 5. `SCAN_TIMEOUT_MINUTES` (default 240) does the same with reason `timeout`.

**`pch scan` exit codes** (constants in `pch/exitcodes.py`):

| Code | Meaning |
|---|---|
| 0 | scan completed |
| 1 | generic failure (for example demo data missing; `prune` had failures) |
| 2 | configuration error (invalid settings/YAML, missing secret or extra, `ADO_ORG` unset) |
| 3 | database not ready (not at migration head, unreachable, driver missing) |
| 4 | another scan (or prune) holds the scan lock |
| 5 | interrupted (SIGTERM/SIGINT) or timed out; the scan row is `failed` and the lock released |

## Roadmap

M9: GitHub Actions adapter (`collectors/github/` interface exists). M10: read-only agent layer (`pch/agent/tools.py` exposes `list_findings`, `get_repo`, `explain_rule`; MCP server and chat panel are stubs). The AI layer will explain findings, never decide compliance.
