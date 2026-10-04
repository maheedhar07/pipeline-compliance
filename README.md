# Pipeline Compliance Hub

A **report-only** CI/CD compliance dashboard, built as a template you import and extend. It scores every repository's pipelines (Azure DevOps YAML and Classic, GitHub Actions; SonarQube, Aikido and ServiceNow as supporting sources) against 61 deterministic Python rules and serves the result as a server-rendered dashboard plus a JSON API.
It never writes to Azure DevOps, GitHub, SonarQube, Aikido or ServiceNow (a transport-level guard, tested), never persists secret values, and fails closed when misconfigured.
Standards are configuration (`config/policy.yaml`, `config/scope.yaml`); five seams (database, secrets, auth, artifact storage, source collectors) are swappable by settings.

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"
pch seed-demo --repos 280 && pch scan --demo     # synthetic API payloads -> REAL collectors -> rules (~15 s)
pch serve                                        # http://127.0.0.1:8000  (AUTH_MODE=none, loopback only)
```

Variants: `pch scan --demo --history 0` (single snapshot), `pch scan --demo --cache` (also write the redacted raw cache), `pch rules list`. The demo keeps the GitHub reader disabled, so its GitHub-only checks show UNKNOWN.

## Start here

| You want to... | Read |
|---|---|
| Adopt it in your organisation (ordered phases, commands, troubleshooting) | [docs/USING_IN_YOUR_ORG.md](docs/USING_IN_YOUR_ORG.md) |
| Change a standard, threshold, severity or scope | [docs/STANDARDS.md](docs/STANDARDS.md) |
| Extend it (rule, collector, DB, auth, rebrand, dependencies) | [docs/CUSTOMIZING.md](docs/CUSTOMIZING.md) |
| Work on it with an AI coding assistant | [docs/AI_GUIDE.md](docs/AI_GUIDE.md) and [CLAUDE.md](CLAUDE.md) |
| Host the dashboard on Azure App Service (optional) | [docs/DEPLOY_AZURE.md](docs/DEPLOY_AZURE.md) |
| Review security | [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Background | [docs/RULES.md](docs/RULES.md) (generated catalog), [docs/DECISIONS.md](docs/DECISIONS.md), [docs/PLAN.md](docs/PLAN.md), [docs/TEMPLATE_PLAN.md](docs/TEMPLATE_PLAN.md) |

## Configuration reference

Settings are environment variables (or a `.env` file; copy `.env.example`). Invalid values stop startup with a clear error naming the variable, and
`pch doctor` validates the whole setup (credentials are reported only as `set` / `missing`; see [docs/USING_IN_YOUR_ORG.md](docs/USING_IN_YOUR_ORG.md)). This table is generated from the `Settings` class
(`pch config reference`) and a test fails when it, `src/pch/config_reference.py` or `.env.example` drift from the code.

<!-- config-reference:start -->
| Variable | Default | Description |
|---|---|---|
| **Runtime** | | |
| `APP_ENV` | `dev` | Profile: `dev`, `test` or `prod`. `prod` turns on the fail-closed checks (https-only sources, `ALLOWED_HOSTS`, no `AUTH_MODE=none`, no auto-migrate of SQLite, `config/scope.yaml` required). |
| `DATA_DIR` | `data` | Local data directory (SQLite file, demo world, local raw cache under `raw/`). |
| `CONFIG_DIR` | `config` | Directory holding `scope.yaml` and `policy.yaml`. |
| **Database** | | |
| `DATABASE_URL` | `sqlite:///data/pch.db` | SQLAlchemy URL: `sqlite:///...`, `postgresql+psycopg://...` or `mssql+pyodbc://...`. May embed a password (never printed). |
| `DB_AUTH` | `password` | `password` (credentials in the URL) or `azure_ad` (Entra access token via `DefaultAzureCredential`; Azure SQL only). |
| `DB_POOL_SIZE` | `5` | Connection pool size (server databases; 1-100). |
| `DB_MAX_OVERFLOW` | `10` | Extra connections above the pool size (0-200). |
| `DB_POOL_RECYCLE` | `1800` | Recycle connections after N seconds (-1 = never). Keep below Azure SQL's ~30 min idle disconnect. |
| `DB_POOL_TIMEOUT` | `30` | Seconds to wait for a pooled connection (0-600). |
| `DB_CONNECT_TIMEOUT_SECONDS` | `15` | Seconds to wait when opening a new server connection (psycopg `connect_timeout`, pyodbc login `timeout`; 1-300). Ignored for SQLite. |
| `DB_AUTO_MIGRATE` | `false` | Run `alembic upgrade head` at startup on any database. Off by default; prefer `pch db upgrade` as a deploy step. |
| `SCAN_LOCK_STALE_MINUTES` | `360` | A scan lock or `running` scan older than this is treated as abandoned. Must be greater than `SCAN_TIMEOUT_MINUTES`. |
| **Providers** | | |
| `SECRETS_PROVIDER` | `env` | Where source credentials come from: `env` (default; App Service Key Vault references arrive as env vars), `file`, `azure_keyvault`. Never mixed. |
| `SECRETS_DIR` | (unset) | Directory with one file per secret (`file` provider; required for it). |
| `KEYVAULT_URL` | (empty) | `https://<vault>.vault.azure.net` (required for `azure_keyvault`; https only). |
| `KEYVAULT_SECRET_MAP` | `{}` | JSON map env-style name -> Key Vault secret name (default: lowercase, `_` -> `-`, e.g. `ADO_PAT` -> `ado-pat`). |
| `KEYVAULT_CACHE_TTL_SECONDS` | `300` | In-memory cache of Key Vault values (0 = always re-read; 0-86400). |
| `ARTIFACT_STORE` | `local` | Raw scan cache backend: `local` or `azure_blob`. |
| `ARTIFACT_BLOB_ACCOUNT_URL` | (empty) | `https://<account>.blob.core.windows.net` (required for `azure_blob`; managed identity only). |
| `ARTIFACT_BLOB_CONTAINER` | (empty) | Blob container name (required for `azure_blob`). |
| **Azure DevOps** | | |
| `ADO_ORG` | (empty) | Organization name (`https://dev.azure.com/<org>`). Required for live scans (or set `organization` in scope.yaml; both set must be equal). |
| `ADO_PAT` | (empty) | Read-only personal access token (secret). |
| `ADO_BASE_URL` | `https://dev.azure.com` | Base URL of Azure DevOps Services (change for Azure DevOps Server). https in prod. |
| `ADO_VSRM_URL` | `https://vsrm.dev.azure.com` | Base URL of the release management service. https in prod. |
| **GitHub** | | |
| `GITHUB_API_URL` | `https://api.github.com` | GitHub REST API base URL: `https://api.github.com`, or GHES `https://<host>/api/v3`. https in prod. Only this host is ever called (pagination links elsewhere are refused). |
| `GITHUB_AUTH` | `pat` | `pat` (fine-grained personal access token, default) or `app` (GitHub App installation; needs the `github-app` extra). |
| `GITHUB_TOKEN` | (empty) | Fine-grained PAT, READ-ONLY (Metadata, Contents, Actions, Environments, Deployments, Administration: read) (secret). Setting it enables the GitHub reader. |
| `GITHUB_APP_ID` | (empty) | Numeric GitHub App id (`GITHUB_AUTH=app`). |
| `GITHUB_APP_INSTALLATION_ID` | (empty) | Numeric installation id of the App on your organisation (`GITHUB_AUTH=app`). |
| `GITHUB_APP_PRIVATE_KEY` | (empty) | App private key, PEM; a one-line value with literal backslash-n line breaks is accepted (secret). |
| **SonarQube** | | |
| `SONAR_URL` | (empty) | SonarQube base URL. Unset = Sonar not queried. https in prod. |
| `SONAR_TOKEN` | (empty) | User token with Browse permission (secret). |
| **Aikido** | | |
| `AIKIDO_URL` | `https://app.aikido.dev` | Aikido base URL. https in prod. |
| `AIKIDO_CLIENT_ID` | (empty) | OAuth client id. Setting it enables Aikido. |
| `AIKIDO_CLIENT_SECRET` | (empty) | OAuth client secret (secret). |
| **ServiceNow** | | |
| `SERVICENOW_URL` | (empty) | ServiceNow instance URL. Unset = not queried. https in prod. |
| `SERVICENOW_USER` | (empty) | User with read access to `change_request`. |
| `SERVICENOW_PASSWORD` | (empty) | Password of that user (secret). |
| **Collection** | | |
| `CONCURRENCY` | `8` | Parallel requests per source (1-64). |
| `HTTP_TIMEOUT` | `30` | Per-request timeout in seconds (>0, <=300). |
| `HTTP_MAX_RESPONSE_MB` | `50` | Largest single upstream response body in MB (1-2048). Larger responses are aborted while streaming and recorded as a collection error. |
| **Lineage and export** | | |
| `LINEAGE_ENABLED` | `true` | Collect the last deployment per stage/environment for the Lineage tab (two extra read-only calls per release definition, one per YAML environment). `false`: stages show as unknown. |
| `LINEAGE_DEPLOYMENTS_TOP` | `200` | Deployments / environment records requested per lookup (10-1000). A stage missing from the page gets a targeted lookup before it is shown as never deployed. |
| `EXPORT_MAX_ROWS` | `200000` | Largest CSV/Excel lineage export in rows (1-5000000). A bigger export is refused with HTTP 413: narrow the filters. |
| **Web server** | | |
| `HOST` | `127.0.0.1` | Bind address. Non-loopback needs an authenticated mode (see guard rules in README). |
| `PORT` | `8000` | Listen port (1-65535). |
| `WEBSITES_PORT` | (unset) | App Service container port; used when `PORT` is not set. |
| `ALLOWED_HOSTS` | (empty) | Comma-separated Host allowlist (wildcards like `*.azurewebsites.net`). Required in prod; a bare `*` is refused. |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxy IPs trusted for `X-Forwarded-*`. `*` only behind the App Service front end. |
| **Web authentication** | | |
| `AUTH_MODE` | `none` | `none` (dev only, loopback only) or `easyauth` (App Service Authentication + Entra app roles). |
| `AUTH_ALLOWED_ROLES` | (empty) | Comma-separated Entra app role values allowed to use the app, e.g. `PCH.Reader`. Exact, case-sensitive match. |
| `AUTH_ALLOW_ANY_AUTHENTICATED` | `false` | Explicit opt-in: any signed-in user passes when no role allowlist is set. |
| `AUTH_ADMIN_ROLES` | (empty) | Comma-separated Entra app role values (e.g. `PCH.Admin`) that may change the feature switches on the Settings page. Empty with `easyauth`: nobody can (read-only for all). An admin role also grants read access. With `AUTH_MODE=none` the local developer is the admin. |
| `SETTINGS_SIGNING_KEY` | (empty) | Secret (>= 32 characters, via the secret provider) that signs the Settings form tokens (CSRF). Unset: dev/test use a random per-process key; prod has no key, so the Settings page is read-only. |
| `WEBSITE_AUTH_ENABLED` | (empty) | Set by App Service when Authentication is on; do not set by hand. `easyauth` refuses to start unless it is `True`. |
| `AUTH_EASYAUTH_ASSUME_ENABLED` | `false` | Local testing of `easyauth` only; refused in prod. |
| `AUTH_NONE_ALLOW_CONTAINER_BIND` | `false` | Dev only (docker compose): allow `AUTH_MODE=none` on `0.0.0.0`. Refused in prod. |
| **Operations** | | |
| `LOG_FORMAT` | (unset) | `text` or `json`. Unset: `json` when `APP_ENV=prod`, else `text`. |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`. |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | (empty) | Enables Application Insights export (needs the `azure-monitor` extra). A secret: use a Key Vault reference. |
| `UVICORN_ACCESS_LOG` | (unset) | uvicorn access log (full URLs). Unset: off in prod, on otherwise. |
| `GRACEFUL_SHUTDOWN_SECONDS` | `20` | Seconds uvicorn drains in-flight requests after SIGTERM (1-600). Keep below the platform stop window. |
| `KEEP_ALIVE_SECONDS` | `65` | Idle keep-alive of client connections (1-600). Keep above the front end's idle reuse window. |
| `SCAN_TIMEOUT_MINUTES` | `240` | A scan running longer is cancelled and marked `failed` (reason `timeout`). Must be smaller than `SCAN_LOCK_STALE_MINUTES`. |
| `HEALTH_READY_TIMEOUT_SECONDS` | `2.5` | Time budget of the `/health/ready` DB probe (0-30). |
| `HEALTH_READY_CACHE_SECONDS` | `5` | How long a readiness result is cached (0-300). |
| `RETENTION_KEEP_SCANS` | (unset) | Default `--keep` for `pch scans prune` (unset = no default). |
| `RETENTION_MAX_AGE_DAYS` | (unset) | Default `--older-than` for `pch scans prune` (unset = no default). |
| `SCAN_STALE_HOURS` | `36` | The dashboard shows a warning banner when the latest complete scan is older than this many hours (1-8760), or when the latest scan failed. Set it above your scan interval. |
<!-- config-reference:end -->

URLs must be `http(s)` without query string (trailing slashes are stripped); in `APP_ENV=prod` every configured source URL must be `https://`.

## Database

The same code runs on SQLite (default, dev/demo), PostgreSQL and Azure SQL / SQL Server; switching is a config change.

| Target | `DATABASE_URL` | Extra |
|---|---|---|
| SQLite | `sqlite:///data/pch.db` | none |
| PostgreSQL | `postgresql+psycopg://user:pw@host:5432/db` | `pip install '.[postgres]'` |
| SQL Server / Azure SQL (password) | `mssql+pyodbc://user:pw@host:1433/db?driver=ODBC+Driver+18+for+SQL+Server` | `.[azuresql]` + Microsoft ODBC Driver 18 |
| Azure SQL (Entra ID, no password) | `mssql+pyodbc://@srv.database.windows.net:1433/db?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes` with `DB_AUTH=azure_ad` | `.[azuresql]` + ODBC Driver 18 |

`DB_AUTH=azure_ad` fetches an access token with `azure-identity` `DefaultAzureCredential` (managed identity in App Service, `az login` locally), caches it and injects it into each new connection, refreshing it 5 minutes before expiry. The identity needs a database user (`CREATE USER [<app-name>] FROM EXTERNAL PROVIDER`) with `db_datareader`/`db_datawriter`, plus DDL rights (`db_ddladmin`) only for whoever runs `pch db upgrade`. If the extra is missing the app stops at startup with a clear message. Server databases use `pool_pre_ping`, and `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_TIMEOUT` and `DB_POOL_RECYCLE` (default 1800 s, below Azure SQL's ~30 min idle disconnect).

The provided Docker image contains the SQLite and PostgreSQL drivers only; for Azure SQL build an image that also installs the Microsoft ODBC Driver 18 and uses `requirements-azure.lock` (see the Dockerfile example in [docs/DEPLOY_AZURE.md](docs/DEPLOY_AZURE.md)).

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

**Secrets.** Only the credentials of the configured sources are resolved (`ADO_PAT`, `GITHUB_TOKEN` or `GITHUB_APP_PRIVATE_KEY`, `SONAR_TOKEN`, `AIKIDO_CLIENT_SECRET`, `SERVICENOW_PASSWORD`), when the live clients are built. Providers are explicit and never mixed: with `file` or `azure_keyvault` the credential env vars are ignored, so a stale variable can not silently win. A missing secret stops the scan with an error that names it (`secret ADO_PAT was not found via SECRETS_PROVIDER=file`), never its value. Replaying a cache (`--from-cache`) needs no credentials.

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

The `github-app` extra (GitHub App auth) is in neither lockfile; add `--extra github-app` to the `pip-compile` command below if you use `GITHUB_AUTH=app` ([docs/CUSTOMIZING.md](docs/CUSTOMIZING.md#9-dependency-updates)).

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

## How it works

```
ADO / Sonar / Aikido / ServiceNow (read-only HTTP, retry/backoff, 429 aware, 8 parallel)
        |  collectors/*  (ReadOnlyTransport guard, redacted raw cache in data/raw/<scan_id>)
        v
canonical model (Pipeline > Stage > Job > Step, Approval, RepoFacts)    <- normalize/capabilities.yaml (task -> capability tags)
        |  target + environment-tier detection, repo scan, test-state classification
        v
rule engine (61 rules, registry + @rule)  ->  findings  ->  scoring + waivers  ->  snapshot in SQLite/Postgres/Azure SQL
        v
FastAPI + Jinja + HTMX + Chart.js dashboard   and   /api/v1 JSON API
```

Pages: Overview (status, severity, migration donuts; compliance by project and by owner; trend; top failing rules and reasons; every chart and tile is clickable and opens the filtered list), Repos (filter chips, sortable columns, pagination, a column chooser, CSV, a "Why" column), Repo detail ("Why this repo is ..." box, "Fix first" list, score by category, score trend, lineage preview), Findings, Rules (+drill-down), Testing, Deploy targets, Migration readiness, Scans, Lineage (last tab, with CSV/Excel export). Every number links to the findings behind it. JSON mirrors live under `/api/v1/` (see `/api/docs`).

Scoring: `score = 100 * sum(weight x credit) / sum(weight x applicable)` with critical 10, high 5, medium 3, low 1 (defaults; severity, category and WARN weights are configurable under `scoring:` in `config/policy.yaml`). A repo is **NON_COMPLIANT** with any critical failure, otherwise **AT_RISK** below 80 or with any high failure, otherwise **COMPLIANT**. Waivers turn failures into WAIVED until they expire.

**Standards are configuration.** Every rule can be disabled, re-rated or tuned in `config/policy.yaml` (`rules: {QLT-004: {enabled: false}, DEP-001: {severity: high}, DEP-005: {params: {window_slack_hours: 4}}}`); `docs/STANDARDS.md` is the one page that maps every knob (file, key, default, which rules use it, how to verify): [docs/STANDARDS.md](docs/STANDARDS.md). The rules and their tunable params are in [docs/RULES.md](docs/RULES.md); `pch rules list --params` prints them.

**GitHub Actions as a pipeline platform (G3).** With the GitHub reader configured, every repo's workflows (`.github/workflows`, default branch) are read-only collected and assessed as `Pipeline(platform="gha")` with the same rule catalog: jobs are stages, jobs with `environment:` are deployment stages whose protection (required reviewers, prevent self-review, wait timer, deployment branches, custom protection rules such as ServiceNow) is read from the environments API, runs give HYG-001/002, and the last deployment per environment feeds the lineage. Needs the read-only permissions **Actions, Environments, Deployments** (plus Contents, Metadata); anything unreadable (denied permission, unreadable reusable workflow, invalid YAML) is UNKNOWN with the reason, never FAIL. Five rules are GitHub-specific: SUP-006 (actions pinned to a commit SHA), SEC-006 (least-privilege token permissions), SEC-007 (`pull_request_target` / `workflow_run` safety), SEC-008 (script injection), SEC-009 (self-hosted runners on public triggers); the others carry GHA semantics or are NOT_APPLICABLE, rule by rule in ADR-17 ([docs/DECISIONS.md](docs/DECISIONS.md)). Action capabilities, deprecated actions and rule params are data/config ([docs/STANDARDS.md](docs/STANDARDS.md)). The **Migration** tab shows each repo as ADO only / In progress (both) / Migrated (GHA only) / No pipelines with counts and a filter, lists ADO pipelines that look superseded by a workflow (candidates to retire), and its readiness score covers Azure DevOps pipelines only. Repo pages badge each pipeline (ADO YAML / ADO Classic / GitHub Actions). GitHub Actions is not in the demo data; the respx-fixture tests (`tests/test_gha_*.py`) carry the verification.

**Why is a repo not compliant?** Each repo carries an ordered list of reasons (its failing rules, critical first, one per rule: `<RULE-ID> <short title>: <message>`), computed once per scan and stored with the repo result. They appear in the Repos "Why" column (top 3, "+N more"), the Overview "Top reasons" panel (click through to the failing repos/findings), the repo page, the Lineage tab (repo status and reasons; failing rules on pipelines and stages), the CSV/Excel exports (`reasons` column) and the JSON API (`reasons` list).

Test states per repo: `TESTS_OK`, `TESTS_LOW_COVERAGE`, `TESTS_NO_COVERAGE`, `TESTS_NOT_RUN`, `NO_TESTS`, `UNKNOWN`, `NOT_APPLICABLE` (ADF / Synapse / IaC / docs repos get the validation rule TST-006 instead).

**Code on GitHub, pipelines in Azure DevOps.** GitHub is the default code host (`code_hosts: [github]` in `config/scope.yaml`; Azure Repos stays available as an opt-in for template reuse, but its API is not called and pipelines sourced from it are out of scope unless `azure_repos` is listed). Repos are discovered per ADO project from the repositories that build definitions and classic release artifacts point at, plus any `org/repo` named in `scope.yaml` `repos:`, so GitHub-hosted repos appear everywhere (named `org/repo`). The provider badge and the "Code hosted on" filter only show when more than one code host is in the scan. Pipeline, release, environment, Sonar, Aikido and ServiceNow rules evaluate normally. Checks that need data only GitHub has (branch protection, CODEOWNERS, repository contents for test detection) are read by the **read-only GitHub reader** when `GITHUB_TOKEN` (or a GitHub App) is configured, see below; without it they are **UNKNOWN with a reason, never FAIL**, and without `github.orgs`/`repos:` a GitHub repo that no ADO pipeline references is not scanned (ADR-13). The demo estate is ~70% GitHub-hosted but runs with the GitHub reader disabled, so its GitHub-only checks show UNKNOWN; the reader is covered by respx-fixture tests.

**GitHub reader (read-only, G2).** Set `GITHUB_TOKEN` (fine-grained PAT, default) or `GITHUB_AUTH=app` with an App installation (`pip install '.[github-app]'`); `GITHUB_API_URL` for GitHub Enterprise Server (`https://<host>/api/v3`). Name the organisations in `config/scope.yaml`:

```yaml
github:
  orgs: [acme]               # GET /orgs/acme/repos?type=all
  include: ["*"]             # globs on repo or org/repo (case-insensitive)
  exclude: ["sandbox-*"]
  topics_any: []             # keep repos with at least one of these topics (empty = no filter)
  include_archived: false
  include_forks: false
```

Repos = the filtered org listing, plus repos ADO pipelines reference, plus `repos:` entries. Repos with no ADO pipeline are grouped under their GitHub organisation, so their key is `<org>/<org>/<repo>` (ADO-referenced repos stay `<ADO project>/<org>/<repo>`; waivers, `exclude_repos` and overrides use that key). Per repo it reads metadata, the file tree (tests, Dockerfiles, IaC; no clone), CODEOWNERS (its `*` owner becomes the repo owner unless `scope.yaml` sets one) and the **effective default-branch rules** (rulesets and classic protection merged), which feed SRC-001..003, SRC-007..009 and TST-001..003/006. **The token must be read-only** (a write-capable token is a needless blast radius; the code only sends GETs and a guard enforces it) with repository permissions **Metadata: read, Contents: read, Administration: read**; Administration is only for classic branch protection, without it that part is UNKNOWN. For GitHub Actions workflows (G3) also **Actions: read, Environments: read, Deployments: read**. Anything the token cannot read becomes UNKNOWN with the missing permission named. `pch doctor` checks the configuration offline; `pch doctor --online` also calls `GET /rate_limit` and probes one repo per permission. Details: [docs/CUSTOMIZING.md](docs/CUSTOMIZING.md#github-reader), ADR-16.

## Lineage

The **Lineage** tab (last in the navigation) maps what comes out of each repository, per scan, from Azure DevOps pipelines and GitHub Actions workflows:

```
repo (provider badge, default branch, service connection)
  -> CI pipelines (YAML or classic: id, name, definition path, triggers, artifacts, YAML in another repo?)
       -> downstream pipelines (YAML `resources.pipelines`, classic build completion)
  -> releases (classic release definitions: artifact source, CD trigger, branch filters) or YAML deployment stages
       -> stages in order (environment, tier, depends on, targets with resource names, service connections, approvals/gates)
            -> last deployment per stage (version, artifact version, date, result, who triggered it: display name only)
```

* **Flow view** (default on the repo page, `?view=table` for the table): Repo -> pipelines (ADO YAML / ADO Classic / GitHub Actions badge, last run) -> releases / deploy workflows -> environment stages in order (tier colour, target icons, approval and ServiceNow badges, last-deploy chip), drawn as connected cards with plain CSS connectors. Downstream triggers (`workflow_run`, pipeline completion) are dashed side branches; each card shows its failing-rule count linking to the matching findings. The frame scrolls horizontally inside the card; a compact flow is previewed on the repo page.
* List view: a sortable, paginated table with one row per repo and a compact chain (pipelines -> releases -> environment chips with the last-deploy status); the **Flow** button of a row loads its flow on first open (no inline script), or use `/lineage/{project}/{repo}` for one repo (linked from the Repos table and the repo page). Filters: project, code host, deploy target, environment tier, has prod deployment (a prod stage whose last deployment succeeded), orphans only, search (repo, pipeline, release, environment, service connection and target resource names), plus the scan selector.
* **Orphans**: pipelines whose repository cannot be resolved, releases with no linked build, and repos without any pipeline or release. A GitHub repo that no pipeline builds is listed only when the GitHub reader discovers it (`github.orgs`) or `scope.yaml` names it.
* **Unknown is not "never".** A stage whose deployment data could not be collected shows `unknown (not collected)`; `never deployed` only appears when the lookup succeeded and found nothing. Failures are collection errors (see Scans), never a crash.
* Data: reuses what the scan already collects (definitions, expanded YAML, environments and checks, service connections, build runs) plus read-only GETs for the last deployments (ADR-14): two calls per classic release definition, one call per YAML environment. `LINEAGE_ENABLED=false` skips them (stages show as unknown); `LINEAGE_DEPLOYMENTS_TOP` sizes the lookups.
* People: only the **display name** of whoever triggered the last deployment is stored and shown. E-mails/UPNs are dropped, approvers are summarised as counts and kinds, never named.

**Export.** *Export CSV* and *Export Excel* on the page (`GET /lineage.csv`, `GET /lineage.xlsx`) honour the current filters and scan (the same query parameters as the page and `GET /api/v1/lineage`), require the same authentication as every page, are never cached (`Cache-Control: no-store`) and download as `pch-lineage[-<project>]-<scan date>.csv|xlsx`. A larger export than `EXPORT_MAX_ROWS` (default 200000 rows) is refused with HTTP 413 and a message; narrow the filters. The CSV is UTF-8 with a BOM (Excel opens it correctly), CRLF line ends, one row per repo -> pipeline -> release/deploy-stage path (a repo without pipelines or releases still gets one row; orphans are in the Excel "Orphans" sheet and the JSON API). The workbook has three sheets: **Summary** (scan info, filters, counts by project / code host / deploy target / tier / last-deploy status), **Lineage** (the CSV columns; frozen header, autofilter, column widths, real Excel dates) and **Orphans**. It is written in streaming (write-only) mode. Spreadsheet formula injection: names are attacker-influenced, so every text cell is written with an explicit string type and a value starting with `=`, `+`, `-`, `@` also gets a leading apostrophe (same rule as `/repos.csv`); a test loads the workbook and asserts that no cell is a formula.

JSON: `GET /api/v1/lineage` (same filters; `repos` with the nested documents, `orphans`, `summary`, `options`) and `GET /api/v1/lineage/{project}/{repo}`.

<a id="lineage-export-columns"></a>
**Export columns** (CSV and the Excel "Lineage" sheet; the order is stable, new columns are only ever appended):

| # | Column | Meaning |
|---|---|---|
| 1 | `project` | ADO project the repo is grouped under. |
| 2 | `repo` | Repo name (`org/repo` for GitHub-hosted code). |
| 3 | `provider` | `azure_repos`, `github`, `github_enterprise` or `other_git`. |
| 4 | `default_branch` | Default branch of the repo. |
| 5 | `repo_service_connection` | Name of the service connection ADO uses to read the code (GitHub repos). |
| 6 | `pipeline_kind` | `yaml`, `classic_build`; empty when the row has no CI pipeline. |
| 7 | `pipeline_id` | Build definition id. |
| 8 | `pipeline_name` | Build definition name. |
| 9 | `pipeline_url` | Link to the definition in Azure DevOps. |
| 10 | `definition_path` | YAML file name, or the classic definition's folder. |
| 11 | `yaml_repo` | Repo that holds the YAML file (YAML only). |
| 12 | `yaml_in_other_repo` | `yes` when the YAML lives in a different repo than the code (`resources.repositories` + `checkout:`), else `no`. |
| 13 | `defined_in_repo` | Set when this row's pipeline is defined in ANOTHER repo (the one named here) and builds this repo's code. |
| 14 | `ci_trigger` | CI trigger: branches (and paths), `CI off`, or empty when unknown. |
| 15 | `pr_trigger` | PR trigger branches / `PR off` (empty = not in the definition: branch policy). |
| 16 | `schedules` | Scheduled runs. |
| 17 | `artifacts` | What the pipeline publishes (`artifact: drop`, `image: repo`, `package: nuget`). |
| 18 | `upstream_pipelines` | Pipelines this one consumes (`resources.pipelines`, classic build-completion trigger). |
| 19 | `downstream_pipelines` | Pipelines that consume this one, with their repo key. |
| 20 | `ci_last_run_status` | Result of the last completed build (`succeeded`, `failed`, ...). |
| 21 | `ci_last_run_number` | Its build number. |
| 22 | `ci_last_run_time_utc` | When it finished (real Excel date). |
| 23 | `release_kind` | `classic_release` or `yaml_stages` (the stage columns belong to the YAML pipeline); empty if none. |
| 24 | `release_id` | Classic release definition id. |
| 25 | `release_name` | Classic release definition name. |
| 26 | `release_url` | Link to the release definition. |
| 27 | `release_source` | Artifact source(s): `Build: <pipeline>` or `GitHub: org/repo@branch`. |
| 28 | `release_trigger` | Continuous-deployment trigger and branch filters, schedules. |
| 29 | `stage_order` | 1-based position of the stage in its release / pipeline. |
| 30 | `stage` | Stage (release environment) name. |
| 31 | `environment` | Environment name (YAML: the `environment:` of the deployment job). |
| 32 | `tier` | `dev`, `test`, `uat`, `prod` or `unknown`. |
| 33 | `depends_on` | Stages this stage waits for. |
| 34 | `deploy_targets` | Target kinds: `functionapp`, `webapp`, `aks`, `adf`, `synapse`, `sql`, `iac`, `other`. |
| 35 | `target_resources` | Resource names from task inputs: `functionapp: orders-fn (rg x, slot staging)`, `aks: cluster (ns y)`, `sql: server/db`. |
| 36 | `service_connections` | Service connection names used by the stage. |
| 37 | `approvals_gates` | Approvals, checks and gates as summaries (kinds and counts, never approver names). |
| 38 | `last_deploy_status` | `succeeded`, `partial`, `failed`, `in_progress`, `pending`, `canceled`, `never` (collected, none found) or `unknown` (not collected). |
| 39 | `last_deploy_version` | Release name (classic) or run number (YAML). |
| 40 | `last_deploy_artifact_version` | Build number / short commit SHA of the deployed artifact. |
| 41 | `last_deploy_time_utc` | Completion (else start) time, UTC (real Excel date). |
| 42 | `last_deploy_by` | Display name of whoever triggered it (never an e-mail/UPN). |
| 43 | `last_deploy_url` | Link to the release / run. |
| 44 | `status` | Compliance status of the repo (`COMPLIANT`, `AT_RISK`, `NON_COMPLIANT`), repeated on every row of the repo. |
| 45 | `score` | Compliance score 0-100 of the repo (empty when no rule applies). |
| 46 | `reasons` | Why the repo is not compliant: its failing rules, most severe first, as `<RULE-ID> <short title>: <message>` separated by `; `. |
| 47 | `platform` | Pipeline platform: `ado_yaml`, `ado_classic_build`, `ado_classic_release` or `gha` (GitHub Actions workflow). `pipeline_kind` is the lineage kind (`yaml`, `classic_build`, `gha`). |

## Extending

Recipes (add a rule, a collector, a secret provider, an auth mode, an artifact store, a DB dialect; edit the data files; rebrand) are in [docs/CUSTOMIZING.md](docs/CUSTOMIZING.md). In short: rules are one decorated function plus a PASS and a FAIL test (`pch rules docs --write docs/RULES.md` regenerates the catalog); task knowledge lives in `src/pch/normalize/capabilities.yaml`, `deprecated_tasks.yaml` and `gha_mapping.yaml` (data, not code); collectors return plain facts and must go through `SourceClient` so the read-only guard applies.

## Development

```bash
pytest --cov=pch            # unit tests; all HTTP is mocked (respx / in-memory demo transport)
ruff check . && mypy src   # CI also runs bandit, pip-audit (both lockfiles), gitleaks, a DB matrix and an all-extras job
```

Collectors are tested against fixtures in `tests/fixtures/` (no live credentials are ever needed). The demo transport (`pch.demo.transport`) lets the whole pipeline run offline.

## Security notes

* Read-only by construction: a transport-level guard rejects non-GET requests (except the documented YAML preview POST, the Aikido OAuth token exchange and, in GitHub App mode, the installation token exchange pinned to the configured GitHub API host and exact path); a test asserts a full scan sends nothing else, and that the web app exposes no mutating route.
* Secret values are never persisted: raw cache files are redacted before writing, variables are classified in memory (only names and reasons are stored), and stored pipeline JSON omits script bodies and secret-like inputs.
* Web security (T5) is described in the next section; every control fails closed and is covered by `tests/test_web_security.py`.

## Security (web)

**Authentication and authorisation.** `AUTH_MODE=easyauth` (production) expects Azure App Service Authentication ("Easy Auth") with Microsoft Entra ID in front of the app. The app reads `X-MS-CLIENT-PRINCIPAL`, takes roles from its signed claims only, and allows a request only if the user holds a role listed in `AUTH_ALLOWED_ROLES` (for example the Entra app role `PCH.Reader`). No principal -> 401, no allowed role -> 403 (a minimal page, no data), malformed or oversized (>16 KB) header -> 401. Only the health endpoints (`/health/live`, `/health/ready`, `/api/v1/health`: status only) and `/static/*` are reachable without a principal; pages, the JSON API, CSV export and OpenAPI all require one. `AUTH_MODE=none` is for local development: it is refused when `APP_ENV=prod` and when the bind host is not loopback. See `docs/DEPLOY_AZURE.md` and `docs/DECISIONS.md` (T5) for the matrix.

**Settings page (the one write path, ADR-19).** An admin (a role in `AUTH_ADMIN_ROLES`; the local developer with `AUTH_MODE=none`) can turn the features `migration`, `gha_scanning`, `source_sonar`, `source_aikido` and `source_servicenow` on and off; defaults come from `config/features.yaml`, changes are stored in the app's own database and audited, and `pch features` does the same from a terminal. The two POSTs (`/settings/features/{key}` and `.../reset`) need the admin role, an HMAC form token signed with `SETTINGS_SIGNING_KEY` (bound to the user and the action, 30 minutes), and a same-origin `Origin`/`Referer` (`Sec-Fetch-Site: cross-site` is refused). Production without the key, or without an admin role, is read-only and says why. Nothing is ever written to a source system.

**Fail-closed startup guard** (`pch.web.guard.assert_safe_to_serve`, used by `create_app` and `pch serve`; `pch doctor` reports it as `auth` and `serve_guard`). The app refuses to start when: `AUTH_MODE=none` with `APP_ENV=prod`; `none` on a non-loopback host (except `APP_ENV=dev` + `AUTH_NONE_ALLOW_CONTAINER_BIND=true`, used by docker compose); `easyauth` with neither `AUTH_ALLOWED_ROLES` nor an explicit `AUTH_ALLOW_ANY_AUTHENTICATED=true`; `easyauth` unless `WEBSITE_AUTH_ENABLED=True` (otherwise `X-MS-*` headers are not stripped and can be forged; `AUTH_EASYAUTH_ASSUME_ENABLED=true` overrides this for local testing only and is itself refused in prod); `APP_ENV=prod` without `ALLOWED_HOSTS` (or with `*`).

**Browser hardening.** Strict CSP (`default-src 'self'`, no inline script or style, no third-party origins), `nosniff`, `Referrer-Policy: same-origin` (nothing leaves the site; a same-origin form post still carries its `Origin`, which the Settings CSRF check needs), `X-Frame-Options: DENY`, COOP, minimal Permissions-Policy, HSTS in prod, `Cache-Control: no-store` on all data responses, on every response including errors. Only GET/HEAD are served (405 otherwise), except the two feature-switch POSTs under `/settings/features/` (admin role + CSRF token + same-origin, see ADR-19). `/api/docs` and `/openapi.json` are disabled in prod (in dev the docs page gets its own scoped CSP using a script hash and jsDelivr). Errors are generic with a correlation id (`X-Request-ID`); no tracebacks. `ALLOWED_HOSTS` is enforced (App Service: `<app>.azurewebsites.net` or `*.azurewebsites.net`); uvicorn runs with `proxy_headers=True`, `FORWARDED_ALLOW_IPS` and no `Server` header. Query parameters are bounded and sort keys whitelisted (422/400, never 500). External data is always escaped; JSON data blocks escape `<`, `>`, `&`; only `http(s)` URLs are rendered as links; CSV cells that start with `=`, `+`, `-`, `@` are neutralised.

**Vendored frontend assets (no CDN at runtime).** `src/pch/web/static/vendor/` holds Tailwind (generated, 3.4.17), HTMX 1.9.12 and Chart.js 4.4.3 with `MANIFEST.json` (version, source, sha256); a test recomputes the hashes. Rebuild Tailwind with `scripts/build_css.sh` (pinned standalone CLI, checksum verified; `--check` fails if the committed CSS is stale). To update HTMX/Chart.js: download the npm tarball, compare its `dist.shasum`/`dist.integrity` with the npm registry, copy the dist file, update `MANIFEST.json` and the filename in `templates/base.html`. Page scripts live in `static/app.js`; pages pass data through inert `<script type="application/json">` blocks.

## Scheduling

`.github/workflows/scheduled-scan.yml` runs `pch scan` daily (02:00 UTC) and on demand; it is opt-in (`PCH_SCAN_ENABLED=true`), read-only, SHA-pinned and takes its secrets from the GitHub environment `pch-scan`. Setup, the secret and variable tables, the Azure SQL OIDC variant and the exit codes are in [docs/USING_IN_YOUR_ORG.md](docs/USING_IN_YOUR_ORG.md) (phase 4); the design is ADR-18 in [docs/DECISIONS.md](docs/DECISIONS.md).
The dashboard header shows `Last scan: 3 h ago (live)` and a warning banner when the latest complete scan is older than `SCAN_STALE_HOURS` (default 36) or the newest scan failed.

## Operations

**Logging.** `LOG_FORMAT=text|json` (default `text`; `json` when `APP_ENV=prod`) and `LOG_LEVEL` (default `INFO`) apply to the CLI and the web app (`pch.logging_setup.configure_logging`). JSON lines carry `ts` (UTC), `level`, `logger`, `message`, `request_id`, `scan_id` (inside a scan), `exception` and, for requests, `method`, `path` (no query string), `status`, `duration_ms` and `principal` (a hash of the principal id, never the name or e-mail). A redaction filter on every handler scrubs bearer/basic credentials, `Authorization` headers, `pat/token/password/secret/api_key...` pairs, URL credentials (`scheme://user:pass@host`, e.g. DB URLs), well-known token formats and every secret value the secret provider or settings resolved (exact match) from the message, its arguments and exception text before it is written or exported. The request id is the inbound `X-Request-ID` if it matches `[A-Za-z0-9][A-Za-z0-9._-]{7,63}`, else a fresh UUID; it is echoed in the response header and the error pages. uvicorn's own access log (full URLs) is off in prod (`UVICORN_ACCESS_LOG` to override); the app's single structured request line replaces it.

**Health.** `GET /health/live` -> `200 {"status":"ok"}` (process only; no DB, so a DB outage never restarts the container). `GET /health/ready` -> `200 {"status":"ok"}` when the DB is reachable and migrated to head, else `503 {"status":"unavailable","reason":"db_unreachable|db_timeout|schema_not_ready"}` (no URLs or exception text). The probe has a 2.5 s budget (`HEALTH_READY_TIMEOUT_SECONDS`), is single-flight and cached for 5 s (`HEALTH_READY_CACHE_SECONDS`). Readiness deliberately excludes the artifact store, secret provider and external sources: the dashboard only reads the DB, and probing optional dependencies lets one flaky dependency pull every instance out of rotation at once. `/api/v1/health` stays as an alias of live (status + version). All three are unauthenticated and accept a loopback `Host`; the container `HEALTHCHECK` uses `/health/live`. A DB that is merely unreachable at start-up no longer stops `pch serve` (it serves `503` on `/health/ready` until the DB is back); a schema that is not at head still exits 3.

**Application Insights (optional).** `pip install 'pipeline-compliance[azure-monitor]'` (included in `requirements-azure.lock`) and set `APPLICATIONINSIGHTS_CONNECTION_STRING` (a secret: use a Key Vault reference). Unset = nothing is imported or exported. Set without the extra = exit 2 with the install hint. Logs go through the redaction filter before export; traces cover FastAPI, httpx (outbound to ADO/Sonar/...) and SQLAlchemy; request/response bodies and headers are never captured and a span processor strips query strings and URL credentials; the cloud role name is `pch-web` (`pch serve`) or `pch-scan` (`pch scan`, `pch scans prune`). Sampling is the distro's: set `OTEL_TRACES_SAMPLER` and `OTEL_TRACES_SAMPLER_ARG` (for example `microsoft.fixed_percentage` and `0.1`, or `microsoft.rate_limited` and traces per second). `pch doctor` shows `logging` and `telemetry`.

**Retention.** `pch scans prune [--keep N] [--older-than DAYS] [--dry-run]` (defaults `RETENTION_KEEP_SCANS` / `RETENTION_MAX_AGE_DAYS`; neither = error). A scan is deleted when it is outside the newest N scans **and** older than DAYS (with a single option only that condition applies). The latest `complete` scan and any `running` scan inside the stale window are never deleted. For each scan the artifact-store prefix `<scan_id>/` is deleted first, then its DB rows in one transaction (children in chunks, then `delete_scan`). A real run holds the scan lock (exit 4 if a scan is running); `--dry-run` is read-only and takes no lock. Schedule it after the scan, for example `pch scan && pch scans prune --keep 30 --older-than 90`.

**Shutdown and timeouts.** uvicorn drains in-flight requests for `GRACEFUL_SHUTDOWN_SECONDS` (default 20) after SIGTERM; keep-alive is `KEEP_ALIVE_SECONDS` (default 65). On shutdown the app disposes its DB engine. `pch scan` turns SIGTERM/SIGINT into a cancellation: collectors stop, the scan is marked `failed` with reason `interrupted`, the lock is released and the exit code is 5. `SCAN_TIMEOUT_MINUTES` (default 240) does the same with reason `timeout`.

**Exit codes** of `pch scan` (0 ok, 1 failure, 2 configuration, 3 database not ready, 4 lock held, 5 interrupted/timeout; constants in `pch/exitcodes.py`) and what to do about each: [docs/USING_IN_YOUR_ORG.md](docs/USING_IN_YOUR_ORG.md) (phase 4).

## Tables

Repos, Findings, Rules and the Lineage list share the same behaviour, all through GET query strings (links work without JavaScript, HTMX only swaps the results region): a sticky header, sorting on every meaningful column (`sort` and `dir`, whitelisted keys), server-side pagination (`page`, `per_page` of 25, 50, 100 or 200; the page keeps filters and sort; total count and a keyboard-reachable pager), active **filter chips** (each removable, plus "Clear all") and a **Columns** chooser whose choice is stored per viewer in `localStorage` (optional: without it every column shows). Invalid values return 400 (pages) or 422 (API). CSV/Excel exports honour the filters, never the page. Repos also filter by `owner` and `migration` (`ado_only`, `in_progress`, `migrated`, `none`); Findings by `pipeline` and `stage`.

## Roadmap

GitHub Actions (ADR-17) and the read-only GitHub reader (ADR-16) are implemented. Next: a read-only agent layer (`pch/agent/tools.py` exposes `list_findings`, `get_repo`, `explain_rule`; the MCP server and chat panel are stubs) that explains findings and never decides compliance.
