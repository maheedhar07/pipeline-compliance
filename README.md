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

## Dependency lockfile

`requirements.lock` pins every runtime dependency (plus the `postgres` extra) with hashes; the Dockerfile installs
from it with `--require-hashes`. Regenerate after editing dependencies in `pyproject.toml`:

```bash
pip install pip-tools
pip-compile --generate-hashes --extra postgres -o requirements.lock pyproject.toml   # add --upgrade to bump
```

## Docker

```bash
docker compose up --build                                   # dashboard + Postgres on http://127.0.0.1:8000
docker compose run --rm app sh -c "pch seed-demo && pch scan --demo"   # demo data
docker compose run --rm app pch scan                        # real scan (needs .env)
```

The container image runs as a non-root user; the app port is bound to localhost in `docker-compose.yml` because the dashboard has no authentication in v1.

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
* The dashboard has no authentication and binds to `127.0.0.1`. For shared use, deploy it behind Entra ID, for example Azure App Service with Easy Auth in front of the container.

## Roadmap

M9: GitHub Actions adapter (`collectors/github/` interface exists). M10: read-only agent layer (`pch/agent/tools.py` exposes `list_findings`, `get_repo`, `explain_rule`; MCP server and chat panel are stubs). The AI layer will explain findings, never decide compliance.
