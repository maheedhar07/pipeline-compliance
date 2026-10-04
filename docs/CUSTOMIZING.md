# Building on this template

How the code is layered, and one recipe per common change. Every command here exists in this repo; every recipe ends with how to verify it.
Run `ruff check . && mypy src && pytest -q -p no:warnings` after each change (CI also runs bandit, pip-audit, gitleaks and a DB matrix).

## Architecture

```
  Azure DevOps   SonarQube   Aikido   ServiceNow          (read-only HTTP, never written to)
       \            |          |         /
        v           v          v        v
 +------------------------------------------------------------+
 | collectors/*   SourceClient -> ReadOnlyTransport           |  SEAM 5  source collectors
 |   SizeLimitTransport -> RecordingTransport(redact) -> ArtifactStore (raw cache)   SEAM 4  artifact storage
 +----------------------------+-------------------------------+
                              v   plain facts (pydantic models in model/)
 +------------------------------------------------------------+
 | normalize/   capabilities.yaml, deprecated_tasks.yaml,     |
 |              gha_mapping.yaml (data), target/tier detection|
 +----------------------------+-------------------------------+
                              v   RepoContext
 +------------------------------------------------------------+
 | engine/      @rule registry -> findings -> scoring+waivers |  deterministic Python, no AI
 +----------------------------+-------------------------------+
                              v   one transaction per scan, DB-backed scan lock
 +------------------------------------------------------------+
 | store/       SQLAlchemy models, Alembic, engine factory    |  SEAM 1  database (sqlite | postgres | azure sql)
 +----------------------------+-------------------------------+
                              v   read-only queries
 +------------------------------------------------------------+
 | web/         FastAPI + Jinja + HTMX, AuthMiddleware        |  SEAM 3  auth (none | easyauth | yours)
 +------------------------------------------------------------+

 SEAM 2  secrets (env | file | azure_keyvault): resolved when live source clients are built (sources.py).
 Orchestration: orchestrator.py (Scanner), scanrun.py (timeout/SIGTERM), cli.py. Settings: settings.py.
```

The five seams and where each is selected:

| Seam | Setting | Code | Registered in |
|---|---|---|---|
| Database | `DATABASE_URL`, `DB_AUTH` | `store/engine.py`, `store/azure_sql.py`, `store/types.py` | `build_engine` (per-dialect branches) |
| Secrets | `SECRETS_PROVIDER` | `providers/secrets.py`, `providers/azure_keyvault.py` | `build_secret_provider` |
| Auth | `AUTH_MODE` | `web/auth.py`, `web/guard.py` | `AUTHENTICATORS` dict |
| Artifact storage | `ARTIFACT_STORE` | `providers/artifacts.py`, `providers/azure_blob.py` | `build_artifact_store` |
| Source collectors | per-source URL/credentials | `collectors/*`, `sources.py`, `orchestrator.py` | `Sources` dataclass, `live_sources` |

Everything else is deliberately concrete. Do not add abstraction layers beyond these seams.

Template invariants to keep (they are also listed in `CLAUDE.md`): fail-closed serve guard, strict config, schema only through migrations, all HTTP through
`ReadOnlyTransport`, redaction before anything is persisted, providers selected through their factory/registry, the docs-drift test.

---

## 1. Switch the database

Files: `.env` / app settings, `pyproject.toml` extras (already defined), no code. Settings: `DATABASE_URL`, `DB_AUTH`, `DB_POOL_*`, `DB_CONNECT_TIMEOUT_SECONDS`, `DB_AUTO_MIGRATE`.

**SQLite (default, dev/demo)**: `DATABASE_URL=sqlite:///data/pch.db`. In `APP_ENV=dev|test` startup runs `upgrade head` itself.

**PostgreSQL**: `pip install -e ".[postgres]"`, `DATABASE_URL=postgresql+psycopg://user:pw@host:5432/db`, then `pch db upgrade`.

**Azure SQL, password**: `pip install -e ".[azuresql]"` plus the Microsoft ODBC Driver 18 on the host,
`DATABASE_URL=mssql+pyodbc://user:pw@srv.database.windows.net:1433/db?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes`.

**Azure SQL, Entra ID (managed identity, no password)**: same extra and driver, `DB_AUTH=azure_ad` and a user-less URL
`mssql+pyodbc://@srv.database.windows.net:1433/db?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes`. With a user-assigned identity also set `AZURE_CLIENT_ID`
(read by `DefaultAzureCredential`). In the database create the contained user (`CREATE USER [<identity name>] FROM EXTERNAL PROVIDER`) and grant roles
(see `DEPLOY_AZURE.md`). `DB_AUTH=azure_ad` with a non-mssql URL is rejected at startup.

Apply the schema (always an explicit deploy step in prod; the app refuses to start on a database that is not at head):

```bash
pch db upgrade            # create/upgrade to head (also: --revision <id>)
pch db current            # database revision vs the revision this build expects
pch db check              # exit 1 unless at head (deploy gate)
pch db stamp head         # adopt a database created by the pre-Alembic create_all, WITHOUT changing tables
```

All accept `--db <url>`. Use `stamp` only for a database whose schema already equals the initial revision.

**Verify**: `pch doctor` (`database`, `db_migrations`), `curl localhost:8000/health/ready`, and the portability suite against the target:
`TEST_DATABASE_URL=<disposable db url> pytest -p no:warnings tests/test_db_portability.py tests/test_azure_sql.py` (the database is wiped by the tests).

### Add a migration after changing a model

There is no CLI wrapper for creating revisions (`pch db` only applies them). The migrations ship inside the package and `pch.store.migrate.make_config` builds the Alembic config in code
(no `alembic.ini`), so create a revision with this invocation (tested; needs an editable install so the file lands in `src/pch/store/migrations/versions/`):

```bash
# 1. edit src/pch/store/models.py
# 2. generate against a scratch database that is at the current head
export DATABASE_URL=sqlite:///data/scratch.db
python - <<'PY'
from alembic import command
from pch.settings import get_settings
from pch.store.engine import build_engine
from pch.store.migrate import make_config, upgrade

engine = build_engine(get_settings().database_url)
upgrade(engine)                                    # autogenerate compares against a database at head
with engine.connect() as conn:
    command.revision(make_config(conn), message="add scans note", autogenerate=True, rev_id="0002")
PY
```

Then review the file by hand (autogenerate misses renames, server defaults and data migrations; it runs in batch mode for SQLite), keep `downgrade()` correct, and run
`pytest tests/test_db_portability.py` (`test_models_and_migrations_in_sync` fails on any model/migration difference, `test_upgrade_empty_to_head_and_downgrade_base` exercises the chain).
Revision ids so far are sequential (`0001`); keep that convention with `rev_id`. Test the revision on PostgreSQL and SQL Server too: CI's `db-matrix` job does.
Never edit an already released revision; add a new one.

### Adding another dialect (checklist)

1. `pyproject.toml`: new optional extra with the driver; regenerate both lockfiles (recipe 9); document the URL in the README Database table.
2. `store/engine.py`: pool/connect options, driver connect timeout in `connect_args_for`, any pragma/session setup. Dialect options live only here.
3. `store/types.py`: `UTCDateTime` branches (`load_dialect_impl`, `process_bind_param`) for timezone handling; check JSON, text and boolean mapping.
4. `store/models.py`: indexed string length (the limit here is 450 characters, from SQL Server's 900-byte key; check the new engine's key limit), reserved words as column names (`external` is stored as `external_summary`).
5. `store/repository.py`: bound-parameter limit (SQL Server 2100; `insert_rows` and `select_where_in` chunk below it), `IN` list size.
6. `store/locks.py`: the scan lock must work with plain INSERT + compare-and-swap UPDATE on the new engine; no advisory locks.
7. `store/migrate.py` `compare_type`: silence benign type-drift reports for the new engine.
8. Migrations: run `upgrade`, `downgrade base`, `upgrade` on it.
9. CI: add an entry to the `db-matrix` job in `.github/workflows/ci.yml` (service container, driver install, `TEST_DATABASE_URL`, CLI end-to-end steps).
10. Tests: `tests/test_db_portability.py` must pass unchanged with `TEST_DATABASE_URL` pointing at it; add a `connect_args_for` assertion in `tests/test_hardening_t7b.py`.

---

## 2. Swap or add a secrets provider

Scope: only the four source credentials (`ADO_PAT`, `SONAR_TOKEN`, `AIKIDO_CLIENT_SECRET`, `SERVICENOW_PASSWORD`; list in `providers/secrets.py` `SOURCE_SECRETS`). A database password is part of `DATABASE_URL`, not a provider secret (use `DB_AUTH=azure_ad` or a Key Vault reference for that setting).

| Provider | Setting | Notes |
|---|---|---|
| `env` (default) | `SECRETS_PROVIDER=env` | Credentials are the env vars. On App Service set them as Key Vault references, e.g. `ADO_PAT=@Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/ado-pat/)`; the platform resolves them before the container starts, so the app needs no Azure code. |
| `file` | `SECRETS_PROVIDER=file`, `SECRETS_DIR=/mnt/secrets` | One file per secret named like the variable. Path traversal and symlink escapes are rejected. |
| `azure_keyvault` | `SECRETS_PROVIDER=azure_keyvault`, `KEYVAULT_URL`, optional `KEYVAULT_SECRET_MAP`, `KEYVAULT_CACHE_TTL_SECONDS` | Needs `pip install -e ".[azure-keyvault]"`; managed identity needs *Key Vault Secrets User*. `ADO_PAT` is read from the secret `ado-pat`. |

Providers are never mixed: with `file` or `azure_keyvault` the credential env vars are ignored, and a missing secret is an error naming it.

**Add a provider** (for example HashiCorp Vault):

1. Files: `src/pch/providers/<name>.py` (class with `name: str` and `get(name) -> str | None`; import the SDK lazily and raise `ProviderUnavailable` with the pip command when missing), `providers/secrets.py` (`build_secret_provider`: new `elif`), `settings.py` (add the value to the `secrets_provider` `Literal`, new settings, validation in `_provider_settings`), `pyproject.toml` (extra), `config_reference.py` + `.env.example` (docs-drift test), `README.md` (`pch config reference --write README.md`).
2. Call `register_secret(value)` (from `pch.logging_setup`) for every value you return so the log filter scrubs it by exact match. Never log values or SDK error text.
3. Tests (follow `tests/test_providers.py`): found / not found, error never echoes the backend message, missing extra is a clear error (`importorskip` for the SDK so the default test run needs no cloud SDK), `live_sources` uses only the selected provider.
4. Verify: `pch doctor` shows `secrets_provider` and `secret:<source>` as `set`/`missing`.

---

## 3. Authentication and authorization

Production mode is **App Service Authentication (Easy Auth) with Entra ID plus an app role**; the app never handles passwords or tokens. Setup (portal steps, app role manifest, excluded health paths) is in
`DEPLOY_AZURE.md`, "Easy Auth". In short: add the Microsoft identity provider, require authentication, exclude `/health/live` and `/health/ready`, create the app role `PCH.Reader`, set Enterprise application
*Assignment required = Yes*, assign users or groups, and set `AUTH_MODE=easyauth`, `AUTH_ALLOWED_ROLES=PCH.Reader`, `ALLOWED_HOSTS=<host>`. The app refuses to start unless `WEBSITE_AUTH_ENABLED=True` (set by the platform).

To use a different role name, change the role `value` in the app registration and `AUTH_ALLOWED_ROLES` (exact, case-sensitive match). Allowing "any signed-in user" requires the explicit `AUTH_ALLOW_ANY_AUTHENTICATED=true`
and is only acceptable with a single-tenant app registration and assignment required.

**Add an auth mode** (for example an API gateway that injects a JWT):

1. `web/auth.py`: implement `Authenticator` (`mode`, `authenticate(headers) -> Principal` raising `AuthError(401, ...)`, `authorize(principal)` raising `AuthError(403, ...)`) and register it in `AUTHENTICATORS`.
   Any parsing problem must be a 401, never an exception that becomes a 500.
2. `settings.py`: add the value to the `auth_mode` `Literal` and its settings.
3. **`web/guard.py` (`guard_problems`)**: add a branch for the mode. An unknown mode is refused at startup (fail closed), so the app will not serve until the mode has its own guard rules.
   Refuse start-up when what the mode trusts (headers, a JWKS URL, ...) is not guaranteed.
4. Keep `/health/*` and `/static/` the only unauthenticated paths (`auth.is_public_path`); do not add a path to `PUBLIC_EXACT` without a test.
5. Tests: extend `tests/test_web_security.py` (guard matrix, `test_guard_exhaustive_invariants`, 401/403 behavior, malformed input is 401). Verify with a forged-header request against the deployed app (expect 401), see `IMPORT_CHECKLIST.md`.

---

## 4. Artifact store (raw response cache)

Used for `pch scan` caching and `--from-cache`; the demo world (`data/demo/world.json.gz`) always stays local.

| Store | Setting | Notes |
|---|---|---|
| `local` (default) | `ARTIFACT_STORE=local` | `DATA_DIR/raw/<scan_id>/<host>/<hash>.json`, files mode 0600, atomic writes. |
| `azure_blob` | `ARTIFACT_STORE=azure_blob`, `ARTIFACT_BLOB_ACCOUNT_URL`, `ARTIFACT_BLOB_CONTAINER` | `pip install -e ".[azure-blob]"`. Managed identity only (*Storage Blob Data Contributor* on the container); no keys, SAS or connection strings. Disable shared-key access on the account. |

Retention: `pch scans prune --keep N --older-than DAYS [--dry-run]` deletes artifacts first, then rows.

**Add a store**: class implementing the async `ArtifactStore` protocol in `providers/artifacts.py` (`put`, `get`, `list`, `delete_prefix`; validate keys with `validate_key`; run blocking I/O in `asyncio.to_thread`),
branch in `build_artifact_store`, `Literal` value and settings in `settings.py`, `pyproject.toml` extra, docs-drift entries (recipe 2, step 1). Callers redact before `put`; the store must never inspect or log content.
Tests (follow `tests/test_providers.py`): roundtrip/list/`delete_prefix`, escaping keys rejected, a secret in a response never reaches `put` (`test_secret_in_response_never_reaches_store` pattern), store failure does not fail a scan.
Verify: `pch doctor` (`artifact_store` does a write/read/delete probe), `pch scan --demo --cache`, then `pch scan --from-cache <scan_id>` (replay of a demo cache through the live path is only approximate, see `DECISIONS.md` Provider seams; the exact check is `tests/test_scan_demo.py::test_cache_has_no_secrets_and_replay_reproduces`).

---

## 5. Add a source collector

Example: a new system "Acme". Read-only by construction; follow `collectors/sonar.py`.

1. **Client** `src/pch/collectors/acme.py`: build every HTTP call on `SourceClient` (`collectors/http.py`). Never create an `httpx.Client` yourself: `SourceClient` wraps the transport in `ReadOnlyTransport`
   (GET/HEAD/OPTIONS only, plus the two documented POST exceptions in `transport.ALLOWED_POSTS`), applies retry/backoff, concurrency and the response size cap. A test fails if any other module builds an `httpx.AsyncClient`
   (`test_every_httpx_client_is_built_through_the_read_only_wrapper`). A new mutating endpoint must not be added to `ALLOWED_POSTS` for this template: it is report-only.
   Put API details you are unsure about in one function with a `# VERIFY:` comment. Return plain pydantic facts, add the model to `model/repo.py` and a field to `RepoContext`.
2. **Settings and secrets**: URL and non-secret fields as `Settings` fields (URL validation list in `settings.py` `_urls`, https enforced in prod), the credential as `SecretStr`, an entry in `Settings.source_requirements` and in
   `providers/secrets.py` `SOURCE_SECRETS`. Docs-drift entries (recipe 2, step 1).
3. **Wiring**: add the client to the `Sources` dataclass and construct it in `sources._live` (live and cache replay) and `sources.demo_sources`; call it from `orchestrator.py` (a failing source must be recorded as a collection error, never abort the scan: wrap in the existing `rerr(...)` pattern).
4. **Redaction**: the raw cache is written by `RecordingTransport.build_record`, which already runs `redact_json` / `redact_text` on every response. Add any new secret-bearing field name to `collectors/redact.py` and a case to `tests/test_redact_transport.py`.
   Exception text is scrubbed (`logging_setup.scrub`) before it is stored; do not put response bodies in exception messages.
5. **Tests** with respx and fixtures only (no live credentials): `tests/test_collectors_acme.py` using `@respx.mock` and JSON under `tests/fixtures/acme/` (see `tests/test_collectors_sonar.py`); a 404/500 case; paging if any.
6. **Demo hook**: `demo/transport.py` (`DemoTransport`) answers by host name (`SONAR_HOST` etc.). Add a host constant, route handling and generated payloads in `demo/generator.py` / `demo/payloads.py`, then pass the demo host in `sources.demo_sources` and the `demo` branch of `cache_sources`.
   `pch seed-demo && pch scan --demo` must then exercise your real collector. Keep `tests/test_scan_demo.py` (`test_scan_never_mutates`) green.
7. **Rules** that use the new facts: recipe 6. **Doctor**: it reports configured sources and missing credentials from `source_requirements`.

Verify: `pytest -q`, `pch seed-demo && pch scan --demo`, `pch doctor`.

### Plug in a GitHub reader

Repo-level checks for GitHub-hosted repos are UNKNOWN today (ADR-13) because nothing reads GitHub. A reader fills the gap without touching the rules:

1. Implement the read-only contract in `collectors/github/` (`GitHubAdapter`; all HTTP through `SourceClient`, a new `Settings` source following recipe 5 above, a `github.com`/Enterprise base URL, token via the secret provider).
2. In `Scanner.scan_repo` (`orchestrator.py`), where `unavailable_facts(ref.provider)` is used for `ref.external`, call the reader instead: build a populated `RepoFacts` with `facts_source="github"` (tree to `analyze_repo(paths, contents)`, CODEOWNERS) and map branch protection / rulesets to `BranchPolicies(available=True, min_reviewers=..., reset_on_push=..., build_validation=..., ...)`. Keep `facts_source="unavailable"` / `available=False` when the call fails (and record a collection error), so a flaky reader yields UNKNOWN, never FAIL.
3. SRC-001..003/006 and TST-001..003/006 then evaluate normally: they only switch to UNKNOWN on `facts_source == "unavailable"` or `policies.available == False`. `classify_test_state` stops using the "pipeline proves tests" shortcut as soon as facts are available.
4. The same reader can enumerate the GitHub organisation to add repos that no ADO pipeline references (extend `collect_project` / `discover`).
5. Tests: respx fixtures for the GitHub API; reuse `tests/test_external_repos.py` (replace the `unavailable_facts` context with reader output) and keep `test_demo_github_estate_is_scanned_through_real_collectors` green after pointing the demo transport at a fake `api.github.com` host.

---

## 6. Rules, policy and data files

**Add a rule** (one function; the runner, dashboard, API and catalog pick it up):

```python
# src/pch/engine/rules/hygiene.py  (or a new module in that package; every module is auto-imported)
from pch.engine.registry import rule
from pch.model.findings import RuleResult

@rule("HYG-004", "Pipeline has a description", "low", "pipeline",
      "Descriptions tell responders what a pipeline deploys.",
      {"classic": "Edit the definition and fill in the description.", "yaml": "Add a comment header to the YAML."})
def hyg_004(ctx, policy, p):        # scope "repo": (ctx, policy); "pipeline": (ctx, policy, p); "stage": (ctx, policy, t)
    return RuleResult.passed("ok") if p.name else RuleResult.failed("unnamed")
```

The id prefix is the category (`SRC QLT TST SUP SEC DEP TGT HYG`; a new prefix also needs an entry in `CATEGORY_NAMES` in `engine/registry.py`). Optional decorator filters: `platforms=`, `targets=`, `tiers=`.
Return `passed`, `failed`, `warn`, `na` or `unknown` (unknown = data was not collected; it is excluded from the score). Rules must be deterministic and must not do I/O.
Tests: every rule needs at least one PASS and one FAIL case in `tests/test_rules.py` (helpers `ctx`, `pipe`, `stage`, `step`, `one`, `statuses` in `tests/builders.py`).
Regenerate the catalog: `pch rules docs --write docs/RULES.md` (`tests/test_docs.py` fails when it is stale; `--check` verifies without writing). Verify: `pch rules list`, `pytest tests/test_rules.py tests/test_docs.py`.

**Policy thresholds and waivers**: `config/policy.yaml` (strict model `Policy` in `settings.py`: coverage, Sonar gate name, reviewers, Aikido SLAs, registries, branches, `compliant_score_threshold`, waivers).
A waiver is `{rule, repo, reason, owner, expires}`, repo is `Project/repo`, a bare repo name or `*`; it turns FAIL/WARN into WAIVED until `expires`. Per-repo overrides, projects and tiers: `config/scope.yaml`.
A new policy key needs a field on `Policy`, a default, a test in `tests/test_config_doctor.py` and a comment in `config/policy.yaml`. Verify with `pch doctor` (unknown keys are errors).
Scoring weights and status thresholds are code (`engine/scoring.py`, `docs/DECISIONS.md` "Scoring and status"); changing them changes every historical comparison.

**Data files** (no code change, tests in `tests/test_normalize_capabilities.py`):
`src/pch/normalize/capabilities.yaml` (task or inline-script patterns to capability tags such as `unit-test`, `deploy:aks`; syntax is documented at the top of the file),
`deprecated_tasks.yaml` (`{task, below_major, replacement}`), `gha_mapping.yaml` (Azure Pipelines task to GitHub Actions equivalent, `gha: null` = no equivalent).

---

## 7. Rebrand and rename

The product name is cosmetic; the Python package name is a mechanical but wide change. Be honest about effort: about 90 files import `pch`, so renaming the package is a one-hour search-and-replace plus a full test run. Renaming the app (title, cloud role, distribution name) is small.

**Cosmetic (do these first, they are enough for most orgs)**

| What | Where |
|---|---|
| UI title and page titles | `src/pch/web/templates/base.html` (`<title>`, header link) and the `{% block title %}` suffix in each template, `src/pch/web/security.py` (error page title), `src/pch/web/app.py` (`FastAPI(title=...)`, Swagger title), `tests/test_web.py` (asserts the name) |
| Distribution name | `pyproject.toml` `name`; install hints in `src/pch/telemetry.py`, `providers/azure_blob.py`, `providers/azure_keyvault.py`, `store/azure_sql.py` (`pip install 'pipeline-compliance[...]'`) and their tests in `tests/test_providers.py` |
| CLI help text | `src/pch/cli.py` (`typer.Typer(help=...)`), `src/pch/__init__.py` docstring |
| Cloud role names (App Insights `service.name`) | `SERVICE_WEB`, `SERVICE_SCAN` in `src/pch/telemetry.py` (`pch-web`, `pch-scan`), the `_bootstrap(..., "pch-scan")` calls in `cli.py` and the matching text in `DEPLOY_AZURE.md`, `README.md`, `tests/test_ops.py` |
| App role value | Entra app role `PCH.Reader` (your tenant) and `AUTH_ALLOWED_ROLES`; examples in `config_reference.py`, `.env.example`, docs |
| Org placeholders | see `IMPORT_CHECKLIST.md` (grep list) |

**Python package and console script** (`src/pch`, import path `pch`, command `pch`). Keeping the command name `pch` is fine and avoids touching docs and hint messages; rename only the import path if you must:

```bash
NEW=acme_compliance
git mv src/pch "src/$NEW"
# imports and dotted strings in code and tests (perl: portable between macOS and Linux)
git ls-files -z src tests | xargs -0 perl -pi -e "s/\\bfrom pch\\b/from $NEW/g; s/\\bimport pch\\b/import $NEW/g; s/\\bpch\\.(?=[a-z_])/$NEW./g"
# packaging, tooling and CI
perl -pi -e "s#pch\\.cli:app#$NEW.cli:app#; s#src/pch#src/$NEW#g" pyproject.toml tailwind.config.js scripts/build_css.sh README.md docs/*.md
perl -pi -e "s#--cov=pch#--cov=$NEW#" .github/workflows/ci.yml
# tests that locate the package directory
perl -pi -e "s#\"src\" / \"pch\"#\"src\" / \"$NEW\"#" tests/test_web_security.py tests/test_security_review.py
perl -pi -e "s#src/pch/#src/$NEW/#g" src/$NEW/docs.py tests/test_docs.py
ruff check . --fix                                   # import order changes with the new name
pch rules docs --write docs/RULES.md                  # the catalog header mentions the package path (use your command name)
```

This sequence was run once on a copy of this repo and the full suite passed afterwards. Then check what is left: `git ls-files | xargs grep -n "src/pch\|pch\.\|import pch"`;
remaining hits should be prose in `docs/` and `README.md` (`pch/store/...`, `pch.web.guard`), which you can edit by hand or leave. To rename the command too, change `[project.scripts]` and then every `pch ` occurrence in `Dockerfile` (`CMD`, `HEALTHCHECK` is Python so unaffected),
`docker-compose.yml`, `.github/workflows/ci.yml`, source hint messages (`grep -rn "\`pch " src`) and docs. Do not blind-replace the word `pch`: it is also the container user, database name in compose and CI, and the OS user in the Dockerfile.
Verify: `pip install -e ".[dev]" && ruff check . && mypy src && pytest -q -p no:warnings`, `python -m pip show <dist-name>`, `<command> --help`, and a demo scan.

---

## 8. Rebuild CSS, bump vendored JavaScript

The UI loads nothing from a CDN. Assets live in `src/pch/web/static/vendor/` with `MANIFEST.json` (version, source, sha256); `tests/test_web_security.py::test_vendor_manifest_matches_files` recomputes every hash and requires every file in the directory to be listed.

* **Tailwind CSS** (generated): after changing templates, `static/*.js` or `web/*.py` classes, run `scripts/build_css.sh` (pinned standalone Tailwind CLI, downloaded into the gitignored `.tools/`, sha256-verified; it rewrites `tailwind.css` and the manifest hash).
  `scripts/build_css.sh --check` fails if the committed CSS is stale (CI runs it). To bump Tailwind: edit `VERSION` and the four platform hashes in the script (from the release's `sha256sums.txt`), rebuild, commit.
* **HTMX / Chart.js**: download the npm tarball, compare its `dist.shasum` / `dist.integrity` with the npm registry (`npm view <pkg>@<version> dist`), copy `dist/htmx.min.js` or `dist/chart.umd.js` into `vendor/` under a versioned name,
  update `MANIFEST.json` (version, file, source, npm hashes, sha256 via `shasum -a 256`) and the `<script src>` in `templates/base.html`; delete the old file. Re-run the tests.
* New front-end code goes in `static/app.js` (no inline script or style, no `eval`, no `innerHTML`; the CSP and `test_templates_have_no_inline_script_style_handlers_or_cdn` / `test_static_js_has_no_eval_or_html_injection` enforce it). Do not add a third-party origin.

---

## 9. Dependency updates

Runtime dependencies are hash-locked; the Dockerfile installs with `--require-hashes`. Two lockfiles exist: `requirements.lock` (core + `postgres`) and `requirements-azure.lock` (core + every extra). Regenerate **both** together after editing `pyproject.toml`
(or to bump versions; `pip-tools` is in the `dev` extra):

```bash
pip-compile --generate-hashes --extra postgres -o requirements.lock pyproject.toml                      # add --upgrade to bump
pip-compile --generate-hashes --extra postgres --extra azuresql --extra azure-keyvault --extra azure-blob --extra azure-monitor \
  -o requirements-azure.lock pyproject.toml
```

Compile on the same Python minor as the image (3.11). Then run `pip-audit --require-hashes --disable-pip -r requirements.lock` (and the azure lock), the full test suite with all extras
(`pip install -e ".[dev,postgres,azuresql,azure-keyvault,azure-blob,azure-monitor]"`), and build the image: `docker build --build-arg PCH_LOCKFILE=requirements-azure.lock -t pch:azure .`.

**Dependabot** (`.github/dependabot.yml`) opens weekly grouped PRs for pip (`pyproject.toml` ranges only: regenerate both lockfiles in the PR before merging), GitHub Actions and Docker. For actions, keep the full commit SHA and update the `# vX.Y.Z` comment.
**Base image digest**: the Dockerfile pins `python:3.11-slim@sha256:...` in both stages. To bump, resolve the new multi-arch index digest (`docker buildx imagetools inspect python:3.11-slim`) and replace it in both `FROM` lines; Dependabot's docker ecosystem proposes the same.
The CI tools installed unpinned (`pip install bandit pip-audit`, SEC-12) are an accepted risk in `SECURITY_REVIEW.md`; pin them if your org requires it.

## 10. Lineage: add a field or an export column

The lineage is one JSON document per repo (`pch.model.lineage.RepoLineage`), built in `src/pch/normalize/lineage.py`, stored whole in `lineage.doc` and read by `web/lineage_q.py` (page, JSON API, exports). Because the document is JSON, **a new field needs no migration**: add it to the pydantic model with a default (old scans keep loading), fill it in `build_pipeline` / `build_release` / `lstage` (pure functions over what the scan already collected), then show it in `templates/_lineage_chain.html`. Only a new *filterable scalar* needs a column on `LineageRow` plus an Alembic revision (see "Add a migration after changing a model").

To add an export column: append a `(key, header, width)` entry to `COLUMNS` in `web/lineage_q.py` (never insert or reorder: the order is the contract for downstream spreadsheets), put the value in the right helper (`_pipeline_cols`, `_release_cols` or `_stage_cols`), add the row to the column table in README ("Export columns"), and a date column also goes into `DATE_COLUMNS` (it is written as a real Excel date). `tests/test_web_lineage.py` fails if the README table and `COLUMNS` differ. Strings are neutralised and typed as text by `web/exports.py`; do not write cells any other way. A new read-only deployment lookup goes into `collectors/ado/deployments.py` (through `AdoClient`, with a `# VERIFY:` comment on the endpoint shape and fail-open behaviour: unknown, never a guess).
