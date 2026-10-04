# Import checklist: from template to your org

Ordered steps to import this repository, adapt it and go live. Tick each box. Commands are examples for a Unix shell; replace `<...>`.
Background: `CUSTOMIZING.md` (recipes), `DEPLOY_AZURE.md` (Azure runbook), `THREAT_MODEL.md`, `SECURITY_REVIEW.md`.

## 1. Import the repository

- [ ] Import with history into your org (GitHub: *Import repository*, or `git clone --mirror <source> && cd <dir>.git && git push --mirror <new-url>`). Keep `main` as the default branch.
- [ ] The CI is **GitHub Actions only** (`.github/workflows/ci.yml`, `.github/dependabot.yml`). If your org hosts code elsewhere, port the eight jobs to your CI before relying on it; the commands are in the workflow.
- [ ] Add a `LICENSE` (the repo ships none; only the vendored HTMX and Chart.js licenses are present) and a `CODEOWNERS` file.
- [ ] Enable Dependabot alerts and security updates, secret scanning and push protection.

## 2. Protect `main`

- [ ] Require pull requests (at least 1 approval; 2 if your policy requires), dismiss stale approvals, block force-push and deletion, require conversation resolution.
- [ ] Required status checks (names as in the workflow): `lint + types + tests (py3.11)`, `lint + types + tests (py3.12)`, `all extras (py3.11)`, `pip-audit (both lockfiles)`, `bandit (SAST)`, `gitleaks (secret scan)`, `db portability (postgres)`, `db portability (mssql)`.
- [ ] Actions settings: workflow token read-only by default, allow only pinned (SHA) actions if your org supports that policy. No repository secrets are needed (see section 6).

## 3. Replace placeholders

Generate the current list (these are the only org-specific literals; fictional `contoso` data in `src/pch/demo/` and `tests/` is fixture data, leave it):

```bash
git grep -nE 'your-org|example\.(com|net)|service-now\.com|myorgacr|myapp\.azurewebsites|<your-org>|Sonar way' -- . ':!tests' ':!*.lock' ':!docs' ':!src/pch/demo'
```

| Where | Placeholder | Replace with |
|---|---|---|
| `config/scope.yaml` | `organization: your-org`, commented `owner: team-payments@example.com` | your Azure DevOps organization name (`https://dev.azure.com/<org>`) |
| `config/policy.yaml` | `approved_registries: [myorgacr.azurecr.io]`, `sonar_quality_gate_name: "Sonar way"`, `marketplace_task_allowlist`, commented waiver with `jane@example.com` | your registry host(s), your Sonar gate name, your approved marketplace tasks |
| `.env.example` | `ADO_ORG=<your-org>`, `SONAR_URL=https://sonar.example.com`, `SERVICENOW_URL=https://example.service-now.com`, `myapp.azurewebsites.net`, `<vault-name>`, `<account>` | your values (and delete the lines for sources you do not use: a set URL marks the source as configured) |
| `src/pch/settings.py`, `src/pch/web/guard.py` | `myapp.azurewebsites.net` in an error message / comment | optional wording |
| `README.md`, `docs/*.md` | `<app>`, `<vault>`, `<account>` examples | optional |
| Cosmetic branding | UI title, distribution name, cloud role names, app role | `CUSTOMIZING.md` section 7 |

Also check: `.github/dependabot.yml` (reviewers, schedule), `config/` is baked into the image (`COPY config ./config`), so rebuild after editing it. In `APP_ENV=prod` `config/scope.yaml` must exist.

- [ ] `git grep` above returns only lines you chose to keep.

## 4. Choose extras and lockfile

| You use | Install extras | Image lockfile (`--build-arg PCH_LOCKFILE=...`) | Also needs |
|---|---|---|---|
| SQLite or PostgreSQL, env secrets, local cache | none / `postgres` | `requirements.lock` (default) | nothing |
| Azure SQL | `azuresql` | `requirements-azure.lock` | Microsoft ODBC Driver 18 in the image (Dockerfile snippet in `DEPLOY_AZURE.md`) |
| Key Vault SDK provider | `azure-keyvault` | `requirements-azure.lock` | not needed if you use App Service Key Vault references |
| Blob raw cache | `azure-blob` | `requirements-azure.lock` | |
| Application Insights | `azure-monitor` | `requirements-azure.lock` | |

- [ ] Decided. If you trim extras or add dependencies, regenerate **both** lockfiles (`CUSTOMIZING.md` section 9).

## 5. Configure scope and policy

- [ ] `config/scope.yaml`: organization, `projects` (empty = all), `exclude_repos`, `env_tiers`, per-repo overrides (`sonar_key`, `aikido_repo`, `owner`, `servicenow_ci`, `coverage_threshold`).
- [ ] `config/policy.yaml`: thresholds, Sonar gate name, Aikido SLAs, approved registries/branches, waivers (each with `reason`, `owner`, `expires`).
- [ ] `pch doctor` reports both files `OK` (unknown or mistyped keys are errors).

## 6. CI secrets

None are needed. The tests use fixtures and mocks; the DB matrix uses throw-away service-container credentials defined in the workflow; gitleaks runs from a checksum-verified binary. Never put the ADO PAT or any source credential in repository or Actions secrets. Credentials live only in the deployed app (Key Vault).

- [ ] First CI run on your org's `main` is green (all eight checks).

## 7. First `pch doctor` (local, before any deploy)

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"      # add extras you chose
cp .env.example .env                                                                  # edit; set APP_ENV=dev first
pch doctor            # settings, scope/policy, sources (set/missing), secret provider, artifact store, DB, migrations
pch db upgrade && pch scan && pch serve                                               # needs the read-only ADO PAT scopes (README)
```

- [ ] `pch doctor` has no `FAIL`. Then repeat with the production settings (`APP_ENV=prod`, https URLs, `ALLOWED_HOSTS`, `AUTH_MODE=easyauth`...) from a shell with the real settings: doctor and `pch serve` must accept them (`WEBSITE_AUTH_ENABLED` is only present on the platform; use `AUTH_EASYAUTH_ASSUME_ENABLED=true` locally only outside prod).
- [ ] Review the first real scan: collection errors page, `UNKNOWN` findings (data the sources did not return), and the `# VERIFY:` source details in section 8.

## 8. First deploy

Follow `DEPLOY_AZURE.md` in order: resources and identities, role assignments, app settings, image build and push, `pch db upgrade` as a release step, web app start, Easy Auth, health check, scan job. Do not enable the scan schedule until the go-live gate passes.

## 9. Go-live gate

All of these must be checked before real users get access. Items marked (V) are `# VERIFY:` assumptions; the authoritative list with file references is
[SECURITY_REVIEW.md, "VERIFY markers and go-live checklist"](SECURITY_REVIEW.md#verify-markers-and-go-live-checklist). Do not copy it; tick each entry there and record the result in your change ticket.

**Platform behavior**
- [ ] Every (V) item in the SECURITY_REVIEW list is confirmed on the real App Service (Easy Auth variables and header stripping, health probe host, shutdown window, Azure SQL token auth, telemetry content, source API field names).
- [ ] **Forged-header test** (from outside, against the public URL): a request with a made-up principal must not get data.

  ```bash
  P=$(printf '%s' '{"auth_typ":"aad","name_typ":"name","role_typ":"roles","claims":[{"typ":"roles","val":"PCH.Reader"},{"typ":"oid","val":"00000000-0000-0000-0000-000000000000"}]}' | base64 | tr -d '\n')
  curl -s -o /dev/null -w '%{http_code}\n' -H "X-MS-CLIENT-PRINCIPAL: $P" https://<app>.azurewebsites.net/api/v1/overview   # expect 401 (or 302 to the Microsoft login if the unauthenticated action is Redirect); never 200
  curl -s -o /dev/null -w '%{http_code}\n' -H "X-MS-CLIENT-PRINCIPAL: $P" https://<app>.azurewebsites.net/health/live         # 200 and no data: excluded paths stay data-free
  ```
  Repeat against every other ingress that exists (private endpoint name, custom domain, `*.scm.azurewebsites.net` must not serve the app). A 200 with data anywhere is a stop.
- [ ] **Readiness probe**: `curl -i https://<app>.azurewebsites.net/health/ready` returns `200 {"status":"ok"}`; with the DB stopped or the schema behind head it returns `503` with a reason code and no URL or exception text. The App Service health check path is `/health/ready` and at least 2 instances run.
- [ ] **Easy Auth excluded paths** are exactly `/health/live` and `/health/ready` (and `/api/v1/health` if used). Everything else requires sign-in: an anonymous browser request to `/` is redirected to Microsoft (or 401), `/api/v1/overview` and `/static/` behave as documented.
- [ ] **Role assignment**: *Assignment required = Yes*; the reader app role is assigned to the intended group; a signed-in user without the role gets 403 (page with no data); a user with the role gets 200. `AUTH_ALLOW_ANY_AUTHENTICATED` is unset. The app registration is single tenant.
- [ ] `APP_ENV=prod`; `/api/docs` and `/openapi.json` return 404; response headers include HSTS and the strict CSP; `ALLOWED_HOSTS` lists only your host names.
- [ ] All source URLs are `https://` (settings validation enforces it) and the credentials are read-only tokens with the scopes in the README.

**Data and operations**
- [ ] **Retention schedule** exists and ran once: `pch scans prune --keep 30 --older-than 90` (or `RETENTION_KEEP_SCANS` / `RETENTION_MAX_AGE_DAYS`) scheduled after the scan; `--dry-run` reviewed first.
- [ ] **Scan job**: runs `pch scan` out-of-band with `APP_ENV=prod`, `SCAN_TIMEOUT_MINUTES` below `SCAN_LOCK_STALE_MINUTES` (validated), exit code alerts (`4` = already running is benign; `1`, `2`, `3`, `5` alert).
- [ ] **Backup and restore of the database** tested, not assumed (see section 10).
- [ ] Logs reach Log Analytics / App Insights, and a sample of `exceptions`, `dependencies` and `requests` contains no URL query, credential or row value (SEC-09).
- [ ] Identities hold only the roles in the `DEPLOY_AZURE.md` table; Azure SQL is Entra-only, the storage account has shared-key access disabled, Key Vault uses RBAC.
- [ ] Alerts: failed scan (exit code or no `complete` scan within 36 h), health check failures, 5xx rate.

## 10. Backup, restore and rollback

**Database backup and restore.** Azure SQL: automated backups and point-in-time restore are on by default (check the retention you need; configure long-term retention if policy requires). PostgreSQL: your managed service's PITR or `pg_dump`. Before every release that includes a migration, take (or confirm) a restorable point.
Restore drill: restore to a **new** database name, point a staging copy of the app at it (`DATABASE_URL`), run `pch db current` and `pch doctor`, open the dashboard. Compliance data can be re-created by re-scanning (history cannot), so the drill's pass criterion is "schema at head and the latest scan visible".

**Rollback of the application.** Deployments are by image digest. Roll back by redeploying the previous image digest (`<acr>.azurecr.io/<repo>@sha256:<previous>`) to the web app and the scan job. Keep the digest of the running release in your release notes.
The app requires the database to be at **exactly the head revision of the running build** (`pch db check`, readiness `schema_not_ready`), so an older image will not start against a newer schema. Decide by the migrations in the release:

| Migrations in the release | Rollback |
|---|---|
| None | Redeploy the previous digest. Done. |
| Additive only (new table, new nullable column, new index) | Redeploy the previous digest after running the downgrade to the previous revision (below); it only drops the new, empty objects. Test it on a restored copy first. |
| Destructive or data-rewriting (drop, narrowing a type, backfill) | Do **not** run a downgrade in prod. Restore the pre-release backup into a new database, point the app at it, redeploy the previous digest, re-scan if needed. |

Downgrade (no CLI command exists for it; `pch db upgrade --revision` can only move forward). Run it from the previous or current image, with the app and scan job stopped:

```bash
python - <<'PY'
from pch.settings import get_settings
from pch.store.engine import build_engine
from pch.store.migrate import downgrade
downgrade(build_engine(get_settings().database_url), "<previous-revision-id>")   # never "base": that drops every table
PY
pch db check    # run with the PREVIOUS image: must report at head
```

Downgrading to `base` (or below revision `0001`) deletes all data and is never a rollback. Write a correct `downgrade()` for every migration you add (`CUSTOMIZING.md`, "Add a migration").
Release order that keeps rollback simple: stop the scan schedule, confirm the backup, `pch db upgrade` (as the deploy identity), deploy the new digest, check `/health/ready`, re-enable the schedule.
