# Template & Production-Hardening Plan (T1–T7)

This repo will be imported into a Microsoft-only organisation and built upon. Goal: a **boilerplate** whose
infrastructure seams are swappable by configuration, and which **fails safe** in a live environment.
`docs/PLAN.md` still governs the domain (collectors, rules). This file governs the template/hardening work.

## Decisions (agreed with the owner)

| Topic | Decision |
|---|---|
| Hosting target | Azure App Service (Linux, container) — "Web App". Scans run out-of-band (WebJob / scheduled job / ADO pipeline) via `pch scan`, never inside a web request. |
| Auth | Microsoft standard: **App Service Authentication (Easy Auth) + Entra ID**. App reads `X-MS-CLIENT-PRINCIPAL`, enforces an app-role / group allowlist, and **fails closed** if Easy Auth is not actually enabled (`WEBSITE_AUTH_ENABLED`). |
| Secrets | Default: env vars (App Service **Key Vault references** resolve into env). Optional extras: file mount, Azure Key Vault SDK via managed identity. |
| DB | SQLite (dev/demo), Postgres, **Azure SQL** (optional extra, Entra token via managed identity). Selected by `DATABASE_URL` + `DB_AUTH`. |
| Blob | Raw-response cache: local FS (default) or **Azure Blob** (optional extra). |
| Telemetry | Std logging (JSON in prod). Optional **Application Insights** via `azure-monitor-opentelemetry`. |
| CI | GitHub Actions only (hardened). |
| Adapters | Azure adapters are built now as **optional pip extras**, fixture/mock tested. Core stays cloud-neutral. |

## Design principles (enforced in code + tests)

1. **Ports & adapters at 5 seams only:** database, secrets, auth, artifact storage, source collectors. Everything else stays concrete. No speculative abstraction.
2. **Security fails closed.** `APP_ENV=prod` + auth `none` → refuse to start. Non-loopback bind + auth `none` → refuse to start.
3. **Config fails fast.** Strict validation (`extra="forbid"` on YAML models); `pch doctor` validates config, secrets resolution, DB connectivity and migration head.
4. **Collection fails open** (existing behaviour: one bad source/repo never aborts a scan) — keep and test.
5. **No half-written state.** Scan writes transactional; DB-backed scan lock; schema only via `pch db upgrade` (Alembic). `create_all` allowed only for sqlite in dev/test/demo.
6. **Every adapter selected by settings, registered in one place,** with an import-guarded optional dependency and a clear error if the extra is missing.
7. **Report-only and secret-safety rules from CLAUDE.md still apply.**
8. Optional-extra adapters are tested with mocks/fakes so the default `pip install -e ".[dev]"` test run needs no cloud SDKs (tests `importorskip` where needed). CI also runs a job with all extras installed.

## Milestones

Status: **T1-T7 are complete.** T7 also closed the residual risks the security review had accepted (https-only prod sources, scan timeout < lock window, response size cap, DB connect timeout) and added `CUSTOMIZING.md`, `IMPORT_CHECKLIST.md`, `THREAT_MODEL.md`, an expanded `DEPLOY_AZURE.md`, ADR-01..12 in `DECISIONS.md` and the docs-drift tests.

Each milestone ends with `ruff check . && mypy src && pytest`, a conventional commit, and `git push origin main`.

### T1 — Supply-chain baseline (done)
- Pin GitHub Actions by full commit SHA (with version comment). Least-privilege `permissions:` on workflows.
- CI jobs: lint+type+test (3.11, 3.12), `pip-audit`, `bandit -r src` (config in pyproject), gitleaks (or equivalent secret scan).
- Dependabot for pip, github-actions, docker.
- Upper-bounded dependency ranges in pyproject; `requirements.lock` generated with hashes (pip-tools style) and used by the Dockerfile.
- Dockerfile: base image pinned by digest (comment how to bump), multi-stage, non-root, no build tools in final image, `--require-hashes` install.

### T2 — Settings & config (done)
- `APP_ENV` (`dev|test|prod`) profile. Settings grouped and documented; `.env.example` complete.
- Strict YAML models (`extra="forbid"`), useful error messages with file + field path.
- Move org-specific literals (e.g. quality-gate name "Company Way", contoso hosts) into config / `.example` files.
- `pch doctor` command (exit non-zero on any failure, never prints secret values).

### T3 — Portable persistence (done)
- Alembic migrations (initial revision = current schema), `pch db upgrade|current|check`. Prod: no `create_all`; app readiness fails if DB not at head.
- Dialect-neutral types: timezone-aware UTC datetimes everywhere (no `utcnow()`), JSON via a TypeDecorator that works on SQLite/Postgres/MSSQL, string lengths valid for MSSQL index limits.
- Engine factory: per-dialect options isolated in one module; `pool_pre_ping`, pool sizing/recycle from settings; credential hook interface (`DB_AUTH=password|azure_ad`) — Azure SQL token injected via `do_connect` using `azure-identity` (extra `azuresql`).
- Scan lock (DB row/table-based, works on all 3 dialects, with stale-lock timeout).
- CI matrix: SQLite, Postgres (service container), SQL Server (`mcr.microsoft.com/mssql/server` service container + ODBC driver). DB-portability tests skip locally unless `TEST_DATABASE_URL` set.

### T4 — Provider seams (done)
- `SecretProvider`: `env` (default), `file` (mounted dir), `azure_keyvault` (extra). Settings secrets resolved through it.
- `ArtifactStore` for raw cache + `--from-cache`: `local` (default), `azure_blob` (extra, managed identity). Redaction happens before any store write.
- Single `providers` registry module; clear error when an extra is missing.

### T5 — Web security (done)
- Auth modes: `none` (dev only, loopback only), `easyauth` (parse `X-MS-CLIENT-PRINCIPAL`, require `WEBSITE_AUTH_ENABLED=True` in prod, allowlist of roles/groups, 401/403 fail closed), dependency-injected so other modes can be added.
- Security headers middleware: strict CSP (no third-party origins), HSTS (prod), X-Content-Type-Options, frame-ancestors none, Referrer-Policy, Permissions-Policy.
- Vendor Tailwind (prebuilt CSS), HTMX, Chart.js into `static/vendor` with recorded versions + SHA256 in a manifest; no CDN at runtime.
- `/api/docs` disabled in prod; generic error pages (no tracebacks); trusted-host / proxy-headers config for App Service.

### T6 — Operability (done)
- Structured JSON logging in prod with request id; log filter redacting secret-like values.
- `/health/live` (process) and `/health/ready` (DB reachable + migrations at head); keep `/api/v1/health` as alias.
- Optional App Insights (extra `azure-monitor`) enabled by `APPLICATIONINSIGHTS_CONNECTION_STRING`.
- `pch scans prune --keep N --older-than D` (retention, also prunes artifact store).
- Graceful shutdown; App Service startup command / `WEBSITES_PORT` docs.

### T7 — Template docs + independent security review (done)
- `docs/CUSTOMIZING.md`: one recipe per seam (swap DB → Azure SQL, secrets, auth, storage, add collector, add rule).
- `docs/DEPLOY_AZURE.md`: App Service + Easy Auth + managed identity + Key Vault references + Azure SQL + Blob + App Insights; least-privilege role assignments; go-live checklist.
- `docs/THREAT_MODEL.md` (STRIDE-lite), `docs/IMPORT_CHECKLIST.md`, ADRs appended to `docs/DECISIONS.md`.
- Independent security review of the whole T1–T6 diff; fix findings.

---

# GitHub-first phase (G1–G5)

Owner's estate: **all code on GitHub; pipelines in Azure DevOps (YAML + Classic), migrating to GitHub Actions.**
Azure Repos is not used. Not going live yet: optimise for clarity and customisability. **Do not spend effort on
demo/mock data** — add or adjust only the one or two records needed to verify a change; spend the effort on the code.

| # | Milestone | Outcome |
|---|---|---|
| G1 | GitHub-only + standards-as-config + reasons | Azure Repos removed from scan/UI (GitHub is the code host). Per-rule `enabled`/`severity`/params in `policy.yaml`; `docs/STANDARDS.md` maps every knob. Every non-compliant repo/pipeline shows a plain-language **"why"** (failing critical/high rules + message) on Repos, Overview, Lineage, repo page, CSV/XLSX/JSON. |
| G2 | GitHub read-only reader (done, ADR-16) | Fine-grained PAT (default) or GitHub App. Repo discovery from the GitHub org; branch protection + rulesets, file tree (tests/Dockerfiles/IaC), CODEOWNERS. Replaces the UNKNOWNs from ADR-13 with real PASS/FAIL. |
| G3 | GitHub Actions pipelines (done, ADR-17) | Workflows → canonical `Pipeline(platform="gha")`, environments + protection rules, deployments/runs, OIDC vs secrets, action SHA pinning. Rules + lineage cover GHA, so repos are covered as they migrate. |
| G4 | Scheduling + richer UI | Scheduled GitHub Actions workflow running `pch scan` (opt-in, OIDC, pinned). UI: visual lineage flow, richer overview (by project/owner, severity, top reasons, drill-down charts), richer repo page (category breakdown, fix-first list, trend), better tables (sticky headers, sort, pagination, column chooser, filter chips). |
| G5 | Org playbook | Short `docs/USING_IN_YOUR_ORG.md` (ordered steps, commands, don'ts), compact `docs/AI_GUIDE.md` for AI-assisted work, README/CLAUDE.md pointers; prune duplication. |
