# AI guide: working in a fork of Pipeline Compliance Hub

Read `CLAUDE.md` (rules and invariants) and this file; that is enough to start. Open other docs only when a row below sends you there.

## What it is (5 lines)

* Report-only CI/CD compliance hub: it never writes to GitHub, Azure DevOps, SonarQube, Aikido or ServiceNow.
* Code is on GitHub, pipelines are Azure DevOps (YAML, Classic) and GitHub Actions workflows, all normalised to one `Pipeline` model.
* 61 deterministic Python rules (`pch rules list`) produce findings (PASS/FAIL/WARN/UNKNOWN/NA/WAIVED), scored per repo.
* Standards are config: `config/policy.yaml` and `config/scope.yaml` (see `docs/STANDARDS.md`); a scan is stored as one DB snapshot.
* Server-rendered dashboard (FastAPI + Jinja + HTMX) plus `/api/v1` JSON; scans run out-of-band via `pch scan`.

## Layer map

| Layer | What it does | Key files (under `src/pch/`) |
|---|---|---|
| Entry | Typer CLI (`pch --help`: doctor, db, scan, serve, scans, rules, config, seed-demo), exit codes | `cli.py`, `exitcodes.py`, `settings.py` (all env + YAML models), `doctor.py` |
| Collectors | Read-only HTTP to ADO, GitHub, Sonar, Aikido, ServiceNow; plain facts out | `collectors/http.py` (`SourceClient`), `collectors/transport.py` (`ReadOnlyTransport`), `collectors/ado/`, `collectors/github/`, `sonar.py`, `aikido.py`, `servicenow.py` |
| Wiring | Builds live/demo/cache clients; secrets via provider | `sources.py`, `providers/` |
| Orchestration | One scan: collect, normalise, evaluate, store in one transaction | `orchestrator.py` (`Scanner`), `scanrun.py` (timeout/SIGTERM) |
| Normalise | Canonical models and detection; data files | `model/`, `normalize/` (`gha.py`, `lineage.py`, `target_detect.py`, `capabilities.yaml`, `gha_capabilities.yaml`, `deprecated_tasks.yaml`, `gha_mapping.yaml`), `repo_scan/` |
| Engine | Rule registry, runner, scoring, waivers, reasons | `engine/registry.py` (`@rule`), `engine/rules/*.py`, `engine/runner.py`, `engine/scoring.py`, `engine/reasons.py`, `engine/migration.py` |
| Store | SQLAlchemy models, Alembic, engine factory, scan lock | `store/models.py`, `store/migrations/versions/`, `store/engine.py` (only place for dialect options), `store/repository.py`, `store/locks.py` |
| Web | Pages, JSON API, auth, security headers, exports | `web/app.py` (routes), `web/queries.py`, `web/tables.py`, `web/lineage_q.py`, `web/auth.py`, `web/guard.py`, `web/security.py`, `web/templates/`, `web/static/app.js` |
| Demo | Synthetic payloads through the real collectors (GitHub reader disabled) | `demo/` |

Flow: collectors -> normalize -> engine/rules -> store -> web. Rules read the normalised context (`ctx`), never raw API payloads and never do I/O.

## Where to change X

| I want to... | Change | Then |
|---|---|---|
| Add a rule | decorated function in `engine/rules/<module>.py` (`@rule(id, title, severity, scope, ...)`); recipe in `docs/CUSTOMIZING.md` section 6 | PASS and FAIL test in `tests/test_rules.py` (or `test_gha_rules.py`, `test_github_rules.py`); `pch rules docs --write docs/RULES.md` |
| Change a threshold, severity, list or disable a rule | `config/policy.yaml` (`rules:` map, thresholds) via `docs/STANDARDS.md`; not Python | `pch doctor`; `pch rules list --params --policy config/policy.yaml` |
| Change scope, repo overrides, env tiers | `config/scope.yaml` | `pch doctor` |
| Teach it a task or Action | `normalize/capabilities.yaml`, `gha_capabilities.yaml`, `deprecated_tasks.yaml`, `gha_mapping.yaml` | `tests/test_normalize_capabilities.py` |
| Add a collector or source | `docs/CUSTOMIZING.md` section 5: client on `SourceClient`, settings, `sources.py`, `orchestrator.py`, redaction, respx tests, demo hook | `pytest -q`; `pch scan --demo` |
| Add a GitHub field a rule needs | `collectors/github/protection.py` or `reader.py`, then the rule | respx fixture in `tests/fixtures/github/` |
| Add a setting | field in `settings.py`, entry in `config_reference.py`, mention in `.env.example` | `pch config reference --write README.md` |
| Add a DB column or table | `store/models.py` plus an Alembic revision with a working `downgrade()` (`docs/CUSTOMIZING.md` "Add a migration") | `pytest tests/test_db_portability.py` |
| Change a UI page | route in `web/app.py`, query in `web/queries.py`, template in `web/templates/`; no inline script or style, no third-party origin | `scripts/build_css.sh --check` (Tailwind rebuild if classes changed); `tests/test_web*.py` |
| Add an export column | append to `COLUMNS` in `web/lineage_q.py` (never reorder) and to the README "Export columns" table | `pytest tests/test_web_lineage.py` |
| Add or change an auth mode or bind option | `web/auth.py` (`AUTHENTICATORS`) and a branch in `web/guard.py` | extend `tests/test_web_security.py` |
| Change the scheduled scan | `.github/workflows/scheduled-scan.yml` (no `${{ }}` inside `run:`; pin actions by SHA) | `tests/test_scheduled_workflow.py` |
| Record a decision that weakens an invariant | `docs/DECISIONS.md` (new ADR) | |

## Invariants

Listed in `CLAUDE.md` ("Template invariants"); do not duplicate or weaken them without an ADR in `docs/DECISIONS.md`.

## Verify (run all that apply before committing)

```bash
ruff check . && mypy src && pytest -q -p no:warnings
```

```bash
scripts/build_css.sh --check
```

```bash
pch config reference --write README.md
```

```bash
pch rules docs --write docs/RULES.md
```

`tests/test_docs.py` fails on stale docs, broken relative links, undocumented settings, or `pch` commands/flags in the playbook and this guide that do not exist. Commit with a conventional message and push as `CLAUDE.md` says.

## Do not read unless the task needs it

* `docs/RULES.md` (generated, ~800 lines; use `pch rules list`), `docs/DECISIONS.md` (ADRs, ~300 lines; grep the ADR number), `docs/PLAN.md` (original build plan, partly historical), `docs/TEMPLATE_PLAN.md` (milestone log), `docs/THREAT_MODEL.md`, `docs/SECURITY_REVIEW.md`, `docs/DEPLOY_AZURE.md` (only for App Service hosting).
* README: the config table and the export-columns table are generated or test-checked; skim only the section you need.
* Large code files: `orchestrator.py`, `web/queries.py`, `web/app.py`, `cli.py`, `settings.py`; search by symbol instead of reading whole.
* `tests/fixtures/`, `src/pch/demo/`, `web/static/vendor/`, `requirements*.lock`, `data/`: generated or vendored; never edit by hand.

## Operating the system (not coding)

Adoption, configuration, scheduling and troubleshooting live in `docs/USING_IN_YOUR_ORG.md`. Never ask the user to paste a token; credentials live only in `.env` or secret stores.
