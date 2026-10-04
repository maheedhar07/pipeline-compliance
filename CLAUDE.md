# Pipeline Compliance Hub

Start here: `docs/AI_GUIDE.md` (layer map, where to change what, verify commands).
Using it in an org: `docs/USING_IN_YOUR_ORG.md`. Standards and thresholds: `docs/STANDARDS.md`.
Scope, architecture and the rule catalog (historical build plan): `docs/PLAN.md`; decisions: `docs/DECISIONS.md`. Read them only when a task needs them.

## Working rules
- Before committing: `ruff check . && mypy src && pytest -q -p no:warnings`, then a conventional commit and `git push origin main`. Keep each commit green.
- No live credentials. Every collector is developed and tested against fixtures (respx); demo mode must exercise the real collectors, normalizers and rules.
- Report-only: never add code that writes to Azure DevOps, GitHub, SonarQube, Aikido or ServiceNow.
- Never persist secret values. Redact raw caches.
- Standards are config: thresholds, severities and rule switches go in `config/policy.yaml`, not in rule Python.
- Rules are deterministic Python. Each rule needs a PASS and a FAIL test.
- Keep `capabilities.yaml`, `gha_capabilities.yaml`, `deprecated_tasks.yaml` and `gha_mapping.yaml` as data files, not code.
- If an external API detail is uncertain, isolate it behind one function and leave a `# VERIFY:` comment.

## Template invariants
These hold for every change in this repo and in repos derived from it. A change that weakens one needs an explicit decision recorded in `docs/DECISIONS.md`.
- **Fail-closed serve guard.** `pch.web.guard.assert_safe_to_serve` decides whether the app may start; any new auth mode or bind option gets its own branch there (an unknown mode must not start unchecked). Public paths stay limited to the health endpoints (`/health/live`, `/health/ready`, `/api/v1/health`) and `/static/`.
- **Strict config.** `Settings` validates at startup and YAML models are `extra="forbid"`. `APP_ENV=prod` requires https source URLs; `SCAN_TIMEOUT_MINUTES` stays below `SCAN_LOCK_STALE_MINUTES`.
- **Schema only through migrations.** Every model change ships an Alembic revision (with a working `downgrade()`); no `create_all` outside the SQLite dev/test auto-migrate path. Dialect options live only in `store/engine.py`.
- **All HTTP through `ReadOnlyTransport`.** Build clients with `SourceClient`; never create another `httpx` client or add mutating endpoints to `ALLOWED_POSTS`; the only other POST is the GitHub App token exchange, a per-client allowance bound to the API host and exact path (ADR-16). Upstream response size stays capped (`HTTP_MAX_RESPONSE_MB`).
- **Redaction before persist.** Redact before anything reaches the artifact store, database, logs or telemetry; scrub exception text; never store secret values; register resolved secrets with `register_secret`.
- **Providers via their factory/registry.** Secrets and artifact stores are selected in `build_secret_provider` / `build_artifact_store`, auth in `AUTHENTICATORS`; cloud SDKs stay optional extras with a clear `ProviderUnavailable` error; no silent fallback between providers.
- **Docs-drift test.** A new `Settings` field needs an entry in `src/pch/config_reference.py`, a mention in `.env.example` and a regenerated README table (`pch config reference --write README.md`); `docs/RULES.md` is regenerated with `pch rules docs --write docs/RULES.md`. `tests/test_docs.py` must stay green.
- **Rules stay deterministic Python** with a PASS and a FAIL test, and data files (`capabilities.yaml`, `gha_capabilities.yaml`, `deprecated_tasks.yaml`, `gha_mapping.yaml`) stay data.
