# Pipeline Compliance Hub

The source of truth for scope, architecture and the rule catalog is `docs/PLAN.md`. Read it before working.

## Working rules
- Execute milestones in order (M0 → M8). After each milestone: `ruff check . && pytest`, then commit (conventional commit message) and `git push origin main`.
- There are no live credentials. Every collector must be developed and tested against fixtures (respx). Demo mode must exercise the real collectors → normalizers → rules path.
- Report-only: never add code that writes to Azure DevOps, GitHub, SonarQube, Aikido or ServiceNow.
- Never persist secret values. Redact raw caches.
- Rules are deterministic Python. Each rule needs ≥1 PASS and ≥1 FAIL test.
- Keep `capabilities.yaml`, the deprecated-task list and the GHA mapping as data files, not code.
- If an external API detail is uncertain (especially Aikido), isolate it behind one function and leave a `# VERIFY:` comment.

## Template invariants
These hold for every change in this repo and in repos derived from it. A change that weakens one needs an explicit decision recorded in `docs/DECISIONS.md`.
- **Fail-closed serve guard.** `pch.web.guard.assert_safe_to_serve` decides whether the app may start; any new auth mode or bind option gets its own branch there (an unknown mode must not start unchecked). Public paths stay limited to `/health/*` and `/static/`.
- **Strict config.** `Settings` validates at startup and YAML models are `extra="forbid"`. `APP_ENV=prod` requires https source URLs; `SCAN_TIMEOUT_MINUTES` stays below `SCAN_LOCK_STALE_MINUTES`.
- **Schema only through migrations.** Every model change ships an Alembic revision (with a working `downgrade()`); no `create_all` outside the SQLite dev/test auto-migrate path. Dialect options live only in `store/engine.py`.
- **All HTTP through `ReadOnlyTransport`.** Build clients with `SourceClient`; never create another `httpx` client or add mutating endpoints to `ALLOWED_POSTS`. Upstream response size stays capped (`HTTP_MAX_RESPONSE_MB`).
- **Redaction before persist.** Redact before anything reaches the artifact store, database, logs or telemetry; scrub exception text; never store secret values; register resolved secrets with `register_secret`.
- **Providers via their factory/registry.** Secrets and artifact stores are selected in `build_secret_provider` / `build_artifact_store`, auth in `AUTHENTICATORS`; cloud SDKs stay optional extras with a clear `ProviderUnavailable` error; no silent fallback between providers.
- **Docs-drift test.** A new `Settings` field needs an entry in `src/pch/config_reference.py`, a mention in `.env.example` and a regenerated README table (`pch config reference --write README.md`); `docs/RULES.md` is regenerated with `pch rules docs --write docs/RULES.md`. `tests/test_docs.py` must stay green.
- **Rules stay deterministic Python** with a PASS and a FAIL test, and data files (`capabilities.yaml`, `deprecated_tasks.yaml`, `gha_mapping.yaml`) stay data.
