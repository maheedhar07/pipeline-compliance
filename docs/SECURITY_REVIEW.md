# Independent security review (T7)

Scope: the T1-T6 hardening diff (`git diff 2f41ebd..HEAD`) plus the pre-existing code it sits on. Target deployment: Azure App Service
(Linux container) behind Easy Auth / Entra ID, Azure SQL or Postgres, Key Vault, Blob, Application Insights. Properties under test:
report-only (never writes to ADO / GitHub / Sonar / Aikido / ServiceNow), never persists secrets, fails closed.

## Method

* Read all of `web/` (auth, guard, security, app, health, templates, static JS), `collectors/` (transport, http, redact, every client),
  `providers/`, `logging_setup.py`, `telemetry.py`, `settings.py`, `orchestrator.py`, `store/` (engine, locks, azure_sql, queries),
  `retention.py`, `cli.py serve/scan`, CI workflow, Dockerfile, dependabot.
* Exploit tests written against raw ASGI scopes (no client-side path normalisation), `httpx.MockTransport`, and adversarial strings
  (65 KB runs) with wall-clock budgets. Every confirmed finding has a regression test in `tests/test_security_review.py`, which fails on
  the pre-fix code.
* Tooling (treated as leads, verified by hand): `bandit -c pyproject.toml -r src` (clean), `pip-audit` on `requirements.lock` and
  `requirements-azure.lock` (clean), `semgrep --config p/python --config p/fastapi --config p/secrets src` (2 hits, both false
  positives: SHA-1 used as a non-security cache key with `usedforsecurity=False`; a log line that names a secret *file*, not its value).

## Findings

| ID | Severity | Area | Description | Status | Test |
|---|---|---|---|---|---|
| SEC-01 | High | DoS / robustness | Catastrophic regex backtracking. `logging_setup.scrub` (`_KV`, `_URL_CREDS`, `_KNOWN`) was quadratic: a 65 KB request path or upstream text such as `token` x 13 000 or `a.` x 30 000 pinned the event loop for minutes, because every log line passes through it (an authenticated user could stall the whole app with one long URL; the scan could be stalled by hostile text in an upstream error). `collectors/redact.redact_text` (`_YAML_KV`, `_YAML_NAME_VALUE`) was cubic on blank-line / whitespace runs (500 newlines = 2.3 s, 1 000 = minutes), reachable by anyone who can commit a pipeline YAML / repo file the scanner fetches; `asyncio.timeout` cannot interrupt a regex, so the scan timeout would not fire. `PY_TEST_DEP` was quadratic on blank lines. All rewritten with word-start lookbehinds, lookahead key detection and possessive quantifiers; semantics preserved. | Fixed | `test_scrub_is_linear_on_adversarial_log_text`, `test_redact_text_is_linear_on_adversarial_pipeline_text`, `test_scrub_still_scrubs_after_the_linear_rewrite`, `test_redact_text_still_redacts_after_the_linear_rewrite` |
| SEC-02 | Medium | Secrets / raw cache | `redact_json` matched secret field names exactly, so `apiToken`, `authToken`, `id_token`, `privateKey`, `bearerToken`, `AWS_SECRET_ACCESS_KEY` were written unredacted to the raw cache (local dir or Blob). Added a suffix rule (`...token/secret/password/pwd/apikey/privatekey/accesskey`); paging cursors (`continuationToken`, `nextPageToken`) and `tokenType` are exempt because the collectors read them back from the cache. | Fixed | `test_redact_json_covers_suffixed_secret_field_names_but_keeps_paging_cursors` |
| SEC-03 | Medium | Secrets / DB | Exception text was persisted unscrubbed in `collection_errors`, `COLLECTION-ERROR` findings and `scans.summary.error`. Pydantic validation errors embed `input_value=` (raw upstream data), so a credential-bearing field could reach the database and the dashboard. All four sinks now pass through `scrub()`. | Fixed | `test_scanner_err_scrubs_before_the_text_is_kept_for_the_database`, `test_failed_scan_reason_is_scrubbed_in_the_scans_table` |
| SEC-04 | Medium | Secrets / logs / telemetry | SQLAlchemy `DBAPIError` text includes `[parameters: (...)]` (row values) and reaches logs, `scans.summary.error` and OpenTelemetry exception events. Engine now built with `hide_parameters=True`. | Fixed | `test_sql_error_text_hides_bound_parameters` |
| SEC-05 | Low | Secrets | `repr(Settings())` / `str()` exposed `DATABASE_URL`, which may embed a password. Field is `repr=False`. | Fixed | `test_settings_repr_does_not_contain_the_database_password` |
| SEC-06 | Low | Injection (logic) | `findings_list(project=...)` used `LIKE 'project/%'`; `%` / `_` in the query parameter acted as wildcards (not SQL injection; values are bound). Now `startswith(..., autoescape=True)`. | Fixed | `test_findings_project_filter_treats_wildcards_literally` |
| SEC-07 | Low | Web | The `u()` template helper put project / repo names into link paths unencoded (`#`, `?`, `%` change the link target). Path is now percent-encoded (the `href` was already HTML-escaped; no XSS). | Fixed | `test_u_helper_encodes_path_segments` |
| SEC-08 | Medium | AuthN (platform) | Everything depends on Easy Auth stripping client-supplied `X-MS-CLIENT-PRINCIPAL*` on every non-excluded path, on `WEBSITE_AUTH_ENABLED` being exposed to the container, and on the front end being the only ingress (no private endpoint / SCM / direct container port that skips it). The code fails closed without the env flag but cannot prove the rest. | Verify on Azure | n/a (see go-live checklist) |
| SEC-09 | Low | Telemetry | OpenTelemetry span *events* (`exception.message`, stack trace) are not passed through `RedactingFilter`; URL attributes are sanitised at span start only. Parameters are now excluded (SEC-04). | Verify on Azure | n/a |
| SEC-10 | Low | Read-only guard | `ALLOWED_POSTS` is anchored at the end only and not bound to a host, so a POST to `<any host>/<any prefix>/api/oauth/token` passes. Not exploitable against ADO / Sonar / ServiceNow (no such mutating route), and anchoring the start would break an Aikido URL configured with a path prefix. Every client still goes through `ReadOnlyTransport` (verified: it is the only `httpx.AsyncClient` in the package, and wraps Recording / Replay / Mock transports). Lower-case and unusual methods, `/preview/..` tricks and `previewRun=false` are all blocked. | Accepted | `test_read_only_guard_blocks_mutations_in_any_spelling`, `test_every_httpx_client_is_built_through_the_read_only_wrapper` |
| SEC-11 | Low | Config | Source base URLs could be `http://` (credentials in clear) even in prod, and `SCAN_TIMEOUT_MINUTES` >= `SCAN_LOCK_STALE_MINUTES` would let a second scan steal the lock of a still-running one. Now (a) `APP_ENV=prod` rejects any configured ADO / vsrm / Sonar / Aikido / ServiceNow / Key Vault / Blob URL that is not `https://`, and (b) Settings validation fails unless the scan timeout is smaller than the stale-lock window (all environments). | Fixed | `test_prod_rejects_plain_http_source_urls`, `test_prod_accepts_https_and_unset_sources`, `test_scan_timeout_must_be_below_lock_stale_window`, `test_stale_lock_window_is_longer_than_the_scan_timeout_by_default` |
| SEC-12 | Low | Supply chain | CI installs dev tools unpinned (`pip install -e ".[dev]"`, `pip install bandit pip-audit`); the Docker builder runs `pip install --no-deps .` whose PEP 517 build backend is fetched without hashes. Runtime dependencies are hash-locked and base images / actions are SHA-pinned (SHAs verified to exist upstream). | Accepted | n/a |
| SEC-13 | Low | DoS | `RecordingTransport` buffered whole upstream responses with no cap, and server DB engines had no connect timeout (a hung DB could occupy the sync request thread pool). Now `SizeLimitTransport` (`HTTP_MAX_RESPONSE_MB`, default 50) sits under the recorder: it rejects on `Content-Length` before reading and aborts chunked bodies while streaming, raising `ResponseTooLargeError` (not retried; an ordinary collection error, the scan continues). Engines pass `connect_timeout` (psycopg) / `timeout` = login timeout (pyodbc), `DB_CONNECT_TIMEOUT_SECONDS`, default 15. | Fixed | `test_content_length_over_cap_is_rejected_without_reading_the_body`, `test_chunked_response_is_aborted_when_it_passes_the_cap`, `test_response_within_cap_is_unchanged_and_error_is_not_retried`, `test_recording_transport_never_buffers_past_the_cap`, `test_live_sources_wrap_the_network_transport_with_the_cap`, `test_connect_args_per_dialect`, `test_build_engine_passes_connect_args_to_the_driver` (all in `tests/test_hardening_t7b.py`) |
| SEC-14 | Info | Host header | `hostname_of` is lenient (`app.example.net:80@evil.com` passes as `app.example.net`). Verified that redirects are built from the parsed host and never reflect the attacker part; no impact. | Accepted | n/a |

### Checked, no issue found

* **Auth bypass probes** (raw ASGI): `/health/live/`, `/health/live/../repos`, `/health/ready/x`, upper-case health, `/api/v1/health/..`, `/static`,
  `//static/x`, `/static/../repos`, `/static/%2e%2e/..`, backslash traversal, HEAD / OPTIONS / POST / TRACE: none reach data without a
  principal; static traversal is 404 even when authenticated; unknown paths answer 401 (no existence leak) because auth runs before routing;
  role match is exact and case-sensitive; malformed / oversized principal headers deny with 401; parser exceptions deny.
* **XSS / CSP**: autoescape on, no `|safe` / `Markup` outside `json_for_script` (escapes `< > &` and U+2028/9), `safe_url` allows only `http(s)`,
  no inline script or `innerHTML`, strict CSP on every response including error pages, swagger inline script hashed and dev-only.
* **CSV export**: formula prefixes neutralised. **Request id**: strict regex, `fullmatch`, control characters escaped in the path log field.
* **SSRF / traversal**: paging builds URLs from the configured base plus a `continuationToken` parameter (no absolute next-links followed);
  redirects to another origin drop `Authorization` / basic auth (httpx behaviour, now tested for header and tuple auth);
  `LocalArtifactStore` / `FileSecretProvider` reject `..`, absolute, backslash and escaping symlinks.
* **DB**: no `text()` with interpolation (only `SELECT 1`); scan lock is an INSERT + compare-and-swap UPDATE; Azure SQL token never logged.
* **Pipeline storage**: script bodies omitted, secret-looking inputs dropped, variable values never stored.
* **CI**: `pull_request` (not `_target`), `contents: read`, `persist-credentials: false`, no `github.event.*` in `run:`, checksum-verified gitleaks.
  **Docker**: digest-pinned base, `--require-hashes`, non-root uid 10001, `PCH_LOCKFILE` is a build-time choice only.

## L2 addendum: Lineage tab and exports (self-review)

| ID | Severity | Area | Description | Status | Test |
|---|---|---|---|---|---|
| SEC-15 | Medium | Excel / CSV injection | Repo, pipeline, stage, environment and target names are attacker-influenced and now reach a spreadsheet. openpyxl turns any `str` starting with `=` into a formula cell. Every text cell is written with an explicit string type and additionally neutralised with the `/repos.csv` rule; both layers are tested independently (the string type alone, and the loaded workbook of a database with hostile names: no cell is a formula, no `<f>` element in any sheet XML). | Fixed | `test_xlsx_never_contains_formulas`, `test_string_cell_is_literal_even_without_neutralisation`, `test_csv_neutralises_formulas_in_every_cell` |
| SEC-16 | Low | Privacy | The lineage stores people only as the display name of whoever triggered the last deployment/run; values that look like e-mails/UPNs are dropped; approvers are summarised as kinds/counts. | By design | `test_classic_chain_build_release_stages_in_order`, `test_release_deployments_last_per_environment_with_followup` |
| SEC-17 | Low | DoS | Exports of the whole estate could be large. Row cap `EXPORT_MAX_ROWS` (413 with a clear message instead of a silent truncation), Excel written in streaming mode, list page renders at most 500 repos (chains load on demand). | Fixed | `test_export_row_cap_is_enforced_with_a_clear_message` |
| SEC-18 | Info | Read-only | The new collectors only issue GET requests through `AdoClient`; a test asserts the lineage requests of a full scan are GETs, and the scan still sends nothing else. Exports are GET-only routes behind the same auth middleware, `no-store`, with sanitised filenames. | Verified | `test_lineage_requests_are_read_only_gets`, `test_export_and_pages_are_get_only`, `test_lineage_requires_authentication_and_role` |
| SEC-19 | Info | XSS | All lineage text is escaped by Jinja; links go through `safe_url`; the chain loads as an HTML fragment from the same origin (no inline script, CSP unchanged). | Verified | `test_xss_escaped_everywhere_on_lineage_pages` |

New `# VERIFY:` markers (confirm on first contact with real data): `release/deployments` (all-environment listing, `definitionEnvironmentId` filter), `release/releases?$expand=artifacts` version shape (GitHub artifacts: commit id in `version.id`), `environmentdeploymentrecords` (`top`, `definition`, `stageName`, `owner`, `result`), and that the preview `finalYaml` keeps `resources:`/`trigger:`/`schedules:` (`collectors/ado/deployments.py`, `collectors/ado/lineage_meta.py`).

## Residual risks

* Easy Auth is the only authentication; with `AUTH_ALLOW_ANY_AUTHENTICATED=true` and a multi-tenant app registration any signed-in user
  passes. Use the role allowlist, single tenant, and "Assignment required = Yes".
* Regex-based redaction is best effort for free text; structured fields and exact registered secrets are the strong controls.
* Over-scrubbing is intentional: long high-entropy identifiers (for example a Sonar project key) can show as `***REDACTED***` in logs / error rows.
* Dashboard data (compliance findings, repo names, owners) is sensitive to anyone holding the reader role.

## VERIFY markers and go-live checklist

Confirm on a real App Service before go-live (the `# VERIFY:` comments in the code; the full gate is in `DEPLOY_AZURE.md` section 11).

**Easy Auth / ingress** (`web/auth.py`, `web/guard.py`, `settings.py`, `docs/DEPLOY_AZURE.md`)
* `WEBSITE_AUTH_ENABLED=True` reaches the container when Authentication is on (`guard.py:62`, `settings.py:131`).
* Client-supplied `X-MS-CLIENT-PRINCIPAL*` is stripped on every request, including excluded health paths, private endpoints and SCM (`auth.py:11`). Send a forged header to the public URL and expect 401.
* Principal header shape and `roles` claim type (`auth.py:11`).
* The container is reachable only through the front end, so `FORWARDED_ALLOW_IPS=*` is safe (`settings.py:121`; `DEPLOY_AZURE.md`).
* Health probe `Host` header is allowed by `ALLOWED_HOSTS`; health check needs >= 2 instances (`DEPLOY_AZURE.md`).

**Lifecycle** (`settings.py:146`, `settings.py:149`, `.env.example:100`)
* SIGTERM to SIGKILL window (~30 s) vs `GRACEFUL_SHUTDOWN_SECONDS`; ARR idle timeout (~230 s) vs `KEEP_ALIVE_SECONDS`.

**Azure data plane** (`store/azure_sql.py:98`, `DEPLOY_AZURE.md`)
* Azure SQL token auth works after `Trusted_Connection` / `UID` / `PWD` stripping; managed identity / federated credential variables for the scan job.

**Telemetry** (`telemetry.py:70`)
* No URL query, credential or row value in Application Insights `exceptions` / `dependencies` / `requests`.

**Source systems** (`collectors/aikido.py:18,20,22,39,44`, `collectors/transport.py:21,22`, `ado/service_conn.py:16`, `ado/runs.py:116`, `ado/environments.py:47`)
* GitHub (G2, ADR-16): response field names of rulesets and classic branch protection (`collectors/github/protection.py`, `# VERIFY:`), org-ruleset bypass actors visibility, and `pch doctor --online` against the real organisation. The GitHub App token exchange is the one POST that IS bound to host and exact path (unlike the Aikido regexes of SEC-10).
* Aikido token / repository / issue endpoints and field names (the two token paths in `ALLOWED_POSTS`); ARM connection scope fields;
  where CRQ numbers appear in release data; how the ServiceNow check shows up in environments. Re-run the collectors against fixtures after any change.
