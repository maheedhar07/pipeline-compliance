# Threat model (STRIDE-lite)

Scope: the deployed system on Azure App Service (web) plus a scheduled scan job, Azure SQL or PostgreSQL, Blob/Key Vault (optional), reading Azure DevOps, SonarQube, Aikido and ServiceNow.
Companion documents: `SECURITY_REVIEW.md` (findings, `# VERIFY:` list), `DEPLOY_AZURE.md`, `USING_IN_YOUR_ORG.md`. Tests are cited as `file::name` under `tests/`.

## Assets

| Asset | Why it matters |
|---|---|
| A1 Compliance data (scans, findings, repo and owner names; the redacted raw cache) | Shows where controls are missing across the whole estate: a map for an attacker |
| A2 Read-only credentials for ADO / GitHub / Sonar / Aikido / ServiceNow | Reach upstream systems with broad read scopes |
| A3 Managed identities (web, scan, deploy) | Reach the database, Blob and Key Vault |
| A4 Availability of the dashboard and the scan | Compliance reporting is a control itself |

## Trust boundaries

```
 Browser (Entra user) --TLS--> [ App Service front end: Easy Auth, strips X-MS-* ]        boundary 1: internet -> platform
                                        | (only ingress; headers now trusted)
                                        v
                               [ web container: pch serve ] ----managed identity----> [ Azure SQL / PostgreSQL ]   boundary 3: app -> data
                                        |                                              [ Blob (raw cache)       ]
                                        |                                              [ Key Vault             ]
 [ scan job: pch scan ] --read-only HTTPS (PAT/token)--> [ ADO / Sonar / Aikido / ServiceNow ]   boundary 2: app -> upstream
        |  (same image, same DB; DB scan lock)                  upstream content is untrusted input (YAML, names, errors)
        +--> [ DB / Blob ]
 Developer / CI --> GitHub Actions (read-only token, pinned actions) --> ACR image (digest) --> App Service      boundary 4: supply chain
```

## Threats, mitigations, evidence

| STRIDE | Threat | Mitigation | Tests / evidence |
|---|---|---|---|
| S | Forged `X-MS-CLIENT-PRINCIPAL` header gives access | `easyauth` refuses to start unless the platform reports `WEBSITE_AUTH_ENABLED=True`; roles read from signed claims only; any parse problem is 401; unknown paths are 401 | `test_web_security.py::test_guard_exhaustive_invariants`, `::test_easyauth_missing_principal_is_401_everywhere`, `::test_roles_never_come_from_id_name_headers`, `test_security_review.py::test_unauthenticated_requests_never_reach_data`; platform side is go-live gate (SEC-08) |
| S | App started with no auth in prod or bound to all interfaces | Fail-closed serve guard, `APP_ENV=prod` rules | `test_web_security.py::test_guard_matrix`, `::test_pch_serve_refuses_unsafe_config` |
| T | The tool changes ADO, GitHub, Sonar, Aikido or ServiceNow | Every client is built on `SourceClient`, which wraps the transport in `ReadOnlyTransport` (GET/HEAD/OPTIONS plus 3 allowlisted POSTs and, in GitHub App mode, one per-client POST pinned to the configured GitHub host and exact token-exchange path; ADR-16); web app has no mutating route | `test_security_review.py::test_read_only_guard_blocks_mutations_in_any_spelling`, `::test_every_httpx_client_is_built_through_the_read_only_wrapper`, `test_scan_demo.py::test_scan_never_mutates`, `test_web_security.py::test_no_mutating_routes` |
| T | Two scans race, a crashed scan leaves partial data | DB scan lock with stale takeover; results and `complete` in one transaction; timeout < stale window enforced | `test_db_portability.py::test_scan_lock_acquire_conflict_release`, `::test_persist_failure_rolls_back_and_marks_scan_failed`, `test_hardening_t7b.py::test_scan_timeout_must_be_below_lock_stale_window` |
| T | Schema drift or unreviewed schema change | Schema only through Alembic; app refuses to start/serve readiness if not at head | `test_db_portability.py::test_models_and_migrations_in_sync`, `::test_prod_never_auto_migrates_unless_opted_in` |
| R | Cannot tell who viewed what | One structured request line (method, path without query, status, duration, request id, SHA-256 of principal id) | `test_ops.py::test_request_id_propagates_and_request_line_is_clean`; residual: no per-record audit trail |
| I | Secret values reach the database, cache, logs or telemetry | Redaction before the store (`build_record`), exception text scrubbed before the DB, log filter with exact registered secrets, `hide_parameters=True`, `repr=False` on the DB URL, URL query stripped from spans | `test_providers.py::test_secret_in_response_never_reaches_store`, `test_security_review.py::test_redact_json_covers_suffixed_secret_field_names_but_keeps_paging_cursors`, `::test_scanner_err_scrubs_before_the_text_is_kept_for_the_database`, `::test_sql_error_text_hides_bound_parameters`, `::test_settings_repr_does_not_contain_the_database_password`, `test_ops.py::test_sanitizer_and_httpx_spans_do_not_leak_urls_or_authorization` |
| I | Credentials sent in clear to a source | `https://` required for every source URL in prod | `test_hardening_t7b.py::test_prod_rejects_plain_http_source_urls` |
| I | Reader without the app role sees data; XSS or third-party script exfiltrates it | Role allowlist (403, no data); strict CSP, vendored assets, autoescape, `safe_url`, CSV formula neutralising | `test_web_security.py::test_easyauth_wrong_role_403_without_data`, `::test_csp_has_no_unsafe_or_third_party`, `::test_xss_escaped_in_html_and_json_blocks`, `::test_templates_have_no_inline_script_style_handlers_or_cdn` |
| D | Regex backtracking on hostile pipeline text or URLs | Linear-time patterns | `test_security_review.py::test_scrub_is_linear_on_adversarial_log_text`, `::test_redact_text_is_linear_on_adversarial_pipeline_text` |
| D | Huge upstream response exhausts memory; hung DB holds request threads; runaway scan | `HTTP_MAX_RESPONSE_MB` cap beneath the recorder; `DB_CONNECT_TIMEOUT_SECONDS`; `SCAN_TIMEOUT_MINUTES`; readiness probe is time-boxed, cached and single-flight | `test_hardening_t7b.py::test_chunked_response_is_aborted_when_it_passes_the_cap`, `::test_build_engine_passes_connect_args_to_the_driver`, `test_ops.py::test_scan_timeout_marks_failed_with_reason_and_raises`, `::test_readiness_probe_timeout_cache_and_single_flight` |
| E | SQL injection, path traversal, SSRF / credential forwarding on redirect | Bound parameters only (no `text()` with interpolation); store and file-provider key validation; redirects drop credentials; no absolute next-links followed (GitHub `Link` headers are followed only on the configured API host and path) | `test_security_review.py::test_findings_project_filter_treats_wildcards_literally`, `::test_redirect_to_another_host_does_not_forward_credentials`, `test_providers.py::test_local_store_rejects_escaping_keys`, `::test_file_provider_rejects_symlink_escape` |
| E | Compromised dependency, action or image | Hash-locked lockfiles, SHA-pinned actions, digest-pinned base, pip-audit / bandit / gitleaks in CI, non-root container | CI jobs (`.github/workflows/ci.yml`); SEC-12 accepted |
| E | The scheduled-scan workflow leaks source credentials or runs on untrusted code | Opt-in (`PCH_SCAN_ENABLED`), `permissions: {}` at the top, secrets only from the protected environment `pch-scan` and only through `env:`, no `pull_request_target` / `${{ }}` in `run:`, SHA-pinned actions, hash-checked lockfile, passwordless Azure OIDC, non-overlapping runs | `test_scheduled_workflow.py` (all tests); `.github/workflows/scheduled-scan.yml` |
| D | A broken schedule goes unnoticed and the dashboard shows stale data | Header "Last scan" label and warning banner (`SCAN_STALE_HOURS`, failed latest scan), job summary with the exit code meaning | `test_web_freshness.py` |
| E | An identity can do more than needed | Separate web / scan / deploy identities, least-privilege roles (`DEPLOY_AZURE.md`), Entra-only SQL auth, storage shared-key access disabled | Configuration; verify with the go-live gate in `IMPORT_CHECKLIST.md` |

## Residual risks

* **Platform behavior is assumed, not proven** (SEC-08, SEC-09, and the `# VERIFY:` items): that Easy Auth strips client `X-MS-*` headers on every path and that the container is reachable only through the front end. Mitigation: the forged-header test and probes in the go-live gate.
* **Any signed-in user** passes if `AUTH_ALLOW_ANY_AUTHENTICATED=true` with a multi-tenant app registration. Use the role allowlist, a single-tenant app and "Assignment required = Yes".
* **Redaction of free text is best effort**; structured fields and exactly registered secrets are the strong controls. Over-scrubbing of long identifiers is intentional.
* **Dashboard data is sensitive** to every holder of the reader role; there is no per-project access control.
* **The read-only guard is path-based** (SEC-10): a POST to an allowlisted path suffix on any host would pass; not exploitable against the supported systems. The raw cache (local disk or Blob) is trusted when replayed: restrict write access to the store.
* **Upstream API assumptions** (Aikido paths, ServiceNow fields) are unverified until run against the real systems; wrong guesses produce `UNKNOWN` or collection errors, not silent passes.
* **Accepted supply-chain gaps**: unpinned dev tools in CI and an unhashed PEP 517 build backend (SEC-12); Dependabot PRs still need review.
