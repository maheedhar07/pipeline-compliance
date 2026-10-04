"""Configuration reference rendered from ``Settings`` (the README table is checked against it).

``FIELD_DOCS`` holds one description per Settings field, grouped. Adding a Settings field without an entry here
(or without a row in the README / a mention in ``.env.example``) fails ``tests/test_docs.py``, so the docs cannot drift.
The README table sits between ``<!-- config-reference:start -->`` and ``<!-- config-reference:end -->``;
regenerate it with ``pch config reference --write README.md``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import SecretStr
from pydantic_core import PydanticUndefined

from pch.settings import Settings

START = "<!-- config-reference:start -->"
END = "<!-- config-reference:end -->"

# group -> [(FIELD, description)]. Order is the order of the rendered table.
FIELD_DOCS: dict[str, list[tuple[str, str]]] = {
    "Runtime": [
        ("app_env", "Profile: `dev`, `test` or `prod`. `prod` turns on the fail-closed checks (https-only sources, `ALLOWED_HOSTS`, no `AUTH_MODE=none`, no auto-migrate of SQLite, `config/scope.yaml` required)."),
        ("data_dir", "Local data directory (SQLite file, demo world, local raw cache under `raw/`)."),
        ("config_dir", "Directory holding `scope.yaml` and `policy.yaml`."),
    ],
    "Database": [
        ("database_url", "SQLAlchemy URL: `sqlite:///...`, `postgresql+psycopg://...` or `mssql+pyodbc://...`. May embed a password (never printed)."),
        ("db_auth", "`password` (credentials in the URL) or `azure_ad` (Entra access token via `DefaultAzureCredential`; Azure SQL only)."),
        ("db_pool_size", "Connection pool size (server databases; 1-100)."),
        ("db_max_overflow", "Extra connections above the pool size (0-200)."),
        ("db_pool_recycle", "Recycle connections after N seconds (-1 = never). Keep below Azure SQL's ~30 min idle disconnect."),
        ("db_pool_timeout", "Seconds to wait for a pooled connection (0-600)."),
        ("db_connect_timeout_seconds", "Seconds to wait when opening a new server connection (psycopg `connect_timeout`, pyodbc login `timeout`; 1-300). Ignored for SQLite."),
        ("db_auto_migrate", "Run `alembic upgrade head` at startup on any database. Off by default; prefer `pch db upgrade` as a deploy step."),
        ("scan_lock_stale_minutes", "A scan lock or `running` scan older than this is treated as abandoned. Must be greater than `SCAN_TIMEOUT_MINUTES`."),
    ],
    "Providers": [
        ("secrets_provider", "Where source credentials come from: `env` (default; App Service Key Vault references arrive as env vars), `file`, `azure_keyvault`. Never mixed."),
        ("secrets_dir", "Directory with one file per secret (`file` provider; required for it)."),
        ("keyvault_url", "`https://<vault>.vault.azure.net` (required for `azure_keyvault`; https only)."),
        ("keyvault_secret_map", "JSON map env-style name -> Key Vault secret name (default: lowercase, `_` -> `-`, e.g. `ADO_PAT` -> `ado-pat`)."),
        ("keyvault_cache_ttl_seconds", "In-memory cache of Key Vault values (0 = always re-read; 0-86400)."),
        ("artifact_store", "Raw scan cache backend: `local` or `azure_blob`."),
        ("artifact_blob_account_url", "`https://<account>.blob.core.windows.net` (required for `azure_blob`; managed identity only)."),
        ("artifact_blob_container", "Blob container name (required for `azure_blob`)."),
    ],
    "Azure DevOps": [
        ("ado_org", "Organization name (`https://dev.azure.com/<org>`). Required for live scans (or set `organization` in scope.yaml; both set must be equal)."),
        ("ado_pat", "Read-only personal access token (secret)."),
        ("ado_base_url", "Base URL of Azure DevOps Services (change for Azure DevOps Server). https in prod."),
        ("ado_vsrm_url", "Base URL of the release management service. https in prod."),
    ],
    "GitHub": [
        ("github_api_url", "GitHub REST API base URL: `https://api.github.com`, or GHES `https://<host>/api/v3`. https in prod. Only this host is ever called (pagination links elsewhere are refused)."),
        ("github_auth", "`pat` (fine-grained personal access token, default) or `app` (GitHub App installation; needs the `github-app` extra)."),
        ("github_token", "Fine-grained PAT, READ-ONLY (Metadata, Contents, Actions, Environments, Deployments, Administration: read) (secret). Setting it enables the GitHub reader."),
        ("github_app_id", "Numeric GitHub App id (`GITHUB_AUTH=app`)."),
        ("github_app_installation_id", "Numeric installation id of the App on your organisation (`GITHUB_AUTH=app`)."),
        ("github_app_private_key", "App private key, PEM; a one-line value with literal backslash-n line breaks is accepted (secret)."),
    ],
    "SonarQube": [
        ("sonar_url", "SonarQube base URL. Unset = Sonar not queried. https in prod."),
        ("sonar_token", "User token with Browse permission (secret)."),
    ],
    "Aikido": [
        ("aikido_url", "Aikido base URL. https in prod."),
        ("aikido_client_id", "OAuth client id. Setting it enables Aikido."),
        ("aikido_client_secret", "OAuth client secret (secret)."),
    ],
    "ServiceNow": [
        ("servicenow_url", "ServiceNow instance URL. Unset = not queried. https in prod."),
        ("servicenow_user", "User with read access to `change_request`."),
        ("servicenow_password", "Password of that user (secret)."),
    ],
    "Collection": [
        ("concurrency", "Parallel requests per source (1-64)."),
        ("http_timeout", "Per-request timeout in seconds (>0, <=300)."),
        ("http_max_response_mb", "Largest single upstream response body in MB (1-2048). Larger responses are aborted while streaming and recorded as a collection error."),
    ],
    "Lineage and export": [
        ("lineage_enabled", "Collect the last deployment per stage/environment for the Lineage tab (two extra read-only calls per release definition, one per YAML environment). `false`: stages show as unknown."),
        ("lineage_deployments_top", "Deployments / environment records requested per lookup (10-1000). A stage missing from the page gets a targeted lookup before it is shown as never deployed."),
        ("export_max_rows", "Largest CSV/Excel lineage export in rows (1-5000000). A bigger export is refused with HTTP 413: narrow the filters."),
    ],
    "Web server": [
        ("host", "Bind address. Non-loopback needs an authenticated mode (see guard rules in README)."),
        ("port", "Listen port (1-65535)."),
        ("websites_port", "App Service container port; used when `PORT` is not set."),
        ("allowed_hosts", "Comma-separated Host allowlist (wildcards like `*.azurewebsites.net`). Required in prod; a bare `*` is refused."),
        ("forwarded_allow_ips", "Proxy IPs trusted for `X-Forwarded-*`. `*` only behind the App Service front end."),
    ],
    "Web authentication": [
        ("auth_mode", "`none` (dev only, loopback only) or `easyauth` (App Service Authentication + Entra app roles)."),
        ("auth_allowed_roles", "Comma-separated Entra app role values allowed to use the app, e.g. `PCH.Reader`. Exact, case-sensitive match."),
        ("auth_allow_any_authenticated", "Explicit opt-in: any signed-in user passes when no role allowlist is set."),
        ("website_auth_enabled", "Set by App Service when Authentication is on; do not set by hand. `easyauth` refuses to start unless it is `True`."),
        ("auth_easyauth_assume_enabled", "Local testing of `easyauth` only; refused in prod."),
        ("auth_none_allow_container_bind", "Dev only (docker compose): allow `AUTH_MODE=none` on `0.0.0.0`. Refused in prod."),
    ],
    "Operations": [
        ("log_format", "`text` or `json`. Unset: `json` when `APP_ENV=prod`, else `text`."),
        ("log_level", "`DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`."),
        ("applicationinsights_connection_string", "Enables Application Insights export (needs the `azure-monitor` extra). A secret: use a Key Vault reference."),
        ("uvicorn_access_log", "uvicorn access log (full URLs). Unset: off in prod, on otherwise."),
        ("graceful_shutdown_seconds", "Seconds uvicorn drains in-flight requests after SIGTERM (1-600). Keep below the platform stop window."),
        ("keep_alive_seconds", "Idle keep-alive of client connections (1-600). Keep above the front end's idle reuse window."),
        ("scan_timeout_minutes", "A scan running longer is cancelled and marked `failed` (reason `timeout`). Must be smaller than `SCAN_LOCK_STALE_MINUTES`."),
        ("health_ready_timeout_seconds", "Time budget of the `/health/ready` DB probe (0-30)."),
        ("health_ready_cache_seconds", "How long a readiness result is cached (0-300)."),
        ("retention_keep_scans", "Default `--keep` for `pch scans prune` (unset = no default)."),
        ("retention_max_age_days", "Default `--older-than` for `pch scans prune` (unset = no default)."),
        ("scan_stale_hours", "The dashboard shows a warning banner when the latest complete scan is older than this many hours (1-8760), or when the latest scan failed. Set it above your scan interval."),
    ],
}


def documented_fields() -> list[str]:
    return [name for rows in FIELD_DOCS.values() for name, _ in rows]


def env_name(field: str) -> str:
    return field.upper()


def render_default(field: str) -> str:
    info = Settings.model_fields[field]
    v: Any = info.default
    if info.default_factory is not None:
        v = info.default_factory()  # type: ignore[call-arg]
    if v is PydanticUndefined or v is None:
        return "(unset)"
    if isinstance(v, SecretStr):
        return "(empty)"
    if isinstance(v, bool):
        return "`true`" if v else "`false`"
    if isinstance(v, float) and v == int(v):
        v = int(v)
    if isinstance(v, dict):
        return "`{}`" if not v else f"`{v}`"
    if v == "":
        return "(empty)"
    return f"`{v}`"


def render_table() -> str:
    out = ["| Variable | Default | Description |", "|---|---|---|"]
    for group, rows in FIELD_DOCS.items():
        out.append(f"| **{group}** | | |")
        for name, desc in rows:
            out.append(f"| `{env_name(name)}` | {render_default(name)} | {desc.replace('|', '/')} |")
    return "\n".join(out)


def render_block() -> str:
    return f"{START}\n{render_table()}\n{END}"


def splice(text: str) -> str:
    """Replace the marked block in ``text`` (README) with a fresh one."""
    a, b = text.index(START), text.index(END) + len(END)
    return text[:a] + render_block() + text[b:]


def check_file(path: Path) -> bool:
    return path.read_text() == splice(path.read_text())
