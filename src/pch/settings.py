"""Runtime settings (env vars) plus the YAML config files (scope.yaml, policy.yaml)."""

from __future__ import annotations

import re
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from pch.model.findings import SEVERITY_WEIGHT, Severity


class ConfigError(Exception):
    """Raised for any invalid or unreadable configuration file.

    The message always names the file and, where applicable, the field path
    (``config/policy.yaml: waivers.0.expires: <reason>``). Input values are never included.
    """


def _clean_url(v: str) -> str:
    v = v.strip()
    if not v:
        return ""
    parts = urlsplit(v)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("must be an http(s) URL such as https://host")
    if parts.query or parts.fragment:
        raise ValueError("must not contain a query string or fragment")
    return v.rstrip("/")


class Settings(BaseSettings):
    """Environment-driven settings (env vars / .env). Secrets are SecretStr and never persisted.

    Fields are grouped by concern; later milestones add new groups rather than reshaping these.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- runtime profile
    app_env: Literal["dev", "test", "prod"] = "dev"

    # --- storage / paths
    database_url: str = Field("sqlite:///data/pch.db", repr=False)  # may embed a password: keep it out of repr(settings)
    data_dir: Path = Path("data")
    config_dir: Path = Path("config")

    # --- database engine / migrations (server DBs only for pool settings)
    # DB_AUTH=password: credentials are in DATABASE_URL. azure_ad: Azure SQL with an Entra access token
    # (managed identity / DefaultAzureCredential); needs the `azuresql` extra and an mssql+pyodbc URL.
    db_auth: Literal["password", "azure_ad"] = "password"
    db_pool_size: int = Field(5, ge=1, le=100)
    db_max_overflow: int = Field(10, ge=0, le=200)
    db_pool_recycle: int = Field(1800, ge=-1)  # seconds; Azure SQL drops idle connections after ~30 min
    db_pool_timeout: float = Field(30.0, gt=0, le=600)
    # Seconds to wait for a new server connection (psycopg ``connect_timeout``, pyodbc login ``timeout``). A hung DB must
    # not hold a request thread forever. Ignored for SQLite.
    db_connect_timeout_seconds: int = Field(15, ge=1, le=300)
    # Apply pending migrations automatically at startup. Off by default; sqlite in dev/test always
    # auto-migrates. In prod prefer `pch db upgrade` as an explicit deploy step.
    db_auto_migrate: bool = False
    # A scan lock (or a scan left `running`) older than this is considered abandoned.
    scan_lock_stale_minutes: int = Field(360, ge=1)

    # --- provider seams (see README "Providers")
    # SECRETS_PROVIDER: env = credential env vars above (default; App Service Key Vault references arrive this way);
    # file = one file per secret in SECRETS_DIR; azure_keyvault = read Key Vault with a managed identity.
    # Providers are never mixed: with file/azure_keyvault the credential env vars below are ignored.
    secrets_provider: Literal["env", "file", "azure_keyvault"] = "env"
    secrets_dir: Path | None = None
    keyvault_url: str = ""
    keyvault_secret_map: dict[str, str] = Field(default_factory=dict)  # env-style name -> vault secret name
    keyvault_cache_ttl_seconds: float = Field(300.0, ge=0, le=86400)
    # ARTIFACT_STORE: where the redacted raw scan cache (data/raw/<scan_id>) lives. azure_blob uses a managed
    # identity only (no account keys / connection strings / SAS).
    artifact_store: Literal["local", "azure_blob"] = "local"
    artifact_blob_account_url: str = ""
    artifact_blob_container: str = ""

    # --- Azure DevOps
    ado_org: str = ""
    ado_pat: SecretStr = SecretStr("")
    ado_base_url: str = "https://dev.azure.com"
    ado_vsrm_url: str = "https://vsrm.dev.azure.com"

    # --- GitHub (read-only reader, G2). GITHUB_AUTH=pat: GITHUB_TOKEN (fine-grained PAT, read-only). app: a GitHub App installation
    # (needs the `github-app` extra). GITHUB_API_URL is https://api.github.com or a GHES https://<host>/api/v3.
    github_api_url: str = "https://api.github.com"
    github_auth: Literal["pat", "app"] = "pat"
    github_token: SecretStr = SecretStr("")
    github_app_id: str = ""
    github_app_installation_id: str = ""
    github_app_private_key: SecretStr = SecretStr("")  # PEM; resolved through the secret provider like every credential

    # --- SonarQube
    sonar_url: str = ""
    sonar_token: SecretStr = SecretStr("")

    # --- Aikido
    aikido_url: str = "https://app.aikido.dev"
    aikido_client_id: str = ""
    aikido_client_secret: SecretStr = SecretStr("")

    # --- ServiceNow
    servicenow_url: str = ""
    servicenow_user: str = ""
    servicenow_password: SecretStr = SecretStr("")

    # --- collection tuning
    concurrency: int = Field(8, ge=1, le=64)
    http_timeout: float = Field(30.0, gt=0, le=300)
    # Upper bound for ONE upstream response body (MB). Larger responses are aborted while streaming and become a normal
    # collection error (the scan continues); Content-Length is checked up front.
    http_max_response_mb: int = Field(50, ge=1, le=2048)

    # --- lineage (L2): extra read-only lookups of the last deployment per stage; and the size limit of CSV/Excel exports
    lineage_enabled: bool = True
    lineage_deployments_top: int = Field(200, ge=10, le=1000)
    export_max_rows: int = Field(200_000, ge=1, le=5_000_000)

    # --- web server. Bind/auth policy is enforced by pch.web.guard.assert_safe_to_serve (fails closed).
    host: str = "127.0.0.1"
    port: int = Field(8000, ge=1, le=65535)  # env PORT (App Service sets PORT / WEBSITES_PORT for containers)
    websites_port: int | None = Field(None, ge=1, le=65535)  # env WEBSITES_PORT; used when PORT is not set
    # Comma-separated Host header allowlist (TrustedHost), e.g. "myapp.azurewebsites.net,*.azurewebsites.net".
    # Required (non-empty, no bare "*") when APP_ENV=prod.
    allowed_hosts: str = ""
    # Which proxy IPs may set X-Forwarded-*. "*" is acceptable on App Service only because the platform front end
    # is the sole ingress to the container. # VERIFY: App Service Linux custom containers are reachable only via the front end.
    forwarded_allow_ips: str = "127.0.0.1"

    # --- web authentication (see docs/DEPLOY_AZURE.md)
    # AUTH_MODE=none: dev only, loopback bind only. easyauth: App Service Authentication (Entra ID); the app reads
    # X-MS-CLIENT-PRINCIPAL and authorises by Entra app role.
    auth_mode: Literal["none", "easyauth"] = "none"
    auth_allowed_roles: str = ""  # comma-separated app roles, e.g. "PCH.Reader"
    auth_allow_any_authenticated: bool = False  # explicit opt-in to "any signed-in user" when no role allowlist is set
    # Easy Auth only strips/overwrites X-MS-* when it is enabled; the app refuses to start unless the platform says so.
    # # VERIFY: App Service exposes WEBSITE_AUTH_ENABLED=True to the container when Authentication is turned on.
    website_auth_enabled: str = ""  # env WEBSITE_AUTH_ENABLED (set by the platform; do not set by hand)
    auth_easyauth_assume_enabled: bool = False  # local testing only; forbidden when APP_ENV=prod
    auth_none_allow_container_bind: bool = False  # dev only: allow non-loopback bind for AUTH_MODE=none (docker compose)

    # --- operability (T6; see README "Operations")
    # LOG_FORMAT unset -> json when APP_ENV=prod, text otherwise.
    log_format: Literal["text", "json"] | None = None
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    # Optional Application Insights export (extra `azure-monitor`). A secret: it contains the instrumentation key.
    applicationinsights_connection_string: SecretStr = SecretStr("")
    # Uvicorn access log (full URLs incl. query strings): off in prod by default; the app writes its own structured
    # request line (method, path without query, status, duration, request id, hashed principal) in every environment.
    uvicorn_access_log: bool | None = None
    # SIGTERM -> uvicorn stops accepting, drains in-flight requests for at most this long, then exits.
    # # VERIFY: App Service Linux sends SIGTERM and waits ~30 s (WEBSITES_CONTAINER_STOP_TIME_LIMIT, max 1800) before SIGKILL.
    graceful_shutdown_seconds: int = Field(20, ge=1, le=600)
    # Idle keep-alive of client connections. Must exceed the front end's idle reuse window to avoid racing 502s.
    # # VERIFY: the App Service front end (ARR) idles upstream connections after ~230 s.
    keep_alive_seconds: int = Field(65, ge=1, le=600)
    # A scan running longer than this is cancelled, marked `failed` (reason `timeout`) and releases the scan lock.
    scan_timeout_minutes: int = Field(240, ge=1)
    # /health/ready: DB probe time budget and result cache (probe-storm protection).
    health_ready_timeout_seconds: float = Field(2.5, gt=0, le=30)
    health_ready_cache_seconds: float = Field(5.0, ge=0, le=300)
    # Retention defaults for `pch scans prune` (None = disabled): keep the newest N scans / delete older than D days.
    retention_keep_scans: int | None = Field(None, ge=1)
    retention_max_age_days: int | None = Field(None, ge=1)
    # Dashboard freshness: the header shows a warning when the latest complete scan is older than this (or the latest scan failed),
    # so a broken schedule is visible. Set it a little above the scan interval (daily schedule -> 36).
    scan_stale_hours: int = Field(36, ge=1, le=8760)

    @field_validator("log_format", "uvicorn_access_log", "retention_keep_scans", "retention_max_age_days", mode="before")
    @classmethod
    def _blank_is_unset(cls, v: Any) -> Any:
        return None if isinstance(v, str) and not v.strip() else v

    @field_validator("log_format", "log_level", mode="before")
    @classmethod
    def _lower_upper(cls, v: Any, info: Any) -> Any:
        if not isinstance(v, str):
            return v
        return v.strip().lower() if info.field_name == "log_format" else v.strip().upper()

    @field_validator(
        "ado_base_url", "ado_vsrm_url", "github_api_url", "sonar_url", "aikido_url", "servicenow_url", "keyvault_url", "artifact_blob_account_url"
    )
    @classmethod
    def _urls(cls, v: str) -> str:
        return _clean_url(v)

    @field_validator("github_app_id", "github_app_installation_id")
    @classmethod
    def _numeric_ids(cls, v: str) -> str:
        v = v.strip()
        if v and not v.isdigit():
            raise ValueError("must be the numeric id shown in the GitHub App settings")
        return v

    @model_validator(mode="after")
    def _provider_settings(self) -> Settings:
        if not self.github_api_url:
            raise ValueError("GITHUB_API_URL must not be empty (default https://api.github.com)")
        if self.secrets_provider == "file" and self.secrets_dir is None:
            raise ValueError("SECRETS_PROVIDER=file requires SECRETS_DIR")
        if self.secrets_provider == "azure_keyvault" and not self.keyvault_url:
            raise ValueError("SECRETS_PROVIDER=azure_keyvault requires KEYVAULT_URL")
        if self.artifact_store == "azure_blob" and not (self.artifact_blob_account_url and self.artifact_blob_container):
            raise ValueError("ARTIFACT_STORE=azure_blob requires ARTIFACT_BLOB_ACCOUNT_URL and ARTIFACT_BLOB_CONTAINER")
        for u in (self.keyvault_url, self.artifact_blob_account_url):
            if u and not u.startswith("https://"):
                raise ValueError("Azure endpoints must be https:// URLs")
        if self.is_prod:
            # Credentials travel to these hosts: never in clear text in prod.
            plain = [
                name
                for name, u in (
                    ("ADO_BASE_URL", self.ado_base_url),
                    ("ADO_VSRM_URL", self.ado_vsrm_url),
                    ("GITHUB_API_URL", self.github_api_url),
                    ("SONAR_URL", self.sonar_url),
                    ("AIKIDO_URL", self.aikido_url),
                    ("SERVICENOW_URL", self.servicenow_url),
                    ("KEYVAULT_URL", self.keyvault_url),
                    ("ARTIFACT_BLOB_ACCOUNT_URL", self.artifact_blob_account_url),
                )
                if u and not u.startswith("https://")
            ]
            if plain:
                raise ValueError(f"APP_ENV=prod requires https:// for: {', '.join(plain)}")
        if self.scan_timeout_minutes >= self.scan_lock_stale_minutes:
            # Otherwise a second scan could take over the lock of a scan that is still legitimately running.
            raise ValueError("SCAN_TIMEOUT_MINUTES must be smaller than SCAN_LOCK_STALE_MINUTES")
        return self

    @property
    def effective_port(self) -> int:
        """PORT if set, else WEBSITES_PORT, else 8000."""
        if "port" not in self.model_fields_set and self.websites_port:
            return self.websites_port
        return self.port

    @property
    def allowed_roles(self) -> list[str]:
        return [r.strip() for r in self.auth_allowed_roles.split(",") if r.strip()]

    @property
    def allowed_host_list(self) -> list[str]:
        return [h.strip().lower() for h in self.allowed_hosts.split(",") if h.strip()]

    @property
    def easyauth_platform_enabled(self) -> bool:
        return self.website_auth_enabled.strip().lower() == "true"

    @property
    def access_log_enabled(self) -> bool:
        return (not self.is_prod) if self.uvicorn_access_log is None else self.uvicorn_access_log

    @property
    def is_prod(self) -> bool:
        return self.app_env == "prod"

    @property
    def is_dev(self) -> bool:
        return self.app_env == "dev"

    @property
    def is_test(self) -> bool:
        return self.app_env == "test"

    def source_requirements(self, include_secrets: bool = True) -> dict[str, dict[str, bool]]:
        """Per configured source: required field/env var -> is it non-empty. Never exposes values.

        ``include_secrets=False`` leaves out the credential fields (and ignores them when deciding whether a source
        is configured); used when credentials come from a SecretProvider other than ``env``.
        """

        def s(x: SecretStr) -> bool:
            return bool(x.get_secret_value())

        groups: dict[str, dict[str, bool]] = {
            "ado": {"ADO_ORG": bool(self.ado_org), "ADO_PAT": s(self.ado_pat)},
            "github": (
                {"GITHUB_APP_ID": bool(self.github_app_id), "GITHUB_APP_INSTALLATION_ID": bool(self.github_app_installation_id),
                 "GITHUB_APP_PRIVATE_KEY": s(self.github_app_private_key)}
                if self.github_auth == "app" else {"GITHUB_TOKEN": s(self.github_token)}
            ),
            "sonar": {"SONAR_URL": bool(self.sonar_url), "SONAR_TOKEN": s(self.sonar_token)},
            "aikido": {"AIKIDO_CLIENT_ID": bool(self.aikido_client_id), "AIKIDO_CLIENT_SECRET": s(self.aikido_client_secret)},
            "servicenow": {"SERVICENOW_URL": bool(self.servicenow_url), "SERVICENOW_USER": bool(self.servicenow_user), "SERVICENOW_PASSWORD": s(self.servicenow_password)},
        }
        if not include_secrets:
            from pch.providers.secrets import SOURCE_SECRETS

            groups = {k: {f: ok for f, ok in v.items() if f not in SOURCE_SECRETS[k]} for k, v in groups.items()}
        # A source counts as configured as soon as any of its credential fields is provided.
        return {k: v for k, v in groups.items() if any(v.values())}


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings() -> None:
    """Drop the cached Settings (tests, or after changing the environment)."""
    get_settings.cache_clear()


class _Strict(BaseModel):
    """Base for YAML models: unknown keys are errors (typos must not silently disable policy)."""

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- scope.yaml


class RepoOverride(_Strict):
    project: str
    repo: str
    sonar_key: str | None = None
    aikido_repo: str | None = None
    owner: str | None = None
    servicenow_ci: str | None = None
    coverage_threshold: float | None = None
    env_tiers: dict[str, str] = Field(default_factory=dict)


CODE_HOSTS = ("github", "github_enterprise", "azure_repos", "other_git")
CodeHost = Literal["github", "github_enterprise", "azure_repos", "other_git"]


def _default_code_hosts() -> list[CodeHost]:
    return ["github"]


_GH_ORG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")


class GitHubScope(_Strict):
    """``scope.yaml`` ``github:``. Used only when a GitHub reader is configured (GITHUB_TOKEN or a GitHub App).

    The org listing is filtered by these keys; repos that ADO pipelines reference or that ``repos:`` names are always scanned
    (``exclude_repos`` still removes any repo). ``include``/``exclude`` are case-insensitive globs on ``repo`` or ``org/repo``.
    """

    orgs: list[str] = Field(default_factory=list)  # GitHub organisations whose repositories are listed (GET /orgs/{org}/repos)
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    topics_any: list[str] = Field(default_factory=list)  # keep repos that have at least one of these topics (empty = no topic filter)
    include_archived: bool = False
    include_forks: bool = False

    @field_validator("orgs")
    @classmethod
    def _orgs(cls, v: list[str]) -> list[str]:
        bad = [o for o in v if not _GH_ORG.match(o)]
        if bad:
            raise ValueError("must be GitHub organisation logins (letters, digits, hyphens)")
        return list(dict.fromkeys(v))


class Scope(_Strict):
    organization: str = ""
    # Where the code lives. GitHub is the default; Azure Repos stays available (template reuse) but is OFF unless listed:
    # then `_apis/git/repositories` is not called and pipelines/releases sourced from a host that is not listed are out of scope.
    code_hosts: list[CodeHost] = Field(default_factory=_default_code_hosts)
    projects: list[str] = Field(default_factory=list)
    repos: list[RepoOverride] = Field(default_factory=list)
    env_tiers: dict[str, str] = Field(default_factory=dict)  # stage/environment name -> tier
    exclude_repos: list[str] = Field(default_factory=list)
    github: GitHubScope = Field(default_factory=GitHubScope)

    @field_validator("code_hosts")
    @classmethod
    def _hosts(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError(f"must list at least one of: {', '.join(CODE_HOSTS)}")
        return list(dict.fromkeys(v))

    def hosts(self) -> set[str]:
        return set(self.code_hosts)

    def override_for(self, project: str, repo: str) -> RepoOverride | None:
        for r in self.repos:
            if r.project == project and r.repo.casefold() == repo.casefold():  # GitHub names are case-insensitive
                return r
        return None


# --------------------------------------------------------------- policy.yaml


class Waiver(_Strict):
    rule: str
    repo: str
    reason: str = ""
    owner: str = ""
    expires: date | None = None


class AikidoSla(_Strict):
    critical: int = 7
    high: int = 30
    medium: int = 90
    low: int = 180


def param_type_ok(default: Any, value: Any) -> bool:
    """A rule param must have the type of its registry default (bool is not an int; a list holds the default's element type)."""
    if isinstance(default, bool):
        return isinstance(value, bool)
    if isinstance(default, int):
        return isinstance(value, int) and not isinstance(value, bool)
    if isinstance(default, float):
        return isinstance(value, int | float) and not isinstance(value, bool)
    if isinstance(default, str):
        return isinstance(value, str)
    if isinstance(default, list):
        elem = type(default[0]) if default else str
        return isinstance(value, list) and all(isinstance(x, elem) and not isinstance(x, bool) for x in value)
    return isinstance(value, type(default))


class RuleOverride(_Strict):
    """``policy.yaml`` ``rules: {RULE-ID: {enabled, severity, params}}``: tune a rule without touching code."""

    enabled: bool = True
    severity: Severity | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class ScoringConfig(_Strict):
    """``policy.yaml`` ``scoring:``. Defaults reproduce the built-in scoring (severity weights 10/5/3/1/0, categories equal, WARN half credit)."""

    severity_weights: dict[Severity, float] = Field(default_factory=dict)  # partial: unlisted severities keep their default
    category_weights: dict[str, float] = Field(default_factory=dict)  # multiplier per rule category (SRC, QLT, ...), default 1
    warn_credit: float = Field(0.5, ge=0, le=1)

    @field_validator("severity_weights", "category_weights")
    @classmethod
    def _non_negative(cls, v: dict[Any, float]) -> dict[Any, float]:
        bad = [str(k) for k, w in v.items() if w < 0]
        if bad:
            raise ValueError("weights must be >= 0: " + ", ".join(bad))
        return v

    @field_validator("category_weights")
    @classmethod
    def _known_categories(cls, v: dict[str, float]) -> dict[str, float]:
        from pch.engine.registry import CATEGORY_NAMES

        unknown = sorted(set(v) - set(CATEGORY_NAMES))
        if unknown:
            raise ValueError(f"unknown rule categories {unknown} (known: {', '.join(CATEGORY_NAMES)})")
        return v

    def severity_weight(self, sev: Severity) -> float:
        return float(self.severity_weights.get(sev, SEVERITY_WEIGHT[sev]))

    def category_weight(self, category: str) -> float:
        return float(self.category_weights.get(category, 1.0))


class Policy(_Strict):
    coverage_threshold: float = 80.0
    sonar_staleness_days: int = 14
    sonar_quality_gate_name: str = "Sonar way"
    min_reviewers: int = 2
    aikido_sla_days: AikidoSla = Field(default_factory=AikidoSla)
    prod_retention_days: int = 365
    stale_pipeline_days: int = 90
    min_success_rate: float = 0.8
    marketplace_task_allowlist: list[str] = Field(default_factory=list)
    approved_registries: list[str] = Field(default_factory=list)
    approved_branches: list[str] = Field(default_factory=lambda: ["main", "master", "release/*", "releases/*"])
    waivers: list[Waiver] = Field(default_factory=list)
    smoke_check_required_tiers: list[str] = Field(default_factory=lambda: ["test", "uat", "prod"])
    compliant_score_threshold: float = 80.0
    rules: dict[str, RuleOverride] = Field(default_factory=dict)  # per-rule enabled / severity / params
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)

    @field_validator("rules")
    @classmethod
    def _known_rules(cls, v: dict[str, RuleOverride]) -> dict[str, RuleOverride]:
        """Unknown rule ids / params and wrongly typed params are errors that name their path (``rules.DEP-001.params.x``)."""
        if not v:
            return v
        from pch.engine.registry import all_rules

        known = {r.id: r for r in all_rules()}
        errs: list[str] = []
        for rid, ov in v.items():
            meta = known.get(rid)
            if meta is None:
                errs.append(f"@rules.{rid}: unknown rule id (run `pch rules list`)")
                continue
            for k, val in ov.params.items():
                path = f"@rules.{rid}.params.{k}"
                if k not in meta.params:
                    errs.append(f"{path}: unknown param (this rule's params: {', '.join(sorted(meta.params)) or 'none'})")
                elif not param_type_ok(meta.params[k], val):
                    errs.append(f"{path}: expected {type(meta.params[k]).__name__} like the default")
                elif k.endswith("_pattern"):
                    try:
                        re.compile(val)
                    except re.error as exc:
                        errs.append(f"{path}: invalid regular expression ({exc.msg})")
        if errs:
            raise ValueError("\n".join(errs))
        return v


def format_validation_error(label: str, exc: ValidationError) -> str:
    """``label: a.b.0.c: message`` per error. Uses only loc + msg so input values never leak."""
    parts: list[str] = []
    for e in exc.errors(include_input=False, include_url=False):
        msg = e["msg"].removeprefix("Value error, ")
        if msg.startswith("@"):  # a validator that reports full paths itself ("@rules.X: ..." per line)
            parts.extend(f"{label}: {line[1:]}" for line in msg.splitlines() if line.startswith("@"))
            continue
        loc = ".".join(str(x) for x in e["loc"]) or "(root)"
        parts.append(f"{label}: {loc}: {e['msg']}")
    return "; ".join(parts)


def _load_yaml(path: Path, *, required: bool = False) -> dict[str, Any]:
    if not path.exists():
        if required:
            raise ConfigError(f"{path}: file not found (required when APP_ENV=prod)")
        return {}
    try:
        with path.open() as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark is not None else ""
        raise ConfigError(f"{path}: invalid YAML{where}") from None
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read file ({exc.strerror})") from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping of keys to values")
    return data


def load_scope(path: Path | str = "config/scope.yaml", *, required: bool | None = None) -> Scope:
    """Load scope.yaml. Missing file -> defaults, except in prod (or ``required=True``) where it is an error."""
    p = Path(path)
    if required is None:
        required = get_settings().is_prod
    try:
        return Scope.model_validate(_load_yaml(p, required=required))
    except ValidationError as exc:
        raise ConfigError(format_validation_error(str(p), exc)) from None


def resolve_ado_org(settings: Settings, scope: Scope | None) -> tuple[str, str]:
    """The Azure DevOps organisation and where it came from: ``ADO_ORG``, else ``scope.yaml`` ``organization``, else ``("", "not set")``.

    Both set and different is a ConfigError (never silently pick one). Names are compared case-insensitively (ADO org names are)."""
    env_org = settings.ado_org.strip()
    scope_org = (scope.organization if scope else "").strip()
    if env_org and scope_org and env_org.casefold() != scope_org.casefold():
        raise ConfigError(f"Azure DevOps organization conflict: ADO_ORG={env_org!r} but scope.yaml organization={scope_org!r}. Set only one, or make them equal.")
    if env_org:
        return env_org, "ADO_ORG"
    if scope_org:
        return scope_org, "scope.yaml organization"
    return "", "not set"


def load_policy(path: Path | str = "config/policy.yaml") -> Policy:
    p = Path(path)
    try:
        return Policy.model_validate(_load_yaml(p))
    except ValidationError as exc:
        raise ConfigError(format_validation_error(str(p), exc)) from None
