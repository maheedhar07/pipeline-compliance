"""Runtime settings (env vars) plus the YAML config files (scope.yaml, policy.yaml)."""

from __future__ import annotations

from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    database_url: str = "sqlite:///data/pch.db"
    data_dir: Path = Path("data")
    config_dir: Path = Path("config")

    # --- Azure DevOps
    ado_org: str = ""
    ado_pat: SecretStr = SecretStr("")
    ado_base_url: str = "https://dev.azure.com"
    ado_vsrm_url: str = "https://vsrm.dev.azure.com"

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

    # --- web server (non-loopback bind policy is enforced in T5)
    host: str = "127.0.0.1"
    port: int = Field(8000, ge=1, le=65535)

    @field_validator("ado_base_url", "ado_vsrm_url", "sonar_url", "aikido_url", "servicenow_url")
    @classmethod
    def _urls(cls, v: str) -> str:
        return _clean_url(v)

    @property
    def is_prod(self) -> bool:
        return self.app_env == "prod"

    @property
    def is_dev(self) -> bool:
        return self.app_env == "dev"

    @property
    def is_test(self) -> bool:
        return self.app_env == "test"

    def source_requirements(self) -> dict[str, dict[str, bool]]:
        """Per configured source: required credential env var -> is it non-empty. Never exposes values."""

        def s(x: SecretStr) -> bool:
            return bool(x.get_secret_value())

        groups: dict[str, dict[str, bool]] = {
            "ado": {"ADO_ORG": bool(self.ado_org), "ADO_PAT": s(self.ado_pat)},
            "sonar": {"SONAR_URL": bool(self.sonar_url), "SONAR_TOKEN": s(self.sonar_token)},
            "aikido": {"AIKIDO_CLIENT_ID": bool(self.aikido_client_id), "AIKIDO_CLIENT_SECRET": s(self.aikido_client_secret)},
            "servicenow": {"SERVICENOW_URL": bool(self.servicenow_url), "SERVICENOW_USER": bool(self.servicenow_user), "SERVICENOW_PASSWORD": s(self.servicenow_password)},
        }
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


class Scope(_Strict):
    organization: str = ""
    projects: list[str] = Field(default_factory=list)
    repos: list[RepoOverride] = Field(default_factory=list)
    env_tiers: dict[str, str] = Field(default_factory=dict)  # stage/environment name -> tier
    exclude_repos: list[str] = Field(default_factory=list)

    def override_for(self, project: str, repo: str) -> RepoOverride | None:
        for r in self.repos:
            if r.project == project and r.repo == repo:
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


def format_validation_error(label: str, exc: ValidationError) -> str:
    """``label: a.b.0.c: message`` per error. Uses only loc + msg so input values never leak."""
    parts = []
    for e in exc.errors(include_input=False, include_url=False):
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


def load_policy(path: Path | str = "config/policy.yaml") -> Policy:
    p = Path(path)
    try:
        return Policy.model_validate(_load_yaml(p))
    except ValidationError as exc:
        raise ConfigError(format_validation_error(str(p), exc)) from None
