"""Runtime settings (env vars) plus the YAML config files (scope.yaml, policy.yaml)."""

from __future__ import annotations

from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven settings. Secrets are SecretStr and never persisted."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "sqlite:///data/pch.db"
    data_dir: Path = Path("data")
    config_dir: Path = Path("config")

    ado_org: str = ""
    ado_pat: SecretStr = SecretStr("")
    ado_base_url: str = "https://dev.azure.com"
    ado_vsrm_url: str = "https://vsrm.dev.azure.com"

    sonar_url: str = ""
    sonar_token: SecretStr = SecretStr("")

    aikido_url: str = "https://app.aikido.dev"
    aikido_client_id: str = ""
    aikido_client_secret: SecretStr = SecretStr("")

    servicenow_url: str = ""
    servicenow_user: str = ""
    servicenow_password: SecretStr = SecretStr("")

    concurrency: int = 8
    http_timeout: float = 30.0
    host: str = "127.0.0.1"
    port: int = 8000


@lru_cache
def get_settings() -> Settings:
    return Settings()


# ---------------------------------------------------------------- scope.yaml


class RepoOverride(BaseModel):
    project: str
    repo: str
    sonar_key: str | None = None
    aikido_repo: str | None = None
    owner: str | None = None
    servicenow_ci: str | None = None
    coverage_threshold: float | None = None
    env_tiers: dict[str, str] = Field(default_factory=dict)


class Scope(BaseModel):
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


class Waiver(BaseModel):
    rule: str
    repo: str
    reason: str = ""
    owner: str = ""
    expires: date | None = None


class AikidoSla(BaseModel):
    critical: int = 7
    high: int = 30
    medium: int = 90
    low: int = 180


class Policy(BaseModel):
    coverage_threshold: float = 80.0
    sonar_staleness_days: int = 14
    sonar_quality_gate_name: str = "Company Way"
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


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open() as fh:
        return yaml.safe_load(fh) or {}


def load_scope(path: Path | str = "config/scope.yaml") -> Scope:
    return Scope.model_validate(_load_yaml(Path(path)))


def load_policy(path: Path | str = "config/policy.yaml") -> Policy:
    return Policy.model_validate(_load_yaml(Path(path)))
