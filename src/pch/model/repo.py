"""Repo-level facts: what is in the repo, test state, policies and external tool state."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from pch.model.pipeline import Pipeline
from pch.timeutil import utcnow_naive


class TestState(StrEnum):
    __test__ = False  # not a pytest class

    TESTS_OK = "TESTS_OK"
    TESTS_LOW_COVERAGE = "TESTS_LOW_COVERAGE"
    TESTS_NOT_RUN = "TESTS_NOT_RUN"
    TESTS_NO_COVERAGE = "TESTS_NO_COVERAGE"
    NO_TESTS = "NO_TESTS"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"  # repo contents unavailable (externally hosted repo, no reader) and no pipeline proves tests run


RepoKind = Literal["application", "adf", "synapse", "iac", "sql", "docs"]
RepoProvider = Literal["azure_repos", "github", "github_enterprise", "other_git"]
PROVIDER_LABEL: dict[str, str] = {"azure_repos": "Azure Repos", "github": "GitHub", "github_enterprise": "GitHub Enterprise", "other_git": "Other Git"}
FactsSource = Literal["ado_items", "unavailable"]  # where RepoFacts came from; a future reader adds its own value


def unavailable_reason(provider: str) -> str:
    """Why repo-level facts are missing for an externally hosted repo (shown on UNKNOWN findings)."""
    if provider in ("github", "github_enterprise"):
        return "GitHub-hosted: repository contents/branch protection need the GitHub reader (not configured)"
    return "externally hosted (not Azure Repos): repository contents/branch protection need a reader for that host (not configured)"


class RepoRef(BaseModel):
    id: str
    name: str
    project: str
    url: str = ""
    default_branch: str = "main"
    owner: str | None = None
    sonar_key: str | None = None
    aikido_repo: str | None = None
    servicenow_ci: str | None = None
    coverage_threshold: float | None = None
    disabled: bool = False
    # Hosting. For externally hosted code (built by Azure DevOps pipelines) `name` is the full name ("org/repo").
    provider: RepoProvider = "azure_repos"
    full_name: str = ""
    service_connection_id: str | None = None

    @property
    def key(self) -> str:
        return f"{self.project}/{self.name}"

    @property
    def external(self) -> bool:
        return self.provider != "azure_repos"

    @property
    def short_name(self) -> str:
        return self.name.rsplit("/", 1)[-1]


class RepoFacts(BaseModel):
    languages: list[str] = Field(default_factory=list)
    kind: RepoKind = "application"
    has_app_code: bool = True
    tests_detected: bool = False
    test_signals: list[str] = Field(default_factory=list)
    iac: list[str] = Field(default_factory=list)  # bicep, terraform, arm
    dockerfiles: list[str] = Field(default_factory=list)
    k8s_manifests: bool = False
    helm_chart: bool = False
    adf: bool = False
    synapse: bool = False
    sql_project: bool = False
    codeowners: bool = False
    pipeline_files: list[str] = Field(default_factory=list)
    file_count: int = 0
    test_state: TestState = TestState.NOT_APPLICABLE
    test_state_reason: str = ""
    coverage: float | None = None
    # "unavailable" = nothing was read from the repository (empty defaults mean "not collected", NOT "collected and empty")
    facts_source: FactsSource = "ado_items"
    facts_reason: str = ""


class BranchPolicies(BaseModel):
    """Policies on the default branch."""

    available: bool = False
    unavailable_reason: str = ""  # why `available` is False, when known (e.g. externally hosted repo)
    min_reviewers: int | None = None
    creator_vote_counts: bool | None = None
    reset_on_push: bool | None = None
    build_validation: bool = False
    work_item_required: bool = False
    comment_resolution_required: bool = False
    required_reviewer_paths: list[str] = Field(default_factory=list)  # file patterns covered by required reviewers


class ServiceConnection(BaseModel):
    id: str
    name: str
    type: str = ""
    auth_scheme: str = ""  # WorkloadIdentityFederation | ServicePrincipal | PublishProfile | ...
    scope_level: str = ""  # ResourceGroup | Subscription | ManagementGroup | ""
    all_pipelines_authorized: bool | None = None
    federated: bool = False


class VariableGroup(BaseModel):
    id: str
    name: str
    key_vault_linked: bool = False
    has_secrets: bool = False  # any variable is marked secret (values are never read)


class Environment(BaseModel):
    id: str
    name: str
    checks: list[dict[str, Any]] = Field(default_factory=list)


class SonarFacts(BaseModel):
    onboarded: bool = False
    key: str | None = None
    gate_status: str | None = None  # OK | ERROR | WARN | NONE
    gate_name: str | None = None
    coverage: float | None = None
    new_coverage: float | None = None
    bugs: int | None = None
    vulnerabilities: int | None = None
    hotspots: int | None = None
    code_smells: int | None = None
    duplication: float | None = None
    last_analysis: datetime | None = None
    url: str | None = None


class AikidoIssue(BaseModel):
    id: str
    severity: str
    first_detected: datetime
    type: str = ""


class AikidoFacts(BaseModel):
    onboarded: bool = False
    repo_id: str | None = None
    open_issues: list[AikidoIssue] = Field(default_factory=list)
    url: str | None = None

    def count(self, severity: str) -> int:
        return sum(1 for i in self.open_issues if i.severity == severity)


class ChangeRequest(BaseModel):
    number: str
    state: str = ""
    approval: str = ""
    start_date: datetime | None = None
    end_date: datetime | None = None
    ci: str | None = None
    short_description: str = ""


class SnowFacts(BaseModel):
    available: bool = False
    changes: dict[str, ChangeRequest] = Field(default_factory=dict)
    ci_changes: list[ChangeRequest] = Field(default_factory=list)


class RepoContext(BaseModel):
    """Everything the rule engine needs to evaluate one repo."""

    repo: RepoRef
    pipelines: list[Pipeline] = Field(default_factory=list)
    facts: RepoFacts = Field(default_factory=RepoFacts)
    policies: BranchPolicies = Field(default_factory=BranchPolicies)
    sonar: SonarFacts | None = None
    aikido: AikidoFacts | None = None
    snow: SnowFacts = Field(default_factory=SnowFacts)
    service_connections: dict[str, ServiceConnection] = Field(default_factory=dict)
    variable_groups: dict[str, VariableGroup] = Field(default_factory=dict)
    environments: dict[str, Environment] = Field(default_factory=dict)
    now: datetime = Field(default_factory=utcnow_naive)

    def build_pipelines(self) -> list[Pipeline]:
        return [p for p in self.pipelines if p.platform != "ado_classic_release"]

    def release_pipelines(self) -> list[Pipeline]:
        return [p for p in self.pipelines if p.platform == "ado_classic_release"]
