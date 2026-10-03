"""Canonical pipeline model shared by every platform (ADO classic/YAML, later GitHub Actions)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Platform = Literal["ado_classic_build", "ado_classic_release", "ado_yaml", "gha"]
EnvTier = Literal["dev", "test", "uat", "prod", "unknown"]
TARGETS = ("functionapp", "webapp", "aks", "adf", "synapse", "sql", "iac", "other")


class Variable(BaseModel):
    """A pipeline variable. The VALUE is never stored, only a reason it looks secret."""

    name: str
    is_secret: bool = False
    secret_like_reason: str | None = None  # e.g. "name matches secret pattern"
    source: str = "pipeline"  # pipeline | stage | release


class VariableGroupRef(BaseModel):
    id: str | None = None
    name: str
    key_vault_linked: bool | None = None  # filled in from variable-group collector
    scope: str | None = None  # stage name when group is scoped to a stage


class Step(BaseModel):
    id: str
    name: str
    task: str | None = None  # "AzureFunctionApp@2", "actions/checkout@<sha>", "script"
    task_version: str | None = None
    inputs: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    continue_on_error: bool = False
    condition: str | None = None
    capabilities: set[str] = Field(default_factory=set)
    heuristic_caps: set[str] = Field(default_factory=set)  # caps inferred from scripts/names
    inline_script: str | None = None
    marketplace: bool = False
    deprecated: bool = False

    @property
    def always_false(self) -> bool:
        return bool(self.condition and _ALWAYS_FALSE.match(self.condition))

    @property
    def effective(self) -> bool:
        """The step really runs and its failure fails the build."""
        return self.enabled and not self.continue_on_error and not self.always_false


_ALWAYS_FALSE = re.compile(
    r"^\s*(false|ne\(\s*true\s*,\s*true\s*\)|eq\(\s*(true\s*,\s*false|false\s*,\s*true|0\s*,\s*1|1\s*,\s*0|1\s*,\s*2|2\s*,\s*1)\s*\))\s*$",
    re.I,
)


class Approval(BaseModel):
    kind: Literal["manual", "servicenow", "gate", "branch_control", "business_hours", "other"]
    approvers: list[str] = Field(default_factory=list)
    min_approvers: int | None = None
    requester_can_approve: bool | None = None
    timeout_minutes: int | None = None
    branches: list[str] = Field(default_factory=list)  # for branch_control checks
    name: str | None = None


class Job(BaseModel):
    name: str
    kind: Literal["job", "deployment", "phase"] = "job"
    pool: str | None = None
    self_hosted: bool | None = None
    steps: list[Step] = Field(default_factory=list)


class Stage(BaseModel):
    name: str
    env_name: str | None = None
    env_tier: EnvTier = "unknown"
    depends_on: list[str] = Field(default_factory=list)
    jobs: list[Job] = Field(default_factory=list)
    pre_approvals: list[Approval] = Field(default_factory=list)
    post_approvals: list[Approval] = Field(default_factory=list)
    gates: list[Approval] = Field(default_factory=list)
    deploy_targets: set[str] = Field(default_factory=set)
    service_connections: list[str] = Field(default_factory=list)
    branch_filters: list[str] = Field(default_factory=list)
    retention_days: int | None = None
    is_deploy: bool = False

    def steps(self) -> list[Step]:
        return [s for j in self.jobs for s in j.steps]

    def capabilities(self, enabled_only: bool = True) -> set[str]:
        caps: set[str] = set()
        for s in self.steps():
            if s.enabled or not enabled_only:
                caps |= s.capabilities
        return caps


class RunSummary(BaseModel):
    status: str
    finished: datetime | None = None
    branch: str | None = None
    url: str | None = None


class RunStats(BaseModel):
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    last_success: datetime | None = None

    @property
    def success_rate(self) -> float | None:
        return self.succeeded / self.total if self.total else None


class DeploymentRecord(BaseModel):
    """A past run/deployment to a stage, used for DEP-005 (ServiceNow CRQ correlation)."""

    id: str
    stage_name: str
    env_tier: EnvTier = "unknown"
    completed_at: datetime | None = None
    status: str = "unknown"
    change_refs: list[str] = Field(default_factory=list)
    requested_by: str | None = None


class Pipeline(BaseModel):
    platform: Platform
    id: str
    name: str
    project: str
    repo: str | None = None
    repo_id: str | None = None
    url: str = ""
    definition_in_source_control: bool = False
    triggers: dict[str, Any] = Field(default_factory=dict)
    variables: list[Variable] = Field(default_factory=list)
    variable_groups: list[VariableGroupRef] = Field(default_factory=list)
    stages: list[Stage] = Field(default_factory=list)
    linked_build_ids: list[str] = Field(default_factory=list)
    last_run: RunSummary | None = None
    run_stats_90d: RunStats | None = None
    deployments_90d: list[DeploymentRecord] = Field(default_factory=list)
    retention_days: int | None = None
    owner: str | None = None
    pool_type: Literal["hosted", "self-hosted", "mixed", "unknown"] = "unknown"
    uses_task_groups: bool = False
    uses_deployment_groups: bool = False
    artifact_branch_filters: list[str] = Field(default_factory=list)
    raw_ref: str = ""
    notes: list[str] = Field(default_factory=list)

    def all_steps(self) -> list[Step]:
        return [s for st in self.stages for s in st.steps()]

    def capabilities(self, enabled_only: bool = True) -> set[str]:
        caps: set[str] = set()
        for st in self.stages:
            caps |= st.capabilities(enabled_only)
        return caps

    def stage(self, name: str) -> Stage | None:
        return next((s for s in self.stages if s.name == name), None)

    @property
    def is_classic(self) -> bool:
        return self.platform in ("ado_classic_build", "ado_classic_release")

    @property
    def deploy_targets(self) -> set[str]:
        out: set[str] = set()
        for s in self.stages:
            out |= s.deploy_targets
        return out
