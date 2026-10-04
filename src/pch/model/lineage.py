"""Lineage model: what comes out of a repository, per scan (L2).

repo -> CI/build pipelines (YAML or classic) -> downstream pipelines -> releases (classic definitions or YAML
deployment stages) -> stages in order -> last deployment per stage.

Everything here is a plain description of data the scanner already collected plus a few read-only deployment
lookups. PII is minimised on purpose: people appear ONLY as the display name of whoever triggered the last
deployment (never an email/UPN/id), approvers are summarised as counts/kinds, never named.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

DeployStatus = Literal["succeeded", "partial", "failed", "in_progress", "pending", "canceled", "never", "unknown"]
DEPLOY_STATUS_LABEL: dict[str, str] = {
    "succeeded": "succeeded", "partial": "partially succeeded", "failed": "failed", "in_progress": "in progress", "pending": "pending approval/queued",
    "canceled": "canceled", "never": "never deployed", "unknown": "unknown (not collected)",
}
KINDS_PIPELINE = ("yaml", "classic_build")


class LDeploy(BaseModel):
    """Last deployment of a stage/environment. ``unknown`` = could not be collected; ``never`` = collected, none found."""

    status: DeployStatus = "unknown"
    version: str | None = None  # classic: release name; YAML: run number
    artifact_version: str | None = None  # build number / short commit SHA of the deployed artifact
    finished: datetime | None = None  # completion time, else start time (naive UTC)
    triggered_by: str | None = None  # DISPLAY NAME only (never email/UPN)
    url: str | None = None
    note: str | None = None


class LTarget(BaseModel):
    kind: str  # functionapp | webapp | aks | adf | synapse | sql | iac | other
    name: str | None = None  # resource name extracted from task inputs (may contain $(variables))
    detail: str | None = None  # resource group / namespace / workspace / server ...

    def label(self) -> str:
        bits = [self.name] if self.name else []
        if self.detail:
            bits.append(f"({self.detail})")
        return f"{self.kind}: {' '.join(bits)}" if bits else self.kind


class LStage(BaseModel):
    name: str
    env_name: str | None = None
    env_tier: str = "unknown"
    depends_on: list[str] = Field(default_factory=list)
    targets: list[LTarget] = Field(default_factory=list)
    service_connections: list[str] = Field(default_factory=list)
    approvals: list[str] = Field(default_factory=list)  # summaries only, e.g. "manual approval (min 1)"
    gates: list[str] = Field(default_factory=list)
    branch_filters: list[str] = Field(default_factory=list)
    last_deploy: LDeploy = Field(default_factory=LDeploy)


class LTrigger(BaseModel):
    ci_enabled: bool | None = None  # None = not determinable
    ci_branches: list[str] = Field(default_factory=list)
    ci_paths: list[str] = Field(default_factory=list)
    pr_enabled: bool | None = None
    pr_branches: list[str] = Field(default_factory=list)
    schedules: list[str] = Field(default_factory=list)

    def ci_summary(self) -> str:
        if self.ci_enabled is False:
            return "CI off"
        if not self.ci_enabled and not self.ci_branches:
            return ""
        s = ", ".join(self.ci_branches) or "all branches"
        return f"{s}" + (f" (paths: {', '.join(self.ci_paths)})" if self.ci_paths else "")

    def pr_summary(self) -> str:
        if self.pr_enabled is False:
            return "PR off"
        if not self.pr_enabled:
            return ""
        return ", ".join(self.pr_branches) or "all branches"


class LLink(BaseModel):
    """A pipeline-to-pipeline edge (upstream: what this consumes; downstream: who consumes this)."""

    kind: Literal["yaml_resource", "classic_completion"]
    name: str
    pipeline_id: str | None = None
    project: str | None = None
    repo_key: str | None = None
    url: str = ""
    detail: str = ""  # e.g. "trigger on main"


class LPipeline(BaseModel):
    id: str
    name: str
    kind: Literal["yaml", "classic_build"]
    url: str = ""
    definition_path: str = ""  # YAML file name, or the classic folder path
    yaml_repo: str | None = None  # where the YAML file lives (YAML only)
    code_repos: list[str] = Field(default_factory=list)  # repos whose code it builds (checkout steps)
    template_repos: list[str] = Field(default_factory=list)  # other repositories declared in resources.repositories
    yaml_in_other_repo: bool = False  # YAML lives in a different repo than the code
    adopted_from: str | None = None  # repo key that defines this pipeline (it builds THIS repo's code from there)
    trigger: LTrigger = Field(default_factory=LTrigger)
    artifacts: list[str] = Field(default_factory=list)
    upstream: list[LLink] = Field(default_factory=list)
    downstream: list[LLink] = Field(default_factory=list)
    stages: list[LStage] = Field(default_factory=list)  # YAML deployment stages (classic releases are in `releases`)
    last_run: LDeploy | None = None  # last completed build/run (status + time + display name)


class LArtifactSource(BaseModel):
    type: str  # Build | GitHub | other artifact type
    alias: str = ""
    name: str = ""  # build definition name or "org/repo"
    primary: bool = False
    pipeline_id: str | None = None  # Build artifacts: the build definition id
    branch: str | None = None


class LRelease(BaseModel):
    id: str
    name: str
    url: str = ""
    kind: Literal["classic_release"] = "classic_release"
    sources: list[LArtifactSource] = Field(default_factory=list)
    source_pipeline_ids: list[str] = Field(default_factory=list)
    cd_enabled: bool = False
    cd_branches: list[str] = Field(default_factory=list)
    schedules: list[str] = Field(default_factory=list)
    adopted_from: str | None = None
    stages: list[LStage] = Field(default_factory=list)


class LRepo(BaseModel):
    key: str
    project: str
    name: str
    provider: str = "azure_repos"
    provider_label: str = "Azure Repos"
    url: str = ""
    default_branch: str = ""
    service_connection: str | None = None  # name of the service connection ADO uses to reach the code (GitHub)


class LOrphan(BaseModel):
    type: Literal["pipeline", "release"]
    project: str
    id: str
    name: str
    url: str = ""
    reason: str


class RepoLineage(BaseModel):
    repo: LRepo
    pipelines: list[LPipeline] = Field(default_factory=list)
    releases: list[LRelease] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)  # e.g. collection problems that make stages "unknown"

    def all_stages(self) -> list[LStage]:
        return [s for p in self.pipelines for s in p.stages] + [s for r in self.releases for s in r.stages]

    @property
    def has_prod(self) -> bool:
        """A production stage exists AND its last deployment succeeded (fully or partially)."""
        return any(s.env_tier == "prod" and s.last_deploy.status in ("succeeded", "partial") for s in self.all_stages())

    @property
    def targets(self) -> list[str]:
        return sorted({t.kind for s in self.all_stages() for t in s.targets})

    @property
    def tiers(self) -> list[str]:
        return sorted({s.env_tier for s in self.all_stages() if s.env_tier != "unknown"})

    @property
    def is_empty(self) -> bool:
        return not self.pipelines and not self.releases
