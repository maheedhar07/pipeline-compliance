"""What the GitHub Actions collector read for one repository (raw facts, no judgement). Normalised by ``pch.normalize.gha``."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class WorkflowSource(BaseModel):
    """One workflow file. ``text`` is None when the file could not be read (``error`` says why)."""

    path: str
    id: int | None = None
    name: str = ""
    state: str = "active"  # active | disabled_manually | disabled_inactivity | disabled_fork | deleted (the API's `state`)
    url: str = ""
    text: str | None = None
    error: str = ""


class GhCustomRule(BaseModel):
    slug: str
    name: str = ""
    enabled: bool = True


class GhEnvironment(BaseModel):
    """Protection of one deployment environment (``GET /repos/{o}/{r}/environments`` and its sub-resources)."""

    name: str
    required_reviewers: bool = False  # a required-reviewers rule exists
    reviewers: list[str] = Field(default_factory=list)  # "user:<login>" / "team:<slug>"
    prevent_self_review: bool | None = None
    wait_timer: int = 0  # minutes
    branch_policy: Literal["none", "protected", "custom"] = "none"
    branch_patterns: list[str] = Field(default_factory=list)  # custom branch/tag name patterns
    custom_rules: list[GhCustomRule] = Field(default_factory=list)  # custom deployment protection rules (GitHub Apps)
    branch_error: str = ""  # custom branch policy list unreadable -> SRC-005 UNKNOWN
    custom_error: str = ""  # custom protection rules unreadable -> DEP-003 UNKNOWN unless another ServiceNow control is seen


class GhDeployment(BaseModel):
    """Last deployment of an environment (``/deployments?environment=`` + its latest status)."""

    environment: str
    status: str = "unknown"  # GitHub deployment state: success | failure | error | inactive | in_progress | queued | pending | unknown
    never: bool = False  # collected, and the environment has no deployment
    id: int | None = None
    sha: str | None = None
    creator: str | None = None  # login only
    finished: str | None = None  # ISO timestamp of the latest status (else of the deployment)
    url: str | None = None
    error: str = ""  # lookup failed -> the stage's last deployment is "unknown"


class ActionsRead(BaseModel):
    """Everything the collector read. A part that failed is None / has an ``*_error`` and makes dependent rules UNKNOWN, never FAIL."""

    workflows: list[WorkflowSource] = Field(default_factory=list)
    list_error: str = ""  # the workflow listing failed (workflows then come from the file tree, if known)
    listed: bool = True
    environments: dict[str, GhEnvironment] | None = None  # None: not readable
    environments_error: str = ""
    runs: list[dict[str, Any]] | None = None  # slimmed run records of the window; None: not readable
    runs_truncated: bool = False  # page cap reached: a workflow missing from `runs` proves nothing
    runs_error: str = ""
    deployments: dict[str, GhDeployment] = Field(default_factory=dict)  # lower-cased environment name -> last deployment
    reusable: dict[str, str | None] = Field(default_factory=dict)  # `uses` value -> workflow text (None: could not be read)
    reusable_errors: dict[str, str] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)  # one line per failed call (the scan scrubs them into collection errors)
