"""Repo-level facts for externally hosted repositories (GitHub etc.) that Azure DevOps pipelines build.

Nothing is read from such a repository (ADO's Items API and branch policies cover Azure Repos only, and this tool does
not call the GitHub API yet), so the facts say "unavailable" instead of pretending the repo is empty. A future
read-only reader returns a populated ``RepoFacts`` (``facts_source`` = its own name) and the rules then evaluate normally.
"""

from __future__ import annotations

from pch.model.pipeline import Pipeline
from pch.model.repo import RepoFacts, RepoKind, unavailable_reason


def unavailable_facts(provider: str) -> RepoFacts:
    return RepoFacts(facts_source="unavailable", facts_reason=unavailable_reason(provider))


def infer_external_kind(pipelines: list[Pipeline]) -> RepoKind | None:
    """adf / synapse / iac when everything the repo's pipelines deploy is of that one data-platform/IaC kind."""
    targets = {t for p in pipelines for s in p.stages for t in s.deploy_targets}
    for kind in ("adf", "synapse", "iac"):
        if targets and targets <= {kind}:
            return kind  # type: ignore[return-value]
    return None
