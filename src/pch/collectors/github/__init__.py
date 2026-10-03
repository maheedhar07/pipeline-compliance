"""GitHub Actions adapter (M9, Phase 3): interface only.

The migration target. An implementation must map workflows, environments (required reviewers,
deployment branch policies), rulesets, OIDC federated credentials and action SHA pinning onto the
canonical `Pipeline` model (platform="gha") so the SAME rules apply, and must stay read-only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from pch.model.pipeline import Pipeline


class GitHubAdapter(ABC):
    """Read-only GitHub collector contract (to be implemented in M9)."""

    @abstractmethod
    async def list_workflows(self, owner: str, repo: str) -> list[Pipeline]:
        """Parse .github/workflows/*.yml into canonical pipelines (stages = jobs, environments = stages)."""

    @abstractmethod
    async def environment_protection(self, owner: str, repo: str) -> dict[str, dict]:
        """Required reviewers, wait timers and deployment branch policies per environment."""

    @abstractmethod
    async def branch_rulesets(self, owner: str, repo: str) -> dict:
        """Branch protection / rulesets for the default branch."""

    @abstractmethod
    async def oidc_subjects(self, owner: str, repo: str) -> list[str]:
        """OIDC subject claims / federated credential usage (replacement for service principal secrets)."""


class NotImplementedGitHubAdapter(GitHubAdapter):
    async def list_workflows(self, owner: str, repo: str) -> list[Pipeline]:
        raise NotImplementedError("GitHub Actions support is Phase 3 (M9)")

    async def environment_protection(self, owner: str, repo: str) -> dict[str, dict]:
        raise NotImplementedError("GitHub Actions support is Phase 3 (M9)")

    async def branch_rulesets(self, owner: str, repo: str) -> dict:
        raise NotImplementedError("GitHub Actions support is Phase 3 (M9)")

    async def oidc_subjects(self, owner: str, repo: str) -> list[str]:
        raise NotImplementedError("GitHub Actions support is Phase 3 (M9)")
