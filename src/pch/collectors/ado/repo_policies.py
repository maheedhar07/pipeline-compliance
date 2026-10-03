"""Branch policies (project-wide fetch, filtered per repo/default branch)."""

from __future__ import annotations

from typing import Any

from pch.collectors.ado.client import AdoClient
from pch.model.repo import BranchPolicies

T_MIN_REVIEWERS = "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"
T_BUILD = "0609b952-1397-4640-95ec-e00a01b2c241"
T_WORK_ITEM = "40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e"
T_COMMENTS = "c6a1889d-b943-4856-b76f-9e46bb6b0df2"
T_REQUIRED_REVIEWERS = "fd2167ab-b0be-447a-8ec8-39368250530e"


async def collect_policy_configurations(client: AdoClient, project: str) -> list[dict[str, Any]]:
    return await client.paged(project, "_apis/policy/configurations")


def _applies(cfg: dict[str, Any], repo_id: str, ref: str) -> bool:
    if not cfg.get("isEnabled", True) or cfg.get("isDeleted"):
        return False
    for sc in (cfg.get("settings") or {}).get("scope", []):
        rid = sc.get("repositoryId")
        if rid is not None and rid != repo_id:
            continue
        name = sc.get("refName")
        if name is None:  # whole repository / project
            return True
        if name == ref or (sc.get("matchKind") == "Prefix" and ref.startswith(name)):
            return True
    return False


def policies_for_repo(configs: list[dict[str, Any]], repo_id: str, default_branch: str = "main") -> BranchPolicies:
    ref = default_branch if default_branch.startswith("refs/") else f"refs/heads/{default_branch}"
    pol = BranchPolicies(available=True)
    for cfg in configs:
        if not _applies(cfg, repo_id, ref):
            continue
        tid = (cfg.get("type") or {}).get("id", "").lower()
        s = cfg.get("settings") or {}
        if tid == T_MIN_REVIEWERS:
            n = s.get("minimumApproverCount")
            pol.min_reviewers = max(pol.min_reviewers or 0, n or 0)
            pol.creator_vote_counts = bool(s.get("creatorVoteCounts")) or bool(pol.creator_vote_counts)
            pol.reset_on_push = bool(s.get("resetOnSourcePush")) or bool(pol.reset_on_push)
        elif tid == T_BUILD:
            pol.build_validation = True
        elif tid == T_WORK_ITEM:
            pol.work_item_required = True
        elif tid == T_COMMENTS:
            pol.comment_resolution_required = True
        elif tid == T_REQUIRED_REVIEWERS:
            pol.required_reviewer_paths.extend(s.get("filenamePatterns") or ["*"])
    return pol
