"""Last deployment per stage/environment (lineage, L2). Read-only GETs through the shared AdoClient.

Classic releases: ONE ``release/deployments`` call per release definition (newest first, all environments) plus ONE
``release/releases?$expand=artifacts`` call for the artifact versions. A stage that does not show up in that page gets a
targeted ``definitionEnvironmentId`` lookup (``$top=1``) before it is reported as "never deployed" (the page may simply
have been filled by other environments).

YAML pipelines: ONE ``environmentdeploymentrecords`` call per environment (cached per scan, shared by every pipeline that
deploys there); the records are mapped back to the pipeline definition + stage, and enriched from the build runs the scan
already collected (version, commit, display name of who started the run).

Anything that cannot be collected becomes ``unknown`` (never a crash, never a guess); the caller records a collection error.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from pch.collectors.ado.client import AdoClient
from pch.collectors.ado.runs import parse_dt
from pch.model.lineage import DeployStatus, LDeploy

_SHA = re.compile(r"^[0-9a-f]{7,40}$", re.I)
MAX_FIELD = 120


def display_name(identity: Any) -> str | None:
    """Display name of an identity reference. Never an email/UPN (PII): a value that looks like one is dropped."""
    if not isinstance(identity, dict):
        return None
    name = str(identity.get("displayName") or "").strip()
    if not name or "@" in name:
        return None
    return name[:MAX_FIELD]


def short_sha(v: Any) -> str | None:
    s = str(v or "").strip()
    if not s:
        return None
    return s[:7] if _SHA.match(s) and len(s) >= 40 else s[:MAX_FIELD]


def map_release_status(deployment_status: str | None, operation_status: str | None) -> DeployStatus:
    s = (deployment_status or "").replace("_", "").lower()
    op = (operation_status or "").lower()
    if s == "succeeded":
        return "succeeded"
    if s == "partiallysucceeded":
        return "partial"
    if s == "failed":
        return "failed"
    if s == "inprogress":
        return "in_progress"
    if s == "notdeployed":
        return "canceled" if any(k in op for k in ("cancel", "reject")) else "pending"
    if s == "canceled":
        return "canceled"
    return "unknown"


def map_result(result: str | None) -> DeployStatus | None:
    """Build / environment-record result -> status. ``None`` for results that are not a deployment (skipped)."""
    r = (result or "").replace("_", "").lower()
    return {
        "succeeded": "succeeded", "succeededwithissues": "partial", "partiallysucceeded": "partial", "failed": "failed",
        "canceled": "canceled", "abandoned": "canceled", "none": "unknown",
    }.get(r)  # type: ignore[return-value]


def _release_artifact_version(release: dict[str, Any]) -> str | None:
    arts = [a for a in release.get("artifacts") or [] if isinstance(a, dict)]
    arts.sort(key=lambda a: not a.get("isPrimary"))
    for a in arts:
        ver = (a.get("definitionReference") or {}).get("version") or {}
        v = short_sha(ver.get("id")) if a.get("type") == "GitHub" else (str(ver.get("name") or "").strip()[:MAX_FIELD] or None)
        if v:
            return v
    return None


def deploy_from_release_record(rec: dict[str, Any], artifact_versions: dict[str, str | None], web: Callable[[str], str]) -> LDeploy:
    rel = rec.get("release") or {}
    rid = str(rel.get("id") or "")
    return LDeploy(
        status=map_release_status(rec.get("deploymentStatus"), rec.get("operationStatus")),
        version=str(rel.get("name") or "")[:MAX_FIELD] or None,
        artifact_version=artifact_versions.get(rid),
        finished=parse_dt(rec.get("completedOn")) or parse_dt(rec.get("startedOn")) or parse_dt(rec.get("queuedOn")),
        triggered_by=display_name(rec.get("requestedFor")) or display_name(rec.get("requestedBy")),
        url=web(rid) if rid else None,
    )


def _sort_key(rec: dict[str, Any]) -> datetime:
    return parse_dt(rec.get("startedOn")) or parse_dt(rec.get("queuedOn")) or datetime.min


async def collect_release_deployments(
    client: AdoClient, project: str, definition_id: str, env_ids: dict[str, str], top: int, on_error: Callable[[str], None],
) -> dict[str, LDeploy]:
    """stage (release environment) name -> last deployment. Raises when the main listing fails (caller marks every stage unknown)."""
    def web(release_id: str) -> str:
        return client.web_url(project, f"_releaseProgress?_a=release-pipeline-progress&releaseId={release_id}")

    # VERIFY: GET {vsrm}/{project}/_apis/release/deployments?definitionId=&queryOrder=descending&$top= (api 7.1) lists
    # deployments of all environments, newest first; items carry release{id,name}, releaseEnvironment{id,name},
    # deploymentStatus, operationStatus, requestedFor/requestedBy, startedOn/completedOn/queuedOn.
    data = await client.get(project, "_apis/release/deployments", {"definitionId": definition_id, "queryOrder": "descending", "$top": top}, vsrm=True)
    items = [d for d in (data or {}).get("value", []) if isinstance(d, dict)]
    items.sort(key=_sort_key, reverse=True)
    newest: dict[str, dict[str, Any]] = {}
    for d in items:
        name = (d.get("releaseEnvironment") or {}).get("name")
        if name and name not in newest:
            newest[name] = d
    # Stages missing from the page: ask for that environment alone before claiming "never deployed".
    for name, env_id in env_ids.items():
        if name in newest:
            continue
        try:
            one = await client.get(project, "_apis/release/deployments",
                                   {"definitionId": definition_id, "definitionEnvironmentId": env_id, "queryOrder": "descending", "$top": 1}, vsrm=True)
            vals = [d for d in (one or {}).get("value", []) if isinstance(d, dict)]
            if vals:
                newest[name] = vals[0]
        except Exception as e:  # noqa: BLE001 - fail open: that stage stays unknown
            on_error(f"release {definition_id} stage {name}: last deployment lookup failed: {type(e).__name__}")
            newest[name] = {"__error__": True}
    # Artifact versions of the releases involved (one list call; single GET only for releases outside that page).
    wanted = {str((d.get("release") or {}).get("id")) for d in newest.values() if d.get("release")}
    versions: dict[str, str | None] = {}
    if wanted:
        try:
            # VERIFY: release/releases?definitionId=&$expand=artifacts&$top= returns artifacts[].definitionReference.version.
            lst = await client.get(project, "_apis/release/releases", {"definitionId": definition_id, "$expand": "artifacts", "$top": 50, "queryOrder": "descending"}, vsrm=True)
            for r in (lst or {}).get("value", []):
                if isinstance(r, dict) and r.get("id") is not None:
                    versions[str(r["id"])] = _release_artifact_version(r)
        except Exception as e:  # noqa: BLE001
            on_error(f"release {definition_id}: artifact versions not collected: {type(e).__name__}")
        for rid in sorted(wanted - versions.keys()):
            try:
                r = await client.get(project, f"_apis/release/releases/{rid}", vsrm=True)
                versions[rid] = _release_artifact_version(r or {})
            except Exception:  # noqa: BLE001 - version stays empty; status/time are still shown
                versions[rid] = None
    out: dict[str, LDeploy] = {}
    for name in env_ids or {}:
        rec = newest.get(name)
        if rec is None:
            out[name] = LDeploy(status="never")
        elif rec.get("__error__"):
            out[name] = LDeploy(status="unknown", note="lookup failed")
    for name, d in newest.items():
        if not d.get("__error__"):
            out[name] = deploy_from_release_record(d, versions, web)
    return out


class EnvRecordCache:
    """Environment deployment records, one request per environment per scan (shared by all pipelines deploying there)."""

    def __init__(self, client: AdoClient, top: int):
        self.client, self.top = client, top
        self._tasks: dict[tuple[str, str], asyncio.Task[list[dict[str, Any]]]] = {}

    async def records(self, project: str, env_id: str) -> list[dict[str, Any]]:
        key = (project, str(env_id))
        if key not in self._tasks:
            self._tasks[key] = asyncio.ensure_future(self._fetch(project, str(env_id)))
        return await self._tasks[key]

    async def _fetch(self, project: str, env_id: str) -> list[dict[str, Any]]:
        # VERIFY: GET {org}/{project}/_apis/distributedtask/environments/{id}/environmentdeploymentrecords?top= (api 7.1).
        # Records carry definition{id,name}, stageName, owner{id,name} (the pipeline run), result, queueTime/startTime/finishTime.
        data = await self.client.get(project, f"_apis/distributedtask/environments/{env_id}/environmentdeploymentrecords", {"top": self.top})
        vals = [r for r in (data or {}).get("value", []) if isinstance(r, dict)]
        vals.sort(key=lambda r: parse_dt(r.get("startTime")) or parse_dt(r.get("queueTime")) or datetime.min, reverse=True)
        return vals


def deploy_from_env_record(rec: dict[str, Any], builds: dict[str, dict[str, Any]], web: Callable[[str], str]) -> LDeploy | None:
    """One environment deployment record -> LDeploy (``None`` for skipped/irrelevant records)."""
    owner = rec.get("owner") or {}
    run_id = str(owner.get("id") or "")
    result = rec.get("result")
    if result in (None, ""):
        status: DeployStatus = "in_progress" if (rec.get("startTime") or rec.get("jobAttempt")) else "pending"
    else:
        mapped = map_result(str(result))
        if mapped is None:
            if str(result).lower() == "skipped":
                return None
            mapped = "unknown"
        status = mapped
    b = builds.get(run_id) or {}
    return LDeploy(
        status=status,
        version=(str(b.get("buildNumber") or owner.get("name") or "")[:MAX_FIELD] or None),
        artifact_version=short_sha(b.get("sourceVersion")),
        finished=parse_dt(rec.get("finishTime")) or parse_dt(rec.get("startTime")) or parse_dt(rec.get("queueTime")),
        triggered_by=display_name(b.get("requestedFor")),
        url=web(run_id) if run_id else None,
    )


async def collect_yaml_deployments(
    client: AdoClient, project: str, pipeline_id: str, stage_envs: Mapping[str, str | None], env_ids: dict[str, str],
    cache: EnvRecordCache, builds: list[dict[str, Any]], on_error: Callable[[str], None],
) -> dict[str, LDeploy]:
    """stage name -> last deployment, for the YAML stages that deploy to a (known) environment.

    ``stage_envs`` maps stage name -> environment name; ``env_ids`` maps environment name -> id (from the scan's environments)."""
    by_id = {str(b.get("id")): b for b in builds if isinstance(b, dict)}

    def web(run_id: str) -> str:
        return client.web_url(project, f"_build/results?buildId={run_id}")

    out: dict[str, LDeploy] = {}
    for stage, env_name in stage_envs.items():
        env_id = env_ids.get(env_name or "")
        if not env_id:
            out[stage] = LDeploy(status="unknown", note="environment not found (no access or not created yet)")
            continue
        try:
            recs = await cache.records(project, env_id)
        except Exception as e:  # noqa: BLE001 - fail open
            on_error(f"environment {env_name}: deployment records not collected: {type(e).__name__}")
            out[stage] = LDeploy(status="unknown", note="deployment records not collected")
            continue
        found: LDeploy | None = None
        for r in recs:
            if str((r.get("definition") or {}).get("id")) != str(pipeline_id) or r.get("stageName") != stage:
                continue
            found = deploy_from_env_record(r, by_id, web)
            if found is not None:
                break
        if found is not None:
            out[stage] = found
        elif len(recs) >= cache.top:  # the page is full of other pipelines' records: absence proves nothing
            out[stage] = LDeploy(status="unknown", note=f"not among the latest {cache.top} deployments to this environment")
        else:
            out[stage] = LDeploy(status="never")
    return out
