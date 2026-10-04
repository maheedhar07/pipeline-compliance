"""Lineage builder: repo -> CI pipelines -> downstream pipelines -> releases -> stages -> last deployment.

Pure functions over what the scan already collected (normalized pipelines, raw definitions, environment checks, service
connections, run history) plus the last-deployment lookups from ``collectors.ado.deployments``. No I/O.

Heuristics and their limits are documented in docs/DECISIONS.md (ADR-14):
* YAML stage -> environment is ``stage.environment`` of its deployment jobs (first one); a stage without environment has
  no deployment records, so its last deployment is "unknown", never guessed.
* Deploy target resource names come from a whitelist of task inputs per target kind; values that look like secrets are dropped.
* A YAML file "in a different repo than the code" is detected from ``resources.repositories`` + ``checkout:`` steps
  (code checked out from another repository and ``self`` not checked out).
"""

from __future__ import annotations

import copy
import re
from typing import Any

from pch.collectors.ado.deployments import display_name, map_result, short_sha
from pch.collectors.ado.lineage_meta import (
    MAX_TEXT,
    YamlMeta,
    artifacts_from_steps,
    classic_build_meta,
    clean_branch,
)
from pch.collectors.ado.runs import parse_dt
from pch.collectors.redact import SECRET_NAME, value_looks_secret
from pch.model.lineage import (
    LArtifactSource,
    LDeploy,
    LLink,
    LOrphan,
    LPipeline,
    LRelease,
    LRepo,
    LStage,
    LTarget,
    LTrigger,
    RepoLineage,
)
from pch.model.pipeline import Approval, Pipeline, Stage, Step
from pch.model.repo import PROVIDER_LABEL, RepoRef, ServiceConnection
from pch.normalize.target_detect import TARGET_NAMES

# --------------------------------------------------------------------------- targets
_NAME_KEYS: dict[str, tuple[str, ...]] = {
    "functionapp": ("appname", "webappname", "functionappname", "azurewebappname"),
    "webapp": ("appname", "webappname", "azurewebappname"),
    "aks": ("kubernetescluster", "clustername"),
    "adf": ("datafactoryname", "factoryname"),
    "synapse": ("targetworkspacename", "workspacename"),
}
_RG_KEYS = ("resourcegroupname", "resourcegroup", "azureresourcegroup")
_FACTORY = re.compile(r"-factoryName\s+['\"]?([^\s'\"]+)", re.I)
_NAMESPACE = re.compile(r"(?:--namespace[ =]|\s-n\s+)([A-Za-z0-9_.$()-]+)")
_WEBAPP_N = re.compile(r"(?:--name[ =]|\s-n\s+)([A-Za-z0-9_.$()-]+)")


def _clean(v: Any) -> str | None:
    if not isinstance(v, str | int | float) or isinstance(v, bool):
        return None
    s = str(v).strip()
    if not s or len(s) > 300 or value_looks_secret(s):
        return None
    return s[:MAX_TEXT]


def _inputs(step: Step) -> dict[str, Any]:
    return {str(k).lower(): v for k, v in step.inputs.items() if not SECRET_NAME.search(str(k))}


def _first(low: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for k in keys:
        v = _clean(low.get(k))
        if v:
            return v
    return None


def _step_target(kind: str, step: Step) -> LTarget:
    low = _inputs(step)
    rg = _first(low, _RG_KEYS)
    script = step.inline_script or ""
    if kind in ("functionapp", "webapp"):
        name = _first(low, _NAME_KEYS[kind])
        if not name and script:
            m = _WEBAPP_N.search(script)
            name = m.group(1) if m else None
        slot = _first(low, ("slotname",))
        detail = ", ".join(x for x in (f"rg {rg}" if rg else "", f"slot {slot}" if slot else "") if x)
        return LTarget(kind=kind, name=name, detail=detail or None)
    if kind == "aks":
        ns = _first(low, ("namespace",))
        if not ns and script:
            m = _NAMESPACE.search(script)
            ns = m.group(1) if m else None
        cluster = _first(low, _NAME_KEYS["aks"]) or _first(low, ("kubernetesserviceconnection", "kubernetesserviceendpoint"))
        detail = ", ".join(x for x in (f"ns {ns}" if ns else "", f"rg {rg}" if rg else "") if x)
        return LTarget(kind=kind, name=cluster, detail=detail or None)
    if kind == "adf":
        name = _first(low, _NAME_KEYS["adf"])
        if not name:
            m = _FACTORY.search(str(low.get("overrideparameters") or ""))
            name = _clean(m.group(1)) if m else None
        return LTarget(kind=kind, name=name, detail=f"rg {rg}" if rg else None)
    if kind == "synapse":
        return LTarget(kind=kind, name=_first(low, _NAME_KEYS["synapse"]), detail=f"rg {rg}" if rg else None)
    if kind == "sql":
        server, db = _first(low, ("servername", "sqlserver")), _first(low, ("databasename", "database"))
        return LTarget(kind=kind, name="/".join(x for x in (server, db) if x) or None)
    if kind == "iac":
        return LTarget(kind=kind, detail=f"rg {rg}" if rg else None)
    return LTarget(kind=kind)


def stage_targets(stage: Stage) -> list[LTarget]:
    out: dict[tuple[str, str | None, str | None], LTarget] = {}
    for step in stage.steps():
        if not step.enabled:
            continue
        kinds = {c.split(":", 1)[1] for c in step.capabilities if c.startswith("deploy:")} & (TARGET_NAMES | {"other"})
        for kind in sorted(kinds):
            if kind not in stage.deploy_targets:  # ADF/Synapse refinement of a generic ARM deployment
                kind = "adf" if "adf" in stage.deploy_targets else "synapse" if "synapse" in stage.deploy_targets else kind
            t = _step_target(kind, step)
            out.setdefault((t.kind, t.name, t.detail), t)
    for kind in sorted(stage.deploy_targets):  # target known (script heuristics) but no step produced it
        if not any(k[0] == kind for k in out):
            out[(kind, None, None)] = LTarget(kind=kind)
    named = {t.kind for t in out.values() if t.name or t.detail}
    return [t for t in out.values() if t.name or t.detail or t.kind not in named][:12]


# --------------------------------------------------------------------------- stages
def _approval_text(a: Approval, phase: str) -> str:
    if a.kind == "manual":
        n = a.min_approvers or 1
        return f"{phase}manual approval (min {n})"
    if a.kind == "servicenow":
        return f"{phase}ServiceNow change check"
    if a.kind == "branch_control":
        return f"{phase}branch control" + (f" ({', '.join(a.branches[:4])})" if a.branches else "")
    if a.kind == "business_hours":
        return f"{phase}business hours"
    return f"{phase}{(a.name or 'gate/check')[:60]}"


def approvals_and_gates(stage: Stage) -> tuple[list[str], list[str]]:
    """Summaries only: counts and kinds, no approver names (PII minimisation)."""
    approvals = [_approval_text(a, "") for a in stage.pre_approvals]
    approvals += [_approval_text(a, "post-deploy ") for a in stage.post_approvals if a.kind == "manual"]
    gates = [_approval_text(a, "") for a in stage.gates]
    gates += [_approval_text(a, "post-deploy ") for a in stage.post_approvals if a.kind != "manual"]
    return approvals, gates


def _conn_names(stage: Stage, conns: dict[str, ServiceConnection]) -> list[str]:
    seen: list[str] = []
    for c in stage.service_connections:
        n = conns[c].name if c in conns else c
        if n and n not in seen:
            seen.append(n[:MAX_TEXT])
    return sorted(seen)


def lstage(stage: Stage, conns: dict[str, ServiceConnection], deploy: LDeploy) -> LStage:
    approvals, gates = approvals_and_gates(stage)
    return LStage(
        name=stage.name, env_name=stage.env_name, env_tier=stage.env_tier, depends_on=list(stage.depends_on), targets=stage_targets(stage),
        service_connections=_conn_names(stage, conns), approvals=approvals, gates=gates, branch_filters=list(stage.branch_filters)[:10], last_deploy=deploy,
    )


def is_deploy_stage(st: Stage) -> bool:
    if st.env_name:
        return True
    return bool(st.deploy_targets) and st.name.lower() != "build"


# --------------------------------------------------------------------------- pipelines
def last_run(builds: list[dict[str, Any]] | None) -> LDeploy | None:
    best: dict[str, Any] | None = None
    best_t = None
    for b in builds or []:
        t = parse_dt(b.get("finishTime"))
        if t and (best_t is None or t > best_t):
            best, best_t = b, t
    if best is None:
        return None
    return LDeploy(
        status=map_result(best.get("result")) or "unknown", version=str(best.get("buildNumber") or "")[:MAX_TEXT] or None,
        artifact_version=short_sha(best.get("sourceVersion")), finished=best_t, triggered_by=display_name(best.get("requestedFor")),
        url=((best.get("_links") or {}).get("web") or {}).get("href"),
    )


def build_pipeline(p: Pipeline, ref: RepoRef, defn: dict[str, Any] | None, meta: YamlMeta | None, deploys: dict[str, LDeploy] | None,
                   builds: list[dict[str, Any]] | None, conns: dict[str, ServiceConnection], collected: bool) -> LPipeline:
    defn = defn or {}
    kind = "yaml" if p.platform == "ado_yaml" else "classic_build"
    if kind == "yaml":
        trigger = meta.trigger if meta else LTrigger(ci_enabled=None, ci_branches=[clean_branch(b) for b in p.artifact_branch_filters][:20])
        upstream = list(meta.upstream) if meta else []
        artifacts = list(meta.artifacts) if meta else artifacts_from_steps(p.all_steps())
        path = str((defn.get("process") or {}).get("yamlFilename") or p.triggers.get("yamlFilename") or "")
        code = [n for _, n in meta.code_repos()] if meta else []
        other = bool(meta and meta.yaml_in_other_repo())
        templates = meta.template_repos() if meta else []
    else:
        trigger, upstream = classic_build_meta(defn)
        artifacts = artifacts_from_steps(p.all_steps())
        path = str(defn.get("path") or "")
        code, other, templates = [], False, []
    stages: list[LStage] = []
    if kind == "yaml":
        for st in p.stages:
            if not is_deploy_stage(st):
                continue
            d = (deploys or {}).get(st.name)
            if d is None:
                d = LDeploy(status="unknown", note="not collected" if not collected else ("no environment: deployments are not tracked" if not st.env_name else "not collected"))
            stages.append(lstage(st, conns, d))
    return LPipeline(
        id=p.id, name=p.name, kind=kind, url=p.url, definition_path=path[:MAX_TEXT * 2], yaml_repo=ref.name if kind == "yaml" else None,
        code_repos=code, template_repos=templates, yaml_in_other_repo=other, trigger=trigger, artifacts=artifacts, upstream=upstream, stages=stages, last_run=last_run(builds),
    )


def _release_sources(raw: dict[str, Any]) -> list[LArtifactSource]:
    out: list[LArtifactSource] = []
    for a in raw.get("artifacts") or []:
        if not isinstance(a, dict):
            continue
        ref = a.get("definitionReference") or {}
        d = ref.get("definition") or {}
        branch = (ref.get("defaultVersionBranch") or ref.get("branch") or {}).get("name") or (ref.get("branches") or {}).get("name")
        out.append(LArtifactSource(
            type=str(a.get("type") or "")[:40], alias=str(a.get("alias") or "")[:MAX_TEXT], name=str(d.get("name") or d.get("id") or "")[:MAX_TEXT], primary=bool(a.get("isPrimary")),
            pipeline_id=str(d.get("id")) if a.get("type") == "Build" and d.get("id") is not None else None, branch=str(branch)[:MAX_TEXT] if branch else None,
        ))
    return out


def build_release(p: Pipeline, raw: dict[str, Any], deploys: dict[str, LDeploy] | None, conns: dict[str, ServiceConnection], collected: bool) -> LRelease:
    trig_raw = [t for t in raw.get("triggers") or [] if isinstance(t, dict)]
    cd = [t for t in trig_raw if str(t.get("triggerType") or "").lower() == "artifactsource"]
    branches: list[str] = []
    for t in cd:
        for c in t.get("triggerConditions") or []:
            if c.get("sourceBranch"):
                branches.append(clean_branch(c["sourceBranch"]))
    schedules = []
    for t in trig_raw:
        if str(t.get("triggerType") or "").lower() == "schedule":
            sc = t.get("schedule") or {}
            try:
                schedules.append(f"{int(sc.get('startHours', 0)):02d}:{int(sc.get('startMinutes', 0)):02d} {sc.get('timeZoneId') or 'UTC'}")
            except (TypeError, ValueError):
                schedules.append("scheduled")
    stages = []
    for st in p.stages:
        d = (deploys or {}).get(st.name) or LDeploy(status="unknown", note="not collected" if not collected else "no deployment data")
        stages.append(lstage(st, conns, d))
    return LRelease(
        id=p.id, name=p.name, url=p.url, sources=_release_sources(raw), source_pipeline_ids=list(p.linked_build_ids), cd_enabled=bool(cd), cd_branches=sorted(set(branches))[:10],
        schedules=schedules[:5], stages=stages,
    )


def build_repo_lineage(
    ref: RepoRef, pipelines: list[Pipeline], build_defs: list[dict[str, Any]], release_defs: list[dict[str, Any]], yaml_meta: dict[str, YamlMeta],
    deploys: dict[str, dict[str, LDeploy]], build_runs: dict[str, list[dict[str, Any]]], conns: dict[str, ServiceConnection], collected: bool = True,
    notes: list[str] | None = None,
) -> RepoLineage:
    """``deploys`` is keyed ``"<platform>:<id>"`` -> stage name -> LDeploy."""
    bdefs = {str(d.get("id")): d for d in build_defs}
    rdefs = {str(d.get("id")): d for d in release_defs}
    conn = conns.get(ref.service_connection_id or "")
    lrepo = LRepo(
        key=ref.key, project=ref.project, name=ref.name, provider=ref.provider, provider_label=PROVIDER_LABEL.get(ref.provider, ref.provider), url=ref.url,
        default_branch=ref.default_branch, service_connection=(conn.name if conn else None),
    )
    out = RepoLineage(repo=lrepo, notes=list(notes or []))
    for p in pipelines:
        if p.platform == "gha":
            continue  # workflows are added by normalize.gha.build_lineage (they have no ADO definition or run records)
        if p.platform == "ado_classic_release":
            out.releases.append(build_release(p, rdefs.get(p.id, {}), deploys.get(f"{p.platform}:{p.id}"), conns, collected))
        else:
            out.pipelines.append(build_pipeline(p, ref, bdefs.get(p.id), yaml_meta.get(p.id), deploys.get(f"{p.platform}:{p.id}"), build_runs.get(p.id), conns, collected))
    return out


# --------------------------------------------------------------------------- cross-repo linking
def _resolve_repo_key(project: str, name: str, keys: dict[str, str]) -> str | None:
    """Repository resource name -> repo key of a scanned repo (``keys``: casefolded key -> key).

    GitHub names are "org/repo" (key ``Project/org/repo``), Azure Repos names are "Repo" or "Project/Repo"."""
    for cand in (f"{project}/{name}", name, f"{project}/{name.rsplit('/', 1)[-1]}"):
        if cand.casefold() in keys:
            return keys[cand.casefold()]
    return None


def link_lineages(lineages: list[RepoLineage]) -> None:
    """Downstream links, then cross-repo adoption (pipelines that live in repo T but build code from repo C also show up under C).

    Mutates the lineages in place. Idempotent per scan (run once, after every repo has been scanned)."""
    by_id: dict[tuple[str, str], tuple[RepoLineage, LPipeline]] = {}
    by_name: dict[tuple[str, str], tuple[RepoLineage, LPipeline]] = {}
    for lin in lineages:
        for p in lin.pipelines:
            by_id.setdefault((lin.repo.project.casefold(), p.id), (lin, p))
            by_name.setdefault((lin.repo.project.casefold(), p.name.casefold()), (lin, p))
    for lin in lineages:
        for consumer in lin.pipelines:
            for link in consumer.upstream:
                if link.kind == "workflow_run":
                    continue  # resolved within the repository when the workflows were built (normalize.gha.build_lineage)
                target = None
                tproj = (link.project or lin.repo.project).casefold()
                if link.kind == "classic_completion" and link.pipeline_id:
                    target = by_id.get((tproj, link.pipeline_id))
                if target is None:
                    nm = link.name.casefold().replace("\\", "/")
                    target = by_name.get((tproj, nm)) or by_name.get((tproj, nm.rsplit("/", 1)[-1]))
                if target is None:
                    continue
                tlin, tp = target
                link.repo_key, link.url = tlin.repo.key, tp.url
                if tp is consumer:
                    continue
                tp.downstream.append(LLink(kind=link.kind, name=consumer.name, pipeline_id=consumer.id, project=lin.repo.project, repo_key=lin.repo.key, url=consumer.url, detail=link.detail))
    keys = {lin.repo.key.casefold(): lin.repo.key for lin in lineages}
    by_key = {lin.repo.key: lin for lin in lineages}
    adopted: list[tuple[RepoLineage, RepoLineage, LPipeline, list[LRelease]]] = []
    for lin in lineages:
        for p in lin.pipelines:
            if p.adopted_from or not (p.yaml_in_other_repo and p.code_repos):
                continue
            rels = [r for r in lin.releases if p.id in r.source_pipeline_ids]
            for cr in p.code_repos:
                key = _resolve_repo_key(lin.repo.project, cr, keys)
                if key and key != lin.repo.key:
                    adopted.append((by_key[key], lin, p, rels))
    for dest, origin, p, rels in adopted:
        if any(x.id == p.id and x.adopted_from == origin.repo.key for x in dest.pipelines):
            continue
        cp = copy.deepcopy(p)
        cp.adopted_from = origin.repo.key
        dest.pipelines.append(cp)
        for r in rels:
            if not any(x.id == r.id and x.adopted_from == origin.repo.key for x in dest.releases):
                cr_ = copy.deepcopy(r)
                cr_.adopted_from = origin.repo.key
                dest.releases.append(cr_)


# --------------------------------------------------------------------------- orphans
def orphan_build(raw: dict[str, Any], project: str, base_web: str, reason: str) -> LOrphan:
    url = ((raw.get("_links") or {}).get("web") or {}).get("href") or f"{base_web.rstrip('/')}/_build?definitionId={raw.get('id')}"
    return LOrphan(type="pipeline", project=project, id=str(raw.get("id")), name=str(raw.get("name") or "")[:MAX_TEXT], url=url, reason=reason)


def orphan_release(raw: dict[str, Any], project: str, base_web: str, known_build_ids: set[str]) -> LOrphan:
    arts = [a for a in raw.get("artifacts") or [] if isinstance(a, dict)]
    if not arts:
        reason = "release has no artifact source (no linked build)"
    else:
        builds = [a for a in arts if a.get("type") == "Build"]
        if builds:
            d = (builds[0].get("definitionReference") or {}).get("definition") or {}
            reason = f"artifact source build '{str(d.get('name') or d.get('id'))[:60]}' is not a build definition of a scanned repository"
            if str(d.get("id")) in known_build_ids:
                reason = "artifact source build exists but its repository could not be resolved"
        else:
            reason = f"artifact source type {', '.join(sorted({str(a.get('type')) for a in arts}))} cannot be linked to a repository"
    url = ((raw.get("_links") or {}).get("web") or {}).get("href") or f"{base_web.rstrip('/')}/_release?definitionId={raw.get('id')}"
    return LOrphan(type="release", project=project, id=str(raw.get("id")), name=str(raw.get("name") or "")[:MAX_TEXT], url=url, reason=reason)
