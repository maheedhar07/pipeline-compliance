"""SUP: build integrity and supply chain."""

from __future__ import annotations

import re

from pch.engine.helpers import SCRIPT_TASKS, step_blob
from pch.engine.registry import rule
from pch.model.findings import RuleResult
from pch.model.pipeline import Pipeline
from pch.model.repo import RepoContext
from pch.settings import Policy

LATEST = re.compile(r":latest\b", re.I)
ACR = re.compile(r"\b([a-z0-9]+\.azurecr\.io)\b", re.I)
IMMUTABLE = re.compile(r"@sha256:|\$\((Build\.BuildId|Build\.BuildNumber|Build\.SourceVersion|Build\.BuildId)\)|\$\{\{\s*variables\['Build|\$\(tag\)|\$\(imageTag\)", re.I)


@rule(
    "SUP-001", "Build once, promote everywhere (no rebuild per environment)", "high", "pipeline",
    "Rebuilding per environment means what was tested is not what is deployed.",
    {"classic": "Link the release to a single build artifact and remove build/publish tasks from release stages.",
     "yaml": "Build and publish an artifact in the build stage; deployment stages must only download and deploy it."},
)
def sup_001(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    if p.platform == "ado_classic_build":
        return RuleResult.na("build-only definition")
    deploy_stages = [s for s in p.stages if s.is_deploy]
    if not deploy_stages:
        return RuleResult.na("no deployment stages")
    if p.platform == "ado_classic_release" and not p.linked_build_ids:
        return RuleResult.failed("release has no linked build artifact")
    rebuilt = [s.name for s in deploy_stages if "build" in s.capabilities()]
    if rebuilt:
        return RuleResult.failed(f"build steps found in deployment stage(s): {rebuilt}", stages=rebuilt)
    return RuleResult.passed("deployment stages consume the build artifact without rebuilding")


@rule(
    "SUP-002", "Task major versions are pinned and not deprecated", "medium", "pipeline",
    "Unpinned tasks change behaviour silently; deprecated tasks stop receiving fixes.",
    {"classic": "Pin each task to a major version (e.g. 2.*) and upgrade deprecated tasks.",
     "yaml": "Use Task@<major> and replace deprecated tasks (see data/deprecated_tasks.yaml)."},
)
def sup_002(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    tasks = [s for s in p.all_steps() if s.task and s.task.split("@")[0].lower() not in SCRIPT_TASKS and s.enabled]
    if not tasks:
        return RuleResult.na("no task steps")
    unpinned = sorted({s.task.split("@")[0] for s in tasks if s.task_version is None})
    deprecated = sorted({s.task for s in tasks if s.deprecated})
    if unpinned or deprecated:
        msg = []
        if unpinned:
            msg.append(f"unpinned: {', '.join(unpinned)}")
        if deprecated:
            msg.append(f"deprecated: {', '.join(deprecated)}")
        return RuleResult.failed("; ".join(msg), unpinned=unpinned, deprecated=deprecated)
    return RuleResult.passed(f"{len(tasks)} tasks pinned and current")


@rule(
    "SUP-003", "Marketplace tasks are on the allowlist", "medium", "pipeline",
    "Third-party tasks run with the pipeline's credentials; only reviewed extensions should be used.",
    {"any": "Replace the task, or have the extension reviewed and add it to marketplace_task_allowlist in config/policy.yaml."},
)
def sup_003(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    allow = {a.lower() for a in policy.marketplace_task_allowlist}
    market = sorted({s.task.split("@")[0] for s in p.all_steps() if s.marketplace and s.task and s.enabled})
    bad = [m for m in market if m.lower() not in allow]
    if bad:
        return RuleResult.failed("non-allowlisted marketplace tasks: " + ", ".join(bad), tasks=bad)
    return RuleResult.passed("no non-allowlisted marketplace tasks", marketplace_tasks=market)


@rule(
    "SUP-004", "AKS images come from an approved ACR and are never :latest", "high", "pipeline",
    "Mutable tags make deployments non-reproducible; unapproved registries bypass vulnerability scanning.",
    {"any": "Push to the approved ACR and deploy by digest (@sha256) or an immutable tag such as $(Build.BuildId). Never use :latest."},
    targets={"aks"},
)
def sup_004(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    blobs = [step_blob(s) for s in p.all_steps() if s.enabled]
    text = " ".join(blobs)
    tags_inputs = [str(s.inputs.get("tags", "")) for s in p.all_steps() if s.enabled]
    latest = bool(LATEST.search(text)) or any("latest" in t.lower().split() or t.strip().lower() == "latest" for t in tags_inputs)
    registries = sorted({m.lower() for m in ACR.findall(text)})
    approved = {r.lower() for r in policy.approved_registries}
    bad_reg = [r for r in registries if approved and r not in approved]
    ev = {"registries": registries, "uses_latest": latest}
    if latest:
        return RuleResult.failed("image tag ':latest' is used", **ev)
    if bad_reg:
        return RuleResult.failed(f"image registry not approved: {bad_reg}", approved=sorted(approved), **ev)
    if not IMMUTABLE.search(text):
        return RuleResult.warn("no digest or build-id based immutable tag found", **ev)
    return RuleResult.passed("images are pinned to a digest/immutable tag from an approved registry", **ev)


@rule(
    "SUP-005", "An SBOM is generated", "low", "pipeline",
    "An SBOM makes it possible to answer 'are we affected?' when a new CVE lands.",
    {"classic": "Add the SBOM Generator task or a syft/cyclonedx step.",
     "yaml": "Add sbom-tool / ManifestGenerator, or 'syft packages' to the build."},
)
def sup_005(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    if p.platform == "ado_classic_release":
        return RuleResult.na("release definition")
    if "sbom" in p.capabilities():
        return RuleResult.passed("SBOM generation step present")
    return RuleResult.failed("no SBOM generation step")

