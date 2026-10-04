"""Async scan orchestration: collect -> normalize -> classify -> rules -> score -> persist.

One failing repo or source never aborts the scan: it becomes a collection error (and an info-level
COLLECTION-ERROR finding) while everything else continues.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from pch.collectors.ado.classic_build import normalize_build_definition
from pch.collectors.ado.classic_release import normalize_release_definition
from pch.collectors.ado.deployments import (
    EnvRecordCache,
    collect_release_deployments,
    collect_yaml_deployments,
)
from pch.collectors.ado.environments import apply_environment_checks, collect_environments
from pch.collectors.ado.lineage_meta import YamlMeta, parse_yaml_meta
from pch.collectors.ado.repo_discovery import Discovery, RepoEntry, discover
from pch.collectors.ado.repo_policies import collect_policy_configurations, policies_for_repo
from pch.collectors.ado.runs import collect_build_runs, collect_release_runs
from pch.collectors.ado.service_conn import collect_service_connections
from pch.collectors.ado.task_catalog import TaskCatalog, load_task_catalog
from pch.collectors.ado.variable_groups import collect_variable_groups
from pch.collectors.ado.yaml_pipeline import parse_yaml_pipeline
from pch.collectors.github.actions import read_actions
from pch.collectors.github.discovery import list_org_repos
from pch.collectors.github.reader import RepoRead, read_repo
from pch.collectors.redact import SECRET_NAME, value_looks_secret
from pch.engine.migration import migration_summary, repo_readiness
from pch.engine.reasons import compute_reasons
from pch.engine.registry import all_rules, rule_params
from pch.engine.runner import evaluate, policy_effects
from pch.engine.scoring import apply_waivers, score_repo
from pch.logging_setup import bind_scan, scrub
from pch.model.findings import Finding, Severity, Status
from pch.model.gha import ActionsRead
from pch.model.lineage import LDeploy, LOrphan, RepoLineage
from pch.model.pipeline import Pipeline
from pch.model.repo import (
    AikidoFacts,
    BranchPolicies,
    BranchProtection,
    RepoContext,
    RepoFacts,
    RepoRef,
    ServiceConnection,
    SnowFacts,
    SonarFacts,
    TestState,
    VariableGroup,
)
from pch.normalize.gha import build_lineage as build_gha_lineage
from pch.normalize.gha import build_pipelines as build_gha_pipelines
from pch.normalize.lineage import (
    build_repo_lineage,
    is_deploy_stage,
    link_lineages,
    orphan_build,
    orphan_release,
)
from pch.normalize.target_detect import enrich_pipeline
from pch.repo_scan.external import infer_external_kind, unavailable_facts
from pch.repo_scan.files import fetch_contents, fetch_file, fetch_tree, select_content_paths
from pch.repo_scan.tests_detect import analyze_repo, classify_test_state
from pch.scanrun import REASON_INTERRUPTED, REASON_TIMEOUT, ScanTimeout
from pch.settings import Policy, Scope
from pch.sources import Sources
from pch.store import repository as store
from pch.store.db import session_scope
from pch.store.models import CollectionErrorRow, FindingRow, LineageRow, RepoResultRow
from pch.timeutil import utcnow, utcnow_naive

log = logging.getLogger("pch.scan")


@dataclass
class ScanConfig:
    scope: Scope
    policy: Policy
    db_url: str
    mode: str = "live"  # live | demo | cache
    now: datetime = field(default_factory=utcnow_naive)  # naive UTC (domain convention, see pch.timeutil)
    concurrency: int = 16
    run_days: int = 90
    stale_after: timedelta = timedelta(hours=6)  # `running` scans older than this are orphans of a crashed process
    timeout_s: float | None = None  # overall limit for one scan (SCAN_TIMEOUT_MINUTES); None = unlimited
    lineage: bool = True  # collect the last deployment per stage (LINEAGE_ENABLED); False: stages are "unknown"
    lineage_top: int = 200  # deployments / environment records per lookup (LINEAGE_DEPLOYMENTS_TOP)


@dataclass
class ScanResult:
    scan_id: str
    repos: int
    findings: int
    errors: int
    duration_s: float
    status_counts: dict[str, int]


@dataclass
class _ProjectData:
    name: str
    repos: list[dict[str, Any]] = field(default_factory=list)  # raw Azure Repos repositories
    disc: Discovery = field(default_factory=lambda: Discovery([], {}, {}, []))
    build_defs: list[dict[str, Any]] = field(default_factory=list)
    release_defs: list[dict[str, Any]] = field(default_factory=list)
    policies: list[dict[str, Any]] = field(default_factory=list)
    conns: dict[str, ServiceConnection] = field(default_factory=dict)
    groups: dict[str, VariableGroup] = field(default_factory=dict)
    envs: dict[str, Any] = field(default_factory=dict)


def sanitize_for_storage(p: Pipeline) -> dict[str, Any]:
    """Pipeline JSON for the DB: no script bodies, no secret-looking input values (never persist secrets)."""
    for st in p.stages:
        for step in st.steps():
            kept: dict[str, Any] = {}
            for k, v in step.inputs.items():
                if SECRET_NAME.search(k) or not isinstance(v, str | int | float | bool) or value_looks_secret(v):
                    continue
                kept[k] = v[:120] if isinstance(v, str) else v
            step.inputs = kept
            step.inline_script = "<script omitted>" if step.inline_script else None
    return p.model_dump(mode="json")


class Scanner:
    def __init__(self, sources: Sources, cfg: ScanConfig, progress: Callable[[int, int], None] | None = None):
        self.src = sources
        self.cfg = cfg
        self.progress = progress
        self.errors: list[tuple[str, str, str]] = []  # (source, subject, message)
        self.catalog = TaskCatalog()
        self.aikido_data: tuple[list, list] | None = None
        self.rules = all_rules()
        self.yaml_meta: dict[str, YamlMeta] = {}  # "<project>:<definition id>" -> triggers/resources parsed from the expanded YAML
        self.lineages: dict[str, RepoLineage] = {}  # repo key -> lineage
        self.orphans: dict[str, list[LOrphan]] = {}  # project -> unlinked pipelines / releases
        self.env_records = EnvRecordCache(sources.ado, cfg.lineage_top)
        self.gh_listing: dict[str, dict[str, Any]] = {}  # "org/repo" (casefold) -> record of the GitHub organisation listing

    def err(self, source: str, subject: str, exc: BaseException | str) -> None:
        msg = scrub(f"{type(exc).__name__}: {exc}" if isinstance(exc, BaseException) else exc)  # persisted: never a secret
        self.errors.append((source, subject, msg[:400]))
        log.warning("collection error [%s] %s: %s", source, subject, msg)

    # ------------------------------------------------------------------ project level
    async def collect_project(self, name: str) -> _ProjectData:
        ado = self.src.ado
        pd = _ProjectData(name)
        hosts = self.cfg.scope.hosts()
        if "azure_repos" in hosts:  # Azure Repos is not a code host unless scope.yaml says so: its API is not even called
            try:
                pd.repos = await ado.repositories(name)
            except Exception as e:  # externally hosted repos are still discoverable through the pipelines
                self.err("ado", f"{name}: repositories", e)
        try:
            listing = await ado.paged(name, "_apis/build/definitions", {"includeAllProperties": "true"})
            details = await asyncio.gather(*(ado.get(name, f"_apis/build/definitions/{d['id']}") for d in listing), return_exceptions=True)
            for d, det in zip(listing, details, strict=True):
                if isinstance(det, BaseException):
                    self.err("ado", f"{name}: build definition {d.get('id')}", det)
                else:
                    pd.build_defs.append(det)
        except Exception as e:
            self.err("ado", f"{name}: build definitions", e)
        try:
            rl = await ado.paged(name, "_apis/release/definitions", {"$expand": "environments,artifacts"}, vsrm=True)
            rdet = await asyncio.gather(*(ado.get(name, f"_apis/release/definitions/{d['id']}", vsrm=True) for d in rl), return_exceptions=True)
            for d, det in zip(rl, rdet, strict=True):
                if isinstance(det, BaseException):
                    self.err("ado", f"{name}: release definition {d.get('id')}", det)
                else:
                    pd.release_defs.append(det)
        except Exception as e:
            self.err("ado", f"{name}: release definitions", e)
        for attr, label, fn in (
            ("policies", "branch policies", collect_policy_configurations),
            ("conns", "service connections", collect_service_connections),
            ("groups", "variable groups", collect_variable_groups),
            ("envs", "environments", collect_environments),
        ):
            try:
                setattr(pd, attr, await fn(ado, name))
            except Exception as e:
                self.err("ado", f"{name}: {label}", e)
        known = [o.repo for o in self.cfg.scope.repos if o.project == name]  # "org/repo" names listed in scope.yaml
        pd.disc = discover(pd.repos, pd.build_defs, pd.release_defs, hosts, known)
        if summary := pd.disc.out_of_scope_summary(hosts):
            self.err("ado", f"{name}: code hosts", summary)
        return pd

    async def github_groups(self, pdatas: list[_ProjectData]) -> list[_ProjectData]:
        """GitHub repos that no ADO project already holds: the organisation listing (scope.yaml ``github:``) plus ``repos:`` entries whose
        project is not an ADO project. Grouped by GitHub organisation (the "project" of a repo without an ADO pipeline), key ``<org>/<org>/<repo>``;
        a ``repos:`` entry with a ``project`` groups its repo under that name instead."""
        gh, cfg = self.src.github, self.cfg
        gs = cfg.scope.github
        if gh is None:
            if gs.orgs:
                self.err("github", "organisation discovery", "info: scope.yaml github.orgs is set but no GitHub reader is configured (GITHUB_TOKEN or a GitHub App); those repos are not discovered")
            return []
        provider = "github" if gh.is_github_com else "github_enterprise"
        if provider not in cfg.scope.hosts():
            self.err("github", "organisation discovery", f"info: the GitHub reader is configured but code_hosts does not list '{provider}'; GitHub repos are only read for what ADO pipelines reference")
            return []
        known = {r.name.casefold() for pd in pdatas for r in pd.disc.repos if r.provider in ("github", "github_enterprise")}
        groups: dict[str, list[RepoEntry]] = {}

        def add(group: str, full: str, url: str = "", branch: str = "") -> None:
            if "/" in full and full.casefold() not in known:
                known.add(full.casefold())
                groups.setdefault(group, []).append(RepoEntry(provider=provider, id=full, name=full, url=url, default_branch=branch))  # type: ignore[arg-type]

        ado_projects = {pd.name for pd in pdatas}
        for o in cfg.scope.repos:
            if o.project not in ado_projects:
                add(o.project, o.repo.strip("/"), f"https://github.com/{o.repo.strip('/')}" if gh.is_github_com else "")
        for org in gs.orgs:
            try:
                listed = await list_org_repos(gh, org, gs)
            except Exception as e:  # noqa: BLE001 - one organisation failing must not stop the scan
                self.err("github", f"{org}: repository listing", e)
                continue
            for raw in listed:
                full = str(raw["full_name"])
                self.gh_listing[full.casefold()] = raw
                add(org, full, str(raw.get("html_url") or ""), str(raw.get("default_branch") or ""))
        return [_ProjectData(name, disc=Discovery(entries, {}, {}, [])) for name, entries in groups.items()]

    # ------------------------------------------------------------------ repo level
    async def scan_repo(self, pd: _ProjectData, repo: RepoEntry, builds: list[dict[str, Any]], releases: list[dict[str, Any]]):
        cfg, ado = self.cfg, self.src.ado
        project = pd.name
        branch = (repo.default_branch or "refs/heads/main").removeprefix("refs/heads/")
        ov = cfg.scope.override_for(project, repo.name)
        ref = RepoRef(
            id=repo.id, name=repo.name, project=project, url=repo.url or ado.web_url(project, f"_git/{repo.name}"),
            default_branch=branch, owner=ov.owner if ov else None, sonar_key=ov.sonar_key if ov else None,
            aikido_repo=ov.aikido_repo if ov else None, servicenow_ci=ov.servicenow_ci if ov else None,
            coverage_threshold=ov.coverage_threshold if ov else None, disabled=repo.disabled,
            provider=repo.provider, full_name=repo.name if repo.external else "", service_connection_id=repo.service_connection_id,
        )
        repo_errors: list[tuple[str, str]] = []

        def rerr(source: str, exc: Exception | str) -> None:
            msg = scrub(f"{type(exc).__name__}: {exc}" if isinstance(exc, Exception) else exc)  # persisted: never a secret
            repo_errors.append((source, msg[:300]))
            self.err(source, ref.key, exc)

        # 1. repo files -> facts. Externally hosted repos are not in Azure Repos: the Items API does not apply, the facts
        #    stay "unavailable" (not "empty") until a reader for that host provides them.
        facts: RepoFacts
        protection: BranchProtection | None = None
        gh: RepoRead | None = None
        actions: ActionsRead | None = None
        if ref.external and self.src.github is not None and ref.provider in ("github", "github_enterprise"):
            gh = await read_repo(self.src.github, ref.name, known=self.gh_listing.get(ref.name.casefold()))
            facts, protection = gh.facts, gh.protection
            for msg in gh.errors:
                rerr("github", msg)
            if gh.default_branch:
                branch = ref.default_branch = gh.default_branch
            if gh.web_url and not ref.url:
                ref.url = gh.web_url
            if ref.owner is None and gh.owner:
                ref.owner = gh.owner  # CODEOWNERS default rule; scope.yaml owner wins
            if gh.default_branch:  # GitHub Actions: workflows, environments, runs, last deployments (read-only; failures are reasons, never FAIL)
                try:
                    actions = await read_actions(self.src.github, ref.name, gh.default_branch, now=cfg.now, run_days=cfg.run_days,
                                                 known_paths=facts.pipeline_files, with_deployments=cfg.lineage)
                    for msg in actions.errors:
                        rerr("github", msg)
                except Exception as e:  # noqa: BLE001 - never aborts the repo
                    rerr("github", f"GitHub Actions not read: {e}")
        elif ref.external:
            facts = unavailable_facts(ref.provider)
        else:
            facts = analyze_repo(None)
            try:
                paths = await fetch_tree(ado, project, ref.id, branch)
                if paths:
                    contents = await fetch_contents(ado, project, ref.id, branch, select_content_paths(paths))
                    facts = analyze_repo(paths, contents)
            except Exception as e:
                rerr("ado", e)

        tier_over = {**cfg.scope.env_tiers, **(ov.env_tiers if ov else {})}
        adf_only = facts.adf and not facts.iac
        pipelines: list[Pipeline] = []
        base_web = ado.web_url(project, "")
        # 2. build pipelines (classic + yaml)
        by_build_id: dict[str, Pipeline] = {}
        for d in builds:
            try:
                if (d.get("process") or {}).get("type") == 2:
                    p = await self.yaml_pipeline(d, project, base_web, ref, branch)
                else:
                    p = normalize_build_definition(d, self.catalog, project, base_web, raw_ref=f"build/{d['id']}")
                p.repo, p.repo_id = ref.name, ref.id
                by_build_id[p.id] = p
                pipelines.append(p)
            except Exception as e:
                rerr("ado", f"build definition {d.get('id')}: {e}")
        for d in releases:
            try:
                p = normalize_release_definition(d, self.catalog, project, base_web, {k: v.name for k, v in pd.groups.items() if k.isdigit()}, raw_ref=f"release/{d['id']}")
                p.repo, p.repo_id = ref.name, ref.id
                pipelines.append(p)
            except Exception as e:
                rerr("ado", f"release definition {d.get('id')}: {e}")
        for p in pipelines:
            self.catalog.annotate(p)
            enrich_pipeline(p, adf_only, facts.synapse and not facts.iac, tier_over)
            apply_environment_checks(p, pd.envs)
        if ref.external and facts.facts_source == "unavailable":
            inferred = infer_external_kind(pipelines)  # data-platform / IaC repos are recognisable from what they deploy
            if inferred:
                facts.kind, facts.has_app_code = inferred, False
        # 3. run history
        since = cfg.now - timedelta(days=cfg.run_days)
        crq = re.compile(rule_params(cfg.policy, "DEP-005")["crq_pattern"], re.I)  # change-request number format (policy rules.DEP-005.params)
        build_runs: dict[str, list[dict[str, Any]]] = {}
        for p in pipelines:
            try:
                if p.platform == "ado_classic_release":
                    await collect_release_runs(ado, project, p, since, crq)
                else:
                    build_runs[p.id] = await collect_build_runs(ado, project, p, since, crq)
            except Exception as e:
                rerr("ado", f"runs for {p.name}: {e}")
        # 3a. GitHub Actions workflows join the pipelines (same rules; ADO run history above does not apply to them)
        gha_pipes: list[Pipeline] = []
        unreadable: list[str] = []
        if actions is not None:
            snow_pattern = rule_params(cfg.policy, "DEP-003")["servicenow_app_pattern"]
            gha_pipes, unreadable = build_gha_pipelines(actions, project=project, repo=ref.name, tier_overrides=tier_over, snow_pattern=snow_pattern,
                                                        repo_is_adf=adf_only, repo_is_synapse=facts.synapse and not facts.iac)
            for p in gha_pipes:
                p.repo, p.repo_id = ref.name, ref.id
            pipelines.extend(gha_pipes)
            for u in unreadable:
                rerr("github", f"workflow content not usable: {u}")
        # 3b. lineage (what this repo produces and where it was last deployed); never fails the repo
        try:
            lin = await self.repo_lineage(pd, ref, pipelines, builds, releases, build_runs)
            if gha_pipes and actions is not None:
                lin.pipelines.extend(build_gha_lineage(gha_pipes, ref, actions.deployments, collected=cfg.lineage))
            self.lineages[ref.key] = lin
        except Exception as e:  # noqa: BLE001 - fail open: the repo is scanned, its lineage is missing
            self.err("lineage", ref.key, e)
        # 4. Sonar
        sonar: SonarFacts | None = None
        if self.src.sonar is not None and facts.kind not in ("docs",):
            try:
                keys = [k for k in (ref.sonar_key, f"{project}_{ref.name}", ref.name) if k]
                if ref.external:  # Sonar projects are usually named after the repo, not "org/repo"
                    keys += [k for k in (f"{project}_{ref.short_name}", ref.short_name, ref.name.replace("/", "_")) if k not in keys]
                sonar = await self.src.sonar.first_found(keys)
            except Exception as e:
                rerr("sonar", e)
        # 5. Aikido
        aikido: AikidoFacts | None = None
        if self.aikido_data is not None:
            from pch.collectors.aikido import AikidoClient

            aikido = AikidoClient.facts_for(ref.name, self.aikido_data[0], self.aikido_data[1], ref.aikido_repo)
            if ref.external and not aikido.onboarded and not ref.aikido_repo:  # Aikido may list it as "repo" instead of "org/repo"
                aikido = AikidoClient.facts_for(ref.short_name, self.aikido_data[0], self.aikido_data[1])
        # 6. ServiceNow
        snow = SnowFacts()
        if self.src.snow is not None and any(p.deployments_90d for p in pipelines):
            try:
                numbers = sorted({r for p in pipelines for d in p.deployments_90d for r in d.change_refs})
                changes = await self.src.snow.by_numbers(numbers)
                ci_changes = await self.src.snow.by_ci(ref.servicenow_ci, since) if ref.servicenow_ci else []
                snow = SnowFacts(available=True, changes=changes, ci_changes=ci_changes)
            except Exception as e:
                rerr("servicenow", e)
        # 7. test state
        threshold = ref.coverage_threshold or cfg.policy.coverage_threshold
        state, reason, cov = classify_test_state(facts, pipelines, sonar, threshold)
        if state == TestState.TESTS_NOT_RUN and (unreadable or any(p.meta.get("unresolved") for p in gha_pipes)):
            state, reason = TestState.UNKNOWN, "tests exist but a pipeline that might run them could not be fully read (see the collection errors)"
        facts.test_state, facts.test_state_reason, facts.coverage = state, reason, cov
        # 8. rules
        if ref.external:  # ADO branch policies cover Azure Repos only; GitHub branch protection comes from the GitHub reader (ctx.protection)
            policies = BranchPolicies(available=False, unavailable_reason=facts.facts_reason or "GitHub-hosted: Azure DevOps branch policies do not apply")
        else:
            policies = policies_for_repo(pd.policies, ref.id, branch)
            if not pd.policies:
                policies.available = False  # policies were not collected for this project
        ctx = RepoContext(
            repo=ref, pipelines=pipelines, facts=facts, policies=policies, protection=protection,
            sonar=sonar, aikido=aikido, snow=snow, service_connections=pd.conns, variable_groups=pd.groups, environments=pd.envs, unreadable=unreadable, now=cfg.now,
        )
        findings = evaluate(ctx, cfg.policy, self.rules)
        apply_waivers(findings, ref.key, cfg.policy, cfg.now.date())
        sc = score_repo(findings, cfg.policy)
        mig_score, blockers = repo_readiness(ctx)
        for source, msg in repo_errors:
            findings.append(Finding(rule_id="COLLECTION-ERROR", repo_key=ref.key, category="SYS", severity=Severity.INFO,
                                    status=Status.UNKNOWN, message=f"{source}: {msg}", evidence={"source": source}))
        return ctx, findings, sc, mig_score, blockers

    async def yaml_pipeline(self, d: dict[str, Any], project: str, base_web: str, ref: RepoRef, branch: str) -> Pipeline:
        ado = self.src.ado
        text: str | None = None
        try:
            text = (await ado.post_preview(project, d["id"])).get("finalYaml")
        except Exception as e:
            self.err("ado", f"{ref.key}: YAML preview for pipeline {d['id']} failed, falling back to the raw file", e)
        if not text and ref.external:  # the Items API only serves Azure Repos; the preview (via the service connection) was the one way
            raise RuntimeError(f"YAML definition could not be retrieved ({ref.provider} repository: Azure Repos file fallback does not apply)")
        if not text:
            fname = (d.get("process") or {}).get("yamlFilename", "azure-pipelines.yml")
            text = await fetch_file(ado, project, ref.id, branch, fname)
        if not text:
            raise RuntimeError("YAML definition could not be retrieved")
        meta = parse_yaml_meta(text, external_pr_default=ref.external)
        if meta is not None:
            self.yaml_meta[f"{project}:{d['id']}"] = meta
        return parse_yaml_pipeline(text, d, project, base_web, raw_ref=f"pipeline/{d['id']}")

    async def repo_lineage(self, pd: _ProjectData, ref: RepoRef, pipelines: list[Pipeline], builds: list[dict[str, Any]], releases: list[dict[str, Any]],
                           build_runs: dict[str, list[dict[str, Any]]]) -> RepoLineage:
        """Collect the last deployment per stage (read-only) and assemble the repo's lineage document."""
        ado, project, cfg = self.src.ado, pd.name, self.cfg
        deploys: dict[str, dict[str, LDeploy]] = {}
        notes: list[str] = []

        def lerr(msg: str) -> None:
            self.err("ado", f"{ref.key}: lineage", msg)

        rel_raw = {str(d.get("id")): d for d in releases}
        env_ids = {name: e.id for name, e in pd.envs.items()}

        async def classic(p: Pipeline) -> None:
            raw_envs = rel_raw.get(p.id, {}).get("environments") or []
            ids = {str(e["name"]): str(e["id"]) for e in raw_envs if e.get("name") and e.get("id") is not None}
            try:
                deploys[f"{p.platform}:{p.id}"] = await collect_release_deployments(ado, project, p.id, ids, cfg.lineage_top, lerr)
            except Exception as e:  # noqa: BLE001
                lerr(f"release {p.name}: last deployments not collected: {type(e).__name__}: {e}")
                notes.append(f"last deployments of release '{p.name}' could not be collected")

        async def yaml(p: Pipeline) -> None:
            stage_envs = {st.name: st.env_name for st in p.stages if is_deploy_stage(st) and st.env_name}
            if not stage_envs:
                return
            deploys[f"{p.platform}:{p.id}"] = await collect_yaml_deployments(ado, project, p.id, stage_envs, env_ids, self.env_records, build_runs.get(p.id, []), lerr)

        if cfg.lineage:
            jobs = [classic(p) if p.platform == "ado_classic_release" else yaml(p) for p in pipelines if p.platform in ("ado_classic_release", "ado_yaml")]
            await asyncio.gather(*jobs)
        meta = {p.id: m for p in pipelines if (m := self.yaml_meta.get(f"{project}:{p.id}")) is not None}
        return build_repo_lineage(ref, pipelines, builds, releases, meta, deploys, build_runs, pd.conns, collected=cfg.lineage, notes=notes)

    def collect_orphans(self, pd: _ProjectData) -> None:
        base_web = self.src.ado.web_url(pd.name, "")
        known = {str(b.get("id")) for b in pd.build_defs}
        items = [orphan_build(b, pd.name, base_web, why) for b, why in pd.disc.unlinked_builds]
        items += [orphan_release(r, pd.name, base_web, known) for r in pd.disc.unlinked_releases]
        if items:
            self.orphans[pd.name] = items

    # ------------------------------------------------------------------ whole scan
    async def run(self, scan_id: str) -> ScanResult:
        """Run a scan. The scan row is created ``running`` first; results are then written in ONE transaction
        together with ``status=complete``. Any failure (including cancellation) rolls that back and the scan row
        is marked ``failed``, so a scan is never left ``running`` by an error."""
        cfg = self.cfg
        with bind_scan(scan_id):
            with session_scope(cfg.db_url) as s:
                store.fail_orphaned_scans(s, cfg.stale_after, exclude=scan_id)
                store.create_scan(s, scan_id, cfg.mode, cfg.now)
            log.info("scan started (mode=%s)", cfg.mode)
            limit = asyncio.timeout(cfg.timeout_s)
            try:
                async with limit:
                    return await self._run(scan_id)
            except BaseException as exc:
                timed_out = isinstance(exc, TimeoutError) and limit.expired()
                if timed_out:
                    reason = f"{REASON_TIMEOUT}: exceeded {cfg.timeout_s / 60:g} minutes" if cfg.timeout_s else REASON_TIMEOUT
                elif isinstance(exc, asyncio.CancelledError):
                    reason = REASON_INTERRUPTED
                else:
                    reason = scrub(f"{type(exc).__name__}: {exc}")  # persisted in scans.summary: never a secret
                try:
                    with session_scope(cfg.db_url) as s:
                        store.mark_failed(s, scan_id, reason)
                except Exception:  # noqa: BLE001 - keep the original error; orphan cleanup recovers the row
                    log.exception("could not mark scan %s as failed", scan_id)
                log.error("scan failed: %s", reason)
                if timed_out:
                    raise ScanTimeout(reason) from None
                raise

    async def _run(self, scan_id: str) -> ScanResult:
        t0 = time.time()
        cfg = self.cfg
        projects = list(cfg.scope.projects)
        if not projects:
            try:
                projects = [p["name"] for p in await self.src.ado.projects()]
            except Exception as e:
                self.err("ado", "projects", e)
        try:
            self.catalog = await load_task_catalog(self.src.ado, projects)
        except Exception as e:
            self.err("ado", "task catalog", e)
        if self.src.aikido is not None:
            try:
                self.aikido_data = await self.src.aikido.fetch_all()
            except Exception as e:
                self.err("aikido", "organisation fetch", e)
        pdatas = list(await asyncio.gather(*(self.collect_project(p) for p in projects)))
        pdatas += await self.github_groups(pdatas)
        jobs = []
        excluded = {x.casefold() for x in cfg.scope.exclude_repos}
        for pd in pdatas:
            for r in pd.disc.unlinked_releases:
                self.err("ado", f"{pd.name}: release {r.get('name')}", "release is not linked to a build definition in a known repo (skipped)")
            for repo in pd.disc.repos:
                key = f"{pd.name}/{repo.name}"
                if key.casefold() in excluded:
                    continue
                if repo.disabled:
                    self.err("ado", key, "repository is disabled (skipped)")
                    continue
                jobs.append((pd, repo, pd.disc.builds_by_repo.get(repo.link_key, []), pd.disc.releases_by_repo.get(repo.link_key, [])))
        total = len(jobs)
        sem = asyncio.Semaphore(cfg.concurrency)
        done = 0
        results: list[Any] = []

        async def one(job):
            nonlocal done
            pd, repo, builds, releases = job
            async with sem:
                try:
                    out = await self.scan_repo(pd, repo, builds, releases)
                except Exception as e:  # last-resort: never abort the scan
                    self.err("scan", f"{pd.name}/{repo.name}", e)
                    out = (pd.name, repo, e)
            done += 1
            if self.progress and (done % 25 == 0 or done == total):
                self.progress(done, total)
            return out

        results = await asyncio.gather(*(one(j) for j in jobs))
        for pd in pdatas:
            self.collect_orphans(pd)
        try:
            link_lineages(sorted(self.lineages.values(), key=lambda lin: lin.repo.key))
        except Exception as e:  # noqa: BLE001 - downstream/adoption links are an enrichment
            self.err("lineage", "linking pipelines across repositories", e)
        return self.persist(scan_id, results, t0)

    # ------------------------------------------------------------------ persistence
    def persist(self, scan_id: str, results: list[Any], t0: float) -> ScanResult:
        cfg = self.cfg
        n_findings = 0
        counts: Counter[str] = Counter()
        failed = 0
        cat_fail: Counter[str] = Counter()
        providers: set[str] = set()
        with session_scope(cfg.db_url) as s:
            for out in results:
                if len(out) == 3:  # hard failure
                    project, repo, exc = out
                    failed += 1
                    providers.add(repo.provider)
                    s.add(RepoResultRow(scan_id=scan_id, repo_key=f"{project}/{repo.name}", project=project, repo=repo.name, status="NOT_SCANNED", test_state="NOT_APPLICABLE",
                                        external={"repo": {"provider": repo.provider, "full_name": repo.name if repo.external else "", "service_connection_id": repo.service_connection_id}}))
                    s.add(FindingRow(scan_id=scan_id, repo_key=f"{project}/{repo.name}", rule_id="COLLECTION-ERROR", category="SYS", severity="info", status="UNKNOWN", message=scrub(str(exc))[:300]))
                    counts["NOT_SCANNED"] += 1
                    continue
                ctx, findings, sc, mig_score, blockers = out
                counts[sc.status.value] += 1
                providers.add(ctx.repo.provider)
                kinds = sorted({p.platform for p in ctx.pipelines})
                targets = sorted({t for p in ctx.pipelines for t in p.deploy_targets})
                s.add(RepoResultRow(
                    scan_id=scan_id, repo_key=ctx.repo.key, project=ctx.repo.project, repo=ctx.repo.name, url=ctx.repo.url, owner=ctx.repo.owner,
                    platform_mix=kinds, targets=targets, test_state=ctx.facts.test_state.value, test_state_reason=ctx.facts.test_state_reason,
                    coverage=ctx.facts.coverage, sonar_gate=ctx.sonar.gate_status if ctx.sonar and ctx.sonar.onboarded else None,
                    aikido_criticals=ctx.aikido.count("critical") if ctx.aikido and ctx.aikido.onboarded else None,
                    score=sc.score, status=sc.status.value, unknowns=sc.unknown, critical_fails=sc.critical_fails, high_fails=sc.high_fails,
                    migration_score=mig_score, migration_blockers=blockers,
                    facts=ctx.facts.model_dump(mode="json", exclude={"test_signals"}) | {"test_signals": ctx.facts.test_signals[:8]},
                    pipelines=[sanitize_for_storage(p) for p in ctx.pipelines], rule_status={k: v.value for k, v in sc.by_rule.items()},
                    external={
                        "sonar": ctx.sonar.model_dump(mode="json") if ctx.sonar else None,
                        "aikido": ({"onboarded": ctx.aikido.onboarded, "url": ctx.aikido.url, "open": {sev: ctx.aikido.count(sev) for sev in ("critical", "high", "medium", "low")}} if ctx.aikido else None),
                        "snow_available": ctx.snow.available,
                        "repo": {"provider": ctx.repo.provider, "full_name": ctx.repo.full_name, "service_connection_id": ctx.repo.service_connection_id},
                        "policies": ctx.policies.model_dump(mode="json"),
                        "protection": ctx.protection.model_dump(mode="json") if ctx.protection else None,
                        "migration": migration_summary(ctx.pipelines),
                        "reasons": compute_reasons(findings, self.rules),  # why the repo is not compliant (pages/exports read this)
                    },
                ))
                for f in findings:
                    n_findings += 1
                    if f.status == Status.FAIL:
                        cat_fail[f.category] += 1
                    s.add(FindingRow(
                        scan_id=scan_id, repo_key=f.repo_key, rule_id=f.rule_id, category=f.category, severity=f.severity.value, status=f.status.value,
                        pipeline_id=f.pipeline_id, pipeline_name=f.pipeline_name, stage=f.stage, message=f.message, evidence=_jsonable(f.evidence),
                        link=f.link, waiver=f.waiver.model_dump(mode="json") if f.waiver else None,
                        original_status=f.original_status.value if f.original_status else None,
                    ))
            store.insert_rows(s, LineageRow, lineage_row_dicts(scan_id, self.lineages, self.orphans))
            for source, subject, msg in self.errors:
                s.add(CollectionErrorRow(scan_id=scan_id, source=source, subject=subject, message=msg))
            row = store.get_scan(s, scan_id)
            duration = time.time() - t0
            if row is not None:
                row.finished_at = utcnow()
                row.status = "complete"
                row.repos_total = len(results)
                row.repos_failed = failed
                row.findings_total = n_findings
                row.duration_s = round(duration, 2)
                row.summary = {"status_counts": dict(counts), "category_fails": dict(cat_fail), "errors": len(self.errors), "providers": sorted(providers), "github_reader": self.src.github is not None,
                               "policy": policy_effects(cfg.policy, self.rules)}
        return ScanResult(scan_id, len(results), n_findings, len(self.errors), round(duration, 2), dict(counts))


def lineage_row_dicts(scan_id: str, lineages: dict[str, RepoLineage], orphans: dict[str, list[LOrphan]]) -> list[dict[str, Any]]:
    """Rows for the ``lineage`` table: one per repo, one per project that has unlinked items."""
    rows: list[dict[str, Any]] = []
    for key in sorted(lineages):
        lin = lineages[key]
        rows.append({
            "scan_id": scan_id, "repo_key": key, "kind": "repo", "project": lin.repo.project, "provider": lin.repo.provider, "has_prod": lin.has_prod,
            "n_pipelines": len(lin.pipelines), "n_releases": len(lin.releases), "targets": "," + ",".join(lin.targets) + ",", "tiers": "," + ",".join(lin.tiers) + ",",
            "doc": lin.model_dump(mode="json"),
        })
    for project in sorted(p for p in orphans if orphans[p]):
        rows.append({
            "scan_id": scan_id, "repo_key": f"{project}/(unlinked)", "kind": "orphan", "project": project, "provider": "azure_repos", "has_prod": False,
            "n_pipelines": sum(1 for o in orphans[project] if o.type == "pipeline"), "n_releases": sum(1 for o in orphans[project] if o.type == "release"),
            "targets": ",", "tiers": ",", "doc": {"orphans": [o.model_dump(mode="json") for o in orphans[project]]},
        })
    return rows


def _jsonable(d: dict[str, Any]) -> dict[str, Any]:
    import json

    return json.loads(json.dumps(d, default=str))

