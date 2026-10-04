"""Async scan orchestration: collect -> normalize -> classify -> rules -> score -> persist.

One failing repo or source never aborts the scan: it becomes a collection error (and an info-level
COLLECTION-ERROR finding) while everything else continues.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from pch.collectors.ado.classic_build import normalize_build_definition
from pch.collectors.ado.classic_release import normalize_release_definition
from pch.collectors.ado.environments import apply_environment_checks, collect_environments
from pch.collectors.ado.repo_policies import collect_policy_configurations, policies_for_repo
from pch.collectors.ado.runs import collect_build_runs, collect_release_runs
from pch.collectors.ado.service_conn import collect_service_connections
from pch.collectors.ado.task_catalog import TaskCatalog, load_task_catalog
from pch.collectors.ado.variable_groups import collect_variable_groups
from pch.collectors.ado.yaml_pipeline import parse_yaml_pipeline
from pch.collectors.redact import SECRET_NAME, value_looks_secret
from pch.engine.migration import repo_readiness
from pch.engine.registry import all_rules
from pch.engine.runner import evaluate
from pch.engine.scoring import apply_waivers, score_repo
from pch.logging_setup import bind_scan
from pch.model.findings import Finding, Severity, Status
from pch.model.pipeline import Pipeline
from pch.model.repo import (
    AikidoFacts,
    RepoContext,
    RepoRef,
    ServiceConnection,
    SnowFacts,
    SonarFacts,
    VariableGroup,
)
from pch.normalize.target_detect import enrich_pipeline
from pch.repo_scan.files import fetch_contents, fetch_file, fetch_tree, select_content_paths
from pch.repo_scan.tests_detect import analyze_repo, classify_test_state
from pch.scanrun import REASON_INTERRUPTED, REASON_TIMEOUT, ScanTimeout
from pch.settings import Policy, Scope
from pch.sources import Sources
from pch.store import repository as store
from pch.store.db import session_scope
from pch.store.models import CollectionErrorRow, FindingRow, RepoResultRow
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
    repos: list[dict[str, Any]] = field(default_factory=list)
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

    def err(self, source: str, subject: str, exc: BaseException | str) -> None:
        msg = f"{type(exc).__name__}: {exc}" if isinstance(exc, BaseException) else exc
        self.errors.append((source, subject, msg[:400]))
        log.warning("collection error [%s] %s: %s", source, subject, msg)

    # ------------------------------------------------------------------ project level
    async def collect_project(self, name: str) -> _ProjectData:
        ado = self.src.ado
        pd = _ProjectData(name)
        try:
            pd.repos = await ado.repositories(name)
        except Exception as e:
            self.err("ado", f"{name}: repositories", e)
            return pd
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
        return pd

    # ------------------------------------------------------------------ repo level
    async def scan_repo(self, pd: _ProjectData, repo: dict[str, Any], builds: list[dict[str, Any]], releases: list[dict[str, Any]]):
        cfg, ado = self.cfg, self.src.ado
        project = pd.name
        branch = (repo.get("defaultBranch") or "refs/heads/main").removeprefix("refs/heads/")
        ov = cfg.scope.override_for(project, repo["name"])
        ref = RepoRef(
            id=repo["id"], name=repo["name"], project=project, url=repo.get("webUrl") or ado.web_url(project, f"_git/{repo['name']}"),
            default_branch=branch, owner=ov.owner if ov else None, sonar_key=ov.sonar_key if ov else None,
            aikido_repo=ov.aikido_repo if ov else None, servicenow_ci=ov.servicenow_ci if ov else None,
            coverage_threshold=ov.coverage_threshold if ov else None, disabled=bool(repo.get("isDisabled")),
        )
        repo_errors: list[tuple[str, str]] = []

        def rerr(source: str, exc: Exception | str) -> None:
            msg = f"{type(exc).__name__}: {exc}" if isinstance(exc, Exception) else exc
            repo_errors.append((source, msg[:300]))
            self.err(source, ref.key, exc)

        # 1. repo files -> facts
        facts = analyze_repo(None)
        paths: list[str] | None = None
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
        # 3. run history
        since = cfg.now - timedelta(days=cfg.run_days)
        for p in pipelines:
            try:
                if p.platform == "ado_classic_release":
                    await collect_release_runs(ado, project, p, since)
                else:
                    await collect_build_runs(ado, project, p, since)
            except Exception as e:
                rerr("ado", f"runs for {p.name}: {e}")
        # 4. Sonar
        sonar: SonarFacts | None = None
        if self.src.sonar is not None and facts.kind not in ("docs",):
            try:
                keys = [k for k in (ref.sonar_key, f"{project}_{ref.name}", ref.name) if k]
                sonar = await self.src.sonar.first_found(keys)
            except Exception as e:
                rerr("sonar", e)
        # 5. Aikido
        aikido: AikidoFacts | None = None
        if self.aikido_data is not None:
            from pch.collectors.aikido import AikidoClient

            aikido = AikidoClient.facts_for(ref.name, self.aikido_data[0], self.aikido_data[1], ref.aikido_repo)
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
        facts.test_state, facts.test_state_reason, facts.coverage = state, reason, cov
        # 8. rules
        ctx = RepoContext(
            repo=ref, pipelines=pipelines, facts=facts, policies=policies_for_repo(pd.policies, ref.id, branch) if pd.policies else policies_for_repo([], ref.id, branch),
            sonar=sonar, aikido=aikido, snow=snow, service_connections=pd.conns, variable_groups=pd.groups, environments=pd.envs, now=cfg.now,
        )
        if not pd.policies:
            ctx.policies.available = False  # policies were not collected for this project
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
        if not text:
            fname = (d.get("process") or {}).get("yamlFilename", "azure-pipelines.yml")
            text = await fetch_file(ado, project, ref.id, branch, fname)
        if not text:
            raise RuntimeError("YAML definition could not be retrieved")
        return parse_yaml_pipeline(text, d, project, base_web, raw_ref=f"pipeline/{d['id']}")

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
                    reason = f"{type(exc).__name__}: {exc}"
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
        pdatas = await asyncio.gather(*(self.collect_project(p) for p in projects))
        jobs = []
        for pd in pdatas:
            builds_by_repo: dict[str, list] = {}
            repo_of_build: dict[str, str] = {}
            for b in pd.build_defs:
                rid = (b.get("repository") or {}).get("id")
                if rid:
                    builds_by_repo.setdefault(rid, []).append(b)
                    repo_of_build[str(b["id"])] = rid
            releases_by_repo: dict[str, list] = {}
            for r in pd.release_defs:
                linked = [str(((a.get("definitionReference") or {}).get("definition") or {}).get("id")) for a in r.get("artifacts", []) if a.get("type") == "Build"]
                rid = next((repo_of_build[x] for x in linked if x in repo_of_build), None)
                if rid:
                    releases_by_repo.setdefault(rid, []).append(r)
                else:
                    self.err("ado", f"{pd.name}: release {r.get('name')}", "release is not linked to a build definition in a known repo (skipped)")
            for repo in pd.repos:
                key = f"{pd.name}/{repo['name']}"
                if key in cfg.scope.exclude_repos:
                    continue
                if repo.get("isDisabled"):
                    self.err("ado", key, "repository is disabled (skipped)")
                    continue
                jobs.append((pd, repo, builds_by_repo.get(repo["id"], []), releases_by_repo.get(repo["id"], [])))
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
                    self.err("scan", f"{pd.name}/{repo['name']}", e)
                    out = (pd.name, repo, e)
            done += 1
            if self.progress and (done % 25 == 0 or done == total):
                self.progress(done, total)
            return out

        results = await asyncio.gather(*(one(j) for j in jobs))
        return self.persist(scan_id, results, t0)

    # ------------------------------------------------------------------ persistence
    def persist(self, scan_id: str, results: list[Any], t0: float) -> ScanResult:
        cfg = self.cfg
        n_findings = 0
        counts: Counter[str] = Counter()
        failed = 0
        cat_fail: Counter[str] = Counter()
        with session_scope(cfg.db_url) as s:
            for out in results:
                if len(out) == 3:  # hard failure
                    project, repo, exc = out
                    failed += 1
                    s.add(RepoResultRow(scan_id=scan_id, repo_key=f"{project}/{repo['name']}", project=project, repo=repo["name"], status="NOT_SCANNED", test_state="NOT_APPLICABLE"))
                    s.add(FindingRow(scan_id=scan_id, repo_key=f"{project}/{repo['name']}", rule_id="COLLECTION-ERROR", category="SYS", severity="info", status="UNKNOWN", message=str(exc)[:300]))
                    counts["NOT_SCANNED"] += 1
                    continue
                ctx, findings, sc, mig_score, blockers = out
                counts[sc.status.value] += 1
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
                        "policies": ctx.policies.model_dump(mode="json"),
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
                row.summary = {"status_counts": dict(counts), "category_fails": dict(cat_fail), "errors": len(self.errors)}
        return ScanResult(scan_id, len(results), n_findings, len(self.errors), round(duration, 2), dict(counts))


def _jsonable(d: dict[str, Any]) -> dict[str, Any]:
    import json

    return json.loads(json.dumps(d, default=str))

