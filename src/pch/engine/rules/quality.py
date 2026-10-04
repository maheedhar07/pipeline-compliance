"""QLT: code quality and security (SonarQube, Aikido)."""

from __future__ import annotations

import re
from datetime import timedelta

from pch.engine.registry import rule, rule_params
from pch.model.findings import RuleResult, Status
from pch.model.pipeline import Pipeline
from pch.model.repo import RepoContext
from pch.normalize.capabilities import is_security_or_test_cap
from pch.settings import Policy

NO_SONAR_KINDS = {"docs", "adf", "synapse", "iac"}


def _na_kind(ctx: RepoContext) -> RuleResult | None:
    if ctx.facts.kind in NO_SONAR_KINDS:
        return RuleResult.na(f"{ctx.facts.kind} repository: Sonar analysis not applicable")
    return None


@rule(
    "QLT-001", "Build pipeline runs Sonar prepare, analyze and publish (all enabled)", "high", "repo",
    "Static analysis must run on every build; a partially configured Sonar integration silently stops reporting.",
    {"classic": "Add SonarQube Prepare (before build), Analyze (after tests) and Publish Quality Gate Result tasks to the build definition.",
     "yaml": "Add SonarQubePrepare@5, SonarQubeAnalyze@5 and SonarQubePublish@5 to the build stage."},
    params={"required_steps": ["sonar:prepare", "sonar:analyze", "sonar:publish"]},
)
def qlt_001(ctx: RepoContext, policy: Policy) -> RuleResult:
    if (na := _na_kind(ctx)) is not None:
        return na
    builds = ctx.build_pipelines()
    if not builds:
        return RuleResult.failed("no build pipeline found for this repo")
    need = set(rule_params(policy, "QLT-001")["required_steps"])
    best_missing = need
    for p in builds:
        have = p.capabilities(enabled_only=True)
        missing = need - have
        if len(missing) < len(best_missing):
            best_missing = missing
        if not missing:
            return RuleResult.passed("Sonar prepare, analyze and publish present and enabled", pipeline=p.name)
    return RuleResult.failed("missing/disabled Sonar steps: " + ", ".join(sorted(best_missing)), missing=sorted(best_missing))


@rule(
    "QLT-002", "Sonar quality gate is enforced (breaks the build)", "high", "repo",
    "A quality gate that only reports does not prevent bad code from shipping.",
    {"any": "Set sonar.qualitygate.wait=true (extraProperties on Prepare) or add a quality-gate breaker step that fails the pipeline."},
    params={"wait_pattern": r"sonar\.qualitygate\.wait\s*[=:]\s*true"},
)
def qlt_002(ctx: RepoContext, policy: Policy) -> RuleResult:
    if (na := _na_kind(ctx)) is not None:
        return na
    sonar_steps = [(p, s) for p in ctx.build_pipelines() for s in p.all_steps() if s.enabled and any(c.startswith("sonar:") for c in s.capabilities)]
    if not sonar_steps:
        return RuleResult.na("no Sonar integration in the pipelines (see QLT-001)")
    wait = re.compile(rule_params(policy, "QLT-002")["wait_pattern"], re.I)
    for p, s in sonar_steps:
        if "sonar:gate-breaker" in s.capabilities:
            return RuleResult.passed("quality-gate breaker step present", pipeline=p.name)
        blob = " ".join(str(v) for v in s.inputs.values())
        if wait.search(blob):
            return RuleResult.passed("sonar.qualitygate.wait=true", pipeline=p.name)
    return RuleResult.warn("quality gate is reported only; the pipeline is not broken when the gate fails")


@rule(
    "QLT-003", "Current Sonar quality gate status is OK", "high", "repo",
    "A failing quality gate means the latest analysed code does not meet the quality bar.",
    {"any": "Open the project in SonarQube and fix the failing gate conditions (new code coverage, new issues, hotspots)."},
    requires_sources={"sonar"},
)
def qlt_003(ctx: RepoContext, policy: Policy) -> RuleResult:
    if (na := _na_kind(ctx)) is not None:
        return na
    s = ctx.sonar
    if s is None:
        return RuleResult.unknown("SonarQube was not queried")
    link = s.url
    if not s.onboarded:
        return RuleResult.failed("no SonarQube project found for this repo")
    if s.gate_status in (None, "NONE"):
        return RuleResult.unknown("project has no quality gate status")
    if s.gate_status == "OK":
        return RuleResult(status=Status.PASS, message="quality gate OK", evidence={"gate": s.gate_status}, link=link)
    if s.gate_status == "WARN":
        return RuleResult(status=Status.WARN, message="quality gate WARN", evidence={"gate": s.gate_status}, link=link)
    return RuleResult(status=Status.FAIL, message=f"quality gate {s.gate_status}", evidence={"gate": s.gate_status}, link=link)


@rule(
    "QLT-004", "Project uses the company quality gate", "medium", "repo",
    "Using the default 'Sonar way' gate bypasses the company's agreed thresholds.",
    {"any": "In SonarQube: Project Settings > Quality Gate > select the company gate."},
    requires_sources={"sonar"},
)
def qlt_004(ctx: RepoContext, policy: Policy) -> RuleResult:
    if (na := _na_kind(ctx)) is not None:
        return na
    s = ctx.sonar
    if s is None or not s.onboarded:
        return RuleResult.na("no Sonar project (see QLT-003)")
    if not s.gate_name:
        return RuleResult.unknown("quality gate assignment not readable")
    if s.gate_name == policy.sonar_quality_gate_name:
        return RuleResult.passed("company quality gate assigned", gate=s.gate_name)
    return RuleResult.failed(f"uses '{s.gate_name}', expected '{policy.sonar_quality_gate_name}'", gate=s.gate_name)


@rule(
    "QLT-005", "Last Sonar analysis is recent", "medium", "repo",
    "A stale analysis means the gate status no longer reflects the code that is shipping.",
    {"any": "Check that the CI pipeline still runs Sonar analysis on the default branch."},
    requires_sources={"sonar"},
)
def qlt_005(ctx: RepoContext, policy: Policy) -> RuleResult:
    if (na := _na_kind(ctx)) is not None:
        return na
    s = ctx.sonar
    if s is None or not s.onboarded:
        return RuleResult.na("no Sonar project (see QLT-003)")
    if s.last_analysis is None:
        return RuleResult.failed("project has never been analysed")
    age = (ctx.now - s.last_analysis).days
    ev = {"last_analysis": s.last_analysis.isoformat(), "age_days": age, "max_days": policy.sonar_staleness_days}
    if age > policy.sonar_staleness_days:
        return RuleResult.failed(f"last analysis {age} days ago (max {policy.sonar_staleness_days})", **ev)
    return RuleResult.passed(f"analysed {age} days ago", **ev)


@rule(
    "QLT-006", "Repo is onboarded to Aikido", "high", "repo",
    "Aikido provides SCA/secret/IaC scanning that SonarQube does not.",
    {"any": "Connect the repository in Aikido (Settings > Code repositories)."},
    requires_sources={"aikido"},
)
def qlt_006(ctx: RepoContext, policy: Policy) -> RuleResult:
    if ctx.facts.kind == "docs":
        return RuleResult.na("docs-only repository")
    if ctx.aikido is None:
        return RuleResult.unknown("Aikido was not queried")
    if ctx.aikido.onboarded:
        return RuleResult.passed("repo is onboarded to Aikido")
    return RuleResult.failed("repo is not onboarded to Aikido")


@rule(
    "QLT-007", "No open Aikido issues past their SLA", "critical", "repo",
    "Known vulnerabilities left open beyond the SLA are a direct compliance breach.",
    {"any": "Triage and fix (or formally snooze with justification) the overdue issues in Aikido."},
    requires_sources={"aikido"},
)
def qlt_007(ctx: RepoContext, policy: Policy) -> RuleResult:
    a = ctx.aikido
    if ctx.facts.kind == "docs":
        return RuleResult.na("docs-only repository")
    if a is None:
        return RuleResult.unknown("Aikido was not queried")
    if not a.onboarded:
        return RuleResult.na("repo not onboarded (see QLT-006)")
    sla = policy.aikido_sla_days.model_dump()
    breaches: dict[str, int] = {}
    oldest = 0
    for i in a.open_issues:
        limit = sla.get(i.severity)
        if limit is None:
            continue
        age = (ctx.now - i.first_detected).days
        if ctx.now - i.first_detected > timedelta(days=limit):
            breaches[i.severity] = breaches.get(i.severity, 0) + 1
            oldest = max(oldest, age)
    ev = {"open_by_severity": {s: a.count(s) for s in ("critical", "high", "medium", "low")}, "sla_days": sla}
    if breaches:
        return RuleResult.failed("overdue issues: " + ", ".join(f"{n} {s}" for s, n in sorted(breaches.items())), breaches=breaches, oldest_overdue_age_days=oldest, **ev)
    return RuleResult.passed("no issues past SLA", **ev)


@rule(
    "QLT-008", "Security, quality and test steps cannot be skipped", "critical", "pipeline",
    "A Sonar/test/security step that is disabled, continueOnError or conditioned false is a silent bypass.",
    {"classic": "Enable the step, untick 'Continue on error' and remove custom conditions.",
     "yaml": "Remove continueOnError: true / enabled: false / false conditions from security and test steps."},
)
def qlt_008(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    relevant = [s for s in p.all_steps() if any(is_security_or_test_cap(c) for c in s.capabilities)]
    if not relevant:
        return RuleResult.na("no security/quality/test steps")
    bad = []
    for s in relevant:
        why = []
        if not s.enabled:
            why.append("disabled")
        if s.continue_on_error:
            why.append("continueOnError")
        if s.always_false:
            why.append("always-false condition")
        if why:
            bad.append({"step": s.name, "task": s.task, "reason": ", ".join(why)})
    if bad:
        return RuleResult.failed(f"{len(bad)} step(s) can be bypassed: " + "; ".join(f"{b['step']} ({b['reason']})" for b in bad), steps=bad)
    return RuleResult.passed(f"{len(relevant)} security/quality/test steps are enforced")
