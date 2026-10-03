"""TST: testing."""

from __future__ import annotations

from pch.engine.registry import rule
from pch.model.findings import RuleResult
from pch.model.pipeline import Pipeline
from pch.model.repo import RepoContext, TestState
from pch.settings import Policy


@rule(
    "TST-001", "Application repo has automated tests (no repo without tests)", "high", "repo",
    "Code without tests cannot be safely changed or deployed.",
    {"any": "Add a unit-test project and wire it into the build pipeline."},
)
def tst_001(ctx: RepoContext, policy: Policy) -> RuleResult:
    st = ctx.facts.test_state
    if st == TestState.NOT_APPLICABLE:
        return RuleResult.na(ctx.facts.test_state_reason)
    if st == TestState.NO_TESTS:
        return RuleResult.failed(ctx.facts.test_state_reason, test_state=st.value, languages=ctx.facts.languages)
    return RuleResult.passed("tests detected", test_state=st.value, signals=ctx.facts.test_signals[:5])


@rule(
    "TST-002", "Existing tests are executed by a pipeline", "high", "repo",
    "Tests that never run provide no protection.",
    {"classic": "Add a VSTest / DotNetCoreCLI test task (enabled, no continue-on-error) to the build definition.",
     "yaml": "Add a test step (dotnet test / pytest / npm test) without continueOnError."},
)
def tst_002(ctx: RepoContext, policy: Policy) -> RuleResult:
    st = ctx.facts.test_state
    if st in (TestState.NOT_APPLICABLE, TestState.NO_TESTS):
        return RuleResult.na("no tests to run (see TST-001)" if st == TestState.NO_TESTS else ctx.facts.test_state_reason)
    if st == TestState.TESTS_NOT_RUN:
        return RuleResult.failed(ctx.facts.test_state_reason, test_state=st.value)
    return RuleResult.passed("a pipeline runs the tests", test_state=st.value)


@rule(
    "TST-003", "Code coverage meets the threshold", "high", "repo",
    "Coverage below the agreed floor means large parts of the code are untested.",
    {"any": "Add tests and make sure coverage is published to Sonar (sonar.coverage.* or PublishCodeCoverageResults)."},
)
def tst_003(ctx: RepoContext, policy: Policy) -> RuleResult:
    st = ctx.facts.test_state
    thr = ctx.repo.coverage_threshold or policy.coverage_threshold
    if st in (TestState.NOT_APPLICABLE, TestState.NO_TESTS, TestState.TESTS_NOT_RUN):
        return RuleResult.na("coverage not measurable until tests run")
    if st == TestState.TESTS_NO_COVERAGE:
        return RuleResult.failed("tests run but no coverage is reported", threshold=thr)
    if st == TestState.TESTS_LOW_COVERAGE:
        return RuleResult.failed(ctx.facts.test_state_reason, coverage=ctx.facts.coverage, threshold=thr)
    return RuleResult.passed(f"coverage {ctx.facts.coverage:.1f}% >= {thr:.0f}%", coverage=ctx.facts.coverage, threshold=thr)


@rule(
    "TST-004", "Test results and coverage are published", "medium", "pipeline",
    "Published results give traceable evidence that tests ran and what they covered.",
    {"classic": "Add Publish Test Results and Publish Code Coverage Results tasks.",
     "yaml": "Add PublishTestResults@2 and PublishCodeCoverageResults@1 (or --logger trx plus coverage publish)."},
)
def tst_004(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    if p.platform == "ado_classic_release":
        return RuleResult.na("release definition")
    caps = p.capabilities()
    if "unit-test" not in caps:
        return RuleResult.na("pipeline does not run tests")
    missing = [c for c in ("test-results-publish", "coverage-publish") if c not in caps]
    if missing:
        return RuleResult.failed("not published: " + ", ".join(missing), missing=missing)
    return RuleResult.passed("test results and coverage published")


@rule(
    "TST-005", "Post-deployment smoke or health check exists", "medium", "stage",
    "Without a post-deploy check a broken release is only noticed by users.",
    {"classic": "Add a post-deployment gate (Invoke REST API / Azure Monitor) or a smoke-test task after the deploy.",
     "yaml": "Add a smoke test step (curl /health) or an environment check after deployment."},
    tiers={"test", "uat", "prod"},
)
def tst_005(ctx, policy: Policy, t) -> RuleResult:
    st = t.stage
    if not st.is_deploy or not st.deploy_targets:
        return RuleResult.na("not a deployment stage")
    if st.env_tier not in policy.smoke_check_required_tiers:
        return RuleResult.na("tier not in scope")
    if "smoke-test" in st.capabilities():
        return RuleResult.passed("smoke/health check step present")
    post_gates = [a for a in st.post_approvals if a.kind in ("gate", "servicenow")]
    if post_gates:
        return RuleResult.passed("post-deployment gate present", gates=[g.name for g in post_gates])
    return RuleResult.failed("no post-deployment smoke/health check or gate")


@rule(
    "TST-006", "Pre-deploy validation runs for ADF / Synapse / IaC repos", "medium", "repo",
    "Data-platform and IaC repos have no unit tests; validation (ADF validate, Synapse validate, what-if/plan) is their test.",
    {"any": "ADF: 'npm run build validate'; Synapse: Synapse workspace deployment with operation validateDeploy; Bicep: 'az deployment group what-if'; Terraform: 'terraform plan'."},
)
def tst_006(ctx: RepoContext, policy: Policy) -> RuleResult:
    kind = ctx.facts.kind
    need = {"adf": {"validate:adf"}, "synapse": {"validate:synapse"}, "iac": {"whatif", "plan", "validate:iac"}}.get(kind)
    if need is None:
        return RuleResult.na("not an ADF/Synapse/IaC repository")
    caps: set[str] = set()
    for p in ctx.pipelines:
        caps |= p.capabilities()
    if caps & need:
        return RuleResult.passed("pre-deploy validation present", found=sorted(caps & need))
    return RuleResult.failed(f"no pre-deploy validation for {kind} (expected one of {sorted(need)})", expected=sorted(need))
