"""Rules over GitHub Actions pipelines (G3): the five GHA-specific rules and the audit of the existing catalog (PASS / FAIL / NOT_APPLICABLE / UNKNOWN)."""

from datetime import datetime

from pch.engine.registry import REGISTRY, load_rules
from pch.engine.runner import StageTarget
from pch.model.gha import ActionsRead, GhCustomRule, GhEnvironment, WorkflowSource
from pch.model.pipeline import Pipeline
from pch.model.repo import GitHubMeta, RepoFacts
from pch.normalize.gha import apply_environments, build_pipelines, parse_workflow
from pch.settings import Policy, RuleOverride
from tests.builders import ctx, one, run, statuses
from tests.github_mock import actions_json, actions_text

load_rules()
PROD = GhEnvironment(name="production", required_reviewers=True, reviewers=["team:a"], prevent_self_review=True, branch_policy="protected",
                     custom_rules=[GhCustomRule(slug="servicenow-devops")])


def wf(name: str, text: str | None = None, **kw) -> Pipeline:
    p = parse_workflow(WorkflowSource(path=f".github/workflows/{name}", id=1, text=text or actions_text(name)), project="P", repo="r", **kw)
    from pch.normalize.target_detect import enrich_pipeline

    return enrich_pipeline(p)


def inline(yml: str) -> Pipeline:
    return wf("x.yml", yml)


def deploy(env: GhEnvironment | None = PROD, envs_known=True) -> Pipeline:
    p = wf("deploy.yml")
    apply_environments(p, ({"production": env} if env else {}) if envs_known else None)
    return p


def c(*pipes: Pipeline, **kw):
    return ctx(list(pipes), **kw)


# ----------------------------------------------------------------------------- new rules
def test_sup_006_pinning():
    assert one("SUP-006", c(wf("ci.yml"))) == "PASS"
    assert one("SUP-006", c(wf("insecure.yml"))) == "FAIL"
    tagged = inline("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: acme/x@v1\n")
    assert one("SUP-006", c(tagged)) == "FAIL"
    assert one("SUP-006", c(tagged), Policy(rules={"SUP-006": RuleOverride(params={"trusted_owners": ["actions"]})})) == "FAIL"  # acme/x@v1 is still a tag
    only_actions = inline("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/local\n")
    assert one("SUP-006", c(only_actions), Policy(rules={"SUP-006": RuleOverride(params={"trusted_owners": ["actions"]})})) == "PASS"
    assert one("SUP-006", c(only_actions)) == "FAIL"
    branch = inline("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n")
    assert one("SUP-006", c(branch), Policy(rules={"SUP-006": RuleOverride(params={"trusted_owners": ["actions"]})})) == "FAIL"  # branches are never trusted
    assert statuses("SUP-006", c(inline("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"))) == []
    assert statuses("SUP-006", c(pipe_ado())) == []  # GitHub Actions only


def pipe_ado():
    from tests.builders import pipe, stage, step

    return pipe([stage("b", [step("script", script="echo")])])


def test_sec_006_permissions():
    assert one("SEC-006", c(wf("ci.yml"))) == "PASS"
    assert one("SEC-006", c(wf("deploy.yml"))) == "PASS"  # id-token: write on the jobs is an allowed job-level scope
    assert one("SEC-006", c(wf("insecure.yml"))) == "FAIL"  # write-all
    no_top = inline("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
    assert one("SEC-006", c(no_top)) == "FAIL"
    top_write = inline("on: push\npermissions:\n  contents: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
    assert one("SEC-006", c(top_write)) == "FAIL"
    job_write = inline("on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps:\n      - run: echo\n")
    assert one("SEC-006", c(job_write)) == "WARN"
    assert one("SEC-006", c(job_write), Policy(rules={"SEC-006": RuleOverride(params={"job_write_scopes": ["contents"]})})) == "PASS"


def test_sec_007_untrusted_checkout():
    assert one("SEC-007", c(wf("insecure.yml"))) == "FAIL"
    assert one("SEC-007", c(wf("deploy.yml"))) == "PASS"  # workflow_run, no checkout of the triggering head
    assert statuses("SEC-007", c(wf("ci.yml"))) == []
    wr = inline("on:\n  workflow_run:\n    workflows: [CI]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n")
    assert one("SEC-007", c(wr)) == "FAIL"
    art = inline("on:\n  workflow_run:\n    workflows: [CI]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          run-id: ${{ github.event.workflow_run.id }}\n")
    assert one("SEC-007", c(art)) == "WARN"
    scripted = inline("on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh pr checkout ${{ github.event.number }}\n")
    assert one("SEC-007", c(scripted)) == "FAIL"
    safe = inline("on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo labeled\n")
    assert one("SEC-007", c(safe)) == "PASS"


def test_sec_008_script_injection():
    assert one("SEC-008", c(wf("insecure.yml"))) == "FAIL"
    assert one("SEC-008", c(wf("ci.yml"))) == "PASS"
    safe = inline("on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"$TITLE ${{ github.run_id }}\"\n        env:\n          TITLE: ${{ github.event.pull_request.title }}\n")
    assert one("SEC-008", c(safe)) == "PASS"  # the expression is in env, not interpolated into the script
    gs = inline("on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: console.log(`${{ github.event.issue.body }}`)\n")
    assert one("SEC-008", c(gs)) == "FAIL"
    assert statuses("SEC-008", c(inline("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"))) == []
    extra = Policy(rules={"SEC-008": RuleOverride(params={"untrusted_contexts": [r"github\.actor"]})})
    actor = inline("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.actor }}\n")
    assert one("SEC-008", c(actor)) == "PASS" and one("SEC-008", c(actor), extra) == "FAIL"


def test_sec_009_self_hosted_on_public_triggers():
    assert one("SEC-009", c(wf("insecure.yml"))) == "WARN"
    private = inline("on: push\njobs:\n  a:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: echo\n")
    assert one("SEC-009", c(private)) == "PASS"
    assert statuses("SEC-009", c(wf("ci.yml"))) == []
    msg = run("SEC-009", c(wf("insecure.yml"), facts=RepoFacts(github=GitHubMeta(visibility="public"))))[0].message
    assert "public repository" in msg


# ----------------------------------------------------------------------------- audit of the existing catalog
def stage_of(p: Pipeline, name: str):
    st = p.stage(name)
    assert st is not None
    return StageTarget(p, st)


def direct(rule_id: str, cx, target=None, policy=None):
    meta = REGISTRY[rule_id]
    pol = policy or Policy()
    return meta.fn(cx, pol) if meta.scope == "repo" else meta.fn(cx, pol, target)


def test_dep_001_002_003_use_environment_protection():
    p = deploy()
    assert one("DEP-001", c(p)) == "PASS" and one("DEP-002", c(p)) == "PASS" and one("DEP-003", c(p)) == "PASS"
    bare = deploy(GhEnvironment(name="production"))
    assert one("DEP-001", c(bare)) == "FAIL" and statuses("DEP-002", c(bare)) == [] and one("DEP-003", c(bare)) == "FAIL"
    self_review = deploy(GhEnvironment(name="production", required_reviewers=True, prevent_self_review=False))
    assert one("DEP-002", c(self_review)) == "FAIL"
    unconfigured = deploy(None)
    assert one("DEP-001", c(unconfigured)) == "FAIL"  # the environment is not configured: no protection
    denied = deploy(envs_known=False)
    assert one("DEP-001", c(denied)) == "UNKNOWN" and one("DEP-003", c(denied)) == "UNKNOWN" and one("SRC-005", c(denied)) == "UNKNOWN"
    custom_unreadable = deploy(GhEnvironment(name="production", required_reviewers=True, custom_error="denied"))
    assert one("DEP-001", c(custom_unreadable)) == "PASS" and one("DEP-003", c(custom_unreadable)) == "UNKNOWN"
    action = inline("on: push\njobs:\n  p:\n    runs-on: ubuntu-latest\n    environment: production\n    steps:\n      - uses: ServiceNow/servicenow-devops-change@v6\n")
    apply_environments(action, {})
    assert one("DEP-003", c(action)) == "PASS"  # the ServiceNow DevOps Change action counts
    custom = deploy(GhEnvironment(name="production", custom_rules=[GhCustomRule(slug="approvals-app")]))
    assert one("DEP-003", c(custom)) == "FAIL"  # a custom rule that is not ServiceNow


def test_dep_004_needs_and_workflow_run():
    assert one("DEP-004", c(deploy())) == "PASS"  # needs deploy-test
    flat = inline("on: push\njobs:\n  prod:\n    runs-on: ubuntu-latest\n    environment: production\n    steps:\n      - run: echo\n")
    assert one("DEP-004", c(flat)) == "FAIL"
    lower = inline("name: Staging\non: push\njobs:\n  s:\n    runs-on: ubuntu-latest\n    environment: staging\n    steps:\n      - run: echo\n")
    prod = inline("name: Prod\non:\n  workflow_run:\n    workflows: [Staging]\njobs:\n  prod:\n    runs-on: ubuntu-latest\n    environment: production\n    steps:\n      - run: echo\n")
    assert one("DEP-004", c(lower, prod)) == "PASS" and one("DEP-004", c(prod)) == "FAIL"


def test_src_005_environment_branch_policy():
    assert one("SRC-005", c(deploy())) == "PASS"  # protected branches only
    custom = deploy(GhEnvironment(name="production", branch_policy="custom", branch_patterns=["main", "tag:v*"]))
    assert one("SRC-005", c(custom)) == "PASS"
    wide = deploy(GhEnvironment(name="production", branch_policy="custom", branch_patterns=["feature/*"]))
    assert one("SRC-005", c(wide)) == "FAIL"
    assert one("SRC-005", c(deploy(GhEnvironment(name="production")))) == "FAIL"


def test_dep_006_and_security_audit_na():
    cx = c(deploy())
    assert direct("DEP-006", cx, deploy()).status.value == "NOT_APPLICABLE"
    assert statuses("DEP-006", cx) == []
    for rid in ("SEC-002", "SEC-004", "SEC-005"):
        p = deploy()
        assert statuses(rid, c(p)) == [], rid


def test_sec_003_oidc_vs_secret():
    assert one("SEC-003", c(wf("deploy.yml"))) == "PASS"
    assert one("SEC-003", c(wf("insecure.yml"))) == "FAIL"
    assert statuses("SEC-003", c(wf("ci.yml"))) == []
    undecided = inline("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: azure/login@v2\n        with:\n          client-id: x\n")
    assert one("SEC-003", c(undecided)) == "UNKNOWN"
    sp = inline("on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: az login --service-principal -u $ID -p ${{ secrets.SP }} --tenant t\n")
    assert "auth:secret" in sp.all_steps()[0].capabilities


def test_sec_001_literal_env_secret():
    assert one("SEC-001", c(wf("insecure.yml"))) == "FAIL" and one("SEC-001", c(wf("ci.yml"))) == "PASS"


def test_sup_001_002_003_005_for_actions():
    assert one("SUP-001", c(deploy())) == "PASS"
    rebuild = inline("on: push\njobs:\n  prod:\n    runs-on: ubuntu-latest\n    environment: production\n    steps:\n      - run: dotnet build\n")
    assert one("SUP-001", c(rebuild)) == "FAIL"
    assert one("SUP-002", c(wf("ci.yml"))) == "PASS" and one("SUP-002", c(wf("insecure.yml"))) == "FAIL"  # branch ref + deprecated azure/login@v1
    assert one("SUP-003", c(wf("ci.yml"))) == "FAIL"  # dorny, codecov, SonarSource are not trusted owners
    allow = Policy(rules={"SUP-003": RuleOverride(params={"trusted_action_owners": ["actions", "dorny", "codecov"]})}, marketplace_task_allowlist=["SonarSource/*"])
    assert one("SUP-003", c(wf("ci.yml")), allow) == "PASS"
    assert one("SUP-003", c(inline("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"))) == "PASS"
    assert one("SUP-005", c(wf("ci.yml"))) == "FAIL"
    sbom = inline("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: anchore/sbom-action@v0\n")
    assert one("SUP-005", c(sbom)) == "PASS"


def test_quality_testing_rules_for_actions():
    cx = c(wf("ci.yml"), facts=RepoFacts(languages=["dotnet"], tests_detected=True))
    assert one("QLT-001", cx) == "PASS" and one("QLT-002", cx) == "PASS" and one("QLT-008", cx) == "PASS" and one("TST-004", cx) == "PASS"
    assert one("QLT-008", c(wf("insecure.yml"))) == "FAIL"  # continue-on-error on the Sonar step
    weak = inline("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: SonarSource/sonarqube-scan-action@v5\n")
    assert one("QLT-001", c(weak)) == "FAIL" and one("QLT-002", c(weak)) == "WARN"
    assert statuses("TST-005", c(deploy())) == ["PASS", "PASS"]  # smoke check in the test and prod deploy jobs


def test_hyg_and_srcs_for_actions():
    p = wf("tests.yml")
    assert statuses("HYG-001", c(p)) == [] and statuses("HYG-002", c(p)) == []  # reusable workflows have no runs of their own
    assert one("SRC-004", c(wf("ci.yml"))) == "PASS"
    assert one("HYG-001", c(wf("ci.yml"))) == "UNKNOWN"  # run history was not collected
    pipes, _ = build_pipelines(ActionsRead(workflows=[WorkflowSource(path=".github/workflows/ci.yml", id=101, text=actions_text("ci.yml"))], runs=actions_json("runs.json")["workflow_runs"]),
                               project="P", repo="r")
    cx = ctx(pipes)
    cx.now = datetime(2026, 10, 2)
    assert one("HYG-001", cx) == "PASS" and one("HYG-002", cx) == "FAIL"  # 1 of 2 completed runs succeeded


def test_target_rules_for_actions():
    assert one("TGT-WA-001", c(deploy())) == "PASS"  # slot-name + slot swap in the prod job
    no_slot = inline("on: push\njobs:\n  prod:\n    runs-on: ubuntu-latest\n    environment: production\n    steps:\n      - uses: azure/webapps-deploy@v3\n        with:\n          app-name: a\n")
    assert statuses("TGT-WA-001", c(no_slot)) == ["FAIL"]
    prof = inline("on: push\njobs:\n  prod:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: azure/webapps-deploy@v3\n        with:\n          app-name: a\n          publish-profile: ${{ secrets.PUBLISH }}\n")
    assert statuses("TGT-WA-002", c(prof)) == ["FAIL"] and statuses("TGT-WA-002", c(wf("deploy.yml"))) == ["PASS", "PASS"]
    aks = inline("on: push\njobs:\n  dev:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: azure/k8s-deploy@v5\n        with:\n          images: contosoacr.azurecr.io/a:${{ github.sha }}\n")
    assert statuses("TGT-AKS-002", c(aks)) == ["PASS"] and statuses("TGT-AKS-001", c(aks)) == ["FAIL"]
    assert one("SUP-004", c(aks)) == "PASS"


def test_unreadable_pipeline_content_makes_failures_unknown():
    caller = parse_workflow(WorkflowSource(path=".github/workflows/c.yml", id=2, text=actions_text("caller.yml")), project="P", repo="r",
                            callees={"./.github/workflows/tests.yml": actions_text("tests.yml")}, callee_errors={})
    assert caller.meta["unresolved"]
    assert one("QLT-001", c(caller)) == "UNKNOWN" and one("SUP-005", c(caller)) == "UNKNOWN"
    assert one("SEC-006", c(caller)) == "PASS"  # caller-only rules are not hedged
    plain = wf("ci.yml")
    cx = c(plain)
    cx.unreadable = [".github/workflows/bad.yml: workflow file is not valid YAML"]
    assert one("SUP-005", cx) == "UNKNOWN" and one("SEC-006", cx) == "PASS"
    assert one("SUP-005", c(plain)) == "FAIL"
