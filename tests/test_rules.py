"""Every rule has at least one PASS and one FAIL test (plus NA/UNKNOWN edge cases)."""

from datetime import timedelta

from pch.model.pipeline import Approval, DeploymentRecord, RunStats
from pch.model.repo import ChangeRequest, Environment, RepoFacts
from tests.builders import (
    NOW,
    AikidoFacts,
    AikidoIssue,
    BranchPolicies,
    ServiceConnection,
    SnowFacts,
    SonarFacts,
    TestState,
    VariableGroup,
    VariableGroupRef,
    ctx,
    manual,
    one,
    pipe,
    run,
    stage,
    statuses,
    step,
)

# ================================================================== SRC


def test_src_001():
    ok = BranchPolicies(available=True, min_reviewers=2, creator_vote_counts=False, reset_on_push=True)
    assert one("SRC-001", ctx(policies=ok)) == "PASS"
    assert one("SRC-001", ctx(policies=ok.model_copy(update={"min_reviewers": 1}))) == "FAIL"
    assert one("SRC-001", ctx(policies=ok.model_copy(update={"creator_vote_counts": True}))) == "FAIL"
    assert one("SRC-001", ctx(policies=ok.model_copy(update={"reset_on_push": False}))) == "FAIL"
    assert one("SRC-001", ctx()) == "UNKNOWN"


def test_src_002():
    assert one("SRC-002", ctx(policies=BranchPolicies(available=True, build_validation=True))) == "PASS"
    assert one("SRC-002", ctx(policies=BranchPolicies(available=True))) == "FAIL"


def test_src_003():
    assert one("SRC-003", ctx(policies=BranchPolicies(available=True, work_item_required=True, comment_resolution_required=True))) == "PASS"
    assert one("SRC-003", ctx(policies=BranchPolicies(available=True, work_item_required=True))) == "FAIL"


def test_src_004():
    classic = pipe([stage("build")], platform="ado_classic_build")
    yml = pipe([stage("build")], platform="ado_yaml", id="2")
    assert statuses("SRC-004", ctx([classic, yml])) == ["FAIL", "PASS"]


def test_src_005():
    s_ok = stage("Prod", [step("AzureFunctionApp@2")], tier="prod", branch_filters=["main", "release/*"])
    s_none = stage("Prod", [step("AzureFunctionApp@2")], tier="prod")
    s_bad = stage("Prod", [step("AzureFunctionApp@2")], tier="prod", branch_filters=["feature/*"])
    assert one("SRC-005", ctx([pipe([s_ok], "ado_classic_release")])) == "PASS"
    assert one("SRC-005", ctx([pipe([s_none], "ado_classic_release")])) == "FAIL"
    assert one("SRC-005", ctx([pipe([s_bad], "ado_classic_release")])) == "FAIL"
    yaml_stage = stage("Prod", [step("AzureFunctionApp@2")], tier="prod", env="prod-env")
    assert one("SRC-005", ctx([pipe([yaml_stage])])) == "UNKNOWN"  # env checks not collected


def test_src_006():
    yml = pipe([stage("build")])
    assert one("SRC-006", ctx([yml], facts=RepoFacts(codeowners=True, pipeline_files=["azure-pipelines.yml"]))) == "PASS"
    assert one("SRC-006", ctx([yml], policies=BranchPolicies(available=True, required_reviewer_paths=["/azure-pipelines*.yml"]))) == "PASS"
    assert one("SRC-006", ctx([yml])) == "FAIL"
    assert statuses("SRC-006", ctx([pipe([stage("b")], "ado_classic_build")])) == []  # NA


# ================================================================== QLT
SONAR_STEPS = [step("SonarQubePrepare@5", {"extraProperties": "sonar.qualitygate.wait=true"}), step("SonarQubeAnalyze@5"), step("SonarQubePublish@5")]


def test_qlt_001():
    assert one("QLT-001", ctx([pipe([stage("build", SONAR_STEPS)])])) == "PASS"
    assert one("QLT-001", ctx([pipe([stage("build", SONAR_STEPS[:2])])])) == "FAIL"
    disabled = [step("SonarQubePrepare@5"), step("SonarQubeAnalyze@5"), step("SonarQubePublish@5", enabled=False)]
    assert one("QLT-001", ctx([pipe([stage("build", disabled)])])) == "FAIL"
    assert one("QLT-001", ctx([])) == "FAIL"
    assert statuses("QLT-001", ctx([], facts=RepoFacts(kind="adf", has_app_code=False))) == []


def test_qlt_002():
    assert one("QLT-002", ctx([pipe([stage("build", SONAR_STEPS)])])) == "PASS"
    breaker = [*SONAR_STEPS[1:], step("sonar-buildbreaker@8"), step("SonarQubePrepare@5")]
    assert one("QLT-002", ctx([pipe([stage("build", breaker)])])) == "PASS"
    reported = [step("SonarQubePrepare@5", {"extraProperties": "sonar.x=1"}), step("SonarQubeAnalyze@5")]
    assert one("QLT-002", ctx([pipe([stage("build", reported)])])) == "WARN"
    assert statuses("QLT-002", ctx([pipe([stage("build")])])) == []


def test_qlt_003():
    f = lambda **k: ctx(sonar=SonarFacts(onboarded=True, url="http://s", **k))  # noqa: E731
    assert one("QLT-003", f(gate_status="OK")) == "PASS"
    assert one("QLT-003", f(gate_status="ERROR")) == "FAIL"
    assert one("QLT-003", f(gate_status="WARN")) == "WARN"
    assert one("QLT-003", f(gate_status="NONE")) == "UNKNOWN"
    assert one("QLT-003", ctx(sonar=SonarFacts(onboarded=False))) == "FAIL"
    assert one("QLT-003", ctx()) == "UNKNOWN"
    assert run("QLT-003", f(gate_status="OK"))[0].link == "http://s"


def test_qlt_004():
    assert one("QLT-004", ctx(sonar=SonarFacts(onboarded=True, gate_name="Company Way"))) == "PASS"
    assert one("QLT-004", ctx(sonar=SonarFacts(onboarded=True, gate_name="Sonar way"))) == "FAIL"
    assert one("QLT-004", ctx(sonar=SonarFacts(onboarded=True))) == "UNKNOWN"


def test_qlt_005():
    assert one("QLT-005", ctx(sonar=SonarFacts(onboarded=True, last_analysis=NOW - timedelta(days=3)))) == "PASS"
    assert one("QLT-005", ctx(sonar=SonarFacts(onboarded=True, last_analysis=NOW - timedelta(days=40)))) == "FAIL"
    assert one("QLT-005", ctx(sonar=SonarFacts(onboarded=True))) == "FAIL"


def test_qlt_006():
    assert one("QLT-006", ctx(aikido=AikidoFacts(onboarded=True))) == "PASS"
    assert one("QLT-006", ctx(aikido=AikidoFacts(onboarded=False))) == "FAIL"
    assert one("QLT-006", ctx()) == "UNKNOWN"


def test_qlt_007():
    def issue(sev, days):
        return AikidoIssue(id="1", severity=sev, first_detected=NOW - timedelta(days=days))

    ok = AikidoFacts(onboarded=True, open_issues=[issue("critical", 3), issue("high", 29), issue("medium", 89)])
    assert one("QLT-007", ctx(aikido=ok)) == "PASS"
    late = AikidoFacts(onboarded=True, open_issues=[issue("critical", 8)])
    f = run("QLT-007", ctx(aikido=late))[0]
    assert f.status.value == "FAIL" and f.evidence["breaches"] == {"critical": 1}
    assert one("QLT-007", ctx(aikido=AikidoFacts(onboarded=True, open_issues=[issue("high", 31)]))) == "FAIL"
    assert one("QLT-007", ctx(aikido=AikidoFacts(onboarded=True, open_issues=[issue("medium", 91)]))) == "FAIL"
    assert one("QLT-007", ctx()) == "UNKNOWN"
    assert statuses("QLT-007", ctx(aikido=AikidoFacts(onboarded=False))) == []


def test_qlt_008():
    ok = pipe([stage("b", [step("VSTest@2"), step("SonarQubeAnalyze@5")])])
    assert one("QLT-008", ctx([ok])) == "PASS"
    for kw in ({"continue_on_error": True}, {"enabled": False}, {"condition": "false"}):
        bad = pipe([stage("b", [step("VSTest@2", **kw)])])
        assert one("QLT-008", ctx([bad])) == "FAIL", kw
    assert statuses("QLT-008", ctx([pipe([stage("b", [step("PublishBuildArtifacts@1")])])])) == []


# ================================================================== TST
def facts(state, cov=None, **kw):
    return RepoFacts(languages=["dotnet"], has_app_code=True, test_state=state, test_state_reason="why", coverage=cov, **kw)


def test_tst_001_002_003():
    assert one("TST-001", ctx(facts=facts(TestState.NO_TESTS))) == "FAIL"
    assert one("TST-001", ctx(facts=facts(TestState.TESTS_OK, 90))) == "PASS"
    assert statuses("TST-001", ctx(facts=facts(TestState.NOT_APPLICABLE))) == []
    assert one("TST-002", ctx(facts=facts(TestState.TESTS_NOT_RUN))) == "FAIL"
    assert one("TST-002", ctx(facts=facts(TestState.TESTS_LOW_COVERAGE, 10))) == "PASS"
    assert statuses("TST-002", ctx(facts=facts(TestState.NO_TESTS))) == []
    assert one("TST-003", ctx(facts=facts(TestState.TESTS_OK, 85))) == "PASS"
    assert one("TST-003", ctx(facts=facts(TestState.TESTS_LOW_COVERAGE, 40))) == "FAIL"
    assert one("TST-003", ctx(facts=facts(TestState.TESTS_NO_COVERAGE))) == "FAIL"
    assert statuses("TST-003", ctx(facts=facts(TestState.TESTS_NOT_RUN))) == []


def test_tst_004():
    ok = pipe([stage("b", [step("VSTest@2"), step("PublishTestResults@2"), step("PublishCodeCoverageResults@1")])])
    bad = pipe([stage("b", [step("VSTest@2")])], id="2")
    assert statuses("TST-004", ctx([ok, bad])) == ["PASS", "FAIL"]
    assert statuses("TST-004", ctx([pipe([stage("b")])])) == []


def test_tst_005():
    ok = stage("Prod", [step("AzureFunctionApp@2"), step("script", script="curl -f https://x/health")], tier="prod", env="e")
    bad = stage("Prod", [step("AzureFunctionApp@2")], tier="prod", env="e")
    gate = stage("UAT", [step("AzureFunctionApp@2")], tier="uat", post_approvals=[Approval(kind="gate", name="Health")])
    dev = stage("Dev", [step("AzureFunctionApp@2")], tier="dev")
    assert one("TST-005", ctx([pipe([ok])])) == "PASS"
    assert one("TST-005", ctx([pipe([bad])])) == "FAIL"
    assert one("TST-005", ctx([pipe([gate], "ado_classic_release")])) == "PASS"
    assert statuses("TST-005", ctx([pipe([dev])])) == []


def test_tst_006():
    adf = RepoFacts(kind="adf", has_app_code=False)
    ok = pipe([stage("b", [step("script", script="npm run build validate ./ /sub/x")])])
    assert one("TST-006", ctx([ok], facts=adf)) == "PASS"
    assert one("TST-006", ctx([pipe([stage("b")])], facts=adf)) == "FAIL"
    iac = RepoFacts(kind="iac", has_app_code=False)
    assert one("TST-006", ctx([pipe([stage("b", [step("script", script="az deployment group what-if -g x")])])], facts=iac)) == "PASS"
    syn = RepoFacts(kind="synapse", has_app_code=False)
    assert one("TST-006", ctx([pipe([stage("b", [step("Synapse workspace deployment@2", {"operation": "validateDeploy"})])])], facts=syn)) == "PASS"
    assert statuses("TST-006", ctx([ok])) == []


# ================================================================== SUP
def test_sup_001():
    classic_ok = pipe([stage("Dev", [step("AzureWebApp@1")], tier="dev")], "ado_classic_release", linked_build_ids=["1"])
    classic_nolink = pipe([stage("Dev", [step("AzureWebApp@1")], tier="dev")], "ado_classic_release", id="2")
    rebuild = pipe([stage("Build", [step("DotNetCoreCLI@2", {"command": "build"})]), stage("Prod", [step("DotNetCoreCLI@2", {"command": "publish"}), step("AzureWebApp@1")], env="prod")], id="3")
    good_yaml = pipe([stage("Build", [step("DotNetCoreCLI@2", {"command": "build"})]), stage("Prod", [step("AzureWebApp@1")], env="prod")], id="4")
    assert one("SUP-001", ctx([classic_ok])) == "PASS"
    assert one("SUP-001", ctx([classic_nolink])) == "FAIL"
    assert one("SUP-001", ctx([rebuild])) == "FAIL"
    assert one("SUP-001", ctx([good_yaml])) == "PASS"
    assert statuses("SUP-001", ctx([pipe([stage("b")], "ado_classic_build")])) == []


def test_sup_002():
    ok = pipe([stage("b", [step("DotNetCoreCLI@2"), step("script", script="echo hi")])])
    assert one("SUP-002", ctx([ok])) == "PASS"
    unpinned = step("DotNetCoreCLI")
    assert one("SUP-002", ctx([pipe([stage("b", [unpinned])])])) == "FAIL"
    assert one("SUP-002", ctx([pipe([stage("b", [step("AzureResourceGroupDeployment@2")])])])) == "FAIL"
    assert statuses("SUP-002", ctx([pipe([stage("b", [step("script", script="x")])])])) == []


def test_sup_003():
    ok = step("SonarQubePrepare@5")
    ok.marketplace = True
    bad = step("replacetokens@5")
    bad.marketplace = True
    assert one("SUP-003", ctx([pipe([stage("b", [ok])])])) == "PASS"
    assert one("SUP-003", ctx([pipe([stage("b", [ok, bad])])])) == "FAIL"


def test_sup_004():
    def aks(script_or_inputs, **inputs):
        return ctx([pipe([stage("Prod", [step("KubernetesManifest@1", inputs, script=script_or_ontent(script_or_inputs))], tier="prod")])])

    def script_or_ontent(x):
        return x if isinstance(x, str) else None

    good = aks(None, containers="contosoacr.azurecr.io/orders:$(Build.BuildId)")
    assert one("SUP-004", good) == "PASS"
    assert one("SUP-004", aks(None, containers="contosoacr.azurecr.io/orders:latest")) == "FAIL"
    assert one("SUP-004", aks(None, containers="evilreg.azurecr.io/orders:$(Build.BuildId)")) == "FAIL"
    assert one("SUP-004", aks(None, containers="contosoacr.azurecr.io/orders:v1")) == "WARN"
    assert one("SUP-004", aks(None, containers="contosoacr.azurecr.io/orders@sha256:abc")) == "PASS"
    assert one("SUP-004", ctx([pipe([stage("Prod", [step("Docker@2", {"command": "push", "tags": "latest"}), step("script", script="kubectl apply -f k8s/")], tier="prod")])])) == "FAIL"


def test_sup_005():
    assert one("SUP-005", ctx([pipe([stage("b", [step("script", script="syft packages dir:.")])])])) == "PASS"
    assert one("SUP-005", ctx([pipe([stage("b")])])) == "FAIL"
    assert statuses("SUP-005", ctx([pipe([stage("b")], "ado_classic_release")])) == []


# ================================================================== SEC
def test_sec_001():
    from pch.model.pipeline import Variable

    bad = pipe([stage("b")], variables=[Variable(name="dbPassword", secret_like_reason="name looks secret-like")])
    ok = pipe([stage("b")], id="2", variables=[Variable(name="Config"), Variable(name="apiKey", is_secret=True)])
    assert statuses("SEC-001", ctx([bad, ok])) == ["FAIL", "PASS"]
    f = run("SEC-001", ctx([bad]))[0]
    assert "dbPassword" in f.message and "value" not in str(f.evidence).lower().replace("secret-like", "")


def test_sec_002():
    prod = stage("Prod", [step("AzureWebApp@1")], tier="prod", env="p")
    kv = VariableGroup(id="1", name="kv", key_vault_linked=True)
    plain = VariableGroup(id="2", name="plain")
    mk = lambda g: pipe([prod], variable_groups=[VariableGroupRef(id=g.id, name=g.name)])  # noqa: E731
    assert one("SEC-002", ctx([mk(kv)], groups=[kv])) == "PASS"
    assert one("SEC-002", ctx([mk(plain)], groups=[plain])) == "FAIL"
    assert one("SEC-002", ctx([mk(kv)])) == "UNKNOWN"
    assert statuses("SEC-002", ctx([pipe([prod])])) == []


def conn(name, scheme="WorkloadIdentityFederation", level="ResourceGroup", all_p=False):
    return ServiceConnection(id=name + "-id", name=name, type="azurerm", auth_scheme=scheme, scope_level=level,
                             all_pipelines_authorized=all_p, federated=scheme == "WorkloadIdentityFederation")


def with_conn(name, tier="prod"):
    return pipe([stage("Prod", [step("AzureFunctionApp@2", {"azureSubscription": name})], tier=tier, env="e")])


def test_sec_003():
    assert one("SEC-003", ctx([with_conn("c")], conns=[conn("c")])) == "PASS"
    assert one("SEC-003", ctx([with_conn("c")], conns=[conn("c", "ServicePrincipal")])) == "FAIL"
    assert one("SEC-003", ctx([with_conn("c")], conns=[conn("c", "ManagedServiceIdentity")])) == "PASS"
    assert one("SEC-003", ctx([with_conn("c")])) == "UNKNOWN"
    assert statuses("SEC-003", ctx([pipe([stage("b", [step("DotNetCoreCLI@2")])])])) == []


def test_sec_004():
    assert one("SEC-004", ctx([with_conn("c")], conns=[conn("c", all_p=False)])) == "PASS"
    assert one("SEC-004", ctx([with_conn("c")], conns=[conn("c", all_p=True)])) == "FAIL"
    assert one("SEC-004", ctx([with_conn("c")], conns=[conn("c", all_p=None)])) == "UNKNOWN"


def test_sec_005():
    assert one("SEC-005", ctx([with_conn("c")], conns=[conn("c", level="ResourceGroup")])) == "PASS"
    assert one("SEC-005", ctx([with_conn("c")], conns=[conn("c", level="Subscription")])) == "WARN"
    assert one("SEC-005", ctx([with_conn("c")], conns=[conn("c", level="ManagementGroup")])) == "FAIL"
    assert statuses("SEC-005", ctx([with_conn("c", "dev")], conns=[conn("c")])) == []


# ================================================================== DEP
def prod_stage(**kw):
    return stage("Prod", [step("AzureWebApp@1")], tier="prod", **kw)


def classic(*stages):
    return pipe(list(stages), "ado_classic_release")


def test_dep_001_002():
    ok = classic(prod_stage(pre_approvals=[manual(False)]))
    none = classic(prod_stage())
    self_ok = classic(prod_stage(pre_approvals=[manual(True)]))
    assert one("DEP-001", ctx([ok])) == "PASS" and one("DEP-001", ctx([none])) == "FAIL"
    assert one("DEP-002", ctx([ok])) == "PASS" and one("DEP-002", ctx([self_ok])) == "FAIL"
    assert statuses("DEP-002", ctx([none])) == []
    yaml_p = pipe([prod_stage(env="prod-env")])
    assert one("DEP-001", ctx([yaml_p])) == "UNKNOWN"
    assert one("DEP-001", ctx([yaml_p], envs={"prod-env": Environment(id="1", name="prod-env")})) == "FAIL"


def test_dep_003():
    ok = classic(prod_stage(gates=[Approval(kind="servicenow", name="CRQ")]))
    task = classic(stage("Prod", [step("ServiceNow-DevOps-Change@1"), step("AzureWebApp@1")], tier="prod"))
    bad = classic(prod_stage(gates=[Approval(kind="gate", name="monitor")]))
    assert one("DEP-003", ctx([ok])) == "PASS" and one("DEP-003", ctx([task])) == "PASS"
    assert one("DEP-003", ctx([bad])) == "FAIL"


def test_dep_004():
    dev = stage("Dev", [step("AzureWebApp@1")], tier="dev")
    p_ok = classic(dev, prod_stage(depends_on=["Dev"]))
    p_direct = classic(dev, prod_stage())
    unknown_dep = classic(stage("Blue", [step("AzureWebApp@1")]), prod_stage(depends_on=["Blue"]))
    assert one("DEP-004", ctx([p_ok])) == "PASS"
    assert one("DEP-004", ctx([p_direct])) == "FAIL"
    assert one("DEP-004", ctx([unknown_dep])) == "WARN"


def dep(id, hours_ago=24, refs=()):
    return DeploymentRecord(id=id, stage_name="Prod", env_tier="prod", completed_at=NOW - timedelta(hours=hours_ago),
                            status="succeeded", change_refs=list(refs))


def cr(number, state="Implement", approval="approved", start=-30, end=-20):
    return ChangeRequest(number=number, state=state, approval=approval, start_date=NOW + timedelta(hours=start),
                         end_date=NOW + timedelta(hours=end), ci="r")


def dep005_ctx(deps, changes, ci_changes=(), available=True, ci=None):
    p = classic(prod_stage())
    p.deployments_90d = deps
    return ctx([p], snow=SnowFacts(available=available, changes={c.number: c for c in changes}, ci_changes=list(ci_changes)),
               repo_kw={"servicenow_ci": ci})


def test_dep_005():
    assert one("DEP-005", dep005_ctx([dep("1", 24, ["CHG0000001"])], [cr("CHG0000001")])) == "PASS"
    assert one("DEP-005", dep005_ctx([dep("1", 24, ["CHG0000001"])], [cr("CHG0000001", state="Canceled")])) == "FAIL"
    assert one("DEP-005", dep005_ctx([dep("1", 24, ["CHG0000001"])], [cr("CHG0000001", start=-200, end=-100)])) == "FAIL"  # outside window
    assert one("DEP-005", dep005_ctx([dep("1", 24, ["CHG0000009"])], [])) == "FAIL"  # CRQ referenced but not in SNOW
    assert one("DEP-005", dep005_ctx([dep("1", 24)], [])) == "UNKNOWN"  # cannot link, no CI
    assert one("DEP-005", dep005_ctx([dep("1", 24)], [], ci="r")) == "FAIL"  # CI known, nothing in window
    assert one("DEP-005", dep005_ctx([dep("1", 24)], [], [cr("CHG0000002")], ci="r")) == "PASS"  # CI + time window
    assert one("DEP-005", dep005_ctx([dep("1", 24, ["CHG0000001"])], [], available=False)) == "UNKNOWN"
    assert statuses("DEP-005", dep005_ctx([], [])) == []


def test_dep_006():
    ok = classic(stage("Prod", [step("AzureWebApp@1")], tier="prod", retention_days=365))
    short = classic(stage("Prod", [step("AzureWebApp@1")], tier="prod", retention_days=30))
    none = classic(stage("Prod", [step("AzureWebApp@1")], tier="prod"))
    assert one("DEP-006", ctx([ok])) == "PASS" and one("DEP-006", ctx([short])) == "FAIL" and one("DEP-006", ctx([none])) == "UNKNOWN"
    y = pipe([prod_stage(env="e")], retention_days=400)
    assert one("DEP-006", ctx([y])) == "PASS"


# ================================================================== TGT
def fa(steps, tier="prod", plat="ado_yaml"):
    return pipe([stage("Prod", steps, tier=tier, env="e")], plat)


def test_tgt_slots():
    good = fa([step("AzureFunctionApp@2", {"appType": "functionApp", "deployToSlotOrASE": True, "slotName": "staging"}), step("AzureAppServiceManage@0", {"Action": "Swap Slots"})])
    no_swap = fa([step("AzureFunctionApp@2", {"appType": "functionApp", "deployToSlotOrASE": True, "slotName": "staging"})])
    direct = fa([step("AzureFunctionApp@2", {"appType": "functionApp"})])
    assert one("TGT-FA-001", ctx([good])) == "PASS"
    assert one("TGT-FA-001", ctx([no_swap])) == "FAIL" and one("TGT-FA-001", ctx([direct])) == "FAIL"
    assert statuses("TGT-FA-001", ctx([fa([step("AzureFunctionApp@2")], tier="dev")])) == []
    wa_good = fa([step("AzureWebApp@1", {"slotName": "staging"}), step("script", script="az webapp deployment slot swap -g r -n w --slot staging")])
    assert one("TGT-WA-001", ctx([wa_good])) == "PASS"
    assert one("TGT-WA-001", ctx([fa([step("AzureWebApp@1")])])) == "FAIL"


def test_tgt_publish_profile():
    assert one("TGT-FA-002", ctx([fa([step("AzureFunctionApp@2", {"azureSubscription": "c"})])])) == "PASS"
    assert one("TGT-FA-002", ctx([fa([step("AzureFunctionApp@2", {"publishProfile": "x"})])])) == "FAIL"
    assert one("TGT-WA-002", ctx([fa([step("AzureWebApp@1", {"azureSubscription": "c"})])])) == "PASS"
    assert one("TGT-WA-002", ctx([fa([step("AzureWebApp@1"), step("script", script="curl -u $u:$p https://x.scm.azurewebsites.net/api/zipdeploy")])])) == "FAIL"
    assert one("TGT-WA-002", ctx([fa([step("AzureRmWebAppDeployment@4", {"ConnectionType": "PublishProfile"})])])) == "FAIL"


def aks_p(steps, build_steps=None):
    stages = ([stage("Build", build_steps, is_deploy=False)] if build_steps is not None else []) + [stage("Prod", steps, tier="prod", env="e")]
    return pipe(stages)


def test_tgt_aks():
    assert one("TGT-AKS-001", ctx([aks_p([step("KubernetesManifest@1", {"action": "deploy"})], [step("script", script="helm lint charts/x")])])) == "PASS"
    assert one("TGT-AKS-001", ctx([aks_p([step("KubernetesManifest@1", {"action": "deploy"})])])) == "FAIL"
    assert one("TGT-AKS-002", ctx([aks_p([step("KubernetesManifest@1", {"action": "deploy"})])])) == "PASS"
    assert one("TGT-AKS-002", ctx([aks_p([step("script", script="kubectl apply -f k8s/ && kubectl rollout status deploy/x")])])) == "PASS"
    assert one("TGT-AKS-002", ctx([aks_p([step("script", script="kubectl apply -f k8s/")])])) == "FAIL"
    assert one("TGT-AKS-002", ctx([aks_p([step("script", script="helm upgrade --install x chart --atomic")])])) == "PASS"


def adf_p(steps, build=None):
    stages = ([stage("Build", build, is_deploy=False)] if build is not None else []) + [stage("Prod", steps, tier="prod", env="e")]
    return pipe(stages)


ARM = lambda **inp: step("AzureResourceManagerTemplateDeployment@3", {"csmFile": "ArmTemplate/ARMTemplateForFactory.json", **inp})  # noqa: E731


def test_tgt_adf():
    npm = [step("script", script="npm run build validate ./ /subscriptions/x")]
    assert one("TGT-ADF-001", ctx([adf_p([ARM()], npm)])) == "PASS"
    assert one("TGT-ADF-001", ctx([adf_p([ARM()], [])])) == "FAIL"
    assert one("TGT-ADF-001", ctx([adf_p([ARM(), step("script", script="git checkout adf_publish")])])) == "FAIL"
    toggle = step("script", script="Stop-AzDataFactoryV2Trigger -Name x")
    assert one("TGT-ADF-002", ctx([adf_p([toggle, ARM()])])) == "PASS"
    assert one("TGT-ADF-002", ctx([adf_p([ARM()])])) == "FAIL"
    assert one("TGT-ADF-003", ctx([adf_p([ARM(overrideParameters="-factoryName adf-prod")])])) == "PASS"
    assert one("TGT-ADF-003", ctx([adf_p([ARM()])])) == "FAIL"


def test_tgt_synapse():
    syn = lambda **i: ctx([pipe([stage("Dev", [step("Synapse workspace deployment@2", i)], tier="dev", env="e")])])  # noqa: E731
    assert one("TGT-SYN-001", syn(operation="validateDeploy")) == "PASS"
    assert one("TGT-SYN-001", syn(operation="deploy")) == "FAIL"
    p_manual = pipe([stage("Dev", [step("script", script="az synapse workspace-package")], tier="dev", env="e")])
    p_manual.stages[0].deploy_targets = {"synapse"}
    assert one("TGT-SYN-001", ctx([p_manual])) == "FAIL"
    toggle = step("script", script="Stop-AzSynapseTrigger -Name t")
    mk = lambda *s: ctx([pipe([stage("Dev", [step("Synapse workspace deployment@2", {"operation": "deploy"}), *s], tier="dev", env="e")])])  # noqa: E731
    assert one("TGT-SYN-002", mk(toggle)) == "PASS"
    assert one("TGT-SYN-002", mk()) == "FAIL"


def test_tgt_sql():
    sql = lambda args, tier="prod", extra=(): ctx([pipe([stage("Prod", [step("SqlAzureDacpacDeployment@1", {"AdditionalArguments": args}), *extra], tier=tier, env="e")])])  # noqa: E731
    assert one("TGT-SQL-001", sql("/p:BlockOnPossibleDataLoss=true")) == "PASS"
    assert one("TGT-SQL-001", sql("/p:BlockOnPossibleDataLoss=false")) == "FAIL"
    assert one("TGT-SQL-002", sql("/DeployReportPath:r.xml")) == "PASS"
    assert one("TGT-SQL-002", sql("")) == "FAIL"
    assert one("TGT-SQL-002", sql("", extra=[step("script", script="sqlpackage /Action:DeployReport")])) == "PASS"
    assert statuses("TGT-SQL-002", sql("", tier="dev")) == []


def test_tgt_iac():
    ordered = pipe([stage("Dev", [step("script", script="az deployment group what-if -g r -f m.bicep"), step("script", script="az deployment group create -g r -f m.bicep")], tier="dev", env="e")])
    unordered = pipe([stage("Dev", [step("script", script="az deployment group create -g r -f m.bicep"), step("script", script="az deployment group what-if -g r -f m.bicep")], tier="dev", env="e")])
    none = pipe([stage("Dev", [step("script", script="az deployment group create -g r -f m.bicep")], tier="dev", env="e")])
    earlier_stage = pipe([stage("Plan", [step("TerraformTaskV4@4", {"command": "plan"})], env="p"), stage("Apply", [step("TerraformTaskV4@4", {"command": "apply"})], env="a")])
    assert one("TGT-IAC-001", ctx([ordered])) == "PASS"
    assert one("TGT-IAC-001", ctx([unordered])) == "FAIL"
    assert one("TGT-IAC-001", ctx([none])) == "FAIL"
    assert statuses("TGT-IAC-001", ctx([earlier_stage])) == ["PASS"]


# ================================================================== HYG
def test_hyg():
    ok = pipe([stage("b")], run_stats_90d=RunStats(total=10, succeeded=9, failed=1, last_success=NOW - timedelta(days=2)), owner="a@b.c")
    stale = pipe([stage("b")], id="2", run_stats_90d=RunStats(total=3, succeeded=0, failed=3))
    norun = pipe([stage("b")], id="3", run_stats_90d=RunStats())
    unk = pipe([stage("b")], id="4")
    assert statuses("HYG-001", ctx([ok, stale, unk])) == ["PASS", "FAIL", "UNKNOWN"]
    assert statuses("HYG-002", ctx([ok, stale, norun, unk])) == ["PASS", "FAIL", "UNKNOWN"]
    bad_rate = pipe([stage("b")], id="5", run_stats_90d=RunStats(total=10, succeeded=5, failed=5, last_success=NOW))
    assert one("HYG-002", ctx([bad_rate])) == "FAIL"
    assert statuses("HYG-003", ctx([ok, stale])) == ["PASS", "FAIL"]
    assert one("HYG-003", ctx([stale], repo_kw={"owner": "team@x"})) == "PASS"


def test_catalog_complete():
    from pch.engine.registry import all_rules

    ids = {r.id for r in all_rules()}
    expected = (
        [f"SRC-00{i}" for i in range(1, 7)] + [f"QLT-00{i}" for i in range(1, 9)] + [f"TST-00{i}" for i in range(1, 7)]
        + [f"SUP-00{i}" for i in range(1, 6)] + [f"SEC-00{i}" for i in range(1, 6)] + [f"DEP-00{i}" for i in range(1, 7)]
        + ["TGT-FA-001", "TGT-FA-002", "TGT-WA-001", "TGT-WA-002", "TGT-AKS-001", "TGT-AKS-002", "TGT-ADF-001", "TGT-ADF-002",
           "TGT-ADF-003", "TGT-SYN-001", "TGT-SYN-002", "TGT-SQL-001", "TGT-SQL-002", "TGT-IAC-001"]
        + [f"HYG-00{i}" for i in range(1, 4)]
    )
    assert ids == set(expected)
    for r in all_rules():
        assert r.rationale and r.remediation and r.title


# ================================================================== MIG
def test_migration_readiness():
    from pch.engine.migration import pipeline_readiness, repo_readiness

    yaml_p = pipe([stage("Build", [step("DotNetCoreCLI@2"), step("PublishPipelineArtifact@1")])])
    s, b = pipeline_readiness(yaml_p)
    assert s == 100 and b == []
    classic_rel = pipe([stage("Prod", [step("ManualIntervention@8"), step("AzureFunctionApp@2")], tier="prod", gates=[Approval(kind="servicenow", name="x")])],
                       "ado_classic_release", uses_task_groups=True, uses_deployment_groups=True)
    s2, b2 = pipeline_readiness(classic_rel)
    assert s2 < 50 and any("ManualIntervention" in x for x in b2) and any("deployment groups" in x for x in b2)
    assert repo_readiness(ctx([yaml_p, classic_rel]))[0] == round((s + s2) / 2)
    assert repo_readiness(ctx([])) == (None, [])
