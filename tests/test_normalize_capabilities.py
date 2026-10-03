import pytest

from pch.model.pipeline import Pipeline, Stage, Step
from pch.normalize.capabilities import classify_step, load_catalog
from pch.normalize.target_detect import detect_env_tier, detect_targets, enrich_pipeline, tier_from_name


def S(task=None, inputs=None, script=None, name="step", **kw):
    return classify_step(Step(id="1", name=name, task=task, inputs=inputs or {}, inline_script=script, **kw))


@pytest.mark.parametrize(
    "task,inputs,expected",
    [
        ("SonarQubePrepare@5", {}, {"sast:sonar", "sonar:prepare"}),
        ("SonarQubeAnalyze@5", {}, {"sonar:analyze"}),
        ("SonarQubePublish@5", {}, {"sonar:publish"}),
        ("DotNetCoreCLI@2", {"command": "test"}, {"unit-test"}),
        ("DotNetCoreCLI@2", {"command": "build"}, {"build"}),
        ("DotNetCoreCLI@2", {}, {"build"}),  # default command
        ("VSTest@2", {}, {"unit-test"}),
        ("Maven@3", {"goals": "clean verify"}, {"unit-test", "build"}),
        ("PublishTestResults@2", {}, {"test-results-publish"}),
        ("PublishCodeCoverageResults@1", {}, {"coverage-publish"}),
        ("AzureFunctionApp@2", {}, {"deploy:functionapp"}),
        ("AzureWebApp@1", {}, {"deploy:webapp"}),
        ("AzureRmWebAppDeployment@4", {"WebAppKind": "functionApp"}, {"deploy:functionapp"}),
        ("AzureRmWebAppDeployment@4", {"appType": "webAppLinux"}, {"deploy:webapp"}),
        ("AzureAppServiceManage@0", {"Action": "Swap Slots"}, {"slot-swap"}),
        ("KubernetesManifest@1", {"action": "deploy"}, {"deploy:aks", "rollout-status"}),
        ("HelmDeploy@0", {"command": "upgrade"}, {"deploy:aks"}),
        ("AzureResourceManagerTemplateDeployment@3", {"deploymentMode": "Incremental"}, {"deploy:iac"}),
        ("AzureResourceManagerTemplateDeployment@3", {"deploymentMode": "Validation"}, {"whatif"}),
        ("AzureCLI@2", {}, {"azcli"}),
        ("Synapse workspace deployment@2", {}, {"deploy:synapse"}),
        ("SqlAzureDacpacDeployment@1", {}, {"deploy:sql"}),
        ("SqlDacpacDeploymentOnMachineGroup@0", {}, {"deploy:sql"}),
        ("TerraformTaskV4@4", {"command": "apply"}, {"deploy:iac"}),
        ("TerraformTaskV4@4", {"command": "plan"}, {"plan"}),
        ("ServiceNow-DevOps-Change@1", {}, {"gate:servicenow"}),
        ("Docker@2", {"command": "buildAndPush"}, {"container:push", "build", "container:build"}),
        ("AdvancedSecurity-Codeql-Init@1", {}, {"sast:ghas"}),
    ],
)
def test_task_capabilities(task, inputs, expected):
    assert S(task, inputs).capabilities >= expected


@pytest.mark.parametrize(
    "script,cap",
    [
        ("dotnet test --no-build", "unit-test"),
        ("pytest -q", "unit-test"),
        ("npm test", "unit-test"),
        ("npm run test", "unit-test"),
        ("go test ./...", "unit-test"),
        ("kubectl apply -f k8s/", "deploy:aks"),
        ("helm upgrade --install x chart", "deploy:aks"),
        ("kubectl rollout status deploy/x", "rollout-status"),
        ("helm lint chart", "lint:k8s"),
        ("az functionapp deployment source config-zip -g rg -n f", "deploy:functionapp"),
        ("az webapp deploy --src-path x.zip", "deploy:webapp"),
        ("az deployment group create -g rg -f main.bicep", "deploy:iac"),
        ("az deployment group what-if -g rg -f main.bicep", "whatif"),
        ("terraform plan -out tf.plan", "plan"),
        ("Stop-AzDataFactoryV2Trigger -Name t", "trigger-toggle"),
        ("npm i @microsoft/azure-data-factory-utilities", "adf:npm-utils"),
        ("npm run build validate ./ /subscriptions/x", "validate:adf"),
        ("curl -f https://x/health", "smoke-test"),
        ("syft packages dir:. -o cyclonedx-json", "sbom"),
        ("sqlpackage /Action:DeployReport /SourceFile:x.dacpac", "dacpac-report"),
    ],
)
def test_script_capabilities_are_heuristic(script, cap):
    s = S("script", script=script)
    assert cap in s.capabilities
    assert cap in s.heuristic_caps


def test_step_name_heuristic_and_inline_from_inputs():
    assert "smoke-test" in S("AzureCLI@2", name="Post-deployment smoke test").capabilities
    s = S("AzureCLI@2", inputs={"inlineScript": "kubectl apply -f x"})
    assert "deploy:aks" in s.capabilities and "azcli" in s.capabilities


def test_deprecated_flag_and_unknown():
    assert S("AzureResourceGroupDeployment@2").deprecated
    assert S("AzureFunctionApp@1").deprecated
    assert not S("AzureFunctionApp@2").deprecated
    assert not S("SomeRandomTask@1").deprecated
    assert S("SomeRandomTask@1").capabilities == set()


def test_catalog_is_data():
    cat = load_catalog()
    assert any(k[0] == "azurefunctionapp" for k in cat.tasks)


@pytest.mark.parametrize(
    "name,tier",
    [
        ("Production", "prod"), ("Deploy_Prod", "prod"), ("prd-eu", "prod"), ("PROD", "prod"), ("DeployProd", "prod"),
        ("PreProd", "uat"), ("pre-prod", "uat"), ("UAT", "uat"), ("staging", "uat"), ("Stage", "uat"),
        ("QA", "test"), ("Test", "test"), ("SIT", "test"), ("tst2", "test"),
        ("Dev", "dev"), ("development", "dev"), ("INT", "dev"),
        ("Build", "unknown"), ("Internal", "unknown"), ("ProductService", "unknown"), (None, "unknown"),
    ],
)
def test_tier_from_name(name, tier):
    assert tier_from_name(name) == tier


def test_tier_overrides_win():
    assert detect_env_tier(["Blue"], {"Blue": "prod"}) == "prod"
    assert detect_env_tier(["Production"], {"Production": "uat"}) == "uat"
    assert detect_env_tier([None, "dev-1"], {}) == "dev"


def test_adf_and_synapse_detection():
    arm = Step(id="1", name="arm", task="AzureResourceManagerTemplateDeployment@3",
               inputs={"csmFile": "x/ARMTemplateForFactory.json"})
    classify_step(arm)
    st = Stage(name="Prod", jobs=[__import__("pch.model.pipeline", fromlist=["Job"]).Job(name="j", steps=[arm])])
    assert detect_targets(st) == {"adf"}
    plain = Step(id="2", name="arm", task="AzureResourceManagerTemplateDeployment@3", inputs={"csmFile": "main.json"})
    classify_step(plain)
    st2 = Stage(name="d", jobs=[__import__("pch.model.pipeline", fromlist=["Job"]).Job(name="j", steps=[plain])])
    assert detect_targets(st2) == {"iac"}
    syn = Step(id="3", name="arm", task="AzureResourceManagerTemplateDeployment@3", inputs={"csmFile": "TemplateForWorkspace.json"})
    classify_step(syn)
    st3 = Stage(name="d", jobs=[__import__("pch.model.pipeline", fromlist=["Job"]).Job(name="j", steps=[syn])])
    assert detect_targets(st3) == {"synapse"}


def test_enrich_sets_tier_connections():
    from pch.model.pipeline import Job

    step = classify_step(Step(id="1", name="d", task="AzureFunctionApp@2", inputs={"azureSubscription": "conn-prod"}))
    p = Pipeline(platform="ado_yaml", id="1", name="p", project="P",
                 stages=[Stage(name="Deploy_Prod", env_name="orders-prod", jobs=[Job(name="j", steps=[step])])])
    enrich_pipeline(p)
    st = p.stages[0]
    assert st.env_tier == "prod" and st.deploy_targets == {"functionapp"} and st.service_connections == ["conn-prod"]
    assert st.is_deploy
