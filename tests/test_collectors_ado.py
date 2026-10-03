import httpx
import pytest
import respx

from pch.collectors.ado.classic_build import normalize_build_definition
from pch.collectors.ado.classic_release import normalize_release_definition
from pch.collectors.ado.client import AdoClient
from pch.collectors.ado.task_catalog import TaskCatalog, load_task_catalog
from pch.collectors.ado.yaml_pipeline import parse_yaml_pipeline
from pch.normalize.target_detect import enrich_pipeline

WEB = "https://dev.azure.com/contoso/Payments"


def build(fx, catalog):
    return normalize_build_definition(fx("ado", "build_def_classic_dotnet.json"), catalog, "Payments", WEB)


def release(fx, catalog, name, **kw):
    p = normalize_release_definition(fx("ado", f"release_def_{name}.json"), catalog, "Payments", WEB, {"5": "payments-common"}, **kw)
    return enrich_pipeline(p)


def test_task_catalog_resolution(fx):
    cat = TaskCatalog.from_payload(fx("ado", "tasks.json"))
    tid = [t["id"] for t in fx("ado", "tasks.json")["value"] if t["name"] == "SonarQubePrepare"][0]
    name, major, d = cat.resolve(tid, "5.*")
    assert (name, major) == ("SonarQubePrepare", "5") and d.marketplace
    assert cat.resolve(tid, "*")[1] is None  # unpinned
    assert cat.resolve("unknown-guid", None)[0] == "unknown-guid"
    fa = [t["id"] for t in fx("ado", "tasks.json")["value"] if t["name"] == "AzureFunctionApp"][0]
    assert cat.by_id[fa.lower()].major == 2 and not cat.by_id[fa.lower()].marketplace


@respx.mock
async def test_load_task_catalog_fetches_once(fx):
    r1 = respx.get("https://dev.azure.com/contoso/_apis/distributedtask/tasks").mock(
        return_value=httpx.Response(200, json=fx("ado", "tasks.json")))
    respx.get(f"{WEB}/_apis/distributedtask/taskgroups").mock(return_value=httpx.Response(200, json=fx("ado", "taskgroups.json")))
    c = AdoClient("contoso", "x", backoff_base=0)
    cat = await load_task_catalog(c, ["Payments"])
    await c.aclose()
    assert r1.call_count == 1 and cat.task_groups


def test_classic_build_normalization(fx, catalog):
    p = build(fx, catalog)
    assert p.platform == "ado_classic_build" and not p.definition_in_source_control
    assert p.repo == "payments-api" and p.pool_type == "hosted" and p.retention_days == 30
    caps = p.capabilities()
    assert {"sonar:prepare", "sonar:analyze", "sonar:publish", "unit-test", "coverage-publish", "test-results-publish", "build"} <= caps
    names = {v.name: v for v in p.variables}
    assert names["dbPassword"].secret_like_reason  # plaintext secret-like var flagged
    assert names["apiKey"].is_secret and names["apiKey"].secret_like_reason is None
    assert names["BuildConfiguration"].secret_like_reason is None
    assert not any(hasattr(v, "value") for v in p.variables)  # values are never kept
    assert p.variable_groups[0].name == "payments-common"
    assert all(s.task_version == "5" for s in p.all_steps() if s.task and s.task.startswith("Sonar"))


def test_classic_build_task_group_expansion(fx, catalog):
    defn = fx("ado", "build_def_classic_dotnet.json")
    tg = list(catalog.task_groups)[0]
    defn["process"]["phases"][0]["steps"].append({"enabled": True, "displayName": "tg", "task": {"id": tg, "versionSpec": "1.*"}, "inputs": {}})
    p = normalize_build_definition(defn, catalog, "Payments", WEB)
    assert p.uses_task_groups
    assert any(s.name.startswith("[Sonar Standard]") for s in p.all_steps())


def test_release_functionapp_governance(fx, catalog):
    p = release(fx, catalog, "functionapp")
    assert p.platform == "ado_classic_release" and p.linked_build_ids == ["12"]
    dev, uat, prod = p.stages
    assert [s.env_tier for s in p.stages] == ["dev", "uat", "prod"]
    assert prod.depends_on == ["UAT"] and dev.depends_on == []
    assert prod.pre_approvals[0].kind == "manual" and prod.pre_approvals[0].requester_can_approve is False
    assert any(g.kind == "servicenow" for g in prod.gates)
    assert prod.post_approvals and prod.post_approvals[0].kind == "gate"
    assert prod.deploy_targets == {"functionapp"} and "slot-swap" in prod.capabilities()
    assert not dev.pre_approvals and prod.retention_days == 365
    assert prod.service_connections == ["conn-prod-wif"]
    assert prod.branch_filters == ["main"]
    assert any(v.secret_like_reason for v in p.variables)  # connStr with password
    assert p.variable_groups[0].name == "payments-common"


@pytest.mark.parametrize("name,target", [("aks", "aks"), ("adf", "adf"), ("synapse", "synapse"), ("sql", "sql"), ("iac", "iac")])
def test_release_targets(fx, catalog, name, target):
    p = release(fx, catalog, name)
    assert target in p.deploy_targets


def test_release_adf_trigger_toggle_and_overrides(fx, catalog):
    p = release(fx, catalog, "adf")
    prod = p.stages[-1]
    assert "trigger-toggle" in prod.capabilities()
    assert prod.deploy_targets == {"adf"}


def test_release_iac_whatif_precedes_deploy(fx, catalog):
    p = release(fx, catalog, "iac")
    caps = [sorted(s.capabilities) for s in p.stages[0].steps()]
    assert "whatif" in caps[0] and "deploy:iac" in caps[1]


def test_release_deployment_group_and_taskgroup(fx, catalog):
    p = release(fx, catalog, "taskgroup")
    assert p.uses_deployment_groups and p.uses_task_groups


def test_release_disabled_gates_ignored(fx, catalog):
    d = fx("ado", "release_def_functionapp.json")
    d["environments"][2]["preDeploymentGates"]["gatesOptions"]["isEnabled"] = False
    p = normalize_release_definition(d, catalog, "Payments", WEB)
    assert not p.stages[2].gates


@pytest.mark.parametrize(
    "name,target,tier_stage",
    [("functionapp", "functionapp", "Prod"), ("aks", "aks", "Prod"), ("adf", "adf", "Prod"),
     ("synapse", "synapse", "Dev"), ("sql", "sql", "Prod"), ("iac", "iac", "Dev")],
)
def test_yaml_targets(fxt, name, target, tier_stage):
    p = parse_yaml_pipeline(fxt("ado", f"yaml_{name}.yaml"), {"id": 1, "name": "x", "repository": {"name": "r", "id": "i"}}, "Payments", WEB)
    enrich_pipeline(p)
    assert p.platform == "ado_yaml" and p.definition_in_source_control
    stage = p.stage(tier_stage)
    assert target in stage.deploy_targets


def test_yaml_functionapp_details(fxt):
    p = parse_yaml_pipeline(fxt("ado", "yaml_functionapp.yaml"), {"id": 21, "name": "o", "repository": {"name": "orders-func", "id": "r2"}, "retentionRules": [{"daysToKeep": 400}]}, "Payments", WEB)
    enrich_pipeline(p)
    assert [s.name for s in p.stages] == ["Build", "Dev", "Prod"]
    assert p.stage("Prod").depends_on == ["Dev"] and p.stage("Prod").env_name == "orders-prod"
    assert p.stage("Prod").env_tier == "prod" and p.stage("Dev").env_tier == "dev"
    assert p.retention_days == 400 and p.pool_type == "hosted"
    assert {"sonar:prepare", "sonar:analyze", "sonar:publish", "artifact:publish"} <= p.stage("Build").capabilities()
    test_step = [s for s in p.stage("Build").steps() if s.name == "Test"][0]
    assert test_step.continue_on_error and "unit-test" in test_step.capabilities
    assert "smoke-test" in p.stage("Prod").capabilities()
    assert [v.name for v in p.variables if v.secret_like_reason] == ["dbPassword"]
    assert p.variable_groups[0].name == "payments-common"
    assert p.triggers["branches"] == ["main"]


def test_yaml_implicit_sequential_dependency_and_empty_dependson(fxt):
    p = parse_yaml_pipeline(fxt("ado", "yaml_aks.yaml"), {"id": 1, "name": "x"}, "P", WEB)
    assert p.stage("Prod").depends_on == []  # explicit empty list
    p2 = parse_yaml_pipeline("stages:\n- stage: A\n  jobs: []\n- stage: B\n  jobs: []\n", {"id": 1, "name": "x"}, "P", WEB)
    assert p2.stage("B").depends_on == ["A"]


def test_yaml_no_stages_single_implicit(fxt):
    p = parse_yaml_pipeline(fxt("ado", "yaml_webapp.yaml"), {"id": 2, "name": "w"}, "P", WEB)
    enrich_pipeline(p)
    assert len(p.stages) == 1
    assert {"unit-test", "deploy:webapp"} <= p.stages[0].capabilities()


@respx.mock
async def test_yaml_preview_post(fx):
    route = respx.post("https://dev.azure.com/contoso/Payments/_apis/pipelines/21/preview").mock(
        return_value=httpx.Response(200, json=fx("ado", "preview_functionapp.json")))
    c = AdoClient("contoso", "x", backoff_base=0)
    out = await c.post_preview("Payments", 21)
    await c.aclose()
    assert "AzureFunctionApp@2" in out["finalYaml"]
    assert b"previewRun" in route.calls[0].request.content
