"""Synthetic estate generator: ~280 repos across 6 projects, emitted as RAW API payloads.

Everything is deterministic for a given (seed, repos, quality_shift). Per-repo "traits" are drawn from
independent uniform samples keyed by name, so changing `quality_shift` (used for demo history snapshots)
moves traits smoothly instead of reshuffling the whole estate.
"""

from __future__ import annotations

import json
import random
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from pch.demo import payloads as P
from pch.demo.payloads import SD, WEB

PROJECT_PLAN: dict[str, tuple[float, dict[str, int]]] = {
    "Payments": (0.92, {"functionapp": 14, "webapp": 14, "aks": 14, "sql": 4, "lib": 8, "iac": 2, "docs": 4}),
    "Customer": (0.80, {"functionapp": 12, "webapp": 18, "aks": 8, "lib": 10, "sql": 3, "docs": 4}),
    "Logistics": (0.68, {"functionapp": 10, "webapp": 12, "aks": 12, "lib": 8, "sql": 3, "iac": 3, "docs": 2}),
    "Data-Platform": (0.62, {"adf": 22, "synapse": 11, "sql": 8, "functionapp": 4}),
    "Platform-Infra": (0.90, {"iac": 17, "lib": 5, "docs": 4, "webapp": 2, "functionapp": 2}),
    "Retail": (0.52, {"webapp": 16, "functionapp": 8, "aks": 6, "lib": 10}),
}
DOMAIN_WORDS = {
    "Payments": ["ledger", "billing", "invoice", "settlement", "fraud", "refund", "wallet", "checkout", "tax", "payout"],
    "Customer": ["profile", "loyalty", "consent", "support", "onboarding", "identity", "preferences", "notification", "crm", "survey"],
    "Logistics": ["shipment", "routing", "warehouse", "fleet", "tracking", "dispatch", "inventory", "returns", "customs", "pickup"],
    "Data-Platform": ["sales", "orders", "finance", "marketing", "telemetry", "hr", "pricing", "supply", "risk", "reference"],
    "Platform-Infra": ["network", "identity", "monitoring", "keyvault", "aks-cluster", "landing-zone", "policy", "storage", "registry", "dns"],
    "Retail": ["catalog", "cart", "storefront", "promo", "search", "pos", "stock", "pricing", "reviews", "recommend"],
}
SUFFIX = {"functionapp": ["func", "fn", "processor"], "webapp": ["web", "api", "portal"], "aks": ["svc", "service", "gateway"],
          "adf": ["adf"], "synapse": ["synapse", "dwh"], "sql": ["db", "sqlproj"], "iac": ["infra", "iac", "tf"],
          "lib": ["lib", "sdk", "common"], "docs": ["docs", "runbooks", "wiki"]}
APP_KINDS = {"functionapp", "webapp", "aks", "lib", "sql"}
SECRET_WORDS = ["dbPassword", "apiKey", "clientSecret", "storageConnectionString", "sasToken"]


def _u(seed: int, idx: int, name: str) -> float:
    return random.Random(f"{seed}:{idx}:{name}").random()


def clamp(x: float, lo: float = 0.02, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


@dataclass
class RepoSpec:
    idx: int
    seed: int
    project: str
    name: str
    kind: str
    lang: str | None
    q: float
    repo_id: str
    default_branch: str
    style: str  # classic | yaml | none
    tests: str  # none | notrun | ok | low | nocov | na
    t: dict[str, bool] = field(default_factory=dict)  # boolean traits
    n: dict[str, Any] = field(default_factory=dict)  # numeric / enum traits

    def has(self, trait: str) -> bool:
        return self.t.get(trait, False)

    @property
    def key(self) -> str:
        return f"{self.project}/{self.name}"


def build_plan(repos: int) -> list[tuple[str, str]]:
    base: list[tuple[str, str]] = []
    for project, (_, kinds) in PROJECT_PLAN.items():
        for kind, count in kinds.items():
            base.extend([(project, kind)] * count)
    plan = [base[i % len(base)] for i in range(repos)]
    return plan


def make_spec(seed: int, idx: int, project: str, kind: str, qshift: float, used_names: set[str]) -> RepoSpec:
    u = lambda n: _u(seed, idx, n)  # noqa: E731
    q = clamp(PROJECT_PLAN[project][0] + (u("qnoise") - 0.5) * 0.3 + qshift)
    word = DOMAIN_WORDS[project][int(u("word") * len(DOMAIN_WORDS[project])) % len(DOMAIN_WORDS[project])]
    suf = SUFFIX[kind][int(u("suffix") * 99) % len(SUFFIX[kind])]
    base = f"{word}-{suf}"
    name, n = base, 2
    while name in used_names:
        name, n = f"{base}-{n}", n + 1
    used_names.add(name)
    lang_roll = u("lang")
    lang = None
    if kind == "functionapp":
        lang = "dotnet" if lang_roll < 0.55 else "python" if lang_roll < 0.8 else "js"
    elif kind == "webapp":
        lang = "dotnet" if lang_roll < 0.55 else "js" if lang_roll < 0.9 else "java"
    elif kind == "aks":
        lang = "java" if lang_roll < 0.4 else "dotnet" if lang_roll < 0.75 else "python" if lang_roll < 0.9 else "js"
    elif kind == "lib":
        lang = "dotnet" if lang_roll < 0.6 else "js" if lang_roll < 0.9 else "python"
    elif kind == "sql":
        lang = "sql"
    # pipeline style: ~5% none, ~55% classic, ~40% yaml (yaml share grows with quality)
    sr = u("style")
    yaml_cut = clamp(0.62 - (q - 0.7) * 0.25, 0.5, 0.75)
    style = "none" if sr < 0.05 else ("classic" if sr < yaml_cut else "yaml")
    if kind == "docs":
        style = "none" if sr < 0.45 else "yaml"
    # tests (application repos only): ~25% none, ~10% not run
    tests = "na"
    if kind in APP_KINDS:
        tr = u("tests")
        p_no = clamp(0.27 + (0.6 - q) * 0.15, 0.15, 0.4)
        p_notrun = 0.07
        p_nocov = 0.10
        p_low = clamp(0.18 + (0.55 - q) * 0.2, 0.05, 0.4)
        if tr < p_no:
            tests = "none"
        elif tr < p_no + p_notrun:
            tests = "notrun"
        elif tr < p_no + p_notrun + p_nocov:
            tests = "nocov"
        elif tr < p_no + p_notrun + p_nocov + p_low:
            tests = "low"
        else:
            tests = "ok"
    spec = RepoSpec(idx=idx, seed=seed, project=project, name=name, kind=kind, lang=lang, q=q, repo_id=f"repo-{idx:04d}",
                    default_branch="master" if u("branch") < 0.1 else "main", style=style, tests=tests)

    def b(trait: str, p: float) -> None:
        spec.t[trait] = u(trait) < clamp(p, 0.0, 1.0)

    b("sonar_steps", 0.5 + 0.45 * q); b("sonar_enforce", 0.3 + 0.5 * q); b("sonar_extra", 0.1)
    b("sonar_company_gate", 0.45 + 0.5 * q); b("sonar_recent", 0.45 + 0.5 * q); b("sonar_coe", 0.2 - 0.17 * q)
    b("aikido", 0.65 + 0.3 * q)
    b("pol_two_reviewers", 0.5 + 0.45 * q); b("pol_creator_votes", 0.3 - 0.28 * q); b("pol_reset", 0.55 + 0.4 * q)
    b("pol_build", 0.5 + 0.4 * q); b("pol_workitem", 0.55 + 0.4 * q); b("pol_comments", 0.55 + 0.4 * q)
    b("pol_required_rev", 0.2 + 0.2 * q); b("codeowners", 0.15 + 0.25 * q)
    b("publish_results", 0.5 + 0.45 * q); b("publish_cov", 0.5 + 0.45 * q); b("sbom", 0.05 + 0.25 * q)
    b("smoke", 0.45 + 0.5 * q); b("smoke_gate", 0.5)
    b("direct_to_prod", 0.02 + 0.1 * (1 - q)); b("prod_approval", 0.5 + 0.45 * q); b("requester_can_approve", 0.3 - 0.25 * q)
    b("snow_gate", 0.5 + 0.45 * q); b("branch_filter", 0.55 + 0.4 * q); b("kv_group", 0.3 + 0.6 * q); b("secret_var", 0.22 - 0.2 * q)
    b("conn_wif", 0.45 + 0.5 * q); b("conn_rg", 0.3 + 0.5 * q); b("retention_ok", 0.55 + 0.4 * q)
    b("unpinned", 0.3 - 0.25 * q); b("deprecated_task", 0.3 - 0.25 * q); b("marketplace_unlisted", 0.12)
    b("rebuild_in_deploy", 0.25 - 0.2 * q); b("slot", 0.3 + 0.55 * q); b("publish_profile", 0.15 - 0.12 * q)
    b("k8s_lint", 0.3 + 0.5 * q); b("k8s_rollout", 0.4 + 0.5 * q); b("k8s_latest", 0.3 - 0.25 * q); b("k8s_registry_ok", 0.7 + 0.25 * q)
    b("adf_npm", 0.4 + 0.5 * q); b("adf_toggle", 0.35 + 0.55 * q); b("adf_overrides", 0.5 + 0.45 * q); b("adf_validate", 0.5 + 0.4 * q)
    b("syn_validate", 0.4 + 0.5 * q); b("syn_toggle", 0.3 + 0.5 * q)
    b("sql_block_false", 0.3 - 0.25 * q); b("sql_report", 0.25 + 0.5 * q); b("iac_whatif", 0.35 + 0.55 * q)
    b("stale", 0.12 * (1 - q)); b("has_owner", 0.85); b("has_ci", 0.65); b("sonar_key_override", 0.2); b("preview_fails", 0.05); b("def_500", 0.012); b("disabled", 0.007); b("empty_repo", 0.01)
    b("sonar_exists_noxsteps", 0.1); b("sonar_error_500", 0.03)
    tr = u("tiers")
    spec.n["tiers"] = ["Prod"] if tr < 0.12 else ["Dev", "Prod"] if tr < 0.12 + 0.3 * (1 - q) else (["Dev", "Test", "Prod"] if tr < 0.75 else ["Dev", "UAT", "Prod"])
    ar = u("aks_mode")
    spec.n["aks_mode"] = "manifest" if ar < 0.5 else "helm" if ar < 0.75 else "kubectl"
    spec.n["tf"] = u("tf") < 0.4
    cr = u("crq")
    spec.n["crq"] = "good" if cr < 0.45 + 0.5 * q else "partial" if cr < 0.45 + 0.5 * q + 0.2 else "none"
    spec.n["runs"] = int(u("runs") * 38) + 2
    spec.n["success"] = clamp(0.8 + 0.2 * q + (u("succ") - 0.5) * 0.2, 0.45, 0.99)
    spec.n["gate_roll"] = u("gate")
    spec.n["secret_name"] = SECRET_WORDS[int(u("secname") * 99) % len(SECRET_WORDS)]
    return spec


# ------------------------------------------------------------------ repo contents
def repo_files(s: RepoSpec) -> tuple[list[str], dict[str, str]]:
    paths: list[str] = ["README.md", ".gitignore"]
    contents: dict[str, str] = {}
    nm = "".join(w.capitalize() for w in s.name.replace("_", "-").split("-"))
    has_tests = s.tests != "none" and s.tests != "na"
    if s.kind in ("functionapp", "webapp", "aks", "lib") and s.lang == "dotnet":
        paths += [f"src/{nm}/{nm}.csproj", f"src/{nm}/Program.cs", f"src/{nm}/Startup.cs"]
        contents[f"src/{nm}/{nm}.csproj"] = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>'
        if has_tests:
            tp = f"tests/{nm}.Tests/{nm}.Tests.csproj"
            paths += [tp, f"tests/{nm}.Tests/UnitTests.cs"]
            contents[tp] = '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="xunit" Version="2.6.0" /><PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.8.0" /></ItemGroup></Project>'
    elif s.lang == "java":
        paths += ["pom.xml", f"src/main/java/com/contoso/{nm}/App.java", f"src/main/java/com/contoso/{nm}/Service.java"]
        if has_tests:
            paths += [f"src/test/java/com/contoso/{nm}/AppTest.java"]
    elif s.lang == "python":
        paths += ["requirements.txt", f"app/{s.name.replace('-', '_')}/main.py", "app/__init__.py"]
        contents["requirements.txt"] = "flask\nrequests\n" + ("pytest==8.0\n" if has_tests else "")
        if has_tests:
            paths += ["tests/test_main.py"]
    elif s.lang == "js":
        paths += ["package.json", "src/index.ts", "src/handler.ts"]
        deps = '{"name": "x", "scripts": {"test": "jest"}, "devDependencies": {"jest": "^29.0.0"}}' if has_tests else '{"name": "x", "dependencies": {"express": "^4"}}'
        contents["package.json"] = deps
        if has_tests:
            paths += ["src/handler.test.ts"]
    elif s.kind == "sql":
        paths += [f"db/{nm}.sqlproj", "db/Tables/Customer.sql", "db/Tables/Order.sql", "db/StoredProcedures/usp_get.sql"]
        contents[f"db/{nm}.sqlproj"] = "<Project><PropertyGroup><Name>db</Name></PropertyGroup></Project>"
        if has_tests:
            paths += ["db/tSQLt/Tests_Customer.sql"]
    elif s.kind == "adf":
        paths += ["factory/adf-prod.json", "pipeline/CopySales.json", "pipeline/Transform.json", "dataset/SalesCsv.json",
                  "linkedService/AzureSqlLS.json", "trigger/Daily.json", "publish_config.json"]
        if s.has("adf_npm"):
            paths += ["package.json", "build/package.json"]
            contents["package.json"] = '{"scripts": {"build": "node node_modules/@microsoft/azure-data-factory-utilities/lib/index"}}'
    elif s.kind == "synapse":
        paths += ["notebook/Prep.json", "sqlscript/Load.json", "pipeline/Ingest.json", "integrationRuntime/ir1.json", "linkedService/ls.json"]
        if s.has("syn_validate"):
            paths += ["TemplateForWorkspace.json"]
    elif s.kind == "iac":
        if s.n.get("tf"):
            paths += ["main.tf", "variables.tf", "modules/network/main.tf"]
        else:
            paths += ["main.bicep", "modules/storage.bicep", "modules/network.bicep", "main.parameters.json"]
    else:
        paths += ["docs/index.md", "docs/runbook.md"]
    if s.kind == "aks":
        paths += ["Dockerfile", "k8s/deployment.yaml", "k8s/service.yaml"]
        if s.n["aks_mode"] == "helm":
            paths += [f"charts/{s.name}/Chart.yaml", f"charts/{s.name}/values.yaml"]
    if s.style == "yaml":
        paths += ["azure-pipelines.yml"]
    if s.has("codeowners"):
        paths += ["CODEOWNERS"]
    return paths, contents


# ------------------------------------------------------------------ step descriptors
def conn_name(project: str, tier: str, spec: RepoSpec) -> str:
    style = "wif" if spec.has("conn_wif") else "spn"
    scope = "rg" if spec.has("conn_rg") else "sub"
    return f"{project.lower()}-{tier}-{style}-{scope}"


TIER_OF = {"Dev": "dev", "Test": "test", "UAT": "uat", "Prod": "prod"}
CLASSIC_LABEL = {"Dev": "Dev", "Test": "QA", "UAT": "UAT", "Prod": "Production"}
YAML_LABEL = {"Dev": "Dev", "Test": "Test", "UAT": "UAT", "Prod": "Prod"}


def ver(s: RepoSpec, default: int, *, pinnable: bool = True) -> int | None:
    return None if (s.has("unpinned") and pinnable and s.idx % 3 == 0) else default


def build_sds(s: RepoSpec) -> list[SD]:
    sds: list[SD] = []
    sonar_ok = s.has("sonar_steps") and s.kind not in ("adf", "synapse", "iac", "docs")
    if sonar_ok:
        extra = "sonar.qualitygate.wait=true\nsonar.exclusions=**/Migrations/**" if s.has("sonar_enforce") else "sonar.exclusions=**/Migrations/**"
        sds.append(SD("SonarQubePrepare", 5, {"SonarQube": "sonarqube-conn", "scannerMode": "MSBuild", "projectKey": f"{s.project}_{s.name}", "extraProperties": extra}, "Prepare analysis on SonarQube"))
    lang = s.lang
    if s.kind == "adf":
        if s.has("adf_npm"):
            sds.append(SD(script="npm install --prefix build", name="Install ADF utilities"))
            if s.has("adf_validate"):
                sds.append(SD(script="npm run build validate $(Build.Repository.LocalPath)/ /subscriptions/x/resourceGroups/rg/providers/Microsoft.DataFactory/factories/adf --prefix build", name="Validate ADF"))
            sds.append(SD(script="npm run build export $(Build.Repository.LocalPath)/ /subscriptions/x/resourceGroups/rg/providers/Microsoft.DataFactory/factories/adf ArmTemplate --prefix build", name="Export ARM template"))
            sds.append(SD("PublishPipelineArtifact", 1, {"targetPath": "build/ArmTemplate", "artifact": "ArmTemplate"}, "Publish ARM template"))
        else:
            sds.append(SD(script="git fetch origin adf_publish && git checkout adf_publish", name="Use adf_publish branch"))
            sds.append(SD("PublishBuildArtifacts", 1, {"PathtoPublish": "$(Build.SourcesDirectory)", "ArtifactName": "adf_publish"}, "Publish adf_publish"))
        return sds
    if s.kind == "synapse":
        sds.append(SD("PublishPipelineArtifact", 1, {"targetPath": "$(Build.SourcesDirectory)", "artifact": "workspace"}, "Publish workspace"))
        return sds
    if s.kind == "iac":
        if s.n.get("tf"):
            sds.append(SD("TerraformTaskV4", 4, {"command": "init", "provider": "azurerm"}, "Terraform init"))
            sds.append(SD("TerraformTaskV4", 4, {"command": "validate"}, "Terraform validate"))
            if s.has("iac_whatif"):
                sds.append(SD("TerraformTaskV4", 4, {"command": "plan", "commandOptions": "-out=tfplan"}, "Terraform plan"))
        else:
            sds.append(SD(script="az bicep build --file main.bicep", name="Bicep build"))
            if s.has("iac_whatif"):
                sds.append(SD(script="az deployment group what-if -g rg-$(env) -f main.bicep", name="What-if"))
        sds.append(SD("PublishPipelineArtifact", 1, {"targetPath": "$(Build.SourcesDirectory)", "artifact": "iac"}, "Publish IaC"))
        return sds
    if s.kind == "docs":
        return [SD(script="echo building docs", name="Build docs")]
    # application build
    if lang == "dotnet":
        sds.append(SD("DotNetCoreCLI", ver(s, 2), {"command": "build", "projects": "**/*.csproj"}, "Build"))
    elif lang == "java":
        sds.append(SD("Maven", 3, {"mavenPomFile": "pom.xml", "goals": "package", "options": "-DskipTests"}, "Maven package"))
    elif lang == "js":
        sds.append(SD("Npm", ver(s, 1), {"command": "custom", "customCommand": "run build"}, "npm build"))
    elif lang == "python":
        sds.append(SD(script="pip install -r requirements.txt && python -m build", name="Build"))
    elif lang == "sql":
        sds.append(SD("MSBuild", 1, {"solution": "**/*.sqlproj"}, "Build database project"))
    # tests
    t = s.tests
    if t in ("ok", "low", "nocov"):
        test_name = "Run unit tests"
        if lang == "dotnet":
            sds.append(SD("DotNetCoreCLI", ver(s, 2), {"command": "test", "projects": "**/*Tests.csproj", "arguments": "--collect:'XPlat Code Coverage'"}, test_name))
        elif lang == "java":
            sds.append(SD("Maven", 3, {"goals": "verify", "publishJUnitResults": True}, test_name))
        elif lang == "js":
            sds.append(SD(script="npm test -- --coverage", name=test_name))
        elif lang == "python":
            sds.append(SD(script="pytest --cov=app --junitxml=results.xml", name=test_name))
        elif lang == "sql":
            sds.append(SD(script="sqlpackage /Action:DeployReport /SourceFile:db.dacpac", name="tSQLt run") if False else SD(script="echo run tSQLt tests", name="tSQLt unit tests"))
        if s.has("publish_results") or t == "ok":
            sds.append(SD("PublishTestResults", 2, {"testResultsFormat": "VSTest", "testResultsFiles": "**/*.trx"}, "Publish test results"))
        if t in ("ok", "low") and (s.has("publish_cov") or t == "ok"):
            sds.append(SD("PublishCodeCoverageResults", 1, {"summaryFileLocation": "**/coverage.cobertura.xml"}, "Publish coverage"))
    elif t == "notrun":
        how = s.idx % 3
        if lang in ("dotnet", None):
            sds.append(SD("DotNetCoreCLI", 2, {"command": "test"}, "Run unit tests", enabled=how != 0, coe=how == 1, condition="eq(1, 2)" if how == 2 else None))
        else:
            sds.append(SD("VSTest", 2, {"testAssemblyVer2": "**/*test*.dll"}, "Run unit tests", enabled=how != 0, coe=how == 1))
    if sonar_ok:
        sds.append(SD("SonarQubeAnalyze", 5, {}, "Run Code Analysis", coe=s.has("sonar_coe")))
        sds.append(SD("SonarQubePublish", 5, {"pollingTimeoutSec": "300"}, "Publish Quality Gate Result"))
    if s.has("sbom"):
        sds.append(SD(script="syft packages dir:. -o cyclonedx-json > sbom.json", name="Generate SBOM"))
    if s.has("marketplace_unlisted"):
        sds.append(SD("replacetokens", 5, {"rootDirectory": "config", "targetFiles": "*.json"}, "Replace tokens"))
    if s.has("deprecated_task") and s.kind != "lib":
        sds.append(SD("AzureResourceGroupDeployment", 2, {"action": "Create Or Update Resource Group", "resourceGroupName": "rg-build"}, "Provision test RG", enabled=False))
    if s.kind == "aks":
        if s.has("k8s_lint"):
            sds.append(SD(script="helm lint charts/ || kubeconform -strict k8s/", name="Validate manifests"))
        reg = "contosoacr.azurecr.io" if s.has("k8s_registry_ok") else f"{s.name.replace('-', '')}reg.azurecr.io"
        tag = "latest" if s.has("k8s_latest") else "$(Build.BuildId)"
        sds.append(SD("Docker", 2, {"command": "buildAndPush", "containerRegistry": "acr-conn", "repository": s.name, "tags": tag, "dockerfile": "Dockerfile", "registry": reg}, "Build and push image"))
    if s.kind == "sql":
        sds.append(SD("PublishPipelineArtifact", 1, {"targetPath": "db/bin/Release", "artifact": "dacpac"}, "Publish dacpac"))
    elif s.kind != "lib":
        sds.append(SD("PublishPipelineArtifact", 1, {"targetPath": "$(Build.ArtifactStagingDirectory)", "artifact": "drop"}, "Publish artifact"))
    else:
        sds.append(SD("PublishPipelineArtifact", 1, {"targetPath": "$(Build.ArtifactStagingDirectory)", "artifact": "package"}, "Publish package"))
    return sds


def registry_of(s: RepoSpec) -> str:
    return "contosoacr.azurecr.io" if s.has("k8s_registry_ok") else f"{s.name.replace('-', '')}reg.azurecr.io"


def deploy_sds(s: RepoSpec, tier_label: str, conn: str, classic: bool) -> list[SD]:
    """Deploy steps for one environment. `tier_label` is Dev/Test/UAT/Prod."""
    is_prod = tier_label == "Prod"
    sds: list[SD] = []
    app = f"{s.name}-{tier_label.lower()}"
    kind = s.kind
    slot = s.has("slot") and is_prod
    if kind == "functionapp":
        if s.has("publish_profile"):
            sds.append(SD("AzureRmWebAppDeployment", 4, {"ConnectionType": "PublishProfile", "PublishProfilePath": "$(System.DefaultWorkingDirectory)/profile.pubxml", "WebAppKind": "functionApp", "WebAppName": app}, "Deploy Function App (publish profile)"))
        else:
            inputs: dict[str, Any] = {"azureSubscription": conn, "appType": "functionAppLinux", "appName": app, "package": "$(Pipeline.Workspace)/drop/*.zip"}
            if slot:
                inputs |= {"deployToSlotOrASE": True, "resourceGroupName": f"rg-{app}", "slotName": "staging"}
            sds.append(SD("AzureFunctionApp", ver(s, 1 if s.has("deprecated_task") and s.idx % 2 == 0 else 2), inputs, "Deploy Function App"))
        if slot:
            sds.append(SD("AzureAppServiceManage", 0, {"azureSubscription": conn, "Action": "Swap Slots", "WebAppName": app, "ResourceGroupName": f"rg-{app}", "SourceSlot": "staging"}, "Swap staging to production"))
    elif kind == "webapp":
        if s.has("publish_profile"):
            sds.append(SD(script=f"curl -u $(deployUser):$(deployPass) -X POST https://{app}.scm.azurewebsites.net/api/zipdeploy --data-binary @drop.zip", name="Deploy via Kudu"))
        else:
            inputs = {"azureSubscription": conn, "appType": "webAppLinux", "appName": app, "package": "$(Pipeline.Workspace)/drop/*.zip"}
            if slot:
                inputs["slotName"] = "staging"
            sds.append(SD("AzureWebApp", 1, inputs, "Deploy Web App"))
        if slot:
            sds.append(SD(script=f"az webapp deployment slot swap -g rg-{app} -n {app} --slot staging", name="Swap slots"))
    elif kind == "aks":
        reg = registry_of(s)
        tag = "latest" if s.has("k8s_latest") else "$(Build.BuildId)"
        mode = s.n["aks_mode"]
        kconn = f"aks-{tier_label.lower()}"
        if mode == "manifest":
            sds.append(SD("KubernetesManifest", 1, {"action": "deploy", "kubernetesServiceConnection": kconn, "namespace": s.name, "manifests": "k8s/*.yaml", "containers": f"{reg}/{s.name}:{tag}"}, "Deploy to AKS"))
        elif mode == "helm":
            sds.append(SD("HelmDeploy", 0, {"command": "upgrade", "connectionType": "Kubernetes Service Connection", "kubernetesServiceConnection": kconn, "chartPath": f"charts/{s.name}", "overrideValues": f"image.repository={reg}/{s.name},image.tag={tag}", "arguments": "--wait" if s.has("k8s_rollout") else ""}, "Helm upgrade"))
        else:
            sds.append(SD(script=f"kubectl apply -f k8s/ --namespace {s.name}\nsed -i 's#IMAGE#{reg}/{s.name}:{tag}#' k8s/deployment.yaml", name="kubectl apply"))
            if s.has("k8s_rollout"):
                sds.append(SD(script=f"kubectl rollout status deployment/{s.name} -n {s.name}", name="Verify rollout"))
    elif kind == "adf":
        if s.has("adf_toggle"):
            sds.append(SD("AzurePowerShell", 5, {"azureSubscription": conn, "ScriptType": "InlineScript", "Inline": "Get-AzDataFactoryV2Trigger -ResourceGroupName rg -DataFactoryName adf | Stop-AzDataFactoryV2Trigger -Force"}, "Stop triggers"))
        inputs = {"azureResourceManagerConnection": conn, "action": "Create Or Update Resource Group", "resourceGroupName": f"rg-adf-{tier_label.lower()}", "csmFile": "$(Pipeline.Workspace)/ArmTemplate/ARMTemplateForFactory.json", "deploymentMode": "Incremental"}
        if s.has("adf_overrides"):
            inputs["overrideParameters"] = f"-factoryName adf-{tier_label.lower()} -AzureSqlLS_connectionString $(sqlConnStr)"
        sds.append(SD("AzureResourceManagerTemplateDeployment", 3, inputs, "Deploy ADF ARM template"))
        if s.has("adf_toggle"):
            sds.append(SD("AzurePowerShell", 5, {"azureSubscription": conn, "ScriptType": "InlineScript", "Inline": "Start-AzDataFactoryV2Trigger -Name Daily -Force"}, "Start triggers"))
    elif kind == "synapse":
        op = "validateDeploy" if s.has("syn_validate") else "deploy"
        if s.has("syn_toggle"):
            sds.append(SD("AzurePowerShell", 5, {"azureSubscription": conn, "ScriptType": "InlineScript", "Inline": "Stop-AzSynapseTrigger -WorkspaceName syn -Name t"}, "Stop Synapse triggers"))
        sds.append(SD("Synapse workspace deployment", 2, {"operation": op, "TemplateFile": "TemplateForWorkspace.json", "ParametersFile": "TemplateParametersForWorkspace.json", "azureSubscription": conn, "ResourceGroup": f"rg-syn-{tier_label.lower()}", "TargetWorkspaceName": f"syn-{tier_label.lower()}"}, "Synapse deploy"))
        if s.has("syn_toggle"):
            sds.append(SD("AzurePowerShell", 5, {"azureSubscription": conn, "ScriptType": "InlineScript", "Inline": "Start-AzSynapseTrigger -WorkspaceName syn -Name t"}, "Start Synapse triggers"))
    elif kind == "sql":
        args = "/p:BlockOnPossibleDataLoss=false" if s.has("sql_block_false") else "/p:BlockOnPossibleDataLoss=true"
        if s.has("sql_report") and is_prod:
            sds.append(SD(script="sqlpackage /Action:DeployReport /SourceFile:$(Pipeline.Workspace)/dacpac/db.dacpac /TargetConnectionString:$(sqlConn) /OutputPath:report.xml", name="Generate deploy report"))
        sds.append(SD("SqlAzureDacpacDeployment", 1, {"azureSubscription": conn, "AuthenticationType": "servicePrincipal", "ServerName": f"sql-{tier_label.lower()}.database.windows.net", "DatabaseName": s.name, "deployType": "DacpacTask", "DacpacFile": "$(Pipeline.Workspace)/dacpac/*.dacpac", "AdditionalArguments": args}, "Deploy DACPAC"))
    elif kind == "iac":
        if s.n.get("tf"):
            sds.append(SD("TerraformTaskV4", 4, {"command": "apply", "environmentServiceNameAzureRM": conn, "commandOptions": "tfplan"}, "Terraform apply"))
        else:
            sds.append(SD("AzureResourceManagerTemplateDeployment", 3, {"azureResourceManagerConnection": conn, "deploymentScope": "Resource Group", "resourceGroupName": f"rg-{s.name}-{tier_label.lower()}", "csmFile": "main.bicep", "deploymentMode": "Incremental"}, "Deploy Bicep"))
    if s.has("smoke") and not (classic and s.has("smoke_gate")) and tier_label != "Dev":
        sds.append(SD(script=f"curl -fsS https://{app}.azurewebsites.net/health", name="Smoke test"))
    return sds


# ------------------------------------------------------------------ the world
DEPLOY_KINDS = {"functionapp", "webapp", "aks", "adf", "synapse", "sql", "iac"}


def iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


class WorldBuilder:
    def __init__(self, seed: int, repos: int, qshift: float, now: datetime):
        self.seed, self.n_repos, self.qshift, self.now = seed, repos, qshift, now
        self.next_id = 100
        self.crq_n = 40000
        self.world: dict[str, Any] = {
            "meta": {"seed": seed, "repos": repos, "quality_shift": qshift, "generated_at": iso(now), "org": P.ORG},
            "tasks": P.tasks_payload(), "ado": {}, "sonar": {}, "aikido": {"repos": [], "issues": []},
            "snow": {"changes": []}, "scope_repos": [],
        }
        self.aikido_id = 5000

    def rid(self) -> int:
        self.next_id += 1
        return self.next_id

    # ---- project scaffolding
    def project(self, name: str) -> dict[str, Any]:
        if name in self.world["ado"]:
            return self.world["ado"][name]
        pr: dict[str, Any] = {
            "repos": [], "build_defs": {}, "release_defs": {}, "policies": [], "endpoints": [], "perms": {},
            "variable_groups": [], "environments": [], "env_checks": {}, "builds": {}, "deployments": {},
            "yaml": {}, "yaml_preview_fail": [], "faulty_defs": [], "items": {}, "files": {}, "taskgroups": [],
        }
        eid_n = 0
        for tier in ("dev", "test", "uat", "prod"):
            for style in ("wif", "spn"):
                for scope in ("rg", "sub"):
                    eid_n += 1
                    nm = f"{name.lower()}-{tier}-{style}-{scope}"
                    eid = f"ep-{name.lower()}-{eid_n:02d}"
                    ep = P.endpoint(eid, nm, "WorkloadIdentityFederation" if style == "wif" else "ServicePrincipal",
                                    "ResourceGroup" if scope == "rg" else "Subscription", f"rg-{name.lower()}-{tier}" if scope == "rg" else None)
                    pr["endpoints"].append(ep)
                    open_p = _u(self.seed, zlib.crc32(nm.encode()), "allp") < clamp(0.2 - 0.15 * PROJECT_PLAN[name][0] + self.qshift * -0.3, 0.03, 0.5)
                    pr["perms"][eid] = {"resource": {"id": eid, "type": "endpoint"}, "allPipelines": {"authorized": open_p}, "pipelines": []}
        pr["endpoints"].append({"id": f"ep-{name.lower()}-sonar", "name": "sonarqube-conn", "type": "sonarqube", "authorization": {"scheme": "Token"}, "data": {}})
        pr["perms"][f"ep-{name.lower()}-sonar"] = {"allPipelines": {"authorized": False}}
        pr["variable_groups"] = [
            {"id": 1, "name": f"{name.lower()}-common", "type": "Vsts", "variables": {"Region": {"value": "westeurope"}}},
            {"id": 2, "name": f"{name.lower()}-prod-kv", "type": "AzureKeyVault", "providerData": {"vaultName": f"kv-{name.lower()}"}, "variables": {"dbPassword": {"isSecret": True}}},
            {"id": 3, "name": f"{name.lower()}-prod-plain", "type": "Vsts", "variables": {"sqlConn": {"value": "x", "isSecret": True}}},
        ]
        self.world["ado"][name] = pr
        return pr

    def conn_id(self, pr: dict[str, Any], name: str, classic: bool) -> str:
        if not classic:
            return name
        return next(e["id"] for e in pr["endpoints"] if e["name"] == name)

    # ---- one repo
    def add_repo(self, s: RepoSpec) -> None:
        pr = self.project(s.project)
        paths, contents = repo_files(s)
        pr["repos"].append({"id": s.repo_id, "name": s.name, "project": {"name": s.project}, "defaultBranch": f"refs/heads/{s.default_branch}",
                            "isDisabled": s.has("disabled"), "webUrl": f"{WEB}/{s.project}/_git/{s.name}", "size": 1000 + s.idx})
        if not s.has("empty_repo"):
            pr["items"][s.repo_id] = [{"objectId": f"{s.idx:040x}", "gitObjectType": "tree", "path": "/", "isFolder": True}] + [
            {"objectId": f"{zlib.crc32(p.encode()):040x}", "gitObjectType": "blob", "path": "/" + p} for p in paths]
        pr["files"][s.repo_id] = {"/" + k: v for k, v in contents.items()}
        self.policies(pr, s)
        build_id = None
        if s.style != "none":
            if s.style == "classic":
                build_id = self.classic_build(pr, s)
                if s.kind in DEPLOY_KINDS:
                    self.classic_release(pr, s, build_id)
            else:
                self.yaml_pipeline(pr, s)
        self.sonar(s)
        self.aikido(s)
        self.scope_entry(s)

    def policies(self, pr: dict[str, Any], s: RepoSpec) -> None:
        rid, br = s.repo_id, s.default_branch
        i = self.rid()
        pr["policies"].append(P.policy_cfg(i, P.T_MIN_REVIEWERS, "Minimum number of reviewers", {
            "minimumApproverCount": 2 if s.has("pol_two_reviewers") else 1, "creatorVoteCounts": s.has("pol_creator_votes"),
            "allowDownvotes": False, "resetOnSourcePush": s.has("pol_reset"), "requireVoteOnLastIteration": False}, rid, br))
        if s.has("pol_build") and s.style != "none":
            pr["policies"].append(P.policy_cfg(self.rid(), P.T_BUILD, "Build", {"buildDefinitionId": 1, "queueOnSourceUpdateOnly": False, "manualQueueOnly": False, "displayName": "PR build", "validDuration": 720}, rid, br))
        if s.has("pol_workitem"):
            pr["policies"].append(P.policy_cfg(self.rid(), P.T_WORK_ITEM, "Work item linking", {}, rid, br))
        if s.has("pol_comments"):
            pr["policies"].append(P.policy_cfg(self.rid(), P.T_COMMENTS, "Comment requirements", {}, rid, br))
        if s.has("pol_required_rev"):
            pr["policies"].append(P.policy_cfg(self.rid(), P.T_REQ_REVIEWERS, "Required reviewers", {"requiredReviewerIds": ["g1"], "filenamePatterns": ["/azure-pipelines*.yml", "/.azure-pipelines/*"], "minimumApproverCount": 1}, rid, br))

    # ---- classic build
    def classic_build(self, pr: dict[str, Any], s: RepoSpec) -> int:
        did = self.rid()
        steps = [P.classic_step(sd, i) for i, sd in enumerate(build_sds(s))]
        variables: dict[str, Any] = {"BuildConfiguration": {"value": "Release", "allowOverride": True}, "system.debug": {"value": "false", "allowOverride": True}}
        if s.has("secret_var"):
            variables[s.n["secret_name"]] = {"value": "S3cr3t-Value-Do-Not-Store-123", "isSecret": False, "allowOverride": True}
        else:
            variables["apiKey"] = {"value": None, "isSecret": True, "allowOverride": True}
        defn = {
            "id": did, "name": f"{s.name}-CI", "path": f"\\{s.project}", "type": "build", "revision": 3 + s.idx % 11,
            "project": {"name": s.project}, "repository": {"id": s.repo_id, "name": s.name, "type": "TfsGit", "defaultBranch": f"refs/heads/{s.default_branch}"},
            "process": {"type": 1, "phases": [{"name": "Agent job 1", "refName": "Phase_1", "condition": "succeeded()", "target": {"type": 1}, "steps": steps}]},
            "queue": {"name": "Azure Pipelines" if s.idx % 9 else "OnPrem-Pool", "pool": {"name": "Azure Pipelines" if s.idx % 9 else "OnPrem-Pool", "isHosted": bool(s.idx % 9)}},
            "variables": variables,
            "variableGroups": [{"id": 1, "name": f"{s.project.lower()}-common", "type": "Vsts"}],
            "triggers": [{"triggerType": "continuousIntegration", "branchFilters": [f"+refs/heads/{s.default_branch}"]}],
            "retentionRules": [{"branches": ["+refs/heads/*"], "daysToKeep": 30 if not s.has("retention_ok") else 400, "minimumToKeep": 1}],
            "authoredBy": self.author(s), "_links": P.web_link(s.project, "build", did),
        }
        pr["build_defs"][did] = defn
        if s.has("def_500"):
            pr["faulty_defs"].append(did)
        self.runs(pr, s, did, "build")
        return did

    def author(self, s: RepoSpec) -> dict[str, str]:
        n = ["Ava Chen", "Liam Okafor", "Noor Haddad", "Sven Larsen", "Maya Iyer", "Tomas Novak"][s.idx % 6]
        return {"displayName": n, "uniqueName": n.lower().replace(" ", ".") + "@contoso.com"}

    # ---- classic release
    def classic_release(self, pr: dict[str, Any], s: RepoSpec, build_id: int) -> None:
        did = self.rid()
        tiers = s.n["tiers"]
        envs = []
        for rank, tier in enumerate(tiers, start=1):
            is_prod = tier == "Prod"
            conn = self.conn_id(pr, conn_name(s.project, TIER_OF[tier], s), True)
            sds = deploy_sds(s, tier, conn, True)
            if is_prod and s.has("rebuild_in_deploy") and s.lang == "dotnet":
                sds.insert(0, SD("DotNetCoreCLI", 2, {"command": "publish", "projects": "**/*.csproj"}, "Rebuild for prod"))
            tasks = [P.classic_workflow_task(sd) for sd in sds]
            if rank == 1 or (is_prod and s.has("direct_to_prod")):
                conds = [{"name": "ReleaseStarted", "conditionType": 1, "value": ""}]
            else:
                conds = [{"name": CLASSIC_LABEL[tiers[rank - 2]], "conditionType": 2, "value": "4"}]
            if is_prod and s.has("branch_filter"):
                conds.append({"name": "_build", "conditionType": 3, "value": json.dumps({"sourceBranch": s.default_branch, "tags": [], "useBuildDefinitionBranch": False})})
            approve = is_prod and s.has("prod_approval")
            pre = {"approvals": [{"rank": 1, "isAutomated": True, "isNotificationOn": False}], "approvalOptions": {"requiredApproverCount": None, "releaseCreatorCanBeApprover": True}}
            if approve or (tier == "UAT" and s.n["gate_roll"] < 0.3):
                pre = {"approvals": [{"rank": 1, "isAutomated": False, "isNotificationOn": True, "approver": {"displayName": "Change Approvers", "uniqueName": f"{s.project.lower()}-approvers@contoso.com"}}],
                       "approvalOptions": {"requiredApproverCount": 1, "releaseCreatorCanBeApprover": s.has("requester_can_approve"), "timeoutInMinutes": 43200}}
            gates: dict[str, Any] = {"gates": [], "gatesOptions": {"isEnabled": False}}
            if is_prod and s.has("snow_gate"):
                gates = {"gates": [{"tasks": [{"taskId": P.task_guid("ServiceNow-DevOps-Change"), "name": "ServiceNow CRQ gate", "version": "1.*", "inputs": {"table": "change_request", "instance": "contoso.service-now.com"}}]}],
                         "gatesOptions": {"isEnabled": True, "timeout": 1440, "samplingInterval": 15}}
            post: dict[str, Any] = {"gates": [], "gatesOptions": {"isEnabled": False}}
            if tier != "Dev" and s.has("smoke") and s.has("smoke_gate"):
                post = {"gates": [{"tasks": [{"taskId": P.task_guid("InvokeRESTAPI"), "name": "Health endpoint check", "version": "1.*", "inputs": {"urlSuffix": "/health", "method": "GET"}}]}],
                        "gatesOptions": {"isEnabled": True, "timeout": 360}}
            env_vars = {}
            if is_prod:
                env_vars = {"slotName": {"value": "staging"}}
            groups = []
            if is_prod:
                groups = [2 if s.has("kv_group") else 3]
            envs.append({
                "id": self.rid(), "name": CLASSIC_LABEL[tier], "rank": rank, "conditions": conds, "preDeployApprovals": pre,
                "postDeployApprovals": {"approvals": [{"rank": 1, "isAutomated": True}]}, "preDeploymentGates": gates, "postDeploymentGates": post,
                "deployPhases": [{"name": "Agent job", "phaseType": 1 if (s.idx % 17) else 2, "workflowTasks": tasks}],
                "retentionPolicy": {"daysToKeep": 365 if (is_prod and s.has("retention_ok")) else 30, "releasesToKeep": 3, "retainBuild": True},
                "variables": env_vars, "variableGroups": groups,
            })
        trig_cond = [{"sourceBranch": s.default_branch, "tags": [], "useBuildDefinitionBranch": False}] if s.has("branch_filter") else []
        defn = {
            "id": did, "name": f"{s.name}-CD", "path": f"\\{s.project}",
            "artifacts": [{"alias": "_build", "type": "Build", "isPrimary": True, "definitionReference": {"definition": {"id": str(build_id), "name": f"{s.name}-CI"}, "project": {"name": s.project}}}],
            "triggers": [{"triggerType": "artifactSource", "artifactAlias": "_build", "triggerConditions": trig_cond}] if trig_cond else [],
            "environments": envs, "variables": {}, "variableGroups": [1],
            "modifiedBy": self.author(s), "createdBy": self.author(s), "_links": P.web_link(s.project, "release", did),
        }
        pr["release_defs"][did] = defn
        self.runs(pr, s, did, "release")

    # ---- yaml pipeline
    def yaml_pipeline(self, pr: dict[str, Any], s: RepoSpec) -> None:
        did = self.rid()
        tiers = s.n["tiers"] if s.kind in DEPLOY_KINDS else []
        lines = [f"trigger:\n  branches:\n    include:\n      - {s.default_branch}", "variables:", f"  - group: {s.project.lower()}-common"]
        if s.kind in DEPLOY_KINDS and tiers:
            lines.append(f"  - group: {s.project.lower()}-prod-{'kv' if s.has('kv_group') else 'plain'}")
        if s.has("secret_var"):
            lines.append(f"  - name: {s.n['secret_name']}\n    value: S3cr3t-Value-Do-Not-Store-123")
        lines.append("  - name: BuildConfiguration\n    value: Release")
        lines.append("stages:\n  - stage: Build\n    jobs:\n      - job: build\n        pool:\n          vmImage: ubuntu-latest\n        steps:")
        build_steps = [P.yaml_step(sd) for sd in build_sds(s)]
        for bs in build_steps:
            lines.append(P.indent(bs, 10))
        env_defs: list[tuple[str, str]] = []
        for rank, tier in enumerate(tiers):
            env = f"{s.name}-{tier.lower()}"
            env_defs.append((env, tier))
            conn = conn_name(s.project, TIER_OF[tier], s)
            sds = deploy_sds(s, tier, conn, False)
            if tier == "Prod" and s.has("snow_gate") and s.idx % 4 == 0:
                sds.insert(0, SD("ServiceNow-DevOps-Change", 1, {"connectedService": "snow-conn", "action": "createChange"}, "ServiceNow change"))
            if tier == "Prod" and s.has("rebuild_in_deploy") and s.lang == "dotnet":
                sds.insert(0, SD("DotNetCoreCLI", 2, {"command": "publish", "projects": "**/*.csproj"}, "Rebuild for prod"))
            dep = "[]" if (tier == "Prod" and s.has("direct_to_prod")) else (YAML_LABEL[tiers[rank - 1]] if rank else "Build")
            lines.append(f"  - stage: {YAML_LABEL[tier]}\n    dependsOn: {dep}\n    jobs:\n      - deployment: deploy_{tier.lower()}\n        environment: {env}\n        pool:\n          vmImage: ubuntu-latest\n        strategy:\n          runOnce:\n            deploy:\n              steps:")
            for sd in [SD("DownloadPipelineArtifact", 2, {"artifact": "drop"}, "Download artifact"), *sds]:
                lines.append(P.indent(P.yaml_step(sd), 16))
        text = "\n".join(lines) + "\n"
        defn = {
            "id": did, "name": f"{s.name}", "path": f"\\{s.project}", "type": "build", "project": {"name": s.project},
            "repository": {"id": s.repo_id, "name": s.name, "type": "TfsGit", "defaultBranch": f"refs/heads/{s.default_branch}"},
            "process": {"type": 2, "yamlFilename": "azure-pipelines.yml"}, "queue": {"pool": {"name": "Azure Pipelines", "isHosted": True}},
            "retentionRules": [{"branches": ["+refs/heads/*"], "daysToKeep": 400 if s.has("retention_ok") else 30}],
            "authoredBy": self.author(s), "_links": P.web_link(s.project, "build", did),
        }
        pr["build_defs"][did] = defn
        pr["yaml"][did] = text
        if s.has("preview_fails"):
            pr["yaml_preview_fail"].append(did)
            pr["files"][s.repo_id]["/azure-pipelines.yml"] = text
        # environments + checks
        for env, tier in env_defs:
            eid = self.rid()
            pr["environments"].append({"id": eid, "name": env})
            checks = []
            if tier == "Prod":
                if s.has("prod_approval"):
                    checks.append({"id": self.rid(), "type": {"id": "8c6f20a7", "name": "Approval"}, "timeout": 43200,
                                   "settings": {"approvers": [{"displayName": "Change Approvers", "id": "g-approvers"}], "minRequiredApprovers": 1,
                                                "requesterCannotBeApprover": not s.has("requester_can_approve"), "executionOrder": "anyOrder"}})
                if s.has("branch_filter"):
                    checks.append({"id": self.rid(), "type": {"id": "fe1de3ee", "name": "BranchControl"},
                                   "settings": {"allowedBranches": f"refs/heads/{s.default_branch},refs/heads/release/*", "ensureProtectionOfBranch": True}})
                if s.has("snow_gate") and s.idx % 4 != 0:
                    checks.append({"id": self.rid(), "type": {"id": "t3", "name": "TaskCheck"},
                                   "settings": {"displayName": "ServiceNow CRQ check", "definitionRef": {"name": "ServiceNow-DevOps-Change"}, "inputs": {"url": "https://contoso.service-now.com/api/sn_devops/change"}}})
            pr["env_checks"][eid] = checks
        self.runs(pr, s, did, "yaml", prod_env=env_defs[-1][0] if env_defs and env_defs[-1][1] == "Prod" else None)

    # ---- run history + CRQs
    def runs(self, pr: dict[str, Any], s: RepoSpec, did: int, kind: str, prod_env: str | None = None) -> None:
        rng = random.Random(f"{s.seed}:{s.idx}:runs:{did}")
        n = 0 if s.has("stale") else s.n["runs"]
        success = s.n["success"]
        builds, deployments = [], []
        has_prod = kind == "release" and s.n["tiers"][-1] == "Prod" or (kind == "yaml" and prod_env)
        for i in range(n):
            ago = timedelta(days=rng.random() * 88, hours=rng.random() * 20)
            fin = self.now - ago
            ok = rng.random() < success
            if kind == "release":
                for tier in s.n["tiers"]:
                    if tier != "Prod":
                        continue
                    crq = self.crq_for(s, rng, fin, ok)
                    rel_name = f"Release-{i + 1}"
                    desc = f"{crq} deploy build {1000 + i}" if crq and rng.random() < 0.85 else ""
                    if crq and not desc:
                        rel_name = f"Release-{i + 1} {crq}"
                    deployments.append({"id": self.rid(), "release": {"id": 900 + i, "name": rel_name, "description": desc},
                                        "releaseEnvironment": {"name": CLASSIC_LABEL[tier]}, "deploymentStatus": "succeeded" if ok else "failed",
                                        "startedOn": iso(fin - timedelta(minutes=12)), "completedOn": iso(fin), "requestedFor": self.author(s)})
            else:
                b = {"id": self.rid(), "buildNumber": f"{fin:%Y%m%d}.{i + 1}", "status": "completed", "result": "succeeded" if ok else "failed",
                     "finishTime": iso(fin), "sourceBranch": f"refs/heads/{s.default_branch}", "definition": {"id": did},
                     "requestedFor": self.author(s), "tags": [], "parameters": "{}"}
                if kind == "yaml" and has_prod and ok:
                    crq = self.crq_for(s, rng, fin, ok)
                    if crq:
                        b["parameters"] = json.dumps({"changeRequest": crq})
                builds.append(b)
        if kind == "release":
            pr["deployments"][did] = deployments
        else:
            pr["builds"][did] = builds

    def crq_for(self, s: RepoSpec, rng: random.Random, when: datetime, ok: bool) -> str | None:
        """Create the ServiceNow CRQ record for a prod deployment (per the repo's discipline). Returns the ref (or None)."""
        mode = s.n["crq"]
        if not ok:
            return None
        self.crq_n += 1
        number = f"CHG{self.crq_n:07d}"
        ci = s.name if s.has("has_ci") else None
        roll = rng.random()
        good = {"number": number, "state": rng.choice(["Implement", "Implement", "Closed", "Review"]), "approval": "approved",
                "start_date": (when - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S"), "end_date": (when + timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S"),
                "cmdb_ci": ci or "", "short_description": f"Deploy {s.name}"}
        if mode == "good" or (mode == "partial" and roll < 0.6):
            self.world["snow"]["changes"].append(good)
            return number if (mode == "good" and roll < 0.93) or (mode == "partial") else (None if ci else number)
        if mode == "partial":
            if roll < 0.75:
                bad = dict(good, state="Canceled")
            elif roll < 0.9:
                bad = dict(good, start_date=(when - timedelta(days=9)).strftime("%Y-%m-%d %H:%M:%S"), end_date=(when - timedelta(days=8)).strftime("%Y-%m-%d %H:%M:%S"))
            else:
                return None
            self.world["snow"]["changes"].append(bad)
            return number
        # mode none: ~no references at all
        return number if roll < 0.04 else None

    # ---- external tools
    def sonar(self, s: RepoSpec) -> None:
        if s.kind == "docs":
            return
        exists = s.has("sonar_steps") or s.has("sonar_exists_noxsteps") or (s.tests in ("ok", "low") and _u(s.seed, s.idx, "sx2") < 0.5)
        if s.kind in ("adf", "synapse", "iac"):
            exists = False
        if not exists:
            return
        key = f"{s.project}_{s.name}" if not s.has("sonar_key_override") else f"contoso.{s.project.lower()}.{s.name}"
        age = int(_u(s.seed, s.idx, "sage") * 12) + 1 if s.has("sonar_recent") else int(16 + _u(s.seed, s.idx, "sage") * 120)
        g = _u(s.seed, s.idx, "gstat")
        status = "OK" if g < 0.45 + 0.4 * s.q else ("WARN" if g < 0.5 + 0.4 * s.q else "ERROR")
        cov: float | None
        if s.tests == "ok":
            cov = round(80 + _u(s.seed, s.idx, "cov") * 15, 1)
        elif s.tests == "low":
            cov = round(15 + _u(s.seed, s.idx, "cov") * 62, 1)
        elif s.tests == "nocov" or s.tests == "na":
            cov = None
        else:
            cov = round(_u(s.seed, s.idx, "cov") * 25, 1) if _u(s.seed, s.idx, "hascov") < 0.4 else None
        self.world["sonar"][key] = {
            "status": status, "coverage": cov, "bugs": int(_u(s.seed, s.idx, "bugs") * 20), "vulnerabilities": int(_u(s.seed, s.idx, "vuln") * 6 * (1.2 - s.q)),
            "hotspots": int(_u(s.seed, s.idx, "hot") * 9), "smells": int(_u(s.seed, s.idx, "smell") * 300), "dup": round(_u(s.seed, s.idx, "dup") * 12, 1),
            "date": (self.now - timedelta(days=age)).strftime("%Y-%m-%dT%H:%M:%S+0000"),
            "gate": "Company Way" if s.has("sonar_company_gate") else "Sonar way", "error500": s.has("sonar_error_500"),
        }

    def aikido(self, s: RepoSpec) -> None:
        if s.kind == "docs" or not s.has("aikido"):
            return
        self.aikido_id += 1
        self.world["aikido"]["repos"].append({"id": self.aikido_id, "name": s.name, "provider": "azure_devops", "active": True})
        n = int(_u(s.seed, s.idx, "aik") ** 2 * 6 * (1.1 - s.q))
        for i in range(n):
            r = _u(s.seed, s.idx, f"aiks{i}")
            sev = "critical" if r < 0.1 else "high" if r < 0.35 else "medium" if r < 0.75 else "low"
            age = int(_u(s.seed, s.idx, f"aika{i}") ** 2 * (40 if sev in ("critical", "high") else 130)) + 1
            self.world["aikido"]["issues"].append({
                "id": f"{self.aikido_id}-{i}", "severity": sev, "type": ["open_source", "sast", "iac", "secrets"][i % 4],
                "first_detected_at": iso(self.now - timedelta(days=age)), "code_repo_id": self.aikido_id,
            })

    def scope_entry(self, s: RepoSpec) -> None:
        e: dict[str, Any] = {"project": s.project, "repo": s.name}
        if s.has("has_owner"):
            e["owner"] = f"team-{s.project.lower()}-{s.idx % 5}@contoso.com"
        if s.has("sonar_key_override"):
            e["sonar_key"] = f"contoso.{s.project.lower()}.{s.name}"
        if s.has("has_ci"):
            e["servicenow_ci"] = s.name
        if len(e) > 2:
            self.world["scope_repos"].append(e)


def generate_world(seed: int = 42, repos: int = 280, quality_shift: float = 0.0, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.utcnow().replace(microsecond=0)
    wb = WorldBuilder(seed, repos, quality_shift, now)
    used: set[str] = set()
    for idx, (project, kind) in enumerate(build_plan(repos)):
        spec = make_spec(seed, idx, project, kind, quality_shift, used)
        wb.add_repo(spec)
    # a deliberately disabled / empty repo exercises collection-error tolerance
    wb.world["meta"]["projects"] = list(wb.world["ado"])
    # normalise through JSON so a freshly generated world is identical to one loaded from disk (str keys)
    return json.loads(json.dumps(wb.world))
