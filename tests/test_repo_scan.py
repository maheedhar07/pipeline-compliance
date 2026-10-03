import httpx
import pytest
import respx

from pch.collectors.ado.client import AdoClient
from pch.model.pipeline import Job, Pipeline, Stage, Step
from pch.model.repo import RepoFacts, SonarFacts, TestState
from pch.normalize.capabilities import classify_step
from pch.repo_scan.files import fetch_contents, fetch_tree, select_content_paths
from pch.repo_scan.tests_detect import analyze_repo, classify_test_state, detect_tests

BASE = "https://dev.azure.com/contoso/P/_apis/git/repositories/r1/items"


@pytest.mark.parametrize(
    "paths,contents,detected",
    [
        (["src/Api/Api.csproj", "src/Api.Tests/Api.Tests.csproj"], {}, True),
        (["src/Api/Api.csproj", "src/Api/Program.cs"], {}, False),
        (["src/Specs/Specs.csproj"], {"src/Specs/Specs.csproj": '<PackageReference Include="xunit" />'}, True),
        (["src/Specs/Specs.csproj"], {"src/Specs/Specs.csproj": '<PackageReference Include="Microsoft.NET.Test.Sdk" />'}, True),
        (["pom.xml", "src/main/java/A.java", "src/test/java/ATest.java"], {}, True),
        (["pom.xml", "src/main/java/A.java"], {}, False),
        (["app/main.py", "tests/test_main.py"], {}, True),
        (["app/main.py", "app/foo_test.py"], {}, True),
        (["app/main.py", "requirements-dev.txt"], {"requirements-dev.txt": "pytest==8.0\n"}, True),
        (["app/main.py", "pyproject.toml"], {"pyproject.toml": "[tool.pytest.ini_options]\n"}, True),
        (["app/main.py", "requirements.txt"], {"requirements.txt": "flask\n"}, False),
        (["web/src/App.tsx", "web/src/App.test.tsx"], {}, True),
        (["web/src/App.js", "web/src/__tests__/a.js"], {}, True),
        (["web/src/App.js", "web/package.json"], {"web/package.json": '{"devDependencies": {"jest": "^29"}}'}, True),
        (["web/src/App.js", "web/package.json"], {"web/package.json": '{"dependencies": {"react": "1"}}'}, False),
        (["cmd/main.go", "pkg/x_test.go"], {}, True),
        (["cmd/main.go"], {}, False),
        (["db/db.sqlproj", "db/tSQLt/Tests.sql"], {}, True),
        (["db/db.sqlproj", "db/Tables/a.sql"], {}, False),
    ],
)
def test_detect_tests_per_language(paths, contents, detected):
    assert detect_tests(paths, contents)[0] is detected


def test_repo_kinds():
    assert analyze_repo(["src/a.cs", "a.csproj"]).kind == "application"
    adf = analyze_repo(["factory/f.json", "pipeline/p.json", "publish_config.json", "package.json"])
    assert adf.kind == "adf" and adf.adf and not adf.has_app_code
    syn = analyze_repo(["TemplateForWorkspace.json", "notebook/n.json"])
    assert syn.kind == "synapse" and syn.synapse
    assert analyze_repo(["main.bicep", "modules/a.bicep"]).kind == "iac"
    assert analyze_repo(["main.tf"]).kind == "iac"
    assert analyze_repo(["README.md", "docs/a.md"]).kind == "docs"
    assert analyze_repo(["db/db.sqlproj", "db/a.sql"]).kind == "sql"
    empty = analyze_repo(None)
    assert empty.kind == "docs" and not empty.has_app_code


def test_repo_facts_files():
    f = analyze_repo(["src/a.py", "Dockerfile", "svc/Dockerfile.prod", "k8s/dep.yaml", "charts/x/Chart.yaml", "CODEOWNERS",
                      "azure-pipelines.yml", "node_modules/x/index.js"])
    assert f.languages == ["python"] and len(f.dockerfiles) == 2 and f.k8s_manifests and f.helm_chart and f.codeowners
    assert f.pipeline_files == ["azure-pipelines.yml"]
    assert "js" not in f.languages  # node_modules ignored


def test_select_content_paths_shallow_first_and_capped():
    paths = [f"a/b/c/p{i}.csproj" for i in range(40)] + ["package.json", "x/y/package.json", "readme.md"]
    sel = select_content_paths(paths)
    assert sel[0] == "package.json" and len(sel) == 25 and "readme.md" not in sel


@respx.mock
async def test_fetch_tree_and_contents(fx):
    def handler(request):
        if request.url.params.get("recursionLevel") == "Full":
            return httpx.Response(200, json={"count": 3, "value": [
                {"path": "/", "gitObjectType": "tree", "isFolder": True},
                {"path": "/a/A.csproj", "gitObjectType": "blob"}, {"path": "/b.py", "gitObjectType": "blob"}]})
        return httpx.Response(200, json={"path": request.url.params["path"], "content": "<xunit/>"})

    respx.get(BASE).mock(side_effect=handler)
    c = AdoClient("contoso", "x", backoff_base=0)
    paths = await fetch_tree(c, "P", "r1", "main")
    assert paths == ["a/A.csproj", "b.py"]
    got = await fetch_contents(c, "P", "r1", "main", ["a/A.csproj"])
    assert got == {"a/A.csproj": "<xunit/>"}
    await c.aclose()


@respx.mock
async def test_fetch_tree_empty_repo_is_none():
    respx.get(BASE).mock(return_value=httpx.Response(404, json={}))
    c = AdoClient("contoso", "x", backoff_base=0)
    assert await fetch_tree(c, "P", "r1", "main") is None
    await c.aclose()


# ------------------------------------------------------------ test-state classification
def pipe(*caps_lists, coe=False, enabled=True, cond=None, platform="ado_classic_build"):
    steps = []
    for i, task in enumerate(caps_lists):
        s = Step(id=str(i), name=task, task=task, enabled=enabled, continue_on_error=coe, condition=cond)
        steps.append(classify_step(s))
    return Pipeline(platform=platform, id="1", name="p", project="P", stages=[Stage(name="build", jobs=[Job(name="j", steps=steps)])])


FACTS = RepoFacts(languages=["dotnet"], tests_detected=True, has_app_code=True)
SONAR_OK = SonarFacts(onboarded=True, coverage=85.0)


def state(facts=FACTS, pipelines=None, sonar=SONAR_OK, thr=80.0):
    return classify_test_state(facts, pipelines if pipelines is not None else [], sonar, thr)[0]


def test_state_not_applicable():
    for kind in ("adf", "synapse", "iac", "docs"):
        assert state(RepoFacts(kind=kind, has_app_code=False)) == TestState.NOT_APPLICABLE


def test_state_no_tests():
    assert state(RepoFacts(languages=["python"], has_app_code=True, tests_detected=False)) == TestState.NO_TESTS


def test_state_not_run_variants():
    assert state(pipelines=[pipe("PublishBuildArtifacts@1")]) == TestState.TESTS_NOT_RUN
    assert state(pipelines=[]) == TestState.TESTS_NOT_RUN
    assert state(pipelines=[pipe("VSTest@2", coe=True)]) == TestState.TESTS_NOT_RUN
    assert state(pipelines=[pipe("VSTest@2", enabled=False)]) == TestState.TESTS_NOT_RUN
    assert state(pipelines=[pipe("VSTest@2", cond="eq(1, 2)")]) == TestState.TESTS_NOT_RUN
    assert state(pipelines=[pipe("VSTest@2", platform="ado_classic_release")]) == TestState.TESTS_NOT_RUN


def test_state_no_coverage():
    assert state(pipelines=[pipe("VSTest@2")], sonar=None) == TestState.TESTS_NO_COVERAGE
    assert state(pipelines=[pipe("VSTest@2")], sonar=SonarFacts(onboarded=True, coverage=None)) == TestState.TESTS_NO_COVERAGE
    assert state(pipelines=[pipe("VSTest@2")], sonar=SonarFacts(onboarded=False)) == TestState.TESTS_NO_COVERAGE


def test_state_low_coverage_and_ok():
    ps = [pipe("VSTest@2", "PublishCodeCoverageResults@1")]
    assert state(pipelines=ps, sonar=SonarFacts(onboarded=True, coverage=42.0)) == TestState.TESTS_LOW_COVERAGE
    assert state(pipelines=ps, sonar=SonarFacts(onboarded=True, coverage=80.0)) == TestState.TESTS_OK
    assert state(pipelines=ps, sonar=SonarFacts(onboarded=True, coverage=70.0), thr=70.0) == TestState.TESTS_OK
    st, reason, cov = classify_test_state(FACTS, ps, SONAR_OK, 80.0)
    assert st == TestState.TESTS_OK and cov == 85.0 and "85.0" in reason
