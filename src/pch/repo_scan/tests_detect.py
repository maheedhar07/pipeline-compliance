"""Language-aware test detection, repo-kind detection and the test-state classification."""

from __future__ import annotations

import re
from collections.abc import Iterable

from pch.model.pipeline import Pipeline
from pch.model.repo import RepoFacts, SonarFacts, TestState

LANG_EXT = {
    "dotnet": (".cs", ".csproj", ".fs", ".vb"),
    "java": (".java", ".kt"),
    "python": (".py",),
    "js": (".ts", ".tsx", ".js", ".jsx", ".mjs"),
    "go": (".go",),
    "sql": (".sql", ".sqlproj"),
}
APP_LANGS = set(LANG_EXT)
IGNORED_DIRS = ("node_modules/", "bin/", "obj/", ".git/", "vendor/", "dist/", "build/", "packages/")
DOTNET_TEST_REF = re.compile(r"xunit|nunit|MSTest|Microsoft\.NET\.Test\.Sdk", re.I)
JS_TEST_DEP = re.compile(r'"(jest|vitest|mocha|jasmine|ava|@playwright/test|cypress)"', re.I)
PY_TEST_DEP = re.compile(r"(?im)^\s*(pytest|unittest2|nose2?)\b|\bpytest\b")


def _lang_files(paths: Iterable[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {k: [] for k in LANG_EXT}
    for p in paths:
        low = p.lower()
        for lang, exts in LANG_EXT.items():
            if low.endswith(exts):
                out[lang].append(p)
    return out


def detect_tests(paths: list[str], contents: dict[str, str]) -> tuple[bool, list[str]]:
    """Return (tests_detected, signals) using the per-language signals from the plan."""
    signals: list[str] = []
    low = [p.lower() for p in paths]
    # .NET
    for p in paths:
        if p.lower().endswith(".csproj"):
            name = p.rsplit("/", 1)[-1]
            if "test" in name.lower():
                signals.append(f"dotnet: test project {name}")
            elif DOTNET_TEST_REF.search(contents.get(p, "")):
                signals.append(f"dotnet: {name} references a test framework")
    # Java
    if any("/src/test/" in "/" + p.lower() or p.lower().startswith("src/test/") for p in paths) or any(p.endswith("Test.java") for p in paths):
        signals.append("java: src/test or *Test.java")
    # Python
    if any(re.search(r"(^|/)test_[^/]*\.py$|_test\.py$", p) for p in low) or any(re.search(r"(^|/)tests?/", p) and p.endswith(".py") for p in low):
        signals.append("python: test_*.py / *_test.py / tests/")
    for p, c in contents.items():
        pl = p.lower()
        if (pl.endswith("pyproject.toml") or "requirements" in pl) and PY_TEST_DEP.search(c):
            signals.append(f"python: pytest listed in {p}")
    # JS/TS
    if any(re.search(r"\.(test|spec)\.[jt]sx?$", p) for p in low) or any("__tests__/" in p for p in low):
        signals.append("js: *.test.* / *.spec.* / __tests__/")
    for p, c in contents.items():
        if p.lower().endswith("package.json") and JS_TEST_DEP.search(c):
            signals.append(f"js: test framework dependency in {p}")
    # Go
    if any(p.endswith("_test.go") for p in low):
        signals.append("go: *_test.go")
    # SQL (tSQLt)
    if any("tsqlt" in p for p in low) or any("tsqlt" in c.lower() for c in contents.values()):
        signals.append("sql: tSQLt")
    return bool(signals), signals


def analyze_repo(paths: list[str] | None, contents: dict[str, str] | None = None) -> RepoFacts:
    """Build RepoFacts (languages, kind, IaC, Dockerfiles, ...) from the file list."""
    if not paths:
        return RepoFacts(kind="docs", has_app_code=False, file_count=0)
    contents = contents or {}
    paths = [p for p in paths if not any(d in "/" + p.lower() + "/" for d in ("/node_modules/", "/bin/", "/obj/"))]
    low = [p.lower() for p in paths]
    lang_files = _lang_files(paths)
    languages = sorted(k for k, v in lang_files.items() if v)
    # a repo with only .sql is a database repo; only .sql/.sqlproj count as app code when tests exist or sqlproj present
    app_languages = [lang for lang in languages if lang in APP_LANGS]
    has_app = bool(app_languages)
    iac: list[str] = []
    if any(p.endswith(".bicep") for p in low):
        iac.append("bicep")
    if any(p.endswith(".tf") for p in low):
        iac.append("terraform")
    if any(re.search(r"(^|/)(azuredeploy[^/]*|armtemplate[^/]*|main)\.json$", p) for p in low) and not any("factory/" in p for p in low):
        iac.append("arm")
    adf = any(re.search(r"(^|/)factory/[^/]+\.json$", p) for p in low) or any(p.endswith("publish_config.json") for p in low) or (
        any("/pipeline/" in "/" + p and p.endswith(".json") for p in low) and any("/dataset/" in "/" + p or "/linkedservice/" in "/" + p for p in low)
    )
    synapse = any(p.endswith("templateforworkspace.json") for p in low) or (
        any("/notebook/" in "/" + p for p in low) and any("/sqlscript/" in "/" + p or "/integrationruntime/" in "/" + p for p in low)
    )
    sqlproj = any(p.endswith(".sqlproj") for p in low)
    code_langs_non_sql = [lang for lang in app_languages if lang != "sql"]
    kind = "application"
    if not has_app:
        kind = "adf" if adf else "synapse" if synapse else "iac" if iac else "docs"
    elif not code_langs_non_sql:
        kind = "sql"
    if adf and not code_langs_non_sql and kind in ("sql", "application"):
        kind = "adf"
        has_app = False
    if synapse and not code_langs_non_sql and kind in ("sql", "application"):
        kind = "synapse"
        has_app = False
    tests, signals = detect_tests(paths, contents)
    codeowners = any(re.search(r"(^|/)(\.azuredevops/|docs/|\.github/)?codeowners$", p) for p in low)
    pipeline_files = [p for p in paths if re.search(r"(^|/)(azure-pipelines[^/]*\.ya?ml|\.azure-pipelines/.*\.ya?ml|\.github/workflows/.*\.ya?ml)$", p, re.I)]
    return RepoFacts(
        languages=languages,
        kind=kind,
        has_app_code=has_app,
        tests_detected=tests,
        test_signals=signals,
        iac=iac,
        dockerfiles=[p for p in paths if re.search(r"(^|/)dockerfile[^/]*$", p, re.I)],
        k8s_manifests=any(re.search(r"(^|/)(k8s|kubernetes|manifests)/", p) and p.endswith((".yml", ".yaml")) for p in low),
        helm_chart=any(p.endswith("chart.yaml") for p in low),
        adf=adf,
        synapse=synapse,
        sql_project=sqlproj,
        codeowners=codeowners,
        pipeline_files=pipeline_files,
        file_count=len(paths),
    )


def runs_tests(pipelines: list[Pipeline]) -> tuple[bool, bool]:
    """(any unit-test step present, any effective one: enabled, not continueOnError, not always-false)."""
    present = effective = False
    for p in pipelines:
        if p.platform == "ado_classic_release":
            continue
        for s in p.all_steps():
            if "unit-test" in s.capabilities:
                present = True
                effective |= s.effective
    return present, effective


def publishes_coverage(pipelines: list[Pipeline]) -> bool:
    return any(
        "coverage-publish" in s.capabilities and s.enabled
        for p in pipelines
        if p.platform != "ado_classic_release"
        for s in p.all_steps()
    )


def has_sonar_analysis_step(pipelines: list[Pipeline]) -> bool:
    return any("sonar:analyze" in s.capabilities and s.enabled for p in pipelines for s in p.all_steps())


def classify_test_state(
    facts: RepoFacts,
    pipelines: list[Pipeline],
    sonar: SonarFacts | None,
    threshold: float = 80.0,
) -> tuple[TestState, str, float | None]:
    """Return (state, human reason, coverage). See PLAN section 6."""
    coverage = sonar.coverage if sonar and sonar.onboarded else None
    if not facts.has_app_code:
        return TestState.NOT_APPLICABLE, f"{facts.kind} repository: validated by TST-006 instead of unit tests", coverage
    if not facts.tests_detected:
        return TestState.NO_TESTS, "no test files, test projects or test frameworks detected in an application repo", coverage
    present, effective = runs_tests(pipelines)
    if not effective:
        why = "a test step exists but is disabled / continueOnError / always-false" if present else "tests exist but no build pipeline runs them"
        return TestState.TESTS_NOT_RUN, why, coverage
    published = publishes_coverage(pipelines) or has_sonar_analysis_step(pipelines)
    if coverage is None or not published:
        return TestState.TESTS_NO_COVERAGE, "tests run but no coverage is published or Sonar has no coverage metric", coverage
    if coverage < threshold:
        return TestState.TESTS_LOW_COVERAGE, f"coverage {coverage:.1f}% is below the {threshold:.0f}% threshold", coverage
    return TestState.TESTS_OK, f"tests run and coverage {coverage:.1f}% meets the {threshold:.0f}% threshold", coverage
