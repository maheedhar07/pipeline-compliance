"""Standards as configuration (G1): policy.yaml `rules:` (enabled / severity / params) and `scoring:`, strict validation."""

import re
from datetime import timedelta

import pytest
import respx
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from pch.cli import app
from pch.collectors.ado.runs import change_refs
from pch.engine.registry import REGISTRY, load_rules, rule_params
from pch.engine.runner import evaluate, policy_effects
from pch.engine.scoring import score_repo
from pch.model.findings import Finding, RepoStatus, Severity, Status
from pch.model.pipeline import DeploymentRecord
from pch.model.repo import ChangeRequest
from pch.settings import ConfigError, Policy, load_policy
from pch.store import repository as store
from pch.store.db import session_scope
from tests.builders import (
    NOW,
    BranchPolicies,
    ServiceConnection,
    SnowFacts,
    SonarFacts,
    VariableGroup,
    VariableGroupRef,
    ctx,
    one,
    pipe,
    run,
    stage,
    step,
)
from tests.test_external_repos import mock_ado, scan

ORG = Policy(sonar_quality_gate_name="Org Quality Gate")
WRONG_GATE = SonarFacts(onboarded=True, gate_name="Sonar way")


def pol(**rules) -> Policy:
    return Policy.model_validate({"rules": rules})


# ------------------------------------------------------------------ enabled / severity
def test_disabled_rule_is_not_evaluated_and_default_is_enabled():
    c = ctx(sonar=WRONG_GATE)
    assert one("QLT-004", c, ORG) == "FAIL"
    off = ORG.model_copy(update={"rules": pol(**{"QLT-004": {"enabled": False}}).rules})
    assert run("QLT-004", c, off) == []
    assert [f.rule_id for f in evaluate(c, off) if f.rule_id == "QLT-004"] == []
    assert one("QLT-004", c, ORG.model_copy(update={"rules": pol(**{"QLT-004": {"enabled": True}}).rules})) == "FAIL"


def test_severity_override_changes_finding_scoring_and_status():
    c = ctx(sonar=WRONG_GATE)
    assert REGISTRY["QLT-004"].severity == Severity.MEDIUM
    crit = ORG.model_copy(update={"rules": pol(**{"QLT-004": {"severity": "critical"}}).rules})
    f = run("QLT-004", c, crit)[0]
    assert f.severity == Severity.CRITICAL and f.status == Status.FAIL
    base_f = run("QLT-004", c, ORG)[0]
    assert base_f.severity == Severity.MEDIUM
    others = [Finding(rule_id=f"X-{i}", repo_key="P/r", category="SRC", severity=Severity.HIGH, status=Status.PASS) for i in range(30)]
    assert score_repo([base_f, *others], ORG).status == RepoStatus.COMPLIANT
    assert score_repo([f, *others], crit).status == RepoStatus.NON_COMPLIANT  # a critical failure now
    low = ORG.model_copy(update={"rules": pol(**{"QLT-004": {"severity": "info"}}).rules})
    assert score_repo([run("QLT-004", c, low)[0]], low).score is None  # weight 0: not counted


def test_policy_effects_snapshot():
    eff = policy_effects(pol(**{"QLT-004": {"enabled": False}, "DEP-001": {"severity": "high"}, "SRC-004": {"params": {}}}))
    assert eff == {"disabled": ["QLT-004"], "severity": {"DEP-001": {"from": "critical", "to": "high"}}}
    assert policy_effects(Policy()) == {"disabled": [], "severity": {}}


# ------------------------------------------------------------------ params (each flips a result)
def with_params(rule_id, **params) -> Policy:
    return Policy.model_validate({"approved_registries": ["contosoacr.azurecr.io"], "marketplace_task_allowlist": [], "rules": {rule_id: {"params": params}}})


def test_every_rule_param_default_is_valid_and_merged():
    load_rules()
    with_p = {r.id: r for r in REGISTRY.values() if r.params}
    assert {"SRC-001", "QLT-001", "QLT-002", "TST-004", "DEP-004", "DEP-005", "SEC-002", "SEC-005", "SUP-002", "SUP-004"} <= set(with_p)
    for rid, meta in with_p.items():
        assert rule_params(Policy(), rid) == meta.params
        Policy.model_validate({"rules": {rid: {"params": dict(meta.params)}}})  # the defaults themselves validate
    assert rule_params(with_params("DEP-004", lower_tiers=["qa"]), "DEP-004") == {"lower_tiers": ["qa"]}
    assert rule_params(with_params("DEP-005", window_slack_hours=5), "DEP-005")["crq_pattern"] == REGISTRY["DEP-005"].params["crq_pattern"]  # partial override


def test_src_001_params():
    pols = BranchPolicies(available=True, min_reviewers=2, creator_vote_counts=True, reset_on_push=False)
    assert one("SRC-001", ctx(policies=pols)) == "FAIL"
    assert one("SRC-001", ctx(policies=pols), with_params("SRC-001", allow_creator_vote=True, require_reset_on_push=False)) == "PASS"


def test_qlt_params():
    sonar = [step("SonarQubePrepare@5"), step("SonarQubeAnalyze@5")]
    c = ctx([pipe([stage("build", sonar)])])
    assert one("QLT-001", c) == "FAIL"  # publish missing
    assert one("QLT-001", c, with_params("QLT-001", required_steps=["sonar:prepare", "sonar:analyze"])) == "PASS"
    waiting = ctx([pipe([stage("build", [step("SonarQubePrepare@5", {"extraProperties": "sonar.qualitygate.wait=true"})])])])
    assert one("QLT-002", waiting) == "PASS"
    assert one("QLT-002", waiting, with_params("QLT-002", wait_pattern=r"never-matches-\d+")) == "WARN"


def test_tst_004_params():
    only_results = ctx([pipe([stage("b", [step("VSTest@2"), step("PublishTestResults@2")])])])
    assert one("TST-004", only_results) == "FAIL"
    assert one("TST-004", only_results, with_params("TST-004", required_published=["test-results-publish"])) == "PASS"


def classic_prod(*stages):
    return pipe(list(stages), platform="ado_classic_release")


def test_dep_004_lower_tiers():
    dev = stage("Dev", [step("AzureWebApp@1")], tier="dev")
    prod = stage("Prod", [step("AzureWebApp@1")], tier="prod", depends_on=["Dev"])
    c = ctx([classic_prod(dev, prod)])
    assert one("DEP-004", c) == "PASS"
    assert one("DEP-004", c, with_params("DEP-004", lower_tiers=["uat"])) == "WARN"  # this org only counts UAT as a real predecessor


def test_dep_005_window_slack_and_crq_pattern():
    def case(hours_ago):
        p = classic_prod(stage("Prod", [step("AzureWebApp@1")], tier="prod"))
        p.deployments_90d = [DeploymentRecord(id="1", stage_name="Prod", env_tier="prod", completed_at=NOW - timedelta(hours=hours_ago), status="succeeded", change_refs=["CHG0000001"])]
        cr = ChangeRequest(number="CHG0000001", state="Implement", approval="approved", start_date=NOW - timedelta(hours=30), end_date=NOW - timedelta(hours=20), ci="r")
        return ctx([p], snow=SnowFacts(available=True, changes={cr.number: cr}))

    assert one("DEP-005", case(17)) == "FAIL"  # 3 h after the window: beyond the default 2 h slack
    assert one("DEP-005", case(17), with_params("DEP-005", window_slack_hours=4)) == "PASS"
    assert change_refs("see CHG0000123 and RFC-77") == ["CHG0000123"]
    assert change_refs("see CHG0000123 and RFC-77", pattern=re.compile(r"\bRFC-\d+\b", re.I)) == ["RFC-77"]


def conn(name, level="ResourceGroup"):
    return ServiceConnection(id=name + "-id", name=name, type="azurerm", auth_scheme="WorkloadIdentityFederation", scope_level=level,
                             all_pipelines_authorized=False, federated=True)


def test_sec_params():
    plain = VariableGroup(id="1", name="payments-live", key_vault_linked=False, has_secrets=False)
    prod = stage("Prod", [step("AzureWebApp@1")], tier="prod")
    p = pipe([prod], variable_groups=[VariableGroupRef(id="1", name="payments-live")])
    assert one("SEC-002", ctx([p], groups=[plain])) == "PASS"  # the group name does not say "prod"
    assert one("SEC-002", ctx([p], groups=[plain]), with_params("SEC-002", prod_name_hints=["live"])) == "FAIL"
    cp = pipe([stage("Prod", [step("AzureFunctionApp@2", {"azureSubscription": "c"})], tier="prod", env="e")])
    cc = ctx([cp], conns=[conn("c", "Subscription")])
    assert one("SEC-005", cc) == "WARN"
    assert one("SEC-005", cc, with_params("SEC-005", fail_scope_levels=["subscription"], warn_scope_levels=[])) == "FAIL"


def test_sup_params():
    unpinned = ctx([pipe([stage("b", [step("DotNetCoreCLI"), step("NuGetCommand@2")])])])
    assert one("SUP-002", unpinned) == "FAIL"
    assert one("SUP-002", unpinned, with_params("SUP-002", ignored_tasks=["DotNetCoreCLI"])) == "PASS"

    def aks(image):
        return ctx([pipe([stage("Prod", [step("KubernetesManifest@1", {"containers": image})], tier="prod")])])

    assert one("SUP-004", aks("contosoacr.azurecr.io/orders:latest")) == "FAIL"
    assert one("SUP-004", aks("contosoacr.azurecr.io/orders:latest"), with_params("SUP-004", forbidden_tags=[])) == "WARN"  # no tag is forbidden; still not immutable
    assert one("SUP-004", aks("contosoacr.azurecr.io/orders:stable"), with_params("SUP-004", forbidden_tags=["stable"])) == "FAIL"
    assert "':stable'" in run("SUP-004", aks("contosoacr.azurecr.io/orders:stable"), with_params("SUP-004", forbidden_tags=["stable"]))[0].message


# ------------------------------------------------------------------ scoring
def F(rule_id, cat, sev, status):
    return Finding(rule_id=rule_id, repo_key="P/r", category=cat, severity=sev, status=status)


def test_scoring_weights_are_configurable_and_default_is_unchanged():
    fs = [F("A-1", "SRC", Severity.HIGH, Status.PASS), F("A-2", "QLT", Severity.MEDIUM, Status.FAIL), F("A-3", "TST", Severity.LOW, Status.WARN)]
    assert score_repo(fs).score == score_repo(fs, Policy()).score == pytest.approx(100 * (5 + 0.5) / (5 + 3 + 1), abs=0.1)
    sev = Policy.model_validate({"scoring": {"severity_weights": {"medium": 20}}})
    assert score_repo(fs, sev).score == pytest.approx(100 * (5 + 0.5) / (5 + 20 + 1), abs=0.1)  # unlisted severities keep their default
    cat = Policy.model_validate({"scoring": {"category_weights": {"QLT": 0}}})  # QLT does not count at all
    assert score_repo(fs, cat).score == pytest.approx(100 * (5 + 0.5) / (5 + 1), abs=0.1)
    warn = Policy.model_validate({"scoring": {"warn_credit": 1.0}})
    assert score_repo(fs, warn).score == pytest.approx(100 * (5 + 1) / (5 + 3 + 1), abs=0.1)


# ------------------------------------------------------------------ strict validation (messages name the path)
def load(tmp_path, body) -> Policy:
    f = tmp_path / "policy.yaml"
    f.write_text(yaml.safe_dump(body) if not isinstance(body, str) else body)
    return load_policy(f)


@pytest.mark.parametrize("body,needle", [
    ({"rules": {"NOPE-999": {"enabled": False}}}, "rules.NOPE-999: unknown rule id"),
    ({"rules": {"QLT-004": {"enabld": False}}}, "rules.QLT-004.enabld"),
    ({"rules": {"QLT-004": {"severity": "urgent"}}}, "rules.QLT-004.severity"),
    ({"rules": {"QLT-004": {"enabled": "maybe"}}}, "rules.QLT-004.enabled"),
    ({"rules": {"DEP-004": {"params": {"nope": 1}}}}, "rules.DEP-004.params.nope: unknown param"),
    ({"rules": {"DEP-004": {"params": {"lower_tiers": "dev"}}}}, "rules.DEP-004.params.lower_tiers: expected list"),
    ({"rules": {"DEP-005": {"params": {"window_slack_hours": True}}}}, "rules.DEP-005.params.window_slack_hours: expected int"),
    ({"rules": {"DEP-005": {"params": {"crq_pattern": "(unclosed"}}}}, "rules.DEP-005.params.crq_pattern: invalid regular expression"),
    ({"rules": {"QLT-004": {"params": {"x": 1}}}}, "rules.QLT-004.params.x: unknown param (this rule's params: none)"),
    ({"scoring": {"severity_weights": {"urgent": 3}}}, "scoring.severity_weights"),
    ({"scoring": {"severity_weights": {"high": -1}}}, "weights must be >= 0"),
    ({"scoring": {"category_weights": {"ZZZ": 2}}}, "unknown rule categories ['ZZZ']"),
    ({"scoring": {"warn_credit": 2}}, "scoring.warn_credit"),
    ({"scoring": {"bogus": 1}}, "scoring.bogus"),
])
def test_invalid_policy_rules_and_scoring_are_config_errors(tmp_path, body, needle):
    with pytest.raises(ConfigError) as e:
        load(tmp_path, body)
    msg = str(e.value)
    assert needle in msg and str(tmp_path / "policy.yaml") in msg, msg


def test_valid_rules_map_loads(tmp_path):
    p = load(tmp_path, {"rules": {"QLT-004": {"enabled": False}, "DEP-001": {"severity": "high"}, "DEP-004": {"params": {"lower_tiers": ["dev"]}}},
                        "scoring": {"severity_weights": {"critical": 12}, "category_weights": {"DEP": 2}}})
    assert not p.rules["QLT-004"].enabled and p.rules["DEP-001"].severity == Severity.HIGH
    assert p.scoring.severity_weight(Severity.CRITICAL) == 12 and p.scoring.severity_weight(Severity.HIGH) == 5 and p.scoring.category_weight("DEP") == 2
    assert load(tmp_path, "{}\n").rules == {}


def test_shipped_policy_yaml_documents_rules_and_scoring_examples():
    text = (__import__("pathlib").Path(__file__).parent.parent / "config" / "policy.yaml").read_text()
    assert "# rules:" in text and "# scoring:" in text
    assert load_policy("config/policy.yaml").rules == {}
    blocks = re.findall(r"(?m)^# (?:rules|scoring):\n(?:#   .*\n)+", text)  # the commented-out examples must be valid when uncommented
    assert len(blocks) == 2
    uncommented = "\n".join(line[2:] for b in blocks for line in b.splitlines())
    p = Policy.model_validate(yaml.safe_load(uncommented))
    assert not p.rules["QLT-004"].enabled and p.rules["DEP-005"].params["window_slack_hours"] == 4 and p.scoring.category_weight("SEC") == 2


# ------------------------------------------------------------------ CLI
def test_cli_rules_list_params_and_policy(tmp_path):
    r = CliRunner().invoke(app, ["rules", "list", "--params", "-c", "DEP"])
    assert r.exit_code == 0 and "lower_tiers = ['dev', 'test', 'uat']" in r.output and "window_slack_hours = 2" in r.output
    f = tmp_path / "policy.yaml"
    f.write_text(yaml.safe_dump({"rules": {"DEP-001": {"severity": "high"}, "DEP-004": {"enabled": False, "params": {}}, "DEP-005": {"params": {"window_slack_hours": 6}}}}))
    r = CliRunner().invoke(app, ["rules", "list", "--params", "--policy", str(f), "-c", "DEP"])
    assert r.exit_code == 0, r.output
    assert re.search(r"DEP-001\s+high\*", r.output) and "[disabled by policy]" in r.output and "window_slack_hours = 6  (default: 2)" in r.output
    js = CliRunner().invoke(app, ["rules", "list", "--json", "--policy", str(f)]).output
    assert '"default_severity": "critical"' in js and '"enabled": false' in js
    f.write_text("rules: {NOPE-1: {enabled: false}}")
    bad = CliRunner().invoke(app, ["rules", "list", "--policy", str(f)])
    assert bad.exit_code != 0 and "rules.NOPE-1: unknown rule id" in bad.output


def test_doctor_reports_policy_effects(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_text(yaml.safe_dump({"rules": {"QLT-004": {"enabled": False}, "DEP-001": {"severity": "high"}}}))
    r = CliRunner().invoke(app, ["doctor", "--policy", str(f), "--scope", str(tmp_path / "none.yaml")], env={"DATABASE_URL": f"sqlite:///{tmp_path}/d.db", "DATA_DIR": str(tmp_path)})
    assert "disabled rules: QLT-004; severity overrides: DEP-001" in r.output


# ------------------------------------------------------------------ end to end: scan + UI
@respx.mock
def test_scan_applies_policy_and_ui_marks_it(fx, fxt, tmp_path):
    from pch.settings import Scope
    from pch.web.app import create_app

    mock_ado(fx, fxt, items_calls=[])
    policy = Policy.model_validate({"rules": {"SRC-004": {"enabled": False}, "SUP-005": {"severity": "critical"}}})
    db = scan(tmp_path, Scope(projects=["Payments"]), policy)
    with session_scope(db) as s:
        assert store.findings(s, "ext", rule_id="SRC-004") == []
        sup = store.findings(s, "ext", rule_id="SUP-005")
        assert sup and {f.severity for f in sup} == {"critical"}
        assert not any("SRC-004" in (r.rule_status or {}) for r in store.repo_results(s, "ext"))
        assert store.get_scan(s, "ext").summary["policy"] == {"disabled": ["SRC-004"], "severity": {"SUP-005": {"from": "low", "to": "critical"}}}
    c = TestClient(create_app(db))
    rules_page = c.get("/rules").text
    assert "disabled by policy" in rules_page and "severity overridden by policy (default: low)" in rules_page
    assert "overridden" in c.get("/findings", params={"rule": "SUP-005"}).text
    stats = {r["id"]: r for r in c.get("/api/v1/rules").json()["rules"]}
    assert stats["SRC-004"]["disabled"] is True and stats["SUP-005"]["severity"] == "critical" and stats["SUP-005"]["severity_default"] == "low"
    detail = c.get("/rules/SRC-004").text
    assert "disabled by policy" in detail
    assert "window_slack_hours" in c.get("/rules/DEP-005").text
