from datetime import date, datetime, timedelta

import pytest

from pch.engine import registry
from pch.engine.registry import RuleMeta, rule
from pch.engine.runner import StageTarget, evaluate
from pch.engine.scoring import aggregate_rule_status, apply_waivers, score_repo
from pch.model.findings import Finding, RepoStatus, RuleResult, Severity, Status
from pch.model.pipeline import Pipeline, Stage
from pch.model.repo import RepoContext, RepoRef
from pch.settings import Policy, Waiver
from pch.store import repository as repo_store
from pch.store.db import session_scope
from pch.store.models import FindingRow, RepoResultRow


def F(rule_id, sev, status, repo="P/r"):
    return Finding(rule_id=rule_id, repo_key=repo, category=rule_id[:3], severity=sev, status=status)


def test_score_weights_and_status():
    fs = [F("A-1", Severity.HIGH, Status.PASS), F("A-2", Severity.MEDIUM, Status.FAIL), F("A-3", Severity.LOW, Status.PASS)]
    sc = score_repo(fs)
    assert sc.score == pytest.approx(100 * (5 + 1) / (5 + 3 + 1), abs=0.1)
    assert sc.status == RepoStatus.AT_RISK  # score < 80


def test_critical_fail_is_non_compliant_and_high_fail_at_risk():
    assert score_repo([F("A-1", Severity.CRITICAL, Status.FAIL), F("A-2", Severity.LOW, Status.PASS)]).status == RepoStatus.NON_COMPLIANT
    many_pass = [F(f"P-{i}", Severity.CRITICAL, Status.PASS) for i in range(20)]
    assert score_repo(many_pass + [F("H-1", Severity.HIGH, Status.FAIL)]).status == RepoStatus.AT_RISK
    assert score_repo(many_pass).status == RepoStatus.COMPLIANT


def test_unknown_and_na_excluded_and_counted():
    fs = [F("A-1", Severity.HIGH, Status.PASS), F("A-2", Severity.HIGH, Status.UNKNOWN), F("A-3", Severity.HIGH, Status.NOT_APPLICABLE)]
    sc = score_repo(fs)
    assert sc.score == 100.0
    assert sc.unknown == 1


def test_warn_gets_half_credit():
    sc = score_repo([F("A-1", Severity.HIGH, Status.WARN)])
    assert sc.score == 50.0


def test_worst_finding_per_rule_wins():
    fs = [F("A-1", Severity.HIGH, Status.PASS), F("A-1", Severity.HIGH, Status.FAIL)]
    assert score_repo(fs).by_rule["A-1"] == Status.FAIL
    assert aggregate_rule_status([]) == Status.NOT_APPLICABLE


def test_waiver_active_turns_fail_into_waived():
    pol = Policy(waivers=[Waiver(rule="A-1", repo="P/r", reason="ok", owner="o", expires=date.today() + timedelta(days=5))])
    fs = [F("A-1", Severity.CRITICAL, Status.FAIL), F("A-2", Severity.LOW, Status.FAIL)]
    apply_waivers(fs, "P/r", pol)
    assert fs[0].status == Status.WAIVED and fs[0].original_status == Status.FAIL
    assert fs[1].status == Status.FAIL
    assert score_repo(fs).critical_fails == 0


def test_waiver_expired_keeps_fail_with_badge():
    pol = Policy(waivers=[Waiver(rule="A-1", repo="r", expires=date.today() - timedelta(days=1))])
    fs = [F("A-1", Severity.HIGH, Status.FAIL)]
    apply_waivers(fs, "P/r", pol)
    assert fs[0].status == Status.FAIL
    assert fs[0].waiver is not None and fs[0].waiver.expired


def test_waiver_other_repo_ignored():
    pol = Policy(waivers=[Waiver(rule="A-1", repo="P/other")])
    fs = [F("A-1", Severity.HIGH, Status.FAIL)]
    apply_waivers(fs, "P/r", pol)
    assert fs[0].status == Status.FAIL and fs[0].waiver is None


@pytest.fixture
def temp_rules():
    saved = dict(registry.REGISTRY)
    yield
    registry.REGISTRY.clear()
    registry.REGISTRY.update(saved)


def _ctx():
    st_prod = Stage(name="prod", env_tier="prod", deploy_targets={"webapp"}, is_deploy=True)
    st_dev = Stage(name="dev", env_tier="dev", deploy_targets={"functionapp"}, is_deploy=True)
    p = Pipeline(platform="ado_yaml", id="1", name="p", project="P", stages=[st_dev, st_prod])
    return RepoContext(repo=RepoRef(id="r", name="r", project="P"), pipelines=[p], now=datetime(2026, 1, 1))


def test_runner_scopes_and_filters(temp_rules):
    @rule("ZZZ-001", "repo rule", "high", "repo", "r")
    def r1(ctx, policy):
        return RuleResult.passed("ok")

    @rule("ZZZ-002", "pipeline rule", "low", "pipeline", "r", platforms={"ado_classic_build"})
    def r2(ctx, policy, p):
        return RuleResult.failed("x")

    @rule("ZZZ-003", "stage rule", "medium", "stage", "r", tiers={"prod"}, targets={"webapp"})
    def r3(ctx, policy, t: StageTarget):
        return RuleResult.failed(t.stage.name)

    @rule("ZZZ-004", "na rule", "medium", "repo", "r")
    def r4(ctx, policy):
        return RuleResult.na()

    @rule("ZZZ-005", "crash", "medium", "repo", "r")
    def r5(ctx, policy):
        raise RuntimeError("boom")

    metas = [registry.REGISTRY[k] for k in sorted(registry.REGISTRY) if k.startswith("ZZZ")]
    fs = {f.rule_id: f for f in evaluate(_ctx(), Policy(), metas)}
    assert fs["ZZZ-001"].status == Status.PASS
    assert "ZZZ-002" not in fs  # wrong platform
    assert fs["ZZZ-003"].stage == "prod" and fs["ZZZ-003"].status == Status.FAIL
    assert "ZZZ-004" not in fs  # NA dropped
    assert fs["ZZZ-005"].status == Status.UNKNOWN and "boom" in fs["ZZZ-005"].message


def test_duplicate_rule_rejected(temp_rules):
    @rule("ZZZ-010", "t", "low", "repo", "r")
    def a(ctx, policy):
        return RuleResult.passed()

    with pytest.raises(ValueError):
        rule("ZZZ-010", "t", "low", "repo", "r")(a)


def test_rulemeta_remediation_fallback():
    m = RuleMeta("X-1", "t", "X", Severity.LOW, "repo", "r", {"classic": "c", "yaml": "y"}, lambda c, p: None)
    assert m.remediation_for("ado_classic_release") == "c"
    assert m.remediation_for("ado_yaml") == "y"


def test_store_roundtrip(tmp_path):
    url = f"sqlite:///{tmp_path}/t.db"
    with session_scope(url) as s:
        repo_store.create_scan(s, "scan1", "demo")
        s.add(RepoResultRow(scan_id="scan1", repo_key="P/r", project="P", repo="r", status="COMPLIANT", score=99.0))
        s.add(FindingRow(scan_id="scan1", repo_key="P/r", rule_id="A-1", category="A", severity="high", status="FAIL"))
        s.get(repo_store.ScanRow, "scan1").status = "complete"
    with session_scope(url) as s:
        assert repo_store.latest_scan(s).id == "scan1"
        assert len(repo_store.repo_results(s, "scan1")) == 1
        assert repo_store.repo_result(s, "scan1", "P/r").score == 99.0
        assert len(repo_store.findings(s, "scan1", rule_id="A-1")) == 1
        assert len(repo_store.list_scans(s)) == 1
        repo_store.delete_scan(s, "scan1")
    with session_scope(url) as s:
        assert repo_store.latest_scan(s) is None
