"""Feature switches: strict features.yaml, DB overrides with an audit trail, and what each switch does to a scan, the rules and the sources."""

import asyncio
from datetime import datetime

import pytest
import respx
from typer.testing import CliRunner

from pch import features as F
from pch.cli import app
from pch.demo.generator import generate_world
from pch.demo.transport import parse_world_time
from pch.engine.registry import REGISTRY, all_rules
from pch.engine.runner import rules_for_features
from pch.orchestrator import ScanConfig, Scanner
from pch.settings import ConfigError, Policy, Scope, Settings
from pch.sources import Sources, demo_sources, live_sources
from pch.store import migrate
from pch.store import repository as store
from pch.store.db import get_raw_engine, reset_engines, session_scope
from pch.store.models import FeatureAuditRow
from tests.builders import ALL_HOSTS

runner = CliRunner()
ALICE = F.Actor("oid-alice", "Alice Admin")


@pytest.fixture
def db(tmp_path):
    reset_engines()
    url = f"sqlite:///{tmp_path}/f.db"
    migrate.upgrade(get_raw_engine(url))
    yield url
    reset_engines()


# ------------------------------------------------------------------ features.yaml
def test_features_file_defaults_all_on_and_missing_file_is_fine(tmp_path):
    assert F.load_feature_defaults(tmp_path / "nope.yaml") == F.ALL_ON == F.load_feature_defaults(None)
    p = tmp_path / "features.yaml"
    p.write_text("")
    assert F.load_feature_defaults(p) == F.ALL_ON
    p.write_text("migration: false\nsource_sonar: false\n")
    got = F.load_feature_defaults(p)
    assert got["migration"] is False and got["source_sonar"] is False and got["gha_scanning"] is True


@pytest.mark.parametrize("text", ["migrations: false\n", "migration: maybe\n", "migration: 1\n", "migration: 'off'\n", "- migration\n"])
def test_features_file_is_strict(tmp_path, text):
    p = tmp_path / "features.yaml"
    p.write_text(text)
    with pytest.raises(ConfigError) as e:
        F.load_feature_defaults(p)
    assert str(p) in str(e.value)


def test_shipped_features_yaml_is_valid_and_all_on():
    from pathlib import Path

    assert F.load_feature_defaults(Path(__file__).parent.parent / "config" / "features.yaml") == F.ALL_ON


# ------------------------------------------------------------------ precedence, audit, reset
def test_override_wins_over_file_default_and_reset_restores_it(db):
    defaults = {**F.ALL_ON, "migration": False}
    with session_scope(db) as s:
        st = {x.key: x for x in F.effective_states(s, defaults)}
        assert st["migration"].enabled is False and not st["migration"].overridden and st["migration"].source_text == "default from features.yaml"
        assert F.set_override(s, "migration", True, ALICE, "ui") is True
        assert F.set_override(s, "gha_scanning", False, ALICE, "ui") is True
    with session_scope(db) as s:
        st = {x.key: x for x in F.effective_states(s, defaults)}
        assert st["migration"].enabled is True and st["migration"].overridden and "changed by Alice Admin at " in st["migration"].source_text
        assert st["gha_scanning"].enabled is False
        assert F.effective_flags(s, defaults)["migration"] is True
        assert F.set_override(s, "migration", None, ALICE, "ui") is True
    with session_scope(db) as s:
        assert F.effective_flags(s, defaults)["migration"] is False  # back to the file


def test_audit_rows_old_new_actor_source_and_noop_writes_nothing(db):
    with session_scope(db) as s:
        assert F.set_override(s, "source_sonar", False, ALICE, "ui")
        assert not F.set_override(s, "source_sonar", False, ALICE, "ui")  # already off: no row
        assert F.set_override(s, "source_sonar", None, F.CLI_ACTOR, "cli")
        assert not F.set_override(s, "source_sonar", None, F.CLI_ACTOR, "cli")
    with session_scope(db) as s:
        rows = list(reversed(F.audit_entries(s)))
    assert [(r.feature_key, r.old_value, r.new_value, r.source, r.actor_display_name) for r in rows] == [
        ("source_sonar", "default", "off", "ui", "Alice Admin"), ("source_sonar", "off", "default", "cli", "cli")]
    assert rows[0].actor_id_hash == F.Actor("oid-alice", "x").id_hash and "oid-alice" not in rows[0].actor_id_hash and len(rows[0].actor_id_hash) == 64
    assert rows[0].at.tzinfo is not None


def test_unknown_key_is_rejected(db):
    with session_scope(db) as s, pytest.raises(KeyError):
        F.set_override(s, "nope", True, ALICE, "ui")


@pytest.mark.parametrize("name,want", [("Ada Lovelace", "Ada Lovelace"), ("ada@example.com", ""), ("Ada <ada@x.org>", ""), ("A\x00d\na", "Ada"), ("x" * 500, "x" * 100), (None, "")])
def test_actor_display_name_drops_emails_and_control_chars(name, want):
    assert F.clean_display_name(name) == want


def test_email_like_name_is_not_stored(db):
    with session_scope(db) as s:
        F.set_override(s, "migration", False, F.Actor("oid", "ada@example.com"), "ui")
    with session_scope(db) as s:
        assert "@" not in "".join(r.actor_display_name for r in F.audit_entries(s))
        assert F.effective_states(s, F.ALL_ON)[0].updated_by == ""
        assert "an administrator" in F.effective_states(s, F.ALL_ON)[0].source_text


# ------------------------------------------------------------------ rule metadata
def test_registry_declares_which_rules_depend_on_which_source():
    dep = {r.id: set(r.requires_sources) for r in all_rules() if r.requires_sources}
    assert dep == {"QLT-003": {"sonar"}, "QLT-004": {"sonar"}, "QLT-005": {"sonar"}, "QLT-006": {"aikido"}, "QLT-007": {"aikido"}, "DEP-005": {"servicenow"},
                   "SUP-006": {"gha"}, "SEC-006": {"gha"}, "SEC-007": {"gha"}, "SEC-008": {"gha"}, "SEC-009": {"gha"}}
    assert all(x in F.SOURCE_FEATURE for r in all_rules() for x in r.requires_sources)


@pytest.mark.parametrize("key,gone", [
    ("source_sonar", {"QLT-003", "QLT-004", "QLT-005"}), ("source_aikido", {"QLT-006", "QLT-007"}), ("source_servicenow", {"DEP-005"}),
    ("gha_scanning", {"SUP-006", "SEC-006", "SEC-007", "SEC-008", "SEC-009"}), ("migration", set())])
def test_rules_for_features_drops_exactly_the_dependent_rules(key, gone):
    kept = {r.id for r in rules_for_features(all_rules(), {**F.ALL_ON, key: False})}
    assert {r.id for r in all_rules()} - kept == gone
    assert {r.id for r in rules_for_features(all_rules(), F.ALL_ON)} == set(REGISTRY)


# ------------------------------------------------------------------ what a scan does with each switch
def demo_scan(tmp_path, features=None, sid="s1"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    url = f"sqlite:///{tmp_path}/scan.db"
    w = generate_world(seed=11, repos=14, now=datetime(2026, 10, 1, 12, 0, 0))
    src = demo_sources(w, features=features)
    cfg = ScanConfig(scope=Scope(code_hosts=ALL_HOSTS, projects=w["meta"]["projects"]), policy=Policy(approved_registries=["contosoacr.azurecr.io"]), db_url=url, mode="demo",
                     now=parse_world_time(w), **({"features": features} if features is not None else {}))

    async def go():
        try:
            return src, await Scanner(src, cfg).run(sid)
        finally:
            await src.aclose()

    return url, *asyncio.run(go())


def rule_ids(url, sid="s1"):
    with session_scope(url) as s:
        return {f.rule_id for f in store.findings(s, sid)}, store.get_scan(s, sid).summary


def test_all_on_scan_snapshots_features_and_evaluates_everything(tmp_path):
    url, src, _ = demo_scan(tmp_path)
    ids, summary = rule_ids(url)
    assert summary["features"] == F.ALL_ON and {"QLT-003", "QLT-006", "DEP-005"} <= ids
    assert src.sonar is not None and src.aikido is not None and src.snow is not None


@pytest.mark.parametrize("key,attr,gone", [
    ("source_sonar", "sonar", {"QLT-003", "QLT-004", "QLT-005"}), ("source_aikido", "aikido", {"QLT-006", "QLT-007"}), ("source_servicenow", "snow", {"DEP-005"})])
def test_source_off_means_no_client_and_its_rules_are_neither_evaluated_nor_scored(tmp_path, key, attr, gone):
    url, src, _ = demo_scan(tmp_path, {**F.ALL_ON, key: False})
    assert getattr(src, attr) is None
    ids, summary = rule_ids(url)
    assert not (ids & gone) and summary["features"][key] is False
    with session_scope(url) as s:
        for r in store.repo_results(s, "s1"):
            assert not (set(r.rule_status) & gone)  # no verdict recorded, so nothing in the score either


def test_scores_exclude_the_off_rules_exactly_like_a_policy_disabled_rule(tmp_path):
    """Switching a source off scores the same as disabling its rules in policy.yaml."""
    from pch.settings import RuleOverride

    on_url, *_ = demo_scan(tmp_path / "a", None)
    off_url, *_ = demo_scan(tmp_path / "b", {**F.ALL_ON, "source_aikido": False})
    w = generate_world(seed=11, repos=14, now=datetime(2026, 10, 1, 12, 0, 0))
    (tmp_path / "c").mkdir()
    pol_url = f"sqlite:///{tmp_path}/c/p.db"
    pol = Policy(approved_registries=["contosoacr.azurecr.io"], rules={"QLT-006": RuleOverride(enabled=False), "QLT-007": RuleOverride(enabled=False)})
    src = demo_sources(w)
    cfg = ScanConfig(scope=Scope(code_hosts=ALL_HOSTS, projects=w["meta"]["projects"]), policy=pol, db_url=pol_url, mode="demo", now=parse_world_time(w))

    async def go():
        try:
            await Scanner(src, cfg).run("s1")
        finally:
            await src.aclose()

    asyncio.run(go())
    scores = {}
    for name, u in (("off", off_url), ("policy", pol_url)):
        with session_scope(u) as s:
            scores[name] = {r.repo_key: (r.score, r.status) for r in store.repo_results(s, "s1")}
    assert scores["off"] == scores["policy"]
    with session_scope(on_url) as s:
        assert {r.repo_key: (r.score, r.status) for r in store.repo_results(s, "s1")} != scores["off"]  # Aikido findings did matter


def test_migration_off_skips_readiness_but_keeps_the_scan_otherwise(tmp_path):
    url, *_ = demo_scan(tmp_path, {**F.ALL_ON, "migration": False})
    with session_scope(url) as s:
        rows = store.repo_results(s, "s1")
        assert rows and all(r.migration_score is None and not r.migration_blockers and "migration" not in r.external for r in rows)
        assert store.get_scan(s, "s1").summary["features"]["migration"] is False
    url2, *_ = demo_scan(tmp_path / "x", None)
    with session_scope(url2) as s:
        assert any(r.migration_score is not None for r in store.repo_results(s, "s1"))


def test_live_sources_do_not_build_or_read_secrets_of_a_source_that_is_off():
    asked: list[str] = []

    class Provider:
        name = "spy"

        def get(self, name):
            asked.append(name)
            return "fake-value"

    s = Settings(_env_file=None, ado_org="o", sonar_url="https://sonar.example.com", aikido_client_id="id", servicenow_url="https://snow.example.com", servicenow_user="u")  # type: ignore[call-arg]
    src = live_sources(s, secrets=Provider())  # type: ignore[arg-type]
    assert src.sonar and src.aikido and src.snow and {"SONAR_TOKEN", "AIKIDO_CLIENT_SECRET", "SERVICENOW_PASSWORD"} <= set(asked)
    asked.clear()
    src = live_sources(s, secrets=Provider(), features={**F.ALL_ON, "source_sonar": False, "source_aikido": False, "source_servicenow": False})  # type: ignore[arg-type]
    assert (src.sonar, src.aikido, src.snow) == (None, None, None) and asked == ["ADO_PAT", "GITHUB_TOKEN"]
    assert isinstance(src, Sources)


# GitHub Actions: no Actions / Environments / Deployments call at all while the switch is off
@respx.mock
def test_gha_scanning_off_makes_no_actions_calls_and_skips_the_gha_rules(fx, fxt, tmp_path):
    from pch.collectors.ado.client import AdoClient
    from pch.collectors.github.client import GitHubClient
    from pch.settings import GitHubScope
    from tests.github_mock import API, PAT
    from tests.test_external_repos import NOW, mock_ado
    from tests.test_gha_scan import ORG, mock_github

    def scan_with(flags):
        db = f"sqlite:///{tmp_path}/{'on' if flags['gha_scanning'] else 'off'}.db"
        src = Sources(ado=AdoClient("contoso", "x", backoff_base=0, max_attempts=1), github=GitHubClient(API, token=PAT, backoff_base=0, max_attempts=1))
        scope = Scope(code_hosts=ALL_HOSTS, projects=["Payments"], github=GitHubScope(orgs=[ORG], exclude=["sandbox-*"]), env_tiers={"production": "prod"})
        cfg = ScanConfig(scope=scope, policy=Policy(), db_url=db, mode="demo", now=NOW, features=flags)

        async def go():
            try:
                await Scanner(src, cfg).run("g")
            finally:
                await src.aclose()

        asyncio.run(go())
        return db

    mock_ado(fx, fxt, items_calls=[])
    mock_github()
    on = scan_with(F.ALL_ON)
    def actions_calls():
        return [c for c in respx.calls if c.request.url.host == "api.github.com" and any(x in c.request.url.path for x in ("/actions/", "/environments", "/deployments"))]

    actions_on = actions_calls()
    assert actions_on  # the mocks are really reached when the switch is on
    before = len(respx.calls)
    off = scan_with({**F.ALL_ON, "gha_scanning": False})
    assert len(respx.calls) > before and not [c for c in list(respx.calls)[before:] if c in actions_calls()]
    assert any("/branches/" in c.request.url.path or "/rules/" in c.request.url.path for c in list(respx.calls)[before:])  # the rest of the GitHub reader still ran
    gha_rules = {"SUP-006", "SEC-006", "SEC-007", "SEC-008", "SEC-009"}
    with session_scope(on) as s:
        assert any(f.rule_id in gha_rules for f in store.findings(s, "g"))
        assert any("gha" in r.platform_mix for r in store.repo_results(s, "g"))
    with session_scope(off) as s:
        assert not any(f.rule_id in gha_rules for f in store.findings(s, "g"))
        assert not any("gha" in r.platform_mix for r in store.repo_results(s, "g"))
        assert not any(r.rule_status.keys() & gha_rules for r in store.repo_results(s, "g"))
        assert store.get_scan(s, "g").summary["features"]["gha_scanning"] is False
        from pch.model.lineage import RepoLineage

        assert not any(p.kind == "gha" for r in store.lineage_rows(s, "g") if r.kind == "repo" for p in RepoLineage.model_validate(r.doc).pipelines)  # lineage excludes GHA


# ------------------------------------------------------------------ CLI
def test_cli_features_list_set_reset_and_audit(db, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", db)
    monkeypatch.setenv("CONFIG_DIR", str(tmp_path))
    from pch.settings import reset_settings

    reset_settings()
    (tmp_path / "features.yaml").write_text("source_aikido: false\n")
    def listing():
        return {ln.split()[0]: ln for ln in runner.invoke(app, ["features", "list"]).output.splitlines()}

    out = listing()
    assert list(out) == list(F.KEYS) and "takes effect immediately" in out["migration"] and "takes effect next scan" in out["gha_scanning"]
    assert out["source_aikido"].split()[1] == "off" and "default from features.yaml" in out["source_aikido"] and out["migration"].split()[1] == "on"
    assert runner.invoke(app, ["features", "set", "source_aikido", "on"]).exit_code == 0
    assert listing()["source_aikido"].split()[1] == "on" and "changed by cli at" in listing()["source_aikido"]
    assert "no change" in runner.invoke(app, ["features", "set", "source_aikido", "on"]).output
    assert runner.invoke(app, ["features", "set", "source_aikido", "default"]).exit_code == 0
    assert listing()["source_aikido"].split()[1] == "off" and "default from features.yaml" in listing()["source_aikido"]
    assert runner.invoke(app, ["features", "set", "nope", "on"]).exit_code == 2
    assert runner.invoke(app, ["features", "set", "migration", "ON"]).exit_code == 2
    assert runner.invoke(app, ["features", "set", "migration", "true"]).exit_code == 2
    with session_scope(db) as s:
        rows = list(reversed(F.audit_entries(s)))
        assert [(r.old_value, r.new_value, r.source, r.actor_display_name) for r in rows] == [("default", "on", "cli", "cli"), ("on", "default", "cli", "cli")]
    (tmp_path / "features.yaml").write_text("bogus: true\n")
    assert runner.invoke(app, ["features", "list"]).exit_code == 2
    reset_settings()


def test_cli_scan_reads_db_overrides_at_start_and_snapshots_them(db, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", db)
    monkeypatch.setenv("CONFIG_DIR", str(tmp_path))
    from pch.settings import reset_settings

    reset_settings()
    d = tmp_path / "data"
    assert runner.invoke(app, ["seed-demo", "--data-dir", str(d), "--repos", "10"]).exit_code == 0
    assert runner.invoke(app, ["features", "set", "source_servicenow", "off"]).exit_code == 0
    r = runner.invoke(app, ["scan", "--demo", "--history", "0", "--data-dir", str(d)])
    assert r.exit_code == 0, r.output
    with session_scope(db) as s:
        sc = store.latest_scan(s)
        assert sc.summary["features"]["source_servicenow"] is False and sc.summary["features"]["migration"] is True
        assert "DEP-005" not in {f.rule_id for f in store.findings(s, sc.id)}
    reset_settings()


# ------------------------------------------------------------------ doctor
def test_doctor_shows_effective_features_and_their_source(db, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", db)
    monkeypatch.setenv("CONFIG_DIR", str(tmp_path))
    from pch.doctor import check_features
    from pch.settings import reset_settings

    reset_settings()
    (tmp_path / "features.yaml").write_text("source_sonar: false\n")
    with session_scope(db) as s:
        F.set_override(s, "gha_scanning", False, ALICE, "ui")
    c = check_features(Settings())
    assert c.status == "OK" and "migration=on (default from features.yaml)" in c.detail and "source_sonar=off (default from features.yaml)" in c.detail
    assert "gha_scanning=off (changed by Alice Admin at " in c.detail
    out = runner.invoke(app, ["doctor"]).output
    assert "features" in out and "gha_scanning=off" in out
    (tmp_path / "features.yaml").write_text("bogus: 1\n")
    assert check_features(Settings()).status == "FAIL"
    reset_settings()


# ------------------------------------------------------------------ persistence of the new tables
def test_feature_tables_exist_after_upgrade_and_downgrade_removes_only_them(tmp_path):
    reset_engines()
    eng = get_raw_engine(f"sqlite:///{tmp_path}/m.db")
    migrate.upgrade(eng)
    from sqlalchemy import inspect

    assert {"feature_flags", "feature_audit"} <= set(inspect(eng).get_table_names())
    with session_scope(f"sqlite:///{tmp_path}/m.db") as s:
        store.create_scan(s, "keep", "demo")
        F.set_override(s, "migration", False, ALICE, "ui")
    migrate.downgrade(eng, "0002")
    names = set(inspect(eng).get_table_names())
    assert not ({"feature_flags", "feature_audit"} & names) and {"scans", "lineage"} <= names
    migrate.upgrade(eng)
    with session_scope(f"sqlite:///{tmp_path}/m.db") as s:
        assert store.get_scan(s, "keep") is not None and F.audit_entries(s) == []
    reset_engines()


def test_deleting_or_pruning_a_scan_does_not_touch_flags_or_audit(db):
    with session_scope(db) as s:
        store.create_scan(s, "old", "demo")
        F.set_override(s, "migration", False, ALICE, "ui")
    with session_scope(db) as s:
        store.delete_scan(s, "old")
    with session_scope(db) as s:
        assert store.get_scan(s, "old") is None
        assert F.effective_flags(s, F.ALL_ON)["migration"] is False and len(s.query(FeatureAuditRow).all()) == 1
