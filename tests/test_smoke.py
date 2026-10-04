from typer.testing import CliRunner

from pch.cli import app
from pch.settings import load_policy, load_scope


def test_cli_version():
    res = CliRunner().invoke(app, ["version"])
    assert res.exit_code == 0
    assert "0.1.0" in res.output


def test_config_loads():
    assert load_policy("config/policy.yaml").coverage_threshold == 80
    assert load_scope("config/scope.yaml").organization == ""


def test_rules_list_shows_all():
    res = CliRunner().invoke(app, ["rules", "list"])
    assert res.exit_code == 0
    assert "61 rules" in res.output and "DEP-005" in res.output and "TGT-ADF-003" in res.output
    only = CliRunner().invoke(app, ["rules", "list", "--category", "dep", "--json"])
    assert only.exit_code == 0 and only.output.count('"id"') == 6
