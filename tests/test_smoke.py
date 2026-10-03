from typer.testing import CliRunner

from pch.cli import app
from pch.settings import load_policy, load_scope


def test_cli_version():
    res = CliRunner().invoke(app, ["version"])
    assert res.exit_code == 0
    assert "0.1.0" in res.output


def test_config_loads():
    assert load_policy("config/policy.yaml").coverage_threshold == 80
    assert load_scope("config/scope.yaml").organization == "contoso"
