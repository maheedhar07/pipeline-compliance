import json
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from pch.cli import app
from pch.settings import ConfigError, Policy, Settings, get_settings, load_policy, load_scope, reset_settings

REPO = Path(__file__).resolve().parent.parent
SECRETS = {"ADO_PAT": "pat-S3CRET-1", "SONAR_TOKEN": "sonar-S3CRET-2", "AIKIDO_CLIENT_SECRET": "aik-S3CRET-3", "SERVICENOW_PASSWORD": "snow-S3CRET-4"}
ALL_ENV = ["APP_ENV", "DATABASE_URL", "DATA_DIR", "CONFIG_DIR", "ADO_ORG", "SONAR_URL", "AIKIDO_CLIENT_ID", "SERVICENOW_URL", "SERVICENOW_USER", "CONCURRENCY", "HTTP_TIMEOUT", "PORT", *SECRETS]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for k in ALL_ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.chdir(tmp_path)  # no stray .env
    reset_settings()
    yield
    reset_settings()


def run(*args):
    return CliRunner().invoke(app, ["doctor", *args])


# ------------------------------------------------------------------ settings
def test_app_env_default_and_helpers(monkeypatch):
    s = Settings()
    assert s.app_env == "dev" and s.is_dev and not s.is_prod and s.host == "127.0.0.1"
    monkeypatch.setenv("APP_ENV", "prod")
    assert Settings().is_prod and Settings().host == "127.0.0.1"
    monkeypatch.setenv("APP_ENV", "staging")
    with pytest.raises(ValidationError):
        Settings()


def test_get_settings_cache_reset(monkeypatch):
    assert get_settings() is get_settings()
    monkeypatch.setenv("APP_ENV", "test")
    assert get_settings().app_env == "dev"
    reset_settings()
    assert get_settings().app_env == "test"


def test_secrets_never_in_repr_or_dump(monkeypatch):
    for k, v in SECRETS.items():
        monkeypatch.setenv(k, v)
    s = Settings()
    blob = repr(s) + str(s) + json.dumps(s.model_dump(mode="json")) + str(s.model_dump())
    for v in SECRETS.values():
        assert v not in blob
    assert s.ado_pat.get_secret_value() == SECRETS["ADO_PAT"]


@pytest.mark.parametrize("env,val", [("CONCURRENCY", "0"), ("CONCURRENCY", "65"), ("HTTP_TIMEOUT", "0"), ("HTTP_TIMEOUT", "301"), ("PORT", "0"),
                                     ("SONAR_URL", "ftp://x"), ("SONAR_URL", "sonar.example.com"), ("ADO_BASE_URL", "https://x/?a=1")])
def test_bounds_and_urls_rejected(monkeypatch, env, val):
    monkeypatch.setenv(env, val)
    with pytest.raises(ValidationError):
        Settings()


def test_url_trailing_slash_normalised(monkeypatch):
    monkeypatch.setenv("SONAR_URL", "https://sonar.example.com/")
    assert Settings().sonar_url == "https://sonar.example.com"


# ------------------------------------------------------------------ yaml
def test_repo_configs_and_defaults_validate():
    assert load_scope(REPO / "config" / "scope.yaml").organization
    assert load_policy(REPO / "config" / "policy.yaml").coverage_threshold == 80
    assert Policy().sonar_quality_gate_name == "Sonar way"


def test_unknown_key_names_file_and_path(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_text("coverage_treshold: 70\n")
    with pytest.raises(ConfigError, match=r"policy\.yaml: coverage_treshold: "):
        load_policy(f)


def test_waiver_date_path(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_text("waivers:\n  - {rule: SRC-004, repo: A/b, expires: not-a-date}\n")
    with pytest.raises(ConfigError, match=r"policy\.yaml: waivers\.0\.expires: "):
        load_policy(f)
    f.write_text("waivers:\n  - {rule: SRC-004, repo: A/b, expires: 2027-03-31}\n")
    assert load_policy(f).waivers[0].expires == date(2027, 3, 31)


def test_nested_and_scope_errors(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("aikido_sla_days: {critical: 7, urgent: 1}\n")
    with pytest.raises(ConfigError, match=r"aikido_sla_days\.urgent"):
        load_policy(f)
    s = tmp_path / "s.yaml"
    s.write_text("repos:\n  - {project: P}\n")
    with pytest.raises(ConfigError, match=r"s\.yaml: repos\.0\.repo: "):
        load_scope(s)
    s.write_text("- just\n- a list\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_scope(s)
    s.write_text("a: [unclosed\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_scope(s)


def test_missing_files_defaults_in_dev_error_in_prod(tmp_path, monkeypatch):
    missing = tmp_path / "nope.yaml"
    assert load_scope(missing).projects == [] and load_policy(missing).min_reviewers == 2
    monkeypatch.setenv("APP_ENV", "prod")
    reset_settings()
    with pytest.raises(ConfigError, match="nope.yaml: file not found"):
        load_scope(missing)
    assert load_policy(missing).min_reviewers == 2


def test_demo_generated_config_validates(tmp_path):
    r = CliRunner().invoke(app, ["seed-demo", "--repos", "40", "--data-dir", str(tmp_path)])
    assert r.exit_code == 0, r.output
    d = tmp_path / "demo"
    assert load_scope(d / "scope.yaml").projects
    assert load_policy(d / "policy.yaml").waivers


# ------------------------------------------------------------------ doctor
def test_doctor_pass(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "d"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/x.db")
    for k, v in SECRETS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("ADO_ORG", "o")
    monkeypatch.setenv("SONAR_URL", "https://sonar.example.com")
    monkeypatch.setenv("AIKIDO_CLIENT_ID", "cid")
    monkeypatch.setenv("SERVICENOW_URL", "https://x.service-now.com")
    monkeypatch.setenv("SERVICENOW_USER", "u")
    sc, po = tmp_path / "s.yaml", tmp_path / "p.yaml"
    sc.write_text("organization: o\n")
    po.write_text("coverage_threshold: 70\n")
    res = run("--scope", str(sc), "--policy", str(po))
    assert res.exit_code == 0, res.output
    assert "FAIL" not in res.output and "ADO_PAT=set" in res.output
    for v in SECRETS.values():
        assert v not in res.output
    js = json.loads(run("--json", "--scope", str(sc), "--policy", str(po)).output)
    assert js["ok"] is True and {c["name"] for c in js["checks"]} >= {"settings", "scope.yaml", "policy.yaml", "database", "data_dir", "source:ado"}


def test_doctor_fail_cases_and_no_secret_leak(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "d"))
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:hunter2pw@127.0.0.1:1/db")
    monkeypatch.setenv("ADO_PAT", SECRETS["ADO_PAT"])  # org missing -> partial source
    sc, po = tmp_path / "s.yaml", tmp_path / "p.yaml"
    sc.write_text("organisation: typo\n")
    po.write_text("waivers:\n  - {rule: X, repo: A/b, expires: nope}\n")
    res = run("--scope", str(sc), "--policy", str(po))
    assert res.exit_code == 1
    assert "ADO_ORG=missing" in res.output and "ADO_PAT=set" in res.output
    assert "waivers.0.expires" in res.output and "organisation" in res.output
    assert SECRETS["ADO_PAT"] not in res.output and "hunter2pw" not in res.output
    js = json.loads(run("--json", "--scope", str(sc), "--policy", str(po)).output)
    assert js["ok"] is False and {c["name"] for c in js["checks"] if c["status"] == "FAIL"} >= {"scope.yaml", "policy.yaml", "source:ado", "database"}


def test_doctor_invalid_settings_and_prod_missing_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("CONCURRENCY", "999")
    res = run()
    assert res.exit_code == 1 and "settings" in res.output and "concurrency" in res.output
    monkeypatch.setenv("CONCURRENCY", "4")
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "d"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/x.db")
    res = run("--scope", str(tmp_path / "missing.yaml"))
    assert res.exit_code == 1 and "file not found" in res.output


def test_doctor_data_dir_not_writable(tmp_path, monkeypatch):
    f = tmp_path / "afile"
    f.write_text("x")
    monkeypatch.setenv("DATA_DIR", str(f / "sub"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/x.db")
    res = run()
    assert res.exit_code == 1 and "data_dir" in res.output
    assert Path(f).is_file()
