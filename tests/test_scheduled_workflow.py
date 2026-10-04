"""The scheduled-scan workflow is opt-in, least-privilege, pinned and never interpolates secrets into shell."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
WF = ROOT / ".github" / "workflows" / "scheduled-scan.yml"
SHA = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def load() -> dict:
    return yaml.safe_load(WF.read_text())


def triggers(doc: dict) -> dict:
    return doc.get("on") or doc[True]  # PyYAML (YAML 1.1) reads the key `on` as boolean True


def all_steps(doc: dict):
    for job in doc["jobs"].values():
        yield from job["steps"]


def test_triggers_schedule_and_manual_only():
    t = triggers(load())
    assert set(t) == {"schedule", "workflow_dispatch"}  # never pull_request / pull_request_target / push
    assert re.fullmatch(r"[\d*/,-]+ [\d*/,-]+ [\d*/,-]+ [\d*/,-]+ [\d*/,A-Za-z,-]+", t["schedule"][0]["cron"])
    assert "prune" in t["workflow_dispatch"]["inputs"]
    assert "pull_request_target" not in WF.read_text().replace("pull_request_target` ", "")  # also not mentioned as a trigger


def test_opt_in_condition_on_every_job():
    doc = load()
    for job in doc["jobs"].values():
        assert "vars.PCH_SCAN_ENABLED == 'true'" in job["if"]


def test_permissions_are_minimal():
    doc = load()
    assert doc["permissions"] == {}
    job = doc["jobs"]["scan"]
    assert job["permissions"] == {"contents": "read", "id-token": "write"}
    assert job["environment"] == "pch-scan"  # secrets come from an environment the org can protect


def test_concurrency_and_timeout():
    doc = load()
    assert doc["concurrency"]["group"] and doc["concurrency"]["cancel-in-progress"] is False  # never kill a running scan
    job = doc["jobs"]["scan"]
    assert job["runs-on"] == "ubuntu-24.04"
    from pch.settings import Settings

    assert job["timeout-minutes"] > Settings.model_fields["scan_timeout_minutes"].default  # slightly above SCAN_TIMEOUT_MINUTES


def test_every_action_is_pinned_to_a_full_sha():
    uses = [s["uses"] for s in all_steps(load()) if "uses" in s]
    assert len(uses) >= 3
    for u in uses:
        assert SHA.match(u), u
    # the same pins as ci.yml where the action is shared
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    for u in uses:
        if u.startswith(("actions/checkout", "actions/setup-python")):
            assert u in ci


def test_no_expression_interpolation_in_run_scripts():
    for s in all_steps(load()):
        if "run" in s:
            assert "${{" not in s["run"], f"step {s.get('name')!r}: pass values through env:, never ${{{{ }}}} in run:"
            assert "set -x" not in s["run"] and "echo $" not in s["run"]


def test_secrets_only_through_env_and_never_echoed():
    doc = load()
    text = WF.read_text()
    assert "secrets." in text
    for s in all_steps(doc):
        for k, v in (s.get("env") or {}).items():
            if "secrets." in str(v):
                assert k.isupper()
        assert "secrets." not in str(s.get("with", ""))  # OIDC login takes ids (variables), not secrets
        assert "secrets." not in s.get("run", "")
    assert "GITHUB_TOKEN" in text and "secrets.GITHUB_TOKEN" not in text  # the workflow's own token is never the scan credential
    for line in text.splitlines():
        assert not re.search(r"\becho\b.*\$\{?(ADO_PAT|GITHUB_TOKEN|DATABASE_URL|SONAR_TOKEN|AIKIDO_CLIENT_SECRET|SERVICENOW_PASSWORD)", line)


def test_install_from_hash_checked_lockfile_then_scan_flow():
    runs = "\n".join(s.get("run", "") for s in all_steps(load()))
    assert "pip install --require-hashes -r" in runs and "pip install --no-deps ." in runs
    order = [runs.index(x) for x in ("pch doctor", "pch db check", "pch scan", "pch scans summary", "pch scans prune")]
    assert order == sorted(order)
    assert "azure/login@" in WF.read_text() and "vars.AZURE_CLIENT_ID" in WF.read_text()


def test_scheduled_workflow_vars_are_allowed_names():
    """GitHub rejects variable / secret names that start with GITHUB_."""
    text = WF.read_text()
    assert not re.search(r"(vars|secrets)\.GITHUB_", text)
