from pathlib import Path

from typer.testing import CliRunner

from pch.agent import tools
from pch.cli import app
from pch.docs import render_rules_md
from pch.engine.registry import all_rules


def test_rules_md_is_up_to_date():
    path = Path(__file__).parent.parent / "docs" / "RULES.md"
    assert path.read_text() == render_rules_md(), "docs/RULES.md is stale: run `pch rules docs --write docs/RULES.md`"


def test_rules_md_covers_every_rule():
    text = render_rules_md()
    for r in all_rules():
        assert f"### {r.id}" in text and r.title in text


def test_rules_docs_cli(tmp_path):
    out = tmp_path / "RULES.md"
    runner = CliRunner()
    assert runner.invoke(app, ["rules", "docs", "--write", str(out)]).exit_code == 0
    assert runner.invoke(app, ["rules", "docs", "--write", str(out), "--check"]).exit_code == 0
    out.write_text("stale")
    assert runner.invoke(app, ["rules", "docs", "--write", str(out), "--check"]).exit_code == 1
    assert "61 rules" in runner.invoke(app, ["rules", "docs"]).output


def test_agent_tools_interface(tmp_path):
    db = f"sqlite:///{tmp_path}/a.db"
    assert tools.list_findings(db) == [] and tools.get_repo(db, "P", "r") is None
    ex = tools.explain_rule("dep-001")
    assert ex and ex["severity"] == "critical" and tools.explain_rule("NOPE-1") is None


# ----------------------------------------------------------------------------- docs cannot drift from the code
ROOT = Path(__file__).parent.parent


def test_every_settings_field_is_documented():
    from pch import config_reference as ref
    from pch.settings import Settings

    documented = ref.documented_fields()
    assert len(documented) == len(set(documented)), "a field is documented twice in config_reference.FIELD_DOCS"
    assert set(documented) == set(Settings.model_fields), (
        "add/remove the field in src/pch/config_reference.py: "
        f"missing={set(Settings.model_fields) - set(documented)} stale={set(documented) - set(Settings.model_fields)}"
    )


def test_readme_config_table_is_up_to_date():
    from pch import config_reference as ref

    assert ref.check_file(ROOT / "README.md"), "README config table is stale: run `pch config reference --write README.md`"


def test_env_example_mentions_every_setting():
    from pch.settings import Settings

    text = (ROOT / ".env.example").read_text()
    missing = [n.upper() for n in Settings.model_fields if n.upper() not in text]
    assert not missing, f".env.example does not mention: {missing}"


def test_config_reference_cli():
    out = CliRunner().invoke(app, ["config", "reference"])
    assert out.exit_code == 0 and "`APP_ENV`" in out.output and "`HTTP_MAX_RESPONSE_MB`" in out.output
    assert CliRunner().invoke(app, ["config", "reference", "--write", str(ROOT / "README.md"), "--check"]).exit_code == 0


def test_relative_links_in_markdown_docs_resolve():
    import re

    files = [ROOT / "README.md", ROOT / "CLAUDE.md", *sorted((ROOT / "docs").glob("*.md"))]
    bad = []
    for f in files:
        for target in re.findall(r"\]\(([^)\s#]+)(?:#[^)]*)?\)", f.read_text()):
            if re.match(r"[a-z]+:", target):
                continue
            if not (f.parent / target).exists():
                bad.append(f"{f.name} -> {target}")
    assert not bad, bad


def test_tests_cited_in_docs_exist():
    """`test_*` names quoted in the docs (threat model, security review, customizing) must be real tests."""
    import re

    defined = set()
    for f in (ROOT / "tests").glob("test_*.py"):
        defined |= set(re.findall(r"^(?:async )?def (test_\w+)", f.read_text(), re.M))
    missing = []
    for name in ("THREAT_MODEL.md", "SECURITY_REVIEW.md", "CUSTOMIZING.md", "IMPORT_CHECKLIST.md", "DEPLOY_AZURE.md"):
        for t in set(re.findall(r"`(?:[\w]+\.py)?(?:::)?(test_\w+)`", (ROOT / "docs" / name).read_text())):
            if t not in defined:
                missing.append(f"{name}: {t}")
    assert not missing, missing
