import asyncio
from pathlib import Path

from typer.testing import CliRunner

from pch.agent import tools
from pch.cli import app
from pch.collectors.github import GitHubAdapter, NotImplementedGitHubAdapter
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
    assert "53 rules" in runner.invoke(app, ["rules", "docs"]).output


def test_github_adapter_is_a_stub():
    adapter = NotImplementedGitHubAdapter()
    assert isinstance(adapter, GitHubAdapter)
    try:
        asyncio.run(adapter.list_workflows("o", "r"))
    except NotImplementedError as e:
        assert "M9" in str(e)
    else:
        raise AssertionError("expected NotImplementedError")


def test_agent_tools_interface(tmp_path):
    db = f"sqlite:///{tmp_path}/a.db"
    assert tools.list_findings(db) == [] and tools.get_repo(db, "P", "r") is None
    ex = tools.explain_rule("dep-001")
    assert ex and ex["severity"] == "critical" and tools.explain_rule("NOPE-1") is None
