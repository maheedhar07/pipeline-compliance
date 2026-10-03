"""Typer CLI: pch scan | serve | rules list | seed-demo."""

from __future__ import annotations

import typer

app = typer.Typer(help="Pipeline Compliance Hub (report-only)", no_args_is_help=True)
rules_app = typer.Typer(help="Inspect the rule catalog", no_args_is_help=True)
app.add_typer(rules_app, name="rules")


@app.callback()
def main() -> None:
    """Pipeline Compliance Hub: report-only CI/CD compliance scoring."""


@app.command()
def version() -> None:
    """Print the version."""
    from pch import __version__

    typer.echo(__version__)


@rules_app.command("list")
def rules_list(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category prefix, e.g. DEP"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
) -> None:
    """List every registered rule."""
    import json

    from pch.engine.registry import all_rules

    rules = [r for r in all_rules() if not category or r.category == category.upper()]
    if json_out:
        typer.echo(json.dumps([{"id": r.id, "title": r.title, "severity": r.severity.value, "scope": r.scope, "category": r.category} for r in rules], indent=2))
        return
    typer.echo(f"{'ID':<13}{'SEVERITY':<10}{'SCOPE':<10}TITLE")
    for r in rules:
        typer.echo(f"{r.id:<13}{r.severity.value:<10}{r.scope:<10}{r.title}")
    typer.echo(f"\n{len(rules)} rules")
