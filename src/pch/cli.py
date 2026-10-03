"""Typer CLI: pch scan | serve | rules list | seed-demo."""

from __future__ import annotations

import typer

app = typer.Typer(help="Pipeline Compliance Hub (report-only)", no_args_is_help=True)


@app.callback()
def main() -> None:
    """Pipeline Compliance Hub."""


@app.command()
def version() -> None:
    """Print the version."""
    from pch import __version__

    typer.echo(__version__)
