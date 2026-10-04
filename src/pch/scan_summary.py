"""Markdown job summary of the latest scan (``pch scans summary``), written to ``$GITHUB_STEP_SUMMARY`` by the scheduled workflow.

Counts and short labels only: no URLs, no exception text, no secret values (collection-error *messages* are never printed,
only how many there are per source). Read-only: it never starts a scan or writes to any source.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from pch import exitcodes
from pch.store import repository as store

# What to do about each exit code (shown in the job summary next to the code's description).
HINTS: dict[int, str] = {
    exitcodes.OK: "The scan completed and its results are stored.",
    exitcodes.FAILED: "Generic failure: open the job log (secrets are masked there).",
    exitcodes.CONFIG: "Configuration error: check the repository variables and the `pch-scan` environment secrets (`pch doctor` output is in the job log).",
    exitcodes.SCHEMA_NOT_READY: "Database not ready: it must be reachable and migrated to head (`pch db upgrade`); for Azure SQL check the OIDC login and the database role.",
    exitcodes.LOCK_HELD: "Another scan or prune holds the scan lock. Usually harmless: the next scheduled run retries.",
    exitcodes.INTERRUPTED: "The scan was interrupted or exceeded `SCAN_TIMEOUT_MINUTES`; the scan row is marked `failed` and the lock released.",
}
STATUS_LABELS = (("COMPLIANT", "compliant"), ("AT_RISK", "at risk"), ("NON_COMPLIANT", "non-compliant"), ("NOT_SCANNED", "not scanned"))


def _md(text: str) -> str:
    """Keep table cells and lines inert: no pipes, no newlines, no HTML."""
    return text.replace("|", "/").replace("\n", " ").replace("<", "(").replace(">", ")")[:160]


def build(s: Session, exit_code: int | None = None, since: datetime | None = None) -> str:
    lines: list[str] = ["## Pipeline Compliance Hub: scheduled scan", ""]
    if exit_code is not None:
        verdict = "succeeded" if exit_code == exitcodes.OK else "did not complete"
        lines += [f"**Result:** {verdict} (exit code {exit_code}: {exitcodes.DESCRIPTIONS.get(exit_code, 'unknown')})", HINTS.get(exit_code, ""), ""]
    newest = next(iter(store.list_scans(s, 1)), None)
    if newest is None or (since is not None and newest.started_at < since):
        lines.append("No scan was recorded by this run.")
        return "\n".join(lines) + "\n"
    summary: dict[str, Any] = newest.summary or {}
    errors = store.collection_errors(s, newest.id)
    by_source = Counter(e.source for e in errors)
    lines += ["| | |", "|---|---|", f"| Scan | `{_md(newest.id)}` ({_md(newest.mode)}) |", f"| Status | {_md(newest.status)} |"]
    if newest.duration_s is not None:
        lines.append(f"| Duration | {newest.duration_s:g} s |")
    if newest.status == "complete":
        counts = summary.get("status_counts") or {}
        lines += [f"| Repos scanned | {newest.repos_total} ({newest.repos_failed} not scanned) |", f"| Findings | {newest.findings_total} |",
                  "| Status counts | " + ", ".join(f"{counts.get(k, 0)} {label}" for k, label in STATUS_LABELS) + " |"]
    elif summary.get("error"):
        lines.append(f"| Reason | {_md(str(summary['error']))} |")
    lines.append(f"| Collection errors | {len(errors)}" + (" (" + ", ".join(f"{_md(k)}: {v}" for k, v in sorted(by_source.items())) + ")" if by_source else "") + " |")
    if errors:
        lines += ["", "Collection errors mean some data could not be read; affected checks show UNKNOWN, never FAIL. Details: the dashboard, Scans page."]
    return "\n".join(lines) + "\n"
