"""Process exit codes of the ``pch`` CLI (one place; documented in the README, "Operations")."""

from __future__ import annotations

OK = 0
FAILED = 1  # generic failure: demo data missing, `db check` not at head, `rules docs --check` stale, prune had errors
CONFIG = 2  # invalid / missing configuration (settings, YAML files, provider extra missing, unsafe serve config)
SCHEMA_NOT_READY = 3  # database unusable: not migrated to head, unreachable, driver / extra missing
LOCK_HELD = 4  # another scan (or prune) holds the scan lock
INTERRUPTED = 5  # scan stopped by SIGTERM/SIGINT or exceeded SCAN_TIMEOUT_MINUTES (marked `failed`, lock released)

DESCRIPTIONS: dict[int, str] = {
    OK: "ok",
    FAILED: "generic failure",
    CONFIG: "configuration error",
    SCHEMA_NOT_READY: "database not ready (not at migration head / unreachable)",
    LOCK_HELD: "scan lock held by another run",
    INTERRUPTED: "interrupted (SIGTERM/SIGINT) or timed out",
}
