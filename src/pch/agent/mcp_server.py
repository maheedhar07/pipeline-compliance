"""MCP server placeholder (M10, not implemented in v1).

Planned tools: list_findings, get_repo, explain_rule (see pch.agent.tools). The agent layer is
read-only and explanatory; it must never change a compliance decision.
"""

from __future__ import annotations


def serve() -> None:  # pragma: no cover - interface stub
    raise NotImplementedError("The MCP agent server is a Phase 4 (M10) deliverable; see pch.agent.tools for the tool surface.")
