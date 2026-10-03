"""Rule registry: the @rule decorator, rule metadata and applicability filters."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from pch.model.findings import RuleResult, Severity

Scope = Literal["repo", "pipeline", "stage"]

CATEGORY_NAMES = {
    "SRC": "Source and change control",
    "QLT": "Code quality and security",
    "TST": "Testing",
    "SUP": "Build integrity and supply chain",
    "SEC": "Secrets and identity",
    "DEP": "Deployment governance",
    "TGT": "Deployment targets",
    "HYG": "Hygiene",
}

RuleFn = Callable[..., RuleResult]


@dataclass
class RuleMeta:
    id: str
    title: str
    category: str
    severity: Severity
    scope: Scope
    rationale: str
    remediation: dict[str, str]
    fn: RuleFn
    platforms: frozenset[str] | None = None  # restrict to pipeline platforms
    targets: frozenset[str] | None = None  # restrict to deploy targets
    tiers: frozenset[str] | None = None  # restrict to environment tiers
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def category_name(self) -> str:
        return CATEGORY_NAMES.get(self.category, self.category)

    def remediation_for(self, platform: str | None) -> str:
        key = {"ado_classic_build": "classic", "ado_classic_release": "classic", "ado_yaml": "yaml", "gha": "gha"}.get(
            platform or "", "yaml"
        )
        return self.remediation.get(key) or self.remediation.get("any", "")


REGISTRY: dict[str, RuleMeta] = {}


def rule(
    id: str,
    title: str,
    severity: str | Severity,
    scope: Scope,
    rationale: str,
    remediation: dict[str, str] | None = None,
    platforms: set[str] | None = None,
    targets: set[str] | None = None,
    tiers: set[str] | None = None,
) -> Callable[[RuleFn], RuleFn]:
    """Register a deterministic rule. The category is the id prefix (SRC, QLT, ...)."""

    def deco(fn: RuleFn) -> RuleFn:
        if id in REGISTRY:
            raise ValueError(f"duplicate rule id {id}")
        REGISTRY[id] = RuleMeta(
            id=id,
            title=title,
            category=id.split("-")[0],
            severity=Severity(severity),
            scope=scope,
            rationale=rationale,
            remediation=remediation or {},
            fn=fn,
            platforms=frozenset(platforms) if platforms else None,
            targets=frozenset(targets) if targets else None,
            tiers=frozenset(tiers) if tiers else None,
        )
        return fn

    return deco


def load_rules() -> dict[str, RuleMeta]:
    """Import every module in pch.engine.rules so the decorators run."""
    import pch.engine.rules as pkg

    for m in pkgutil.iter_modules(pkg.__path__):
        importlib.import_module(f"{pkg.__name__}.{m.name}")
    return REGISTRY


def all_rules() -> list[RuleMeta]:
    load_rules()
    return sorted(REGISTRY.values(), key=lambda r: r.id)
