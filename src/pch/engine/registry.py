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

# Rules whose verdict depends on the CONTENT of pipelines (steps, capabilities): when a pipeline calls a reusable workflow that could not be
# read, or a pipeline source of the repo was unreadable, their FAIL becomes UNKNOWN (the missing steps might satisfy them). ADR-17.
CONTENT_RULES = frozenset({"QLT-001", "QLT-002", "TST-004", "TST-005", "TST-006", "SUP-001", "SUP-005", "DEP-003", "DEP-004"})
CONTENT_PREFIXES = ("TGT-",)


def is_content_rule(rule_id: str) -> bool:
    return rule_id in CONTENT_RULES or rule_id.startswith(CONTENT_PREFIXES)


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
    params: dict[str, Any] = field(default_factory=dict)  # tunable knobs and their defaults (policy.yaml rules.<ID>.params)
    requires_sources: frozenset[str] = frozenset()  # sources the verdict depends on (sonar, aikido, servicenow, gha): the Settings switch of each one off => not evaluated
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
    params: dict[str, Any] | None = None,
    requires_sources: set[str] | None = None,
) -> Callable[[RuleFn], RuleFn]:
    """Register a deterministic rule. The category is the id prefix (SRC, QLT, ...).

    ``params`` declares the rule's tunable knobs with their defaults; an org overrides them in ``policy.yaml``
    (``rules: {ID: {params: {...}}}``) and the rule reads the merged values with ``rule_params(policy, id)``.

    ``requires_sources`` names the sources the verdict rests on (``sonar``, ``aikido``, ``servicenow``, ``gha``; see ``pch.features.SOURCE_FEATURE``).
    When the matching switch on the Settings page is off the rule is not evaluated and not scored, like a rule disabled by policy."""

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
            params=dict(params or {}),
            requires_sources=frozenset(requires_sources or ()),
        )
        return fn

    return deco


def rule_params(policy: Any, rule_id: str) -> dict[str, Any]:
    """The rule's params: registry defaults overridden by ``policy.rules[rule_id].params`` (validated at load time)."""
    load_rules()
    meta = REGISTRY[rule_id]
    ov = policy.rules.get(rule_id)
    return {**meta.params, **(ov.params if ov else {})}


def load_rules() -> dict[str, RuleMeta]:
    """Import every module in pch.engine.rules so the decorators run."""
    import pch.engine.rules as pkg

    for m in pkgutil.iter_modules(pkg.__path__):
        importlib.import_module(f"{pkg.__name__}.{m.name}")
    return REGISTRY


def all_rules() -> list[RuleMeta]:
    load_rules()
    return sorted(REGISTRY.values(), key=lambda r: r.id)
