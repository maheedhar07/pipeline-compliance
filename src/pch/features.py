"""Feature switches (the Settings page): what is on or off, where the value came from, and the audited writes.

Defaults come from ``config/features.yaml`` (strict, every key optional, default ``true``). An override set in the UI or with
``pch features set`` is stored in the app's own database (``feature_flags``) and wins over the file; every change is appended to
``feature_audit``. This module never talks to any upstream system.

* ``migration``: display feature. Takes effect immediately (pages read the effective value on every request); a scan also skips the readiness
  computation while it is off.
* ``gha_scanning`` and ``source_*``: scan features. A scan reads the effective values when it starts and snapshots them into
  ``scans.summary["features"]``; pages for older scans keep using that snapshot.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictBool, ValidationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from pch.settings import ConfigError, _load_yaml, format_validation_error
from pch.store.models import FeatureAuditRow, FeatureFlagRow
from pch.timeutil import utcnow

Timing = Literal["immediate", "next_scan"]
Via = Literal["ui", "cli"]


@dataclass(frozen=True)
class FeatureDef:
    key: str
    label: str
    description: str
    timing: Timing


FEATURES: tuple[FeatureDef, ...] = (
    FeatureDef("migration", "Azure DevOps to GitHub Actions migration",
               "Migration tab, overview donut, readiness and \"candidate to retire\" hints on repo pages, the repos filter, the API and the exports. "
               "Off: hidden everywhere (the migration API answers 404) and scans skip the readiness computation.", "immediate"),
    FeatureDef("gha_scanning", "GitHub Actions scanning",
               "Read workflows, environments and deployments through the GitHub Actions API and evaluate the GitHub-Actions-only rules (SUP-006, SEC-006 to SEC-009). "
               "Off: no Actions, Environments or Deployments calls, no workflows in the lineage.", "next_scan"),
    FeatureDef("source_sonar", "SonarQube", "Query SonarQube. Off: the client is not built even if credentials are configured; QLT-003, QLT-004 and QLT-005 are not evaluated.", "next_scan"),
    FeatureDef("source_aikido", "Aikido", "Query Aikido. Off: the client is not built even if credentials are configured; QLT-006 and QLT-007 are not evaluated.", "next_scan"),
    FeatureDef("source_servicenow", "ServiceNow", "Query ServiceNow. Off: the client is not built even if credentials are configured; DEP-005 is not evaluated.", "next_scan"),
)
KEYS: tuple[str, ...] = tuple(f.key for f in FEATURES)
BY_KEY: dict[str, FeatureDef] = {f.key: f for f in FEATURES}
ALL_ON: dict[str, bool] = dict.fromkeys(KEYS, True)

# Rule metadata (``@rule(..., requires_sources={...})``) names a source; the switch that controls it is:
SOURCE_FEATURE: dict[str, str] = {"sonar": "source_sonar", "aikido": "source_aikido", "servicenow": "source_servicenow", "gha": "gha_scanning"}
VALUES = ("on", "off")


class FeaturesFile(BaseModel):
    """``config/features.yaml``: unknown keys are errors (a typo must not silently leave a feature on)."""

    model_config = ConfigDict(extra="forbid")
    migration: StrictBool = True
    gha_scanning: StrictBool = True
    source_sonar: StrictBool = True
    source_aikido: StrictBool = True
    source_servicenow: StrictBool = True


def load_feature_defaults(path: Path | str | None) -> dict[str, bool]:
    """Defaults from the file; a missing file (or ``None``) means everything on."""
    if path is None:
        return dict(ALL_ON)
    p = Path(path)
    try:
        return FeaturesFile.model_validate(_load_yaml(p)).model_dump()
    except ValidationError as exc:
        raise ConfigError(format_validation_error(str(p), exc)) from None


@dataclass(frozen=True)
class FeatureState:
    key: str
    label: str
    description: str
    timing: Timing
    enabled: bool
    default: bool
    overridden: bool
    updated_by: str = ""
    updated_at: datetime | None = None

    @property
    def source_text(self) -> str:
        if not self.overridden:
            return "default from features.yaml"
        who = f"changed by {self.updated_by or 'an administrator'}"
        return f"{who} at {self.updated_at:%Y-%m-%d %H:%M} UTC" if self.updated_at else who


@dataclass(frozen=True)
class Actor:
    """Who made a change. Only a hash of the id and a PII-free display name are ever stored."""

    id: str
    name: str

    @property
    def id_hash(self) -> str:
        return hashlib.sha256(self.id.encode()).hexdigest()

    @property
    def display(self) -> str:
        return clean_display_name(self.name)


CLI_ACTOR = Actor("cli", "cli")
_CTRL = re.compile(r"[\x00-\x1f\x7f  ]")


def clean_display_name(name: str | None) -> str:
    """Display name only: control characters removed, capped; a value that looks like an e-mail / UPN is dropped (same PII rule as the lineage)."""
    v = _CTRL.sub("", str(name or "")).strip()
    return "" if "@" in v else v[:100]


def _overrides(s: Session) -> dict[str, FeatureFlagRow]:
    return {r.feature_key: r for r in s.scalars(select(FeatureFlagRow)) if r.feature_key in BY_KEY}


def effective_states(s: Session, defaults: Mapping[str, bool]) -> list[FeatureState]:
    over = _overrides(s)
    out: list[FeatureState] = []
    for f in FEATURES:
        d = bool(defaults.get(f.key, True))
        row = over.get(f.key)
        out.append(FeatureState(f.key, f.label, f.description, f.timing, row.enabled if row else d, d, row is not None,
                                row.updated_by if row else "", row.updated_at if row else None))
    return out


def effective_flags(s: Session, defaults: Mapping[str, bool]) -> dict[str, bool]:
    return {st.key: st.enabled for st in effective_states(s, defaults)}


def _state_word(v: bool | None) -> str:
    return "default" if v is None else "on" if v else "off"


def set_override(s: Session, key: str, value: bool | None, actor: Actor, via: Via) -> bool:
    """Set (``True``/``False``) or clear (``None``: back to the file default) one override and append an audit row, in the caller's transaction.
    Returns False (and writes nothing) when the stored state is already what was asked."""
    if key not in BY_KEY:
        raise KeyError(key)
    row = s.get(FeatureFlagRow, key)
    old = row.enabled if row else None
    if old == value:
        return False
    now = utcnow()
    if value is None:
        s.execute(delete(FeatureFlagRow).where(FeatureFlagRow.feature_key == key))
    elif row is None:
        s.add(FeatureFlagRow(feature_key=key, enabled=value, updated_by=actor.display, updated_at=now))
    else:
        row.enabled, row.updated_by, row.updated_at = value, actor.display, now
    s.add(FeatureAuditRow(feature_key=key, old_value=_state_word(old), new_value=_state_word(value), actor_id_hash=actor.id_hash,
                          actor_display_name=actor.display, at=now, source=via))
    s.flush()
    return True


def audit_entries(s: Session, limit: int = 20) -> list[FeatureAuditRow]:
    return list(s.scalars(select(FeatureAuditRow).order_by(FeatureAuditRow.id.desc()).limit(limit)))


def feature_off_for_rule(requires_sources: frozenset[str], flags: Mapping[str, bool]) -> list[str]:
    """The switches (keys) that currently turn a rule off, given a flag set."""
    return [SOURCE_FEATURE[x] for x in sorted(requires_sources) if x in SOURCE_FEATURE and not flags.get(SOURCE_FEATURE[x], True)]
