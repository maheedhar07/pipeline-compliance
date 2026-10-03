"""Findings, evidence, severities, statuses and waivers."""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(StrEnum):
    PASS = "PASS"  # nosec B105 - enum label, not a password
    FAIL = "FAIL"
    WARN = "WARN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"
    WAIVED = "WAIVED"


class RepoStatus(StrEnum):
    COMPLIANT = "COMPLIANT"
    AT_RISK = "AT_RISK"
    NON_COMPLIANT = "NON_COMPLIANT"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class Evidence(BaseModel):
    """Free-form evidence dict plus an optional deep link."""

    data: dict[str, Any] = Field(default_factory=dict)
    link: str | None = None


class RuleResult(BaseModel):
    """What a rule function returns."""

    status: Status
    message: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    link: str | None = None

    @classmethod
    def passed(cls, message: str = "", **evidence: Any) -> RuleResult:
        return cls(status=Status.PASS, message=message, evidence=evidence)

    @classmethod
    def failed(cls, message: str = "", **evidence: Any) -> RuleResult:
        return cls(status=Status.FAIL, message=message, evidence=evidence)

    @classmethod
    def warn(cls, message: str = "", **evidence: Any) -> RuleResult:
        return cls(status=Status.WARN, message=message, evidence=evidence)

    @classmethod
    def na(cls, message: str = "", **evidence: Any) -> RuleResult:
        return cls(status=Status.NOT_APPLICABLE, message=message, evidence=evidence)

    @classmethod
    def unknown(cls, message: str = "", **evidence: Any) -> RuleResult:
        return cls(status=Status.UNKNOWN, message=message, evidence=evidence)


class WaiverInfo(BaseModel):
    reason: str = ""
    owner: str = ""
    expires: date | None = None
    expired: bool = False


class Finding(BaseModel):
    rule_id: str
    repo_key: str  # "Project/repo"
    category: str
    severity: Severity
    status: Status
    message: str = ""
    pipeline_id: str | None = None
    pipeline_name: str | None = None
    stage: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    link: str | None = None
    waiver: WaiverInfo | None = None
    original_status: Status | None = None  # set when waived (the status before the waiver)
