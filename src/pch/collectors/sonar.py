"""SonarQube collector (read-only): quality gate, measures, last analysis, gate assignment."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from pch.collectors.http import HttpError, SourceClient
from pch.model.repo import SonarFacts

METRICS = "coverage,new_coverage,bugs,vulnerabilities,security_hotspots,code_smells,duplicated_lines_density"


def parse_sonar_date(v: str | None) -> datetime | None:
    if not v:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
        try:
            return datetime.strptime(v, fmt).astimezone(UTC).replace(tzinfo=None)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _num(v: Any, cast=float):
    try:
        return cast(v) if v is not None else None
    except (TypeError, ValueError):
        return None


class SonarClient:
    def __init__(self, base_url: str, token: str = "", *, transport: httpx.AsyncBaseTransport | None = None,  # nosec B107 - empty default means 'not configured'; real values come from env
                 concurrency: int = 8, backoff_base: float = 0.5, max_attempts: int = 4):
        self.base_url = base_url.rstrip("/")
        self.http = SourceClient(self.base_url, transport=transport, auth=(token, "") if token else None,
                                 concurrency=concurrency, backoff_base=backoff_base, max_attempts=max_attempts)

    async def aclose(self) -> None:
        await self.http.aclose()

    async def project_facts(self, key: str) -> SonarFacts:
        """Collect everything for one project key. A 404 on project_status means 'not onboarded'."""
        facts = SonarFacts(key=key, url=f"{self.base_url}/dashboard?id={key}")
        try:
            status = await self.http.get_json("/api/qualitygates/project_status", {"projectKey": key})
        except HttpError as e:
            if e.status in (403, 404):
                return facts
            raise
        facts.onboarded = True
        facts.gate_status = (status.get("projectStatus") or {}).get("status")
        try:
            m = await self.http.get_json("/api/measures/component", {"component": key, "metricKeys": METRICS})
            measures = {x["metric"]: x.get("value") if "value" in x else (x.get("period") or {}).get("value")
                        for x in (m.get("component") or {}).get("measures", [])}
            facts.coverage = _num(measures.get("coverage"))
            facts.new_coverage = _num(measures.get("new_coverage"))
            facts.bugs = _num(measures.get("bugs"), int)
            facts.vulnerabilities = _num(measures.get("vulnerabilities"), int)
            facts.hotspots = _num(measures.get("security_hotspots"), int)
            facts.code_smells = _num(measures.get("code_smells"), int)
            facts.duplication = _num(measures.get("duplicated_lines_density"))
        except HttpError as e:
            if e.status not in (403, 404):
                raise
        try:
            an = await self.http.get_json("/api/project_analyses/search", {"project": key, "ps": 1})
            analyses = an.get("analyses", [])
            facts.last_analysis = parse_sonar_date(analyses[0]["date"]) if analyses else None
        except HttpError as e:
            if e.status not in (403, 404):
                raise
        try:
            qg = await self.http.get_json("/api/qualitygates/get_by_project", {"project": key})
            facts.gate_name = (qg.get("qualityGate") or {}).get("name")
        except HttpError as e:
            if e.status not in (403, 404):
                raise
        return facts

    async def first_found(self, keys: list[str]) -> SonarFacts:
        """Try candidate keys in order; return the first onboarded project (or the first miss)."""
        miss: SonarFacts | None = None
        for k in keys:
            f = await self.project_facts(k)
            if f.onboarded:
                return f
            miss = miss or f
        return miss or SonarFacts()
