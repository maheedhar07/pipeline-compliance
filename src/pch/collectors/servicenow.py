"""ServiceNow collector (read-only Table API on change_request)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from pch.collectors.http import SourceClient
from pch.model.repo import ChangeRequest

FIELDS = "number,state,approval,start_date,end_date,cmdb_ci,short_description"
VALID_APPROVAL = {"approved"}
VALID_STATES = {"implement", "approved", "scheduled", "review", "closed"}
INVALID_STATES = {"canceled", "cancelled", "rejected"}


def parse_snow_dt(v: str | None) -> datetime | None:
    if not v:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue
    return None


def _display(v: Any) -> str | None:
    if isinstance(v, dict):
        return v.get("display_value") or v.get("value")
    return v or None


def to_change(raw: dict[str, Any]) -> ChangeRequest:
    return ChangeRequest(
        number=_display(raw.get("number")) or "",
        state=(_display(raw.get("state")) or ""),
        approval=(_display(raw.get("approval")) or ""),
        start_date=parse_snow_dt(_display(raw.get("start_date"))),
        end_date=parse_snow_dt(_display(raw.get("end_date"))),
        ci=_display(raw.get("cmdb_ci")),
        short_description=_display(raw.get("short_description")) or "",
    )


def change_is_valid(cr: ChangeRequest) -> bool:
    """Approved (or in an implement-capable state) and not cancelled/rejected."""
    if cr.state.lower() in INVALID_STATES or cr.approval.lower() == "rejected":
        return False
    return cr.approval.lower() in VALID_APPROVAL or cr.state.lower() in VALID_STATES


def window_covers(cr: ChangeRequest, when: datetime, slack_hours: int = 2) -> bool:
    if cr.start_date is None or cr.end_date is None:
        return False
    slack = timedelta(hours=slack_hours)
    return cr.start_date - slack <= when <= cr.end_date + slack


class ServiceNowClient:
    def __init__(self, base_url: str, user: str = "", password: str = "", *,  # nosec B107 - empty default means 'not configured'; real values come from env
                 transport: httpx.AsyncBaseTransport | None = None, concurrency: int = 8,
                 backoff_base: float = 0.5, max_attempts: int = 4):
        self.base_url = base_url.rstrip("/")
        self.http = SourceClient(self.base_url, transport=transport, auth=(user, password) if user else None,
                                 headers={"Accept": "application/json"}, concurrency=concurrency,
                                 backoff_base=backoff_base, max_attempts=max_attempts)

    async def aclose(self) -> None:
        await self.http.aclose()

    async def _query(self, query: str, limit: int = 500) -> list[ChangeRequest]:
        data = await self.http.get_json(
            "/api/now/table/change_request",
            {"sysparm_query": query, "sysparm_fields": FIELDS, "sysparm_display_value": "true", "sysparm_limit": limit},
        )
        return [to_change(r) for r in (data or {}).get("result", [])]

    async def by_numbers(self, numbers: list[str]) -> dict[str, ChangeRequest]:
        if not numbers:
            return {}
        out: dict[str, ChangeRequest] = {}
        for i in range(0, len(numbers), 50):
            for cr in await self._query("numberIN" + ",".join(numbers[i : i + 50])):
                out[cr.number.upper()] = cr
        return out

    async def by_ci(self, ci: str, since: datetime) -> list[ChangeRequest]:
        s = since.replace(tzinfo=UTC).strftime("%Y-%m-%d %H:%M:%S")
        return await self._query(f"cmdb_ci.nameLIKE{ci}^end_date>={s}^ORDERBYstart_date")
