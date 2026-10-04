"""Shared table mechanics for the list pages: pagination, sorting helpers and active-filter chips.

Everything is server side and GET only; the page, sort and filter state lives in the query string (links, not scripts), so a
table works without JavaScript. Exports ignore ``page`` / ``per_page`` (they honour filters only).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import Query
from pydantic import AfterValidator

PAGE_SIZES = (25, 50, 100, 200)
DEFAULT_PER_PAGE = 50
MAX_PAGE = 100_000


def _per_page(v: int) -> int:
    if v not in PAGE_SIZES:
        raise ValueError(f"must be one of {', '.join(map(str, PAGE_SIZES))}")
    return v


# Query-parameter types (bad values -> 400 on pages / 422 on the API, never 500)
PerPage = Annotated[int, Query(ge=1, le=200), AfterValidator(_per_page)]
PageNo = Annotated[int, Query(ge=1, le=MAX_PAGE)]


@dataclass
class Page:
    total: int
    page: int
    per_page: int
    pages: int
    start: int  # 1-based index of the first row shown (0 when empty)
    end: int
    items: list[Any]

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.pages

    def window(self, span: int = 2) -> list[int | None]:
        """Page numbers to link: first, last and ``span`` around the current page; ``None`` marks a gap."""
        want = sorted({1, self.pages, *range(max(1, self.page - span), min(self.pages, self.page + span) + 1)})
        out: list[int | None] = []
        prev = 0
        for n in want:
            if n - prev > 1:
                out.append(None)
            out.append(n)
            prev = n
        return out


def make_page(items: Sequence[Any], total: int, page: int, per_page: int) -> Page:
    pages = max(1, -(-total // per_page))
    page = min(page, pages)  # an out-of-range page shows the last one (a shared link keeps working after the data shrinks)
    start = (page - 1) * per_page
    return Page(total, page, per_page, pages, start + 1 if total else 0, min(total, start + per_page), list(items))


def slice_page(items: Sequence[Any], page: int, per_page: int) -> Page:
    """Paginate an in-memory list (sorted and filtered already)."""
    pages = max(1, -(-len(items) // per_page))
    page = min(page, pages)
    start = (page - 1) * per_page
    return make_page(items[start : start + per_page], len(items), page, per_page)


def sort_rows(rows: list[Any], key: Callable[[Any], Any], direction: str, tiebreak: Callable[[Any], Any]) -> list[Any]:
    """Stable sort where missing values (``None`` from ``key``) always come last, in both directions."""
    present = [r for r in rows if key(r) is not None]
    missing = [r for r in rows if key(r) is None]
    present.sort(key=tiebreak)
    present.sort(key=key, reverse=direction == "desc")
    return present + missing


def text_key(v: Any) -> Any:
    return v.lower() if isinstance(v, str) else v


def query_string(params: dict[str, Any], **over: Any) -> str:
    d = {k: v for k, v in {**params, **over}.items() if v not in (None, "")}
    return urlencode(d)


def chips(path: str, params: dict[str, Any], filters: Iterable[tuple[str, str, Any]], reset: Iterable[str] = ("page",)) -> list[dict[str, str]]:
    """Active filter chips: one per set filter, each with the URL that removes it (and returns to page 1).

    ``filters``: ``(param name, human label, display value)`` in display order; unset values are skipped."""
    out = []
    for name, label, value in filters:
        if value in (None, ""):
            continue
        over = {name: None, **{r: None for r in reset}}
        out.append({"param": name, "label": label, "value": str(value), "remove": f"{path}?{query_string(params, **over)}".rstrip("?")})
    return out


def clear_url(path: str, params: dict[str, Any], names: Iterable[str]) -> str:
    over: dict[str, Any] = {n: None for n in names}
    over["page"] = None
    return f"{path}?{query_string(params, **over)}".rstrip("?")
