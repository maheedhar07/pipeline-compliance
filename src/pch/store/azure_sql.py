"""Azure SQL authentication with Microsoft Entra ID (managed identity / DefaultAzureCredential).

Selected with ``DB_AUTH=azure_ad``. The access token is injected into every new pyodbc connection via
SQLAlchemy's ``do_connect`` event (``SQL_COPT_SS_ACCESS_TOKEN``), so no password is ever stored. Needs the
``azuresql`` extra (``pyodbc`` + ``azure-identity``) and the Microsoft ODBC Driver 18 on the host.
"""

from __future__ import annotations

import re
import struct
import threading
import time
from collections.abc import Callable
from typing import Any, Protocol

from sqlalchemy import event
from sqlalchemy.engine import Engine

SCOPE = "https://database.windows.net/.default"
SQL_COPT_SS_ACCESS_TOKEN = 1256  # msodbcsql connection attribute id
REFRESH_SKEW_S = 300  # refresh when fewer than 5 minutes of validity remain

# Connection-string keys that conflict with token auth (SQLAlchemy adds Trusted_Connection=Yes when the URL has no user).
_CONFLICTING = re.compile(r"(?:^|;)\s*(?:Trusted_Connection|UID|PWD|Authentication)\s*=[^;]*", re.IGNORECASE)


class AzureSqlUnavailable(RuntimeError):
    """The ``azuresql`` extra (or the ODBC driver Python package) is not installed."""


class _Token(Protocol):
    token: str
    expires_on: int | float


class _Credential(Protocol):
    def get_token(self, *scopes: str, **kwargs: Any) -> _Token: ...


def encode_token(token: str) -> bytes:
    """ODBC ``SQL_COPT_SS_ACCESS_TOKEN`` struct: 4-byte little-endian length + UTF-16-LE token bytes."""
    raw = token.encode("utf-16-le")
    return struct.pack("<I", len(raw)) + raw


def default_credential() -> _Credential:
    try:
        import pyodbc  # noqa: F401
        from azure.identity import DefaultAzureCredential
    except ImportError as exc:
        raise AzureSqlUnavailable(
            "DB_AUTH=azure_ad requires the 'azuresql' extra (pyodbc + azure-identity): "
            "pip install 'pipeline-compliance[azuresql]' (and the Microsoft ODBC Driver 18 for SQL Server)"
        ) from exc
    return DefaultAzureCredential()  # type: ignore[no-any-return]


class TokenProvider:
    """Caches an Entra access token and refreshes it shortly before it expires (thread-safe)."""

    def __init__(
        self,
        credential: _Credential | Callable[[], _Credential] | None = None,
        scope: str = SCOPE,
        skew_s: float = REFRESH_SKEW_S,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._credential = credential
        self._scope = scope
        self._skew = skew_s
        self._clock = clock
        self._lock = threading.Lock()
        self._token: str | None = None
        self._expires_on = 0.0

    def _cred(self) -> _Credential:
        if self._credential is None:
            self._credential = default_credential()
        elif callable(self._credential) and not hasattr(self._credential, "get_token"):
            self._credential = self._credential()
        return self._credential  # type: ignore[return-value]

    def get(self) -> str:
        with self._lock:
            if self._token is None or self._expires_on - self._clock() <= self._skew:
                tok = self._cred().get_token(self._scope)
                self._token, self._expires_on = tok.token, float(tok.expires_on)
            return self._token

    def struct(self) -> bytes:
        return encode_token(self.get())


def inject_token(provider: TokenProvider, cargs: list[Any], cparams: dict[str, Any]) -> None:
    """Mutate pyodbc ``connect`` arguments in place (the body of the ``do_connect`` hook)."""
    if cargs and isinstance(cargs[0], str):
        # VERIFY: with an access token the ODBC string must carry no Trusted_Connection/UID/PWD/Authentication;
        # SQLAlchemy emits Trusted_Connection=Yes for user-less URLs, so it is stripped here (confirm on real Azure SQL).
        cargs[0] = _CONFLICTING.sub("", cargs[0]).lstrip(";")
    cparams.setdefault("attrs_before", {})[SQL_COPT_SS_ACCESS_TOKEN] = provider.struct()


def install(engine: Engine, provider: TokenProvider | None = None) -> TokenProvider:
    """Inject a fresh access token into every new connection of ``engine``."""
    if engine.dialect.name != "mssql" or engine.dialect.driver != "pyodbc":
        raise ValueError("DB_AUTH=azure_ad requires an mssql+pyodbc:// DATABASE_URL")
    prov = provider or TokenProvider()

    @event.listens_for(engine, "do_connect")
    def _inject(dialect: Any, conn_rec: Any, cargs: list[Any], cparams: dict[str, Any]) -> None:
        inject_token(prov, cargs, cparams)

    return prov
