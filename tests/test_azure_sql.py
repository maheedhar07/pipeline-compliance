import struct
import sys
from types import SimpleNamespace

import pytest

from pch.settings import Settings
from pch.store import azure_sql
from pch.store.azure_sql import (
    SCOPE,
    SQL_COPT_SS_ACCESS_TOKEN,
    AzureSqlUnavailable,
    TokenProvider,
    encode_token,
    inject_token,
)
from pch.store.engine import build_engine


class FakeCred:
    def __init__(self, clock, lifetime=3600):
        self.clock, self.lifetime, self.calls, self.scopes = clock, lifetime, 0, []

    def get_token(self, *scopes, **_):
        self.calls += 1
        self.scopes.append(scopes)
        return SimpleNamespace(token=f"tok{self.calls}", expires_on=self.clock() + self.lifetime)


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def test_encode_token_struct():
    b = encode_token("héllo")
    (n,) = struct.unpack("<I", b[:4])
    assert n == len(b) - 4 == len("héllo") * 2
    assert b[4:].decode("utf-16-le") == "héllo"
    assert SQL_COPT_SS_ACCESS_TOKEN == 1256 and SCOPE == "https://database.windows.net/.default"


def test_token_cached_then_refreshed_before_expiry():
    clock = Clock()
    cred = FakeCred(clock, lifetime=3600)
    p = TokenProvider(cred, clock=clock, skew_s=300)
    assert p.get() == "tok1" and p.get() == "tok1" and cred.calls == 1
    assert cred.scopes[0] == (SCOPE,)
    clock.t += 3600 - 301  # still > 5 min of validity left
    assert p.get() == "tok1" and cred.calls == 1
    clock.t += 2  # inside the refresh skew
    assert p.get() == "tok2" and cred.calls == 2
    assert p.struct() == encode_token("tok2")


def test_inject_token_sets_attrs_before_and_strips_conflicting_auth():
    p = TokenProvider(FakeCred(Clock()))
    cargs = ["DRIVER={ODBC Driver 18 for SQL Server};SERVER=h.database.windows.net;DATABASE=d;Trusted_Connection=Yes;Encrypt=yes"]
    cparams: dict = {}
    inject_token(p, cargs, cparams)
    assert "Trusted_Connection" not in cargs[0] and "Encrypt=yes" in cargs[0] and "DATABASE=d" in cargs[0]
    assert cparams["attrs_before"][1256] == encode_token("tok1")
    cargs2 = ["Trusted_Connection=Yes;UID=u;PWD=secret;SERVER=x"]
    inject_token(p, cargs2, {})
    assert cargs2 == ["SERVER=x"]


def test_install_requires_mssql_pyodbc():
    from sqlalchemy import create_engine

    with pytest.raises(ValueError, match="mssql"):
        azure_sql.install(create_engine("sqlite://"), TokenProvider(FakeCred(Clock())))


def test_azure_ad_with_non_mssql_url_is_rejected():
    with pytest.raises(ValueError, match="mssql"):
        build_engine("sqlite://", Settings(_env_file=None, db_auth="azure_ad"))


def test_azure_ad_without_extra_fails_clearly(monkeypatch):
    monkeypatch.setitem(sys.modules, "pyodbc", None)  # simulate missing package
    with pytest.raises(AzureSqlUnavailable, match=r"azuresql"):
        build_engine("mssql+pyodbc://@h.database.windows.net/d?driver=ODBC+Driver+18+for+SQL+Server", Settings(_env_file=None, db_auth="azure_ad"))


def test_pool_options_from_settings_for_server_dialects():
    pytest.importorskip("psycopg")
    s = Settings(_env_file=None, db_pool_size=3, db_max_overflow=1, db_pool_recycle=900, db_pool_timeout=5)
    e = build_engine("postgresql+psycopg://u:p@localhost/db", s)
    assert (e.pool.size(), e.pool._max_overflow, e.pool._recycle, e.pool._timeout) == (3, 1, 900, 5)  # noqa: SLF001
    assert e.pool._pre_ping is True  # noqa: SLF001


def test_sqlite_memory_shares_one_connection():
    from sqlalchemy import text

    e = build_engine("sqlite://", Settings(_env_file=None))
    with e.begin() as c:
        c.execute(text("CREATE TABLE t (x int)"))
    with e.connect() as c:
        assert c.execute(text("SELECT count(*) FROM t")).scalar() == 0
