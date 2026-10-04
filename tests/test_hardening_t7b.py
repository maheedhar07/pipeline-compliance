"""T7b: fail-safe settings (https in prod, timeout < lock window), response size cap, DB connect timeout."""

from __future__ import annotations

import httpx
import pytest
from pydantic import ValidationError

from pch.collectors.http import SourceClient
from pch.collectors.transport import RecordingTransport, ResponseTooLargeError, SizeLimitTransport
from pch.providers.artifacts import LocalArtifactStore
from pch.settings import Settings
from pch.store.engine import connect_args_for

MB = 1024 * 1024


def S(**kw) -> Settings:
    return Settings(_env_file=None, **kw)  # type: ignore[call-arg]


# ------------------------------------------------------------- SEC-11a: https only in prod
@pytest.mark.parametrize(
    "field",
    ["ado_base_url", "ado_vsrm_url", "sonar_url", "aikido_url", "servicenow_url", "keyvault_url", "artifact_blob_account_url"],
)
def test_prod_rejects_plain_http_source_urls(field):
    kw = {field: "http://internal.example.net", "artifact_store": "local"}
    if field == "keyvault_url":
        # the Azure endpoint check rejects http everywhere; for prod the https rule must too
        with pytest.raises(ValidationError):
            S(app_env="prod", **kw)
        return
    if field == "artifact_blob_account_url":
        kw.update(artifact_store="azure_blob", artifact_blob_container="c")
        with pytest.raises(ValidationError):
            S(app_env="prod", **kw)
        return
    with pytest.raises(ValidationError, match="https"):
        S(app_env="prod", **kw)
    S(app_env="dev", **kw)  # on-prem / local mocks stay possible outside prod
    S(app_env="test", **kw)


def test_prod_accepts_https_and_unset_sources():
    s = S(app_env="prod", sonar_url="https://sonar.example.net", servicenow_url="https://x.service-now.com")
    assert s.is_prod
    S(app_env="prod")  # defaults are https; unset optional sources are fine


# ------------------------------------------------------------- SEC-11b: a running scan never looks stale
def test_scan_timeout_must_be_below_lock_stale_window():
    with pytest.raises(ValidationError, match="SCAN_TIMEOUT_MINUTES"):
        S(scan_timeout_minutes=360, scan_lock_stale_minutes=360)
    with pytest.raises(ValidationError, match="SCAN_TIMEOUT_MINUTES"):
        S(scan_timeout_minutes=400, scan_lock_stale_minutes=360)
    ok = S(scan_timeout_minutes=359, scan_lock_stale_minutes=360)
    assert ok.scan_timeout_minutes < ok.scan_lock_stale_minutes
    S()  # defaults (240 < 360)


# ------------------------------------------------------------- SEC-13a: response size cap
def _transport(handler, limit: int, **kw) -> SourceClient:
    return SourceClient("https://h.example.net", transport=httpx.MockTransport(handler), max_response_bytes=limit,
                        backoff_base=0, **kw)


async def test_content_length_over_cap_is_rejected_without_reading_the_body():
    read = []

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            read.append(1)
            yield b"x"

    def handler(request):
        return httpx.Response(200, headers={"content-length": str(2 * MB)}, stream=Body())

    c = _transport(handler, MB)
    with pytest.raises(ResponseTooLargeError, match="declares"):
        await c.get_text("/big")
    await c.aclose()
    assert not read


async def test_chunked_response_is_aborted_when_it_passes_the_cap():
    pulled = []

    class Endless(httpx.AsyncByteStream):  # no Content-Length: a chunked / unbounded body
        async def __aiter__(self):
            while True:
                pulled.append(1)
                yield b"y" * 65536
                if len(pulled) > 1000:  # safety net so a broken cap cannot hang the suite
                    return

    c = _transport(lambda r: httpx.Response(200, stream=Endless()), MB)
    with pytest.raises(ResponseTooLargeError, match="exceeds"):
        await c.get_text("/stream")
    await c.aclose()
    assert len(pulled) <= 20  # stopped near 1 MB / 64 KiB, not after 1000 chunks


async def test_response_within_cap_is_unchanged_and_error_is_not_retried():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json={"v": "z" * 1000})

    c = _transport(handler, MB)
    assert (await c.get_json("/ok"))["v"] == "z" * 1000
    await c.aclose()

    calls.clear()
    c = _transport(lambda r: (calls.append(1), httpx.Response(200, content=b"q" * (2 * MB)))[1], MB, max_attempts=4)
    with pytest.raises(ResponseTooLargeError):
        await c.get_text("/big")
    await c.aclose()
    assert len(calls) == 1  # not an httpx.TransportError: no retry storm on a huge body


def test_error_text_has_no_query_string():
    # The message is built from host + path only.
    import asyncio

    async def go():
        t = SizeLimitTransport(httpx.MockTransport(lambda r: httpx.Response(200, headers={"content-length": "999999999"})), MB)
        async with httpx.AsyncClient(transport=t) as cl:
            with pytest.raises(ResponseTooLargeError) as e:
                await cl.get("https://h.example.net/p?token=SECRETVALUE")
        assert "SECRETVALUE" not in str(e.value) and "h.example.net/p" in str(e.value)

    asyncio.run(go())


async def test_recording_transport_never_buffers_past_the_cap(tmp_path):
    """Live wiring: SizeLimit sits under the recorder, so the cache cannot buffer an unbounded body either."""
    class Endless(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(500):
                yield b"y" * 65536

    store = LocalArtifactStore(tmp_path)
    inner = SizeLimitTransport(httpx.MockTransport(lambda r: httpx.Response(200, stream=Endless())), MB)
    c = SourceClient("https://h.example.net", transport=RecordingTransport(inner, store), backoff_base=0)
    with pytest.raises(ResponseTooLargeError):
        await c.get_text("/x")
    await c.aclose()
    assert list(tmp_path.rglob("*.json")) == []


def test_live_sources_wrap_the_network_transport_with_the_cap(monkeypatch):
    from pch import sources

    seen = {}
    real = sources._live

    def spy(settings, transport, kw, secrets):
        seen["t"] = transport
        return real(settings, transport, kw, secrets)

    monkeypatch.setattr(sources, "_live", spy)
    s = S(ado_org="o", http_max_response_mb=7)
    sources.live_sources(s, secrets=type("P", (), {"get": lambda self, n: "fake"})())  # type: ignore[arg-type]
    t = seen["t"]
    assert isinstance(t, SizeLimitTransport) and t.max_bytes == 7 * MB


# Demo scans and cache replay run through the unchanged transports: tests/test_scan_demo.py
# (test_cache_has_no_secrets_and_replay_reproduces, test_cli_seed_and_scan) cover them.


# ------------------------------------------------------------- SEC-13b: DB connect timeout per dialect
def test_connect_args_per_dialect():
    assert connect_args_for("postgresql", 15) == {"connect_timeout": 15}
    assert connect_args_for("mssql", 9) == {"timeout": 9}
    assert connect_args_for("sqlite", 15) == {}
    assert connect_args_for("mysql", 15) == {}


def test_build_engine_passes_connect_args_to_the_driver(monkeypatch):
    captured: dict = {}
    import pch.store.engine as eng

    def fake_create(url, **kw):
        captured["kw"] = kw
        captured["url"] = url
        from sqlalchemy import create_engine

        return create_engine("sqlite://")

    monkeypatch.setattr(eng, "create_engine", fake_create)
    s = S(db_connect_timeout_seconds=7)
    eng.build_engine("postgresql+psycopg://u:p@localhost/db", s)
    assert captured["kw"]["connect_args"] == {"connect_timeout": 7}
    eng.build_engine("mssql+pyodbc://u:p@localhost/db?driver=ODBC+Driver+18+for+SQL+Server", s)
    assert captured["kw"]["connect_args"] == {"timeout": 7}
    eng.build_engine("sqlite:///:memory:", s)
    assert captured["kw"]["connect_args"] == {"check_same_thread": False}  # sqlite keeps its own args, no timeout


def test_settings_bounds_for_new_fields():
    assert S().db_connect_timeout_seconds == 15 and S().http_max_response_mb == 50
    with pytest.raises(ValidationError):
        S(db_connect_timeout_seconds=0)
    with pytest.raises(ValidationError):
        S(http_max_response_mb=0)
