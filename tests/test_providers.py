"""Provider seams: SecretProvider (env/file/azure_keyvault) and ArtifactStore (local/azure_blob). No network."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import sys

import httpx
import pytest
from typer.testing import CliRunner

from pch.cli import app
from pch.collectors.transport import CacheReplayTransport, RecordingTransport
from pch.doctor import check_artifact_store, check_secrets, check_sources
from pch.providers import (
    EnvSecretProvider,
    FileSecretProvider,
    InvalidArtifactKey,
    LocalArtifactStore,
    PrefixedStore,
    ProviderUnavailable,
    SecretBackendError,
    SecretNotFound,
    get_artifact_store,
    get_secret_provider,
    require_secret,
)
from pch.providers.azure_blob import BlobArtifactStore
from pch.providers.azure_keyvault import KeyVaultSecretProvider
from pch.settings import ConfigError, Settings
from pch.sources import live_sources

SECRET = "s3cr3t-VALUE-must-not-leak-0123456789"


def mk(**kw) -> Settings:
    return Settings(_env_file=None, **kw)


# ------------------------------------------------------------------ secrets: env
def test_env_provider_reads_only_secret_fields():
    s = mk(ado_pat=SECRET, ado_org="o", database_url="sqlite:///x.db")
    p = EnvSecretProvider(s)
    assert p.get("ADO_PAT") == SECRET
    assert p.get("SONAR_TOKEN") is None  # empty -> None
    assert p.get("DATABASE_URL") is None  # not a SecretStr field: never exposed
    assert p.get("NOPE") is None
    assert get_secret_provider(s).name == "env"


def test_require_secret_names_the_secret_not_a_value():
    with pytest.raises(SecretNotFound) as e:
        require_secret(EnvSecretProvider(mk()), "ADO_PAT")
    assert "ADO_PAT" in str(e.value) and "SECRETS_PROVIDER=env" in str(e.value)
    assert isinstance(e.value, ConfigError)


# ------------------------------------------------------------------ secrets: file
def test_file_provider_reads_strips_newline_and_warns(tmp_path, caplog):
    f = tmp_path / "ADO_PAT"
    f.write_text(SECRET + "\n")
    os.chmod(f, 0o644)
    p = FileSecretProvider(tmp_path)
    with caplog.at_level(logging.WARNING):
        assert p.get("ADO_PAT") == SECRET
        p.get("ADO_PAT")
    assert [r.message for r in caplog.records].count("secret file for ADO_PAT is world-readable; restrict its permissions (chmod 640/600)") == 1
    assert SECRET not in caplog.text
    assert p.get("MISSING") is None
    (tmp_path / "EMPTY").write_text("\n")
    assert p.get("EMPTY") is None


def test_file_provider_no_warning_for_private_file(tmp_path, caplog):
    f = tmp_path / "ADO_PAT"
    f.write_text(SECRET)
    os.chmod(f, 0o600)
    with caplog.at_level(logging.WARNING):
        FileSecretProvider(tmp_path).get("ADO_PAT")
    assert not caplog.records


@pytest.mark.parametrize("bad", ["../x", "a/b", "..", "/etc/passwd", "", ".hidden", "a\\b", "x\x00y"])
def test_file_provider_rejects_bad_names(tmp_path, bad):
    with pytest.raises(SecretNotFound):
        FileSecretProvider(tmp_path).get(bad)


def test_file_provider_rejects_symlink_escape(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("x")
    d = tmp_path / "secrets"
    d.mkdir()
    (d / "ADO_PAT").symlink_to(outside)
    with pytest.raises(SecretNotFound):
        FileSecretProvider(d).get("ADO_PAT")


def test_file_provider_allows_kubernetes_style_symlinks(tmp_path):
    data = tmp_path / "..2024_01"
    data.mkdir()
    (data / "ADO_PAT").write_text(SECRET + "\n")
    (tmp_path / "..data").symlink_to(data)
    (tmp_path / "ADO_PAT").symlink_to("..data/ADO_PAT")
    assert FileSecretProvider(tmp_path).get("ADO_PAT") == SECRET


def test_registry_file_provider(tmp_path):
    (tmp_path / "ADO_PAT").write_text(SECRET)
    p = get_secret_provider(mk(secrets_provider="file", secrets_dir=tmp_path))
    assert p.name == "file" and p.get("ADO_PAT") == SECRET


def test_settings_require_provider_config():
    with pytest.raises(ValueError, match="SECRETS_DIR"):
        mk(secrets_provider="file")
    with pytest.raises(ValueError, match="KEYVAULT_URL"):
        mk(secrets_provider="azure_keyvault")
    with pytest.raises(ValueError, match="ARTIFACT_BLOB"):
        mk(artifact_store="azure_blob")
    with pytest.raises(ValueError, match="https"):
        mk(secrets_provider="azure_keyvault", keyvault_url="http://kv.example")


# ------------------------------------------------------------------ secrets: key vault (fake client)
class _NotFound(Exception):
    pass


_NotFound.__name__ = "ResourceNotFoundError"


class FakeKvClient:
    def __init__(self, data):
        self.data, self.calls = data, []

    def get_secret(self, name):
        self.calls.append(name)
        if name == "boom":
            raise RuntimeError(f"auth failed token={SECRET}")
        if name not in self.data:
            raise _NotFound(f"no {name}")
        return type("S", (), {"value": self.data[name]})()


def test_keyvault_name_mapping_cache_ttl_and_miss():
    now = [0.0]
    c = FakeKvClient({"ado-pat": SECRET, "custom-name": "x"})
    p = KeyVaultSecretProvider(c, name_map={"SONAR_TOKEN": "custom-name"}, ttl_seconds=60, clock=lambda: now[0])
    assert p.get("ADO_PAT") == SECRET and p.get("ADO_PAT") == SECRET
    assert c.calls == ["ado-pat"]  # cached
    now[0] = 61
    p.get("ADO_PAT")
    assert c.calls == ["ado-pat", "ado-pat"]  # TTL expired
    assert p.get("SONAR_TOKEN") == "x" and c.calls[-1] == "custom-name"  # mapping override
    assert p.get("AIKIDO_CLIENT_SECRET") is None and p.get("AIKIDO_CLIENT_SECRET") is None
    assert c.calls.count("aikido-client-secret") == 2  # misses are not cached


def test_keyvault_backend_error_never_echoes_message():
    p = KeyVaultSecretProvider(FakeKvClient({}), name_map={"X": "boom"})
    with pytest.raises(SecretBackendError) as e:
        p.get("X")
    assert SECRET not in str(e.value) and "RuntimeError" in str(e.value) and "'boom'" in str(e.value)


def test_keyvault_missing_extra_is_clear(monkeypatch):
    for m in ("azure.identity", "azure.keyvault.secrets"):
        monkeypatch.setitem(sys.modules, m, None)
    with pytest.raises(ProviderUnavailable, match=r"pip install 'pipeline-compliance\[azure-keyvault\]'"):
        get_secret_provider(mk(secrets_provider="azure_keyvault", keyvault_url="https://v.vault.azure.net"))


def test_keyvault_real_sdk_client_builds():
    pytest.importorskip("azure.keyvault.secrets")
    pytest.importorskip("azure.identity")
    p = get_secret_provider(mk(secrets_provider="azure_keyvault", keyvault_url="https://v.vault.azure.net"))
    assert p.name == "azure_keyvault"


# ------------------------------------------------------------------ live sources resolve through the provider
def test_live_sources_use_selected_provider_only(tmp_path):
    (tmp_path / "ADO_PAT").write_text("pat-from-file")
    # env var is set too but must be ignored when the provider is `file` (no silent mixing)
    s = mk(ado_org="o", ado_pat="pat-from-env", secrets_provider="file", secrets_dir=tmp_path)
    src = live_sources(s)
    expected = "Basic " + base64.b64encode(b":pat-from-file").decode()
    assert src.ado.http.client.headers["Authorization"] == expected
    assert src.sonar is None


def test_live_sources_missing_secret_is_clear_error(tmp_path):
    s = mk(ado_org="o", ado_pat="pat-from-env", secrets_provider="file", secrets_dir=tmp_path)
    with pytest.raises(SecretNotFound, match="ADO_PAT"):
        live_sources(s)
    s = mk(ado_org="o", ado_pat=SECRET, sonar_url="https://sonar.example")
    with pytest.raises(SecretNotFound, match="SONAR_TOKEN") as e:
        live_sources(s)
    assert SECRET not in str(e.value)


def test_live_sources_env_default_works():
    src = live_sources(mk(ado_org="o", ado_pat=SECRET))
    assert src.ado is not None


# ------------------------------------------------------------------ artifact store: local
async def test_local_store_roundtrip_list_delete(tmp_path):
    st = LocalArtifactStore(tmp_path / "raw")
    await st.put("scan1/h/a.json", b"1")
    await st.put("scan1/h/b.json", b"2")
    await st.put("scan2/h/c.json", b"3")
    assert await st.get("scan1/h/a.json") == b"1"
    assert await st.get("scan1/h/nope.json") is None
    assert await st.list("scan1/") == ["scan1/h/a.json", "scan1/h/b.json"]
    assert await st.list() == ["scan1/h/a.json", "scan1/h/b.json", "scan2/h/c.json"]
    assert await st.delete_prefix("scan1/") == 2
    assert await st.list() == ["scan2/h/c.json"]
    assert not (tmp_path / "raw" / "scan1").exists()  # emptied directories are pruned
    await st.put("scan2/h/c.json", b"overwritten")
    assert await st.get("scan2/h/c.json") == b"overwritten"
    assert not [p for p in (tmp_path / "raw").rglob(".tmp-*")]


@pytest.mark.parametrize("bad", ["../x", "a/../../x", "/abs", "a//b", "a\\b", "", "a/./b", "x\x00"])
async def test_local_store_rejects_escaping_keys(tmp_path, bad):
    st = LocalArtifactStore(tmp_path / "raw")
    with pytest.raises(InvalidArtifactKey):
        await st.put(bad, b"x")
    with pytest.raises(InvalidArtifactKey):
        await st.get(bad)


async def test_local_store_rejects_symlink_escape_and_empty_delete(tmp_path):
    (tmp_path / "raw").mkdir()
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "raw" / "link").symlink_to(tmp_path / "elsewhere")
    st = LocalArtifactStore(tmp_path / "raw")
    with pytest.raises(InvalidArtifactKey):
        await st.put("link/x", b"x")
    with pytest.raises(InvalidArtifactKey):
        await st.delete_prefix("")


async def test_prefixed_store_scopes_keys(tmp_path):
    base = LocalArtifactStore(tmp_path)
    s1 = PrefixedStore(base, "scan1")
    await s1.put("h/a.json", b"1")
    assert await base.get("scan1/h/a.json") == b"1"
    assert await s1.list() == ["h/a.json"]
    assert await s1.get("h/a.json") == b"1"
    with pytest.raises(InvalidArtifactKey):
        await s1.get("../scan2/x")
    with pytest.raises(InvalidArtifactKey):
        PrefixedStore(base, "../x")
    assert await s1.delete_prefix("h/") == 1


def test_registry_artifact_store_defaults_local(tmp_path):
    st = get_artifact_store(mk(data_dir=tmp_path))
    assert isinstance(st, LocalArtifactStore) and st.base == tmp_path / "raw"
    assert get_artifact_store(mk(), tmp_path / "other").base == tmp_path / "other" / "raw"


# ------------------------------------------------------------------ artifact store: azure blob (fake container)
class _BlobNotFound(Exception):
    pass


_BlobNotFound.__name__ = "ResourceNotFoundError"


class FakeContainer:
    def __init__(self):
        self.blobs: dict[str, bytes] = {}
        self.puts: list[tuple[str, bytes]] = []

    def upload_blob(self, name, data, overwrite=False):
        assert overwrite is True and isinstance(data, bytes)
        self.puts.append((name, data))
        self.blobs[name] = data

    def download_blob(self, name):
        if name not in self.blobs:
            raise _BlobNotFound(name)
        data = self.blobs[name]
        return type("D", (), {"readall": lambda self: data})()

    def list_blobs(self, name_starts_with=None):
        return [type("B", (), {"name": n})() for n in sorted(self.blobs) if n.startswith(name_starts_with or "")]

    def delete_blob(self, name):
        if name not in self.blobs:
            raise _BlobNotFound(name)
        del self.blobs[name]


async def test_blob_store_roundtrip():
    c = FakeContainer()
    st = BlobArtifactStore(c)
    await st.put("s1/h/a.json", b"1")
    await st.put("s1/h/b.json", b"2")
    await st.put("s2/h/c.json", b"3")
    assert await st.get("s1/h/a.json") == b"1"
    assert await st.get("s1/h/zzz") is None
    assert await st.list("s1/") == ["s1/h/a.json", "s1/h/b.json"]
    assert await st.delete_prefix("s1/") == 2
    assert await st.list() == ["s2/h/c.json"]
    with pytest.raises(InvalidArtifactKey):
        await st.put("../x", b"x")
    with pytest.raises(InvalidArtifactKey):
        await st.delete_prefix("")


def test_blob_missing_extra_is_clear(monkeypatch):
    for m in ("azure.identity", "azure.storage.blob"):
        monkeypatch.setitem(sys.modules, m, None)
    s = mk(artifact_store="azure_blob", artifact_blob_account_url="https://a.blob.core.windows.net", artifact_blob_container="raw")
    with pytest.raises(ProviderUnavailable, match=r"pip install 'pipeline-compliance\[azure-blob\]'"):
        get_artifact_store(s)


def test_blob_real_sdk_client_builds():
    pytest.importorskip("azure.storage.blob")
    pytest.importorskip("azure.identity")
    s = mk(artifact_store="azure_blob", artifact_blob_account_url="https://a.blob.core.windows.net", artifact_blob_container="raw")
    assert get_artifact_store(s).name == "azure_blob"


# ------------------------------------------------------------------ redaction happens BEFORE put (both impls)
def _leaky_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/yaml"):
        return httpx.Response(200, text=f"steps:\n  password: {SECRET}\n  name: x\n", headers={"content-type": "text/plain"})
    body = {
        "password": SECRET,
        "variables": {"apiToken": {"value": SECRET, "isSecret": True}, "dbPassword": {"value": SECRET}},
        "ok": 1,
    }
    return httpx.Response(200, json=body)


@pytest.fixture(params=["local", "azure_blob"])
def store_and_dump(request, tmp_path):
    if request.param == "local":
        st = LocalArtifactStore(tmp_path / "raw")

        def dump() -> bytes:
            return b"\n".join(p.read_bytes() for p in (tmp_path / "raw").rglob("*") if p.is_file())

        return st, dump
    c = FakeContainer()
    return BlobArtifactStore(c), lambda: b"\n".join([k.encode() + v for k, v in c.puts]) or b""


async def test_secret_in_response_never_reaches_store(store_and_dump):
    st, dump = store_and_dump
    transport = RecordingTransport(httpx.MockTransport(_leaky_handler), PrefixedStore(st, "scan1"))
    async with httpx.AsyncClient(transport=transport) as c:
        r = await c.get("https://dev.azure.com/o/_apis/x?api-version=7.1&access_token=" + SECRET)
        assert r.json()["password"] == SECRET  # the live caller still sees the real response
        await c.get("https://dev.azure.com/o/yaml")
    stored = dump()
    assert stored and SECRET.encode() not in stored
    assert len(await st.list("scan1/")) == 2
    async with httpx.AsyncClient(transport=CacheReplayTransport(PrefixedStore(st, "scan1"))) as c:
        hit = await c.get("https://dev.azure.com/o/_apis/x?api-version=7.1&access_token=" + SECRET)
        assert hit.status_code == 200 and hit.json()["ok"] == 1 and SECRET not in hit.text


async def test_store_failure_does_not_fail_the_scan(caplog):
    class Broken:
        name = "broken"

        async def put(self, key, data):
            raise OSError(f"disk full {SECRET}")

    t = RecordingTransport(httpx.MockTransport(lambda r: httpx.Response(200, json={"a": 1})), Broken())  # type: ignore[arg-type]
    with caplog.at_level(logging.WARNING):
        async with httpx.AsyncClient(transport=t) as c:
            assert (await c.get("https://x.example/a")).json() == {"a": 1}
            assert (await c.get("https://x.example/b")).json() == {"a": 1}
    assert caplog.text.count("raw cache write failed") == 1 and SECRET not in caplog.text


# ------------------------------------------------------------------ doctor
def test_doctor_checks_secrets_and_store(tmp_path):
    s = mk(ado_org="o", data_dir=tmp_path, sonar_url="https://sonar.example", ado_pat=SECRET)
    out = {c.name: c for c in check_secrets(s)}
    assert out["secret:ado"].status == "OK" and "ADO_PAT=set" in out["secret:ado"].detail
    assert out["secret:sonar"].status == "FAIL" and "SONAR_TOKEN=missing" in out["secret:sonar"].detail
    assert SECRET not in "".join(c.detail for c in out.values())
    assert all(SECRET not in c.detail and "ADO_PAT" not in c.detail for c in check_sources(s))
    c = check_artifact_store(s)
    assert c.status == "OK" and c.detail == "local"
    assert not [p for p in (tmp_path / "raw").rglob("*") if p.is_file()]  # probe key was deleted


def test_doctor_file_provider_ignores_env_credentials(tmp_path):
    sec = tmp_path / "sec"
    sec.mkdir()
    (sec / "ADO_PAT").write_text("x")
    s = mk(ado_org="o", ado_pat="env-value", secrets_provider="file", secrets_dir=sec, sonar_token="only-env")
    names = {c.name for c in check_secrets(s)}
    assert names == {"secrets_provider", "secret:ado"}  # sonar not configured: SONAR_URL is empty


def test_doctor_artifact_store_failure_reports_type_only(tmp_path):
    s = mk(data_dir=tmp_path / "raw-file")
    (tmp_path / "raw-file").write_text("a file, not a dir")
    c = check_artifact_store(s)
    assert c.status == "FAIL" and "probe failed" in c.detail


# ------------------------------------------------------------------ CLI end-to-end through the local store
def test_cli_demo_cache_lands_in_local_store_and_replays(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    monkeypatch.setenv("APP_ENV", "dev")
    from pch.settings import reset_settings

    reset_settings()
    runner = CliRunner()
    d = str(tmp_path / "data")
    assert runner.invoke(app, ["seed-demo", "--repos", "12", "--data-dir", d]).exit_code == 0
    r = runner.invoke(app, ["scan", "--demo", "--history", "0", "--cache", "--data-dir", d])
    assert r.exit_code == 0, r.output
    scans = [p for p in (tmp_path / "data" / "raw").iterdir() if p.is_dir()]
    assert len(scans) == 1 and any(scans[0].rglob("*.json"))
    assert json.loads(next(scans[0].rglob("*.json")).read_text())["method"]
    reset_settings()
    assert asyncio.run(LocalArtifactStore(tmp_path / "data" / "raw").list(scans[0].name + "/"))
