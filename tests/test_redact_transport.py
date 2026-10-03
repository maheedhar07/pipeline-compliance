import json

import httpx
import pytest

from pch.collectors.redact import SUSPECTED, redact_json, redact_text, value_looks_secret
from pch.collectors.transport import (
    CacheReplayTransport,
    MutationBlockedError,
    ReadOnlyTransport,
    RecordingTransport,
)


def test_redact_variables():
    out = redact_json({"variables": {
        "apiKey": {"value": "real-secret", "isSecret": True},
        "dbPassword": {"value": "pw", "isSecret": False},
        "Config": {"value": "Release", "allowOverride": True},
    }})
    v = out["variables"]
    assert v["apiKey"]["value"] is None
    assert v["dbPassword"]["value"] == SUSPECTED
    assert v["Config"]["value"] == "Release"
    assert "real-secret" not in json.dumps(out) and '"pw"' not in json.dumps(out)


def test_redact_secret_fields_and_named_pairs():
    out = redact_json({"authorization": {"parameters": {"serviceprincipalkey": "abc", "tenantid": "t", "password": "p"}},
                       "items": [{"name": "dbPassword", "value": "zzz", "isSecret": False}, {"name": "Region", "value": "x"}]})
    s = json.dumps(out)
    assert "abc" not in s and '"p"' not in s and "zzz" not in s
    assert out["items"][1]["value"] == "x"


def test_redact_yaml_text():
    t = "variables:\n  - name: dbPassword\n    value: hunter2x\n  - name: Region\n    value: west\nenv:\n  API_TOKEN: abcdef\n  OK: $(API_TOKEN)\n"
    r = redact_text(t)
    assert "hunter2x" not in r and "abcdef" not in r and "west" in r and "$(API_TOKEN)" in r


def test_value_looks_secret():
    assert value_looks_secret("ghp_abcdefghijklmnop")
    assert value_looks_secret("Server=x;Password=abcd1234;")
    assert value_looks_secret("aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3")
    assert value_looks_secret("Release") is None
    assert value_looks_secret("$(secretVar)") is None
    assert value_looks_secret(None) is None


async def test_readonly_guard_wraps_any_transport():
    t = ReadOnlyTransport(httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    async with httpx.AsyncClient(transport=t) as c:
        assert (await c.get("https://x/y")).status_code == 200
        with pytest.raises(MutationBlockedError):
            await c.put("https://x/y", json={})


async def test_record_and_replay_redacts(tmp_path):
    payload = {"value": [{"variables": {"pw": {"value": "topsecret", "isSecret": True}}}]}
    inner = httpx.MockTransport(lambda r: httpx.Response(200, json=payload))
    async with httpx.AsyncClient(transport=RecordingTransport(inner, tmp_path)) as c:
        r = await c.get("https://dev.azure.com/o/_apis/x?api-version=7.1")
        assert r.json()["value"][0]["variables"]["pw"]["value"] == "topsecret"  # live caller still sees it
    files = list(tmp_path.rglob("*.json"))
    assert len(files) == 1 and "topsecret" not in files[0].read_text()
    async with httpx.AsyncClient(transport=CacheReplayTransport(tmp_path)) as c:
        hit = await c.get("https://dev.azure.com/o/_apis/x?api-version=7.1")
        assert hit.status_code == 200 and hit.json()["value"][0]["variables"]["pw"]["value"] is None
        miss = await c.get("https://dev.azure.com/o/_apis/other")
        assert miss.status_code == 404
