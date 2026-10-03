import httpx
import pytest
import respx

from pch.collectors.ado.client import AdoClient
from pch.collectors.http import HttpError, RetryableError
from pch.collectors.transport import MutationBlockedError

BASE = "https://dev.azure.com/contoso"


def make(**kw):
    return AdoClient("contoso", "pat123", backoff_base=0, **kw)


@respx.mock
async def test_basic_auth_and_api_version():
    route = respx.get(f"{BASE}/_apis/projects").mock(return_value=httpx.Response(200, json={"value": [{"name": "P"}]}))
    c = make()
    out = await c.projects()
    await c.aclose()
    assert out == [{"name": "P"}]
    req = route.calls[0].request
    assert req.url.params["api-version"] == "7.1"
    assert req.headers["authorization"].startswith("Basic ")


@respx.mock
async def test_continuation_token_header_paging():
    def handler(request):
        if "continuationToken" in request.url.params:
            return httpx.Response(200, json={"value": [{"id": 3}]})
        return httpx.Response(200, json={"value": [{"id": 1}, {"id": 2}]}, headers={"x-ms-continuationtoken": "abc"})

    respx.get(f"{BASE}/P/_apis/build/definitions").mock(side_effect=handler)
    c = make()
    items = await c.paged("P", "_apis/build/definitions")
    await c.aclose()
    assert [i["id"] for i in items] == [1, 2, 3]


@respx.mock
async def test_continuation_token_in_body():
    calls = []

    def handler(request):
        calls.append(dict(request.url.params))
        if "continuationToken" in request.url.params:
            return httpx.Response(200, json={"value": [2]})
        return httpx.Response(200, json={"value": [1], "continuationToken": "t"})

    respx.get(f"{BASE}/P/_apis/x").mock(side_effect=handler)
    c = make()
    assert await c.paged("P", "_apis/x") == [1, 2]
    await c.aclose()


@respx.mock
async def test_retry_after_429_then_success():
    route = respx.get(f"{BASE}/_apis/projects").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(200, json={"value": []})]
    )
    c = make()
    assert await c.projects() == []
    await c.aclose()
    assert route.call_count == 2


@respx.mock
async def test_retry_exhausted_raises():
    respx.get(f"{BASE}/_apis/projects").mock(return_value=httpx.Response(503))
    c = make(max_attempts=2)
    with pytest.raises(RetryableError):
        await c.projects()
    await c.aclose()


@respx.mock
async def test_404_raises_and_optional_returns_none():
    respx.get(f"{BASE}/P/_apis/nothing").mock(return_value=httpx.Response(404, json={}))
    c = make()
    with pytest.raises(HttpError):
        await c.get("P", "_apis/nothing")
    assert await c.get_optional("P", "_apis/nothing") is None
    await c.aclose()


@respx.mock
async def test_preview_post_allowed_but_other_post_blocked():
    respx.post(f"{BASE}/P/_apis/pipelines/5/preview").mock(return_value=httpx.Response(200, json={"finalYaml": "x"}))
    c = make()
    assert (await c.post_preview("P", 5))["finalYaml"] == "x"
    with pytest.raises(MutationBlockedError):
        await c.http.request("POST", f"{BASE}/P/_apis/build/builds", json={"definition": {"id": 1}})
    with pytest.raises(MutationBlockedError):
        await c.http.request("DELETE", f"{BASE}/P/_apis/build/definitions/1")
    with pytest.raises(MutationBlockedError):
        await c.http.request("PATCH", f"{BASE}/P/_apis/build/definitions/1")
    with pytest.raises(MutationBlockedError):
        await c.http.request("POST", f"{BASE}/P/_apis/pipelines/5/preview", json={"previewRun": False})
    await c.aclose()
