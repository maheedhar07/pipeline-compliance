import httpx
import respx

from pch.collectors.sonar import SonarClient, parse_sonar_date

BASE = "https://sonar.example.com"


def mock_all(fx, status="project_status_ok.json", measures="measures.json", gate="gate.json"):
    respx.get(f"{BASE}/api/qualitygates/project_status").mock(return_value=httpx.Response(200, json=fx("sonar", status)))
    respx.get(f"{BASE}/api/measures/component").mock(return_value=httpx.Response(200, json=fx("sonar", measures)))
    respx.get(f"{BASE}/api/project_analyses/search").mock(return_value=httpx.Response(200, json=fx("sonar", "analyses.json")))
    respx.get(f"{BASE}/api/qualitygates/get_by_project").mock(return_value=httpx.Response(200, json=fx("sonar", gate)))


@respx.mock
async def test_project_facts_full(fx):
    mock_all(fx)
    c = SonarClient(BASE, "tok", backoff_base=0)
    f = await c.project_facts("contoso_payments-api")
    await c.aclose()
    assert f.onboarded and f.gate_status == "OK" and f.gate_name == "Org Quality Gate"
    assert f.coverage == 81.2 and f.new_coverage == 88.0 and f.bugs == 3 and f.hotspots == 2 and f.duplication == 2.4
    assert f.last_analysis.year == 2026 and f.last_analysis.month == 9
    assert f.url.endswith("id=contoso_payments-api")


@respx.mock
async def test_error_gate_and_default_gate_and_no_coverage(fx):
    mock_all(fx, "project_status_error.json", "measures_nocoverage.json", "gate_default.json")
    c = SonarClient(BASE, "tok", backoff_base=0)
    f = await c.project_facts("k")
    await c.aclose()
    assert f.gate_status == "ERROR" and f.gate_name == "Sonar way" and f.coverage is None


@respx.mock
async def test_not_onboarded_on_404():
    respx.get(f"{BASE}/api/qualitygates/project_status").mock(return_value=httpx.Response(404, json={"errors": []}))
    c = SonarClient(BASE, "tok", backoff_base=0)
    f = await c.project_facts("nope")
    await c.aclose()
    assert not f.onboarded and f.gate_status is None


@respx.mock
async def test_first_found_candidates(fx):
    def status(request):
        return httpx.Response(200, json=fx("sonar", "project_status_ok.json")) if request.url.params["projectKey"] == "P_r" else httpx.Response(404)

    respx.get(f"{BASE}/api/qualitygates/project_status").mock(side_effect=status)
    respx.get(f"{BASE}/api/measures/component").mock(return_value=httpx.Response(200, json=fx("sonar", "measures.json")))
    respx.get(f"{BASE}/api/project_analyses/search").mock(return_value=httpx.Response(200, json={"analyses": []}))
    respx.get(f"{BASE}/api/qualitygates/get_by_project").mock(return_value=httpx.Response(403))
    c = SonarClient(BASE, backoff_base=0)
    f = await c.first_found(["custom", "P_r", "r"])
    await c.aclose()
    assert f.onboarded and f.key == "P_r" and f.last_analysis is None and f.gate_name is None


def test_parse_sonar_date():
    assert parse_sonar_date("2026-09-30T10:15:00+0000").day == 30
    assert parse_sonar_date("2026-09-30T10:15:00Z").hour == 10
    assert parse_sonar_date(None) is None and parse_sonar_date("garbage") is None
