"""In-memory httpx transport that serves a generated demo world as if it were the real services.

The REAL collectors talk to this transport exactly as they would talk to Azure DevOps, SonarQube,
Aikido and ServiceNow, so demo mode exercises collectors -> normalizers -> rules end to end.
It is read-only by construction (only GET plus the documented preview/token POSTs).
"""

from __future__ import annotations

import gzip
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx

from pch.demo import payloads as P

ADO_HOST = "dev.azure.com"
VSRM_HOST = "vsrm.dev.azure.com"
SONAR_HOST = "sonar.demo.local"
AIKIDO_HOST = "aikido.demo.local"
SNOW_HOST = "snow.demo.local"
PAGE = 100


def save_world(world: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(world, fh)


def load_world(path: Path) -> dict[str, Any]:
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def _json(data: Any, status: int = 200, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, json=data, headers=headers)


def _page(items: list[Any], request: httpx.Request) -> httpx.Response:
    """Serve a list with ADO-style continuation-token paging (exercises the real paging code)."""
    start = int(request.url.params.get("continuationToken", "0") or 0)
    chunk = items[start : start + PAGE]
    nxt = start + PAGE
    headers = {"x-ms-continuationtoken": str(nxt)} if nxt < len(items) else {}
    return _json({"count": len(chunk), "value": chunk}, headers=headers)


class DemoTransport(httpx.AsyncBaseTransport):
    def __init__(self, world: dict[str, Any]):
        self.w = world
        self.ado = world["ado"]
        self._sonar_calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        path = unquote(request.url.path)
        try:
            if host == ADO_HOST:
                return self.ado_route(request, path)
            if host == VSRM_HOST:
                return self.vsrm_route(request, path)
            if host == SONAR_HOST:
                return self.sonar_route(request, path)
            if host == AIKIDO_HOST:
                return self.aikido_route(request, path)
            if host == SNOW_HOST:
                return self.snow_route(request, path)
        except KeyError:
            return _json({"message": "not found"}, 404)
        return _json({"message": f"unknown host {host}"}, 404)

    # ------------------------------------------------------------------ ADO
    def ado_route(self, req: httpx.Request, path: str) -> httpx.Response:
        m = re.match(rf"^/{P.ORG}(/.*)$", path)
        if not m:
            return _json({}, 404)
        rest = m.group(1)
        if rest == "/_apis/projects":
            return _json({"count": len(self.ado), "value": [{"id": f"p-{n}", "name": n} for n in self.ado]})
        if rest == "/_apis/distributedtask/tasks":
            return _json(self.w["tasks"])
        pm = re.match(r"^/([^/]+)/_apis/(.*)$", rest)
        if not pm:
            return _json({}, 404)
        pr = self.ado[pm.group(1)]
        api = pm.group(2)
        q = req.url.params
        if api == "git/repositories":
            return _page(pr["repos"], req)
        im = re.match(r"^git/repositories/([^/]+)/items$", api)
        if im:
            rid = im.group(1)
            if q.get("recursionLevel") == "Full":
                return _page(pr["items"][rid], req)
            files = pr["files"].get(rid, {})
            content = files.get(q.get("path", ""))
            if content is None:
                return _json({"message": "item not found"}, 404)
            return _json({"path": q.get("path"), "content": content, "gitObjectType": "blob"})
        if api == "build/definitions":
            return _page([{"id": d["id"], "name": d["name"], "path": d["path"], "type": "build"} for d in pr["build_defs"].values()], req)
        dm = re.match(r"^build/definitions/(\d+)$", api)
        if dm:
            if int(dm.group(1)) in pr["faulty_defs"]:
                return httpx.Response(500, text="Internal Server Error")
            return _json(pr["build_defs"][dm.group(1)])
        if api == "build/builds":
            return _page(pr["builds"].get(q["definitions"], []), req)
        pv = re.match(r"^pipelines/(\d+)/preview$", api)
        if pv and req.method == "POST":
            did = pv.group(1)
            if int(did) in pr["yaml_preview_fail"]:
                return _json({"message": "preview not permitted"}, 403)
            return _json({"finalYaml": pr["yaml"][did]})
        if api == "policy/configurations":
            return _page(pr["policies"], req)
        if api == "serviceendpoint/endpoints":
            return _page(pr["endpoints"], req)
        pp = re.match(r"^pipelines/pipelinePermissions/endpoint/(.+)$", api)
        if pp:
            return _json(pr["perms"][pp.group(1)])
        if api == "distributedtask/variablegroups":
            return _page(pr["variable_groups"], req)
        if api == "distributedtask/environments":
            return _page(pr["environments"], req)
        em = re.match(r"^distributedtask/environments/(\d+)/environmentdeploymentrecords$", api)
        if em:  # lineage (L2): last deployments of YAML environments
            recs = pr.get("env_records", {}).get(em.group(1), [])
            return _json({"count": len(recs), "value": recs[: int(q.get("top") or len(recs))]})
        if api == "distributedtask/taskgroups":
            return _json({"count": 0, "value": pr["taskgroups"]})
        if api == "pipelines/checks/configurations":
            return _json({"count": 0, "value": pr["env_checks"].get(q["resourceId"], [])})
        return _json({"message": f"demo route not implemented: {api}"}, 404)

    def vsrm_route(self, req: httpx.Request, path: str) -> httpx.Response:
        m = re.match(rf"^/{P.ORG}/([^/]+)/_apis/release/(.*)$", path)
        if not m:
            return _json({}, 404)
        pr = self.ado[m.group(1)]
        api = m.group(2)
        if api == "definitions":
            return _page([{"id": d["id"], "name": d["name"], "path": d["path"]} for d in pr["release_defs"].values()], req)
        dm = re.match(r"^definitions/(\d+)$", api)
        if dm:
            return _json(pr["release_defs"][dm.group(1)])
        q = req.url.params
        if api == "deployments":
            if "minStartedTime" in q:  # run statistics / CRQ correlation (prod deployments of the last 90 days)
                return _page(pr["deployments"].get(q["definitionId"], []), req)
            items = pr.get("lineage_deployments", {}).get(q["definitionId"], [])  # lineage (L2): every environment, newest first
            if q.get("definitionEnvironmentId"):
                items = [d for d in items if str(d["definitionEnvironmentId"]) == q["definitionEnvironmentId"]]
            items = sorted(items, key=lambda d: d["startedOn"], reverse=True)
            return _json({"count": len(items), "value": items[: int(q.get("$top") or len(items))]})
        if api == "releases":
            items = pr.get("lineage_releases", {}).get(q["definitionId"], [])
            return _json({"count": len(items), "value": sorted(items, key=lambda r: r["createdOn"], reverse=True)[: int(q.get("$top") or len(items))]})
        rm = re.match(r"^releases/(\d+)$", api)
        if rm:
            hit = next((r for lst in pr.get("lineage_releases", {}).values() for r in lst if str(r["id"]) == rm.group(1)), None)
            return _json(hit) if hit else _json({"message": "release not found"}, 404)
        return _json({}, 404)

    # ------------------------------------------------------------------ Sonar
    def sonar_route(self, req: httpx.Request, path: str) -> httpx.Response:
        q = req.url.params
        key = q.get("projectKey") or q.get("component") or q.get("project") or ""
        data = self.w["sonar"].get(key)
        if data is None:
            return _json({"errors": [{"msg": f"Project '{key}' not found"}]}, 404)
        if data.get("error500") and path.endswith("project_status"):
            return httpx.Response(500, text="Internal Server Error")
        if path.endswith("/qualitygates/project_status"):
            return _json({"projectStatus": {"status": data["status"], "conditions": []}})
        if path.endswith("/measures/component"):
            ms = []
            for metric, k in (("coverage", "coverage"), ("bugs", "bugs"), ("vulnerabilities", "vulnerabilities"), ("security_hotspots", "hotspots"),
                              ("code_smells", "smells"), ("duplicated_lines_density", "dup")):
                if data.get(k) is not None:
                    ms.append({"metric": metric, "value": str(data[k])})
            return _json({"component": {"key": key, "measures": ms}})
        if path.endswith("/project_analyses/search"):
            return _json({"paging": {"total": 1}, "analyses": [{"key": "AX1", "date": data["date"]}]})
        if path.endswith("/qualitygates/get_by_project"):
            return _json({"qualityGate": {"name": data["gate"], "default": data["gate"] == "Sonar way"}})
        return _json({}, 404)

    # ------------------------------------------------------------------ Aikido
    def aikido_route(self, req: httpx.Request, path: str) -> httpx.Response:
        if path.endswith("/oauth/token"):
            return _json({"access_token": "demo-token-not-a-secret", "token_type": "Bearer", "expires_in": 3600})  # nosec B105 - fake token served by the demo transport
        if "Bearer" not in req.headers.get("authorization", ""):
            return _json({"message": "unauthorized"}, 401)
        page, per = int(req.url.params.get("page", 0)), int(req.url.params.get("per_page", 200))
        if path.endswith("/repositories/code"):
            items = self.w["aikido"]["repos"]
        elif path.endswith("/open-issue-groups"):
            items = self.w["aikido"]["issues"]
        else:
            return _json({}, 404)
        return _json(items[page * per : (page + 1) * per])

    # ------------------------------------------------------------------ ServiceNow
    def snow_route(self, req: httpx.Request, path: str) -> httpx.Response:
        if not path.endswith("/api/now/table/change_request"):
            return _json({}, 404)
        query = req.url.params.get("sysparm_query", "")
        changes = self.w["snow"]["changes"]
        out: list[dict[str, Any]] = []
        nm = re.match(r"^numberIN(.+)$", query)
        if nm:
            wanted = set(nm.group(1).split(","))
            out = [c for c in changes if c["number"] in wanted]
        else:
            cm = re.match(r"^cmdb_ci\.nameLIKE([^\^]+)\^end_date>=([^\^]+)", query)
            if cm:
                ci, since = cm.group(1), cm.group(2)
                out = [c for c in changes if ci in (c.get("cmdb_ci") or "") and c["end_date"] >= since]
        return _json({"result": out})


def parse_world_time(world: dict[str, Any]) -> datetime:
    return datetime.strptime(world["meta"]["generated_at"], "%Y-%m-%dT%H:%M:%SZ")
