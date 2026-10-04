"""Read the GitHub Actions side of one repository (read-only): workflows, reusable workflows, environments, runs, last deployments.

Failure model (same as ``reader.py``): nothing here raises for a normal GitHub answer. A part that cannot be read becomes an ``*_error`` /
None on ``ActionsRead`` with a precise reason, and one line per failed call in ``ActionsRead.errors``; the rules then answer UNKNOWN, never FAIL.

Endpoints (all GET; required read-only permissions: Actions, Environments, Deployments, Contents, Metadata):
``/repos/{o}/{r}/actions/workflows`` (Actions), ``/repos/{o}/{r}/contents/{path}?ref=`` (Contents: workflow files and reusable workflows),
``/repos/{o}/{r}/environments`` (+ ``/environments/{env}/deployment-branch-policies`` and ``/deployment_protection_rules``) (Environments),
``/repos/{o}/{r}/actions/runs?per_page=100&created=>=<date>`` (Actions), ``/repos/{o}/{r}/deployments?environment=&per_page=1`` and
``/deployments/{id}/statuses?per_page=1`` (Deployments).
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

from pch.collectors.github.client import GitHubClient, parse_link_next
from pch.collectors.github.discovery import FULL_NAME
from pch.collectors.github.reader import reason_for
from pch.model.gha import ActionsRead, GhCustomRule, GhDeployment, GhEnvironment, WorkflowSource
from pch.normalize.gha import REUSABLE_PATH, environment_names, reusable_refs

WORKFLOW_DIR = ".github/workflows/"
WORKFLOW_FILE = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$", re.I)
MAX_WORKFLOWS = 100  # per repo
MAX_REUSABLE = 10  # reusable workflows fetched per repo (one level deep)
MAX_ENVIRONMENTS = 30
MAX_RUN_PAGES = 5  # 500 runs: the API itself stops at 1000 results
RUN_PER_PAGE = 100


def _q(v: str) -> str:
    return quote(v, safe="")


def _repo_path(full_name: str) -> str:
    return "/".join(_q(x) for x in full_name.split("/"))


async def _text(client: GitHubClient, full: str, path: str, ref: str) -> str:
    return await client.get_raw(f"/repos/{full}/contents/{quote(path)}", {"ref": ref})


def _reviewers(rule: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for r in rule.get("reviewers") or []:
        who = (r or {}).get("reviewer") or {}
        if str(r.get("type", "")).lower() == "team":
            out.append(f"team:{who.get('slug') or who.get('name') or '?'}")
        else:
            out.append(f"user:{who.get('login') or '?'}")
    return out[:20]


async def _environment(client: GitHubClient, full: str, raw: dict[str, Any], errors: list[str]) -> GhEnvironment:
    name = str(raw.get("name") or "")
    env = GhEnvironment(name=name)
    for rule in raw.get("protection_rules") or []:
        kind = (rule or {}).get("type")
        if kind == "required_reviewers":
            env.required_reviewers = True
            env.reviewers = _reviewers(rule)
            env.prevent_self_review = rule.get("prevent_self_review")  # VERIFY: boolean on required_reviewers rules
        elif kind == "wait_timer":
            env.wait_timer = int(rule.get("wait_timer") or 0)
    pol = raw.get("deployment_branch_policy")
    base = f"/repos/{full}/environments/{_q(name)}"
    if isinstance(pol, dict) and pol.get("custom_branch_policies"):
        env.branch_policy = "custom"
        try:
            items = await client.paged(f"{base}/deployment-branch-policies", key="branch_policies")  # VERIFY: list key is `branch_policies`
            env.branch_patterns = [("tag:" if i.get("type") == "tag" else "") + str(i.get("name")) for i in items if isinstance(i, dict) and i.get("name")][:30]
        except Exception as e:  # noqa: BLE001 - becomes a reason
            env.branch_error = reason_for(e, f"deployment branch policies of environment {name}", "Environments: read")
            errors.append(env.branch_error)
    elif isinstance(pol, dict) and pol.get("protected_branches"):
        env.branch_policy = "protected"
    try:
        # VERIFY: GET .../deployment_protection_rules -> {custom_deployment_protection_rules: [{id, enabled, app: {slug, id, ...}}]}
        items = await client.paged(f"{base}/deployment_protection_rules", key="custom_deployment_protection_rules")
        env.custom_rules = [
            GhCustomRule(slug=str((i.get("app") or {}).get("slug") or ""), name=str((i.get("app") or {}).get("name") or ""), enabled=bool(i.get("enabled", True)))
            for i in items if isinstance(i, dict)
        ]
    except Exception as e:  # noqa: BLE001
        env.custom_error = reason_for(e, f"custom deployment protection rules of environment {name}", "Environments: read")
        errors.append(env.custom_error)
    return env


async def _environments(client: GitHubClient, full: str, out: ActionsRead) -> None:
    try:
        raw = await client.paged(f"/repos/{full}/environments", key="environments")
    except Exception as e:  # noqa: BLE001
        out.environments_error = reason_for(e, "environments", "Environments: read")
        out.errors.append(out.environments_error)
        return
    items = [r for r in raw if isinstance(r, dict) and r.get("name")]
    if len(items) > MAX_ENVIRONMENTS:
        out.errors.append(f"GitHub: {len(items)} environments; only the first {MAX_ENVIRONMENTS} were read")
        items = items[:MAX_ENVIRONMENTS]
    envs = await asyncio.gather(*(_environment(client, full, r, out.errors) for r in items))
    out.environments = {e.name: e for e in envs}


async def _runs(client: GitHubClient, full: str, since: str, out: ActionsRead) -> None:
    try:
        url: str | None = f"/repos/{full}/actions/runs"
        params: dict[str, Any] | None = {"per_page": RUN_PER_PAGE, "created": f">={since}"}
        runs: list[dict[str, Any]] = []
        for page in range(MAX_RUN_PAGES):
            if url is None:
                break
            resp = await client.request(url, params)
            body = resp.json() if resp.content else {}
            for r in (body.get("workflow_runs") if isinstance(body, dict) else None) or []:  # VERIFY: list key is `workflow_runs`
                if isinstance(r, dict):
                    actor = r.get("triggering_actor") or r.get("actor") or {}
                    runs.append({
                        "workflow_id": r.get("workflow_id"), "path": r.get("path"), "status": r.get("status"), "conclusion": r.get("conclusion"),
                        "created_at": r.get("created_at"), "updated_at": r.get("updated_at"), "html_url": r.get("html_url"), "head_branch": r.get("head_branch"),
                        "event": r.get("event"), "run_number": r.get("run_number"), "actor": actor.get("login") if isinstance(actor, dict) else None,
                    })
            url, params = parse_link_next(resp.headers.get("link")), None
            if url is not None and page == MAX_RUN_PAGES - 1:
                out.runs_truncated = True
        out.runs = runs
    except Exception as e:  # noqa: BLE001
        out.runs_error = reason_for(e, "workflow runs", "Actions: read")
        out.errors.append(out.runs_error)


async def _last_deployment(client: GitHubClient, full: str, env: str) -> GhDeployment:
    try:
        deps = await client.get_json(f"/repos/{full}/deployments", {"environment": env, "per_page": 1})
    except Exception as e:  # noqa: BLE001
        return GhDeployment(environment=env, error=reason_for(e, f"deployments of environment {env}", "Deployments: read"))
    if not isinstance(deps, list) or not deps or not isinstance(deps[0], dict):
        return GhDeployment(environment=env, never=True)
    d = deps[0]
    last = GhDeployment(environment=env, id=d.get("id"), sha=d.get("sha"), creator=((d.get("creator") or {}).get("login")), finished=d.get("created_at"))
    try:
        sts = await client.get_json(f"/repos/{full}/deployments/{d.get('id')}/statuses", {"per_page": 1})
        if isinstance(sts, list) and sts and isinstance(sts[0], dict):
            s = sts[0]
            last.status = str(s.get("state") or "unknown")
            last.finished = s.get("updated_at") or s.get("created_at") or last.finished
            last.url = s.get("log_url") or s.get("target_url") or None  # VERIFY: log_url (newer) / target_url (older)
        else:
            last.status = "pending"
    except Exception as e:  # noqa: BLE001
        last.error = reason_for(e, f"status of the last deployment of environment {env}", "Deployments: read")
    return last


async def read_actions(client: GitHubClient, full_name: str, branch: str, *, now: datetime, run_days: int = 90, known_paths: list[str] | None = None) -> ActionsRead:
    """Workflows (+ reusable ones), environments, runs and last deployments of ``org/repo`` at its default branch.

    ``known_paths`` = workflow files seen in the repository tree: used when the workflow listing itself is denied (the files stay readable with
    Contents: read; states and ids are then unknown)."""
    out = ActionsRead()
    if not FULL_NAME.match(full_name):
        out.list_error = f"GitHub: '{full_name[:60]}' is not a valid org/repo name"
        out.listed = False
        out.errors.append(out.list_error)
        return out
    full = _repo_path(full_name)
    since = (now - timedelta(days=run_days)).strftime("%Y-%m-%d")
    # 1. the listing, in parallel with environments and runs (independent calls)
    listing: list[Any] = []

    async def list_workflows() -> None:
        try:
            listing.extend(await client.paged(f"/repos/{full}/actions/workflows", key="workflows"))
        except Exception as e:  # noqa: BLE001
            out.list_error = reason_for(e, "workflow list", "Actions: read")
            out.errors.append(out.list_error)
            out.listed = False

    await asyncio.gather(list_workflows(), _environments(client, full, out), _runs(client, full, since, out))
    sources: list[WorkflowSource] = []
    if out.listed:
        for w in listing:
            path = str((w or {}).get("path") or "")
            if isinstance(w, dict) and WORKFLOW_FILE.match(path):  # dynamic workflows (CodeQL default setup, Dependabot) have no file
                sources.append(WorkflowSource(path=path, id=w.get("id"), name=str(w.get("name") or ""), state=str(w.get("state") or "active"), url=str(w.get("html_url") or "")))
    else:
        sources = [WorkflowSource(path=p) for p in (known_paths or []) if WORKFLOW_FILE.match(p)]
    if len(sources) > MAX_WORKFLOWS:
        out.errors.append(f"GitHub: {len(sources)} workflows; only the first {MAX_WORKFLOWS} were read")
        sources = sources[:MAX_WORKFLOWS]

    # 2. workflow files
    async def fetch(src: WorkflowSource) -> None:
        try:
            src.text = await _text(client, full, src.path, branch)
        except Exception as e:  # noqa: BLE001
            src.error = reason_for(e, f"workflow file {src.path}", "Contents: read")
            out.errors.append(src.error)

    await asyncio.gather(*(fetch(s) for s in sources if s.state != "deleted"))
    out.workflows = sources
    have = {s.path: s.text for s in sources if s.text is not None}

    # 3. reusable workflows, one level deep, same GitHub host only (the client refuses other hosts)
    wanted: list[str] = []
    for s in sources:
        for u in reusable_refs(s.text or ""):
            if u not in wanted:
                wanted.append(u)

    async def fetch_reusable(uses: str) -> None:
        try:
            if uses.startswith("./"):
                path = uses[2:]
                out.reusable[uses] = have[path] if path in have else await _text(client, full, path, branch)
                return
            m = REUSABLE_PATH.match(uses)
            if not m or not FULL_NAME.match(m["repo"]) or ".." in m["path"]:
                raise ValueError("not a valid reusable workflow reference")
            out.reusable[uses] = await _text(client, _repo_path(m["repo"]), m["path"], m["ref"])
        except Exception as e:  # noqa: BLE001
            out.reusable[uses] = None
            out.reusable_errors[uses] = reason_for(e, f"reusable workflow {uses}", "Contents: read") if isinstance(e, Exception) and not isinstance(e, ValueError) else str(e)
            out.errors.append(out.reusable_errors[uses])

    for u in wanted[MAX_REUSABLE:]:
        out.reusable[u] = None
        out.reusable_errors[u] = f"not fetched: more than {MAX_REUSABLE} reusable workflows in this repository"
    if wanted[MAX_REUSABLE:]:
        out.errors.append(f"GitHub: {len(wanted)} reusable workflows referenced; only {MAX_REUSABLE} were fetched")
    await asyncio.gather(*(fetch_reusable(u) for u in wanted[:MAX_REUSABLE]))

    # 4. last deployment per environment: the configured ones, plus those named by the workflows when the list is unreadable
    names: list[str] = list(out.environments or {})
    if out.environments is None:
        for s in sources:
            names += [n for n in environment_names(s.text or "") if n not in names]
    names = names[:MAX_ENVIRONMENTS]
    deps = await asyncio.gather(*(_last_deployment(client, full, n) for n in names))
    for d in deps:
        out.deployments[d.environment.casefold()] = d
        if d.error:
            out.errors.append(d.error)
    return out
