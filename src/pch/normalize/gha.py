"""GitHub Actions workflows -> canonical ``Pipeline(platform="gha")`` (pure functions, no I/O).

Mapping (mirrors ``collectors/ado/yaml_pipeline.py``; the rule-by-rule meaning is ADR-17):

* workflow file -> Pipeline; ``on:`` -> ``triggers`` (+ ``meta.events``); top-level ``permissions`` -> ``meta.permissions``
* job -> Stage (``needs`` -> ``depends_on``); a job with ``environment:`` is a deployment stage; ``runs-on`` -> pool / self_hosted
* step ``uses`` -> task ``owner/repo@ref`` (+ ``ref_kind``: sha / tag / branch / local / docker), ``with`` -> inputs; ``run`` -> inline script
* a job that calls a reusable workflow (``uses: ./.github/workflows/x.yml`` or ``org/repo/.github/workflows/x.yml@ref``) gets the callee's steps
  (one level deep, ids prefixed ``callee:``); an unresolved callee is recorded in ``meta.unresolved`` and makes dependent rules UNKNOWN
* environment protection (required reviewers, prevent_self_review, wait timer, branch policy, custom deployment protection rules such as
  ServiceNow) -> ``Approval`` objects and ``branch_filters`` on the deployment stage
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

import yaml

from pch.collectors.ado.deployments import short_sha
from pch.collectors.ado.lineage_meta import MAX_ITEMS, MAX_TEXT
from pch.collectors.ado.runs import parse_dt
from pch.collectors.redact import SECRET_NAME, value_looks_secret
from pch.model.gha import ActionsRead, GhDeployment, GhEnvironment, WorkflowSource
from pch.model.lineage import LDeploy, LLink, LPipeline, LTrigger
from pch.model.pipeline import (
    PROTECTED_BRANCHES,
    Approval,
    Job,
    Pipeline,
    RunStats,
    RunSummary,
    Stage,
    Step,
    Variable,
)
from pch.model.repo import RepoRef
from pch.normalize.capabilities import classify_pipeline
from pch.normalize.lineage import is_deploy_stage, lstage
from pch.normalize.target_detect import enrich_pipeline

MAX_WORKFLOW_BYTES = 512 * 1024
MAX_ALIASES = 50
PUBLIC_EVENTS = frozenset({
    "pull_request", "pull_request_target", "issues", "issue_comment", "discussion", "discussion_comment", "fork", "watch",
    "pull_request_review", "pull_request_review_comment",
})
FULL_SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$", re.I)
TAG_LIKE = re.compile(r"^v?\d+([.\-_][\w.\-]+)*$")
GITHUB_HOSTED = re.compile(r"^(ubuntu|windows|macos)(-|$)", re.I)
SECRET_REF = re.compile(r"\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)")
EXPR = re.compile(r"^\$\{\{\s*(.*?)\s*\}\}$", re.S)
REUSABLE_PATH = re.compile(r"^(?P<repo>[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+)/(?P<path>\.github/workflows/[^@\s]+\.ya?ml)@(?P<ref>\S+)$")
SECRET_CREDENTIAL_INPUTS = ("creds", "client-secret", "aws-secret-access-key", "credentials_json", "password")
DEFAULT_SNOW_PATTERN = r"(?i)servicenow|snow"
COUNTED = {"success", "failure", "cancelled", "timed_out", "startup_failure"}
FAILED = {"failure", "timed_out", "startup_failure"}


class WorkflowError(Exception):
    """The workflow file cannot be read as a workflow (invalid YAML, too large, not a mapping). Becomes UNKNOWN, never FAIL."""


# --------------------------------------------------------------------------- yaml
def load_workflow_yaml(text: str) -> dict[str, Any]:
    if len(text.encode("utf-8", "ignore")) > MAX_WORKFLOW_BYTES:
        raise WorkflowError(f"workflow file is larger than {MAX_WORKFLOW_BYTES // 1024} KB")
    if len(re.findall(r"(?m)(?:^|[\s:\-\[,])\*[A-Za-z_][\w-]*", text)) > MAX_ALIASES:
        raise WorkflowError("workflow file uses too many YAML aliases to be parsed safely")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        raise WorkflowError("workflow file is not valid YAML") from None
    if not isinstance(doc, dict):
        raise WorkflowError("workflow file is not a YAML mapping")
    if "on" not in doc and True in doc:  # YAML 1.1: a bare `on:` key is the boolean True
        doc["on"] = doc.pop(True)
    return doc


def reusable_refs(text: str) -> list[str]:
    """Job-level ``uses:`` values (reusable workflows called by this workflow), in order, without duplicates. Invalid files give []."""
    try:
        doc = load_workflow_yaml(text)
    except WorkflowError:
        return []
    out: list[str] = []
    for job in _map(doc.get("jobs")).values():
        u = job.get("uses") if isinstance(job, dict) else None
        if isinstance(u, str) and u not in out and (u.startswith("./.github/workflows/") or REUSABLE_PATH.match(u)):
            out.append(u)
    return out


# --------------------------------------------------------------------------- uses / refs
def parse_uses(uses: str) -> tuple[str | None, str]:
    """(ref, kind) of a step's ``uses`` value. kind: sha | tag | branch | local | docker."""
    if uses.startswith("./") or uses.startswith("../"):
        return None, "local"
    if uses.startswith("docker://"):
        rest = uses[len("docker://"):]
        if "@sha256:" in rest:
            return rest.split("@", 1)[1], "sha"
        tag = rest.rsplit(":", 1)[1] if ":" in rest.rsplit("/", 1)[-1] else ""
        return (tag or None), ("tag" if tag and tag != "latest" else "branch")
    if "@" not in uses:
        return None, "branch"
    ref = uses.rsplit("@", 1)[1]
    if FULL_SHA.match(ref):
        return ref, "sha"
    return ref, ("tag" if TAG_LIKE.match(ref) else "branch")


def owner_of(uses: str) -> str:
    return uses.split("/", 1)[0].lower()


# --------------------------------------------------------------------------- permissions
def _perms(raw: Any) -> dict[str, str] | str | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw.strip()
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    return None


def effective_permissions(job: dict[str, str] | str | None, top: dict[str, str] | str | None) -> dict[str, str] | str | None:
    return job if job is not None else top


def write_scopes(perms: dict[str, str] | str | None) -> list[str]:
    """Scopes with write access ("*" for write-all)."""
    if perms == "write-all":
        return ["*"]
    if isinstance(perms, dict):
        return sorted(k for k, v in perms.items() if v == "write")
    return []


def id_token_write(perms: dict[str, str] | str | None) -> bool:
    return perms == "write-all" or (isinstance(perms, dict) and perms.get("id-token") == "write")


# --------------------------------------------------------------------------- triggers
def _events(on: Any) -> dict[str, Any]:
    if on is None:
        return {}
    if isinstance(on, str):
        return {on: {}}
    if isinstance(on, list):
        return {str(x): {} for x in on}
    if isinstance(on, dict):
        return {str(k): (v if v is not None else {}) for k, v in on.items()}
    return {}


def _strs(v: Any) -> list[str]:
    if isinstance(v, str):
        return [v[:MAX_TEXT]]
    if isinstance(v, list):
        return [str(x)[:MAX_TEXT] for x in v if isinstance(x, str | int | float)][:MAX_ITEMS]
    return []


def _filters(cfg: Any, key: str = "branches") -> list[str]:
    if not isinstance(cfg, dict):
        return []
    inc = _strs(cfg.get(key))
    exc = [f"!{x}" for x in _strs(cfg.get(f"{key}-ignore"))]
    return (inc + exc)[:MAX_ITEMS]


def triggers_of(ev: dict[str, Any], path: str) -> dict[str, Any]:
    push, pr = ev.get("push"), ev.get("pull_request", ev.get("pull_request_target"))
    wr = ev.get("workflow_run")
    sched = ev.get("schedule")
    push_branches = _filters(push)
    return {
        "events": sorted(ev), "branches": [b for b in push_branches if not b.startswith("!")], "push_branches": push_branches,
        "push_tags": _strs(push.get("tags")) if isinstance(push, dict) else [], "push_paths": _filters(push, "paths"),
        "pr_branches": _filters(pr), "workflow_dispatch": "workflow_dispatch" in ev,
        "schedules": [str(s.get("cron"))[:MAX_TEXT] for s in sched if isinstance(s, dict) and s.get("cron")] if isinstance(sched, list) else [],
        "workflow_run": _strs(wr.get("workflows")) if isinstance(wr, dict) else [],
        "workflow_run_branches": _filters(wr), "workflow_run_types": _strs(wr.get("types")) if isinstance(wr, dict) else [],
        "yamlFilename": path,
    }


# --------------------------------------------------------------------------- variables / steps / jobs
def _env_variables(env: Any, source: str) -> list[Variable]:
    out: list[Variable] = []
    if not isinstance(env, dict):
        return out
    for k, v in env.items():
        name = str(k)
        if isinstance(v, bool) or v is None:
            continue
        val = str(v)
        reason = None
        if val.startswith("${{") or not val or len(val) <= 3 or val.lower() in ("true", "false", "null"):
            reason = None  # an expression (a secret or variable reference) or a flag: nothing literal to flag
        elif SECRET_NAME.search(name):
            reason = "name looks secret-like and a literal value is set in YAML"
        else:
            reason = value_looks_secret(val)
        out.append(Variable(name=name, is_secret=False, secret_like_reason=reason, source=source))
    return out


def _map(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() == "true"


def _condition(raw: dict[str, Any]) -> str | None:
    if "if" not in raw:
        return None
    s = str(raw["if"]).strip()
    m = EXPR.match(s)
    return (m.group(1) if m else s) or None


def _step(raw: dict[str, Any], idx: str, job_continue: bool) -> Step | None:
    if not isinstance(raw, dict):
        return None
    name = str(raw.get("name") or "")
    common: dict[str, Any] = {
        "id": idx, "enabled": True, "continue_on_error": _truthy(raw.get("continue-on-error")) or job_continue, "condition": _condition(raw),
    }
    env = raw.get("env") if isinstance(raw.get("env"), dict) else {}
    uses = raw.get("uses")
    if isinstance(uses, str) and uses.strip():
        uses = uses.strip()
        ref, kind = parse_uses(uses)
        inputs = dict(raw.get("with") or {}) if isinstance(raw.get("with"), dict) else {}
        if env:
            inputs["$env"] = {str(k): str(v) for k, v in env.items()}
        return Step(
            name=name or uses.split("@")[0], task=uses, task_version=ref if kind in ("sha", "tag") else None, inputs=inputs, ref_kind=kind,  # type: ignore[arg-type]
            marketplace=kind not in ("local", "docker"), **common,
        )
    run = raw.get("run")
    if isinstance(run, str) and run.strip():
        return Step(name=name or run.strip().splitlines()[0][:60], task="script", inline_script=run, inputs={"$env": {str(k): str(v) for k, v in env.items()}} if env else {}, **common)
    return None


def _runner(runs_on: Any) -> tuple[str | None, bool | None]:
    """(pool label, self-hosted?). Custom labels that are neither ``self-hosted`` nor a GitHub-hosted image are unknown (larger hosted runners use custom names)."""
    labels: list[str] = []
    group = None
    if isinstance(runs_on, str):
        labels = [runs_on]
    elif isinstance(runs_on, list):
        labels = [str(x) for x in runs_on]
    elif isinstance(runs_on, dict):
        group = runs_on.get("group")
        raw_labels = runs_on.get("labels")
        labels = [str(x) for x in (raw_labels if isinstance(raw_labels, list) else [raw_labels] if raw_labels else [])]
    if group:
        return f"group:{group}", True
    if not labels:
        return None, None
    pool = ",".join(labels)[:MAX_TEXT]
    if any("${{" in x for x in labels):
        return pool, None
    if any(x.lower() == "self-hosted" for x in labels):
        return pool, True
    if all(GITHUB_HOSTED.match(x) for x in labels):
        return pool, False
    return pool, None


def _env_name(env: Any) -> str | None:
    if isinstance(env, dict):
        env = env.get("name")
    return str(env).strip() if isinstance(env, str | int) and str(env).strip() else None


def _needs(raw: Any) -> list[str]:
    if isinstance(raw, str):
        return [raw]
    return [str(x) for x in raw] if isinstance(raw, list) else []


def _flatten_callee(text: str, prefix: str) -> tuple[list[Step], str | None, list[str]]:
    """(steps, first environment, notes) of a reusable workflow's jobs. Nested reusable calls are not followed (one level only)."""
    notes: list[str] = []
    doc = load_workflow_yaml(text)
    steps: list[Step] = []
    env: str | None = None
    for jid, job in _map(doc.get("jobs")).items():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get("uses"), str):
            notes.append(f"{prefix}: nested reusable workflow '{job['uses']}' is not followed (one level only)")
            continue
        env = env or _env_name(job.get("environment"))
        cof = _truthy(job.get("continue-on-error"))
        for i, raw in enumerate(job.get("steps") or []):
            s = _step(raw, f"callee:{prefix}.{jid}.{i}", cof)
            if s is not None:
                s.name = f"{prefix}: {s.name}"[:120]
                steps.append(s)
    return steps, env, notes


def _auth_caps(job: Job, eff: dict[str, str] | str | None) -> None:
    """Tag cloud-login steps ``auth:secret`` (long-lived credential input) or ``auth:oidc`` (federation: ``id-token: write`` and no credential)."""
    for s in job.steps:
        if "auth:login" not in s.capabilities:
            continue
        low = {str(k).lower(): v for k, v in s.inputs.items()}
        if any(low.get(k) not in (None, "") for k in SECRET_CREDENTIAL_INPUTS):
            s.capabilities.add("auth:secret")
        elif id_token_write(eff):
            s.capabilities.add("auth:oidc")


# --------------------------------------------------------------------------- workflow -> pipeline
def parse_workflow(src: WorkflowSource, *, project: str, repo: str, callees: dict[str, str | None] | None = None,
                   callee_errors: dict[str, str] | None = None) -> Pipeline:
    """Normalise one workflow file. Raises ``WorkflowError`` when the file is unusable (the caller records it as unreadable)."""
    if src.text is None:
        raise WorkflowError(src.error or "workflow file could not be read")
    doc = load_workflow_yaml(src.text)
    callees, callee_errors = callees or {}, callee_errors or {}
    ev = _events(doc.get("on"))
    top_perms = _perms(doc.get("permissions")) if "permissions" in doc else None
    jobs_raw = _map(doc.get("jobs"))
    variables = _env_variables(doc.get("env"), "workflow")
    unresolved: list[str] = []
    stages: list[Stage] = []
    for jid, raw in jobs_raw.items():
        if not isinstance(raw, dict):
            continue
        jid = str(jid)
        variables += _env_variables(raw.get("env"), "job")
        jp = _perms(raw.get("permissions")) if "permissions" in raw else None
        pool, shosted = _runner(raw.get("runs-on"))
        cof = _truthy(raw.get("continue-on-error"))
        env = _env_name(raw.get("environment"))
        steps: list[Step] = []
        uses_wf = raw.get("uses") if isinstance(raw.get("uses"), str) else None
        if uses_wf:
            text = callees.get(uses_wf)
            if text is None:
                unresolved.append(f"{uses_wf}: {callee_errors.get(uses_wf) or 'reusable workflow was not resolved'}")
            else:
                try:
                    steps, cenv, notes = _flatten_callee(text, uses_wf.rsplit("/", 1)[-1].split("@")[0])
                    env = env or cenv
                    unresolved += notes
                except WorkflowError as e:
                    unresolved.append(f"{uses_wf}: {e}")
        for i, sraw in enumerate(raw.get("steps") or []):
            if isinstance(sraw, dict):
                variables += _env_variables(sraw.get("env"), "step")
            s = _step(sraw, f"{jid}.{i}", cof)
            if s is not None:
                steps.append(s)
        job = Job(name=str(raw.get("name") or jid)[:MAX_TEXT], kind="deployment" if env else "job", pool=pool, self_hosted=shosted, steps=steps,
                  permissions=jp, uses_workflow=uses_wf)
        stages.append(Stage(name=jid, env_name=env, depends_on=_needs(raw.get("needs")), jobs=[job], is_deploy=bool(env)))
    text_secrets = sorted({m for m in SECRET_REF.findall(src.text) if m != "GITHUB_TOKEN"})
    pools = [j.self_hosted for st in stages for j in st.jobs if j.self_hosted is not None]
    pool_type = "unknown" if not pools else ("mixed" if len(set(pools)) > 1 else ("self-hosted" if pools[0] else "hosted"))
    trig = triggers_of(ev, src.path)
    p = Pipeline(
        platform="gha", id=f"gha:{src.id}" if src.id is not None else f"gha:{src.path}", name=str(doc.get("name") or src.path.rsplit("/", 1)[-1])[:MAX_TEXT],
        project=project, repo=repo, url=src.url, definition_in_source_control=True, triggers=trig, variables=variables, stages=stages,
        pool_type=pool_type, artifact_branch_filters=trig["branches"], raw_ref=src.path,
        meta={
            "path": src.path, "state": src.state, "workflow_id": src.id, "events": sorted(ev), "permissions": top_perms,
            "callable_only": bool(ev) and set(ev) <= {"workflow_call"}, "public_trigger": bool(set(ev) & PUBLIC_EVENTS),
            "workflow_run": trig["workflow_run"], "unresolved": unresolved, "secrets_used": text_secrets,
            "reusable": sorted({j.uses_workflow for st in stages for j in st.jobs if j.uses_workflow}),
        },
    )
    classify_pipeline(p)
    for st in p.stages:
        for j in st.jobs:
            _auth_caps(j, effective_permissions(j.permissions, top_perms))
    return p


def apply_environments(p: Pipeline, envs: dict[str, GhEnvironment] | None, snow_pattern: str = DEFAULT_SNOW_PATTERN) -> None:
    """Environment protection -> approvals / gates / branch filters of the deployment stages. ``envs`` is keyed by lower-cased name; None = not readable."""
    snow = re.compile(snow_pattern)
    unknown: dict[str, list[str]] = {"all": [], "custom": [], "branch": []}
    for st in p.stages:
        if not st.env_name:
            continue
        if envs is None or "${{" in st.env_name:
            unknown["all"].append(st.name)
            continue
        e = envs.get(st.env_name.casefold())
        if e is None:
            continue  # the environment is not configured: it has no protection (GitHub creates it unprotected on first use)
        if e.required_reviewers:
            st.pre_approvals.append(Approval(
                kind="manual", approvers=list(e.reviewers), min_approvers=1, requester_can_approve=not bool(e.prevent_self_review),  # VERIFY: prevent_self_review absent = false
                name=f"environment {e.name}: required reviewers",
            ))
        if e.wait_timer:
            st.gates.append(Approval(kind="other", name=f"wait timer {e.wait_timer} min", timeout_minutes=e.wait_timer))
        for r in e.custom_rules:
            if r.enabled:
                st.gates.append(Approval(kind="servicenow" if snow.search(f"{r.slug} {r.name}") else "gate", name=(r.name or r.slug)[:MAX_TEXT]))
        if e.custom_error:
            unknown["custom"].append(st.name)
        if e.branch_policy == "protected":
            st.branch_filters = [PROTECTED_BRANCHES]
            st.gates.append(Approval(kind="branch_control", branches=[PROTECTED_BRANCHES], name=f"environment {e.name}: protected branches only"))
        elif e.branch_policy == "custom":
            if e.branch_error:
                unknown["branch"].append(st.name)
            else:
                st.branch_filters = list(e.branch_patterns)
                st.gates.append(Approval(kind="branch_control", branches=list(e.branch_patterns), name=f"environment {e.name}: deployment branches"))
    if any(unknown.values()):
        p.meta["env_unknown"] = {k: sorted(set(v)) for k, v in unknown.items()}


def env_unreadable(p: Pipeline, st: Stage, what: str = "all") -> bool:
    """True when the environment protection of this deployment stage could not be read (rules answer UNKNOWN). ``what``: all | custom | branch."""
    unk = p.meta.get("env_unknown") or {}
    return st.name in unk.get("all", []) or (what != "all" and st.name in unk.get(what, []))


# --------------------------------------------------------------------------- run history
def _when(run: dict[str, Any]) -> datetime | None:
    return parse_dt(run.get("updated_at") or run.get("created_at"))


def apply_runs(pipelines: list[Pipeline], read: ActionsRead) -> None:
    """Per workflow: 90-day RunStats and the last completed run. Not readable -> stats stay None (HYG rules UNKNOWN)."""
    if read.runs is None:
        for p in pipelines:
            p.notes.append(read.runs_error or "run history was not read")
        return
    for p in pipelines:
        wid, path = p.meta.get("workflow_id"), p.meta.get("path") or ""
        mine = [r for r in read.runs if (wid is not None and r.get("workflow_id") == wid) or (wid is None and str(r.get("path") or "").split("@", 1)[0] == path)]
        if not mine and read.runs_truncated:
            p.notes.append("run history is truncated (only the newest runs were read) and this workflow is not among them")
            continue
        st = RunStats()
        last_t: datetime | None = None
        for r in mine:
            if r.get("status") != "completed":
                continue
            concl = str(r.get("conclusion") or "")
            t = _when(r)
            if concl in COUNTED:
                st.total += 1
                if concl == "success":
                    st.succeeded += 1
                    if t and (st.last_success is None or t > st.last_success):
                        st.last_success = t
                elif concl in FAILED:
                    st.failed += 1
            if t and (last_t is None or t > last_t):
                last_t = t
                p.last_run = RunSummary(status=concl or "unknown", finished=t, branch=r.get("head_branch"), url=r.get("html_url"))
                p.meta["last_run_number"] = r.get("run_number")
                actor = r.get("actor")
                p.meta["last_run_by"] = (actor.get("login") if isinstance(actor, dict) else actor) or None
        p.run_stats_90d = st


# --------------------------------------------------------------------------- the whole repo
def build_pipelines(read: ActionsRead, *, project: str, repo: str, tier_overrides: dict[str, str] | None = None, snow_pattern: str = DEFAULT_SNOW_PATTERN,
                    repo_is_adf: bool = False, repo_is_synapse: bool = False) -> tuple[list[Pipeline], list[str]]:
    """(pipelines, unreadable): every readable workflow as a Pipeline; ``unreadable`` lists the reasons for workflow files that could not be used
    (the repo's context carries them so that rules which would FAIL on missing steps answer UNKNOWN instead)."""
    pipelines: list[Pipeline] = []
    unreadable: list[str] = []
    envs = {k.casefold(): v for k, v in read.environments.items()} if read.environments is not None else None
    for src in read.workflows:
        if src.state == "deleted":
            continue
        try:
            p = parse_workflow(src, project=project, repo=repo, callees=read.reusable, callee_errors=read.reusable_errors)
        except WorkflowError as e:
            unreadable.append(f"{src.path}: {e}")
            continue
        enrich_pipeline(p, repo_is_adf, repo_is_synapse, tier_overrides)
        apply_environments(p, envs, snow_pattern)
        pipelines.append(p)
    apply_runs(pipelines, read)
    if read.list_error and not read.workflows:
        unreadable.append(read.list_error)
    return pipelines, unreadable


# --------------------------------------------------------------------------- lineage
DEPLOY_STATE = {"success": "succeeded", "failure": "failed", "error": "failed", "in_progress": "in_progress", "queued": "pending", "pending": "pending"}


def ldeploy_of(d: GhDeployment | None, collected: bool) -> LDeploy:
    if d is None:
        return LDeploy(status="unknown", note="not collected" if not collected else "deployments were not read")
    if d.error:
        return LDeploy(status="unknown", note=d.error[:MAX_TEXT])
    if d.never:
        return LDeploy(status="never")
    status = DEPLOY_STATE.get(d.status, "unknown")
    note = "superseded by a newer deployment (state inactive)" if d.status == "inactive" else None
    return LDeploy(status=status, version=str(d.id) if d.id is not None else None, artifact_version=short_sha(d.sha), finished=parse_dt(d.finished), triggered_by=d.creator,  # type: ignore[arg-type]
                   url=d.url, note=note)


def _artifacts(p: Pipeline) -> list[str]:
    out: list[str] = []
    for s in p.all_steps():
        low = {str(k).lower(): v for k, v in s.inputs.items()}
        name = (s.task or "").split("@")[0].lower()
        label = None
        if name == "actions/upload-artifact":
            label = f"artifact: {str(low.get('name') or 'artifact')[:MAX_TEXT]}"
        elif name == "docker/build-push-action" and "container:push" in s.capabilities:
            label = f"image: {str(low.get('tags') or '').splitlines()[0][:MAX_TEXT]}" if low.get("tags") else "image"
        if label and label not in out:
            out.append(label)
    return out[:MAX_ITEMS]


def build_lineage(pipelines: list[Pipeline], ref: RepoRef, deployments: dict[str, GhDeployment], collected: bool = True) -> list[LPipeline]:
    """Workflows as lineage pipelines: triggers, ``workflow_run`` links within the repo (``workflow_run`` only fires inside one repository),
    deployment jobs as stages with the last deployment of their environment (Deployments API)."""
    out: list[LPipeline] = []
    for p in pipelines:
        t = p.triggers
        events = set(p.meta.get("events") or [])
        lt = LTrigger(
            ci_enabled="push" in events, ci_branches=list(t.get("push_branches") or []), ci_paths=list(t.get("push_paths") or []),
            pr_enabled=bool(events & {"pull_request", "pull_request_target"}), pr_branches=list(t.get("pr_branches") or []), schedules=list(t.get("schedules") or []),
        )
        stages = [lstage(st, {}, ldeploy_of(deployments.get((st.env_name or "").casefold()) if st.env_name else None, collected)) for st in p.stages if is_deploy_stage(st)]
        last = None
        if p.last_run is not None:
            last = LDeploy(status=_run_status(p.last_run.status), version=str(p.meta.get("last_run_number") or "") or None, finished=p.last_run.finished,
                           triggered_by=p.meta.get("last_run_by"), url=p.last_run.url)
        out.append(LPipeline(id=p.id, name=p.name, kind="gha", url=p.url, definition_path=str(p.meta.get("path") or ""), yaml_repo=ref.name, trigger=lt,
                             artifacts=_artifacts(p), stages=stages, last_run=last))
    by_name = {lp.name.casefold(): lp for lp in out}
    pipe_by_id = {p.id: p for p in pipelines}
    for lp in out:
        names = pipe_by_id[lp.id].meta.get("workflow_run") or []
        branches = pipe_by_id[lp.id].triggers.get("workflow_run_branches") or []
        for n in names:
            target = by_name.get(str(n).casefold())
            detail = "on completion" + (f" ({', '.join(branches)})" if branches else "")
            lp.upstream.append(LLink(kind="workflow_run", name=target.name if target else str(n), pipeline_id=target.id if target else None, project=ref.project,
                                     repo_key=ref.key if target else None, url=target.url if target else "", detail=detail))
            if target is not None and target is not lp:
                target.downstream.append(LLink(kind="workflow_run", name=lp.name, pipeline_id=lp.id, project=ref.project, repo_key=ref.key, url=lp.url, detail=detail))
    return out


def _run_status(conclusion: str) -> Any:
    return {"success": "succeeded", "failure": "failed", "timed_out": "failed", "startup_failure": "failed", "cancelled": "canceled"}.get(conclusion, "unknown")



def environment_names(text: str) -> list[str]:
    """Static environment names used by the jobs of a workflow (dynamic ``${{ }}`` names are skipped). Invalid files give []."""
    try:
        doc = load_workflow_yaml(text)
    except WorkflowError:
        return []
    out: list[str] = []
    for job in _map(doc.get("jobs")).values():
        n = _env_name(job.get("environment")) if isinstance(job, dict) else None
        if n and "${{" not in n and n not in out:
            out.append(n)
    return out
