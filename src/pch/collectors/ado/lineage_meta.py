"""Pipeline metadata for the lineage view: triggers, resource links and published artifacts.

Pure functions over data the scan already holds (raw classic build definitions, expanded YAML text, normalized steps).
Nothing here talks to Azure DevOps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

from pch.model.lineage import LLink, LTrigger
from pch.model.pipeline import Step

MAX_ITEMS = 20
MAX_TEXT = 120


def clean_branch(b: Any) -> str:
    """ADO branch filter ("+refs/heads/main", "-refs/heads/old", "main") -> "main" / "!old"."""
    s = str(b or "").strip()
    neg = s.startswith("-")
    s = s.lstrip("+-").removeprefix("refs/heads/").removeprefix("refs/tags/")
    return (f"!{s}" if neg else s)[:MAX_TEXT]


def _branches(v: Any) -> list[str]:
    if isinstance(v, str):
        return [clean_branch(v)] if v else []
    if isinstance(v, list):
        return [clean_branch(x) for x in v if isinstance(x, str)][:MAX_ITEMS]
    if isinstance(v, dict):
        inc = [clean_branch(x) for x in v.get("include") or [] if isinstance(x, str)]
        exc = [f"!{clean_branch(x)}" for x in v.get("exclude") or [] if isinstance(x, str)]
        return (inc + exc)[:MAX_ITEMS]
    return []


def _paths(v: Any) -> list[str]:
    if isinstance(v, dict):
        inc = [str(x).lstrip("+")[:MAX_TEXT] for x in v.get("include") or []]
        exc = [f"!{str(x).lstrip('+-')[:MAX_TEXT]}" for x in v.get("exclude") or []]
        return (inc + exc)[:MAX_ITEMS]
    if isinstance(v, list):
        return [str(x).lstrip("+-")[:MAX_TEXT] for x in v][:MAX_ITEMS]
    return []


def _time(h: Any, m: Any) -> str:
    try:
        return f"{int(h):02d}:{int(m):02d}"
    except (TypeError, ValueError):
        return ""


# ------------------------------------------------------------------ artifacts
def _artifact_from(task: str, inputs: dict[str, Any]) -> str | None:
    """Label of what a publishing step produces, or None when the step publishes nothing."""
    low = {str(k).lower(): v for k, v in inputs.items()}
    name = task.split("@")[0].lower()
    if name == "publishpipelineartifact":
        v = low.get("artifact") or low.get("artifactname") or low.get("targetpath")
        return f"artifact: {str(v)[:MAX_TEXT]}" if v else "artifact"
    if name == "publishbuildartifacts":
        return f"artifact: {str(low.get('artifactname') or 'drop')[:MAX_TEXT]}"
    if name == "docker" and str(low.get("command", "")).lower() in ("push", "buildandpush"):
        repo = low.get("repository") or low.get("containerregistry")
        return f"image: {str(repo)[:MAX_TEXT]}" if repo else "image"
    if name == "nugetcommand" and str(low.get("command", "")).lower() == "push":
        return "package: nuget"
    if name == "npm" and str(low.get("command", "")).lower() == "publish":
        return "package: npm"
    return None


def artifacts_from_steps(steps: list[Step]) -> list[str]:
    out: list[str] = []
    for s in steps:
        if not s.enabled or not s.task:
            continue
        a = _artifact_from(s.task, s.inputs)
        if a and a not in out:
            out.append(a)
    return out[:MAX_ITEMS]


# ------------------------------------------------------------------ classic build definitions
def classic_build_meta(defn: dict[str, Any]) -> tuple[LTrigger, list[LLink]]:
    """Triggers + build-completion upstream links of a classic build definition (``triggers[]``)."""
    t = LTrigger(ci_enabled=False, pr_enabled=False)
    upstream: list[LLink] = []
    for trig in defn.get("triggers") or []:
        kind = str(trig.get("triggerType") or "").lower()
        if kind == "continuousintegration":
            t.ci_enabled = True
            t.ci_branches = [clean_branch(b) for b in trig.get("branchFilters") or []][:MAX_ITEMS]
            t.ci_paths = [(f"!{str(p).lstrip('-')}" if str(p).startswith("-") else str(p).lstrip("+"))[:MAX_TEXT] for p in trig.get("pathFilters") or []][:MAX_ITEMS]
        elif kind == "pullrequest":
            t.pr_enabled = True
            t.pr_branches = [clean_branch(b) for b in trig.get("branchFilters") or []][:MAX_ITEMS]
        elif kind == "schedule":
            for sc in trig.get("schedules") or []:
                days = sc.get("daysToBuild")
                label = f"{_time(sc.get('startHours'), sc.get('startMinutes'))} {sc.get('timeZoneId') or 'UTC'}".strip()
                if isinstance(days, str) and days.lower() not in ("all", "none", ""):
                    label += f" ({days})"
                br = ", ".join(clean_branch(b) for b in sc.get("branchFilters") or [])
                t.schedules.append((label + (f" on {br}" if br else "")).strip()[:MAX_TEXT])
        elif kind == "buildcompletion":
            d = trig.get("definition") or {}
            if d.get("id") is not None or d.get("name"):
                br = ", ".join(clean_branch(b) for b in trig.get("branchFilters") or [])
                upstream.append(LLink(kind="classic_completion", name=str(d.get("name") or d.get("id"))[:MAX_TEXT], pipeline_id=str(d.get("id")) if d.get("id") is not None else None,
                                      project=(d.get("project") or {}).get("name"), detail=("on completion" + (f" of {br}" if br else "") + ("" if trig.get("requiresSuccessfulBuild", True) else " (even if failed)"))))
    t.schedules = t.schedules[:MAX_ITEMS]
    return t, upstream


# ------------------------------------------------------------------ YAML
@dataclass
class YamlMeta:
    trigger: LTrigger = field(default_factory=LTrigger)
    repositories: dict[str, dict[str, str]] = field(default_factory=dict)  # alias -> {type, name, ref}
    upstream: list[LLink] = field(default_factory=list)  # resources.pipelines
    checkouts: list[str] = field(default_factory=list)  # aliases seen in `checkout:` steps ("self" included)
    artifacts: list[str] = field(default_factory=list)

    def code_repos(self) -> list[tuple[str, str]]:
        """(type, name) of repositories checked out besides ``self``."""
        out: list[tuple[str, str]] = []
        for alias in self.checkouts:
            r = self.repositories.get(alias)
            if r and alias != "self":
                out.append((r.get("type", "git"), r.get("name", alias)))
        return out

    def yaml_in_other_repo(self) -> bool:
        return bool(self.code_repos()) and "self" not in self.checkouts

    def template_repos(self) -> list[str]:
        return [r.get("name", a) for a, r in self.repositories.items() if a not in self.checkouts]


def _walk_steps(node: Any, out: list[dict[str, Any]], depth: int = 0) -> None:
    """Collect every step-like mapping (has checkout/task/publish/script keys) in the document."""
    if depth > 12:
        return
    if isinstance(node, dict):
        if any(k in node for k in ("checkout", "task", "publish")):
            out.append(node)
        for k, v in node.items():
            if k not in ("inputs", "variables", "parameters", "env"):
                _walk_steps(v, out, depth + 1)
    elif isinstance(node, list):
        for v in node:
            _walk_steps(v, out, depth + 1)


def parse_yaml_meta(final_yaml: str, external_pr_default: bool = False) -> YamlMeta | None:
    """Triggers, resources and publishing steps from the expanded YAML. ``None`` when it is not parseable.

    ``external_pr_default``: the code is on GitHub/Bitbucket, where an absent ``pr:`` means "validate every PR"; for
    Azure Repos PR validation is a branch policy (not in the YAML) so it stays undetermined."""
    try:
        doc = yaml.safe_load(final_yaml)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None
    m = YamlMeta()
    t = m.trigger
    trig = doc.get("trigger", "__absent__")
    if trig == "__absent__":
        t.ci_enabled = True  # default: every branch
    elif trig in (None, "none") or (isinstance(trig, str) and trig.lower() == "none"):
        t.ci_enabled = False
    elif trig is False:
        t.ci_enabled = False
    else:
        t.ci_enabled = True
        if isinstance(trig, dict):
            t.ci_branches = _branches(trig.get("branches"))
            t.ci_paths = _paths(trig.get("paths"))
        else:
            t.ci_branches = _branches(trig)
    pr = doc.get("pr", "__absent__")
    if pr == "__absent__":
        t.pr_enabled = True if external_pr_default else None
    elif pr in (None, "none") or pr is False or (isinstance(pr, str) and pr.lower() == "none"):
        t.pr_enabled = False
    else:
        t.pr_enabled = True
        t.pr_branches = _branches(pr.get("branches") if isinstance(pr, dict) else pr)
    for sc in doc.get("schedules") or []:
        if isinstance(sc, dict) and sc.get("cron"):
            br = ", ".join(_branches(sc.get("branches")))
            t.schedules.append((f"{str(sc['cron'])[:40]}" + (f" on {br}" if br else "") + ("" if sc.get("always") else " (only with changes)"))[:MAX_TEXT])
    t.schedules = t.schedules[:MAX_ITEMS]
    res: dict[str, Any] = doc["resources"] if isinstance(doc.get("resources"), dict) else {}
    for r in res.get("repositories") or []:
        if isinstance(r, dict) and r.get("repository"):
            m.repositories[str(r["repository"])] = {"type": str(r.get("type") or "git").lower(), "name": str(r.get("name") or r["repository"])[:MAX_TEXT], "ref": str(r.get("ref") or "")[:MAX_TEXT]}
    for p in res.get("pipelines") or []:
        if isinstance(p, dict) and (p.get("source") or p.get("pipeline")):
            trig_p: Any = p.get("trigger")
            if trig_p in (None, "none") or trig_p is False:
                detail = "artifact only (no trigger)"
            else:
                brs = _branches(trig_p.get("branches")) if isinstance(trig_p, dict) else []
                detail = "triggers on completion" + (f" of {', '.join(brs)}" if brs else "")
            m.upstream.append(LLink(kind="yaml_resource", name=str(p.get("source") or p.get("pipeline"))[:MAX_TEXT], project=str(p["project"])[:MAX_TEXT] if p.get("project") else None, detail=detail))
    steps: list[dict[str, Any]] = []
    _walk_steps(doc, steps)
    for st in steps:
        if "checkout" in st and isinstance(st["checkout"], str) and st["checkout"] != "none" and st["checkout"] not in m.checkouts:
            m.checkouts.append(st["checkout"])
        art: str | None = None
        if "publish" in st and "task" not in st:
            art = f"artifact: {str(st.get('artifact') or 'drop')[:MAX_TEXT]}"
        elif isinstance(st.get("task"), str):
            art = _artifact_from(st["task"], st.get("inputs") or {})
        if art and art not in m.artifacts:
            m.artifacts.append(art)
    m.artifacts = m.artifacts[:MAX_ITEMS]
    return m
