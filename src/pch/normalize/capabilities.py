"""Task / script -> capability tags, driven by capabilities.yaml (data, not code)."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from pch.model.pipeline import Pipeline, Step

DATA_DIR = Path(__file__).parent
SCRIPT_TASKS = {"script", "bash", "powershell", "pwsh", "cmdline@2", "powershell@2", "bash@3", "azurecli@2", "azurepowershell@5"}
INLINE_KEYS = ("script", "inlineScript", "Inline", "inline", "scriptBlock")


@dataclass
class CapabilityCatalog:
    tasks: list[tuple[str, str, Any]] = field(default_factory=list)  # (name_pat, ver_pat, spec)
    defaults: dict[str, dict[str, Any]] = field(default_factory=dict)
    scripts: list[tuple[re.Pattern[str], list[str]]] = field(default_factory=list)
    step_names: list[tuple[re.Pattern[str], list[str]]] = field(default_factory=list)
    deprecated: dict[str, dict[str, Any]] = field(default_factory=dict)


def _split_key(key: str) -> tuple[str, str]:
    if "@" in key:
        name, ver = key.rsplit("@", 1)
        return name.lower(), ver
    return key.lower(), "*"


@lru_cache
def load_catalog(path: str | None = None) -> CapabilityCatalog:
    raw = yaml.safe_load(Path(path or DATA_DIR / "capabilities.yaml").read_text()) or {}
    gha = yaml.safe_load((DATA_DIR / "gha_capabilities.yaml").read_text()) or {}  # GitHub Actions: same schema, merged (action names contain "/")
    cat = CapabilityCatalog()
    for key, spec in {**(raw.get("tasks") or {}), **(gha.get("tasks") or {})}.items():
        name, ver = _split_key(key)
        cat.tasks.append((name, ver, spec))
    cat.defaults = {k.lower(): v for k, v in {**(raw.get("defaults") or {}), **(gha.get("defaults") or {})}.items()}
    cat.scripts = [(re.compile(i["pattern"]), list(i["caps"])) for i in raw.get("scripts") or []]
    cat.step_names = [(re.compile(i["pattern"]), list(i["caps"])) for i in raw.get("step_names") or []]
    dep = yaml.safe_load((DATA_DIR / "deprecated_tasks.yaml").read_text()) or {}
    cat.deprecated = {d["task"].lower(): d for d in [*dep.get("deprecated", []), *dep.get("deprecated_actions", [])]}
    return cat


def _input(inputs: dict[str, Any], name: str) -> Any:
    for k, v in inputs.items():
        if k.lower() == name.lower():
            return v
    return None


def _cond_ok(cond: dict[str, Any], inputs: dict[str, Any]) -> bool:
    for key, expected in cond.items():
        regex = key.endswith("~")
        name = key.removeprefix("inputs.").rstrip("~")
        actual = _input(inputs, name)
        if actual is None:
            return False
        actual_s = str(actual)
        if regex:
            if not re.search(str(expected), actual_s):
                return False
        else:
            exp = expected if isinstance(expected, list) else [expected]
            if actual_s.lower() not in [str(e).lower() for e in exp]:
                return False
    return True


def _eval_spec(spec: Any, inputs: dict[str, Any]) -> set[str]:
    caps: set[str] = set()
    if spec is None:
        return caps
    if isinstance(spec, list):
        for item in spec:
            caps |= _eval_spec(item, inputs)
        return caps
    if isinstance(spec, str):
        return {spec}
    if isinstance(spec, dict):
        if "when" in spec:
            matched = _cond_ok(spec["when"], inputs)
        elif "when_any" in spec:
            matched = any(_cond_ok(c, inputs) for c in spec["when_any"])
        else:
            matched = True
        if matched:
            caps |= set(spec.get("caps", []))
        else:
            caps |= set(spec.get("else", []))
    return caps


def _ver_ok(ver_pat: str, major: str | None) -> bool:
    return ver_pat == "*" or (major is not None and fnmatch.fnmatch(str(major), ver_pat))


def task_name_version(task: str | None) -> tuple[str | None, str | None]:
    if not task:
        return None, None
    if "@" in task:
        n, v = task.rsplit("@", 1)
        return n, v
    return task, None


def inline_script_of(step: Step) -> str | None:
    if step.inline_script:
        return step.inline_script
    for k in INLINE_KEYS:
        v = _input(step.inputs, k)
        if isinstance(v, str) and v.strip():
            return v
    return None


def classify_step(step: Step, cat: CapabilityCatalog | None = None) -> Step:
    """Fill step.capabilities (+ heuristic_caps) in place. Idempotent."""
    cat = cat or load_catalog()
    name, ver = task_name_version(step.task)
    ver = step.task_version or ver
    caps: set[str] = set()
    heur: set[str] = set()
    if name:
        inputs = dict(cat.defaults.get(name.lower(), {}))
        inputs.update({k: v for k, v in step.inputs.items() if v not in (None, "")})
        for name_pat, ver_pat, spec in cat.tasks:
            if fnmatch.fnmatch(name.lower(), name_pat) and _ver_ok(ver_pat, ver):
                caps |= _eval_spec(spec, inputs)
        dep = cat.deprecated.get(name.lower())
        if dep is not None:
            try:
                step.deprecated = ver is not None and int(str(ver).lstrip("vV").split(".")[0]) < int(dep["below_major"])
            except ValueError:
                step.deprecated = False
        if "servicenow" in name.lower() and "/" not in name:  # ADO task names; GitHub actions are mapped in gha_capabilities.yaml
            caps.add("gate:servicenow")
    script = inline_script_of(step)
    if script:
        step.inline_script = script
        for pat, c in cat.scripts:
            if pat.search(script):
                heur |= set(c)
    for pat, c in cat.step_names:
        if pat.search(step.name or ""):
            heur |= set(c)
    step.capabilities = caps | heur
    step.heuristic_caps = heur - caps
    return step


def classify_pipeline(p: Pipeline, cat: CapabilityCatalog | None = None) -> Pipeline:
    cat = cat or load_catalog()
    for st in p.stages:
        for s in st.steps():
            classify_step(s, cat)
    return p


def is_security_or_test_cap(cap: str) -> bool:
    return cap.startswith(("sast:", "sonar:", "security-scan")) or cap in {
        "unit-test",
        "coverage-publish",
        "test-results-publish",
        "component-governance",
    }
