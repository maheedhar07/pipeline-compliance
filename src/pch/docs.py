"""Generate docs/RULES.md from the rule registry (single source of truth)."""

from __future__ import annotations

from collections import defaultdict

from pch.engine.registry import CATEGORY_NAMES, all_rules

HEADER = """# Rule catalog

> Generated from the rule registry by `pch rules docs --write docs/RULES.md`. Do not edit by hand:
> change the rule's decorator metadata in `src/pch/engine/rules/` and regenerate.
> A test (`tests/test_docs.py`) fails when this file is out of date.

Every rule is deterministic Python. A rule returns `PASS`, `FAIL`, `WARN`, `NOT_APPLICABLE` or `UNKNOWN`
with an evidence dict and a deep link. Default scoring weights: critical 10, high 5, medium 3, low 1, info 0.
`WARN` earns half credit; `NOT_APPLICABLE`, `UNKNOWN` and `WAIVED` are excluded from the score.

Standards are configuration, not code: in `config/policy.yaml` any rule can be disabled or re-rated
(`rules: {ID: {enabled, severity, params}}`), and the weights can be changed (`scoring:`). The "Tunable params"
line of a rule lists its knobs with their defaults. See [STANDARDS.md](STANDARDS.md) for where every standard lives.
"""

PLATFORM_LABEL = {"any": "All platforms", "classic": "Classic pipelines", "yaml": "YAML pipelines", "gha": "GitHub Actions"}


def render_rules_md() -> str:
    rules = all_rules()
    out = [HEADER, f"**{len(rules)} rules** in {len({r.category for r in rules})} categories.\n", "| Rule | Severity | Scope | Title |", "|---|---|---|---|"]
    for r in rules:
        out.append(f"| [{r.id}](#{r.id.lower()}) | {r.severity.value} | {r.scope} | {r.title} |")
    by_cat: dict[str, list] = defaultdict(list)
    for r in rules:
        by_cat[r.category].append(r)
    for cat in CATEGORY_NAMES:
        if cat not in by_cat:
            continue
        out.append(f"\n## {cat}: {CATEGORY_NAMES[cat]}\n")
        for r in by_cat[cat]:
            out.append(f"### {r.id}\n")
            out.append(f"**{r.title}**\n")
            applies = []
            if r.platforms:
                applies.append("platforms: " + ", ".join(sorted(r.platforms)))
            if r.targets:
                applies.append("targets: " + ", ".join(sorted(r.targets)))
            if r.tiers:
                applies.append("environment tiers: " + ", ".join(sorted(r.tiers)))
            out.append(f"- Severity: **{r.severity.value}**")
            out.append(f"- Evaluated per: **{r.scope}**")
            out.append(f"- Applies to: {'; '.join(applies) if applies else 'all'}")
            if r.params:
                out.append("- Tunable params (`policy.yaml` `rules." + r.id + ".params`): " + ", ".join(f"`{k}` = `{v!r}`" for k, v in r.params.items()))
            out.append(f"- Why it matters: {r.rationale}")
            out.append("- Remediation:")
            for plat, text in r.remediation.items():
                out.append(f"  - {PLATFORM_LABEL.get(plat, plat)}: {text}")
            out.append("")
    return "\n".join(out).rstrip() + "\n"
