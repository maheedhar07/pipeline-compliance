"""Normalise GitHub branch rules (rulesets) and classic branch protection into one ``BranchProtection``.

Pure functions, no I/O: the reader fetches, this module merges. ``# VERIFY:`` the field names below against a real response of
your GitHub (they follow the 2022-11-28 REST API docs): rules/branches returns a list of ``{type, parameters, ruleset_id,
ruleset_source_type, ruleset_source}`` and the branch protection endpoint returns ``required_pull_request_reviews``,
``required_status_checks``, ``enforce_admins`` and ``{enabled}`` objects.
"""

from __future__ import annotations

from typing import Any, Literal

from pch.model.repo import BranchProtection

ClassicState = Literal["present", "none", "unknown"]
Bypass = dict[str, list[str] | None]  # ruleset key -> bypass actor labels, None = could not be read


def ruleset_key(rule: dict[str, Any]) -> str:
    return f"{rule.get('ruleset_source_type') or 'Repository'}:{rule.get('ruleset_source') or ''}:{rule.get('ruleset_id')}"


def bypass_labels(bypass_actors: Any) -> list[str] | None:
    """Actor TYPES and modes only (``RepositoryRole/always``): ids and names are not needed and not stored. None = field absent (no permission)."""
    if not isinstance(bypass_actors, list):
        return None
    return [f"{a.get('actor_type', 'actor')}/{a.get('bypass_mode', 'always')}" for a in bypass_actors if isinstance(a, dict)]


def _enabled(block: Any) -> bool:
    return bool(block.get("enabled")) if isinstance(block, dict) else bool(block)


def merge_protection(
    *,
    rules: list[dict[str, Any]] | None,
    rules_error: str = "",
    bypass: Bypass | None = None,
    classic: dict[str, Any] | None = None,
    classic_state: ClassicState = "none",
    classic_error: str = "",
) -> BranchProtection:
    """``rules`` None = the rules endpoint could not be read; ``classic_state`` says whether the classic call returned
    protection (``present``), 404 (``none``) or was refused (``unknown``)."""
    p = BranchProtection(available=True)
    bypass = bypass or {}
    if rules is None and classic_state == "unknown":
        return BranchProtection(available=False, unavailable_reason="; ".join(x for x in (rules_error, classic_error) if x) or "branch protection could not be read")
    if rules is None:
        p.incomplete.append(rules_error or "rulesets could not be read")
    if classic_state == "unknown":
        p.incomplete.append(classic_error or "classic branch protection could not be read")
    checks: list[str] = []
    ruleset_bypass: list[str] = []
    bypass_unknown = False

    for r in rules or []:
        t, prm = r.get("type"), r.get("parameters") or {}
        label = f"ruleset {r.get('ruleset_id')}"
        if label not in p.sources:
            p.sources.append(label)
        if t == "pull_request":
            p.require_pull_request = True
            p.required_approving_review_count = max(p.required_approving_review_count, int(prm.get("required_approving_review_count") or 0))
            p.dismiss_stale_reviews |= bool(prm.get("dismiss_stale_reviews_on_push"))
            p.require_code_owner_review |= bool(prm.get("require_code_owner_review"))
            p.require_last_push_approval |= bool(prm.get("require_last_push_approval"))
            p.require_conversation_resolution |= bool(prm.get("required_review_thread_resolution"))
        elif t == "required_status_checks":
            checks += [str(c.get("context")) for c in prm.get("required_status_checks") or [] if isinstance(c, dict) and c.get("context")]
        elif t == "non_fast_forward":
            p.block_force_pushes = True
        elif t == "deletion":
            p.block_deletions = True
        elif t == "required_linear_history":
            p.require_linear_history = True
        elif t == "required_signatures":
            p.require_signed_commits = True
    for key in dict.fromkeys(ruleset_key(r) for r in rules or []):
        labels = bypass.get(key)
        if labels is None:
            bypass_unknown = True
        else:
            ruleset_bypass += labels

    classic_bypass: list[str] = []
    if classic_state == "present" and classic is not None:
        p.sources.append("classic branch protection")
        rev = classic.get("required_pull_request_reviews")
        if isinstance(rev, dict):
            p.require_pull_request = True
            p.required_approving_review_count = max(p.required_approving_review_count, int(rev.get("required_approving_review_count") or 0))
            p.dismiss_stale_reviews |= bool(rev.get("dismiss_stale_reviews"))
            p.require_code_owner_review |= bool(rev.get("require_code_owner_reviews"))
            p.require_last_push_approval |= bool(rev.get("require_last_push_approval"))
            allow = rev.get("bypass_pull_request_allowances") or {}
            classic_bypass = [f"classic-bypass-allowance/{k}" for k in ("users", "teams", "apps") if allow.get(k)]
        sc = classic.get("required_status_checks")
        if isinstance(sc, dict):
            checks += [str(c.get("context")) for c in sc.get("checks") or [] if isinstance(c, dict) and c.get("context")]
            checks += [str(c) for c in sc.get("contexts") or []]
        p.block_force_pushes |= not _enabled(classic.get("allow_force_pushes"))
        p.block_deletions |= not _enabled(classic.get("allow_deletions"))
        p.require_linear_history |= _enabled(classic.get("required_linear_history"))
        p.require_conversation_resolution |= _enabled(classic.get("required_conversation_resolution"))
        p.require_signed_commits |= _enabled(classic.get("required_signatures"))
        p.enforce_admins = _enabled(classic.get("enforce_admins"))

    p.required_status_checks = sorted(dict.fromkeys(checks), key=str.casefold)
    p.bypass_actors = ruleset_bypass + classic_bypass
    p.protected = bool(rules) or classic_state == "present"
    # can an administrator (or any bypass actor) get around the protection? any readable "yes" decides; an unreadable part leaves it open
    parts: list[bool | None] = []
    if rules:
        parts.append(None if bypass_unknown else bool(ruleset_bypass))
    if classic_state == "present":
        parts.append(not p.enforce_admins or bool(classic_bypass))
    if classic_state == "unknown":
        parts.append(None)
    if any(x is True for x in parts):
        p.admins_can_bypass = True
    elif any(x is None for x in parts):
        p.admins_can_bypass = None
    else:
        p.admins_can_bypass = False if parts else None
    return p
