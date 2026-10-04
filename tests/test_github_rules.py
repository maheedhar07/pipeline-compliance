"""Repo-level rules on GitHub semantics: PASS / FAIL / UNKNOWN for every mapped or new rule (G2)."""

from pch.model.repo import BranchPolicies, BranchProtection, RepoFacts
from pch.settings import Policy, RuleOverride
from tests.builders import ctx, one, run, statuses

GH = {"name": "acme/r", "provider": "github", "full_name": "acme/r"}


def prot(**kw) -> BranchProtection:
    return BranchProtection(available=True, protected=True, **kw)


def gctx(p: BranchProtection | None, facts: RepoFacts | None = None, **kw):
    return ctx([], facts=facts or RepoFacts(facts_source="github", languages=["dotnet"]), protection=p, repo_kw=GH,
               policies=BranchPolicies(available=False, unavailable_reason="GitHub-hosted: ADO policies do not apply"), **kw)


GOOD = dict(required_approving_review_count=2, dismiss_stale_reviews=True, require_pull_request=True, required_status_checks=["build"],
            require_conversation_resolution=True, block_force_pushes=True, block_deletions=True, enforce_admins=True, admins_can_bypass=False)
UNREADABLE = BranchProtection(available=False, unavailable_reason="GitHub: branch rules denied (HTTP 403) (token needs Metadata: read)")


def with_params(rule_id, **params) -> Policy:
    return Policy(rules={rule_id: RuleOverride(params=params)})


def test_every_rule_is_unknown_with_the_reason_when_protection_is_unreadable():
    for rid in ("SRC-001", "SRC-002", "SRC-003", "SRC-007", "SRC-008"):
        findings = run(rid, gctx(UNREADABLE))
        assert [f.status.value for f in findings] == ["UNKNOWN"], rid
        assert "branch rules denied" in findings[0].message


def test_incomplete_sources_turn_a_missing_control_into_unknown_never_fail():
    blind = prot(incomplete=["classic branch protection denied (token needs administration=read)"])
    for rid in ("SRC-001", "SRC-002", "SRC-003", "SRC-007"):
        assert one(rid, gctx(blind)) == "UNKNOWN", rid
    f = run("SRC-001", gctx(blind))[0]
    assert "administration=read" in f.message and "need >= 2" in f.message
    # ... but whatever IS seen as satisfied still passes
    assert one("SRC-001", gctx(prot(**{**GOOD, "incomplete": ["classic denied"]}))) == "PASS"


# ------------------------------------------------------------------ SRC-001
def test_src001_github():
    assert one("SRC-001", gctx(prot(**GOOD))) == "PASS"
    assert one("SRC-001", gctx(prot(**{**GOOD, "required_approving_review_count": 1}))) == "FAIL"
    assert one("SRC-001", gctx(prot(**{**GOOD, "required_approving_review_count": 0}))) == "FAIL"
    assert one("SRC-001", gctx(prot(**GOOD)), Policy(min_reviewers=3)) == "FAIL"
    assert one("SRC-001", gctx(prot(**{**GOOD, "required_approving_review_count": 1})), Policy(min_reviewers=1)) == "PASS"


def test_src001_reset_on_push_equivalents_and_params():
    no_reset = {**GOOD, "dismiss_stale_reviews": False}
    assert one("SRC-001", gctx(prot(**no_reset))) == "FAIL"
    assert "not reset" in run("SRC-001", gctx(prot(**no_reset)))[0].message
    assert one("SRC-001", gctx(prot(**{**no_reset, "require_last_push_approval": True}))) == "PASS"  # last-push approval is the equivalent
    assert one("SRC-001", gctx(prot(**no_reset)), with_params("SRC-001", require_reset_on_push=False)) == "PASS"
    # GitHub never counts the author's own approval: allow_creator_vote has nothing to fail on
    assert one("SRC-001", gctx(prot(**GOOD)), with_params("SRC-001", allow_creator_vote=False)) == "PASS"


def test_src001_azure_repos_semantics_are_unchanged():
    assert one("SRC-001", ctx([], policies=BranchPolicies(available=True))) == "FAIL"
    assert one("SRC-001", ctx([], policies=BranchPolicies(available=True, min_reviewers=2, reset_on_push=True))) == "PASS"


# ------------------------------------------------------------------ SRC-002
def test_src002_required_status_checks():
    assert one("SRC-002", gctx(prot(**GOOD))) == "PASS"
    assert one("SRC-002", gctx(prot(**{**GOOD, "required_status_checks": []}))) == "FAIL"
    pol = with_params("SRC-002", required_checks=["Build", "security-scan"])
    assert one("SRC-002", gctx(prot(**GOOD)), pol) == "FAIL"  # security-scan is not enforced (names compare case-insensitively)
    assert "security-scan" in run("SRC-002", gctx(prot(**GOOD)), pol)[0].message
    assert one("SRC-002", gctx(prot(**{**GOOD, "required_status_checks": ["BUILD", "security-scan"]})), pol) == "PASS"


# ------------------------------------------------------------------ SRC-003
def test_src003_conversation_resolution():
    assert one("SRC-003", gctx(prot(**GOOD))) == "PASS"
    assert one("SRC-003", gctx(prot(**{**GOOD, "require_conversation_resolution": False}))) == "FAIL"


# ------------------------------------------------------------------ SRC-007 (new)
def test_src007_force_push_and_deletion():
    assert one("SRC-007", gctx(prot(**GOOD))) == "PASS"
    assert one("SRC-007", gctx(prot(**{**GOOD, "block_force_pushes": False}))) == "FAIL"
    assert one("SRC-007", gctx(prot(**{**GOOD, "block_deletions": False}))) == "FAIL"
    assert one("SRC-007", gctx(prot())) == "FAIL"
    pol = with_params("SRC-007", require_linear_history=True, require_signed_commits=True)
    assert one("SRC-007", gctx(prot(**GOOD)), pol) == "FAIL"
    assert one("SRC-007", gctx(prot(**{**GOOD, "require_linear_history": True, "require_signed_commits": True})), pol) == "PASS"


# ------------------------------------------------------------------ SRC-008 (new)
def test_src008_admins_cannot_bypass():
    assert one("SRC-008", gctx(prot(**GOOD))) == "PASS"
    assert one("SRC-008", gctx(prot(**{**GOOD, "enforce_admins": False, "admins_can_bypass": True}))) == "FAIL"
    f = run("SRC-008", gctx(prot(**{**GOOD, "enforce_admins": None, "admins_can_bypass": True, "bypass_actors": ["RepositoryRole/always"]})))[0]
    assert f.status.value == "FAIL" and "RepositoryRole/always" in f.message
    assert one("SRC-008", gctx(prot(**{**GOOD, "admins_can_bypass": None}))) == "UNKNOWN"
    assert statuses("SRC-008", gctx(BranchProtection(available=True, protected=False))) == []  # not applicable: nothing to bypass, see SRC-001


# ------------------------------------------------------------------ new rules outside GitHub reads
def test_github_only_rules_na_for_azure_repos_and_unknown_when_not_read():
    azure = ctx([], policies=BranchPolicies(available=True))
    assert [statuses(r, azure) for r in ("SRC-007", "SRC-008", "SRC-009")] == [[], [], []]  # not applicable (no finding)
    unread = ctx([], facts=RepoFacts(facts_source="unavailable", facts_reason="GitHub reader not configured"), repo_kw=GH,
                 policies=BranchPolicies(available=False, unavailable_reason="GitHub reader not configured"))
    assert [one(r, unread) for r in ("SRC-001", "SRC-002", "SRC-003", "SRC-007", "SRC-008", "SRC-009")] == ["UNKNOWN"] * 6


# ------------------------------------------------------------------ SRC-009 (new) and SRC-006
def test_src009_codeowners():
    assert one("SRC-009", gctx(prot(**GOOD), RepoFacts(facts_source="github", codeowners=True))) == "PASS"
    assert one("SRC-009", gctx(prot(**GOOD), RepoFacts(facts_source="github", codeowners=False))) == "FAIL"
    pol = with_params("SRC-009", require_code_owner_review=True)
    owners = RepoFacts(facts_source="github", codeowners=True)
    assert one("SRC-009", gctx(prot(**GOOD), owners), pol) == "FAIL"
    assert one("SRC-009", gctx(prot(**{**GOOD, "require_code_owner_review": True}), owners), pol) == "PASS"
    assert one("SRC-009", gctx(UNREADABLE, owners), pol) == "UNKNOWN"
    assert one("SRC-009", gctx(prot(incomplete=["classic denied"]), owners), pol) == "UNKNOWN"


def test_src006_uses_codeowners_from_the_github_reader():
    from tests.builders import pipe, stage, step

    y = pipe([stage("Build", [step("DotNetCoreCLI@2")])], platform="ado_yaml")
    assert one("SRC-006", gctx(prot(**GOOD), RepoFacts(facts_source="github", codeowners=True)).model_copy(update={"pipelines": [y]})) == "PASS"
    assert one("SRC-006", gctx(prot(**GOOD), RepoFacts(facts_source="github", codeowners=False)).model_copy(update={"pipelines": [y]})) == "FAIL"


# ------------------------------------------------------------------ TST-001/002/003 and 006 from the tree
def test_tst_rules_evaluate_from_the_github_tree():
    from pch.model.repo import TestState
    from pch.repo_scan.tests_detect import classify_test_state
    from tests.builders import pipe, stage, step

    facts = RepoFacts(facts_source="github", languages=["dotnet"], has_app_code=True, tests_detected=False)
    st, reason, _ = classify_test_state(facts, [], None)
    assert st == TestState.NO_TESTS
    facts.test_state, facts.test_state_reason = st, reason
    assert one("TST-001", gctx(prot(**GOOD), facts)) == "FAIL"  # a complete GitHub tree can prove there are no tests
    facts2 = RepoFacts(facts_source="github", languages=["dotnet"], has_app_code=True, tests_detected=True)
    runner = pipe([stage("Build", [step("DotNetCoreCLI@2", {"command": "test"})])])
    st2, r2, _ = classify_test_state(facts2, [runner], None)
    facts2.test_state, facts2.test_state_reason = st2, r2
    assert one("TST-001", gctx(prot(**GOOD), facts2)) == "PASS" and one("TST-002", gctx(prot(**GOOD), facts2)) == "PASS"
    not_run = RepoFacts(facts_source="github", languages=["dotnet"], has_app_code=True, tests_detected=True)
    st3, r3, _ = classify_test_state(not_run, [], None)
    not_run.test_state, not_run.test_state_reason = st3, r3
    assert one("TST-002", gctx(prot(**GOOD), not_run)) == "FAIL"
    iac = RepoFacts(facts_source="github", kind="iac", has_app_code=False)
    assert one("TST-006", gctx(prot(**GOOD), iac)) == "FAIL"  # kind comes from the tree now
    partial = RepoFacts(facts_source="github", tree_complete=False, facts_reason="GitHub truncated the file tree", kind="docs", has_app_code=False)
    assert one("TST-006", gctx(prot(**GOOD), partial)) == "UNKNOWN"
