# Where every standard lives and how to change it

Compliance standards are configuration, not code. Rule *logic* is Python (`src/pch/engine/rules/`), but every threshold,
list, severity, weight and scope decision below is a file you edit; no code change is needed to tune them.
All YAML is strict: an unknown key, rule id, severity or param is an error that names its path (`pch doctor`).

| You want to... | File and key | Default | Rules / behaviour affected | Example |
|---|---|---|---|---|
| Choose the code host(s) | `config/scope.yaml` `code_hosts` | `[github]` (allowed: `github`, `github_enterprise`, `azure_repos`, `other_git`) | Which repos are scanned. Azure Repos is off: its API is not called and pipelines/releases sourced from an unlisted host are out of scope (one info line per project). Provider badges and the "Code hosted on" filter appear only when more than one host is in the scan. | `code_hosts: [github, github_enterprise]` |
| Choose what is scanned | `scope.yaml` `projects`, `exclude_repos` (the ADO organization is `ADO_ORG`, or `scope.yaml` `organization` when `ADO_ORG` is empty; both set must be equal) | whole org, nothing excluded | Which Azure DevOps projects and repos (`Project/org/repo`, case-insensitive) | `exclude_repos: ["Sandbox/acme/scratch"]` |
| Discover GitHub repos | `scope.yaml` `github.orgs`, `include`, `exclude`, `topics_any`, `include_archived`, `include_forks` (needs `GITHUB_TOKEN` or a GitHub App) | no orgs; archived and forks off | Which repos of the organisation(s) are scanned in addition to those ADO pipelines reference. `include`/`exclude` are case-insensitive globs on `repo` (no slash) or `org/repo`; `topics_any` keeps repos with at least one of the topics. Repos with no ADO pipeline are keyed `<org>/<org>/<repo>` | `github: {orgs: [acme], exclude: ["sandbox-*"], topics_any: [prod]}` |
| Name GitHub repos explicitly | `scope.yaml` `repos[].repo` (`org/repo`) | none | Repo is scanned even when no pipeline references it and the listing is off or filtered it out; a `project` that is not an ADO project becomes its grouping name | `- {project: Payments, repo: acme/ledger}` |
| Per-repo facts and overrides | `scope.yaml` `repos[]`: `sonar_key`, `aikido_repo`, `owner`, `servicenow_ci`, `coverage_threshold`, `env_tiers` | none | Source matching, TST-003 threshold, HYG-003, DEP-005 CI window fallback | `coverage_threshold: 70` |
| Map stage / environment names to tiers | `scope.yaml` `env_tiers` (global) and `repos[].env_tiers` (per repo) | name heuristics in `normalize/target_detect.py` | Every `tiers=`-filtered rule: SRC-005, DEP-001..006, SEC-002, SEC-005, TGT-*-001, TST-005 | `env_tiers: {"Blue": prod, "Staging": uat}` |
| Disable a rule | `config/policy.yaml` `rules.<ID>.enabled` | `true` | Not evaluated, no findings, not scored; Rules page shows "disabled by policy" | `rules: {QLT-004: {enabled: false}}` |
| Re-rate a rule | `policy.yaml` `rules.<ID>.severity` (`critical high medium low info`) | the rule's own severity | Scoring weight, repo status (any critical FAIL = NON_COMPLIANT, any high FAIL = AT_RISK); marked "overridden" in the UI | `rules: {DEP-001: {severity: high}}` |
| Tune a rule's knobs | `policy.yaml` `rules.<ID>.params` (list with `pch rules list --params`) | declared next to the rule in `@rule(..., params={...})` | SRC-001 `allow_creator_vote`, `require_reset_on_push` (GitHub: dismissed stale reviews or last-push approval); SRC-002 `required_checks` (GitHub: status check names that must all be required); SRC-007 `require_linear_history`, `require_signed_commits`; SRC-009 `require_code_owner_review`; QLT-001 `required_steps`; QLT-002 `wait_pattern`; TST-004 `required_published`; DEP-004 `lower_tiers`; DEP-005 `crq_pattern` (CRQ number format), `window_slack_hours`; SEC-002 `prod_name_hints`; SEC-005 `fail_scope_levels`, `warn_scope_levels`; SUP-002 `ignored_tasks`; SUP-003 `trusted_action_owners` (GHA); SUP-004 `forbidden_tags`; SUP-006 `trusted_owners` (GHA: owners that may use version tags); SEC-006 `job_write_scopes`; SEC-008 `untrusted_contexts` (regexes); DEP-003 `servicenow_app_pattern` (which custom deployment protection rule counts as ServiceNow) | `rules: {DEP-005: {params: {window_slack_hours: 4}}}` |
| Coverage floor | `policy.yaml` `coverage_threshold` (per repo: `scope.yaml`) | `80` | TST-003, test-state classification | `coverage_threshold: 75` |
| Sonar | `policy.yaml` `sonar_quality_gate_name`, `sonar_staleness_days` | `"Sonar way"`, `14` | QLT-004, QLT-005 | `sonar_quality_gate_name: "Acme Way"` |
| Reviewers | `policy.yaml` `min_reviewers` | `2` | SRC-001 (Azure Repos minimum reviewers; GitHub required approving reviews) | `min_reviewers: 1` |
| GitHub credential and host | env `GITHUB_TOKEN` (or `GITHUB_AUTH=app` + `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`, `GITHUB_APP_PRIVATE_KEY`), `GITHUB_API_URL` | not set; `https://api.github.com` | Without a credential every GitHub-only check is UNKNOWN. Read-only token: Metadata, Contents, Actions, Environments, Deployments, Administration: read | `GITHUB_API_URL=https://ghe.example.com/api/v3` |
| Aikido SLA (days by severity) | `policy.yaml` `aikido_sla_days` | `critical 7, high 30, medium 90, low 180` | QLT-007 | `aikido_sla_days: {critical: 3}` |
| Retention | `policy.yaml` `prod_retention_days` | `365` | DEP-006 | `prod_retention_days: 730` |
| Pipeline freshness / success | `policy.yaml` `stale_pipeline_days`, `min_success_rate` | `90`, `0.8` | HYG-001, HYG-002 | `min_success_rate: 0.9` |
| Allowed marketplace tasks | `policy.yaml` `marketplace_task_allowlist` | empty (code default) | SUP-003 | `- replacetokens` |
| Approved container registries | `policy.yaml` `approved_registries` | empty | SUP-004 | `- acme.azurecr.io` |
| Protected / release branches | `policy.yaml` `approved_branches` | `main master release/* releases/*` | SRC-005 | `approved_branches: [main]` |
| Tiers that need a smoke check | `policy.yaml` `smoke_check_required_tiers` | `test uat prod` | TST-005 | `[uat, prod]` |
| Status threshold | `policy.yaml` `compliant_score_threshold` | `80` | Below it a repo is AT_RISK | `compliant_score_threshold: 90` |
| Waive a failure until a date | `policy.yaml` `waivers[]` `{rule, repo, reason, owner, expires}` | none | FAIL/WARN become WAIVED (not a reason, not scored) until `expires` | `- {rule: SRC-004, repo: "Payments/acme/api", reason: "GHA migration", owner: "a@x.com", expires: 2027-03-31}` |
| Scoring weights | `policy.yaml` `scoring.severity_weights`, `category_weights`, `warn_credit` | severities `10/5/3/1/0`, every category `1`, WARN `0.5` | Score of every repo: `100 x sum(w x credit) / sum(w)`, `w` = severity weight x category weight | `scoring: {category_weights: {SEC: 2}}` |
| Teach the tool a GitHub Action | `src/pch/normalize/gha_capabilities.yaml` | shipped catalog | Same capability tags for `uses: owner/repo@*` (tests, Sonar, deploy targets, ServiceNow, SBOM, ...), with `with:` input conditions | add `"acme/deploy@*": [deploy:webapp]` |
| Teach the tool a task or script | `src/pch/normalize/capabilities.yaml` | shipped catalog | Capability tags that most pipeline rules read (tests, Sonar, deploy targets, ...) | add `MyTask@*: [unit-test]` |
| Deprecated tasks / actions | `src/pch/normalize/deprecated_tasks.yaml` (`deprecated` for ADO tasks, `deprecated_actions` for GitHub Actions) | shipped list | SUP-002 | `- {task: X, below_major: 3, replacement: "X@3"}` |
| Azure task -> GitHub Actions equivalent | `src/pch/normalize/gha_mapping.yaml` | shipped map | GitHub Actions readiness score and blockers | `X: {gha: "uses: org/action@v1"}` |
| Change or add rule *logic* | `src/pch/engine/rules/*.py` (`@rule(...)`) | | Only needed when a new check cannot be expressed with the knobs above; needs a PASS and a FAIL test, then `pch rules docs --write docs/RULES.md` | see [CUSTOMIZING.md](CUSTOMIZING.md#6-rules-policy-and-data-files) |

## Rules map, step by step

```yaml
# config/policy.yaml
rules:
  QLT-004: {enabled: false}                 # not scored, not evaluated
  DEP-001: {severity: high}                 # re-rated: weight 5 instead of 10, and no longer makes a repo NON_COMPLIANT by itself
  DEP-005:
    params: {window_slack_hours: 4, crq_pattern: "\\b(CHG\\d{7})\\b"}
scoring:
  category_weights: {SEC: 2, HYG: 0.5}
```

Disabling and re-rating are recorded in each scan (`scans.summary.policy`), so an old scan keeps showing the standards it was judged by.
Params are checked against the types of the registry defaults; a `*_pattern` param must be a valid regular expression.
The effective values per rule are in [RULES.md](RULES.md) ("Tunable params") and `pch rules list --params --policy config/policy.yaml`.

## How to verify a change

1. `pch doctor` validates both files (strictly) and prints what the policy switches on, e.g. `disabled rules: QLT-004; severity overrides: DEP-001`.
2. `pch rules list --params --policy config/policy.yaml` shows every rule as configured: `[disabled by policy]`, `severity*` for overrides, and `params` with their defaults when changed.
3. Re-run the scan (`pch scan`, or `pch scan --demo`): standards apply when a scan is made, not retroactively. Disabled rules are absent from findings; the Rules page marks them; overridden severities show an "overridden" marker on Findings, Rules and the repo page.
4. Check the effect: Overview "Top reasons", Repos "Why" column, or `pch serve` and open `/rules/<ID>`.
5. For code changes: `ruff check . && mypy src && pytest -q -p no:warnings`, and `pch rules docs --write docs/RULES.md` after touching a rule.
