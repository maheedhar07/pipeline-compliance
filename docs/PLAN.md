# Pipeline Compliance Hub — Implementation Plan

## 0. Goal

A **report-only** web dashboard that scores the CI/CD pipelines of ~280 repositories against a policy catalog. Sources are Azure DevOps (Classic Build, Classic Release, YAML), SonarQube, Aikido and ServiceNow. GitHub Actions comes in a later phase. Pass/fail is decided by deterministic rules. An AI agent layer comes later (Phase 4) and never decides compliance.

**Non-goals (for now):** blocking deployments, writing to ADO/GitHub, and auto-remediation.

## 1. Tech stack (fixed — do not change without reason)

| Concern | Choice |
|---|---|
| Language | Python 3.11+ |
| Web | FastAPI + Jinja2 templates + HTMX + Chart.js (CDN). Server-rendered, no SPA build step. |
| CSS | Tailwind via CDN (Play CDN is fine for v1) |
| Models | Pydantic v2 (canonical model), SQLAlchemy 2.x ORM (persistence) |
| DB | SQLite for dev/demo, Postgres in prod (selected by `DATABASE_URL`) |
| HTTP | `httpx.AsyncClient` with retry/backoff (`tenacity`) and a concurrency semaphore |
| CLI | Typer: `pch scan`, `pch serve`, `pch rules list`, `pch seed-demo` |
| Config | `pydantic-settings` + `config/scope.yaml` + `config/policy.yaml` |
| Tests | pytest, pytest-asyncio, respx (HTTP mocking). Target ≥ 80% coverage on `engine/` and `collectors/`. |
| Lint | ruff + mypy (non-strict) |
| Packaging | `pyproject.toml` (hatchling), Dockerfile, docker-compose (app + postgres) |
| CI | GitHub Actions workflow: lint + test on PR and main |

## 2. Repository layout

```
pipeline-compliance/
├── pyproject.toml  Dockerfile  docker-compose.yml  .env.example  README.md
├── config/
│   ├── scope.yaml          # orgs/projects/repos in scope + repo→sonar key + env-tier mapping
│   └── policy.yaml         # thresholds (coverage %, Sonar staleness days, Aikido SLA, waivers)
├── src/pch/
│   ├── settings.py
│   ├── model/              # canonical pipeline model (pydantic)
│   │   ├── pipeline.py     # Pipeline, Stage, Job, Step, Approval, Environment, ServiceConnectionRef
│   │   ├── repo.py         # RepoFacts (languages, test state, IaC, Dockerfiles)
│   │   └── findings.py     # Finding, Evidence, Severity, Status, Waiver
│   ├── collectors/
│   │   ├── ado/client.py           # auth, paging (continuationToken), rate limit
│   │   ├── ado/classic_build.py    # build definitions → canonical
│   │   ├── ado/classic_release.py  # release definitions → canonical
│   │   ├── ado/yaml_pipeline.py    # pipelines + /preview expanded YAML → canonical
│   │   ├── ado/repo_policies.py    # branch policies, repo files
│   │   ├── ado/service_conn.py     # service endpoints (auth scheme, scope, all-pipelines access)
│   │   ├── ado/environments.py     # YAML environments + checks (approvals, ServiceNow)
│   │   ├── ado/task_catalog.py     # task GUID → name/version resolution
│   │   ├── sonar.py
│   │   ├── aikido.py
│   │   ├── servicenow.py
│   │   └── github/ (read-only reader and GitHub Actions collection: G2, G3)
│   ├── normalize/
│   │   ├── capabilities.py   # task name/id → capability tags (catalog in capabilities.yaml)
│   │   ├── capabilities.yaml
│   │   └── target_detect.py  # infer deploy targets + env tier per stage
│   ├── repo_scan/
│   │   ├── tests_detect.py   # language-aware test detection
│   │   └── files.py          # fetch tree via ADO Items API (no full clone)
│   ├── engine/
│   │   ├── registry.py       # @rule decorator, metadata, applicability
│   │   ├── runner.py         # evaluate rules → findings; scoring
│   │   ├── scoring.py
│   │   └── rules/            # one module per category: src_control, quality, testing,
│   │                         #   supply_chain, secrets_identity, deploy_gov, targets/*, hygiene, migration
│   ├── store/                # SQLAlchemy models, repositories, scan snapshots
│   ├── web/
│   │   ├── app.py  routes/  templates/  static/
│   ├── cli.py
│   └── demo/                 # fixture generator producing realistic fake data for ~280 repos
└── tests/
    ├── fixtures/ado/*.json  sonar/*.json  aikido/*.json  servicenow/*.json
    ├── test_collectors_*.py  test_normalize_*.py  test_rules_*.py  test_web.py
```

## 3. Canonical model (core of the design)

```python
class Step(BaseModel):
    id: str; name: str; task: str | None            # "AzureFunctionApp@2", "actions/checkout@<sha>", "script"
    task_version: str | None; inputs: dict[str, Any]; enabled: bool
    continue_on_error: bool; condition: str | None
    capabilities: set[str]                          # filled by normalize/capabilities
    inline_script: str | None

class Approval(BaseModel):
    kind: Literal["manual", "servicenow", "gate", "branch_control", "business_hours", "other"]
    approvers: list[str]; min_approvers: int | None
    requester_can_approve: bool | None; timeout_minutes: int | None

class Stage(BaseModel):
    name: str; env_name: str | None
    env_tier: Literal["dev", "test", "uat", "prod", "unknown"]
    depends_on: list[str]; jobs: list[Job]
    pre_approvals: list[Approval]; post_approvals: list[Approval]; gates: list[Approval]
    deploy_targets: set[str]                        # functionapp, webapp, aks, adf, synapse, sql, iac, other
    service_connections: list[str]
    branch_filters: list[str]                       # artifact/trigger branch filters

class Pipeline(BaseModel):
    platform: Literal["ado_classic_build", "ado_classic_release", "ado_yaml", "gha"]
    id: str; name: str; project: str; repo: str | None; url: str
    definition_in_source_control: bool
    triggers: dict; variables: list[Variable]; variable_groups: list[VariableGroupRef]
    stages: list[Stage]                             # a classic build is one implicit "build" stage
    linked_build_ids: list[str]                     # release → build artifact sources
    last_run: RunSummary | None; run_stats_90d: RunStats | None
    raw_ref: str                                    # path to the cached raw JSON/YAML (evidence)
```

**Repo-centric view:** the unit on the dashboard is the **repo** (280). A repo aggregates its build pipeline(s), its release/deploy pipeline(s), its RepoFacts, its Sonar project and its Aikido repo. Rules are evaluated per pipeline or per repo (`scope: pipeline|repo`).

**Linking Classic releases to repos:** follow release `artifacts[].definitionReference.definition.id` to the build definition, then to `repository.id`.

## 4. Collectors — API details

All ADO calls use `api-version=7.1`. Auth: PAT through Basic auth (`:PAT`). Required **read-only** scopes: Build, Release, Code, Project & Team, Service Connections, Variable Groups, Environment, Task Groups.

| Data | Endpoint |
|---|---|
| Build defs | `GET {org}/{project}/_apis/build/definitions?includeAllProperties=true` then `GET .../definitions/{id}` |
| Expanded YAML | `POST {org}/{project}/_apis/pipelines/{id}/preview` body `{"previewRun": true}` returns `finalYaml` |
| Release defs | `GET https://vsrm.dev.azure.com/{org}/{project}/_apis/release/definitions?$expand=environments,artifacts` |
| Task catalog | `GET {org}/_apis/distributedtask/tasks` (cache per run) |
| Task groups | `GET {org}/{project}/_apis/distributedtask/taskgroups` (expand inline steps) |
| Branch policies | `GET {org}/{project}/_apis/policy/configurations` |
| Repos | `GET {org}/{project}/_apis/git/repositories` |
| Repo tree | `GET .../git/repositories/{id}/items?recursionLevel=Full&versionDescriptor.version={default}` |
| Service conns | `GET {org}/{project}/_apis/serviceendpoint/endpoints?includeDetails=true` |
| Pipeline perms | `GET {org}/{project}/_apis/pipelines/pipelinePermissions/endpoint/{id}` (allPipelines.authorized) |
| Var groups | `GET {org}/{project}/_apis/distributedtask/variablegroups` (Key Vault-linked if `type == "AzureKeyVault"`) |
| Environments | `GET {org}/{project}/_apis/distributedtask/environments`, checks via `_apis/pipelines/checks/configurations?resourceType=environment&resourceId={id}&$expand=settings` |
| Runs | `GET .../build/builds?definitions={id}&minTime=...` and `.../release/deployments?definitionId=...` |
| Sonar | `api/qualitygates/project_status?projectKey=`, `api/measures/component?component=&metricKeys=coverage,new_coverage,bugs,vulnerabilities,security_hotspots,code_smells,duplicated_lines_density`, `api/project_analyses/search?project=&ps=1`, `api/qualitygates/get_by_project` |
| Aikido | OAuth client credentials then `GET /api/public/v1/repositories/code` and `GET /api/public/v1/open-issue-groups` (filter by repo, severity, `first_detected_at`). Isolate this in `aikido.py`, because API paths may need adjusting against their docs. |
| ServiceNow | Table API `GET /api/now/table/change_request?sysparm_query=...` (number, state, approval, start_date, end_date, cmdb_ci) |

Engineering requirements:
- Raw responses are cached to `data/raw/{scan_id}/...`. Scans are reproducible with `pch scan --from-cache`.
- One failing repo or source must never abort the whole scan. Record a `collection_error` finding (severity `info`) instead.
- Concurrency defaults to 8 parallel requests. Honor `Retry-After` / 429.
- **Every collector must have a fixture-backed test using respx.** There are no live credentials during development.

## 5. Capability and target detection

Keep `capabilities.yaml` as data, not code. Examples:

```yaml
SonarQubePrepare@*:      [sast:sonar, sonar:prepare]
SonarQubeAnalyze@*:      [sonar:analyze]
SonarQubePublish@*:      [sonar:publish]
DotNetCoreCLI@*:         {when: {inputs.command: test}, caps: [unit-test]}
VSTest@*:                [unit-test]
Maven@*:                 {when: {inputs.goals~: "test|verify|install|package"}, caps: [unit-test]}
PublishTestResults@*:    [test-results-publish]
PublishCodeCoverageResults@*: [coverage-publish]
AzureFunctionApp@*:      [deploy:functionapp]
AzureWebApp@*:           [deploy:webapp]
AzureRmWebAppDeployment@*: {when: {inputs.appType~: "functionApp"}, caps: [deploy:functionapp], else: [deploy:webapp]}
AzureAppServiceManage@*: {when: {inputs.Action: "Swap Slots"}, caps: [slot-swap]}
KubernetesManifest@*:    [deploy:aks]
HelmDeploy@*:            [deploy:aks]
Kubernetes@*:            [deploy:aks]
AzureResourceManagerTemplateDeployment@*: [deploy:iac]   # + adf if template path matches ARMTemplateForFactory
AzureCLI@*:              [azcli]                         # inspect inline script for az deployment / kubectl / helm
"Synapse workspace deployment@*": [deploy:synapse]
SqlAzureDacpacDeployment@*: [deploy:sql]
SqlDacpacDeploymentOnMachineGroup@*: [deploy:sql]
TerraformTaskV4@*:       [deploy:iac]
ServiceNow-DevOps-*:     [gate:servicenow]
Docker@*:                {when: {inputs.command~: "buildAndPush|push"}, caps: [container:push]}
AdvancedSecurity-*:      [sast:ghas]
```

Script steps (`script`, `PowerShell@*`, `Bash@*`, `AzureCLI@*`, `AzurePowerShell@*`) are classified with regex heuristics on the inline script. Examples: `dotnet test`, `pytest`, `npm test`, `kubectl apply`, `helm upgrade`, `az functionapp deployment`, `az webapp deploy`, `az deployment group create`, `Stop-AzDataFactoryV2Trigger`, `npm run build export` with `@microsoft/azure-data-factory-utilities`. Tag each match with `heuristic:true` so the evidence shows the classification is inferred.

**ADF detection:** an ARM deploy whose template path contains `ARMTemplateForFactory.json` or `adf_publish`, or a repo containing `factory/*.json` / `pipeline/*.json` / `publish_config.json`.
**Synapse detection:** the Synapse task, or a repo containing `TemplateForWorkspace.json`.
**Env tier:** take `config/scope.yaml` overrides first, then a name regex on stage/environment (`prod|prd|production` → prod, `uat|stg|stage|preprod` → uat, `qa|test|tst|sit` → test, `dev|development|int` → dev).

## 6. Test-state classification (per repo)

| State | Rule |
|---|---|
| `TESTS_OK` | tests detected AND a pipeline runs them (`unit-test` capability) AND Sonar coverage ≥ threshold |
| `TESTS_LOW_COVERAGE` | tests detected, run, coverage < threshold |
| `TESTS_NOT_RUN` | tests detected, but no build pipeline has a `unit-test` capability (or the test step is disabled or `continueOnError`) |
| `TESTS_NO_COVERAGE` | tests run but no coverage is published or Sonar has no coverage metric |
| `NO_TESTS` | no tests detected in a repo containing application code |
| `NOT_APPLICABLE` | repo type is ADF / Synapse / IaC-only / docs. This repo gets the validation control instead (TST-006). |

Detection signals by language:
- **.NET:** `*.csproj` whose name contains `Test`, or which references `xunit|nunit|MSTest|Microsoft.NET.Test.Sdk`
- **Java:** `src/test/**` or `*Test.java`
- **Python:** `test_*.py`, `*_test.py`, `tests/`, or `pytest` in requirements/pyproject
- **JS/TS:** `*.test.*`, `*.spec.*`, `__tests__/`, or jest/vitest/mocha in package.json
- **Go:** `*_test.go`
- **SQL:** tSQLt

Thresholds live in `policy.yaml`. The default is 80%, with optional per-repo overrides.

## 7. Rule catalog (v1)

Each rule has: `id`, `title`, `category`, `severity` (critical/high/medium/low/info), `scope` (repo|pipeline|stage), `applies_to` (platforms, targets, env tiers), `rationale`, and `remediation` per platform (classic/yaml/gha). Each rule returns `PASS | FAIL | WARN | NOT_APPLICABLE | UNKNOWN`, with an evidence dict and a deep link.

### SRC — Source and change control
- **SRC-001 (high, repo):** The default branch has a min-reviewers policy with at least 2 reviewers, `creatorVoteCounts=false`, and reset on push.
- **SRC-002 (high, repo):** The default branch has a build validation policy.
- **SRC-003 (medium, repo):** A linked work item is required, and comments must be resolved.
- **SRC-004 (high, pipeline):** The pipeline definition is in source control. Classic pipelines FAIL this by design.
- **SRC-005 (high, stage, prod):** The production deploy artifact comes from a protected branch (release artifact branch filter, or YAML environment branch-control check).
- **SRC-006 (low, repo):** CODEOWNERS or a required-reviewer policy covers pipeline files.

### QLT — Code quality and security
- **QLT-001 (high, repo):** The build pipeline contains the Sonar prepare, analyze and publish steps, all enabled.
- **QLT-002 (high, repo):** The Sonar quality gate is *enforced*. Check for `sonar.qualitygate.wait=true` in the inputs, or a gate-breaker step. Otherwise WARN as "reported only".
- **QLT-003 (high, repo):** The current Sonar quality gate status is OK.
- **QLT-004 (medium, repo):** The project uses the company quality gate (name from policy.yaml), not the default.
- **QLT-005 (medium, repo):** The last Sonar analysis is within N days (default 14).
- **QLT-006 (high, repo):** The repo is onboarded to Aikido.
- **QLT-007 (critical, repo):** No open Aikido issues past their SLA (critical 7 days, high 30, medium 90).
- **QLT-008 (critical, pipeline):** No security, quality or test step has `continueOnError` set, is disabled, or has an always-false condition.

### TST — Testing
- **TST-001 (high, repo):** Test state is not `NO_TESTS`. This rule is the "highlight repos with no tests" requirement.
- **TST-002 (high, repo):** Test state is not `TESTS_NOT_RUN`.
- **TST-003 (high, repo):** Coverage is at or above the threshold.
- **TST-004 (medium, pipeline):** Test results and coverage are published.
- **TST-005 (medium, stage, test/uat/prod):** A post-deployment smoke or health check exists (step or gate).
- **TST-006 (medium, repo, ADF/Synapse/IaC):** Pre-deploy validation runs: ADF `validate`, Synapse validate, Bicep `what-if`, or Terraform `plan`.

### SUP — Build integrity and supply chain
- **SUP-001 (high, pipeline):** Build once, promote everywhere. Release stages consume the same build artifact, and the YAML pipeline does not rebuild in deploy stages.
- **SUP-002 (medium, pipeline):** Task major versions are pinned, and none are deprecated (keep the deprecated-tasks list in data).
- **SUP-003 (medium, pipeline):** Marketplace tasks are on the allowlist in policy.yaml.
- **SUP-004 (high, pipeline, aks):** Images are pushed to an approved ACR, deployed by digest or immutable tag, and never `:latest`.
- **SUP-005 (low, pipeline):** An SBOM is generated.

### SEC — Secrets and identity
- **SEC-001 (critical, pipeline):** No plaintext secret-like variables. Flag a variable as a likely secret if its name matches `(?i)pass|pwd|secret|token|key|connstr|connectionstring` and it is not `isSecret`, or if its value matches entropy or known prefixes. **Never store the value.** Store only the variable name and the reason.
- **SEC-002 (high, pipeline):** Variable groups used for prod are Key Vault-linked.
- **SEC-003 (high, pipeline):** Service connections use workload identity federation, not a service principal secret or a publish profile.
- **SEC-004 (medium, pipeline):** Service connections are not authorized for all pipelines.
- **SEC-005 (medium, pipeline):** Service connections used in prod are scoped to a resource group, or to a subscription with a WARN.

### DEP — Deployment governance
- **DEP-001 (critical, stage, prod):** A manual pre-deployment approval exists (classic `preDeployApprovals` non-automated, or a YAML environment approval check).
- **DEP-002 (critical, stage, prod):** The requester cannot approve (classic `isRequesterApprover`; YAML `requesterCannotBeApprover`).
- **DEP-003 (critical, stage, prod):** A ServiceNow CRQ gate or check exists: classic release gate, YAML environment check, or a ServiceNow DevOps task.
- **DEP-004 (high, stage, prod):** Prod depends on a lower environment. No direct-to-prod path.
- **DEP-005 (high, repo, prod):** Every prod deployment in the last 90 days maps to a ServiceNow CRQ that was Approved or Implement and whose window covers the deployment time. Correlate by CRQ number in the run variables or description, or by CI and time window. Return UNKNOWN when the link can't be made.
- **DEP-006 (medium, pipeline):** Run retention meets policy (default: prod releases kept at least 365 days).

### TGT — Target-specific
- **TGT-FA-001 / TGT-WA-001 (medium):** Deploys to a staging slot and then swaps.
- **TGT-FA-002 / TGT-WA-002 (high):** Does not use publish profile or basic auth. Check the `deploymentMethod` and auth inputs.
- **TGT-AKS-001 (medium):** Manifest or Helm lint and validate step exists (kubeconform, `helm lint`, `--dry-run`).
- **TGT-AKS-002 (medium):** A rollout status check exists (KubernetesManifest does this by default, so require it for `kubectl apply` scripts).
- **TGT-ADF-001 (high):** CI uses the ADF npm utilities, not the manual `adf_publish` branch.
- **TGT-ADF-002 (high):** Pre/post-deployment scripts stop and start triggers.
- **TGT-ADF-003 (medium):** Linked services and global parameters are overridden per environment through `overrideParameters`.
- **TGT-SYN-001 (high):** Uses the Synapse workspace deployment task with validate.
- **TGT-SYN-002 (medium):** Triggers are toggled during the deploy.
- **TGT-SQL-001 (high):** `BlockOnPossibleDataLoss` is not false.
- **TGT-SQL-002 (medium, prod):** A deploy report or script is generated before deploy.
- **TGT-IAC-001 (medium):** A `what-if` or `plan` step precedes the deploy.

### HYG — Hygiene
- **HYG-001 (low):** The pipeline had a successful run in the last 90 days (stale check).
- **HYG-002 (low):** The success rate over 90 days is at least 80%.
- **HYG-003 (info):** An owner is identified (from scope.yaml or the last modifier).

### MIG — GitHub Actions migration readiness (informational score, not compliance)
- Signals: classic pipeline, task groups, deployment groups, classic gates, tasks without a GHA equivalent (mapping table), self-hosted pool usage. Output a 0–100 readiness score plus a blockers list.

## 8. Scoring

- Per repo: `score = 100 * Σ(weight × pass) / Σ(weight × applicable)`. Weights are critical 10, high 5, medium 3, low 1. `NOT_APPLICABLE` and `UNKNOWN` are excluded, and UNKNOWN count is shown separately.
- **Status:** `NON_COMPLIANT` if any critical FAIL. Otherwise `AT_RISK` if score < 80 or any high FAIL. Otherwise `COMPLIANT`.
- Waivers (`policy.yaml` → `waivers: [{rule, repo, reason, owner, expires}]`) turn FAIL into WAIVED until they expire. Expired waivers show a badge.
- Each scan is stored as a snapshot so trends can be charted.

## 9. Dashboard (report-only)

Pages:
1. **Overview:** KPI tiles (repos scanned, % compliant, critical findings, repos with no tests, classic-pipeline count). Donut of compliant / at-risk / non-compliant. Trend line across scans. Top 10 failing rules (bar chart). Heatmap of category × project.
2. **Repos:** filterable, sortable table (project, team/owner, platform mix, deploy targets, test state badge, coverage %, Sonar gate, Aikido criticals, score, status). HTMX filters, with CSV export.
3. **Repo detail:** findings grouped by category with evidence, deep links into ADO/Sonar/Aikido, remediation text for the platform in use, pipelines list, and test-state explanation.
4. **Rules:** catalog with pass rate per rule, drill-down to failing repos.
5. **Testing:** a dedicated view of the five test states, listing `NO_TESTS` and `TESTS_NOT_RUN` repos.
6. **Deployment targets:** breakdown by FunctionApp / WebApp / AKS / ADF / Synapse / SQL / IaC, with rule pass rates per target.
7. **Migration readiness:** classic vs YAML counts and readiness distribution.
8. **Scans:** history, duration, collection errors.

UX: clean, dense enterprise style. Supports light and dark modes. Every number is clickable down to the underlying findings.

JSON API (`/api/v1/...`) mirrors each page for future Power BI or agent use.

## 10. Demo mode (critical for autonomous development)

There are no live credentials during the build. `pch seed-demo --repos 280` generates realistic synthetic **raw API payloads** (not DB rows) for 6 projects and 280 repos:
- Pipeline mix: about 55% classic, 40% YAML, 5% none.
- Targets: function apps, web apps, AKS, ADF, Synapse, SQL and IaC.
- About 25% of repos with no tests and 10% with tests that aren't run.
- Varied Sonar, Aikido and ServiceNow states.

These payloads then flow through the **real** collectors (via respx or a file-backed transport), normalizers and rules. That exercises the whole stack end to end, and gives a convincing dashboard on first run with `pch seed-demo && pch serve`.

## 11. Milestones (commit and push after each, with green tests)

| # | Milestone | Acceptance |
|---|---|---|
| M0 | Scaffold: pyproject, ruff/mypy/pytest, CI workflow, settings, README skeleton, .env.example, .gitignore | `pytest` and `ruff` pass in GH Actions |
| M1 | Canonical model + findings model + SQLAlchemy store + rule registry and runner + scoring | unit tests for scoring/waivers |
| M2 | ADO client + task catalog + classic build/release + YAML (preview) collectors + normalizer + capabilities.yaml + target detection | fixture tests for each target type, both classic and YAML |
| M3 | Repo scan + test-state classification + Sonar collector | tests for each language and each test state |
| M4 | Aikido + ServiceNow collectors, branch policies, service connections, environments/checks, var groups | fixture tests |
| M5 | Full rule catalog §7 (each rule ≥ 1 pass and 1 fail test) | `pch rules list` shows all, tests green |
| M6 | Demo data generator + `pch scan` orchestration (async, cached, error-tolerant) | `pch seed-demo && pch scan --demo` completes for 280 repos in < 60 s |
| M7 | Dashboard pages §9 + JSON API | manual browser check of all pages, `test_web.py` smoke tests |
| M8 | Dockerfile, docker-compose (Postgres), README (setup, PAT scopes, config, adding a rule), docs/RULES.md auto-generated from the registry | `docker compose up` works |
| M9 (Phase 3) | GitHub Actions adapter (workflows, environments, rulesets, OIDC, SHA pinning) | fixture tests |
| M10 (Phase 4) | Agent layer: MCP server exposing `list_findings`, `get_repo`, `explain_rule`; chat panel in dashboard | — |

M0–M8 was the scope of the original autonomous build (historical). M9 is implemented (G2/G3, ADR-16/17; the template phases T1–T7 and G1–G5 are in `docs/TEMPLATE_PLAN.md`). M10 remains a stub (`pch/agent/`).

## 12. Security guardrails

- Read-only tokens only. The tool never calls mutating endpoints. A `ReadOnlyTransport` guard rejects any non-GET request, except the documented POST to `pipelines/{id}/preview` (`previewRun: true`).
- Secrets come only from env vars. `.env` is gitignored. Secret values are never persisted. Raw cache files get redacted before writing (variables where `isSecret`, and any `value` key under secret-looking names).
- Original v1 stance (superseded by T5, ADR-06): no auth and loopback only. Today `AUTH_MODE=none` is loopback-only and dev-only, and shared deployments use Easy Auth with Entra roles behind the fail-closed guard.
