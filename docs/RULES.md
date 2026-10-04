# Rule catalog

> Generated from the rule registry by `pch rules docs --write docs/RULES.md`. Do not edit by hand:
> change the rule's decorator metadata in `src/pch/engine/rules/` and regenerate.
> A test (`tests/test_docs.py`) fails when this file is out of date.

Every rule is deterministic Python. A rule returns `PASS`, `FAIL`, `WARN`, `NOT_APPLICABLE` or `UNKNOWN`
with an evidence dict and a deep link. Default scoring weights: critical 10, high 5, medium 3, low 1, info 0.
`WARN` earns half credit; `NOT_APPLICABLE`, `UNKNOWN` and `WAIVED` are excluded from the score.

Standards are configuration, not code: in `config/policy.yaml` any rule can be disabled or re-rated
(`rules: {ID: {enabled, severity, params}}`), and the weights can be changed (`scoring:`). The "Tunable params"
line of a rule lists its knobs with their defaults. See [STANDARDS.md](STANDARDS.md) for where every standard lives.

**56 rules** in 8 categories.

| Rule | Severity | Scope | Title |
|---|---|---|---|
| [DEP-001](#dep-001) | critical | stage | Production deployments require manual approval |
| [DEP-002](#dep-002) | critical | stage | Requester cannot approve their own production deployment |
| [DEP-003](#dep-003) | critical | stage | Production deployments are gated by a ServiceNow change request |
| [DEP-004](#dep-004) | high | stage | Production depends on a lower environment (no direct-to-prod) |
| [DEP-005](#dep-005) | high | repo | Every prod deployment in the last 90 days maps to an approved ServiceNow CRQ |
| [DEP-006](#dep-006) | medium | pipeline | Run retention meets policy for production releases |
| [HYG-001](#hyg-001) | low | pipeline | Pipeline had a successful run recently (not stale) |
| [HYG-002](#hyg-002) | low | pipeline | Success rate over 90 days is at least 80% |
| [HYG-003](#hyg-003) | info | pipeline | An owner is identified |
| [QLT-001](#qlt-001) | high | repo | Build pipeline runs Sonar prepare, analyze and publish (all enabled) |
| [QLT-002](#qlt-002) | high | repo | Sonar quality gate is enforced (breaks the build) |
| [QLT-003](#qlt-003) | high | repo | Current Sonar quality gate status is OK |
| [QLT-004](#qlt-004) | medium | repo | Project uses the company quality gate |
| [QLT-005](#qlt-005) | medium | repo | Last Sonar analysis is recent |
| [QLT-006](#qlt-006) | high | repo | Repo is onboarded to Aikido |
| [QLT-007](#qlt-007) | critical | repo | No open Aikido issues past their SLA |
| [QLT-008](#qlt-008) | critical | pipeline | Security, quality and test steps cannot be skipped |
| [SEC-001](#sec-001) | critical | pipeline | No plaintext secret-like variables |
| [SEC-002](#sec-002) | high | pipeline | Variable groups holding production secrets are Key Vault-linked |
| [SEC-003](#sec-003) | high | pipeline | Service connections use workload identity federation |
| [SEC-004](#sec-004) | medium | pipeline | Service connections are not authorized for all pipelines |
| [SEC-005](#sec-005) | medium | pipeline | Production service connections are scoped (resource group preferred) |
| [SRC-001](#src-001) | high | repo | Default branch requires 2+ reviewers (creator vote excluded, reset on push) |
| [SRC-002](#src-002) | high | repo | Default branch has a build validation policy |
| [SRC-003](#src-003) | medium | repo | Linked work item and resolved comments required |
| [SRC-004](#src-004) | high | pipeline | Pipeline definition is in source control |
| [SRC-005](#src-005) | high | stage | Production deploys only artifacts from a protected branch |
| [SRC-006](#src-006) | low | repo | CODEOWNERS or required-reviewer policy covers pipeline files |
| [SRC-007](#src-007) | high | repo | Default branch blocks force pushes and deletion |
| [SRC-008](#src-008) | medium | repo | Branch protection also applies to administrators (no bypass) |
| [SRC-009](#src-009) | low | repo | CODEOWNERS file present |
| [SUP-001](#sup-001) | high | pipeline | Build once, promote everywhere (no rebuild per environment) |
| [SUP-002](#sup-002) | medium | pipeline | Task major versions are pinned and not deprecated |
| [SUP-003](#sup-003) | medium | pipeline | Marketplace tasks are on the allowlist |
| [SUP-004](#sup-004) | high | pipeline | AKS images come from an approved ACR and are never :latest |
| [SUP-005](#sup-005) | low | pipeline | An SBOM is generated |
| [TGT-ADF-001](#tgt-adf-001) | high | stage | ADF CI uses the npm utilities (not the manual adf_publish branch) |
| [TGT-ADF-002](#tgt-adf-002) | high | stage | ADF deploy stops and restarts triggers (pre/post deployment script) |
| [TGT-ADF-003](#tgt-adf-003) | medium | stage | ADF linked services and global parameters are overridden per environment |
| [TGT-AKS-001](#tgt-aks-001) | medium | stage | Manifests / Helm charts are linted or validated before deploy |
| [TGT-AKS-002](#tgt-aks-002) | medium | stage | Rollout status is verified after deploy |
| [TGT-FA-001](#tgt-fa-001) | medium | stage | Function App deploys to a staging slot and swaps |
| [TGT-FA-002](#tgt-fa-002) | high | stage | Function App deployment does not use publish profile or basic auth |
| [TGT-IAC-001](#tgt-iac-001) | medium | stage | A what-if / plan step precedes the IaC deploy |
| [TGT-SQL-001](#tgt-sql-001) | high | stage | SQL deployment does not disable BlockOnPossibleDataLoss |
| [TGT-SQL-002](#tgt-sql-002) | medium | stage | A deploy report or script is generated before the production SQL deploy |
| [TGT-SYN-001](#tgt-syn-001) | high | stage | Synapse deploys with the workspace deployment task and validates |
| [TGT-SYN-002](#tgt-syn-002) | medium | stage | Synapse triggers are toggled during deployment |
| [TGT-WA-001](#tgt-wa-001) | medium | stage | Web App deploys to a staging slot and swaps |
| [TGT-WA-002](#tgt-wa-002) | high | stage | Web App deployment does not use publish profile or basic auth |
| [TST-001](#tst-001) | high | repo | Application repo has automated tests (no repo without tests) |
| [TST-002](#tst-002) | high | repo | Existing tests are executed by a pipeline |
| [TST-003](#tst-003) | high | repo | Code coverage meets the threshold |
| [TST-004](#tst-004) | medium | pipeline | Test results and coverage are published |
| [TST-005](#tst-005) | medium | stage | Post-deployment smoke or health check exists |
| [TST-006](#tst-006) | medium | repo | Pre-deploy validation runs for ADF / Synapse / IaC repos |

## SRC: Source and change control

### SRC-001

**Default branch requires 2+ reviewers (creator vote excluded, reset on push)**

- Severity: **high**
- Evaluated per: **repo**
- Applies to: all
- Tunable params (`policy.yaml` `rules.SRC-001.params`): `allow_creator_vote` = `False`, `require_reset_on_push` = `True`
- Why it matters: Peer review on the default branch is the primary preventive control for unreviewed code reaching production. Azure Repos: minimum reviewers policy. GitHub: required approving reviews from branch rules or classic protection (the PR author can never approve, so `allow_creator_vote` has nothing to check there); `require_reset_on_push` is met by dismissing stale approvals or by requiring approval of the most recent push.
- Remediation:
  - All platforms: Azure Repos: Branches > main > Branch policies: minimum reviewers 2, disable 'Allow requestors to approve their own changes', enable 'Reset all approval votes'. GitHub: Settings > Rules (or Branches): require a pull request with 2 approvals and 'Dismiss stale pull request approvals' (or 'Require approval of the most recent reviewable push').

### SRC-002

**Default branch has a build validation policy**

- Severity: **high**
- Evaluated per: **repo**
- Applies to: all
- Tunable params (`policy.yaml` `rules.SRC-002.params`): `required_checks` = `[]`
- Why it matters: Build validation stops changes that do not build or pass tests from merging. Azure Repos: Build validation policy. GitHub: required status checks (any, or all of the names in `required_checks`).
- Remediation:
  - All platforms: Azure Repos: add a Build validation branch policy on the default branch pointing at the CI pipeline. GitHub: require status checks (the CI check names) in a branch rule or branch protection.

### SRC-003

**Linked work item and resolved comments required**

- Severity: **medium**
- Evaluated per: **repo**
- Applies to: all
- Why it matters: Work-item linkage gives change traceability; comment resolution prevents ignored review feedback. GitHub has no work-item link policy, so for GitHub repos only conversation resolution is assessed.
- Remediation:
  - All platforms: Azure Repos: enable 'Check for linked work items' (required) and 'Check for comment resolution' (required) on the default branch. GitHub: require conversation resolution before merging.

### SRC-004

**Pipeline definition is in source control**

- Severity: **high**
- Evaluated per: **pipeline**
- Applies to: all
- Why it matters: Pipelines defined in the UI (Classic) have no review, history or diff trail. YAML pipelines are versioned with the code.
- Remediation:
  - Classic pipelines: Export the definition to YAML (Pipelines > ... > Export to YAML) or migrate to GitHub Actions; commit azure-pipelines.yml to the repo.
  - YAML pipelines: Keep azure-pipelines.yml in the repo, protected by branch policy.

### SRC-005

**Production deploys only artifacts from a protected branch**

- Severity: **high**
- Evaluated per: **stage**
- Applies to: environment tiers: prod
- Why it matters: Without an artifact-branch filter or branch-control check, any branch build can be deployed to production.
- Remediation:
  - Classic pipelines: Release definition > Artifact > Continuous deployment trigger > Build branch filters: include only main/release/*.
  - YAML pipelines: Add a 'Branch control' check on the production environment allowing only refs/heads/main and release/*.

### SRC-006

**CODEOWNERS or required-reviewer policy covers pipeline files**

- Severity: **low**
- Evaluated per: **repo**
- Applies to: all
- Why it matters: Pipeline definitions are privileged code; changes need review from the owning team. Azure Repos: CODEOWNERS or a Required reviewers policy; GitHub: the CODEOWNERS file.
- Remediation:
  - All platforms: Add a CODEOWNERS file covering azure-pipelines*.yml, or a Required reviewers policy with path filter /azure-pipelines*.yml.

### SRC-007

**Default branch blocks force pushes and deletion**

- Severity: **high**
- Evaluated per: **repo**
- Applies to: all
- Tunable params (`policy.yaml` `rules.SRC-007.params`): `require_linear_history` = `False`, `require_signed_commits` = `False`
- Why it matters: A force push rewrites the history reviewers approved and deleting the default branch destroys it; both defeat every other source control.
- Remediation:
  - All platforms: GitHub: in the branch rule or branch protection enable 'Block force pushes' and 'Restrict deletions' (leave 'Allow force pushes' and 'Allow deletions' off).

### SRC-008

**Branch protection also applies to administrators (no bypass)**

- Severity: **medium**
- Evaluated per: **repo**
- Applies to: all
- Why it matters: If repository administrators or bypass actors can skip the rules, the review and status-check controls only bind people who are not in a hurry.
- Remediation:
  - All platforms: GitHub: enable 'Do not allow bypassing the above settings' (classic) or remove bypass actors from the ruleset (or limit them to break-glass roles and waive this rule).

### SRC-009

**CODEOWNERS file present**

- Severity: **low**
- Evaluated per: **repo**
- Applies to: all
- Tunable params (`policy.yaml` `rules.SRC-009.params`): `require_code_owner_review` = `False`
- Why it matters: CODEOWNERS names who must review which part of the code and who is reachable for the repository; it also supplies the owner shown in this report.
- Remediation:
  - All platforms: GitHub: add .github/CODEOWNERS (or CODEOWNERS / docs/CODEOWNERS) with at least a default `*` owner, and with the param require_code_owner_review also enable 'Require review from Code Owners'.


## QLT: Code quality and security

### QLT-001

**Build pipeline runs Sonar prepare, analyze and publish (all enabled)**

- Severity: **high**
- Evaluated per: **repo**
- Applies to: all
- Tunable params (`policy.yaml` `rules.QLT-001.params`): `required_steps` = `['sonar:prepare', 'sonar:analyze', 'sonar:publish']`
- Why it matters: Static analysis must run on every build; a partially configured Sonar integration silently stops reporting.
- Remediation:
  - Classic pipelines: Add SonarQube Prepare (before build), Analyze (after tests) and Publish Quality Gate Result tasks to the build definition.
  - YAML pipelines: Add SonarQubePrepare@5, SonarQubeAnalyze@5 and SonarQubePublish@5 to the build stage.

### QLT-002

**Sonar quality gate is enforced (breaks the build)**

- Severity: **high**
- Evaluated per: **repo**
- Applies to: all
- Tunable params (`policy.yaml` `rules.QLT-002.params`): `wait_pattern` = `'sonar\\.qualitygate\\.wait\\s*[=:]\\s*true'`
- Why it matters: A quality gate that only reports does not prevent bad code from shipping.
- Remediation:
  - All platforms: Set sonar.qualitygate.wait=true (extraProperties on Prepare) or add a quality-gate breaker step that fails the pipeline.

### QLT-003

**Current Sonar quality gate status is OK**

- Severity: **high**
- Evaluated per: **repo**
- Applies to: all
- Why it matters: A failing quality gate means the latest analysed code does not meet the quality bar.
- Remediation:
  - All platforms: Open the project in SonarQube and fix the failing gate conditions (new code coverage, new issues, hotspots).

### QLT-004

**Project uses the company quality gate**

- Severity: **medium**
- Evaluated per: **repo**
- Applies to: all
- Why it matters: Using the default 'Sonar way' gate bypasses the company's agreed thresholds.
- Remediation:
  - All platforms: In SonarQube: Project Settings > Quality Gate > select the company gate.

### QLT-005

**Last Sonar analysis is recent**

- Severity: **medium**
- Evaluated per: **repo**
- Applies to: all
- Why it matters: A stale analysis means the gate status no longer reflects the code that is shipping.
- Remediation:
  - All platforms: Check that the CI pipeline still runs Sonar analysis on the default branch.

### QLT-006

**Repo is onboarded to Aikido**

- Severity: **high**
- Evaluated per: **repo**
- Applies to: all
- Why it matters: Aikido provides SCA/secret/IaC scanning that SonarQube does not.
- Remediation:
  - All platforms: Connect the repository in Aikido (Settings > Code repositories).

### QLT-007

**No open Aikido issues past their SLA**

- Severity: **critical**
- Evaluated per: **repo**
- Applies to: all
- Why it matters: Known vulnerabilities left open beyond the SLA are a direct compliance breach.
- Remediation:
  - All platforms: Triage and fix (or formally snooze with justification) the overdue issues in Aikido.

### QLT-008

**Security, quality and test steps cannot be skipped**

- Severity: **critical**
- Evaluated per: **pipeline**
- Applies to: all
- Why it matters: A Sonar/test/security step that is disabled, continueOnError or conditioned false is a silent bypass.
- Remediation:
  - Classic pipelines: Enable the step, untick 'Continue on error' and remove custom conditions.
  - YAML pipelines: Remove continueOnError: true / enabled: false / false conditions from security and test steps.


## TST: Testing

### TST-001

**Application repo has automated tests (no repo without tests)**

- Severity: **high**
- Evaluated per: **repo**
- Applies to: all
- Why it matters: Code without tests cannot be safely changed or deployed.
- Remediation:
  - All platforms: Add a unit-test project and wire it into the build pipeline.

### TST-002

**Existing tests are executed by a pipeline**

- Severity: **high**
- Evaluated per: **repo**
- Applies to: all
- Why it matters: Tests that never run provide no protection.
- Remediation:
  - Classic pipelines: Add a VSTest / DotNetCoreCLI test task (enabled, no continue-on-error) to the build definition.
  - YAML pipelines: Add a test step (dotnet test / pytest / npm test) without continueOnError.

### TST-003

**Code coverage meets the threshold**

- Severity: **high**
- Evaluated per: **repo**
- Applies to: all
- Why it matters: Coverage below the agreed floor means large parts of the code are untested.
- Remediation:
  - All platforms: Add tests and make sure coverage is published to Sonar (sonar.coverage.* or PublishCodeCoverageResults).

### TST-004

**Test results and coverage are published**

- Severity: **medium**
- Evaluated per: **pipeline**
- Applies to: all
- Tunable params (`policy.yaml` `rules.TST-004.params`): `required_published` = `['test-results-publish', 'coverage-publish']`
- Why it matters: Published results give traceable evidence that tests ran and what they covered.
- Remediation:
  - Classic pipelines: Add Publish Test Results and Publish Code Coverage Results tasks.
  - YAML pipelines: Add PublishTestResults@2 and PublishCodeCoverageResults@1 (or --logger trx plus coverage publish).

### TST-005

**Post-deployment smoke or health check exists**

- Severity: **medium**
- Evaluated per: **stage**
- Applies to: environment tiers: prod, test, uat
- Why it matters: Without a post-deploy check a broken release is only noticed by users.
- Remediation:
  - Classic pipelines: Add a post-deployment gate (Invoke REST API / Azure Monitor) or a smoke-test task after the deploy.
  - YAML pipelines: Add a smoke test step (curl /health) or an environment check after deployment.

### TST-006

**Pre-deploy validation runs for ADF / Synapse / IaC repos**

- Severity: **medium**
- Evaluated per: **repo**
- Applies to: all
- Why it matters: Data-platform and IaC repos have no unit tests; validation (ADF validate, Synapse validate, what-if/plan) is their test.
- Remediation:
  - All platforms: ADF: 'npm run build validate'; Synapse: Synapse workspace deployment with operation validateDeploy; Bicep: 'az deployment group what-if'; Terraform: 'terraform plan'.


## SUP: Build integrity and supply chain

### SUP-001

**Build once, promote everywhere (no rebuild per environment)**

- Severity: **high**
- Evaluated per: **pipeline**
- Applies to: all
- Why it matters: Rebuilding per environment means what was tested is not what is deployed.
- Remediation:
  - Classic pipelines: Link the release to a single build artifact and remove build/publish tasks from release stages.
  - YAML pipelines: Build and publish an artifact in the build stage; deployment stages must only download and deploy it.

### SUP-002

**Task major versions are pinned and not deprecated**

- Severity: **medium**
- Evaluated per: **pipeline**
- Applies to: all
- Tunable params (`policy.yaml` `rules.SUP-002.params`): `ignored_tasks` = `['bash', 'powershell', 'pwsh', 'script']`
- Why it matters: Unpinned tasks change behaviour silently; deprecated tasks stop receiving fixes.
- Remediation:
  - Classic pipelines: Pin each task to a major version (e.g. 2.*) and upgrade deprecated tasks.
  - YAML pipelines: Use Task@<major> and replace deprecated tasks (see data/deprecated_tasks.yaml).

### SUP-003

**Marketplace tasks are on the allowlist**

- Severity: **medium**
- Evaluated per: **pipeline**
- Applies to: all
- Why it matters: Third-party tasks run with the pipeline's credentials; only reviewed extensions should be used.
- Remediation:
  - All platforms: Replace the task, or have the extension reviewed and add it to marketplace_task_allowlist in config/policy.yaml.

### SUP-004

**AKS images come from an approved ACR and are never :latest**

- Severity: **high**
- Evaluated per: **pipeline**
- Applies to: targets: aks
- Tunable params (`policy.yaml` `rules.SUP-004.params`): `forbidden_tags` = `['latest']`
- Why it matters: Mutable tags make deployments non-reproducible; unapproved registries bypass vulnerability scanning.
- Remediation:
  - All platforms: Push to the approved ACR and deploy by digest (@sha256) or an immutable tag such as $(Build.BuildId). Never use :latest.

### SUP-005

**An SBOM is generated**

- Severity: **low**
- Evaluated per: **pipeline**
- Applies to: all
- Why it matters: An SBOM makes it possible to answer 'are we affected?' when a new CVE lands.
- Remediation:
  - Classic pipelines: Add the SBOM Generator task or a syft/cyclonedx step.
  - YAML pipelines: Add sbom-tool / ManifestGenerator, or 'syft packages' to the build.


## SEC: Secrets and identity

### SEC-001

**No plaintext secret-like variables**

- Severity: **critical**
- Evaluated per: **pipeline**
- Applies to: all
- Why it matters: Secrets stored as plain variables are visible to everyone with read access to the pipeline.
- Remediation:
  - Classic pipelines: Tick the lock icon (secret) on the variable, or move it to a Key Vault-linked variable group.
  - YAML pipelines: Remove the literal value; reference a Key Vault-linked variable group or a secret variable.

### SEC-002

**Variable groups holding production secrets are Key Vault-linked**

- Severity: **high**
- Evaluated per: **pipeline**
- Applies to: environment tiers: prod
- Tunable params (`policy.yaml` `rules.SEC-002.params`): `prod_name_hints` = `['prod']`
- Why it matters: Key Vault-linked groups keep secrets out of Azure DevOps and give central rotation and audit.
- Remediation:
  - All platforms: Link the production variable group to Azure Key Vault (Library > variable group > 'Link secrets from an Azure key vault').

### SEC-003

**Service connections use workload identity federation**

- Severity: **high**
- Evaluated per: **pipeline**
- Applies to: all
- Why it matters: Service principal secrets expire, leak and are rarely rotated; federation removes the secret entirely.
- Remediation:
  - All platforms: Convert the Azure Resource Manager service connection to 'Workload identity federation' (Convert action in Service connections).

### SEC-004

**Service connections are not authorized for all pipelines**

- Severity: **medium**
- Evaluated per: **pipeline**
- Applies to: all
- Why it matters: 'Grant access to all pipelines' lets any pipeline in the project use the connection's credentials.
- Remediation:
  - All platforms: Service connection > Security: remove 'Grant access permission to all pipelines' and authorize only the specific pipelines.

### SEC-005

**Production service connections are scoped (resource group preferred)**

- Severity: **medium**
- Evaluated per: **pipeline**
- Applies to: environment tiers: prod
- Tunable params (`policy.yaml` `rules.SEC-005.params`): `fail_scope_levels` = `['managementgroup', 'management group']`, `warn_scope_levels` = `['subscription']`
- Why it matters: A subscription-wide connection used in production gives a pipeline far more access than it needs.
- Remediation:
  - All platforms: Recreate the production service connection scoped to the target resource group.


## DEP: Deployment governance

### DEP-001

**Production deployments require manual approval**

- Severity: **critical**
- Evaluated per: **stage**
- Applies to: environment tiers: prod
- Why it matters: A human gate before production is the baseline change-management control.
- Remediation:
  - Classic pipelines: Release definition > Production stage > Pre-deployment conditions > enable Pre-deployment approvals with named approvers.
  - YAML pipelines: Environment > Approvals and checks > add an Approval check on the production environment.

### DEP-002

**Requester cannot approve their own production deployment**

- Severity: **critical**
- Evaluated per: **stage**
- Applies to: environment tiers: prod
- Why it matters: Separation of duties: the person who triggers a production release must not be its approver.
- Remediation:
  - Classic pipelines: Pre-deployment approvals > untick 'The user requesting a release can approve it'.
  - YAML pipelines: Approval check > tick 'Requester cannot approve their own deployments'.

### DEP-003

**Production deployments are gated by a ServiceNow change request**

- Severity: **critical**
- Evaluated per: **stage**
- Applies to: environment tiers: prod
- Why it matters: Production changes must be backed by an approved ServiceNow CRQ.
- Remediation:
  - Classic pipelines: Add a ServiceNow Change Management gate to the pre-deployment gates of the production stage.
  - YAML pipelines: Add a ServiceNow check to the production environment, or a ServiceNow-DevOps task before deployment.

### DEP-004

**Production depends on a lower environment (no direct-to-prod)**

- Severity: **high**
- Evaluated per: **stage**
- Applies to: environment tiers: prod
- Tunable params (`policy.yaml` `rules.DEP-004.params`): `lower_tiers` = `['dev', 'test', 'uat']`
- Why it matters: Changes must be promoted through dev/test/UAT before production.
- Remediation:
  - Classic pipelines: Production stage > Pre-deployment conditions > trigger 'After stage' = UAT (not 'After release').
  - YAML pipelines: Set dependsOn on the production stage to the UAT/test stage.

### DEP-005

**Every prod deployment in the last 90 days maps to an approved ServiceNow CRQ**

- Severity: **high**
- Evaluated per: **repo**
- Applies to: environment tiers: prod
- Tunable params (`policy.yaml` `rules.DEP-005.params`): `crq_pattern` = `'\\b(CHG\\d{6,9}|CRQ\\d{6,12})\\b'`, `window_slack_hours` = `2`
- Why it matters: Detective control: proves production changes were authorised and inside their change window.
- Remediation:
  - All platforms: Put the CRQ number in the release name/description (or a pipeline parameter) and make the CRQ gate mandatory.

### DEP-006

**Run retention meets policy for production releases**

- Severity: **medium**
- Evaluated per: **pipeline**
- Applies to: environment tiers: prod
- Why it matters: Evidence of production changes must be retained (default 365 days).
- Remediation:
  - Classic pipelines: Release definition > Retention: set Days to retain a release to >= 365 for the production stage.
  - YAML pipelines: Project Settings > Pipelines > Settings > Retention policy; or set retention on the pipeline.


## TGT: Deployment targets

### TGT-ADF-001

**ADF CI uses the npm utilities (not the manual adf_publish branch)**

- Severity: **high**
- Evaluated per: **stage**
- Applies to: targets: adf
- Why it matters: The npm package validates and generates ARM templates from source; adf_publish relies on a manual UI Publish click.
- Remediation:
  - All platforms: Add a build stage using @microsoft/azure-data-factory-utilities (npm run build validate / export) and deploy its ARM output.

### TGT-ADF-002

**ADF deploy stops and restarts triggers (pre/post deployment script)**

- Severity: **high**
- Evaluated per: **stage**
- Applies to: targets: adf
- Why it matters: Deploying over active triggers can fire pipelines mid-deployment or fail with locked triggers.
- Remediation:
  - All platforms: Run PrePostDeploymentScript.ps1 (or Stop/Start-AzDataFactoryV2Trigger) before and after the ARM deployment.

### TGT-ADF-003

**ADF linked services and global parameters are overridden per environment**

- Severity: **medium**
- Evaluated per: **stage**
- Applies to: targets: adf
- Why it matters: Without overrideParameters the dev connection strings are deployed to higher environments.
- Remediation:
  - All platforms: Pass overrideParameters (or a per-environment parameters file) to the ARM deployment.

### TGT-AKS-001

**Manifests / Helm charts are linted or validated before deploy**

- Severity: **medium**
- Evaluated per: **stage**
- Applies to: targets: aks
- Why it matters: Invalid manifests should fail in CI (kubeconform, helm lint, --dry-run), not during the production rollout.
- Remediation:
  - All platforms: Add 'helm lint', kubeconform/kubeval or a 'kubectl apply --dry-run=server' step before deploying.

### TGT-AKS-002

**Rollout status is verified after deploy**

- Severity: **medium**
- Evaluated per: **stage**
- Applies to: targets: aks
- Why it matters: Without a rollout check the pipeline can succeed while pods crash-loop.
- Remediation:
  - All platforms: Use KubernetesManifest@1 deploy (waits by default), 'kubectl rollout status', or helm --wait/--atomic.

### TGT-FA-001

**Function App deploys to a staging slot and swaps**

- Severity: **medium**
- Evaluated per: **stage**
- Applies to: targets: functionapp; environment tiers: prod
- Why it matters: Slot deployment gives warm-up and instant rollback for production Function Apps.
- Remediation:
  - Classic pipelines: Deploy to the 'staging' slot (Deploy to Slot) then add an App Service Manage task with Action=Swap Slots.
  - YAML pipelines: Set deployToSlotOrASE: true / slotName: staging on the deploy task, then AzureAppServiceManage@0 Action: Swap Slots.

### TGT-FA-002

**Function App deployment does not use publish profile or basic auth**

- Severity: **high**
- Evaluated per: **stage**
- Applies to: targets: functionapp
- Why it matters: Publish profiles are long-lived shared credentials that bypass Entra ID.
- Remediation:
  - All platforms: Use an Azure Resource Manager service connection (workload identity); remove publish profiles and basic-auth credentials.

### TGT-IAC-001

**A what-if / plan step precedes the IaC deploy**

- Severity: **medium**
- Evaluated per: **stage**
- Applies to: targets: iac
- Why it matters: Infrastructure changes must be previewed before they are applied.
- Remediation:
  - All platforms: Add 'az deployment group what-if' / validation mode, or 'terraform plan', before the apply step.

### TGT-SQL-001

**SQL deployment does not disable BlockOnPossibleDataLoss**

- Severity: **high**
- Evaluated per: **stage**
- Applies to: targets: sql
- Why it matters: Disabling the data-loss guard lets a dacpac drop columns/tables with data.
- Remediation:
  - All platforms: Remove /p:BlockOnPossibleDataLoss=false; handle destructive changes through reviewed pre-deployment scripts.

### TGT-SQL-002

**A deploy report or script is generated before the production SQL deploy**

- Severity: **medium**
- Evaluated per: **stage**
- Applies to: targets: sql; environment tiers: prod
- Why it matters: Reviewing the generated change script/report before applying is the safety net for schema changes.
- Remediation:
  - All platforms: Run sqlpackage /Action:DeployReport (or /Action:Script) before the deploy and publish it as an artifact.

### TGT-SYN-001

**Synapse deploys with the workspace deployment task and validates**

- Severity: **high**
- Evaluated per: **stage**
- Applies to: targets: synapse
- Why it matters: The Synapse CI/CD task validates artifacts and applies them consistently across workspaces.
- Remediation:
  - All platforms: Use 'Synapse workspace deployment@2' with operation validateDeploy (or a separate validate step).

### TGT-SYN-002

**Synapse triggers are toggled during deployment**

- Severity: **medium**
- Evaluated per: **stage**
- Applies to: targets: synapse
- Why it matters: Active triggers during deployment can run half-deployed artifacts.
- Remediation:
  - All platforms: Stop triggers before and start them after the deployment (Stop/Start-AzSynapseTrigger).

### TGT-WA-001

**Web App deploys to a staging slot and swaps**

- Severity: **medium**
- Evaluated per: **stage**
- Applies to: targets: webapp; environment tiers: prod
- Why it matters: Slot deployment gives warm-up and instant rollback for production Web Apps.
- Remediation:
  - Classic pipelines: Deploy to the 'staging' slot (Deploy to Slot) then add an App Service Manage task with Action=Swap Slots.
  - YAML pipelines: Set deployToSlotOrASE: true / slotName: staging on the deploy task, then AzureAppServiceManage@0 Action: Swap Slots.

### TGT-WA-002

**Web App deployment does not use publish profile or basic auth**

- Severity: **high**
- Evaluated per: **stage**
- Applies to: targets: webapp
- Why it matters: Publish profiles are long-lived shared credentials that bypass Entra ID.
- Remediation:
  - All platforms: Use an Azure Resource Manager service connection (workload identity); remove publish profiles and basic-auth credentials.


## HYG: Hygiene

### HYG-001

**Pipeline had a successful run recently (not stale)**

- Severity: **low**
- Evaluated per: **pipeline**
- Applies to: all
- Why it matters: Pipelines that have not succeeded in 90 days are likely abandoned and still hold permissions.
- Remediation:
  - All platforms: Delete or disable abandoned pipelines; revoke their service connection access.

### HYG-002

**Success rate over 90 days is at least 80%**

- Severity: **low**
- Evaluated per: **pipeline**
- Applies to: all
- Why it matters: Chronically failing pipelines are ignored by their owners and hide real failures.
- Remediation:
  - All platforms: Fix flaky tests/steps or retire the pipeline.

### HYG-003

**An owner is identified**

- Severity: **info**
- Evaluated per: **pipeline**
- Applies to: all
- Why it matters: Someone must be reachable when the pipeline needs attention.
- Remediation:
  - All platforms: Set the repo owner in config/scope.yaml (owner) or keep a named pipeline author.
