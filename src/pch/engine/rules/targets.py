"""TGT: deployment-target specific rules (Function App, Web App, AKS, ADF, Synapse, SQL, IaC)."""

from __future__ import annotations

import re

from pch.engine.helpers import caps_with_builds, stage_blob, step_blob, strings_of
from pch.engine.registry import rule
from pch.model.findings import RuleResult
from pch.model.pipeline import Stage
from pch.model.repo import RepoContext
from pch.settings import Policy

PUBLISH_PROFILE_KEY = re.compile(r"publish.?profile|^(username|password|userName)$", re.I)
BASIC_AUTH_SCRIPT = re.compile(r"\.scm\.azurewebsites\.net|curl\s+[^\n]*-u\s|list-publishing-(profiles|credentials)|--publish-profile|publishsettings", re.I)
BLOCK_FALSE = re.compile(r"BlockOnPossibleDataLoss\s*[=:]\s*(false|0)\b", re.I)
WAIT = re.compile(r"--wait\b|--atomic\b|waitForExecution", re.I)

_SLOT_REMEDIATION = {
    "classic": "Deploy to the 'staging' slot (Deploy to Slot) then add an App Service Manage task with Action=Swap Slots.",
    "yaml": "Set deployToSlotOrASE: true / slotName: staging on the deploy task, then AzureAppServiceManage@0 Action: Swap Slots.",
    "gha": "Set `slot-name: staging` on azure/webapps-deploy (or Azure/functions-action), then `az webapp deployment slot swap` in a following step.",
}
_AUTH_REMEDIATION = {"any": "Use an Azure Resource Manager service connection (workload identity); remove publish profiles and basic-auth credentials."}


def _slot_deploy(stage: Stage) -> bool:
    for s in stage.steps():
        if not s.enabled:
            continue
        v = {k.lower(): val for k, val in s.inputs.items()}
        if str(v.get("deploytoslotorase", "")).lower() == "true" and (v.get("slotname") or v.get("slot-name")):
            return True
        if v.get("slotname") or v.get("slot-name") or v.get("deployslot") or v.get("slot"):
            return True
        if "slot-deploy" in s.capabilities:
            return True
    return False


def _slot_result(t) -> RuleResult:
    st, p = t.stage, t.pipeline
    deployed = _slot_deploy(st)
    swapped = "slot-swap" in p.capabilities()
    if deployed and swapped:
        return RuleResult.passed("deploys to a staging slot and swaps")
    missing = [x for x, ok in (("slot deployment", deployed), ("slot swap", swapped)) if not ok]
    return RuleResult.failed("missing: " + " and ".join(missing), deployed_to_slot=deployed, swap=swapped)


@rule("TGT-FA-001", "Function App deploys to a staging slot and swaps", "medium", "stage",
      "Slot deployment gives warm-up and instant rollback for production Function Apps.", _SLOT_REMEDIATION,
      targets={"functionapp"}, tiers={"prod"})
def tgt_fa_001(ctx, policy: Policy, t) -> RuleResult:
    return _slot_result(t)


@rule("TGT-WA-001", "Web App deploys to a staging slot and swaps", "medium", "stage",
      "Slot deployment gives warm-up and instant rollback for production Web Apps.", _SLOT_REMEDIATION,
      targets={"webapp"}, tiers={"prod"})
def tgt_wa_001(ctx, policy: Policy, t) -> RuleResult:
    return _slot_result(t)


def _auth_result(st: Stage) -> RuleResult:
    bad: list[str] = []
    for s in st.steps():
        if not s.enabled:
            continue
        for k, v in s.inputs.items():
            if PUBLISH_PROFILE_KEY.search(k) and v not in (None, ""):
                bad.append(f"{s.name}: input '{k}'")
            if k.lower() in ("connectiontype", "connectedservicenameselector") and "publish" in str(v).lower():
                bad.append(f"{s.name}: {k}={v}")
        if s.inline_script and BASIC_AUTH_SCRIPT.search(s.inline_script):
            bad.append(f"{s.name}: script uses publish profile / SCM basic auth")
    if bad:
        return RuleResult.failed("publish profile / basic auth in use: " + "; ".join(bad), findings=bad)
    return RuleResult.passed("no publish profile or basic-auth deployment")


@rule("TGT-FA-002", "Function App deployment does not use publish profile or basic auth", "high", "stage",
      "Publish profiles are long-lived shared credentials that bypass Entra ID.", _AUTH_REMEDIATION, targets={"functionapp"})
def tgt_fa_002(ctx, policy: Policy, t) -> RuleResult:
    return _auth_result(t.stage)


@rule("TGT-WA-002", "Web App deployment does not use publish profile or basic auth", "high", "stage",
      "Publish profiles are long-lived shared credentials that bypass Entra ID.", _AUTH_REMEDIATION, targets={"webapp"})
def tgt_wa_002(ctx, policy: Policy, t) -> RuleResult:
    return _auth_result(t.stage)


@rule("TGT-AKS-001", "Manifests / Helm charts are linted or validated before deploy", "medium", "stage",
      "Invalid manifests should fail in CI (kubeconform, helm lint, --dry-run), not during the production rollout.",
      {"any": "Add 'helm lint', kubeconform/kubeval or a 'kubectl apply --dry-run=server' step before deploying."},
      targets={"aks"})
def tgt_aks_001(ctx: RepoContext, policy: Policy, t) -> RuleResult:
    if "lint:k8s" in caps_with_builds(ctx, t.pipeline):
        return RuleResult.passed("manifest/chart validation step present")
    return RuleResult.failed("no manifest/Helm lint or dry-run validation step")


@rule("TGT-AKS-002", "Rollout status is verified after deploy", "medium", "stage",
      "Without a rollout check the pipeline can succeed while pods crash-loop.",
      {"any": "Use KubernetesManifest@1 deploy (waits by default), 'kubectl rollout status', or helm --wait/--atomic."},
      targets={"aks"})
def tgt_aks_002(ctx, policy: Policy, t) -> RuleResult:
    st = t.stage
    caps = st.capabilities()
    if "rollout-status" in caps:
        return RuleResult.passed("rollout status is checked")
    blob = stage_blob(st)
    if WAIT.search(blob):
        return RuleResult.passed("helm --wait/--atomic waits for readiness")
    return RuleResult.failed("deployment does not wait for or verify the rollout")


@rule("TGT-ADF-001", "ADF CI uses the npm utilities (not the manual adf_publish branch)", "high", "stage",
      "The npm package validates and generates ARM templates from source; adf_publish relies on a manual UI Publish click.",
      {"any": "Add a build stage using @microsoft/azure-data-factory-utilities (npm run build validate / export) and deploy its ARM output."},
      targets={"adf"})
def tgt_adf_001(ctx: RepoContext, policy: Policy, t) -> RuleResult:
    caps = caps_with_builds(ctx, t.pipeline)
    for p in ctx.pipelines:  # a separate CI pipeline in the same repo also counts
        caps |= p.capabilities()
    if "adf:npm-utils" in caps or "validate:adf" in caps or "adf:export" in caps:
        return RuleResult.passed("ARM templates are produced by the ADF npm utilities")
    if "adf:publish-branch" in caps or "ARMTemplateForFactory" in stage_blob(t.stage) or "adf_publish" in stage_blob(t.stage):
        return RuleResult.failed("deploys from the manually published adf_publish branch")
    return RuleResult.failed("no ADF npm utilities step found")


@rule("TGT-ADF-002", "ADF deploy stops and restarts triggers (pre/post deployment script)", "high", "stage",
      "Deploying over active triggers can fire pipelines mid-deployment or fail with locked triggers.",
      {"any": "Run PrePostDeploymentScript.ps1 (or Stop/Start-AzDataFactoryV2Trigger) before and after the ARM deployment."},
      targets={"adf"})
def tgt_adf_002(ctx, policy: Policy, t) -> RuleResult:
    if "trigger-toggle" in t.stage.capabilities():
        return RuleResult.passed("trigger stop/start present")
    return RuleResult.failed("no trigger stop/start around the ADF deployment")


@rule("TGT-ADF-003", "ADF linked services and global parameters are overridden per environment", "medium", "stage",
      "Without overrideParameters the dev connection strings are deployed to higher environments.",
      {"any": "Pass overrideParameters (or a per-environment parameters file) to the ARM deployment."},
      targets={"adf"})
def tgt_adf_003(ctx, policy: Policy, t) -> RuleResult:
    arm = [s for s in t.stage.steps() if s.enabled and ("ARMTemplateForFactory" in step_blob(s) or "adf_publish" in step_blob(s))]
    if not arm:
        return RuleResult.unknown("ARM deployment step not identified")
    missing = [s.name for s in arm if not (str(s.inputs.get("overrideParameters", "")).strip() or str(s.inputs.get("csmParametersFile", "")).strip()
               or any(str(s.inputs.get(k, "")).strip() for k in ("parameters", "armTemplateParameters", "parametersFile"))  # VERIFY: input names of Azure/data-factory-deploy-action
               or "-factoryName" in (s.inline_script or "") or "-p " in (s.inline_script or ""))]
    if missing:
        return RuleResult.failed("no environment overrides on: " + ", ".join(missing), steps=missing)
    return RuleResult.passed("environment-specific parameters are overridden")


@rule("TGT-SYN-001", "Synapse deploys with the workspace deployment task and validates", "high", "stage",
      "The Synapse CI/CD task validates artifacts and applies them consistently across workspaces.",
      {"any": "Use 'Synapse workspace deployment@2' with operation validateDeploy (or a separate validate step)."},
      targets={"synapse"})
def tgt_syn_001(ctx: RepoContext, policy: Policy, t) -> RuleResult:
    task_steps = [s for s in t.stage.steps() if s.enabled and s.task and s.task.lower().startswith(("synapse workspace deployment", "azure/synapse-workspace-deployment"))]
    if not task_steps:
        return RuleResult.failed("Synapse is not deployed with the workspace deployment task")
    caps = caps_with_builds(ctx, t.pipeline)
    if "validate:synapse" in caps:
        return RuleResult.passed("workspace deployment task with validation")
    return RuleResult.failed("workspace deployment task used but no validate operation")


@rule("TGT-SYN-002", "Synapse triggers are toggled during deployment", "medium", "stage",
      "Active triggers during deployment can run half-deployed artifacts.",
      {"any": "Stop triggers before and start them after the deployment (Stop/Start-AzSynapseTrigger)."},
      targets={"synapse"})
def tgt_syn_002(ctx, policy: Policy, t) -> RuleResult:
    if "trigger-toggle" in t.stage.capabilities():
        return RuleResult.passed("trigger stop/start present")
    return RuleResult.failed("no trigger stop/start during the Synapse deployment")


@rule("TGT-SQL-001", "SQL deployment does not disable BlockOnPossibleDataLoss", "high", "stage",
      "Disabling the data-loss guard lets a dacpac drop columns/tables with data.",
      {"any": "Remove /p:BlockOnPossibleDataLoss=false; handle destructive changes through reviewed pre-deployment scripts."},
      targets={"sql"})
def tgt_sql_001(ctx, policy: Policy, t) -> RuleResult:
    hits = [s.name for s in t.stage.steps() if s.enabled and BLOCK_FALSE.search(step_blob(s))]
    if hits:
        return RuleResult.failed("BlockOnPossibleDataLoss=false in: " + ", ".join(hits), steps=hits)
    return RuleResult.passed("BlockOnPossibleDataLoss is not disabled")


@rule("TGT-SQL-002", "A deploy report or script is generated before the production SQL deploy", "medium", "stage",
      "Reviewing the generated change script/report before applying is the safety net for schema changes.",
      {"any": "Run sqlpackage /Action:DeployReport (or /Action:Script) before the deploy and publish it as an artifact."},
      targets={"sql"}, tiers={"prod"})
def tgt_sql_002(ctx: RepoContext, policy: Policy, t) -> RuleResult:
    caps = caps_with_builds(ctx, t.pipeline)
    blob = " ".join(strings_of([s.inputs for s in t.stage.steps()]))
    if "dacpac-report" in caps or re.search(r"DeployReport|DeployScriptPath|/Action:Script", blob):
        return RuleResult.passed("deploy report/script generated")
    return RuleResult.failed("no deploy report or script generated before the production deployment")


@rule("TGT-IAC-001", "A what-if / plan step precedes the IaC deploy", "medium", "stage",
      "Infrastructure changes must be previewed before they are applied.",
      {"any": "Add 'az deployment group what-if' / validation mode, or 'terraform plan', before the apply step."},
      targets={"iac"})
def tgt_iac_001(ctx: RepoContext, policy: Policy, t) -> RuleResult:
    steps = [s for s in t.pipeline.all_steps() if s.enabled]
    stage_ids = {id(s) for s in t.stage.steps()}
    first_deploy = next((i for i, s in enumerate(steps) if id(s) in stage_ids and "deploy:iac" in s.capabilities), None)
    if first_deploy is None:
        return RuleResult.unknown("IaC deploy step not found")
    if any({"whatif", "plan"} & s.capabilities for s in steps[:first_deploy]):
        return RuleResult.passed("what-if/plan runs before the deploy")
    from pch.engine.helpers import linked_builds

    if any({"whatif", "plan"} & b.capabilities() for b in linked_builds(ctx, t.pipeline)):
        return RuleResult.passed("what-if/plan runs in the linked CI build")
    return RuleResult.failed("no what-if/plan before the IaC deployment")
