"""SEC: secrets and identity."""

from __future__ import annotations

from pch.engine.helpers import lookup
from pch.engine.registry import rule, rule_params
from pch.model.findings import RuleResult
from pch.model.pipeline import Pipeline
from pch.model.repo import RepoContext
from pch.settings import Policy


def _prod_stage_connections(p: Pipeline) -> list[str]:
    return sorted({c for s in p.stages if s.env_tier == "prod" for c in s.service_connections})


def _all_connections(p: Pipeline) -> list[str]:
    return sorted({c for s in p.stages for c in s.service_connections})


@rule(
    "SEC-001", "No plaintext secret-like variables", "critical", "pipeline",
    "Secrets stored as plain variables are visible to everyone with read access to the pipeline.",
    {"classic": "Tick the lock icon (secret) on the variable, or move it to a Key Vault-linked variable group.",
     "yaml": "Remove the literal value; reference a Key Vault-linked variable group or a secret variable."},
)
def sec_001(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    flagged = [{"name": v.name, "reason": v.secret_like_reason} for v in p.variables if v.secret_like_reason and not v.is_secret]
    if flagged:  # NOTE: only names and reasons are reported, never values
        return RuleResult.failed("secret-like variables in plaintext: " + ", ".join(f["name"] for f in flagged), variables=flagged)
    return RuleResult.passed("no plaintext secret-like variables")


@rule(
    "SEC-002", "Variable groups holding production secrets are Key Vault-linked", "high", "pipeline",
    "Key Vault-linked groups keep secrets out of Azure DevOps and give central rotation and audit.",
    {"any": "Link the production variable group to Azure Key Vault (Library > variable group > 'Link secrets from an Azure key vault')."},
    tiers={"prod"},
    params={"prod_name_hints": ["prod"]},
)
def sec_002(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    if p.platform == "gha":
        return RuleResult.na("GitHub Actions has no variable groups: secrets are repository / environment secrets (see SEC-001 for literal secrets in env)")
    prod = {s.name for s in p.stages if s.env_tier == "prod"}
    groups = [g for g in p.variable_groups if g.scope is None or g.scope in prod]
    if not groups:
        return RuleResult.na("no variable groups")
    hints = [h.lower() for h in rule_params(policy, "SEC-002")["prod_name_hints"]]
    unknown, plain = [], []
    for g in groups:
        vg = lookup(ctx.variable_groups, g.id or "") or lookup(ctx.variable_groups, g.name)
        if vg is None:
            unknown.append(g.name)
        elif not vg.key_vault_linked and (vg.has_secrets or any(h in vg.name.lower() for h in hints)):
            plain.append(g.name)
    if plain:
        return RuleResult.failed("not Key Vault-linked: " + ", ".join(plain), groups=plain)
    if unknown:
        return RuleResult.unknown("variable group not found: " + ", ".join(unknown), groups=unknown)
    return RuleResult.passed("all production variable groups are Key Vault-linked")


@rule(
    "SEC-003", "Service connections use workload identity federation", "high", "pipeline",
    "Service principal secrets expire, leak and are rarely rotated; federation removes the secret entirely.",
    {"any": "Convert the Azure Resource Manager service connection to 'Workload identity federation' (Convert action in Service connections).",
     "gha": "Use azure/login with client-id, tenant-id and subscription-id plus `permissions: id-token: write` (a federated credential), and remove creds / client-secret inputs and long-lived secrets."},
)
def sec_003(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    if p.platform == "gha":
        logins = [s for s in p.all_steps() if s.enabled and ("auth:login" in s.capabilities or "auth:secret" in s.capabilities or "auth:oidc" in s.capabilities)]
        if not logins:
            return RuleResult.na("no cloud login steps")
        secret = sorted({s.task or s.name for s in logins if "auth:secret" in s.capabilities})
        if secret:
            return RuleResult.failed("cloud login with a long-lived secret credential instead of OIDC: " + ", ".join(secret), steps=secret)
        undecided = [s.task or s.name for s in logins if "auth:oidc" not in s.capabilities]
        if undecided:
            return RuleResult.unknown("cannot tell how these login steps authenticate (no `id-token: write` and no credential input): " + ", ".join(sorted(set(undecided))))
        return RuleResult.passed("cloud logins use OIDC federation (id-token: write, no stored credential)")
    names = _all_connections(p)
    if not names:
        return RuleResult.na("no service connections used")
    bad, unknown = [], []
    for n in names:
        sc = lookup(ctx.service_connections, n)
        if sc is None:
            unknown.append(n)
        elif sc.type in ("azurerm", "azure") or sc.auth_scheme:
            if not (sc.federated or sc.auth_scheme == "ManagedServiceIdentity") and sc.type == "azurerm":
                bad.append({"name": n, "auth": sc.auth_scheme or "unknown"})
    if bad:
        return RuleResult.failed("not using workload identity federation: " + ", ".join(b["name"] for b in bad), connections=bad)
    if unknown and len(unknown) == len(names):
        return RuleResult.unknown("service connections not found: " + ", ".join(unknown))
    return RuleResult.passed("service connections use workload identity federation / managed identity")


@rule(
    "SEC-004", "Service connections are not authorized for all pipelines", "medium", "pipeline",
    "'Grant access to all pipelines' lets any pipeline in the project use the connection's credentials.",
    {"any": "Service connection > Security: remove 'Grant access permission to all pipelines' and authorize only the specific pipelines."},
)
def sec_004(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    if p.platform == "gha":
        return RuleResult.na("GitHub has no service connections: OIDC federated credentials are bound to repo/environment claims (see SEC-003)")
    names = _all_connections(p)
    if not names:
        return RuleResult.na("no service connections used")
    open_, unk = [], []
    for n in names:
        sc = lookup(ctx.service_connections, n)
        if sc is None or sc.all_pipelines_authorized is None:
            unk.append(n)
        elif sc.all_pipelines_authorized:
            open_.append(n)
    if open_:
        return RuleResult.failed("authorized for all pipelines: " + ", ".join(open_), connections=open_)
    if unk and len(unk) == len(names):
        return RuleResult.unknown("pipeline permissions not readable for: " + ", ".join(unk))
    return RuleResult.passed("connections are restricted to specific pipelines")


@rule(
    "SEC-005", "Production service connections are scoped (resource group preferred)", "medium", "pipeline",
    "A subscription-wide connection used in production gives a pipeline far more access than it needs.",
    {"any": "Recreate the production service connection scoped to the target resource group."},
    tiers={"prod"},
    params={"fail_scope_levels": ["managementgroup", "management group"], "warn_scope_levels": ["subscription"]},
)
def sec_005(ctx: RepoContext, policy: Policy, p: Pipeline) -> RuleResult:
    if p.platform == "gha":
        return RuleResult.na("the scope of a GitHub OIDC credential is the role assignment of the federated identity in the cloud, which is not read")
    names = _prod_stage_connections(p)
    if not names:
        return RuleResult.na("no service connections in production stages")
    prm = rule_params(policy, "SEC-005")
    fail_levels, warn_levels = {x.lower() for x in prm["fail_scope_levels"]}, {x.lower() for x in prm["warn_scope_levels"]}
    sub, mg, unknown = [], [], []
    for n in names:
        sc = lookup(ctx.service_connections, n)
        if sc is None or not sc.scope_level:
            unknown.append(n)
        elif sc.scope_level.lower() in fail_levels:
            mg.append(n)
        elif sc.scope_level.lower() in warn_levels:
            sub.append(n)
    if mg:
        return RuleResult.failed("broadly scoped connection in production: " + ", ".join(mg), connections=mg)
    if sub:
        return RuleResult.warn("widely scoped connection in production: " + ", ".join(sub), connections=sub)
    if unknown and len(unknown) == len(names):
        return RuleResult.unknown("connection scope unknown: " + ", ".join(unknown))
    return RuleResult.passed("production connections are resource-group scoped")
