# Deploying to Azure App Service (stub; T7 expands this)

Target: Azure App Service (Linux, container). Only the web-security settings are documented here.

## App settings (container environment)

| Setting | Value | Notes |
|---|---|---|
| `APP_ENV` | `prod` | Enables HSTS, disables `/api/docs` + `/openapi.json`, makes `ALLOWED_HOSTS` mandatory, forbids `AUTH_MODE=none`. |
| `AUTH_MODE` | `easyauth` | |
| `AUTH_ALLOWED_ROLES` | `PCH.Reader` | Entra app role value(s), comma separated. Exact, case-sensitive match. |
| `ALLOWED_HOSTS` | `<app>.azurewebsites.net` | `*.azurewebsites.net` also works; add custom domains. A bare `*` is refused in prod. |
| `HOST` | `0.0.0.0` | The container must listen on all interfaces; allowed because Easy Auth is enforced. |
| `WEBSITES_PORT` | `8000` | Used when `PORT` is not set. |
| `FORWARDED_ALLOW_IPS` | `*` | Acceptable on App Service only because the platform front end is the sole ingress to the container (# VERIFY). |

Do **not** set `WEBSITE_AUTH_ENABLED` yourself (the platform sets it when Authentication is on), and never set `AUTH_EASYAUTH_ASSUME_ENABLED` or `AUTH_NONE_ALLOW_CONTAINER_BIND` in prod (both are refused).
The app refuses to start (exit 2, listing every problem) unless these are consistent; run `pch doctor` to see `auth` and `serve_guard`.

## Authentication (Web App -> Settings -> Authentication)

1. Add identity provider **Microsoft** (Entra ID), workforce tenant, new or existing app registration.
2. **Restrict access: Require authentication.**
3. **Unauthenticated requests:** `HTTP 401 Unauthorized` (recommended for APIs) or `HTTP 302 redirect to Microsoft` for browsers. The dashboard is a browser app, so use the redirect; scripted clients of `/api/v1/*` then need a token and get 401 from the platform.
4. Token store: optional (the app does not call downstream APIs or read tokens).
5. **Excluded paths:** `/health/live` and `/health/ready` (and `/api/v1/health` if you use it). The App Service Health check probe carries no sign-in, so with *Require authentication* the platform answers it with 401/302 before it reaches the container unless these paths are excluded (Authentication -> Edit -> *Restrict access* -> Excluded paths; or `excludedPaths` in the `authsettingsV2` config). The endpoints return a status and a generic reason code only. Everything else stays protected. # VERIFY: excluded-paths option and wildcard syntax in the current Easy Auth (authsettingsV2 `globalValidation.excludedPaths`).
6. Enterprise application -> Properties -> **Assignment required = Yes**; assign users/groups to the app role.

## App role (app registration -> Manifest, `appRoles`)

```json
{
  "allowedMemberTypes": ["User"],
  "description": "Read access to the Pipeline Compliance Hub dashboard and API.",
  "displayName": "PCH Reader",
  "id": "<new-guid>",
  "isEnabled": true,
  "value": "PCH.Reader"
}
```

Assign users or groups to **PCH Reader** under Enterprise applications -> Users and groups. The `roles` claim is then present in the principal that Easy Auth passes in `X-MS-CLIENT-PRINCIPAL`; the app allows the request only if it contains a role from `AUTH_ALLOWED_ROLES`. Sign-out is `/.auth/logout` (linked in the header).

## Assumptions to verify on the real platform (`# VERIFY:` in code)

* `WEBSITE_AUTH_ENABLED=True` is exposed to the container when Authentication is enabled (`settings.py`, `guard.py`).
* Easy Auth strips/overwrites client-supplied `X-MS-CLIENT-PRINCIPAL*` headers on every request that reaches the container, including excluded paths and any non-public ingress (private endpoint, SCM) (`auth.py`).
* The principal header format (`auth_typ`, `name_typ`, `role_typ`, `claims[{typ,val}]`) and that app roles arrive as claims of type `roles` (`auth.py`).
* `/.auth/logout` is the sign-out endpoint.
* `FORWARDED_ALLOW_IPS=*` is safe because the App Service front end is the only way to reach the container (`settings.py`).
* The platform health probe sends the site host name as `Host` (so `ALLOWED_HOSTS` does not reject it); the container `HEALTHCHECK` uses a loopback Host, allowed for the three health paths only.

## Operations (T6)

### Health check and probes

* **App Service -> Monitoring -> Health check path: `/health/ready`.** App Service pings it about once a minute; an instance that fails it repeatedly (the *Load balancing* threshold, default 10 minutes in the portal, configurable via `WEBSITE_HEALTHCHECK_MAXPINGFAILURES`, 2-10) is removed from rotation and, if it stays unhealthy, replaced. # VERIFY: current thresholds, the `WEBSITE_HEALTHCHECK_MAXPINGFAILURES` name, and that the probe host/headers are accepted by `ALLOWED_HOSTS`.
* Why `/health/ready` and not `/health/live`: readiness is "DB reachable and migrated to head" (503 with `db_unreachable`, `db_timeout` or `schema_not_ready`). It intentionally ignores the artifact store, Key Vault and external sources so one flaky optional dependency cannot take every instance out of rotation at once. `/health/live` (process only) is what the image `HEALTHCHECK` uses, so a DB outage never restarts the container.
* Both paths must be excluded from Easy Auth (see Authentication step 5), otherwise the platform probe is rejected with 401/302 and the instance is marked unhealthy.
* Health check needs at least 2 instances to be useful (it only removes an unhealthy instance from rotation if another exists). # VERIFY.

### Logging, telemetry

* Set `APP_ENV=prod` (JSON logs by default), `LOG_LEVEL=INFO`. The container writes to stdout/stderr: enable *App Service logs -> Application logging (filesystem)* or route Diagnostic settings (`AppServiceConsoleLogs`) to Log Analytics.
* Application Insights: build the image with `--build-arg PCH_LOCKFILE=requirements-azure.lock` (includes the `azure-monitor` extra) and set `APPLICATIONINSIGHTS_CONNECTION_STRING` as a Key Vault reference. Cloud role name `pch-web` (web) and `pch-scan` (scan). Sampling: `OTEL_TRACES_SAMPLER=microsoft.fixed_percentage`, `OTEL_TRACES_SAMPLER_ARG=0.1`. Do not also enable the App Service *auto-instrumentation* agent for the same app (double telemetry). # VERIFY.

### Graceful shutdown

On stop/restart/scale-in App Service sends SIGTERM and waits before SIGKILL; `GRACEFUL_SHUTDOWN_SECONDS` (default 20) must stay below that window. Raise `WEBSITES_CONTAINER_STOP_TIME_LIMIT` (seconds) if you increase it. # VERIFY: default stop time (~30 s) and the app setting name for custom containers.

### Running the scan out-of-band

`pch serve` (the web app) and `pch scan` (a batch job taking minutes to hours) are separate processes: do not run scans inside the web container. Both use the same image, DB and (optionally) artifact store. The scan lock in the DB guarantees one scan at a time even if two schedulers fire; exit codes are in the README. Required for every option: `APP_ENV=prod`, `DATABASE_URL` (or `DB_AUTH=azure_ad` with a managed identity), the source settings (`ADO_ORG`, `SONAR_URL`, ...; credentials via `SECRETS_PROVIDER=env` with Key Vault references/pipeline secrets, or `azure_keyvault`), `ARTIFACT_STORE=azure_blob` + `ARTIFACT_BLOB_*` if the raw cache should persist, `SCAN_TIMEOUT_MINUTES`. Run `pch db upgrade` as a deploy step before first use (the web app refuses to start on a schema that is not at head).

**(a) Azure DevOps scheduled pipeline (container job).** A YAML pipeline with a `schedules:` cron trigger and `container:` pointing at the same image in ACR, running `pch scan` (then `pch scans prune --keep 30 --older-than 90`). The pipeline itself only *reads* ADO via the PAT stored as a secret variable / variable group linked to Key Vault; it must not write to ADO. Authenticate to Azure SQL/Blob/Key Vault with a workload-identity-federation service connection (OIDC) on the pipeline identity; give that identity the roles below. Treat the exit code: 0 ok, 4 means a scan was already running (usually fine), others fail the run. # VERIFY: use `AzureCLI@2` with `addSpnToEnvironment: true` or the pipeline's federated identity to obtain tokens for `DefaultAzureCredential` (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE`).

**(b) Azure Container Apps Job (scheduled) or App Service WebJob.** Container Apps Job: same image, *Schedule* trigger (cron), command `pch scan`, `replicaTimeout` slightly above `SCAN_TIMEOUT_MINUTES`, `replicaRetryLimit` 0, a user-assigned managed identity, secrets as Key Vault-backed secrets. The platform sends SIGTERM when a replica is stopped; the scan marks itself `failed` (`interrupted`) and releases the lock. A WebJob (triggered, cron `settings.job`) in the web app's own container is possible but shares the app's CPU/memory and stop window; prefer the job. # VERIFY: Container Apps Job field names and WebJob support for custom Linux containers.

**RBAC for the scan identity (least privilege)**

| Resource | Role / grant |
|---|---|
| Azure SQL | contained user `CREATE USER [<identity>] FROM EXTERNAL PROVIDER` with `db_datareader`, `db_datawriter` (scan, prune); a separate deploy identity with `db_ddladmin` runs `pch db upgrade` |
| Blob container (`ARTIFACT_BLOB_CONTAINER`) | Storage Blob Data Contributor on that container (scan writes, prune deletes) |
| Key Vault | Key Vault Secrets User (only when `SECRETS_PROVIDER=azure_keyvault`) |
| Container registry | AcrPull (job pulls the image) |
| ADO / Sonar / Aikido / ServiceNow | read-only tokens only; the app never writes to them |

The web app identity needs only `db_datareader` on the DB.
