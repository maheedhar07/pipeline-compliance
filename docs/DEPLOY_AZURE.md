# Azure App Service runbook (optional)

> **Only if you host the dashboard on Azure App Service.** The adoption path is [USING_IN_YOUR_ORG.md](USING_IN_YOUR_ORG.md); a local `pch serve` plus the scheduled GitHub Actions scan needs nothing from this page.

Ordered runbook to run the dashboard on **Azure App Service for Containers (Linux)** with Entra ID sign-in (Easy Auth), Azure SQL, Key Vault and Blob, and the scan as a separate scheduled job.
All `az` snippets are **examples**: confirm flags with `az <command> --help` for your CLI version, run them with an identity that may create resources, and adapt names, SKUs, networking and tags to your landing zone.
They create and configure resources of *this app's own infrastructure*; nothing here writes to Azure DevOps, GitHub, SonarQube, Aikido or ServiceNow (the app is report-only).
Items tagged **# VERIFY** are platform behaviors the code assumes and that must be confirmed on the real service (full list: `SECURITY_REVIEW.md`, "VERIFY markers and go-live checklist"). Do not add Bicep or Terraform here: your org's IaC repo is the place for it (see the last section).

```
Browser --> App Service front end (Easy Auth, Entra) --> Web App (container: pch serve) --UAMI--> Azure SQL (Entra-only)
                                                              |                                  ^
                                                              +-- Key Vault references ----------+---- scan job (pch scan, own UAMI) --> ADO/Sonar/Aikido/ServiceNow (read-only)
                                                                                                      +--> Blob (raw cache)
 ACR (image by digest) --> pulled with managed identity       App Insights / Log Analytics <-- logs + traces
```

## 1. Resources

| # | Resource | Notes |
|---|---|---|
| 1 | Resource group | One per environment |
| 2 | User-assigned managed identities | `id-pch-web` (web app), `id-pch-scan` (scan job), `id-pch-deploy` (release pipeline: migrations, push). Separate identities keep roles least-privilege |
| 3 | Azure Container Registry | Admin user disabled; pulls by managed identity |
| 4 | Log Analytics workspace + Application Insights | Workspace-based; optional (`azure-monitor` extra) |
| 5 | Key Vault | **RBAC** permission model; holds source credentials and the App Insights connection string |
| 6 | Storage account + container | Raw scan cache (optional); **shared key access disabled**, Entra auth only |
| 7 | Azure SQL server + database | **Microsoft Entra-only authentication**; an Entra group is the admin |
| 8 | App Service plan | Linux; Premium v3 or Standard (health check needs >= 2 instances in production) |
| 9 | Web App for Containers | Image from ACR by digest; `id-pch-web` assigned; Authentication (Easy Auth) on |
| 10 | Scheduler for `pch scan` | ADO scheduled pipeline, Container Apps Job or WebJob (section 9) |
| 11 | Entra app registration + enterprise app | Easy Auth client and the app role (section 7) |

Networking (private endpoints for SQL / Key Vault / Storage, VNet integration for the web app, restricted inbound access) depends on your landing zone and is not scripted here. If you use private endpoints, confirm that the front end remains the only ingress to the container (**# VERIFY**).

## 2. Create the resources (examples)

```bash
# --- variables (example values)
RG=rg-pch-prod; LOC=westeurope; SUB=<subscription-id>
APP=pch-prod-web                      # <APP>.azurewebsites.net
PLAN=plan-pch-prod; ACR=<globally-unique-acr-name>; KV=kv-pch-prod; SA=<globallyuniquestorage>; SQLSRV=sql-pch-prod; SQLDB=pch
ENTRA_ADMIN_GROUP=<group-name>; ENTRA_ADMIN_GROUP_OID=<group-object-id>

az group create -n $RG -l $LOC

# --- identities
for id in id-pch-web id-pch-scan id-pch-deploy; do az identity create -g $RG -n $id -l $LOC; done
WEB_ID=$(az identity show -g $RG -n id-pch-web --query id -o tsv)
WEB_PRINCIPAL=$(az identity show -g $RG -n id-pch-web --query principalId -o tsv)
WEB_CLIENT=$(az identity show -g $RG -n id-pch-web --query clientId -o tsv)
SCAN_PRINCIPAL=$(az identity show -g $RG -n id-pch-scan --query principalId -o tsv)
SCAN_CLIENT=$(az identity show -g $RG -n id-pch-scan --query clientId -o tsv)

# --- registry (no admin user), monitoring
az acr create -g $RG -n $ACR --sku Standard --admin-enabled false
az monitor log-analytics workspace create -g $RG -n log-pch-prod -l $LOC
az monitor app-insights component create -g $RG -a appi-pch-prod -l $LOC --workspace log-pch-prod   # may need: az extension add -n application-insights

# --- Key Vault (RBAC) and Storage (no shared key)
az keyvault create -g $RG -n $KV -l $LOC --enable-rbac-authorization true
az storage account create -g $RG -n $SA -l $LOC --sku Standard_LRS --allow-shared-key-access false --min-tls-version TLS1_2 --allow-blob-public-access false
az storage container create --account-name $SA -n pch-raw --auth-mode login

# --- Azure SQL, Entra-only authentication
az sql server create -g $RG -n $SQLSRV -l $LOC --enable-ad-only-auth \
  --external-admin-principal-type Group --external-admin-name "$ENTRA_ADMIN_GROUP" --external-admin-sid $ENTRA_ADMIN_GROUP_OID
az sql db create -g $RG -s $SQLSRV -n $SQLDB --service-objective S1 --backup-storage-redundancy Local   # choose tier/redundancy per your policy

# --- plan and web app (container, identity, ACR pull by managed identity)
az appservice plan create -g $RG -n $PLAN --is-linux --sku P1v3 --number-of-workers 2
az webapp create -g $RG -p $PLAN -n $APP --container-image-name $ACR.azurecr.io/pch@sha256:<digest> --assign-identity $WEB_ID
az webapp config set -g $RG -n $APP --generic-configurations '{"acrUseManagedIdentityCreds": true, "acrUserManagedIdentityID": "'$WEB_CLIENT'"}'
az webapp update -g $RG -n $APP --set httpsOnly=true keyVaultReferenceIdentity=$WEB_ID                    # # VERIFY: property names for Key Vault references with a user-assigned identity
az webapp update -g $RG -n $APP --client-affinity-enabled false
az webapp config set -g $RG -n $APP --min-tls-version 1.2 --ftps-state Disabled
```

The first `az webapp create` points at an image that must already exist, so do section 4 (build and push an image) first, or create the app and set the image afterwards with
`az webapp config container set -g $RG -n $APP --container-image-name $ACR.azurecr.io/pch@sha256:<digest> --container-registry-url https://$ACR.azurecr.io`.
Deploy by **digest** (immutable) so a rollback is "redeploy the previous digest". # VERIFY: the digest form is accepted as the container image name.

## 3. Role assignments (least privilege)

| Principal | Scope | Role | Why |
|---|---|---|---|
| `id-pch-web` | ACR | **AcrPull** | Pull the image |
| `id-pch-web` | Key Vault | **Key Vault Secrets User** | Resolve Key Vault references (the App Insights connection string) |
| `id-pch-web` | Azure SQL database | contained user, **`db_datareader`** | The dashboard only reads |
| `id-pch-scan` | ACR | **AcrPull** | Job image pull |
| `id-pch-scan` | Key Vault | **Key Vault Secrets User** | Source credentials (references or `azure_keyvault` provider) |
| `id-pch-scan` | Storage container `pch-raw` | **Storage Blob Data Contributor** | Scan writes, prune deletes the raw cache |
| `id-pch-scan` | Azure SQL database | contained user, **`db_datareader`, `db_datawriter`** | Scan results, scan lock, prune |
| `id-pch-deploy` | Azure SQL database | contained user, **`db_ddladmin`** (+ `db_datareader`, `db_datawriter` for the `alembic_version` table) | `pch db upgrade` only |
| `id-pch-deploy` | ACR | **AcrPush** | Push images |
| `id-pch-deploy` | Web App | **Website Contributor** | Update the container image / settings |
| You (operators) | Resource group | Reader; Entra admin group for SQL | Break-glass is your org's process |

Examples:

```bash
ACR_ID=$(az acr show -g $RG -n $ACR --query id -o tsv); KV_ID=$(az keyvault show -g $RG -n $KV --query id -o tsv)
SA_CONTAINER=$(az storage account show -g $RG -n $SA --query id -o tsv)/blobServices/default/containers/pch-raw
az role assignment create --assignee-object-id $WEB_PRINCIPAL  --assignee-principal-type ServicePrincipal --role AcrPull --scope $ACR_ID
az role assignment create --assignee-object-id $WEB_PRINCIPAL  --assignee-principal-type ServicePrincipal --role "Key Vault Secrets User" --scope $KV_ID
az role assignment create --assignee-object-id $SCAN_PRINCIPAL --assignee-principal-type ServicePrincipal --role AcrPull --scope $ACR_ID
az role assignment create --assignee-object-id $SCAN_PRINCIPAL --assignee-principal-type ServicePrincipal --role "Key Vault Secrets User" --scope $KV_ID
az role assignment create --assignee-object-id $SCAN_PRINCIPAL --assignee-principal-type ServicePrincipal --role "Storage Blob Data Contributor" --scope $SA_CONTAINER
```

Database users (connect to the database as a member of the Entra admin group, e.g. with `sqlcmd -G` or Azure Data Studio; the name is the managed identity's **name**):

```sql
CREATE USER [id-pch-web]    FROM EXTERNAL PROVIDER;  ALTER ROLE db_datareader ADD MEMBER [id-pch-web];
CREATE USER [id-pch-scan]   FROM EXTERNAL PROVIDER;  ALTER ROLE db_datareader ADD MEMBER [id-pch-scan];  ALTER ROLE db_datawriter ADD MEMBER [id-pch-scan];
CREATE USER [id-pch-deploy] FROM EXTERNAL PROVIDER;  ALTER ROLE db_ddladmin  ADD MEMBER [id-pch-deploy]; ALTER ROLE db_datareader ADD MEMBER [id-pch-deploy]; ALTER ROLE db_datawriter ADD MEMBER [id-pch-deploy];
```

Source systems (ADO, Sonar, Aikido, ServiceNow): create **read-only** tokens/users (ADO PAT scopes are listed in `USING_IN_YOUR_ORG.md` phase 0) and store them in Key Vault (`ado-pat`, `sonar-token`, `aikido-client-secret`, `servicenow-password`). The web app needs none of them.
The database role set above is the intended minimum; confirm `db_ddladmin` is sufficient for your migrations in staging (**# VERIFY**).

## 4. Build and push the image

```bash
docker build --build-arg PCH_LOCKFILE=requirements-azure.lock -t $ACR.azurecr.io/pch:$(git rev-parse --short HEAD) .
az acr login -n $ACR && docker push $ACR.azurecr.io/pch:$(git rev-parse --short HEAD)
az acr repository show -n $ACR --image pch:$(git rev-parse --short HEAD) --query digest -o tsv      # use this sha256 for deployment
```

`requirements-azure.lock` contains every extra. The provided Dockerfile does **not** install the Microsoft ODBC Driver 18, which `DB_AUTH=azure_ad` (pyodbc) needs. Add this to the final stage *before* `USER pch` (example for the Debian 12 based `python:3.11-slim`; # VERIFY against Microsoft's current "Install the Microsoft ODBC driver for SQL Server (Linux)" page):

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends curl gnupg ca-certificates unixodbc \
 && curl -sSfL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
 && echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" > /etc/apt/sources.list.d/mssql-release.list \
 && apt-get update && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 \
 && apt-get purge -y curl gnupg && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
```

Scan the image in your registry (Defender for Containers or your scanner) before first deploy.

## 5. App settings

### Web app (`pch serve`)

| Setting | Example value | Notes |
|---|---|---|
| `APP_ENV` | `prod` | HSTS, `/api/docs` off, `ALLOWED_HOSTS` mandatory, `AUTH_MODE=none` forbidden, https-only source URLs, `scope.yaml` required |
| `AUTH_MODE` | `easyauth` | |
| `AUTH_ALLOWED_ROLES` | `PCH.Reader` | Entra app role value(s), comma separated, exact and case-sensitive |
| `AUTH_ADMIN_ROLES` | `PCH.Admin` | App role(s) that may change the feature switches on the Settings page (ADR-19); empty = nobody (read-only for all); an admin role also grants read access |
| `SETTINGS_SIGNING_KEY` | Key Vault reference | Secret, at least 32 characters, signs the Settings form tokens (CSRF). Not set in prod = the Settings page is read-only. Same secret on every instance |
| `ALLOWED_HOSTS` | `pch-prod-web.azurewebsites.net` | `*.azurewebsites.net` works; add custom domains; a bare `*` is refused in prod |
| `HOST` | `0.0.0.0` | The container must listen on all interfaces; allowed because Easy Auth is enforced |
| `WEBSITES_PORT` | `8000` | Used when `PORT` is not set |
| `FORWARDED_ALLOW_IPS` | `*` | Only because the App Service front end is the sole ingress (# VERIFY) |
| `DATABASE_URL` | `mssql+pyodbc://@sql-pch-prod.database.windows.net:1433/pch?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes` | No password in the URL |
| `DB_AUTH` | `azure_ad` | Entra token via managed identity |
| `AZURE_CLIENT_ID` | client id of `id-pch-web` | Required for `DefaultAzureCredential` when using a user-assigned identity |
| `LOG_LEVEL` | `INFO` | JSON logs are the default in prod |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | `@Microsoft.KeyVault(SecretUri=https://kv-pch-prod.vault.azure.net/secrets/appinsights-connection-string/)` | Optional; a secret |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | `microsoft.fixed_percentage`, `0.1` | Optional sampling |
| `GRACEFUL_SHUTDOWN_SECONDS` | `20` | Keep below the platform stop window (# VERIFY); raise `WEBSITES_CONTAINER_STOP_TIME_LIMIT` if you raise it |
| `WEBSITES_ENABLE_APP_SERVICE_STORAGE` | `false` | The container is stateless |
| `WEBSITE_AUTH_ENABLED` | (do not set) | The platform sets it when Authentication is on; never set `AUTH_EASYAUTH_ASSUME_ENABLED` or `AUTH_NONE_ALLOW_CONTAINER_BIND` in prod (both refused) |

```bash
az webapp config appsettings set -g $RG -n $APP --settings APP_ENV=prod AUTH_MODE=easyauth AUTH_ALLOWED_ROLES=PCH.Reader \
  ALLOWED_HOSTS=$APP.azurewebsites.net HOST=0.0.0.0 WEBSITES_PORT=8000 FORWARDED_ALLOW_IPS='*' DB_AUTH=azure_ad AZURE_CLIENT_ID=$WEB_CLIENT \
  DATABASE_URL='mssql+pyodbc://@'$SQLSRV'.database.windows.net:1433/'$SQLDB'?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes' \
  LOG_LEVEL=INFO WEBSITES_ENABLE_APP_SERVICE_STORAGE=false
```

The app refuses to start (exit 2, listing every problem) when these are inconsistent; run `pch doctor` (`auth`, `serve_guard`) from the same settings to see why. The Azure SQL password-free URL requires the `azuresql` extra and the ODBC driver (section 4).

### Scan job (`pch scan`, `pch scans prune`)

| Setting | Example value | Notes |
|---|---|---|
| `APP_ENV` | `prod` | |
| `DATABASE_URL`, `DB_AUTH`, `AZURE_CLIENT_ID` | as above, client id of `id-pch-scan` | |
| `ADO_ORG` | `contoso` | Organization name |
| `ADO_PAT`, `SONAR_TOKEN`, `AIKIDO_CLIENT_SECRET`, `SERVICENOW_PASSWORD` | Key Vault references or job secrets | Or `SECRETS_PROVIDER=azure_keyvault` + `KEYVAULT_URL` (then the env credentials are ignored) |
| `SONAR_URL`, `AIKIDO_CLIENT_ID`, `SERVICENOW_URL`, `SERVICENOW_USER` | your values | https only in prod; setting one marks the source configured |
| `ARTIFACT_STORE`, `ARTIFACT_BLOB_ACCOUNT_URL`, `ARTIFACT_BLOB_CONTAINER` | `azure_blob`, `https://<sa>.blob.core.windows.net`, `pch-raw` | Optional raw cache |
| `SCAN_TIMEOUT_MINUTES`, `SCAN_LOCK_STALE_MINUTES` | `240`, `360` | Timeout must be smaller than the stale window (validated) |
| `HTTP_MAX_RESPONSE_MB`, `DB_CONNECT_TIMEOUT_SECONDS`, `CONCURRENCY` | `50`, `15`, `8` | Defaults shown |

Every variable, default and meaning is in the README "Configuration reference".

## 6. Run the migrations (release step)

The web app refuses to start against a schema that is not at the build's head, so migrate **before** starting or updating it, as `id-pch-deploy` (not as the app identity). Example from a release pipeline runner that has the image's Python environment or `pip install ".[azuresql]"` plus the ODBC driver, signed in with `az login` (workload identity federation) so `DefaultAzureCredential` finds the CLI credential:

```bash
export APP_ENV=prod DB_AUTH=azure_ad DATABASE_URL='mssql+pyodbc://@<sql-pch-prod>.database.windows.net:1433/pch?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes'
pch db upgrade && pch db check
```

The SQL server's firewall / private endpoint must allow the runner. Do not use `DB_AUTO_MIGRATE=true` in prod: it needs DDL rights on the app identity and concurrent instances can race. Rollback policy and backups: section 11 below.

## 7. Authentication (Web App, Settings, Authentication)

1. Add identity provider **Microsoft** (Entra ID), workforce tenant, new or existing app registration, **single tenant**.
2. **Restrict access: Require authentication.**
3. **Unauthenticated requests:** `HTTP 302 redirect to Microsoft` for browsers (the dashboard) or `HTTP 401` (recommended for scripted API use; then clients need a token).
4. Token store: optional (the app does not call downstream APIs or read tokens).
5. **Excluded paths:** `/health/live` and `/health/ready` (and `/api/v1/health` if you use it). The App Service Health check probe carries no sign-in, so with *Require authentication* the platform answers it with 401/302 before it reaches the container unless these paths are excluded (Authentication, Edit, *Restrict access*, Excluded paths; or `globalValidation.excludedPaths` in the `authsettingsV2` configuration). The endpoints return a status and a generic reason code only; everything else stays protected. # VERIFY: excluded-paths option and wildcard syntax in the current Easy Auth.
   Example (CLI, **# VERIFY** the option name for your CLI version; the portal is the reference): `az webapp auth update -g $RG -n $APP --enabled true --action RedirectToLoginPage --excluded-paths "/health/live;/health/ready"`.
6. Enterprise application, Properties: **Assignment required = Yes**; assign users or groups to the app role (below).

**App role** (app registration, Manifest, `appRoles`):

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

For the Settings page add a second role, the same way, with `"displayName": "PCH Admin"`, `"description": "May change the feature switches on the Settings page."` and `"value": "PCH.Admin"`, and set `AUTH_ADMIN_ROLES=PCH.Admin` (keep the group small: an admin can switch a source off, which is audited).

Assign users or groups to **PCH Reader** under Enterprise applications, Users and groups. The `roles` claim is then present in the principal that Easy Auth passes in `X-MS-CLIENT-PRINCIPAL`; the app allows the request only if it contains a role from `AUTH_ALLOWED_ROLES`. Sign-out is `/.auth/logout` (linked in the header).
Then run the forged-header test in section 11 (expect 401, or a 302 to Microsoft sign-in, never data).

## 8. Health check, logging, telemetry, shutdown

* **App Service, Monitoring, Health check path: `/health/ready`** (example: `az webapp config set -g $RG -n $APP --generic-configurations '{"healthCheckPath": "/health/ready"}'`). App Service pings it about once a minute; an instance that fails it repeatedly (threshold configurable via `WEBSITE_HEALTHCHECK_MAXPINGFAILURES`, 2-10) is removed from rotation and, if it stays unhealthy, replaced. # VERIFY: current thresholds, the setting name, and that the probe host/headers are accepted by `ALLOWED_HOSTS`.
* Why `/health/ready` and not `/health/live`: readiness is "DB reachable and migrated to head" (503 with `db_unreachable`, `db_timeout` or `schema_not_ready`). It intentionally ignores the artifact store, Key Vault and the sources so one flaky optional dependency cannot take every instance out of rotation at once. `/health/live` (process only) is what the image `HEALTHCHECK` uses, so a DB outage never restarts the container.
* Both paths must be excluded from Easy Auth (section 7, step 5). The health check needs at least 2 instances to be useful (# VERIFY).
* **Logs:** `APP_ENV=prod` gives JSON logs on stdout/stderr. Enable *App Service logs, Application logging (filesystem)* or route Diagnostic settings (`AppServiceConsoleLogs`) to Log Analytics.
* **Application Insights:** build with `requirements-azure.lock`, set `APPLICATIONINSIGHTS_CONNECTION_STRING` as a Key Vault reference. Cloud role names are `pch-web` and `pch-scan`. Do not also enable the App Service *auto-instrumentation* agent for the same app (double telemetry). # VERIFY: no URL query, credential or row value appears in `exceptions`, `dependencies` or `requests`.
* **Graceful shutdown:** on stop/restart/scale-in App Service sends SIGTERM and waits before SIGKILL; `GRACEFUL_SHUTDOWN_SECONDS` (default 20) must stay below that window. `KEEP_ALIVE_SECONDS` (default 65) should exceed the front end's idle reuse window. # VERIFY: ~30 s stop time, `WEBSITES_CONTAINER_STOP_TIME_LIMIT`, ~230 s ARR idle timeout.

## 9. The scan job (out-of-band)

`pch serve` (the web app) and `pch scan` (minutes to hours) are separate processes: never run scans inside the web container. Both use the same image and database; the scan lock in the database ensures one scan at a time even if two schedulers fire.
Exit codes (`USING_IN_YOUR_ORG.md` phase 4): 0 ok, 1 generic failure, 2 configuration, 3 database not ready, 4 another scan holds the lock (usually fine), 5 interrupted or timed out (the scan row is `failed`, the lock released).
Run `pch scan` and then `pch scans prune --keep 30 --older-than 90` (retention; `--dry-run` first).

**(0) GitHub Actions (provided).** `.github/workflows/scheduled-scan.yml` runs the scan on a cron schedule with OIDC login to Azure (no stored client secret), secrets from the `pch-scan` environment and a job summary; see `USING_IN_YOUR_ORG.md` phase 4 for the variables and the federated credential. Pair it with an alert on "no `complete` scan in the last N hours" (the dashboard banner uses `SCAN_STALE_HOURS`).

**(a) Azure DevOps scheduled pipeline (container job).** A YAML pipeline with a `schedules:` cron trigger and `container:` pointing at the same image in ACR, running `pch scan`. The pipeline only *reads* ADO via the PAT stored as a secret variable / variable group linked to Key Vault; it must not write to ADO. Authenticate to Azure SQL/Blob/Key Vault with a workload-identity-federation service connection (OIDC); give that identity the scan roles from section 3. # VERIFY: use `AzureCLI@2` with `addSpnToEnvironment: true` or the pipeline's federated identity to obtain tokens for `DefaultAzureCredential` (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE`).

**(b) Azure Container Apps Job (scheduled) or App Service WebJob.** Container Apps Job: same image, *Schedule* trigger (cron), command `pch scan`, `replicaTimeout` slightly above `SCAN_TIMEOUT_MINUTES` (in seconds), `replicaRetryLimit` 0, the `id-pch-scan` user-assigned identity, secrets as Key Vault-backed secrets. The platform sends SIGTERM when a replica is stopped; the scan marks itself `failed` (`interrupted`) and releases the lock. A WebJob in the web app's own container shares its CPU, memory and stop window; prefer the job. # VERIFY: Container Apps Job field names and WebJob support for custom Linux containers.

Alert on a failed job run and on "no `complete` scan in the last N hours".

## 10. Scaling notes

* The web app is stateless and read-only: scale out (>= 2 instances for the health check) rather than adding workers; `pch serve` runs one uvicorn process per instance. Easy Auth keeps the session at the front end; ARR affinity can be off.
* Each instance opens up to `DB_POOL_SIZE + DB_MAX_OVERFLOW` (default 15) connections; size the Azure SQL tier's connection limit for instances x 15 plus the scan job. `DB_POOL_RECYCLE` (default 1800 s) stays below Azure SQL's ~30 min idle disconnect; `DB_CONNECT_TIMEOUT_SECONDS` bounds a hung server.
* SQLite is for development only: with several instances each would have its own file. Production uses Azure SQL (or PostgreSQL).
* The scan is the heavy part (HTTP fan-out bounded by `CONCURRENCY`, per-response cap `HTTP_MAX_RESPONSE_MB`, overall `SCAN_TIMEOUT_MINUTES`). Give the job its own compute; do not scale the web plan for it.
* `/health/ready` results are cached for `HEALTH_READY_CACHE_SECONDS` (5 s) and the probe is single-flight, so health pings cannot stampede the database.

## 11. Verify, then go live

All of these must hold before real users get access. Items marked (V) are `# VERIFY:` assumptions; the authoritative list with file references is
[SECURITY_REVIEW.md, "VERIFY markers and go-live checklist"](SECURITY_REVIEW.md#verify-markers-and-go-live-checklist). Do not copy it; tick each entry there and record the result in your change ticket.

**Platform behavior**
- [ ] Every (V) item in the SECURITY_REVIEW list is confirmed on the real App Service (Easy Auth variables and header stripping, health probe host, shutdown window, Azure SQL token auth, telemetry content, source API field names).
- [ ] **Forged-header test** (from outside, against the public URL): a request with a made-up principal must not get data.

  ```bash
  P=$(printf '%s' '{"auth_typ":"aad","name_typ":"name","role_typ":"roles","claims":[{"typ":"roles","val":"PCH.Reader"},{"typ":"oid","val":"00000000-0000-0000-0000-000000000000"}]}' | base64 | tr -d '\n')
  curl -s -o /dev/null -w '%{http_code}\n' -H "X-MS-CLIENT-PRINCIPAL: $P" https://<app>.azurewebsites.net/api/v1/overview   # expect 401 (or 302 to the Microsoft login if the unauthenticated action is Redirect); never 200
  curl -s -o /dev/null -w '%{http_code}\n' -H "X-MS-CLIENT-PRINCIPAL: $P" https://<app>.azurewebsites.net/health/live         # 200 and no data: excluded paths stay data-free
  ```
  Repeat against every other ingress that exists (private endpoint name, custom domain, `*.scm.azurewebsites.net` must not serve the app). A 200 with data anywhere is a stop.
- [ ] **Readiness probe**: `curl -i https://<app>.azurewebsites.net/health/ready` returns `200 {"status":"ok"}`; with the DB stopped or the schema behind head it returns `503` with a reason code and no URL or exception text. The App Service health check path is `/health/ready` and at least 2 instances run.
- [ ] **Easy Auth excluded paths** are exactly `/health/live` and `/health/ready` (and `/api/v1/health` if used). Everything else requires sign-in: an anonymous browser request to `/` is redirected to Microsoft (or 401), `/api/v1/overview` and `/static/` behave as documented.
- [ ] **Role assignment**: *Assignment required = Yes*; the reader app role is assigned to the intended group; a signed-in user without the role gets 403 (page with no data); a user with the role gets 200. `AUTH_ALLOW_ANY_AUTHENTICATED` is unset. The app registration is single tenant.
- [ ] `APP_ENV=prod`; `/api/docs` and `/openapi.json` return 404; response headers include HSTS and the strict CSP; `ALLOWED_HOSTS` lists only your host names.
- [ ] All source URLs are `https://` (settings validation enforces it) and the credentials are read-only tokens with the scopes in USING_IN_YOUR_ORG.md phase 0.

**Data and operations**
- [ ] **Retention schedule** exists and ran once: `pch scans prune --keep 30 --older-than 90` (or `RETENTION_KEEP_SCANS` / `RETENTION_MAX_AGE_DAYS`) scheduled after the scan; `--dry-run` reviewed first.
- [ ] **Scan job**: runs `pch scan` out-of-band with `APP_ENV=prod`, `SCAN_TIMEOUT_MINUTES` below `SCAN_LOCK_STALE_MINUTES` (validated), exit code alerts (`4` = already running is benign; `1`, `2`, `3`, `5` alert).
- [ ] **Backup and restore of the database** tested, not assumed (next section).
- [ ] Logs reach Log Analytics / App Insights, and a sample of `exceptions`, `dependencies` and `requests` contains no URL query, credential or row value (SEC-09).
- [ ] Identities hold only the roles in the section 3 table; Azure SQL is Entra-only, the storage account has shared-key access disabled, Key Vault uses RBAC.
- [ ] Alerts: failed scan (exit code or no `complete` scan within 36 h), health check failures, 5xx rate.

### Backup, restore and rollback

**Database backup and restore.** Azure SQL: automated backups and point-in-time restore are on by default (check the retention you need; configure long-term retention if policy requires). PostgreSQL: your managed service's PITR or `pg_dump`. Before every release that includes a migration, take (or confirm) a restorable point.
Restore drill: restore to a **new** database name, point a staging copy of the app at it (`DATABASE_URL`), run `pch db current` and `pch doctor`, open the dashboard. Compliance data can be re-created by re-scanning (history cannot), so the drill's pass criterion is "schema at head and the latest scan visible".

**Rollback of the application.** Deployments are by image digest. Roll back by redeploying the previous image digest (`<acr>.azurecr.io/<repo>@sha256:<previous>`) to the web app and the scan job. Keep the digest of the running release in your release notes.
The app requires the database to be at **exactly the head revision of the running build** (`pch db check`, readiness `schema_not_ready`), so an older image will not start against a newer schema. Decide by the migrations in the release:

| Migrations in the release | Rollback |
|---|---|
| None | Redeploy the previous digest. Done. |
| Additive only (new table, new nullable column, new index) | Redeploy the previous digest after running the downgrade to the previous revision (below); it only drops the new, empty objects. Test it on a restored copy first. |
| Destructive or data-rewriting (drop, narrowing a type, backfill) | Do **not** run a downgrade in prod. Restore the pre-release backup into a new database, point the app at it, redeploy the previous digest, re-scan if needed. |

Downgrade (no CLI command exists for it; `pch db upgrade --revision` can only move forward). Run it from the previous or current image, with the app and scan job stopped:

```bash
python - <<'PY'
from pch.settings import get_settings
from pch.store.engine import build_engine
from pch.store.migrate import downgrade
downgrade(build_engine(get_settings().database_url), "<previous-revision-id>")   # never "base": that drops every table
PY
pch db check    # run with the PREVIOUS image: must report at head
```

Downgrading to `base` (or below revision `0001`) deletes all data and is never a rollback. Write a correct `downgrade()` for every migration you add (`CUSTOMIZING.md`, "Add a migration").
Release order that keeps rollback simple: stop the scan schedule, confirm the backup, `pch db upgrade` (as the deploy identity), deploy the new digest, check `/health/ready`, re-enable the schedule.

## 12. Where infrastructure-as-code goes

Express sections 1-3 and 5 (resources, role assignments, app settings, Easy Auth configuration) in your organisation's IaC repository (Bicep, Terraform, ...) and keep this runbook as the reference for what the app needs. The template deliberately ships none, so it does not dictate your modules or landing zone.

## Assumptions to verify on the real platform (`# VERIFY:` in code)

* `WEBSITE_AUTH_ENABLED=True` is exposed to the container when Authentication is enabled (`settings.py`, `guard.py`).
* Easy Auth strips/overwrites client-supplied `X-MS-CLIENT-PRINCIPAL*` headers on every request that reaches the container, including excluded paths and any non-public ingress (private endpoint, SCM) (`auth.py`).
* The principal header format (`auth_typ`, `name_typ`, `role_typ`, `claims[{typ,val}]`) and that app roles arrive as claims of type `roles` (`auth.py`).
* `/.auth/logout` is the sign-out endpoint.
* `FORWARDED_ALLOW_IPS=*` is safe because the App Service front end is the only way to reach the container (`settings.py`).
* The platform health probe sends the site host name as `Host` (so `ALLOWED_HOSTS` does not reject it); the container `HEALTHCHECK` uses a loopback Host, allowed for the three health paths only.
