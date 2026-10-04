# Using Pipeline Compliance Hub in your organisation

The one adoption path: code on GitHub, pipelines in Azure DevOps (YAML and Classic) moving to GitHub Actions. Do the phases in order; do not start a phase before the previous "Done when" holds.
Report-only: nothing here ever writes to GitHub, Azure DevOps, SonarQube, Aikido or ServiceNow. No live credentials are needed until phase 3.
Reference: [STANDARDS.md](STANDARDS.md) (every knob), [CUSTOMIZING.md](CUSTOMIZING.md) (recipes), [AI_GUIDE.md](AI_GUIDE.md) (for AI assistants), [DEPLOY_AZURE.md](DEPLOY_AZURE.md) (optional hosting).

## 0. Prerequisites

* Python 3.11 and git on the machine that runs the first scan.
* **Azure DevOps PAT, read-only**, owner = a service account if you have one. Scopes: Build (Read), Release (Read), Project and Team (Read), Service Connections (Read), Variable Groups (Read), Environment (Read), Task Groups (Read). Add Code (Read) only if `azure_repos` is in `code_hosts`. No write, manage or execute scope. Expiry: the maximum your policy allows, and a calendar reminder.
* **GitHub credential, read-only**, one of:
  * fine-grained PAT (default, `GITHUB_AUTH=pat`): resource owner = your organisation; repositories = all (or the ones you scan); repository permissions **Metadata, Contents, Actions, Environments, Deployments, Administration: all Read**. Administration is only for classic branch protection (without it that part is UNKNOWN). The organisation must allow fine-grained PATs.
  * GitHub App (`GITHUB_AUTH=app`): the same repository permissions, installed on the organisation; needs the `github-app` extra and a lockfile that includes it ([CUSTOMIZING.md](CUSTOMIZING.md#9-dependency-updates)).
* Optional sources, each unset = not queried: SonarQube user token with Browse permission; Aikido OAuth client id and secret; ServiceNow user with read access to `change_request`.
* Admin rights on the GitHub repository you import into (branch protection, environments, variables, secrets).

Done when: you hold the ADO PAT and the GitHub token and can name your ADO organisation and GitHub organisation(s).

## 1. Import the repository and protect `main`

```bash
git clone --mirror https://github.com/<source-owner>/pipeline-compliance.git
```

```bash
cd pipeline-compliance.git && git push --mirror https://github.com/<your-org>/pipeline-compliance.git
```

* Make the new repository **private**: your `config/` (org names, owners, waivers) lives in it. Keep `main` as the default branch. GitHub's *Import repository* works too.
* Settings, Rules: require a pull request (1+ approval), dismiss stale approvals, block force-push and deletion, require status checks `lint + types + tests (py3.11)`, `lint + types + tests (py3.12)`, `all extras (py3.11)`, `pip-audit (both lockfiles)`, `bandit (SAST)`, `gitleaks (secret scan)`, `db portability (postgres)`, `db portability (mssql)`.
* Settings, Actions: default workflow token read-only. Enable Dependabot alerts, secret scanning and push protection. Add `CODEOWNERS` and a `LICENSE` (none is shipped).
* Keep everything, including the demo (`pch scan --demo` stays a handy sandbox) and the tests. Delete only what you will not use: `docker-compose.yml`/`Dockerfile` (if you will not containerise), `docs/DEPLOY_AZURE.md` (if you will not host on App Service).
* CI needs no secrets. Never add the ADO PAT or the GitHub token as a repository secret (phase 4 uses an environment).

Done when: the first CI run on your `main` is green (all eight checks).

## 2. Set standards and scope

Edit `config/scope.yaml` (what is scanned) and `config/policy.yaml` (how it is judged). Both are strict: an unknown or mistyped key is an error naming file and path. Full knob list: [STANDARDS.md](STANDARDS.md). The five edits almost everyone makes:

```yaml
# config/scope.yaml
github:
  orgs: [acme]                        # 1. your GitHub organisation(s): GET /orgs/acme/repos
  exclude: ["sandbox-*", "acme/tmp-*"] # 2. globs on repo or org/repo; include_archived / include_forks default false
env_tiers: {"Blue": prod, "Staging": uat}   # 3. stage/environment name -> dev|test|uat|prod when the name heuristics guess wrong
repos:                                # per-repo facts: sonar_key, aikido_repo, owner, servicenow_ci, coverage_threshold, env_tiers
  - {project: Payments, repo: acme/ledger, owner: team-payments@acme.com}
```

```yaml
# config/policy.yaml
sonar_quality_gate_name: "Acme Way"     # 4. your org's values: gate, registries, marketplace tasks, reviewers, coverage floor
approved_registries: [acme.azurecr.io]
rules:                                  # 5. standards as config: disable, re-rate or tune a rule, no code
  QLT-004: {enabled: false}
  DEP-001: {severity: high}
  DEP-005: {params: {window_slack_hours: 4}}
```

* The Azure DevOps organisation is `ADO_ORG` (phase 3); `organization:` in `scope.yaml` is an optional fallback used only when `ADO_ORG` is empty. If both are set and differ, `pch scan` and `pch doctor` fail with a config error naming both; `pch doctor` shows which one supplied it. `projects: []` means every ADO project. `code_hosts` stays `[github]` (use `github_enterprise` for GHES).
* A repo's key is `<ADO project>/<org>/<repo>` when an ADO pipeline builds it, otherwise `<org>/<org>/<repo>`. Waivers, `exclude_repos` and overrides use that key (copy it from the Repos page).
* Replace the remaining placeholders: `git grep -nE 'your-org|example\.(com|net)|myorgacr|Sonar way' -- config .env.example`.
* List what a rule can be tuned with: `pch rules list --params --policy config/policy.yaml`.

Done when: `pch doctor` (phase 3) reports `scope.yaml` and `policy.yaml` as `OK`.

## 3. First run on real systems (local)

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"
```

```bash
cp .env.example .env
```

Edit `.env` (gitignored, read from the current directory). The minimum for a live scan:

```bash
APP_ENV=dev
ADO_ORG=<your-ado-org>
ADO_PAT=<read-only PAT>
GITHUB_TOKEN=<read-only fine-grained PAT>
```

Add `SONAR_URL` + `SONAR_TOKEN`, `AIKIDO_*`, `SERVICENOW_*` only if you use them (they are blank or commented out in `.env.example`, so unused sources stay off). Never paste a token into chat, a ticket or an AI assistant. Then:

```bash
pch doctor
```

Done when: no `FAIL` (a `WARN db_migrations ... empty` is fine before the next step). `pch doctor --json` is for machines; credentials show only as `set` / `missing`.

```bash
pch doctor --online
```

Done when: the `github_online` and `github_permissions` lines are `OK` (it calls `GET /rate_limit` and probes one repo per permission, read-only). A `WARN` names the permission to add.

```bash
pch db upgrade
```

Done when: `pch db check` exits 0.

```bash
pch scan
```

Done when: it prints `N repos, N findings, N collection errors, ...`. Cost: about 4 to 6 GitHub calls per repo plus a few Actions calls per workflow/environment; a PAT has 5,000 requests/hour and the scan waits out short rate limits.

```bash
pch serve
```

Open http://127.0.0.1:8000 (`AUTH_MODE=none` binds loopback only; see phase 5). Look at, in this order:

1. **Scans** page: collection errors per source. A missing permission or bad URL shows here, not as a crash. Fix those first.
2. **UNKNOWN** findings: the data was not collected (permission not granted, source not configured, unreadable file). UNKNOWN is never FAIL and is left out of the score; each carries the reason, often naming the permission. Fewer UNKNOWNs means more trustworthy scores.
3. **Overview** "Top reasons" and the Repos "Why" column: what makes repos non-compliant. Check a few against reality before trusting the rest.
4. **Migration** tab: which repos are ADO only, in progress, migrated.

Tune: edit `config/policy.yaml` or `scope.yaml`, run `pch doctor`, run `pch scan` again (standards apply when a scan is made, not retroactively). Replay without hitting the APIs: `pch scan --from-cache <scan_id>`.

## 4. Scheduled scans (GitHub Actions)

`.github/workflows/scheduled-scan.yml` runs `pch scan` daily at 02:00 UTC and on demand. It is opt-in, least-privilege, SHA-pinned and read-only. The runner is ephemeral, so `DATABASE_URL` must be a **server database** (Postgres or Azure SQL) that you migrated once (`pch db upgrade` with that URL in your local `.env`).

1. Settings, Environments, New environment `pch-scan` (add required reviewers or a branch limit if you want a gate).
2. Add secrets **to the environment** (not the repository), one per command; each prompts for the value:

```bash
gh secret set ADO_PAT --env pch-scan
```

| Secret (environment `pch-scan`) | Needed | Maps to |
|---|---|---|
| `ADO_PAT` | yes | `ADO_PAT` |
| `PCH_GITHUB_TOKEN` | yes (PAT mode) | `GITHUB_TOKEN` (GitHub forbids names starting `GITHUB_`) |
| `PCH_GITHUB_APP_PRIVATE_KEY` | App mode | `GITHUB_APP_PRIVATE_KEY` |
| `DATABASE_URL` | yes (may be a variable instead with `DB_AUTH=azure_ad`: no password in it) | `DATABASE_URL` |
| `SONAR_TOKEN`, `AIKIDO_CLIENT_SECRET`, `SERVICENOW_PASSWORD` | if used | same names |

| Variable (repository, Settings, Variables) | Needed | Default |
|---|---|---|
| `PCH_SCAN_ENABLED` | `true` to turn the job on | job skipped |
| `ADO_ORG` | yes | none |
| `PCH_GITHUB_AUTH`, `PCH_GITHUB_APP_ID`, `PCH_GITHUB_APP_INSTALLATION_ID`, `PCH_GITHUB_API_URL` | App mode / GHES | `pat`, none, none, `https://api.github.com` |
| `SONAR_URL`, `AIKIDO_URL`, `AIKIDO_CLIENT_ID`, `SERVICENOW_URL`, `SERVICENOW_USER`, `ADO_BASE_URL` | if used | Aikido and ADO public URLs |
| `RETENTION_KEEP_SCANS`, `RETENTION_MAX_AGE_DAYS` | to prune old scans after each run | no pruning |
| `CONCURRENCY`, `SCAN_TIMEOUT_MINUTES`, `APP_ENV`, `ARTIFACT_STORE` | rarely | `8`, `240`, `prod`, `local` |
| `DB_AUTH`, `PCH_LOCKFILE`, `PCH_INSTALL_ODBC`, `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` | Azure SQL with Entra login | `password`, `requirements.lock`, off, none |

For Azure SQL with `DB_AUTH=azure_ad`: set `DB_AUTH`, `PCH_LOCKFILE=requirements-azure.lock`, `PCH_INSTALL_ODBC=true` and the three `AZURE_*` ids of an app registration or managed identity with a federated credential for subject `repo:<org>/<repo>:environment:pch-scan`. The job then logs in over OIDC; no client secret is stored. `GITHUB_AUTH=app` needs a lockfile that includes the `github-app` extra in `PCH_LOCKFILE`.
`config/scope.yaml` and `config/policy.yaml` are read from the repository the workflow runs in: your private fork holds the real ones (`APP_ENV=prod` requires https URLs and `scope.yaml`).

```bash
gh variable set PCH_SCAN_ENABLED --body true
```

Run it once by hand (add `-f prune=false` to skip pruning), then watch it:

```bash
gh workflow run scheduled-scan.yml
```

```bash
gh run watch --exit-status
```

Read the **job summary** of the run: exit code with its meaning, repos scanned, status counts, collection errors per source (counts only). Change the schedule by editing the `cron` line (UTC). The dashboard shows a banner when the last scan is older than `SCAN_STALE_HOURS` (default 36) or failed.

| Exit | Meaning | Action |
|---|---|---|
| 0 | scan completed | none |
| 1 | generic failure (`prune` had failures) | read the job log |
| 2 | configuration error (invalid settings/YAML, missing secret or extra, `ADO_ORG` unset) | fix config, see phase 8 |
| 3 | database not ready (not at head, unreachable, driver missing) | `pch db upgrade`, check URL and firewall |
| 4 | another scan holds the lock | usually benign; alert only if it persists |
| 5 | interrupted or timed out (the scan is marked `failed`) | raise `SCAN_TIMEOUT_MINUTES` (keep below `SCAN_LOCK_STALE_MINUTES`) and the job `timeout-minutes` |

Done when: a manual run is green, the summary shows your repos, and the dashboard header reads `Last scan: ... (live)`.

## 5. Where the dashboard runs, and which database

**Pilot (default):** run `pch serve` on your own machine, or on a VM and reach it through `ssh -L 8000:127.0.0.1:8000 <vm>`. `AUTH_MODE=none` refuses any non-loopback bind and any `APP_ENV=prod`, by design. To share it, put an authenticating reverse proxy (Entra ID) on the same host, keep the bind on loopback and set `ALLOWED_HOSTS` to the proxy's name. **Shared and production:** Azure App Service with Easy Auth and Entra app roles, only if you choose that host: [DEPLOY_AZURE.md](DEPLOY_AZURE.md). Never expose `AUTH_MODE=none` on a network.

| Database | Use for | `DATABASE_URL` |
|---|---|---|
| SQLite | a local pilot only (cannot be shared with the Actions runner) | `sqlite:///data/pch.db` (default; migrates itself in `APP_ENV=dev`) |
| PostgreSQL | shared, simplest server option (extra `postgres`, already in `requirements.lock`) | `postgresql+psycopg://user:pw@host:5432/db` |
| Azure SQL | Microsoft shop, Entra login without a password (extra `azuresql`, ODBC Driver 18, `requirements-azure.lock`) | see README "Database"; `DB_AUTH=azure_ad` |

Server databases are never migrated implicitly: run `pch db upgrade` on every release before the app or the scan starts.

## 6. Day-2 tasks

* **Waiver** (a failure accepted until a date): add to `config/policy.yaml`, run `pch doctor`, commit, wait for the next scan.
  ```yaml
  waivers:
    - {rule: SRC-004, repo: "Payments/acme/api", reason: "GHA migration", owner: "a@acme.com", expires: 2027-03-31}
  ```
* **Change a severity or disable a rule:** `rules:` in `policy.yaml` (phase 2, edit 5). Never edit rule Python for this. Check with `pch rules list --params --policy config/policy.yaml`.
* **Add a rule:** [CUSTOMIZING.md](CUSTOMIZING.md#6-rules-policy-and-data-files): one decorated function, a PASS and a FAIL test, then `pch rules docs --write docs/RULES.md`.
* **New repo or organisation:** a new repo in a listed org is discovered by the next scan unless excluded. A new org: add it to `github.orgs` and make sure the token's resource owner covers it. Pipelines in a new ADO project are covered when `projects: []`.
* **Teach it a task or Action:** the YAML data files in `src/pch/normalize/` ([STANDARDS.md](STANDARDS.md)); data, not code.
* **Upgrade dependencies:** merge Dependabot PRs; when `pyproject.toml` changes regenerate **both** lockfiles ([CUSTOMIZING.md](CUSTOMIZING.md#9-dependency-updates)). To take template updates, merge the template's `main` into your fork; conflicts will be in `config/` only if you changed template defaults.
* **Prune scans:** preview, then do it (the workflow does it for you when `RETENTION_*` variables are set):
  ```bash
  pch scans prune --keep 30 --older-than 90 --dry-run
  ```

## 7. Don'ts and gotchas

* Never use a write-scoped token (GitHub, ADO or others): the code only reads, but a leaked write token is a needless blast radius. GitHub cannot report a fine-grained token's permissions, so check them when you create it.
* Never run scans inside the web app, and never schedule a scan on a laptop. One scan at a time (database lock); the workflow serialises runs.
* Change thresholds and standards in `policy.yaml`/`scope.yaml`, not in rule Python. Keep `capabilities.yaml`, `deprecated_tasks.yaml`, `gha_mapping.yaml` as data.
* Never call `create_all`: schema changes ship as Alembic revisions only ([CUSTOMIZING.md](CUSTOMIZING.md#add-a-migration-after-changing-a-model)).
* Keep `config/` in your **private** fork. Never commit `.env`, tokens or exported scan data; never put source credentials in repository secrets or CI.
* Never add `AUTH_ALLOW_ANY_AUTHENTICATED=true` or a non-loopback `AUTH_MODE=none` bind; the dashboard lists weaknesses of your estate.
* Some API shapes could not be checked without a real organisation and carry `# VERIFY:` comments (GitHub ruleset and branch-protection fields, Aikido endpoints, where CRQ numbers appear, how ServiceNow attaches to environments). On first contact compare a handful of repos with GitHub and ADO; the list is in [SECURITY_REVIEW.md](SECURITY_REVIEW.md#verify-markers-and-go-live-checklist).
* GitHub rate budget: about 4 to 6 calls per repo plus Actions calls. With thousands of repos prefer a GitHub App (higher limits), lower `CONCURRENCY`, and scan off-hours.
* `UNKNOWN` is information, not a pass. Do not waive it; grant the permission or configure the source.
* Not going live yet: before real users get access to a shared dashboard run the go-live gate in [DEPLOY_AZURE.md](DEPLOY_AZURE.md#11-verify-then-go-live) (or your equivalent) and read [THREAT_MODEL.md](THREAT_MODEL.md).

## 8. Troubleshooting

| Symptom (exact text) | Cause | Fix |
|---|---|---|
| `ADO_ORG is not set. Copy .env.example to .env, ...` (exit 2) | no `ADO_ORG` in the environment or `.env` of the current directory | set `ADO_ORG`; in Actions set the variable `ADO_ORG` |
| `Config error: secret ADO_PAT was not found via SECRETS_PROVIDER=env` | token missing; with `file` or `azure_keyvault` the env variable is ignored on purpose | set it in `.env`; in Actions add the secret to environment `pch-scan` |
| `database is empty (head is ...): run pch db upgrade`, or `database is at revision X but head is Y ...` | schema missing or behind this build | `pch db upgrade`, then `pch db check` |
| `database has tables but no alembic_version (created by an older version)` | database made before migrations existed | `pch db stamp head` only if it came from the initial release, else use an empty database |
| `config/policy.yaml: waivers.0.expires: ...` (file, field path) | strict YAML: unknown key, wrong type or date | fix the named field; `pch doctor` |
| `refusing to start (unsafe web configuration)` / `AUTH_MODE=none refuses to bind to non-loopback host` | `none` on a network address or `APP_ENV=prod` | bind 127.0.0.1 (SSH tunnel), or deploy with `easyauth` |
| browser shows `Invalid host` / HTTP 400 | Host header not allowed (only loopback names with `AUTH_MODE=none`) | open via `127.0.0.1`/`localhost`, or set `ALLOWED_HOSTS` |
| `APP_ENV=prod requires https:// for: ...` | a source URL is `http://` | use https URLs or `APP_ENV=dev` locally |
| `pch doctor`: `github   not configured ... GitHub-only checks are UNKNOWN` | no `GITHUB_TOKEN` / App credentials | set `GITHUB_TOKEN` |
| UNKNOWN reason `GitHub: ... denied (HTTP 403) (token needs: administration=read)` | token lacks that permission | add the named read permission, re-scan |
| UNKNOWN reason `GitHub: ... not found or not visible to the token (HTTP 404)` | repo outside the token's resource owner / repository selection, or the file does not exist | widen the token's repositories; for a missing file it is correct |
| `GitHub rate limit: ... not read (GitHub rate limit exhausted ...)` | quota used up for longer than the scan waits | lower `CONCURRENCY`, use a GitHub App, scan off-hours; check `pch doctor --online` |
| `another scan is running (holder ..., since ...)` (exit 4) | a scan or prune holds the lock | wait; a lock older than `SCAN_LOCK_STALE_MINUTES` (360) is taken over |
| `Azure Key Vault support needs the 'azure-keyvault' extra: pip install ...` (also Blob, `github-app`) | optional extra missing | `pip install '.[azure-keyvault]'`, or a lockfile that includes it |
| Workflow: `PCH_LOCKFILE '...' does not exist in the repository` | wrong `PCH_LOCKFILE` variable | `requirements.lock` or `requirements-azure.lock` |
| Workflow run skipped | `PCH_SCAN_ENABLED` is not exactly `true` | `gh variable set PCH_SCAN_ENABLED --body true` |
| Summary: `did not start. Install, pch doctor or pch db check failed` | pre-flight failed | open the job log; usually a missing secret/variable or an unmigrated database |
| Dashboard banner: last scan stale or failed | schedule not running or scan failing | check the Actions run; set `SCAN_STALE_HOURS` above the scan interval |
