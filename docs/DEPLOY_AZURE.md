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
5. **Excluded path:** `/api/v1/health` (and later `/health/*`) if the platform health check must reach it without sign-in. It returns status and version only. Everything else stays protected.
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
* The platform health probe sends the site host name as `Host` (so `ALLOWED_HOSTS` does not reject it); the container `HEALTHCHECK` uses a loopback Host, allowed for `/api/v1/health` only.
