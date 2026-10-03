"""Startup guard: refuse to serve in any configuration that is not provably safe (fail closed).

``assert_safe_to_serve(settings, host)`` is called by ``create_app`` and by ``pch serve``. It collects *all*
problems so one run tells the operator everything to fix. It never prints secret values.

Fail-closed matrix (every row not listed as "ok" refuses to start):

  AUTH_MODE=none      APP_ENV=prod                                  -> refuse
                      bind host not loopback                        -> refuse, unless APP_ENV=dev and
                                                                       AUTH_NONE_ALLOW_CONTAINER_BIND=true
  AUTH_MODE=easyauth  neither AUTH_ALLOWED_ROLES nor
                      AUTH_ALLOW_ANY_AUTHENTICATED=true             -> refuse
                      both of them set                              -> refuse (ambiguous)
                      WEBSITE_AUTH_ENABLED != True and not
                      AUTH_EASYAUTH_ASSUME_ENABLED=true             -> refuse
                      AUTH_EASYAUTH_ASSUME_ENABLED=true in prod     -> refuse
  APP_ENV=prod        ALLOWED_HOSTS empty or containing "*"         -> refuse
                      AUTH_NONE_ALLOW_CONTAINER_BIND=true           -> refuse
"""

from __future__ import annotations

import ipaddress

from pch.settings import ConfigError, Settings


class UnsafeServeConfig(ConfigError):
    """The configuration would expose the dashboard unsafely."""


def is_loopback_host(host: str) -> bool:
    h = (host or "").strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False  # "", "0.0.0.0", "::", hostnames: not provably loopback


def guard_problems(s: Settings, host: str) -> list[str]:
    p: list[str] = []
    if s.auth_mode == "none":
        if s.is_prod:
            p.append("AUTH_MODE=none is not allowed when APP_ENV=prod. Use AUTH_MODE=easyauth (App Service Authentication with Entra ID).")
        if not is_loopback_host(host):
            if not (s.auth_none_allow_container_bind and s.is_dev):
                p.append(
                    f"AUTH_MODE=none refuses to bind to non-loopback host {host!r}. Bind 127.0.0.1, or put the app behind "
                    "AUTH_MODE=easyauth. (docker compose in APP_ENV=dev may set AUTH_NONE_ALLOW_CONTAINER_BIND=true while "
                    "publishing the port to 127.0.0.1 only.)"
                )
    elif s.auth_mode == "easyauth":
        roles, any_auth = s.allowed_roles, s.auth_allow_any_authenticated
        if not roles and not any_auth:
            p.append("AUTH_MODE=easyauth needs AUTH_ALLOWED_ROLES (e.g. PCH.Reader), or AUTH_ALLOW_ANY_AUTHENTICATED=true to explicitly allow every signed-in user.")
        if roles and any_auth:
            p.append("Set either AUTH_ALLOWED_ROLES or AUTH_ALLOW_ANY_AUTHENTICATED=true, not both (ambiguous authorization policy).")
        if s.auth_easyauth_assume_enabled and s.is_prod:
            p.append("AUTH_EASYAUTH_ASSUME_ENABLED=true is forbidden when APP_ENV=prod.")
        # VERIFY: App Service sets WEBSITE_AUTH_ENABLED=True in the container environment when Authentication is enabled,
        # and strips/overwrites client-supplied X-MS-CLIENT-PRINCIPAL* headers only then (App Service authentication docs).
        if not s.easyauth_platform_enabled and not (s.auth_easyauth_assume_enabled and not s.is_prod):
            p.append(
                "AUTH_MODE=easyauth requires App Service Authentication to be enabled (WEBSITE_AUTH_ENABLED=True): without it "
                "X-MS-CLIENT-PRINCIPAL is not stripped from client requests and can be forged. Enable Authentication on the "
                "Web App, or for local testing only set AUTH_EASYAUTH_ASSUME_ENABLED=true (APP_ENV!=prod)."
            )
    if s.is_prod:
        hosts = s.allowed_host_list
        if not hosts:
            p.append("APP_ENV=prod requires ALLOWED_HOSTS (e.g. myapp.azurewebsites.net or *.azurewebsites.net).")
        if "*" in hosts:
            p.append("ALLOWED_HOSTS must not contain a bare '*' when APP_ENV=prod.")
        if s.auth_none_allow_container_bind:
            p.append("AUTH_NONE_ALLOW_CONTAINER_BIND=true is forbidden when APP_ENV=prod.")
    return p


def assert_safe_to_serve(s: Settings, host: str) -> None:
    problems = guard_problems(s, host)
    if problems:
        raise UnsafeServeConfig("refusing to start (unsafe web configuration):\n  - " + "\n  - ".join(problems))
