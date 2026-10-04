"""``pch doctor``: environment and configuration self-check.

Reports only OK / WARN / FAIL plus non-secret detail. Credential values are never read into output:
sources are reported as "set" / "missing" by field name.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.engine import make_url

from pch.providers.secrets import SOURCE_SECRETS
from pch.settings import (
    ConfigError,
    Policy,
    Scope,
    Settings,
    format_validation_error,
    load_policy,
    load_scope,
    resolve_ado_org,
)

OK, WARN, FAIL = "OK", "WARN", "FAIL"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""


def check_settings() -> tuple[Settings | None, Check]:
    try:
        # Bypass the lru_cache so doctor always reflects the current environment.
        s = Settings()
    except ValidationError as exc:
        return None, Check("settings", FAIL, format_validation_error("environment", exc))
    return s, Check("settings", OK, f"APP_ENV={s.app_env}")


def _config_summary(cfg: Scope | Policy) -> str:
    """What the loaded file switches on, so `pch doctor` shows the effective standards at a glance."""
    if isinstance(cfg, Scope):
        return f" (code_hosts: {', '.join(cfg.code_hosts)})"
    parts = []
    off = sorted(r for r, o in cfg.rules.items() if not o.enabled)
    sev = sorted(r for r, o in cfg.rules.items() if o.enabled and o.severity is not None)
    prm = sorted(r for r, o in cfg.rules.items() if o.params)
    if off:
        parts.append(f"disabled rules: {', '.join(off)}")
    if sev:
        parts.append(f"severity overrides: {', '.join(sev)}")
    if prm:
        parts.append(f"param overrides: {', '.join(prm)}")
    if cfg.scoring.model_fields_set:
        parts.append("custom scoring")
    return f" ({'; '.join(parts)})" if parts else ""


def check_ado_org(s: Settings, scope: Scope | None) -> tuple[Check, Settings]:
    """Which source provided the Azure DevOps organisation (ADO_ORG, else scope.yaml ``organization``); a conflict between them fails."""
    try:
        org, origin = resolve_ado_org(s, scope)
    except ConfigError as exc:
        return Check("ado_org", FAIL, str(exc)), s
    if not org:
        return Check("ado_org", WARN, "not set: set ADO_ORG (or `organization:` in scope.yaml) for live scans"), s
    return Check("ado_org", OK, f"{org} (from {origin})"), s.model_copy(update={"ado_org": org})


def check_config_files(s: Settings, scope_path: Path | None, policy_path: Path | None) -> list[Check]:
    scope_p = scope_path or s.config_dir / "scope.yaml"
    policy_p = policy_path or s.config_dir / "policy.yaml"
    out: list[Check] = []
    for name, path, loader in (("scope.yaml", scope_p, lambda p: load_scope(p, required=s.is_prod)), ("policy.yaml", policy_p, load_policy)):
        try:
            cfg = loader(path)
        except ConfigError as exc:
            out.append(Check(name, FAIL, str(exc)))
            continue
        if path.exists():
            out.append(Check(name, OK, f"{path}{_config_summary(cfg)}"))
        else:
            out.append(Check(name, WARN, f"{path} not found, using defaults"))
    return out


def _configured_sources(s: Settings) -> dict[str, dict[str, bool]]:
    # With env the credential variables themselves signal that a source is configured; with another provider
    # only the non-secret fields can (the credential env vars are ignored there).
    return s.source_requirements(include_secrets=s.secrets_provider == "env")


def check_sources(s: Settings) -> list[Check]:
    """Non-secret fields per configured source. Credentials are reported by ``check_secrets``."""
    configured = _configured_sources(s)
    if not configured:
        return [Check("sources", WARN, "no live source configured (demo mode only)")]
    out = []
    for src, fields in configured.items():
        if src == "github":
            continue  # reported by check_github
        fields = {k: ok for k, ok in fields.items() if k not in SOURCE_SECRETS[src]}
        missing = [k for k, ok in fields.items() if not ok]
        detail = ", ".join(f"{k}={'set' if ok else 'missing'}" for k, ok in fields.items())
        out.append(Check(f"source:{src}", FAIL if missing else OK, detail))
    return out


def check_secrets(s: Settings) -> list[Check]:
    """Resolve every credential the configured sources need through the SecretProvider (set/missing only)."""
    from pch.providers import ProviderError, get_secret_provider

    try:
        provider = get_secret_provider(s)
    except ProviderError as exc:
        return [Check("secrets_provider", FAIL, str(exc))]
    configured = _configured_sources(s)
    if not configured:
        return [Check("secrets_provider", OK, provider.name)]
    out = [Check("secrets_provider", OK, provider.name)]
    for src in configured:
        if src == "github":
            continue  # reported by check_github
        parts, bad = [], False
        for name in SOURCE_SECRETS[src]:
            try:
                ok = bool(provider.get(name))
            except ProviderError as exc:
                parts.append(f"{name}=error ({exc})")
                bad = True
                continue
            parts.append(f"{name}={'set' if ok else 'missing'}")
            bad = bad or not ok
        out.append(Check(f"secret:{src}", FAIL if bad else OK, ", ".join(parts)))
    return out


def _jwt_ready() -> bool:
    try:
        import jwt

        return bool(getattr(jwt.algorithms, "has_crypto", False))
    except ImportError:
        return False


def check_github(s: Settings, scope: Scope | None = None) -> Check:
    """Offline: auth mode, which credentials are set/missing (never values) and, for App mode, whether the extra is installed."""
    from pch.providers import ProviderError, get_secret_provider, source_secret_names

    try:
        provider = get_secret_provider(s)
    except ProviderError:
        return Check("github", WARN, "skipped: the secrets provider is not usable (see secrets_provider)")
    parts: list[str] = [f"auth={s.github_auth}", f"api={s.github_api_url}"]
    missing = False
    try:
        secrets_ok = {n: bool(provider.get(n)) for n in source_secret_names(s, "github")}
    except ProviderError as exc:
        return Check("github", FAIL, f"{', '.join(parts)}; {exc}")
    if s.github_auth == "app":
        ids = {"GITHUB_APP_ID": bool(s.github_app_id), "GITHUB_APP_INSTALLATION_ID": bool(s.github_app_installation_id)}
        configured = any(ids.values()) or any(secrets_ok.values())
    else:
        ids = {}
        configured = any(secrets_ok.values())
    orgs = scope.github.orgs if scope else []
    if not configured:
        note = f"; scope.yaml github.orgs {orgs} will NOT be discovered" if orgs else ""
        return Check("github", WARN if orgs else OK, f"not configured ({', '.join(parts)}): GitHub reader disabled, GitHub-only checks are UNKNOWN{note}")
    for name, ok in {**ids, **secrets_ok}.items():
        parts.append(f"{name}={'set' if ok else 'missing'}")
        missing = missing or not ok
    if s.github_auth == "app":
        if _jwt_ready():
            parts.append("github-app extra=installed")
        else:
            parts.append("github-app extra=MISSING (pip install 'pipeline-compliance[github-app]')")
            missing = True
    elif s.github_app_id:
        parts.append("note: GITHUB_APP_* set but GITHUB_AUTH=pat")
    parts.append("orgs=" + (", ".join(orgs) if orgs else "none in scope.yaml (only repos referenced by ADO pipelines)"))
    return Check("github", FAIL if missing else OK, ", ".join(parts))


async def _github_online(s: Settings, scope: Scope | None) -> list[Check]:
    import httpx

    from pch.collectors.github.client import RateLimited
    from pch.collectors.github.reader import reason_for
    from pch.collectors.http import HttpError
    from pch.providers import get_secret_provider
    from pch.sources import _github_client

    client = _github_client(s, httpx.AsyncHTTPTransport(retries=1), {"backoff_base": 0.5, "max_attempts": 2, "timeout": s.http_timeout}, get_secret_provider(s))
    if client is None:
        return [Check("github_online", WARN, "skipped: GitHub reader is not configured")]
    out: list[Check] = []
    try:
        try:
            core = await client.rate_limit()
            from datetime import datetime

            reset = datetime.fromtimestamp(int(core["reset"])).strftime("%H:%M:%S") if core.get("reset") else "?"
            low = isinstance(core.get("remaining"), int) and core["remaining"] < 200
            out.append(Check("github_online", WARN if low else OK, f"rate limit: {core.get('remaining')}/{core.get('limit')} requests left, resets {reset}"))
        except HttpError as exc:
            hint = "the token/App was rejected (expired, revoked or wrong GITHUB_API_URL)" if exc.status == 401 else f"HTTP {exc.status}"
            return [Check("github_online", FAIL, f"GET /rate_limit failed: {hint}")]
        except RateLimited as exc:
            return [Check("github_online", WARN, str(exc))]
        orgs = scope.github.orgs if scope else []
        if not orgs:
            return out + [Check("github_permissions", OK, "no organisation in scope.yaml to probe (only /rate_limit was called)")]
        probes = []
        try:
            first = await client.get_json(f"/orgs/{orgs[0]}/repos", {"type": "all", "per_page": 1})
        except Exception as exc:  # noqa: BLE001
            return out + [Check("github_permissions", WARN, reason_for(exc, f"organisation {orgs[0]} listing", "Metadata: read"))]
        if not first:
            return out + [Check("github_permissions", WARN, f"organisation {orgs[0]} lists no repositories visible to this credential")]
        full, branch = first[0]["full_name"], first[0].get("default_branch") or "main"
        for label, path, need in (("rules/branches", f"/repos/{full}/rules/branches/{branch}", "Metadata: read"),
                                  ("file tree", f"/repos/{full}/git/trees/{branch}", "Contents: read"),
                                  ("classic branch protection", f"/repos/{full}/branches/{branch}/protection", "Administration: read"),
                                  ("actions workflows", f"/repos/{full}/actions/workflows?per_page=1", "Actions: read"),
                                  ("environments", f"/repos/{full}/environments?per_page=1", "Environments: read"),
                                  ("deployments", f"/repos/{full}/deployments?per_page=1", "Deployments: read")):
            try:
                await client.get_json(path)
                probes.append(f"{label}=ok")
            except HttpError as exc:
                if exc.status == 404 and label == "classic branch protection":
                    probes.append(f"{label}=ok (none set)")
                elif exc.status in (404, 409) and label == "file tree":
                    probes.append(f"{label}=ok (empty)" if exc.status == 409 else f"{label}=MISSING")
                else:
                    probes.append(f"{label}=MISSING ({reason_for(exc, label, need).split(': ', 1)[-1]})")
            except Exception as exc:  # noqa: BLE001
                probes.append(f"{label}=? ({type(exc).__name__})")
        bad = [p for p in probes if "MISSING" in p or "=?" in p]
        out.append(Check("github_permissions", WARN if bad else OK, f"probed {full}: " + "; ".join(probes) + ("; unreadable parts are UNKNOWN in rules, never FAIL" if bad else "")))
    finally:
        await client.aclose()
    return out


def check_github_online(s: Settings, scope: Scope | None = None) -> list[Check]:
    """``pch doctor --online``: GET /rate_limit (quota) and, when scope.yaml names an organisation, one read-only probe per permission."""
    import asyncio

    try:
        return asyncio.run(_github_online(s, scope))
    except Exception as exc:  # noqa: BLE001 - never echo SDK messages
        return [Check("github_online", FAIL, f"probe failed ({type(exc).__name__})")]


def check_artifact_store(s: Settings) -> Check:
    """Write, read back and delete a probe key in the configured artifact store."""
    import asyncio

    from pch.providers import ProviderError, get_artifact_store

    key = f".doctor/probe-{os.getpid()}"
    try:
        store = get_artifact_store(s)
    except ProviderError as exc:
        return Check("artifact_store", FAIL, str(exc))

    async def probe() -> bool:
        await store.put(key, b"ok")
        try:
            return await store.get(key) == b"ok"
        finally:
            await store.delete_prefix(key)

    try:
        ok = asyncio.run(probe())
    except Exception as exc:  # noqa: BLE001 - never echo SDK messages
        return Check("artifact_store", FAIL, f"{store.name}: probe failed ({type(exc).__name__})")
    if not ok:
        return Check("artifact_store", FAIL, f"{store.name}: probe read back different data")
    return Check("artifact_store", OK, store.name)


def check_database(s: Settings) -> Check:
    """Connectivity only; the migration state is reported separately by ``check_db_migrations``."""
    from pch.store.azure_sql import AzureSqlUnavailable
    from pch.store.engine import build_engine

    try:
        url = make_url(s.database_url)
    except Exception:  # noqa: BLE001 - message could echo the URL, keep it generic
        return Check("database", FAIL, "DATABASE_URL could not be parsed")
    shown = url.render_as_string(hide_password=True)
    try:
        engine = build_engine(url, s)
    except AzureSqlUnavailable as exc:
        return Check("database", FAIL, str(exc))
    except Exception as exc:  # noqa: BLE001 - e.g. missing DB driver
        return Check("database", FAIL, f"{shown}: cannot create engine ({type(exc).__name__})")
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        return Check("database", FAIL, f"{shown}: connection failed ({type(exc).__name__})")
    finally:
        engine.dispose()
    return Check("database", OK, shown + (" (auth: azure_ad)" if s.db_auth == "azure_ad" else ""))


def check_db_migrations(s: Settings) -> Check | None:
    """Migration head vs the database's current revision. None when the database is unreachable
    (``check_database`` already reports that)."""
    from pch.store import migrate
    from pch.store.engine import build_engine

    try:
        engine = build_engine(s.database_url, s)
    except Exception:  # noqa: BLE001
        return None
    try:
        st = migrate.db_state(engine)
    except Exception:  # noqa: BLE001
        return None
    finally:
        engine.dispose()
    if st.at_head:
        return Check("db_migrations", OK, f"at head {st.head}")
    auto = s.db_auto_migrate or (engine.dialect.name == "sqlite" and not s.is_prod)
    reason = migrate.not_ready_reason(st)
    if auto and not st.unversioned:
        return Check("db_migrations", WARN, f"{reason} (will be applied automatically on start)")
    return Check("db_migrations", FAIL, reason)


def check_auth(s: Settings) -> Check:
    """Web auth posture. Never prints values; FAIL when the configuration would be refused at start-up."""
    from pch.web.guard import guard_problems

    problems = [x for x in guard_problems(s, s.host) if "AUTH" in x or "WEBSITE_AUTH" in x]
    if s.auth_mode == "easyauth":
        roles = f"roles allowlist set ({len(s.allowed_roles)})" if s.allowed_roles else ("any authenticated user" if s.auth_allow_any_authenticated else "NO allowlist")
        platform = "WEBSITE_AUTH_ENABLED=True" if s.easyauth_platform_enabled else ("assumed enabled (AUTH_EASYAUTH_ASSUME_ENABLED)" if s.auth_easyauth_assume_enabled else "WEBSITE_AUTH_ENABLED not True")
        detail = f"mode=easyauth, {roles}, {platform}"
    else:
        detail = "mode=none (local development only)"
    if problems:
        return Check("auth", FAIL, f"{detail}; " + " ".join(problems))
    return Check("auth", WARN if s.auth_mode == "none" else OK, detail)


def check_serve_guard(s: Settings) -> Check:
    """Would ``pch serve`` / ``create_app`` start with this configuration (bind host from HOST)?"""
    from pch.web.guard import UnsafeServeConfig, assert_safe_to_serve

    try:
        assert_safe_to_serve(s, s.host)
    except UnsafeServeConfig as exc:
        return Check("serve_guard", FAIL, str(exc).replace("\n", " "))
    return Check("serve_guard", OK, f"safe to serve on {s.host}:{s.effective_port}")


def check_logging(s: Settings) -> Check:
    from pch.logging_setup import effective_format

    return Check("logging", OK, f"format={effective_format(s)}, level={s.log_level}")


def check_telemetry(s: Settings) -> Check:
    """Application Insights: disabled (no connection string), enabled (string + extra), FAIL when the extra is missing."""
    from pch.telemetry import EXTRA_HINT, connection_string, sdk_available

    if not connection_string(s):
        return Check("telemetry", OK, "disabled (APPLICATIONINSIGHTS_CONNECTION_STRING not set)")
    if not sdk_available():
        return Check("telemetry", FAIL, f"extra missing: {EXTRA_HINT}")
    return Check("telemetry", OK, "enabled (Application Insights; connection string set)")


def check_data_dir(s: Settings) -> Check:
    d = s.data_dir
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe = d / f".doctor-{os.getpid()}"
        probe.write_text("")
        probe.unlink()
    except OSError as exc:
        return Check("data_dir", FAIL, f"{d} is not writable ({exc.strerror})")
    return Check("data_dir", OK, str(d))


def _scope_or_none(s: Settings, scope_path: Path | None) -> Scope | None:
    try:
        return load_scope(scope_path or s.config_dir / "scope.yaml", required=False)
    except ConfigError:
        return None  # reported by check_config_files


def run_checks(scope_path: Path | None = None, policy_path: Path | None = None, online: bool = False) -> list[Check]:
    s, first = check_settings()
    checks = [first]
    if s is None:
        checks.append(Check("remaining checks", WARN, "skipped: settings are invalid"))
        return checks
    checks += check_config_files(s, scope_path, policy_path)
    scope = _scope_or_none(s, scope_path)
    org_check, s_eff = check_ado_org(s, scope)
    checks.append(org_check)
    checks += check_sources(s_eff)
    checks += check_secrets(s_eff)
    checks.append(check_github(s, scope))
    if online:
        checks += check_github_online(s, scope)
    checks.append(check_database(s))
    mig = check_db_migrations(s)
    if mig is not None:
        checks.append(mig)
    checks.append(check_auth(s))
    checks.append(check_serve_guard(s))
    checks.append(check_logging(s))
    checks.append(check_telemetry(s))
    checks.append(check_data_dir(s))
    checks.append(check_artifact_store(s))
    return checks


def to_dict(checks: list[Check]) -> dict[str, object]:
    return {"ok": not any(c.status == FAIL for c in checks), "checks": [asdict(c) for c in checks]}
