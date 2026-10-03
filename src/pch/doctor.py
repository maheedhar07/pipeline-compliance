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
from pch.settings import ConfigError, Settings, format_validation_error, load_policy, load_scope

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


def check_config_files(s: Settings, scope_path: Path | None, policy_path: Path | None) -> list[Check]:
    scope_p = scope_path or s.config_dir / "scope.yaml"
    policy_p = policy_path or s.config_dir / "policy.yaml"
    out: list[Check] = []
    for name, path, loader in (("scope.yaml", scope_p, lambda p: load_scope(p, required=s.is_prod)), ("policy.yaml", policy_p, load_policy)):
        try:
            loader(path)
        except ConfigError as exc:
            out.append(Check(name, FAIL, str(exc)))
            continue
        if path.exists():
            out.append(Check(name, OK, str(path)))
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


def run_checks(scope_path: Path | None = None, policy_path: Path | None = None) -> list[Check]:
    s, first = check_settings()
    checks = [first]
    if s is None:
        checks.append(Check("remaining checks", WARN, "skipped: settings are invalid"))
        return checks
    checks += check_config_files(s, scope_path, policy_path)
    checks += check_sources(s)
    checks += check_secrets(s)
    checks.append(check_database(s))
    mig = check_db_migrations(s)
    if mig is not None:
        checks.append(mig)
    checks.append(check_auth(s))
    checks.append(check_serve_guard(s))
    checks.append(check_data_dir(s))
    checks.append(check_artifact_store(s))
    return checks


def to_dict(checks: list[Check]) -> dict[str, object]:
    return {"ok": not any(c.status == FAIL for c in checks), "checks": [asdict(c) for c in checks]}
