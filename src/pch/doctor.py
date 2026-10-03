"""``pch doctor``: environment and configuration self-check.

Reports only OK / WARN / FAIL plus non-secret detail. Credential values are never read into output:
sources are reported as "set" / "missing" by field name.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path

from pydantic import ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

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


def check_sources(s: Settings) -> list[Check]:
    configured = s.source_requirements()
    if not configured:
        return [Check("sources", WARN, "no live source configured (demo mode only)")]
    out = []
    for src, fields in configured.items():
        missing = [k for k, ok in fields.items() if not ok]
        detail = ", ".join(f"{k}={'set' if ok else 'missing'}" for k, ok in fields.items())
        out.append(Check(f"source:{src}", FAIL if missing else OK, detail))
    return out


def check_database(s: Settings) -> Check:
    """Connectivity only. T3 extends this with a migration-head check (see ``check_db_migrations``)."""
    try:
        url = make_url(s.database_url)
    except Exception:  # noqa: BLE001 - message could echo the URL, keep it generic
        return Check("database", FAIL, "DATABASE_URL could not be parsed")
    shown = url.render_as_string(hide_password=True)
    try:
        engine = create_engine(url)
    except Exception as exc:  # noqa: BLE001 - e.g. missing DB driver
        return Check("database", FAIL, f"{shown}: cannot create engine ({type(exc).__name__})")
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        return Check("database", FAIL, f"{shown}: connection failed ({type(exc).__name__})")
    finally:
        engine.dispose()
    return Check("database", OK, shown)


def check_db_migrations(s: Settings) -> Check | None:
    """Extension point for T3 (Alembic head check). Returns None until migrations exist."""
    return None


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
    checks.append(check_database(s))
    mig = check_db_migrations(s)
    if mig is not None:
        checks.append(mig)
    checks.append(check_data_dir(s))
    return checks


def to_dict(checks: list[Check]) -> dict[str, object]:
    return {"ok": not any(c.status == FAIL for c in checks), "checks": [asdict(c) for c in checks]}
