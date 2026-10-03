"""SecretProvider seam: where credential values come from.

``env`` (default) reads the already-loaded Settings, ``file`` reads one file per secret from a mounted
directory (Kubernetes / CSI driver), ``azure_keyvault`` (extra ``azure-keyvault``) reads Azure Key Vault with
a managed identity. Providers are explicit: they are never mixed, so a missing secret is an error instead of a
silent fallback to another source. Secret values are never logged.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Protocol

from pydantic import SecretStr

from pch.providers.errors import ProviderUnavailable, SecretNotFound
from pch.settings import Settings

log = logging.getLogger(__name__)

# Credential env-style name per live source (the only secrets this app reads). Database passwords are part of
# DATABASE_URL; use DB_AUTH=azure_ad (no password) or an App Service Key Vault reference for that variable.
SOURCE_SECRETS: dict[str, tuple[str, ...]] = {
    "ado": ("ADO_PAT",),
    "sonar": ("SONAR_TOKEN",),
    "aikido": ("AIKIDO_CLIENT_SECRET",),
    "servicenow": ("SERVICENOW_PASSWORD",),
}
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class SecretProvider(Protocol):
    """``get`` returns the secret value, or None when it does not exist. Names are env-style (``ADO_PAT``)."""

    name: str

    def get(self, name: str) -> str | None: ...


def valid_secret_name(name: str) -> bool:
    return bool(_NAME.match(name)) and ".." not in name


class EnvSecretProvider:
    """Reads the credential fields of the already-loaded Settings (env vars / .env). Only SecretStr fields."""

    name = "env"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def get(self, name: str) -> str | None:
        v = getattr(self._settings, name.lower(), None)
        if isinstance(v, SecretStr):
            return v.get_secret_value() or None
        return None


class FileSecretProvider:
    """One file per secret under ``SECRETS_DIR`` (``<dir>/ADO_PAT``). Trailing newline stripped.

    Rejects names that could escape the directory (separators, ``..``) and files that resolve outside it.
    A world-readable file only produces a warning: Kubernetes secret volumes are 0644 by default.
    """

    name = "file"

    def __init__(self, directory: Path) -> None:
        self._dir = Path(directory)
        self._warned: set[str] = set()

    def get(self, name: str) -> str | None:
        if not valid_secret_name(name):
            raise SecretNotFound(name, self.name, "invalid secret name")
        root = self._dir.resolve()
        path = (root / name).resolve()  # symlinks inside the mount (K8s ..data) are fine, escapes are not
        if path.parent != root and root not in path.parents:
            raise SecretNotFound(name, self.name, "path escapes SECRETS_DIR")
        if not path.is_file():
            return None
        try:
            mode = path.stat().st_mode
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SecretNotFound(name, self.name, f"unreadable: {exc.strerror}") from None
        if mode & 0o004 and name not in self._warned:
            self._warned.add(name)
            log.warning("secret file for %s is world-readable; restrict its permissions (chmod 640/600)", name)
        value = raw.rstrip("\r\n")
        return value or None


def require_secret(provider: SecretProvider, name: str) -> str:
    """The secret's value, or SecretNotFound naming it (never the value)."""
    value = provider.get(name)
    if not value:
        raise SecretNotFound(name, provider.name)
    return value


def build_secret_provider(settings: Settings) -> SecretProvider:
    kind = settings.secrets_provider
    if kind == "env":
        return EnvSecretProvider(settings)
    if kind == "file":
        if settings.secrets_dir is None:
            raise ProviderUnavailable("SECRETS_PROVIDER=file requires SECRETS_DIR")
        return FileSecretProvider(settings.secrets_dir)
    if kind == "azure_keyvault":
        from pch.providers.azure_keyvault import KeyVaultSecretProvider

        return KeyVaultSecretProvider.from_settings(settings)
    raise ProviderUnavailable(f"unknown SECRETS_PROVIDER {kind!r}")  # pragma: no cover - Literal-validated
