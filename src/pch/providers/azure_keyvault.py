"""Azure Key Vault SecretProvider (extra ``azure-keyvault``). Authenticates with DefaultAzureCredential
(managed identity on App Service, ``az login`` locally); no client secrets or connection strings.

The identity needs the *Key Vault Secrets User* role (RBAC) or ``get`` on secrets (access policy) on the vault.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from pch.logging_setup import register_secret
from pch.providers.errors import ProviderUnavailable, SecretBackendError
from pch.settings import Settings

EXTRA_HINT = "Azure Key Vault support needs the 'azure-keyvault' extra: pip install 'pipeline-compliance[azure-keyvault]'"


def default_secret_name(env_name: str) -> str:
    """``ADO_PAT`` -> ``ado-pat`` (Key Vault secret names allow only letters, digits and dashes)."""
    return env_name.lower().replace("_", "-")


def _is_not_found(exc: BaseException) -> bool:
    return any(c.__name__ == "ResourceNotFoundError" for c in type(exc).__mro__)


class KeyVaultSecretProvider:
    name = "azure_keyvault"

    def __init__(
        self,
        client: Any,
        *,
        name_map: dict[str, str] | None = None,
        ttl_seconds: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._map = dict(name_map or {})
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, str]] = {}

    @classmethod
    def from_settings(cls, settings: Settings) -> KeyVaultSecretProvider:
        if not settings.keyvault_url:
            raise ProviderUnavailable("SECRETS_PROVIDER=azure_keyvault requires KEYVAULT_URL")
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError as exc:
            raise ProviderUnavailable(EXTRA_HINT) from exc
        client = SecretClient(vault_url=settings.keyvault_url, credential=DefaultAzureCredential())
        return cls(client, name_map=settings.keyvault_secret_map, ttl_seconds=settings.keyvault_cache_ttl_seconds)

    def vault_name(self, env_name: str) -> str:
        return self._map.get(env_name, default_secret_name(env_name))

    def get(self, name: str) -> str | None:
        now = self._clock()
        with self._lock:
            hit = self._cache.get(name)
            if hit is not None and now - hit[0] < self._ttl:
                return hit[1]
        try:
            value = self._client.get_secret(self.vault_name(name)).value
        except Exception as exc:  # noqa: BLE001 - classify, never echo the SDK message
            if _is_not_found(exc):
                return None
            raise SecretBackendError(
                f"Key Vault lookup of {name} (as '{self.vault_name(name)}') failed: {type(exc).__name__}"
            ) from None
        if not value:
            return None
        register_secret(value)
        with self._lock:
            self._cache[name] = (now, value)
        return str(value)
