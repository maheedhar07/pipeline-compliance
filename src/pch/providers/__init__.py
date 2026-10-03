"""Provider seams: the only two places where deployment-specific backends plug in.

* ``get_secret_provider(settings)``  -> where credentials come from (env | file | azure_keyvault)
* ``get_artifact_store(settings)``   -> where the raw scan cache lives (local | azure_blob)

Azure adapters are optional extras; a missing extra raises ``ProviderUnavailable`` naming the pip command.
"""

from __future__ import annotations

from pathlib import Path

from pch.providers.artifacts import ArtifactStore, LocalArtifactStore, PrefixedStore, build_artifact_store
from pch.providers.errors import (
    InvalidArtifactKey,
    ProviderError,
    ProviderUnavailable,
    SecretBackendError,
    SecretNotFound,
)
from pch.providers.secrets import (
    SOURCE_SECRETS,
    EnvSecretProvider,
    FileSecretProvider,
    SecretProvider,
    build_secret_provider,
    require_secret,
)
from pch.settings import Settings


def get_secret_provider(settings: Settings) -> SecretProvider:
    return build_secret_provider(settings)


def get_artifact_store(settings: Settings, data_dir: Path | None = None) -> ArtifactStore:
    """``data_dir`` overrides ``settings.data_dir`` for the local store (the CLI's ``--data-dir``)."""
    return build_artifact_store(settings, data_dir)


__all__ = [
    "SOURCE_SECRETS",
    "ArtifactStore",
    "EnvSecretProvider",
    "FileSecretProvider",
    "InvalidArtifactKey",
    "LocalArtifactStore",
    "PrefixedStore",
    "ProviderError",
    "ProviderUnavailable",
    "SecretBackendError",
    "SecretNotFound",
    "SecretProvider",
    "get_artifact_store",
    "get_secret_provider",
    "require_secret",
]
