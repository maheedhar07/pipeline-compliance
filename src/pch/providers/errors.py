"""Errors raised by the provider seams. All are configuration errors (the CLI prints them and exits 2)."""

from __future__ import annotations

from pch.settings import ConfigError


class ProviderError(ConfigError):
    """Base class. Messages may name a secret or key but never contain a secret value."""


class ProviderUnavailable(ProviderError):
    """A provider needs an optional extra (or a required setting) that is not available."""


class SecretNotFound(ProviderError):
    """A secret required by a configured source could not be resolved."""

    def __init__(self, name: str, provider: str, detail: str = "") -> None:
        self.name = name
        self.provider = provider
        extra = f" ({detail})" if detail else ""
        super().__init__(f"secret {name} was not found via SECRETS_PROVIDER={provider}{extra}")


class SecretBackendError(ProviderError):
    """The secret backend failed (auth, network, permissions). Carries the error type only."""


class InvalidArtifactKey(ProviderError, ValueError):
    """An artifact key tried to escape the store (absolute path, '..', backslash, control chars)."""
