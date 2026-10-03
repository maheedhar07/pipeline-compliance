"""Azure Blob ArtifactStore (extra ``azure-blob``). Authenticates with DefaultAzureCredential (managed
identity); account keys, SAS tokens and connection strings are intentionally NOT supported.

The identity needs *Storage Blob Data Contributor* on the container. The sync SDK client is driven from worker
threads (``asyncio.to_thread``), which avoids the extra aiohttp dependency and never blocks the event loop.
"""

from __future__ import annotations

import asyncio
from typing import Any

from pch.providers.artifacts import validate_key
from pch.providers.errors import ProviderUnavailable
from pch.settings import Settings

EXTRA_HINT = "Azure Blob support needs the 'azure-blob' extra: pip install 'pipeline-compliance[azure-blob]'"


def _is_not_found(exc: BaseException) -> bool:
    return any(c.__name__ == "ResourceNotFoundError" for c in type(exc).__mro__)


class BlobArtifactStore:
    """``container`` is anything with the azure ``ContainerClient`` methods used below (tests pass a fake)."""

    name = "azure_blob"

    def __init__(self, container: Any) -> None:
        self._c = container

    @classmethod
    def from_settings(cls, settings: Settings) -> BlobArtifactStore:
        if not settings.artifact_blob_account_url or not settings.artifact_blob_container:
            raise ProviderUnavailable("ARTIFACT_STORE=azure_blob requires ARTIFACT_BLOB_ACCOUNT_URL and ARTIFACT_BLOB_CONTAINER")
        try:
            from azure.identity import DefaultAzureCredential
            from azure.storage.blob import ContainerClient
        except ImportError as exc:
            raise ProviderUnavailable(EXTRA_HINT) from exc
        return cls(
            ContainerClient(
                account_url=settings.artifact_blob_account_url,
                container_name=settings.artifact_blob_container,
                credential=DefaultAzureCredential(),
            )
        )

    def _get(self, key: str) -> bytes | None:
        try:
            return bytes(self._c.download_blob(key).readall())
        except Exception as exc:  # noqa: BLE001
            if _is_not_found(exc):
                return None
            raise

    def _list(self, prefix: str) -> list[str]:
        return sorted(b.name for b in self._c.list_blobs(name_starts_with=prefix or None))

    def _delete_prefix(self, prefix: str) -> int:
        n = 0
        for key in self._list(prefix):
            try:
                self._c.delete_blob(key)
                n += 1
            except Exception as exc:  # noqa: BLE001
                if not _is_not_found(exc):
                    raise
        return n

    async def put(self, key: str, data: bytes) -> None:
        validate_key(key)
        await asyncio.to_thread(self._c.upload_blob, key, data, overwrite=True)

    async def get(self, key: str) -> bytes | None:
        validate_key(key)
        return await asyncio.to_thread(self._get, key)

    async def list(self, prefix: str = "") -> list[str]:
        validate_key(prefix, allow_empty=True, allow_trailing_slash=True)
        return await asyncio.to_thread(self._list, prefix)

    async def delete_prefix(self, prefix: str) -> int:
        validate_key(prefix, allow_trailing_slash=True)
        return await asyncio.to_thread(self._delete_prefix, prefix)
