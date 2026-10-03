"""ArtifactStore seam: where the redacted raw-response cache of a scan lives (``--from-cache``).

``local`` (default) writes under ``<DATA_DIR>/raw``; ``azure_blob`` (extra ``azure-blob``) uses a blob
container with a managed identity. Keys are relative, ``/`` separated paths such as
``<scan_id>/<host>/<hash>.json``. Callers MUST redact before ``put``; stores never inspect content.
All methods are async and never block the event loop (blocking I/O runs in a worker thread).
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path
from typing import Protocol

from pch.providers.errors import InvalidArtifactKey, ProviderUnavailable
from pch.settings import Settings


class ArtifactStore(Protocol):
    name: str

    async def put(self, key: str, data: bytes) -> None: ...

    async def get(self, key: str) -> bytes | None: ...

    async def list(self, prefix: str = "") -> list[str]:
        """All keys starting with ``prefix`` (string prefix), sorted."""
        ...

    async def delete_prefix(self, prefix: str) -> int:
        """Delete every key starting with ``prefix`` (must be non-empty). Returns how many were deleted."""
        ...


def validate_key(key: str, *, allow_empty: bool = False, allow_trailing_slash: bool = False) -> str:
    """Reject anything that could escape the store: absolute paths, ``..``, backslashes, control characters."""
    if not key:
        if allow_empty:
            return key
        raise InvalidArtifactKey("artifact key must not be empty")
    if "\\" in key or any(ord(c) < 32 or ord(c) == 127 for c in key):
        raise InvalidArtifactKey("artifact key contains a backslash or control character")
    if key.startswith("/"):
        raise InvalidArtifactKey("artifact key must be relative")
    parts = key.split("/")
    if allow_trailing_slash and parts[-1] == "":
        parts = parts[:-1]
    if any(p in ("", ".", "..") for p in parts):
        raise InvalidArtifactKey("artifact key must not contain empty, '.' or '..' segments")
    return key


class LocalArtifactStore:
    """Files under a base directory. Keys that resolve outside it (``..``, symlinks) are rejected."""

    name = "local"

    def __init__(self, base_dir: Path) -> None:
        self.base = Path(base_dir)

    def _path(self, key: str) -> Path:
        validate_key(key)
        base = self.base.resolve()
        p = (base / key).resolve()
        if base not in p.parents:
            raise InvalidArtifactKey("artifact key escapes the store directory")
        return p

    def _put(self, key: str, data: bytes) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".tmp-")  # mkstemp creates 0600
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, p)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def _get(self, key: str) -> bytes | None:
        p = self._path(key)
        try:
            return p.read_bytes()
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            return None

    def _keys(self, prefix: str) -> list[str]:
        validate_key(prefix, allow_empty=True, allow_trailing_slash=True)
        base = self.base.resolve()
        start = base / prefix.rpartition("/")[0] if "/" in prefix else base
        if not start.is_dir():
            return []
        keys = []
        for root, _dirs, files in os.walk(start):
            for f in files:
                if f.startswith(".tmp-"):
                    continue
                rel = (Path(root) / f).relative_to(base).as_posix()
                if rel.startswith(prefix):
                    keys.append(rel)
        return sorted(keys)

    def _delete_prefix(self, prefix: str) -> int:
        base = self.base.resolve()
        parents: set[Path] = set()
        n = 0
        for key in self._keys(prefix):
            p = self._path(key)
            p.unlink(missing_ok=True)
            parents.add(p.parent)
            n += 1
        for d in sorted(parents, key=lambda x: len(x.parts), reverse=True):  # prune emptied directories only
            while d != base and base in d.parents:
                try:
                    d.rmdir()
                except OSError:
                    break
                d = d.parent
        return n

    async def put(self, key: str, data: bytes) -> None:
        await asyncio.to_thread(self._put, key, data)

    async def get(self, key: str) -> bytes | None:
        return await asyncio.to_thread(self._get, key)

    async def list(self, prefix: str = "") -> list[str]:
        return await asyncio.to_thread(self._keys, prefix)

    async def delete_prefix(self, prefix: str) -> int:
        validate_key(prefix, allow_trailing_slash=True)  # non-empty: never wipe the whole store
        return await asyncio.to_thread(self._delete_prefix, prefix)


class PrefixedStore:
    """View of a store under ``prefix/`` (one scan's cache). Same protocol; keys are relative to the prefix."""

    def __init__(self, inner: ArtifactStore, prefix: str) -> None:
        validate_key(prefix)
        self.inner = inner
        self.prefix = prefix.rstrip("/") + "/"
        self.name = inner.name

    async def put(self, key: str, data: bytes) -> None:
        await self.inner.put(self.prefix + validate_key(key), data)

    async def get(self, key: str) -> bytes | None:
        return await self.inner.get(self.prefix + validate_key(key))

    async def list(self, prefix: str = "") -> list[str]:
        validate_key(prefix, allow_empty=True, allow_trailing_slash=True)
        return [k[len(self.prefix):] for k in await self.inner.list(self.prefix + prefix)]

    async def delete_prefix(self, prefix: str) -> int:
        return await self.inner.delete_prefix(self.prefix + validate_key(prefix, allow_trailing_slash=True))


def build_artifact_store(settings: Settings, data_dir: Path | None = None) -> ArtifactStore:
    kind = settings.artifact_store
    if kind == "local":
        return LocalArtifactStore((data_dir if data_dir is not None else settings.data_dir) / "raw")
    if kind == "azure_blob":
        from pch.providers.azure_blob import BlobArtifactStore

        return BlobArtifactStore.from_settings(settings)
    raise ProviderUnavailable(f"unknown ARTIFACT_STORE {kind!r}")  # pragma: no cover - Literal-validated
