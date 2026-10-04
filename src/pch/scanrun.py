"""Scan lifecycle guards: SIGTERM/SIGINT handling and the scan timeout reasons.

``run_guarded`` turns SIGTERM/SIGINT into a cancellation of the running scan. ``Scanner.run`` then marks the scan
``failed`` with reason ``interrupted`` (or ``timeout``) and re-raises; the CLI releases the scan lock (context manager)
and exits with ``exitcodes.INTERRUPTED``.
"""

from __future__ import annotations

import asyncio
import signal
from collections.abc import Awaitable
from typing import TypeVar

T = TypeVar("T")

REASON_INTERRUPTED = "interrupted"
REASON_TIMEOUT = "timeout"


class ScanInterrupted(Exception):
    """The scan was stopped by SIGTERM/SIGINT."""

    def __init__(self, signame: str = "") -> None:
        super().__init__(f"interrupted by {signame}" if signame else REASON_INTERRUPTED)
        self.signame = signame


class ScanTimeout(Exception):
    """The scan exceeded SCAN_TIMEOUT_MINUTES."""


async def run_guarded(coro: Awaitable[T]) -> T:
    """Await ``coro`` while SIGTERM/SIGINT cancel it. Raises ``ScanInterrupted`` on a signal.

    Signal handlers are only installed from the main thread's event loop (a no-op elsewhere, e.g. on Windows)."""
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    got: list[str] = []

    def on_signal(sig: signal.Signals) -> None:
        got.append(sig.name)
        if task is not None:
            task.cancel()

    installed: list[signal.Signals] = []
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, on_signal, sig)
            installed.append(sig)
        except (NotImplementedError, RuntimeError, ValueError):
            pass
    try:
        return await coro
    except asyncio.CancelledError:
        if got:
            raise ScanInterrupted(got[0]) from None
        raise
    finally:
        for sig in installed:
            loop.remove_signal_handler(sig)
