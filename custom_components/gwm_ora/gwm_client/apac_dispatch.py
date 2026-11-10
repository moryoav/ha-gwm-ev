"""Track the physical dispatch boundary of one APAC command task."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(slots=True)
class ApacCommandDispatch:
    """Keep queued cancellation separate from an uncertain, dispatched write."""

    started: bool = False
    cancelled: bool = False


_CURRENT_DISPATCH: ContextVar[ApacCommandDispatch | None] = ContextVar(
    "gwm_apac_command_dispatch", default=None
)


@contextmanager
def track_apac_dispatch(dispatch: ApacCommandDispatch) -> Iterator[None]:
    """Associate the command's nested send calls with their cancellation state."""
    token = _CURRENT_DISPATCH.set(dispatch)
    try:
        yield
    finally:
        _CURRENT_DISPATCH.reset(token)


def mark_apac_dispatch_started() -> None:
    """Reject a cancelled queue entry immediately before handing it to transport."""
    dispatch = _CURRENT_DISPATCH.get()
    if dispatch is not None:
        if dispatch.cancelled:
            raise asyncio.CancelledError
        dispatch.started = True
