"""Small bounded retries for idempotent Daytona control-plane operations."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

from boundarybench.benchmarks.common.status_taxonomy import (
    DAYTONA_CONNECTION_MARKERS,
)


T = TypeVar("T")

_TRANSIENT_MARKERS = (
    *DAYTONA_CONNECTION_MARKERS,
    "failed to resolve container ip",
    "max retries exceeded",
    "temporarily unavailable",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
    "http 502",
    "status 502",
)

_EMPTY_ERROR_MARKERS = (
    "failed to execute command:",
    "failed to get session command:",
    "failed to create session:",
    "failed to upload files:",
)


def is_transient_daytona_transport_error(exc: BaseException) -> bool:
    """Return whether a Daytona control-plane operation is safe to retry."""

    text = f"{type(exc).__name__}: {exc!r}".lower()
    if any(marker in text for marker in _TRANSIENT_MARKERS):
        return True
    return any(
        marker in text and not text.split(marker, 1)[1].strip(" '\"()[]{}")
        for marker in _EMPTY_ERROR_MARKERS
    )


def retry_daytona_transport(
    operation: Callable[[], T],
    *,
    operation_name: str,
    max_attempts: int = 3,
    sleep_sec: float = 5,
    should_retry: Callable[[BaseException], bool] = (
        is_transient_daytona_transport_error
    ),
) -> T:
    """Run an idempotent operation with a small transient retry budget."""

    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")
    for attempt in range(1, max_attempts + 1):
        try:
            return operation()
        except Exception as exc:
            if attempt == max_attempts or not should_retry(exc):
                raise
            print(
                f"[daytona-transport] retrying {operation_name} "
                f"({attempt}/{max_attempts}): {exc!r}",
                flush=True,
            )
            time.sleep(sleep_sec)
    raise AssertionError("unreachable")
