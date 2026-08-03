from __future__ import annotations

import pytest

from boundarybench.daytona.transport import (
    is_transient_daytona_transport_error,
    retry_daytona_transport,
)


def test_retry_daytona_transport_retries_transient_failure(monkeypatch) -> None:
    attempts = 0

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("502 Bad Gateway")
        return "ok"

    monkeypatch.setattr(
        "boundarybench.daytona.transport.time.sleep", lambda _: None
    )

    assert retry_daytona_transport(operation, operation_name="test") == "ok"
    assert attempts == 2


def test_retry_daytona_transport_does_not_retry_non_transient_failure() -> None:
    attempts = 0

    def operation() -> None:
        nonlocal attempts
        attempts += 1
        raise ValueError("invalid request")

    with pytest.raises(ValueError, match="invalid request"):
        retry_daytona_transport(operation, operation_name="test", sleep_sec=0)
    assert attempts == 1


@pytest.mark.parametrize(
    "message",
    [
        "connection reset",
        "failed to resolve container IP",
        "service unavailable",
        "DaytonaError('Failed to upload files: ')",
    ],
)
def test_transient_daytona_transport_markers(message: str) -> None:
    assert is_transient_daytona_transport_error(RuntimeError(message))
