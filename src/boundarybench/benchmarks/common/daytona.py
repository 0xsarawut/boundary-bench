from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor

from inspect_ai.model import ModelUsage

from boundarybench.benchmarks.common.status_taxonomy import (
    DAYTONA_LIFECYCLE_MARKERS,
)


DEFAULT_AGENT_TIMEOUT_SEC = 3600
DAYTONA_MAX_PARALLEL = 100

_EXECUTORS: dict[str, ThreadPoolExecutor] = {}
_EXECUTORS_LOCK = threading.Lock()


def env_agent_timeout() -> int:
    raw = os.environ.get("BOUNDARYBENCH_AGENT_TIMEOUT_SEC")
    return int(raw) if raw else DEFAULT_AGENT_TIMEOUT_SEC


def max_concurrent() -> int:
    raw = os.environ.get("BOUNDARYBENCH_MAX_CONCURRENT")
    n = int(raw) if raw else 5
    return max(1, min(n, DAYTONA_MAX_PARALLEL))


def runner_executor(thread_name_prefix: str) -> ThreadPoolExecutor:
    executor = _EXECUTORS.get(thread_name_prefix)
    if executor is not None:
        return executor
    with _EXECUTORS_LOCK:
        executor = _EXECUTORS.get(thread_name_prefix)
        if executor is None:
            executor = ThreadPoolExecutor(
                max_workers=max_concurrent(),
                thread_name_prefix=thread_name_prefix,
            )
            _EXECUTORS[thread_name_prefix] = executor
        return executor


def shutdown_runner_executor(thread_name_prefix: str, *, wait: bool = True) -> None:
    with _EXECUTORS_LOCK:
        executor = _EXECUTORS.pop(thread_name_prefix, None)
    if executor is not None:
        executor.shutdown(wait=wait, cancel_futures=True)


def record_model_usage(model: str, usage: ModelUsage | None) -> None:
    if usage is None:
        return
    try:
        from inspect_ai.model._model import record_and_check_model_usage

        record_and_check_model_usage(model, usage)
    except Exception:  # noqa: BLE001 - usage accounting must never fail a task
        pass


def is_transient_daytona_error(exc: Exception) -> bool:
    text = repr(exc).lower()
    return any(marker in text for marker in DAYTONA_LIFECYCLE_MARKERS)
