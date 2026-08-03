from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from importlib import import_module
from inspect import Parameter, isawaitable, signature
from typing import Any, Callable

@dataclass(frozen=True)
class _AgentSHRuntime:
    load_config: Callable[[str, str], Any]
    backend: Any


def _load_agentsh_runtime() -> _AgentSHRuntime:
    """Load AgentSH APIs lazily so local fake smokes need no real AgentSH binary."""

    try:
        config_module = import_module("boundarybench.enforcement.config")
        agentsh_module = import_module("boundarybench.enforcement.agentsh")
    except ImportError as exc:
        raise RuntimeError(
            "enforcement=agentsh requires enforcement AgentSH modules."
        ) from exc

    load_config = getattr(config_module, "get_enforcement_config", None)
    load_backend = getattr(agentsh_module, "load_agentsh_backend", None)
    if load_config is None or load_backend is None:
        raise RuntimeError(
            "enforcement=agentsh found modules but missing get_enforcement_config "
            "or load_agentsh_backend."
        )

    return _AgentSHRuntime(
        load_config=_adapt_config_loader(load_config),
        backend=load_backend(),
    )


def _adapt_config_loader(load_config: Callable[..., Any]) -> Callable[[str, str], Any]:
    params = signature(load_config).parameters
    keyword_args = _supported_config_keywords(params)
    positional_params = [
        param
        for param in params.values()
        if param.kind in (Parameter.POSITIONAL_ONLY, Parameter.POSITIONAL_OR_KEYWORD)
    ]

    def load_config_adapter(config_id: str, config_task_id: str) -> Any:
        values = {"config_id": config_id, "task_id": config_task_id}
        if keyword_args is not None:
            return load_config(
                **{
                    name: value
                    for name, value in values.items()
                    if name in keyword_args
                }
            )
        if len(positional_params) >= 2:
            return load_config(config_id, config_task_id)
        return load_config(config_id)

    return load_config_adapter


def _supported_config_keywords(
    params: dict[str, Parameter],
) -> set[str] | None:
    accepts_keywords = any(
        param.kind == Parameter.VAR_KEYWORD for param in params.values()
    )
    supported = {
        name
        for name in ("config_id", "task_id")
        if accepts_keywords
        or params.get(name, Parameter(name, Parameter.POSITIONAL_ONLY)).kind
        in (Parameter.POSITIONAL_OR_KEYWORD, Parameter.KEYWORD_ONLY)
    }
    return supported or None


async def _maybe_await(value: Any) -> Any:
    if isawaitable(value):
        return await value
    return value


def _to_metadata(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    to_metadata = getattr(value, "to_metadata", None)
    if callable(to_metadata):
        return dict(to_metadata())
    if is_dataclass(value):
        return asdict(value)
    metadata = getattr(value, "metadata", None)
    if isinstance(metadata, dict):
        result = dict(metadata)
        for attr in ("status", "config_id", "backend", "task_id"):
            if hasattr(value, attr):
                result.setdefault(attr, getattr(value, attr))
        return result
    return {"value": value}


def _preflight_passed(preflight: dict[str, Any]) -> bool:
    passed = preflight.get("passed")
    if isinstance(passed, bool):
        return passed

    status = str(preflight.get("status", "")).lower()
    if status in {"passed", "pass", "success", "ok"}:
        return True
    if status in {"failed", "fail", "failure", "error"}:
        return False

    results = preflight.get("results")
    if isinstance(results, list) and results:
        return all(
            str((result or {}).get("status", "")).lower()
            in {"passed", "pass", "success", "ok"}
            for result in results
            if isinstance(result, dict)
        )

    return False


def _collect_events(*payloads: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for payload in payloads:
        payload_events = payload.get("events", [])
        if isinstance(payload_events, list):
            events.extend(event for event in payload_events if isinstance(event, dict))
    return events
