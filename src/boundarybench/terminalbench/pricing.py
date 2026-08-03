"""Cost computation for the OpenRouter models the agent drives.

Claude Code reports ``total_cost_usd`` using Anthropic pricing (it believes it
is calling Anthropic via the remapped base URL), which is wrong for cheaper
OpenRouter-routed models. Inspect has no built-in price for these OpenRouter
model ids either, so we compute cost ourselves from the token counts and the
real OpenRouter list price.
"""

from __future__ import annotations

from dataclasses import dataclass
import httpx
import json
import os
from pathlib import Path
import time
from typing import Any
from urllib.parse import urlsplit

OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
OPENROUTER_PRICING_CACHE_ENV = "BOUNDARYBENCH_OPENROUTER_PRICING_CACHE"
OPENROUTER_PRICING_CACHE_TTL_ENV = "BOUNDARYBENCH_OPENROUTER_PRICING_CACHE_TTL_SEC"
_DEFAULT_CACHE_TTL_SEC = 24 * 60 * 60


@dataclass(frozen=True)
class OpenRouterRates:
    """USD per token for one OpenRouter model."""

    input: float
    output: float
    cache_read: float | None = None
    cache_write: float | None = None


STATIC_OPENROUTER_PRICING: dict[str, OpenRouterRates] = {
    "deepseek/deepseek-v4-flash": OpenRouterRates(
        input=0.00000009,
        output=0.00000018,
        cache_read=0.00000002,
    ),
    "minimax/minimax-m3": OpenRouterRates(
        input=0.0000003,
        output=0.0000012,
        cache_read=0.00000006,
    ),
    "anthropic/claude-haiku-4.5": OpenRouterRates(
        input=0.000001,
        output=0.000005,
        cache_read=0.0000001,
        cache_write=0.00000125,
    ),
    "anthropic/claude-3.5-haiku": OpenRouterRates(
        input=0.0000008,
        output=0.000004,
        cache_read=0.00000008,
        cache_write=0.000001,
    ),
}

_MEMOIZED_PRICING: dict[str, OpenRouterRates] | None = None


def normalize_model(model: str) -> str:
    """Strip an ``openrouter/`` provider prefix so lookups are by bare id."""

    model = (model or "").strip()
    prefix = "openrouter/"
    return model[len(prefix):] if model.startswith(prefix) else model


def _cache_path() -> Path:
    configured = os.getenv(OPENROUTER_PRICING_CACHE_ENV)
    if configured:
        return Path(configured).expanduser()
    base = Path(os.getenv("XDG_CACHE_HOME", "~/.cache")).expanduser()
    return base / "boundarybench" / "openrouter-models.json"


def _cache_ttl_sec() -> int:
    try:
        return int(os.getenv(OPENROUTER_PRICING_CACHE_TTL_ENV, str(_DEFAULT_CACHE_TTL_SEC)))
    except ValueError:
        return _DEFAULT_CACHE_TTL_SEC


def _read_json_file(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_json_file(path: Path, payload: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload), encoding="utf-8")
        tmp_path.replace(path)
    except OSError:
        return


def _fetch_openrouter_models() -> dict[str, Any]:
    payload = _fetch_openrouter_json(OPENROUTER_MODELS_URL, timeout=10)
    if not isinstance(payload, dict):
        raise ValueError("OpenRouter models response is not a JSON object")
    return payload


def _fetch_openrouter_json(url: str, *, timeout: float) -> Any:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "openrouter.ai":
        raise ValueError("refusing to fetch OpenRouter models from an unexpected URL")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("refusing to fetch OpenRouter models from an invalid URL") from exc
    try:
        response = httpx.get(
            url,
            timeout=timeout,
            headers={
                "Accept": "application/json",
                "User-Agent": "boundarybench",
            },
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise ValueError(f"could not fetch OpenRouter models metadata: {exc}") from exc
    try:
        return response.json()
    except ValueError as exc:
        raise ValueError("OpenRouter models response is not valid JSON") from exc


def _price(pricing: dict[str, Any], key: str) -> float | None:
    raw = pricing.get(key)
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def parse_openrouter_pricing(payload: dict[str, Any]) -> dict[str, OpenRouterRates]:
    """Parse OpenRouter ``/api/v1/models`` payload into per-token rates."""

    models = payload.get("data")
    if not isinstance(models, list):
        return {}
    rates: dict[str, OpenRouterRates] = {}
    for model in models:
        if not isinstance(model, dict):
            continue
        model_id = model.get("id")
        pricing = model.get("pricing")
        if not isinstance(model_id, str) or not isinstance(pricing, dict):
            continue
        prompt = _price(pricing, "prompt")
        completion = _price(pricing, "completion")
        if prompt is None or completion is None:
            continue
        rates[model_id] = OpenRouterRates(
            input=prompt,
            output=completion,
            cache_read=_price(pricing, "input_cache_read"),
            cache_write=_price(pricing, "input_cache_write"),
        )
    return rates


def openrouter_pricing(*, refresh: bool = False) -> dict[str, OpenRouterRates]:
    """Return live OpenRouter pricing, falling back to cache/static rates."""

    global _MEMOIZED_PRICING
    if _MEMOIZED_PRICING is not None and not refresh:
        return _MEMOIZED_PRICING

    path = _cache_path()
    now = time.time()
    cached_payload = _read_json_file(path)
    if cached_payload and not refresh:
        written_at = float(cached_payload.get("fetched_at") or 0)
        if now - written_at <= _cache_ttl_sec():
            parsed = parse_openrouter_pricing(cached_payload)
            if parsed:
                _MEMOIZED_PRICING = {**STATIC_OPENROUTER_PRICING, **parsed}
                return _MEMOIZED_PRICING

    try:
        live_payload = _fetch_openrouter_models()
    except Exception:  # noqa: BLE001 - pricing must never break an eval run
        if cached_payload:
            parsed = parse_openrouter_pricing(cached_payload)
            if parsed:
                _MEMOIZED_PRICING = {**STATIC_OPENROUTER_PRICING, **parsed}
                return _MEMOIZED_PRICING
        _MEMOIZED_PRICING = STATIC_OPENROUTER_PRICING
        return _MEMOIZED_PRICING

    live_payload["fetched_at"] = now
    _write_json_file(path, live_payload)
    parsed = parse_openrouter_pricing(live_payload)
    _MEMOIZED_PRICING = {**STATIC_OPENROUTER_PRICING, **parsed}
    return _MEMOIZED_PRICING


def openrouter_cost(
    model: str,
    *,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> float | None:
    """Compute USD cost from token counts, or None if the model is unpriced.

    ``input_tokens`` is the non-cached prompt count (Anthropic-style, as Claude
    Code reports it); cached prompt tokens are billed separately at the
    OpenRouter cache-read/cache-write rates when available.
    """

    rates = openrouter_pricing().get(normalize_model(model))
    if rates is None:
        return None
    cache_read_rate = rates.cache_read if rates.cache_read is not None else rates.input
    cache_write_rate = rates.cache_write if rates.cache_write is not None else rates.input
    return (
        input_tokens * rates.input
        + output_tokens * rates.output
        + cache_read_tokens * cache_read_rate
        + cache_write_tokens * cache_write_rate
    )
