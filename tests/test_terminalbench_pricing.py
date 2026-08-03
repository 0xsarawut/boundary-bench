from __future__ import annotations

import pytest

import boundarybench.terminalbench.pricing as pricing
from boundarybench.terminalbench.pricing import (
    OpenRouterRates,
    normalize_model,
    openrouter_cost,
    parse_openrouter_pricing,
)


def test_normalize_strips_openrouter_prefix():
    assert normalize_model("openrouter/minimax/minimax-m3") == "minimax/minimax-m3"
    assert normalize_model("minimax/minimax-m3") == "minimax/minimax-m3"


def test_minimax_m3_cost_matches_openrouter_rates():
    pricing._MEMOIZED_PRICING = pricing.STATIC_OPENROUTER_PRICING
    cost = openrouter_cost(
        "openrouter/minimax/minimax-m3",
        input_tokens=220992,
        output_tokens=10986,
        cache_read_tokens=1712412,
    )
    assert cost == pytest.approx(0.182225, rel=1e-4)
    assert cost < 0.30


def test_deepseek_v4_flash_cost_matches_openrouter_rates():
    pricing._MEMOIZED_PRICING = pricing.STATIC_OPENROUTER_PRICING
    cost = openrouter_cost(
        "openrouter/deepseek/deepseek-v4-flash",
        input_tokens=100_000,
        output_tokens=20_000,
        cache_read_tokens=250_000,
    )
    assert cost == pytest.approx(0.0176)


def test_unknown_model_returns_none_instead_of_wrong_fallback_cost():
    pricing._MEMOIZED_PRICING = pricing.STATIC_OPENROUTER_PRICING
    assert openrouter_cost("some/other-model", input_tokens=100, output_tokens=10) is None


def test_cost_includes_cache_write_tokens(monkeypatch):
    monkeypatch.setattr(
        pricing,
        "openrouter_pricing",
        lambda: {
            "anthropic/example": OpenRouterRates(
                input=0.000001,
                output=0.000005,
                cache_read=0.0000001,
                cache_write=0.00000125,
            )
        },
    )
    cost = openrouter_cost(
        "openrouter/anthropic/example",
        input_tokens=100,
        output_tokens=10,
        cache_read_tokens=50,
        cache_write_tokens=20,
    )
    assert cost == pytest.approx(0.00018)


def test_parse_openrouter_pricing_understands_cache_fields():
    parsed = parse_openrouter_pricing(
        {
            "data": [
                {
                    "id": "anthropic/example",
                    "pricing": {
                        "prompt": "0.000001",
                        "completion": "0.000005",
                        "input_cache_read": "0.0000001",
                        "input_cache_write": "0.00000125",
                    },
                },
                {
                    "id": "unpriced/router",
                    "pricing": {"prompt": "-1", "completion": "-1"},
                },
            ]
        }
    )
    assert parsed["anthropic/example"] == OpenRouterRates(
        input=0.000001,
        output=0.000005,
        cache_read=0.0000001,
        cache_write=0.00000125,
    )
    assert "unpriced/router" not in parsed


def test_fetch_openrouter_models_rejects_unexpected_urls(monkeypatch):
    monkeypatch.setattr(pricing, "OPENROUTER_MODELS_URL", "http://openrouter.ai/api/v1/models")

    with pytest.raises(ValueError, match="unexpected URL"):
        pricing._fetch_openrouter_models()

    monkeypatch.setattr(
        pricing,
        "OPENROUTER_MODELS_URL",
        "https://metadata.google.internal/api/v1/models",
    )

    with pytest.raises(ValueError, match="unexpected URL"):
        pricing._fetch_openrouter_models()


def test_fetch_openrouter_models_uses_constrained_https_request(monkeypatch):
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(
        pricing,
        "OPENROUTER_MODELS_URL",
        "https://openrouter.ai/api/v1/models?limit=1",
    )

    class FakeResponse:
        def raise_for_status(self):
            calls.append(("raise_for_status", None))

        def json(self):
            calls.append(("json", None))
            return {"data": []}

    def fake_get(url, *, timeout, headers):
        calls.append(("get", (url, timeout, headers)))
        return FakeResponse()

    monkeypatch.setattr(pricing.httpx, "get", fake_get)

    assert pricing._fetch_openrouter_models() == {"data": []}
    assert calls == [
        (
            "get",
            (
                "https://openrouter.ai/api/v1/models?limit=1",
                10,
                {"Accept": "application/json", "User-Agent": "boundarybench"},
            ),
        ),
        ("raise_for_status", None),
        ("json", None),
    ]
