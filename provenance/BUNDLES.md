# Evaluated Bundles — Frozen Provenance

This is the frozen experiment provenance for BoundaryBench: every evaluated
**model + agent-harness bundle**, with the exact provider model ID, the harness
and its pinned version, the inference route, the reasoning effort, the number of
trials, and the policy levels. The machine-readable form is
[`bundles.json`](./bundles.json); this file is its human-readable mirror.

## Shared configuration (all bundles)

| Setting | Value |
| --- | --- |
| Reasoning effort | `high` |
| Trials per cell | 3 |
| Policy levels | `control`; `non-root`; NIST-derived high = the **`high-nist`** preset (N5 fixed-trusted egress + F2 read-only rootfs + P2 privilege lockdown) |
| Inference route | OpenRouter, reached through the in-sandbox loopback accounting proxy (one route for every harness) |
| Vendor health endpoints | `claude_code` → `api.anthropic.com`; `codex` → `chatgpt.com`; `grok`, `terminus_2` → none |

Pinned harness versions: **Claude Code** `2.1.206` · **Codex** `rust-v0.142.5` ·
**Grok Build** `0.2.87` · **Terminus-2** Harbor `0.13.1` / Terminus `2.0.0`.

## The twelve bundles

| # | Model (marketing) | Provider | Provider model ID | Harness | Harness version | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | GPT-5.6 Sol | OpenAI | `openai/gpt-5.6-sol` | Codex | `rust-v0.142.5` | high |
| 2 | GPT-5.6 Terra | OpenAI | `openai/gpt-5.6-terra` | Codex | `rust-v0.142.5` | high |
| 3 | GPT-5.6 Luna | OpenAI | `openai/gpt-5.6-luna` | Codex | `rust-v0.142.5` | high |
| 4 | Claude Sonnet 5 | Anthropic | `anthropic/claude-sonnet-5` | Claude Code | `2.1.206` | high |
| 5 | Claude Opus 4.8 | Anthropic | `anthropic/claude-opus-4.8` | Claude Code | `2.1.206` | high |
| 6 | Claude Fable 5 | Anthropic | `anthropic/claude-fable-5` | Claude Code | `2.1.206` | high |
| 7 | Claude Opus 5 | Anthropic | `anthropic/claude-opus-5` | Claude Code | **`2.1.220`** ⚑ | high |
| 8 | Kimi K3 | Moonshot AI | `moonshotai/kimi-k3` | Terminus-2 | Harbor `0.13.1` / Terminus `2.0.0` | high |
| 9 | GLM-5.2 | Z.ai | `z-ai/glm-5.2` | Terminus-2 | Harbor `0.13.1` / Terminus `2.0.0` | high |
| 10 | Qwen3.7 Max | Alibaba Qwen | `qwen/qwen3.7-max` | Terminus-2 | Harbor `0.13.1` / Terminus `2.0.0` | high |
| 11 | MiniMax M3 | MiniMax | `minimax/minimax-m3` | Terminus-2 | Harbor `0.13.1` / Terminus `2.0.0` | high |
| 12 | Grok 4.5 | xAI | `x-ai/grok-4.5` | Grok Build | `0.2.87` | high |

Each bundle is run across all three policy levels at three trials per cell.

## Ablation crossings (2×2 harness × model)

The native pairings **GPT-5.6 Luna on Codex** (bundle 3) and **Grok 4.5 on Grok
Build** (bundle 12) are already above. The two crossings below swap each model
onto the other's harness, isolating the harness contribution from the model.

| Model (marketing) | Provider | Provider model ID | Harness | Harness version | Effort |
| --- | --- | --- | --- | --- | --- |
| GPT-5.6 Luna | OpenAI | `openai/gpt-5.6-luna` | Grok Build | `0.2.87` | high |
| Grok 4.5 | xAI | `x-ai/grok-4.5` | Codex | `rust-v0.142.5` | high |

## Notes and exceptions

- **⚑ Claude Opus 5 version exception.** Every other Claude Code
  bundle is pinned to `2.1.206`. Claude Code `2.1.206` did not expose a correct
  `anthropic/claude-opus-5` model identifier until `2.1.219`; `2.1.220` (the next
  patch release) supplied it, so Opus 5 alone was evaluated on `2.1.220`. This
  narrowly scoped exception is recorded here in the frozen experiment
  provenance.
- **Claude Fable 5 vendor fallback.** Anthropic's declared default fallback for
  Claude Fable 5 is Claude Opus 4.8. The fallback is kept as configured, so any
  request that falls back is served by `anthropic/claude-opus-4.8`. Recorded per
  bundle 6.
- **Grok 4.5 ↔ Grok Build mapping (verified).** The "Grok 4.5" bundle
  maps to provider model ID `x-ai/grok-4.5` run under the Grok Build harness
  (`grok`, `0.2.87`) at effort `high`. This was confirmed against the frozen
  campaign registry (an earlier roster iteration used `x-ai/grok-4.20`; the
  current roster uses `x-ai/grok-4.5`).
- **Reasoning effort.** All bundles report effort `high`, the evaluated
  configuration; the repository enforces `high` as every harness's test-locked
  default (`tests/test_harness_adapter.py`). For transparency: the
  pre-standardization pareto campaign specifications recorded effort `max` for
  the Claude Code bundles and the harness default for the Terminus-2 bundles,
  before effort was standardized to `high` across all harnesses for the reported
  runs.

## Sources

Provider model IDs, per-bundle harness assignment, the Opus 5 version exception,
and the Fable 5 → Opus 4.8 fallback come from the frozen campaign / runner
registry. Harness version pins and the effort default are taken directly
from this repository:

- `src/boundarybench/harness/claude_code.py`, `codex.py`, `grok.py`,
  `terminus_2.py` — version pins.
- `src/boundarybench/harness/adapter.py` + `tests/test_harness_adapter.py` —
  effort default `high`.
- `src/boundarybench/daytona/policy_axes.py` (resolved in
  `src/boundarybench/terminalbench/policies.py`) — the `high-nist` preset.
