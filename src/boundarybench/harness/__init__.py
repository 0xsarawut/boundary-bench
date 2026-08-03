"""Harness adapter abstraction for agent-agnostic BoundaryBench hardening.

The harness adapter boundary separates the hardening layer (policy selection,
preflight gating, runtime policy probes, policy event capture) from
harness-specific behavior (agent installation, command building, environment
setup, transcript parsing).

Registered harnesses:
  - ``claude_code`` — Claude Code via OpenRouter (production path).
  - ``codex`` — OpenAI Codex CLI via OpenRouter.
  - ``grok`` — xAI Grok Build CLI via OpenRouter.
  - ``terminus_2`` — Harbor Terminus-2 via OpenRouter.

Future harnesses must implement the same ``HarnessAdapter`` protocol and must
run their agent process entirely inside the Daytona sandbox boundary — that is
the registry's admission requirement; benchmark-only adapters that execute
outside the sandbox are not accepted.
"""

from boundarybench.harness.adapter import HarnessAdapter
from boundarybench.harness.claude_code import ClaudeCodeAdapter
from boundarybench.harness.codex import CodexAdapter
from boundarybench.harness.grok import GrokAdapter
from boundarybench.harness.registry import get_harness_adapter
from boundarybench.harness.secrets import provider_api_key_from_managed_env
from boundarybench.harness.terminus_2 import Terminus2Adapter

__all__ = [
    "ClaudeCodeAdapter",
    "CodexAdapter",
    "GrokAdapter",
    "HarnessAdapter",
    "Terminus2Adapter",
    "get_harness_adapter",
    "provider_api_key_from_managed_env",
]
