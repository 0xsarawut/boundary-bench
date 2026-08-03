"""Harness adapter registry: resolve harness names to adapter instances.

Admission requirement: every registered harness runs its agent process
entirely inside the Daytona sandbox boundary, so BoundaryBench hardening applies
to anything in this registry. Adapters that delegate execution outside the
sandbox must not be registered (and such PRs are not merged).
"""

from __future__ import annotations

from boundarybench.harness.adapter import HarnessAdapter
from boundarybench.harness.claude_code import ClaudeCodeAdapter
from boundarybench.harness.codex import CodexAdapter
from boundarybench.harness.grok import GrokAdapter
from boundarybench.harness.terminus_2 import Terminus2Adapter

DEFAULT_HARNESS = "terminus_2"

_ADAPTERS: dict[str, HarnessAdapter] = {
    "claude_code": ClaudeCodeAdapter(),
    "codex": CodexAdapter(),
    "grok": GrokAdapter(),
    "terminus_2": Terminus2Adapter(),
}


def get_harness_adapter(harness: str | None = None) -> HarnessAdapter:
    """Look up a harness adapter by name.

    Returns the Claude Code adapter by default.  Raises ``ValueError`` for
    unknown harness names so task-arg validation fails fast.
    """

    name = (harness or DEFAULT_HARNESS).strip()
    adapter = _ADAPTERS.get(name)
    if adapter is None:
        known = ", ".join(sorted(_ADAPTERS))
        raise ValueError(
            f"unknown harness {name!r}; available: {known}"
        )
    return adapter


def available_harnesses() -> list[str]:
    """Return the list of registered harness names."""

    return sorted(_ADAPTERS)
