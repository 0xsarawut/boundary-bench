"""Harness adapter protocol: boundary between hardening and agent-specific behavior.

The BoundaryBench hardening pipeline (sandbox provisioning, policy hardening
installation, preflight gating, runtime policy probes, policy event capture)
is harness-agnostic. The ``HarnessAdapter`` protocol defines the agent-specific
extension points that the hardening pipeline calls at well-defined moments:

1. ``runtime_layer_script`` — install the agent binary in the sandbox.
2. ``agent_command`` — build the CLI command to invoke the agent.
3. ``agent_env`` — map the managed provider secret into agent env variables.
4. ``agent_binary_path`` — path to the agent binary (for verification).

Transcript parsing, activity summary, blocked-surface extraction, provider-error
detection, and markdown rendering are per-harness methods on this protocol
(``activity_summary``, ``blocked_surfaces``, ``provider_auth_error``,
``parse_transcript``, ``transcript_markdown``). The Claude Code adapter delegates
them to ``terminalbench.daytona_transcript`` (stream-json); other harnesses
implement their own.

Every registered harness MUST run its agent process entirely inside the
Daytona sandbox boundary — that is a repo admission requirement, not a
per-adapter capability flag. Harnesses that delegate execution outside the
sandbox are not accepted into the registry.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class HarnessAdapter(Protocol):
    """Agent harness adapter for the BoundaryBench hardening pipeline.

    Beyond installing and invoking the agent, each adapter owns the
    interpretation of its agent's stdout — every CLI emits its own transcript
    format, so activity counting, blocked-surface extraction, provider-error
    detection, Inspect-message translation, and markdown rendering are
    per-harness. The score itself comes from the Harbor verifier and is
    harness-agnostic; these methods only feed observability and the
    zero-progress retry heuristic, so a minimal implementation is acceptable
    for a new harness.
    """

    @property
    def name(self) -> str:
        """Short machine-readable harness identifier (e.g. ``claude_code``)."""
        ...

    def runtime_layer_script(
        self,
        *,
        workdir: str,
        run_as_root: bool,
    ) -> str:
        """Shell script body to install the agent in the sandbox.

        The returned script runs as root inside the sandbox after base packages
        (curl, gcc, sudo, bash) and the ``daytona`` user have been set up by
        the shared sandbox preparation layer.  It should install the agent
        binary and verify it is executable. The composed sandbox setup script
        prints ``RUNTIME_LAYER_OK`` after the shared base layer and harness
        layer both succeed.
        """
        ...

    def agent_binary_path(self, *, run_as_root: bool) -> str:
        """Absolute path to the agent binary inside the sandbox."""
        ...

    def agent_command(
        self,
        *,
        model: str,
        prompt_path: str,
        run_as_root: bool,
        effort_level: str | None = None,
    ) -> str:
        """Build the CLI command string to invoke the agent.

        The command runs inside the hardening boundary (policy
        mount/network/env namespace). The prompt file has already been uploaded
        to ``prompt_path``. Prompt contents may be arbitrary, including leading
        dashes, multiline text, and shell metacharacters; adapters must prevent
        them from being interpreted as CLI options or shell syntax. New
        harnesses should prefer lossless file or stdin transport when their CLI
        supports it.
        ``effort_level`` is the normalized harness-specific effort setting for
        the run; adapters apply it only when their CLI has a real
        effort/reasoning knob.
        """
        ...

    def agent_env(
        self,
        *,
        provider_api_key: str,
        run_as_root: bool,
    ) -> dict[str, str]:
        """Environment variables for the agent process.

        Provider secrets are passed through this channel, never on the command
        line. The adapter maps the one managed provider secret used in this
        phase into harness-specific env vars and owns any harness-specific env
        toggles (e.g. root-mode sandbox flags).
        """
        ...

    @property
    def api_key_env_var(self) -> str:
        """Managed runtime env var holding the Secret Manager provider key."""
        ...

    @property
    def health_egress_domains(self) -> tuple[str, ...]:
        """Vendor health/telemetry domains the CLI contacts at startup.

        These are distinct from the model path (model inference routes through
        the loopback accounting proxy to OpenRouter). They are injected into the
        egress allowlist only when domain egress is active (N>=1); an empty tuple
        means the harness contacts no vendor health backend that needs allowing.
        """
        ...

    @property
    def home_runtime_subdirs(self) -> tuple[str, ...]:
        """Home-relative dirs this harness's CLI must be able to write at runtime.

        F3 (read-only home) carves exactly these back read-write, on top of the
        shared cache defaults, so the harness's own machinery keeps working
        while the rest of home stays frozen. Declare every dir the CLI writes
        after startup (config/state/session/scratch homes) — a path missing
        here fails with EROFS only INSIDE the walls, which violates the
        setup-before-policy invariant.
        """
        ...

    @property
    def agent_metadata_name(self) -> str:
        """Agent name for metadata/status records (e.g. ``claude_code_openrouter``)."""
        ...

    @property
    def default_effort_level(self) -> str:
        """Harness-specific default effort level used when no task arg is set."""
        ...

    @property
    def supported_effort_levels(self) -> tuple[str, ...]:
        """Accepted effort levels for this harness."""
        ...

    @property
    def effort_level_applied(self) -> bool:
        """Whether the adapter applies effort to the agent command/config."""
        ...

    def session_artifact_dirs(self, *, run_as_root: bool) -> tuple[str, ...]:
        """Remote directories holding the harness's native session/rollout logs.

        The listed directories are read (never modified) after the agent phase
        — on success and on failure — and exported into run metadata before
        the sandbox is torn down. Return ``()`` when the harness has no
        on-disk session state worth exporting (agent stdout already carries
        the full transcript).
        """
        ...


    def activity_summary(self, agent_stdout: str) -> dict[str, int]:
        """Counts of assistant turns / tool calls vs. internal pings.

        Must report ``assistant_turns`` — the solver treats zero turns on a
        non-timed-out run as "the agent did nothing" and retries. A harness
        whose output is opaque should report ``1`` when the agent produced any
        output so a successful run is not falsely retried.
        """
        ...

    def recovery_skill_invocation_count(self, agent_stdout: str) -> int:
        """Number of agent tool-calls/commands that pull up the recovery skill.

        The leading indicator for whether the agent USED the ``recovery_bundle``
        guidance vs ignored it: tool-calls in ``agent_stdout`` that reference the
        ``policy-error-recovery`` skill or its ``RECOVERY.md`` doc. Harnesses
        whose transcript surfaces no tool telemetry return 0 (the default).
        """
        return 0

    def blocked_surfaces(self, agent_stdout: str, *, policy: Any) -> list[Any]:
        """Policy-hardening blocks visible in the transcript (best effort).

        The authoritative block record is the harness-agnostic policy event
        log; this only augments it, so returning ``[]`` is acceptable.
        """
        ...

    def provider_auth_error(self, agent_stdout: str) -> Any | None:
        """Provider/auth/quota failure detected in the agent output, if any."""
        ...

    def parse_transcript(
        self,
        *,
        prompt: str,
        agent_stdout: str,
        model: str,
        pricing_model: str,
        session_artifacts: dict[str, Any] | None = None,
    ) -> tuple[list[Any], Any]:
        """Translate the agent transcript into Inspect messages + ModelOutput."""
        ...

    def transcript_markdown(
        self,
        *,
        task_id: str,
        prompt: str,
        model: str,
        reward: Any,
        answer: Any,
        agent_stdout: str,
        timed_out: bool,
        policy: Any,
        pricing_model: str,
        benchmark_status: Any,
        policy_events: list[dict[str, Any]] | None,
        session_artifacts: dict[str, Any] | None = None,
    ) -> str:
        """Human-readable end-to-end transcript for failure analysis."""
        ...

    def canonical_trace(
        self,
        *,
        agent_stdout: str,
        model: str,
        session_artifacts: dict[str, Any] | None,
        policy_events: list[dict[str, Any]] | None = None,
    ) -> Any:
        """Return the shared, JSON-ready trace for this harness.

        The adapter chooses the richest native source (stdout for Claude/Codex,
        exported ACP session updates for Grok).  All implementations return
        the same ``CanonicalTrace`` contract and explicitly mark fields that
        were unavailable, truncated, or malformed.
        """
        ...


@runtime_checkable
class HarnessRuntimeAssets(Protocol):
    """Optional files uploaded before the harness runtime layer executes."""

    def runtime_layer_assets(self, *, run_as_root: bool) -> dict[str, bytes]:
        """Map absolute sandbox paths to immutable runtime asset bytes."""
        ...


@runtime_checkable
class HarnessPostAgentCleanup(Protocol):
    """Optional lifecycle hook for harness-owned processes left after a run."""

    def post_agent_cleanup_command(self, *, run_as_root: bool) -> str:
        """Return a narrowly scoped, best-effort in-sandbox cleanup command."""
        ...


def explicit_effort_level(effort_level: str | None) -> str | None:
    """Return a normalized explicit effort string, or ``None`` for default."""

    if effort_level is None:
        return None
    normalized = str(effort_level).strip().lower()
    return normalized or None


def effort_level_source(effort_level: str | None) -> str:
    """Artifact label for whether effort came from a task arg or adapter default."""

    return (
        "task_arg"
        if explicit_effort_level(effort_level) is not None
        else "harness_default"
    )


def normalize_effort_level(
    harness: HarnessAdapter,
    effort_level: str | None = None,
) -> str:
    """Normalize and validate a harness effort level."""

    explicit = explicit_effort_level(effort_level)
    normalized = (
        harness.default_effort_level
        if explicit is None or explicit == "default"
        else explicit
    )
    supported = harness.supported_effort_levels
    if normalized not in supported:
        known = ", ".join(supported)
        raise ValueError(
            f"unsupported effort level {normalized!r} for harness "
            f"{harness.name!r}; available: {known}"
        )
    return normalized
