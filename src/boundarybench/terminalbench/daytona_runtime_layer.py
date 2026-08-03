"""Runtime bootstrap script rendering for Terminal-Bench Daytona task images.

Split into two layers:
  1. ``sandbox_base.sh`` — harness-agnostic sandbox preparation (packages,
     ``/bin/bash.real``, ``daytona`` user, workdir ownership).
  2. Harness-specific agent installation, provided by the ``HarnessAdapter``
     via ``runtime_layer_script()``.

Clean post-agent verification uses ``clean_verifier_runtime_layer.sh`` instead;
it installs no harness or policy-hardening assets.
"""

from __future__ import annotations

from importlib.resources import files
import shlex

from boundarybench.harness.adapter import HarnessAdapter

SANDBOX_BASE_SCRIPT = (
    files("boundarybench.terminalbench")
    .joinpath("scripts", "sandbox_base.sh")
    .read_text(encoding="utf-8")
)
CLEAN_VERIFIER_RUNTIME_LAYER_SCRIPT = (
    files("boundarybench.terminalbench")
    .joinpath("scripts", "clean_verifier_runtime_layer.sh")
    .read_text(encoding="utf-8")
)
VERIFIER_ARTIFACT_CAPTURE_SCRIPT = (
    files("boundarybench.terminalbench")
    .joinpath("scripts", "capture_verifier_artifacts.py")
    .read_text(encoding="utf-8")
)


def render_sandbox_base_script(
    *,
    workdir: str,
    run_agent_as_root: bool,
    task_id: str | None = None,
) -> str:
    """Render harness-free sandbox preparation for one task workspace."""

    _ = task_id
    base = SANDBOX_BASE_SCRIPT.replace("__WORKDIR__", shlex.quote(workdir)).replace(
        "__RUN_AGENT_AS_ROOT__", "1" if run_agent_as_root else "0"
    )
    return base


def render_sandbox_setup_script(
    *,
    workdir: str,
    run_agent_as_root: bool,
    harness: HarnessAdapter,
    task_id: str | None = None,
) -> str:
    """Render a two-layer bootstrap: shared base + harness agent install.

    The base script installs packages, creates ``/bin/bash.real``, sets up
    the ``daytona`` user (when non-root), and prepares the workdir. The
    harness adapter then installs the agent binary.
    """

    base = render_sandbox_base_script(
        workdir=workdir,
        run_agent_as_root=run_agent_as_root,
        task_id=task_id,
    )
    agent_install = harness.runtime_layer_script(
        workdir=workdir,
        run_as_root=run_agent_as_root,
    )
    return f"{base}\n{agent_install}\necho RUNTIME_LAYER_OK\n"


def render_clean_verifier_runtime_layer_script(*, workdir: str) -> str:
    """Render verifier-only setup without an agent or hardening layer."""

    return CLEAN_VERIFIER_RUNTIME_LAYER_SCRIPT.replace(
        "__WORKDIR__", shlex.quote(workdir)
    )
