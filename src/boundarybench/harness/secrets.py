"""Provider secret access for managed benchmark runtimes.

Live benchmark execution gets provider credentials from Google Secret Manager
through Cloud Run secret environment variables. Local unit tests may monkeypatch
the same environment variable, but production benchmark code should not fetch
1Password items or read local dotenv files.
"""

from __future__ import annotations

import os

from boundarybench.harness.adapter import HarnessAdapter


def provider_api_key_from_managed_env(
    adapter: HarnessAdapter,
    *,
    purpose: str,
) -> str:
    """Return the provider key injected into the runtime by Cloud Run.

    The adapter owns the expected env var name; infrastructure owns populating
    it from Secret Manager. Missing values fail before any Daytona sandbox is
    provisioned.
    """

    value = os.environ.get(adapter.api_key_env_var)
    if not value:
        raise RuntimeError(
            f"{adapter.api_key_env_var} must be provided by the managed "
            f"Cloud Run Secret Manager environment for {purpose}"
        )
    return value
