from __future__ import annotations

import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from boundarybench.enforcement.agentsh_policy_types import AgentSHPolicyBundle


def materialize_agentsh_policy(bundle: AgentSHPolicyBundle) -> AgentSHPolicyBundle:
    """Write the AgentSH policy YAML and matching local config atomically."""

    policy_path = Path(bundle.policy_path)
    policy_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _atomic_write(policy_path, bundle.policy_yaml)
    _atomic_write(Path(bundle.config_path), bundle.config_yaml)
    return bundle


def _atomic_write(path: Path, payload: str) -> None:
    with NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        delete=False,
    ) as tmp_file:
        tmp_file.write(payload)
        if not payload.endswith("\n"):
            tmp_file.write("\n")
        tmp_name = tmp_file.name
    os.chmod(tmp_name, 0o600)
    os.replace(tmp_name, path)
