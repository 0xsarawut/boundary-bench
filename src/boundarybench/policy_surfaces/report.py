from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from boundarybench.policy_surfaces.evaluator import (
    ProbeResult,
    policy_surface_suite_passed,
)


def write_policy_surface_report(
    path: Path,
    *,
    metadata: dict[str, Any],
    results: list[ProbeResult] | tuple[ProbeResult, ...],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "metadata": dict(metadata),
        "passed": policy_surface_suite_passed(results),
        "results": [result.to_metadata() for result in results],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
