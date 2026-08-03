"""Single typed source of truth for hardening-claim metadata.

``enforcement``, ``hardened_execution``, and ``harness`` must be recorded the
same way everywhere they appear (task metadata, solver success path, solver
error path, boundary-bench-v1) or the generations drift and BigQuery rows
become incomparable. ``HardeningClaims`` makes the claim a value object
instead of a dict convention: an inconsistent combination is not
constructible.

Every registered harness runs its agent inside the Daytona sandbox boundary
(that is the registry's admission requirement), so the claims depend only on
whether the selected policy actually applies hardening overlays.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from boundarybench.harness.adapter import HarnessAdapter

ENFORCEMENT_POLICY_HARDENING = "daytona_policy_hardening"
ENFORCEMENT_BASELINE = "daytona_baseline"


@dataclass(frozen=True)
class HardeningClaims:
    """The queryable hardening-claim fields for one benchmark sample/run."""

    enforcement: Literal["daytona_policy_hardening", "daytona_baseline"]
    hardened_execution: bool
    harness: str

    def __post_init__(self) -> None:
        if self.hardened_execution != (
            self.enforcement == ENFORCEMENT_POLICY_HARDENING
        ):
            raise ValueError(
                "inconsistent hardening claims: "
                f"enforcement={self.enforcement!r} with "
                f"hardened_execution={self.hardened_execution!r}"
            )
        if not self.harness:
            raise ValueError("hardening claims require a harness name")

    @classmethod
    def derive(
        cls,
        *,
        policy_applies_hardening: bool,
        harness: HarnessAdapter,
    ) -> HardeningClaims:
        """Derive the claims for a selected policy and harness.

        ``hardened_execution`` is ``True`` only when the policy actually
        applies hardening overlays; ``policy=none`` runs are recorded as
        baseline instead of overclaiming.
        """

        return cls(
            enforcement=(
                ENFORCEMENT_POLICY_HARDENING
                if policy_applies_hardening
                else ENFORCEMENT_BASELINE
            ),
            hardened_execution=bool(policy_applies_hardening),
            harness=harness.name,
        )

    def to_metadata(self) -> dict[str, Any]:
        """Claim fields as recorded in Inspect metadata and BigQuery rows."""

        return {
            "enforcement": self.enforcement,
            "hardened_execution": self.hardened_execution,
            "harness": self.harness,
        }
