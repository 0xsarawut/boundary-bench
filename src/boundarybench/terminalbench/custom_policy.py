"""Build-your-own hardening: a plain-language surface catalog and compiler.

Users pick from a short list of hardening options in ordinary language — run
as a non-root user, make the OS read-only, restrict network access, and so on.
This module never exposes the underlying N×F×P lattice to the user; it compiles
a chosen set of surfaces into a coherent :class:`HardeningPolicy`, filling in
prerequisites and required companions automatically.

Physical enforcement surfaces are bundled (the CIDR/metadata denylist rides
with the egress wall; the capability drop and setuid strip ride with
no-new-privileges), so the catalog exposes only the choices a user can make
independently. Selecting any network or filesystem hardening implies running
as a non-root user (root could flush the firewall or remount the OS), and the
compiler adds that automatically.

The compiled policy is identified by a surface-based id such as
``custom:non-root+readonly-os+restrict-egress`` — order-independent and stable
— so runs stay reproducible without ever naming an axis or level.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from boundarybench.daytona.hardening_config import (
    DEFAULT_DOMAIN_EGRESS_ALLOWLIST,
)
from boundarybench.daytona.policy_axes import (
    AxisPreset,
    Filesystem,
    Network,
    Privilege,
    build_daytona_config_from_axes,
)
from boundarybench.terminalbench.policies import HardeningPolicy


@dataclass(frozen=True)
class Surface:
    """One independently selectable hardening option, in plain language."""

    key: str
    label: str
    blocks: str
    requires: tuple[str, ...] = ()


SURFACES: tuple[Surface, ...] = (
    Surface(
        key="non-root",
        label="Run as a non-root user",
        blocks=(
            "the agent runs as an ordinary user with no sudo and a locked root "
            "password — `sudo` and `su` fail"
        ),
    ),
    Surface(
        key="no-escalation",
        label="Block privilege escalation",
        blocks=(
            "no process can gain privileges (no-new-privileges), the Linux "
            "capability set is emptied, and setuid bits are stripped, so "
            "privileged syscalls fail with EPERM"
        ),
        requires=("non-root",),
    ),
    Surface(
        key="readonly-os",
        label="Make the operating system read-only",
        blocks=(
            "the OS trees are remounted read-only; only the workspace stays "
            "writable, so writes elsewhere fail with EROFS"
        ),
        requires=("non-root",),
    ),
    Surface(
        key="freeze-home",
        label="Freeze the home directory",
        blocks=(
            "the home directory freezes too; only runtime and cache dirs stay "
            "writable"
        ),
        requires=("readonly-os",),
    ),
    Surface(
        key="restrict-egress",
        label="Restrict network access to an allowlist",
        blocks=(
            "all direct network egress is refused; traffic may only reach an "
            "approved allowlist, and cloud-metadata and private-network "
            "addresses are always blocked"
        ),
        requires=("non-root",),
    ),
)

SURFACES_BY_KEY: dict[str, Surface] = {s.key: s for s in SURFACES}
SURFACE_KEYS: tuple[str, ...] = tuple(s.key for s in SURFACES)

EGRESS_TRUSTED = "trusted"
EGRESS_TASK_ONLY = "task-only"
EGRESS_CUSTOM = "custom"
EGRESS_MODES = (EGRESS_TRUSTED, EGRESS_TASK_ONLY, EGRESS_CUSTOM)


class CustomPolicyError(ValueError):
    """Raised when a requested surface set cannot be compiled."""


@dataclass(frozen=True)
class CompiledCustomPolicy:
    """A compiled custom hardening selection."""

    policy: HardeningPolicy
    policy_id: str
    surfaces: tuple[str, ...]
    added_for_coherence: tuple[str, ...]
    egress_mode: str | None
    egress_allowlist: tuple[str, ...]


def _expand(selected: set[str]) -> tuple[set[str], list[str]]:
    """Add every prerequisite of every selected surface (transitive closure)."""

    resolved = set(selected)
    added: list[str] = []
    changed = True
    while changed:
        changed = False
        for key in sorted(resolved):
            for req in SURFACES_BY_KEY[key].requires:
                if req not in resolved:
                    resolved.add(req)
                    added.append(req)
                    changed = True
    return resolved, added


def normalize_surface_keys(keys: object) -> list[str]:
    """Parse a comma/space list (or iterable) of surface keys, validating each."""

    if keys is None:
        return []
    if isinstance(keys, str):
        raw = [part for chunk in keys.split(",") for part in chunk.split()]
    else:
        raw = [str(k).strip() for k in keys]
    out: list[str] = []
    for key in raw:
        key = key.strip().lower()
        if not key:
            continue
        if key not in SURFACES_BY_KEY:
            known = ", ".join(SURFACE_KEYS)
            raise CustomPolicyError(
                f"unknown hardening surface {key!r}; choose from: {known}"
            )
        if key not in out:
            out.append(key)
    return out


def _axes_for(surfaces: set[str]) -> tuple[Network, Filesystem, Privilege]:
    if "no-escalation" in surfaces:
        privilege = Privilege.P2
    elif surfaces & {"non-root", "readonly-os", "freeze-home", "restrict-egress"}:
        privilege = Privilege.P1
    else:
        privilege = Privilege.P0

    if "freeze-home" in surfaces:
        filesystem = Filesystem.F2
    elif "readonly-os" in surfaces:
        filesystem = Filesystem.F1
    else:
        filesystem = Filesystem.F0

    network = Network.N1 if "restrict-egress" in surfaces else Network.N0
    return network, filesystem, privilege


def compile_custom_policy(
    surface_keys: object,
    *,
    egress_mode: str | None = None,
    egress_domains: object = None,
) -> CompiledCustomPolicy:
    """Compile a plain-language surface selection into a HardeningPolicy.

    ``surface_keys`` is a comma/space string or iterable of catalog keys.
    ``egress_mode`` refines the ``restrict-egress`` surface (defaults to the
    curated trusted allowlist); ``egress_domains`` supplies the caller's own
    allowlist when ``egress_mode`` is ``custom``.
    """

    selected = set(normalize_surface_keys(surface_keys))
    resolved, added = _expand(selected)

    network, filesystem, privilege = _axes_for(resolved)

    tuple_id = f"{network.value}-{filesystem.value}-{privilege.value}".lower()
    preset = AxisPreset(
        name="custom",
        tuple_id=tuple_id,
        network=network,
        filesystem=filesystem,
        privilege=privilege,
        tier="custom",
        nist_story="User-composed hardening selection.",
    )
    config = build_daytona_config_from_axes(preset)

    resolved_egress_mode: str | None = None
    egress_allowlist: tuple[str, ...] = ()
    if "restrict-egress" in resolved:
        resolved_egress_mode = (egress_mode or EGRESS_TRUSTED).strip().lower()
        if resolved_egress_mode not in EGRESS_MODES:
            raise CustomPolicyError(
                f"unknown egress mode {resolved_egress_mode!r}; choose from: "
                + ", ".join(EGRESS_MODES)
            )
        if resolved_egress_mode == EGRESS_CUSTOM:
            domains = _normalize_domains(egress_domains)
            if not domains:
                raise CustomPolicyError(
                    "egress mode 'custom' needs at least one domain "
                    "(bring your own allowlist)"
                )
            merged = _dedup(tuple(DEFAULT_DOMAIN_EGRESS_ALLOWLIST) + domains)
            config = replace(
                config,
                egress_domain_allowlist=merged,
                egress_domain_default_action="deny",
                native_egress_reject=True,
            )
        elif resolved_egress_mode == EGRESS_TASK_ONLY:
            config = replace(
                config,
                egress_domain_allowlist=tuple(DEFAULT_DOMAIN_EGRESS_ALLOWLIST),
            )
        egress_allowlist = config.egress_domain_allowlist

    surfaces_sorted = tuple(sorted(resolved))
    policy_id = "custom:" + "+".join(surfaces_sorted) if surfaces_sorted else "control"
    config = replace(config, name=policy_id)

    policy = HardeningPolicy(
        name=policy_id,
        config=config,
        overlays=(),
        agent_user="root" if privilege == Privilege.P0 else "daytona",
        isolate_network=False,
        block_network=False,
        block_child_shell_network=False,
        unsupported_surfaces=(),
        runtime_probe_scope="all",
        enforcement_mode="native",
        description="User-composed hardening selection.",
    )

    return CompiledCustomPolicy(
        policy=policy,
        policy_id=policy_id,
        surfaces=surfaces_sorted,
        added_for_coherence=tuple(sorted(set(added))),
        egress_mode=resolved_egress_mode,
        egress_allowlist=egress_allowlist,
    )


def applies_hardening(surface_keys: object) -> bool:
    """Whether a surface selection compiles to a hardened (non-control) policy."""

    return bool(normalize_surface_keys(surface_keys))


def _normalize_domains(domains: object) -> tuple[str, ...]:
    if domains is None:
        return ()
    if isinstance(domains, str):
        raw = [part for chunk in domains.split(",") for part in chunk.split()]
    else:
        raw = [str(d) for d in domains]
    return _dedup(tuple(d.strip().lower() for d in raw if d.strip()))


def _dedup(items: tuple[str, ...]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return tuple(seen)
