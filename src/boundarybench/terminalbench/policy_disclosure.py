"""Shared, config-derived disclosure primitives.

These are the drift-sensitive facts that any policy-disclosure channel must agree
on: the writable-path map, the home carveouts, and the disclosed (infra-filtered)
domain list, all read from the FINAL resolved
:class:`~boundarybench.daytona.hardening_config.DaytonaHardeningConfig`,
plus the SHA-256 / UTF-8-length helpers the provenance stamps use. ``policy_prompt``
and the later ``recovery_skill`` both delegate here so the two channels can never
disagree about what the run enforces.

Pure module: no I/O, no Daytona SDK imports, deterministic output.
"""

from __future__ import annotations

import hashlib
from collections.abc import Collection
from typing import TYPE_CHECKING

from boundarybench.daytona.hardening_config import normalize_domain_pattern

if TYPE_CHECKING:
    from boundarybench.daytona.hardening_config import DaytonaHardeningConfig


def sha256(text: str) -> str:
    """SHA-256 hex digest over ``text`` encoded as UTF-8."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utf8_len(text: str) -> int:
    """Byte length of ``text`` encoded as UTF-8."""

    return len(text.encode("utf-8"))


def normalized_infra(infra_domains: Collection[str]) -> set[str]:
    """Normalize caller-supplied infra domains for comparison.

    ``egress_domain_allowlist`` is stored normalized (lowercased, trailing dot
    stripped) by ``DaytonaHardeningConfig``; normalizing infra the same way here
    means an infra domain cannot leak into disclosure on a casing / trailing-dot
    mismatch in un-normalized caller input. An un-normalizable entry can never
    equal a normalized allowlist domain, so it would filter nothing — skip it
    rather than crash a run over prompt rendering.
    """

    normalized: set[str] = set()
    for domain in infra_domains:
        try:
            normalized.add(normalize_domain_pattern(domain))
        except ValueError:
            continue
    return normalized


def disclosed_domains(
    config: "DaytonaHardeningConfig", infra: set[str]
) -> tuple[str, ...]:
    """Resolved allowlist minus infra domains, order-stable and deduped."""

    seen: set[str] = set()
    disclosed: list[str] = []
    for domain in config.egress_domain_allowlist:
        if domain in infra or domain in seen:
            continue
        seen.add(domain)
        disclosed.append(domain)
    return tuple(disclosed)


def writable_dirs(config: "DaytonaHardeningConfig") -> list[str]:
    """Writable directories from the resolved config (prefixes shown as dirs).

    Union of ``writable_path_exact`` and ``writable_path_prefixes`` (trailing
    slash stripped), exact entries first, deduped. ``/dev`` and ``/proc`` pseudo
    nodes are dropped: the templates summarize real workspace locations to
    install into, not the always-present device files.
    """

    dirs: list[str] = []
    seen: set[str] = set()
    for raw in (*config.writable_path_exact, *config.writable_path_prefixes):
        path = raw.rstrip("/") or "/"
        if path in seen:
            continue
        seen.add(path)
        if path.startswith(("/dev/", "/proc/")) or path in ("/dev", "/proc"):
            continue
        dirs.append(path)
    return dirs


def home_carveout_dirs(config: "DaytonaHardeningConfig") -> tuple[str, ...]:
    """Home-relative subdir names that stay writable when the home is frozen.

    ``f3_home_carveout_subdirs`` unchanged (e.g. ``.claude``, ``.cache``); the
    F2 filesystem block renders these as ``~/<sub>`` carveouts.
    """

    return config.f3_home_carveout_subdirs


def enforced_writable_display(config: "DaytonaHardeningConfig") -> list[str]:
    """Writable paths as the MOUNT layer actually enforces them, for display.

    This DELIBERATELY diverges from :func:`writable_dirs`. ``writable_dirs``
    faithfully mirrors the resolved config's ``writable_path_*`` sets, which
    OVER-APPROXIMATE what the mount enforces: they list ``/var/tmp`` writable even
    under F2 (``read_only``), where the mount actually freezes it — ``/var`` is a
    native read-only OS tree, F1 carves ``/var/tmp`` back but F2 carves back only
    the home dirs (``daytona_policy_hardening.py`` :570/:651/:653; documented
    approximation in ``policy_axes._writable_paths``, :604-606). Disclosing
    ``/var/tmp`` as writable under F2 is exactly the misinformation the recovery
    bundle exists to kill, so its §5 renders from THIS enforced view, not from
    ``writable_dirs``.

    The enforced set: always ``/app`` and ``/tmp`` (neither is in the RO trees);
    under ``workspace`` (F1) also ``/var/tmp`` and the whole home (``~``); under
    ``read_only`` (F2) also the home carveouts as ``~/<sub>`` and NEVER
    ``/var/tmp``. For ``open``/``guarded`` (no read-only remount, so §5 never
    renders) it degrades to the always-writable base. Reconciling the config down
    to the mount so ``writable_dirs`` stops over-claiming is the policy_axes
    "Task 6" carveout fix; until then this function encodes the mount rule here.
    """

    display = ["/app", "/tmp"]
    scope = config.filesystem_scope
    if scope == "workspace":
        display.append("/var/tmp")
        display.append("~")
    elif scope == "read_only":
        display.extend(f"~/{sub}" for sub in home_carveout_dirs(config))
    return display
