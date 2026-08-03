# NIST-Derived Benchmark Policies

This document is the source-of-truth reviewer map for the native **N×F×P**
benchmark policy roster: `control`, `non-root`, `low-nist`, `moderate-nist`,
`high-nist`, `netlock`, and `fslock`. The axis model, per-level native
mechanisms, native errors, and NIST citations are defined in
`src/boundarybench/daytona/policy_axes.py` (the single source of truth) and
laid out for humans in `docs/policy-axes.md`, which also carries the design
rationale.

For the full academic-style technical treatment of the policy inventory,
enforcement surfaces, probe methodology, assurance argument, tier
differentiation, and related systems work, see
`docs/nist-hardening-technical-monograph.md`.

These policies define a NIST-derived runtime environment for benchmarking agent
behavior under selected security blockages. They intentionally do not turn
Daytona into a NIST-compliant environment. They are not NIST, SCAP, DISA, CIS,
FedRAMP, or organizational compliance claims.

## NIST Context

NIST SP 800-53 Rev. 5 is a control catalog. NIST describes the controls as
flexible, customizable, and implemented as part of an organization-wide risk
management process:
<https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>.

NIST SP 800-53B defines control baselines for low-impact, moderate-impact, and
high-impact systems, plus tailoring guidance and overlays:
<https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final>.

In this repo, the `moderate-nist` preset maps to the NIST moderate-impact
baseline tier projected into benchmark-policy naming, `low-nist` to low-impact,
and `high-nist` to high-impact. The three tiers are points in the N×F×P lattice. `high-nist` carries the
high-impact F2/P2 controls with a fixed trusted network posture (N5) rather
than a per-task network projection; N5 is not a monotonic strengthening of the
per-task network level.

> **F-ladder consolidation (2026-07-13).** The F axis was renumbered after the
> vacuous "guarded" level was removed: f1 now means the read-only OS workspace
> (old f2) and f2 the frozen-home read-only rootfs (old f3). `low-nist` was
> simultaneously raised to the read-only OS workspace, so the three tiers now
> differ as: low→moderate narrows only the network; moderate→high freezes home
> and locks privilege. Conditional credential-path DAC survives as
> the `secret_paths_root_owned` field (any level; future research), carrying
> AC-6(2), IA-5, SC-28, AC-2, AC-5 only when activated.

## Claim Boundary

The implementation claims only selected runtime hardening behavior that is
compiled, installed, probed where the runtime probe suite owns the surface, and
recorded as benchmark evidence. The intended claim is that the agent runs inside
a NIST-derived runtime environment that approximates the blockage pressure of
selected NIST Linux controls, enforced by **native Linux mechanisms only**:

- non-root execution and privilege lockdown via `setpriv` (drop bounding
  capabilities, `no_new_privs`, strip setuid), no sudoers entry, locked root
  password;
- a real read-only OS via bind-remount (writes return `EROFS`), with workspace
  carveouts and, at the top tier, a frozen home;
- conditional DAC protection for explicitly supplied real credential paths
  (`not_applicable` because none are supplied by current presets); native exec universally sanitizes declared
  infrastructure-key environment names, independent of axis F;
- egress control via a uid-scoped nftables REJECT wall plus a forced proxy
  (blocked domains return a bare `403`; direct-IP bypass returns
  `Connection refused`), with a metadata/RFC-1918 CIDR denylist.

Every block is a **native error** the agent would see on any locked-down Linux
host. There is no `LD_PRELOAD`, no `BOUNDARY_*` env, and no custom deny text.

The implementation does not claim:

- full NIST compliance
- auditd/compliance evidence
- kernel/sysctl/service-state assessment
- complete SELinux/AppArmor profile management
- full organizational control coverage, authorization, or assessment evidence

The catalog preserves those missing or out-of-claim surfaces so downstream
reports cannot silently convert this benchmark profile into a compliance claim.

## Two Corrections From The Prior Model

This document previously described the retired gate-matrix + steering model and
contained two provable errors. Both are corrected here:

1. **Landlock is NOT active on all tiers.** The prior text claimed a Landlock
   MAC boundary was enforced for Low/Medium/High. Landlock was always dormant in
   this codebase (`full_mac_enforcement` was never `True`); it is now retained
   unwired. Native filesystem/privilege enforcement is **DAC + read-only
   bind-remounts + nftables + setpriv** — not Landlock. The Landlock MAC
   boundary code path is kept for a future steering-vs-native A/B benchmark, not
   used as the enforcer.
2. **Egress is NOT OpenRouter-only on any task-aware level.** The prior text
   claimed every tier used an OpenRouter-only allowlist. The truth, from
   `policy_axes.py`, is that declared task dependencies are reachable at every
   N level: N0 is ungated; `low-nist` (N1) allows the **205-domain
   Claude-Code-web trusted list ∪ per-task domains ∪ model plane**;
   `moderate-nist` (N2) allows the **model plane ∪ per-task domains**;
   reserved, unshipped N3 is operationally identical to N2; and reserved,
   unshipped N4 allows the **per-task domains** over an otherwise empty base.
   N5 is deliberately not task-aware: `high-nist` uses the fixed 205-entry
   trusted base, which already includes all three shared model-plane domains,
   never adds per-task domains, and unions only the running harness's declared
   model-plane/health domains.
   N3 carries only N2's citations and makes no stronger network-assurance claim.
   The model plane itself is exactly the three
   harness-agnostic OpenRouter entries in `DEFAULT_DOMAIN_EGRESS_ALLOWLIST`
   (`api.openrouter.ai`, `openrouter.ai`, `*.openrouter.ai`) — it does **not**
   statically include `api.anthropic.com`. Each harness's own vendor health
   domain (`claude_code` → `api.anthropic.com`, `codex` → `chatgpt.com`,
   `grok` / `terminus_2` → none) is
   overlaid onto the allowlist at runtime for the running harness only, and only
   when domain egress is gated (N1–N5, never N0). N4's axis base remains
   task-only and N5's remains fixed-trusted; this operational health overlay is
   applied separately.

## Runtime Architecture

For `boundarybench/hardened_terminalbench_daytona`, the native policy flow
is:

1. `-T policy=<name>` resolves through `terminalbench/policies.py::resolve_policy`
   to one of the seven N×F×P presets. The old
   `nist-linux-80053-*`, `none`, `nonroot`, and `gate-*` names are intentionally
   gone and raise a clear error.
2. `build_daytona_config_from_axes(preset, task_id)` merges the three axis
   contributions into a `DaytonaHardeningConfig`. Native presets set only the
   native fields and leave the legacy denylist fields empty.
3. The Daytona sandbox provisions the native mechanisms: the uid-scoped nftables
   REJECT wall + forced proxy (domain allowlist per axis N), read-only OS
   bind-remounts with workspace carveouts (axis F), conditional DAC protection
   for explicitly configured credential paths (none in current presets), and
   `setpriv` privilege lockdown + locked root (axis P). Infrastructure-key
   environment names are sanitized for every native preset.
4. Runtime probes run before the agent and fail closed when a required enforced
   surface does not behave as expected.
5. The selected harness (`terminus_2` by default; `claude_code`, `codex`, and `grok` are the
   other registered adapters) runs as the `daytona` non-root user under the
   composed native hardening (the `control` preset is the only one that runs
   as root).
6. Harbor's official verifier runs outside the hardening boundary and remains
   the source of Terminal-Bench scoring.

Retained-but-unwired mechanisms (Landlock MAC boundary, seccomp denylist,
LD_PRELOAD path/socket helpers, PATH-shim command denials, and AgentSH
operation-specific path policy) are kept in the schema and code for the future
steering-vs-native A/B benchmark. They are not part of native enforcement and
must not be read as active MAC, syscall, or argument-aware controls.

## Tier Matrix

Each column is a shipped preset; each row is the native mechanism that axis level
provisions. Native errors are what the agent sees.

| Surface | `non-root` | `low-nist` | `moderate-nist` | `high-nist` | Native error |
| --- | --- | --- | --- | --- | --- |
| Privilege (axis P) | non-root + locked root (setpriv drop, no sudoers) | same | same | + `no_new_privs` + drop bounding caps + strip setuid | `not in the sudoers file` / `EPERM` |
| Filesystem (axis F) | DAC only (F0) | read-only OS bind-remount, workspace carveouts (F1) | same (F1) | + frozen home (F2) | `EROFS` (conditional `EACCES` only for an explicitly supplied credential path) |
| Infrastructure-key env sanitation | yes | yes | yes | yes | env var absent |
| Egress domain policy (axis N) | none (N0 full) | default-deny, allow 205-domain trusted list ∪ per-task ∪ model-plane (N1) | default-deny, allow model-plane ∪ per-task (N2) | default-deny, fixed 205-domain trusted base, no per-task widening, plus only the running harness's declared domains (N5) | bare `403` |
| CIDR default-deny | no | metadata/link-local/RFC-1918 denylist | same | same | `Connection refused` |
| Direct-IP egress wall | no | uid-scoped nftables REJECT | same | same | `Connection refused` |
| Landlock MAC boundary | retained unwired (dormant; not enforced) | retained unwired | retained unwired | retained unwired | n/a (not enforced) |
| seccomp denylist | retained unwired | retained unwired | retained unwired | retained unwired | n/a (not enforced) |
| AgentSH operation-specific path policy | retained unwired (Phase-3-intended) | retained unwired | retained unwired | retained unwired | n/a (not enforced) |

`control` is the unhardened root baseline: no native enforcement, no
NIST claim. `netlock` and `fslock` are single-axis
isolation studies: `netlock` applies N2 egress with an open filesystem; `fslock`
applies the F2 immutable rootfs with open egress.

The Landlock, seccomp, and AgentSH rows are intentionally **retained-unwired**
rows, not active enforcement. They document mechanisms that exist in the schema
for the steering-vs-native A/B study. Native enforcement is carried entirely by
DAC, read-only bind-remounts, nftables, and setpriv.

## Enforcement Details

Daytona provisions these native benchmark controls:

- non-root execution and privilege lockdown through `setpriv` (drop bounding
  capabilities, `no_new_privs`, strip setuid), no sudoers entry, and a locked
  root password (axis P);
- a structural read-only OS through bind-remounts with workspace carveouts, and
  a frozen home at F2 (axis F) — writes return `EROFS`;
- conditional DAC protection for explicitly supplied real credential paths so
  reads return `EACCES` (`not_applicable` for current presets because they
  supply no paths); universal native-exec
  sanitation of declared infrastructure-key environment names (not axis F);
- domain default-deny through a forced HTTP(S) proxy whose allowlist follows the
  network axis (N1 = 205-domain trusted list ∪ per-task ∪ model-plane; N2/N3 =
  model-plane ∪ per-task; N4 = per-task only; N5 = one fixed 205-domain trusted
  base with no per-task widening plus only the running harness's declared
  domains; N0 remains ungated) — a blocked
  unrelated domain returns a bare `403` (axis N);
- CIDR default-deny and direct-IP bypass blocking through a uid-scoped nftables
  REJECT wall (metadata/link-local/RFC-1918 denied) — `Connection refused`
  (axis N).

Native presets carry all enforcement through these fields. The legacy denylist
mechanisms (command shims, LD_PRELOAD helpers, seccomp launcher, Landlock
runner, AgentSH argument rules) are retained in the schema but unwired from the
native presets; they exist for the steering-vs-native A/B benchmark, not as the
current enforcer.

## Probes And Failure Semantics

Runtime probes are selected by
`src/boundarybench/daytona/runtime_policy_probes.py`.

Shipped native presets use `runtime_probe_scope="all"`, so probes cover every
configured native blockage instead of only a representative subset. Probe
reports record:

- policy id and name
- runtime target
- policy overlays
- probe id, surface, target, and expected outcome
- actual outcome, status, classification, exit code, timeout, stdout/stderr
- compact structured policy events when a native block fired
- unsupported or out-of-claim metadata for surfaces that should remain visible

Required probe failures fail closed before the agent starts. `policy=control`
should report no BoundaryBench blocked-surface evidence; if it does, treat that as a
pipeline bug.

## Test Coverage

The core local verification set is:

```bash
uv run --extra dev inspect list tasks
uv run boundarybench policy validate --pack-id all
uv run --all-extras pytest -q
```

Focused checks live in:

- `tests/test_policy_axes.py`
- `tests/test_policy_axes_catalog_equivalence.py`
- `tests/test_boundary_native_pack.py`
- `tests/test_policy_catalog_daytona_contract.py`
- `tests/test_policy_catalog_loader.py`
- `tests/test_terminalbench_policies.py`
- `tests/test_daytona_runtime_policy_probes.py`
- `tests/test_daytona_policy_surfaces.py`
- `tests/test_terminalbench_daytona_eval.py`
- `tests/test_terminalbench_daytona_run.py`

## Reviewer Checklist

When reviewing a policy change, verify all of the following:

- The docs use `NIST-derived runtime environment` or `NIST-derived benchmark
  hardening` language and do not imply compliance.
- New axis-level values in `policy_axes.py` flow into both
  `build_daytona_config_from_axes` (executable config) and
  `runtime_mappings_for_preset` (catalog mapping), and the axes↔catalog
  equivalence test stays green.
- Native mechanisms (nftables REJECT wall, read-only bind-remounts, DAC secret
  ownership, setpriv lockdown) carry all enforcement; legacy denylist
  mechanisms stay unwired for native presets.
- Runtime probes cover every configured native blockage for the shipped presets.
- Unsupported, out-of-claim, and retained-unwired surfaces remain visible in
  metadata.
- Local tests pass, and any live benchmark claim uses managed Cloud Run evidence.
