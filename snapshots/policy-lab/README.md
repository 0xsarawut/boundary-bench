# `boundary-policy-lab-v1` — Daytona benchmark snapshot

Go-forward snapshot for the native-enforcement policy benchmark. Replaces the hand-built,
agentsh-named `agentsh-harness-lab-v11-small-1cpu-2gb-3gb`, which had **no build recipe in
git** (it was pushed manually, off-repo — tribal provenance). This directory fixes that:
the image is defined by [`Dockerfile`](./Dockerfile) and built by
[`build_snapshot.py`](./build_snapshot.py).

## Why the rename
- **`agentsh` is retired.** agentsh is not on the scored path (its wrap branch is gated by
  `agentsh_policy_config`, which is always `None`). The new native enforcement (nftables,
  read-only mounts, `setpriv` cap-drop) does not use it, so the image drops it entirely.
- **Fresh `v1`** lineage marks the mechanism change (not a continuation of agentsh's v11).
- The old `-small-1cpu-2gb-3gb` suffix was **cosmetic** — CPU/mem/disk are set at
  sandbox-create time (`Resources()` in `terminalbench/daytona_run.py`), never baked — so
  the name is just `boundary-policy-lab-v1`.

## Build + push
Provide your Daytona API key in the environment. Daytona builds server-side:
```bash
DAYTONA_API_KEY=<your-key> \
  uv run --extra daytona python snapshots/policy-lab/build_snapshot.py
```

## Wire-up (after the snapshot is built + validated)
1. `src/boundarybench/daytona/config.py:12` →
   `DEFAULT_DAYTONA_SNAPSHOT = "boundary-policy-lab-v1"`
2. `tests/test_daytona_policy_surfaces.py` (the snapshot-name assertion) + `docs/env-vars.md`
   (the "minimal ... snapshot" note).
3. `terminalbench/scripts/sandbox_base.sh` — add `nftables iproute2` to the apt line (keep
   it even with the baked image: it's the runtime network-provisioning fallback contract).
4. Retire agentsh: delete the dead `_NIST_*_AGENTSH_CONFIG` in `terminalbench/policies.py`.

## Interim (until built + validated)
The stock **`daytona-small`** snapshot (Debian 13, root-via-sudo, full caps) is active and
passed all Phase-0 spikes (nftables/mounts/setpriv). Run on it via
`BOUNDARYBENCH_DAYTONA_SNAPSHOT=daytona-small` while developing, then flip to the baked
snapshot. Do NOT reactivate the old inactive `agentsh-harness-lab-*` snapshots.

## Validation caveat
Confirm Daytona runs a custom snapshot **exec-as-root** with full caps (CAP_NET_ADMIN +
CAP_SYS_ADMIN), matching `daytona-small`. Validate the full hardening flow against the
built snapshot (reuse the Phase-0 `phase0_root_probe.sh`) before pointing `config.py` at it.
