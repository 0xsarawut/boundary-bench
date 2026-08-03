#!/usr/bin/env python3
"""Build + push the `boundary-policy-lab-v1` Daytona snapshot from ./Dockerfile.

This is the IN-REPO provenance for the go-forward native-enforcement benchmark snapshot,
replacing the hand-built, unversioned `agentsh-harness-lab-v11-...` (which had no recipe
in git anywhere). Daytona builds the image server-side from the Dockerfile.

Run with your Daytona API key in the environment:

    DAYTONA_API_KEY=<your-key> \
      uv run --extra daytona python snapshots/policy-lab/build_snapshot.py

Re-baking: bump SNAPSHOT_NAME to -v2 (don't mutate an existing name), or delete the old
one first (`daytona.snapshot.delete(...)` / dashboard). New snapshots are ACTIVE by default.

Validation before trusting in prod (the exec-model caveat): after build, create one sandbox
from it and confirm `id -u`==0 (exec-as-root), full caps, and that the full hardening flow
(sudo unshare -> setpriv --reuid daytona; nft; remount ro) runs — reuse
scratchpad `phase0_root_probe.sh` against `--snapshot boundary-policy-lab-v1`.
"""
from __future__ import annotations

from pathlib import Path

from daytona_sdk import Daytona
from daytona_sdk.common.image import Image
from daytona_sdk.common.snapshot import CreateSnapshotParams

SNAPSHOT_NAME = "boundary-policy-lab-v1"
DOCKERFILE = Path(__file__).parent / "Dockerfile"


def main() -> int:
    daytona = Daytona()  # reads DAYTONA_API_KEY from env
    image = Image.from_dockerfile(str(DOCKERFILE))
    print(f"Building Daytona snapshot {SNAPSHOT_NAME!r} from {DOCKERFILE} ...", flush=True)
    daytona.snapshot.create(
        CreateSnapshotParams(name=SNAPSHOT_NAME, image=image),
        on_logs=lambda chunk: print(chunk, end="", flush=True),
        timeout=0,
    )
    print(f"\nSnapshot {SNAPSHOT_NAME!r} created (ACTIVE). "
          f"Point daytona/config.py DEFAULT_DAYTONA_SNAPSHOT at it after validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
