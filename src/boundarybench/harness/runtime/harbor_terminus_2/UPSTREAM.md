# Harbor Terminus-2 — quarantined upstream runtime

This package bundles everything needed to run **upstream Harbor's official
Terminus-2 agent** inside the hardened Daytona task sandbox. It is a
quarantined third-party runtime: nothing here reimplements the agent, and the
Terminus/Harbor code itself is **not vendored** — it is installed in-sandbox
from the hashed lock below.

## Provenance

| | |
|---|---|
| Upstream project | Harbor (Laude Institute) — <https://github.com/laude-institute/harbor> |
| Package | `harbor==0.13.1` (PyPI) |
| License | Apache-2.0 |
| Agent | `harbor.agents.terminus_2.Terminus2`, imported unmodified |
| Install integrity | `requirements.lock` is fully hashed; `install.sh` runs `uv pip sync --require-hashes` and refuses a lock whose Harbor pin does not match the adapter's `HARBOR_VERSION` |

## Ownership boundary

- **Ours (first-party):** the thin adapter
  `boundarybench/harness/terminus_2.py`, the sandbox/secret boundary,
  artifact + canonical-trace translation (`trace.py`), and post-agent cleanup.
- **Upstream Harbor:** the agent loop, prompt/parser, tmux implementation, and
  the dependency graph pinned in `requirements.lock`.
- **Patches (temporary, ours):** `patches.py` — see its module docstring for
  the exhaustive patch inventory, per-patch provenance, and the
  upstream-removal path. Patches are applied by subclassing at runtime, never
  by editing upstream sources.

## Files

| File | Role |
|---|---|
| `bridge.py` | Sandbox-side runner: adapts Harbor's environment API to local subprocesses so every tmux command stays inside the native policy boundary. Uploaded and rendered by the adapter (placeholder substitution), installed as `$TERMINUS_HOME/runner.py`. |
| `patches.py` | Temporary subclass patches over Harbor internals (currently: bounded tmux session recovery). Installed beside the runner as `$TERMINUS_HOME/patches.py`. |
| `install.sh` | In-sandbox bootstrap: tmux, pinned `uv`, pinned CPython, venv, hash-verified `pip sync`, self-check. |
| `requirements.in` | Direct pin only (`harbor==0.13.1`). |
| `requirements.lock` | Fully hashed transitive closure actually installed in the sandbox. |
| `trace.py` | First-party normalization of Harbor's ATIF `trajectory.json` + runner-result sentinel into the shared canonical trace schema. |

## Updating Harbor

1. Bump the pin in all three declared locations — `requirements.in`,
   `HARBOR_VERSION` in `boundarybench/harness/terminus_2.py`, and the
   `harbor` extra in `pyproject.toml` (controller-side import surface).
   `tests/test_harness_terminus_2.py::test_harbor_pin_cannot_drift` fails if
   they disagree.
2. Regenerate the lock (the `--exclude-newer` date makes the resolution
   reproducible — advance it to the bump date):

   ```bash
   cd src/boundarybench/harness/runtime/harbor_terminus_2
   uv pip compile --generate-hashes --universal --python-version 3.12 \
     --exclude-newer <YYYY-MM-DD>T00:00:00Z requirements.in -o requirements.lock
   ```

3. Re-audit `patches.py`: every patch documents the upstream behavior it
   overrides — check whether the new Harbor release absorbed it and remove the
   patch if so.
4. Re-run the terminus unit suite, then a managed Cloud Run sanity run
   (General; include `git-multibranch`, which exercises the tmux-recovery
   patch) before treating the bump as validated.

The `requirements.lock` in this directory resolves to the exact package
versions and hashes used by the 89-task Terminal-Bench validation campaign for
PR #164.
