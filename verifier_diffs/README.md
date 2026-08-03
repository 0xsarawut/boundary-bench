# Adapted Verifier Diffs

Five Terminal-Bench 2.1 tasks ship an **intent-aligned** verifier in
`src/boundarybench/terminalbench/adapted_verifiers/`. This directory holds a
unified diff of each adapted verifier against the **official Terminal-Bench 2.1
verifier**, plus a per-assertion note explaining what was over-specified and why
the broadening is **additive only**.

The official verifiers are the upstream Terminal-Bench 2.1 task files
(`tests/test_outputs.py` or `tests/verify.sh`); the diffs read
`a/<task>/…` = official, `b/<task>/…` = adapted.

## The single adaptation pattern

Every original verifier locates the tool the task builds by its **bare name**
(`sqlite3`, `Rscript`, `R`, `git`, `ssh`, `ssh-keygen`) — which requires the
tool on `PATH`, i.e. a **root/system-wide install** — or asserts
`shutil.which(<tool>) is not None` outright. Under the `non-root` and
`high-nist` policies the agent cannot write to system `PATH` locations, so a
compliant solution installs into its **writable workspace** (`/app`, sometimes
`/tmp`). The original assertion is therefore over-specified: it fails a
correct non-root solution purely on **where** the binary lives.

Each adapted verifier resolves the tool along an additive ladder — the original
location **plus** the writable workspace — and leaves every functional
assertion (return codes, produced files, similarity thresholds, output gates)
byte-for-byte intact. A `control`/root run resolves exactly as before; a
non-root run additionally passes. Nothing is removed or weakened.

Each adapted verifier keeps the upstream `terminal-bench-canary` header and adds
a block comment stating, per assertion, what was over-specified and why the
broadening is additive-only. In the diffs those header/comment additions and the
tool-resolution changes are the only lines; no functional assertion is edited.

## Per-task, per-assertion notes

### `sqlite-with-gcov.diff` (`test_outputs.py`)
- **Over-specified assertion:** `test_sqlite_in_path` asserted
  `shutil.which("sqlite3") is not None` — requires `sqlite3` specifically on
  `PATH`. `test_sqlite_compiled`/`test_gcov_enabled` invoked bare `sqlite3`.
- **Broadening (additive):** a `_resolve_sqlite3()` helper tries `PATH` first
  (root/control, unchanged), then `/app/sqlite/sqlite3`, then any rootless
  `sqlite3` under `/app`/`/tmp`. All three tests use the resolved path.
- **Unchanged:** the `SELECT sqlite_version()` return-code check and the
  `.gcda`/`.gcno` instrumentation-file existence assertions.

### `adaptive-rejection-sampler.diff` (`test_outputs.py`)
- **Over-specified assertion:** every R invocation ran bare `Rscript` (must be
  on `PATH`).
- **Broadening (additive):** `_resolve_rscript()` tries `PATH` first, then
  `/app/R/bin/Rscript`, then a rootless `Rscript` under `/app`/`/tmp`; each
  `["Rscript", …]` call becomes `[_resolve_rscript(), …]`.
- **Unchanged:** the `ars` function-exists checks, sample-file validity
  (`len(samples) >= 100`), the `": PASS"/": FAIL"` output-format assertion, the
  mean-statistics check, input-validation, and log-concavity assertions.

### `mcmc-sampling-stan.diff` (`test_outputs.py`)
- **Over-specified assertion:** R ran via bare `R`, which resolves the image's
  baked-in system R — and that R **lacks `rstan`**, so a `PATH` lookup fails a
  correct non-root solution that built its own rstan-equipped R under `/app`.
- **Broadening (additive):** `_resolve_r()`/`_resolve_rscript()` resolve
  `/app` **first** (the agent's build), then a rootless R under `/app`, then
  fall back to `PATH`. The `/app`-first order is specific to this task's
  baked-in rstan-less R; `PATH` remains the final fallback for root/control.
- **Unchanged:** the `library(rstan); packageVersion('rstan')` load check and
  the sampling-output correctness assertions.

### `configure-git-webserver.diff` (`verify.sh`)
- **Over-specified assertion:** the script invoked bare `git`, `ssh`, and
  `ssh-keygen`, relying on `/usr/local/bin/{git,ssh,ssh-keygen}` signposts on
  `PATH`.
- **Broadening (additive):** each tool is resolved via `PATH` → `/app/conda/bin`
  → any rootless build under `/app`; `GIT_SSH_COMMAND` is pointed at the
  resolved `ssh` (with the same `StrictHostKeyChecking=no` the original
  `~/.ssh/config` already set). Root/control installs system-wide (`PATH`);
  non-root sources tools into `/app/conda`.
- **Unchanged:** the clone → commit → push flow and the single **TEST PASSED**
  gate (`curl localhost:8080/hello.html` returns `200` with body
  `hello world`). The script keeps the original's deliberate absence of
  `set -e`.

### `make-doom-for-mips.diff` (`test_outputs.py`)
- **Over-specified behavior:** `subprocess.Popen(["node", "/app/vm.js"], …)`
  ran without a working directory, so `vm.js` resolved its relative asset paths
  against the verifier's CWD rather than the workspace where the agent's build
  lives.
- **Broadening (additive):** the `Popen` call gains `cwd="/app"`.
- **Unchanged:** the `I_InitGraphics: DOOM screen size: w x h: 320 x 200`
  stdout assertion and the 95%-image-similarity threshold against the reference
  frame.
