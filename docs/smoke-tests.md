# Smoke Tests And Phase Validation

Phase 0 smoke tests prove only Inspect extension wiring.

## Unit And Integration Tests

```bash
uv run --extra dev pytest -q
```

## Inspect Plugin Discovery

```bash
uv run --extra dev inspect list tasks
```

The task list should include `boundarybench/hardened_agents`.

## E2E Inspect Smoke

```bash
uv run --all-extras inspect eval boundarybench/hardened_agents \
  -T enforcement=local_fake \
  -T max_samples=1 \
  --model mockllm/model \
  --display none
```

This writes a real `.eval` log under `logs/`.

Inspect the newest log:

```bash
log_path="$(ls -t logs/*.eval | head -n 1)"
uv run inspect log dump --header-only "$log_path"
```

Expected result:

- status: `success`
- total samples: `1`
- completed samples: `1`
- score summary: local fake smoke success

## Phase 1 Real Terminal-Bench Control Run

Phase 1 acceptance requires a real model and Docker. This is Sev0/control only:
no AgentSH, no Daytona, no OS-level hardening, and no custom verifier.

```bash
export INSPECT_LOG_DIR=logs
export OPENROUTER_API_KEY=...
export PHASE1_LOG_DIR="logs/phase1-$(date +%Y%m%d-%H%M%S)"

uv run --all-extras inspect eval boundarybench/hardened_agents \
  -T enforcement=none \
  -T dataset=terminal-bench-2.1 \
  -T task_id=log-summary-date-ranges \
  -T max_samples=1 \
  --model openrouter/<real-model> \
  --log-dir "$PHASE1_LOG_DIR" \
  --display none
```

Run this preflight before spending real model calls:

```bash
docker info --format '{{.ServerVersion}}'
uv run python - <<'PY'
from boundarybench.tasks import hardened_agents

task = hardened_agents(
    enforcement="none",
    dataset="terminal-bench-2.1",
    task_id="log-summary-date-ranges",
    max_samples=1,
)
sample = task.dataset[0]
print(sample.id)
print(sample.metadata["terminal_bench_task_id"])
print(sample.metadata["dataset_version"])
PY
```

Expected Phase 1 evidence:

- status: `success`
- total samples: `1`
- completed samples: `1`
- sample metadata includes `terminal_bench_task_id=log-summary-date-ranges`
- sample metadata includes `dataset_version=terminal-bench-2.1`
- score metadata includes `official_verifier_result`
- score metadata includes `official_verifier_output`
- Inspect score equals Harbor's official verifier reward

## Local Smoke And Contract Matrix

Live Terminal-Bench commands require Harbor / `inspect-harbor` plus credentials
for the selected model provider. The `local_fake` and fake AgentSH commands are
local contract paths only; they do not make a benchmark claim.

For current hardened benchmark validation, use the policy-based Daytona task
`boundarybench/hardened_terminalbench_daytona` with
`-T policy=low-nist` through the managed Cloud Run path. The resolvable policy
names are the N×F×P roster (`control`, `non-root`, `low-nist`, `moderate-nist`,
`high-nist`, `netlock`, `fslock`); see `docs/policy-axes.md`.

### Local Fake Plugin Smoke

```bash
uv run --all-extras inspect eval boundarybench/hardened_agents \
  -T enforcement=local_fake \
  -T max_samples=1 \
  --model mockllm/model \
  --display none
```

Use this only for plugin wiring. It is never benchmark evidence.

### Terminal-Bench Control

```bash
uv run --all-extras inspect eval boundarybench/hardened_agents \
  -T enforcement=none \
  -T dataset=terminal-bench-2.1 \
  -T task_id=log-summary-date-ranges \
  -T max_samples=1 \
  --model openrouter/<real-model> \
  --log-dir logs/phase2-control-$(date +%Y%m%d-%H%M%S) \
  --display none
```

This is the un-hardened Harbor / `inspect-harbor` control. Harbor remains the
source of truth for Terminal-Bench setup and verification.

### AgentSH Contract Preflight Only

```bash
BOUNDARYBENCH_AGENTSH_BACKEND=fake \
uv run --all-extras inspect eval boundarybench/hardened_agents \
  -T enforcement=agentsh \
  -T dataset=terminal-bench-2.1 \
  -T task_id=log-summary-date-ranges \
  -T hardening_config=agentsh_sev1_fixture \
  -T preflight_only=true \
  -T max_samples=1 \
  --model mockllm/model \
  --log-dir logs/phase2-preflight-$(date +%Y%m%d-%H%M%S) \
  --display none
```

Expected evidence: fake AgentSH policy, session, preflight events, and one check
result per declared hardening type. The upstream agent/model path should not be
needed.

### AgentSH Fake Failure Gating

```bash
BOUNDARYBENCH_AGENTSH_BACKEND=fake \
BOUNDARYBENCH_AGENTSH_FAKE_FAILURE=omit_supported_event \
uv run --all-extras inspect eval boundarybench/hardened_agents \
  -T enforcement=agentsh \
  -T dataset=terminal-bench-2.1 \
  -T task_id=log-summary-date-ranges \
  -T hardening_config=agentsh_sev1_fixture \
  -T max_samples=1 \
  --model mockllm/model \
  --log-dir logs/phase2-gating-$(date +%Y%m%d-%H%M%S) \
  --display none
```

Expected evidence: preflight fails, the upstream solver is not called, and the
Inspect log records a `failure_type=hardening_preflight` score with failed check
IDs and AgentSH preflight results rather than a Harbor verifier result.
