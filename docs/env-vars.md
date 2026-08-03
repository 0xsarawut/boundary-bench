# Environment Variables

Local fake and preflight-only commands run without live credentials. Live
benchmark runs (`boundarybench run`) need exactly two secrets:

- `OPENROUTER_API_KEY`: model inference for the agent harness inside the
  sandbox (injected under a harness-specific alias; the canonical name is
  stripped from the agent environment by policy hardening).
- `DAYTONA_API_KEY`: Daytona sandbox execution.

`boundarybench` auto-loads a `.env` from the working directory, so a filled-in
`.env` is enough — no `export` needed. Both keys can also be passed as
`boundarybench run --openrouter-api-key` / `--daytona-api-key` flags. Precedence
is flags > exported vars > `.env` (an explicit override always wins).

## Inspect Variables

- `INSPECT_LOG_DIR`: optional Inspect log directory. Use `logs` for local runs.
- `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`: only needed when running the
  un-hardened `hardened_agents` control task with `--model openai/...` or
  `--model anthropic/...` directly through Inspect. Not used by
  `boundarybench run`.

Docker must be running for the local `sandbox_env_name=docker` smoke path.

## Daytona Variables

- `DAYTONA_API_KEY`: Daytona API authentication.
- `BOUNDARY_DAYTONA_SNAPSHOT`: Daytona snapshot selection (legacy alias).
- `BOUNDARYBENCH_DAYTONA_SNAPSHOT`: Daytona snapshot used by the benchmark
  runtime. Defaults to `boundary-policy-lab-v1` (recipe + provenance in
  `snapshots/policy-lab/`; validated to exec as root with full caps and pass
  the nftables / read-only-mount / setpriv spikes). Note: the Terminal-Bench
  task path builds each sandbox from the task's own Docker image; the snapshot
  is used by standalone diagnostics.
- `BOUNDARYBENCH_DAYTONA_CPU`, `BOUNDARYBENCH_DAYTONA_MEMORY_GIB`,
  `BOUNDARYBENCH_DAYTONA_DISK_GIB`: resource metadata recorded for Daytona
  artifacts. Defaults are `1`, `2`, and `3`. The runner enforces the minimal
  profile by default: a non-default snapshot or larger resource values are
  rejected unless the run passes `--allow-resource-override`
  (`require_minimal_profile`).
- `BOUNDARYBENCH_DAYTONA_RESOURCE_PROFILE`: resource profile label recorded
  on Daytona artifacts. Defaults to `minimal`.
- `BOUNDARYBENCH_AGENT_TIMEOUT_SEC`: fallback agent timeout for
  non-standard local samples that do not carry current Terminal-Bench
  `task.toml` metadata. Current Terminal-Bench tasks use
  `[agent].timeout_sec` from `task.toml`; this env var does not cap those
  task-declared timeouts.
- `BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS`: total attempts for a consecutive
  transient Daytona verifier transport operation; defaults to `3` and must be
  an integer from `1` through `10`. Retries cover safe pre-dispatch test-upload
  operations and poll the existing verifier command with the same session and
  command IDs. Each retry requires a successful same-sandbox liveness probe;
  retries do not restart the verifier or rerun the agent. Definitive sandbox
  loss and non-transport verifier errors remain terminal.
- `BOUNDARYBENCH_SANDBOX_MANAGED_BY`: optional namespace label prefix for
  Daytona sandboxes so parallel checkouts don't claim each other's sandboxes.
  Must match `[a-z0-9][a-z0-9-]*`; fails closed on invalid values.

## Policy Block Message Variables

- `BOUNDARYBENCH_POLICY_BLOCK_MESSAGE`: optional one-line Daytona policy
  block message for quick experiments. Terminal-Bench runtime probes rely on
  structured policy events, so enterprise-style generic messages such as
  `Permission denied` are valid.
- `BOUNDARYBENCH_POLICY_BLOCK_MESSAGE_FILE`: optional UTF-8 file containing
  a full multi-line Daytona policy block message. Prefer this for experiments
  that vary policy wording, rationale, or allowed next-step instructions.
- `BOUNDARYBENCH_APPARMOR_CAPABILITY_PROBE`: optional AppArmor capability
  spike for hardened Daytona runtime probes. Set to `1` to record whether the
  sandbox can inspect AppArmor, load a probe profile, attach it with `aa-exec`,
  inherit it in a child process, block a denied file read, and still allow
  workspace writes. Diagnostic evidence only.

## Run Selection Variables

- `BOUNDARYBENCH_POLICY`: hardening policy name for the run; defaults to
  `control` (`src/boundarybench/terminalbench/daytona_eval.py`). Must resolve to
  a registered N×F×P preset.
- `BOUNDARYBENCH_ALLOW_DEBUG_POLICY`: set truthy to allow resolving a policy
  marked internal `debug_only`. Unset by default; no preset in the current
  resolvable roster is debug-only, so this gates nothing today.

## AgentSH Variables (retained overlay, not wired into benchmark presets)

- `BOUNDARYBENCH_AGENTSH_BACKEND`: required for `enforcement=agentsh`;
  set explicitly to `fake` for local contract evidence or `real` when an
  AgentSH binary is installed. The runtime fails closed when this is unset.
- `BOUNDARYBENCH_AGENTSH_FAKE_FAILURE`: optional fake-backend failure mode
  such as `omit_supported_event` or `invert_supported_event`.
- `AGENTSH_POLICY_DIR`: directory where the derived AgentSH YAML policy and
  matching local config are materialized. Defaults to
  `/tmp/boundarybench-agentsh-policy`.
- `AGENTSH_BIN`: required when `BOUNDARYBENCH_AGENTSH_BACKEND=real`.
- `BOUNDARYBENCH_AGENTSH_RUNTIME`: real-backend runtime mode, either
  `server_session` (default) or `cli_wrap`.
- `AGENTSH_SERVER`: real-backend server URL in `server_session` mode. Defaults
  to `http://127.0.0.1:18080`.
- `BOUNDARYBENCH_AGENTSH_SECURITY_PROFILE`: AgentSH policy security
  profile, either `ptrace` (default) or `full`.

## In-Sandbox Runtime Variables

Set by the runtime hardening layer inside the Daytona sandbox
(`src/boundarybench/daytona/scripts/run_policy_hardening.sh` and the
compiled shims), not by operators. Listed for transcript and debugging
reference.

- `BOUNDARY_BLOCK_NETWORK`: `1` when the active policy blocks the agent
  process's network egress.
- `BOUNDARY_CIDR_EGRESS`: `1` when CIDR default-deny egress enforcement is
  active.
- `BOUNDARY_POLICY_EVENT_LOG`: structured policy-event JSONL path; defaults to
  `/tmp/boundarybench-policy-events.jsonl`.

## Other Variables

No Opik variables are defined or expected.
