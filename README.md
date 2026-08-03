<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/boundary-bench-mark-dark.svg">
  <img src="docs/assets/boundary-bench-mark-light.svg" width="88" alt="Boundary Bench mark">
</picture>

# boundary-bench

**Benchmark coding agents under real sandbox policy.**

<br/>

[Website](https://boundarybench.com/) · [Leaderboard](https://boundarybench.com/leaderboard) · [Quickstart](#quickstart) · [Policies](#policies) · [Citation](#citation)

<br/>

[![License](https://img.shields.io/badge/license-MIT-dde7da?style=flat-square&labelColor=2a3f38)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12+-dde7da?style=flat-square&labelColor=2a3f38)](https://www.python.org/)
[![Benchmark](https://img.shields.io/badge/benchmark-Terminal--Bench_2.1-dde7da?style=flat-square&labelColor=2a3f38)](https://www.tbench.ai/leaderboard/terminal-bench/2.1)
[![Inspect](https://img.shields.io/badge/built_on-Inspect_AI-dde7da?style=flat-square&labelColor=2a3f38)](https://inspect.aisi.org.uk/)
[![arXiv](https://img.shields.io/badge/arXiv-2608.02670-dde7da?style=flat-square&labelColor=2a3f38)](https://arxiv.org/abs/2608.02670)
[![CI](https://img.shields.io/github/actions/workflow/status/boundary-bench/boundary-bench/ci.yml?style=flat-square&labelColor=2a3f38&color=dde7da&label=ci)](https://github.com/boundary-bench/boundary-bench/actions/workflows/ci.yml)
[![Leaderboard](https://img.shields.io/badge/leaderboard-boundarybench.com-f1bd94?style=flat-square&labelColor=2a3f38)](https://boundarybench.com/leaderboard)

</div>

---

**Boundary-Bench** benchmarks coding-agent harnesses on [Terminal-Bench](https://www.tbench.ai/)
tasks while the agent runs inside a hardened sandbox, measuring how much
capability an agent loses as the environment is restricted to
enterprise/NIST-derived controls.

Runs execute in [Daytona](https://www.daytona.io/) sandboxes, agents reach
models through [OpenRouter](https://openrouter.ai/), and tasks and official
verification come from [Harbor](https://github.com/laude-institute/harbor)
(`inspect-harbor`). It's packaged as an [Inspect AI](https://inspect.aisi.org.uk/)
task with standard `.eval` logs.

Live results (the leaderboard, task browser, and research report) are at
**[boundarybench.com](https://boundarybench.com/)**.

<div align="center">
<sub><samp>LEADERBOARD · STRICTEST LEVEL (HIGH-NIST) · AUG 2026</samp></sub>

| # | Agent | Model | Success rate | Cost |
|:--|:--|:--|:--|:--|
| 01 | Grok Build | Grok 4.5 | 74.9% <sub>±1.4</sub> | $123.5 |
| 02 | Codex | GPT-5.6 Sol | 74.2% <sub>±2.4</sub> | $58.9 |
| 03 | Claude Code | Fable 5 | 67.8% <sub>±1.4</sub> | $375.3 |

<sub>Terminal-Bench 2.1 · 89 tasks · reasoning effort high · three trials per cell · <a href="https://boundarybench.com/leaderboard">full leaderboard →</a></sub>
</div>

---

## Quickstart

You need two keys: OpenRouter for model inference and Daytona for sandboxes.
The task, policy, and harness are flags on the run command.

```bash
# 1. Install (Python >= 3.12, uv recommended)
uv sync --extra harbor --extra daytona

# 2. Credentials: create a .env; boundarybench loads it automatically
cp .env.example .env   # then fill in OPENROUTER_API_KEY and DAYTONA_API_KEY

# 3. Run one task, hardened to the High-NIST level, with Claude Code
uv run boundarybench run \
  --task log-summary-date-ranges \
  --policy high-nist \
  --harness claude-code \
  --model anthropic/claude-opus-5
```

> **Costs:** runs bill your own OpenRouter and Daytona keys. Expect a few
> dollars and a few minutes per task, varying by task, model, and policy.

Running with no flags runs the full benchmark: all 89 tasks under the
`control` policy with the `terminus` harness, after a confirmation prompt:

```bash
uv run boundarybench run
```

- `--task`: run one task or a comma-separated list
- `--all-tasks`: run all 89 tasks without the confirmation prompt
- `--exclude-not-applicable`: skip tasks that can't pass under the selected policy
- `--dry-run`: print what would run and exit, without spending anything
- `--yes`: skip confirmation prompts, for scripts and CI

The run provisions a Daytona sandbox from the task's Docker image, installs
the harness, applies the policy's Linux hardening, lets the agent work, then
runs Harbor's official verifier **outside the hardening boundary**. Results
are written as Inspect `.eval` logs (`--log-dir`, default
`logs/boundarybench-<timestamp>`). View them with `inspect view` or export
CSV with `boundarybench export-results`.

Other entry points:

```bash
boundarybench list                # show policies and harnesses
boundarybench export-results ...  # .eval logs -> CSV
boundarybench analyze ...         # policy-blockage report from .eval logs
boundarybench enforcement-probe   # probe a preset's native walls (no agent)
boundarybench policy validate     # validate policy catalog packs
```

Boundary-Bench is an Inspect extension, so you can also run it with plain
`inspect eval`. The `--model` slot is only a label; the harness inside the
sandbox makes the real model calls:

```bash
uv run inspect eval boundarybench/hardened_terminalbench_daytona \
  -T task_ids=log-summary-date-ranges \
  -T policy=high-nist \
  -T harness=claude_code \
  -T model=anthropic/claude-opus-5 \
  --model mockllm/model
```

---

## Policies

Policies are points in an N×F×P lattice (Network × Filesystem × Privilege)
enforced with native Linux controls (nftables, read-only bind remounts,
setpriv/no_new_privs/capability drops, Landlock). Denials show up as ordinary
OS errors (`EROFS`, `EPERM`, connection refused), with no agent-visible shim.

The published benchmark levels:

| Policy | Network | Filesystem | Privilege |
|---|---|---|---|
| `control` | full egress | open | root |
| `non-root` | full egress | open | non-admin user |
| `high-nist` | per-task allowlist | read-only OS + frozen home | non-admin + no_new_privs + capability drop |

### Build your own hardening

Instead of a named level, you can compose a policy from these hardening
options:

| Option | What it does |
|---|---|
| `non-root` | Run the agent as an ordinary user (no sudo; root password locked) |
| `no-escalation` | Block privilege escalation (no-new-privileges, drop capabilities, strip setuid) |
| `readonly-os` | Make the OS read-only; only the workspace stays writable |
| `freeze-home` | Freeze the home directory too |
| `restrict-egress` | Restrict network access to an allowlist; block cloud-metadata & private networks |

Prerequisites are filled in automatically: `freeze-home` implies `readonly-os`
and `non-root`, and any network or filesystem hardening implies `non-root`.
Compose interactively:

```bash
uv run boundarybench build-policy      # answer a few y/n questions, then run
```

Or non-interactively, with your own egress allowlist:

```bash
uv run boundarybench run \
  --task log-summary-date-ranges --harness claude-code \
  --harden non-root,readonly-os,restrict-egress \
  --egress-mode custom --egress-allow pypi.org,files.pythonhosted.org
```

Egress rules never block the model endpoint. Inbound traffic isn't restricted
because the sandbox exposes no services.

---

## Tasks

The benchmark runs all 89 terminal-bench-2.1 tasks. Two task lists
([task_applicability.py](src/boundarybench/terminalbench/task_applicability.py))
affect how results are read. Both are recorded in each sample's metadata and
shown by `export-results` and `analyze`:

- **5 tasks use an adapted verifier** (`adaptive-rejection-sampler`,
  `configure-git-webserver`, `make-doom-for-mips`, `mcmc-sampling-stan`,
  `sqlite-with-gcov`). The stock verifier checks a root-owned path, so a
  correct non-root solution would fail. Each task gets a corrected verifier
  (`adapted_verifiers/<task>/`), used under every policy so grading is
  identical across policy arms. Rows are marked `verifier_source: adapted`.

- **7 tasks can't pass under hardened policies** (`build-pmars`,
  `build-pov-ray`, `build-cython-ext`, `kv-store-grpc`,
  `nginx-request-logging`, `mailman`, `count-dataset-tokens`). Their
  instructions require what the policies deny: system-wide installs, writes
  under `/etc` or `/var`, or non-allowlisted hosts. Under any policy except
  `control`, `boundarybench run` asks for confirmation before running them
  (`--yes` skips the prompt). Forced rows are marked
  `policy_applicability: not_applicable` and excluded from success rates.
  `count-dataset-tokens` is also flagged separately: its verifier accepts the
  expected constant without the computation.

---

## Harnesses

| CLI name | Harness |
|---|---|
| `terminus` | Terminus 2 (Harbor's reference agent, default) |
| `claude-code` | Claude Code |
| `codex` | OpenAI Codex CLI |
| `grok` | Grok CLI |

Pinned harness versions are listed in [`provenance/`](provenance/).

## Standards compatibility

- **Inspect**: `boundarybench` registers tasks via the `inspect_ai` entry point;
  runs produce standard `.eval` logs usable with `inspect view` and the Inspect
  toolchain.
- **Harbor / Terminal-Bench**: task setup and official verification come from
  `inspect-harbor` / `harbor` against the pinned `terminal-bench-2.1` dataset.
  Boundary-Bench does not fork task semantics: the agent runs under policy, and
  Harbor's unmodified verifier decides pass/fail.

---

## Repository layout

This repository is the benchmark core: policies, harnesses, the Daytona
runner, and Harbor verification.

| Path | Purpose |
|---|---|
| `src/boundarybench/terminalbench/` | The Inspect task, Daytona runner, Harbor bundle/verifier glue, policy resolver |
| `src/boundarybench/harness/` | Harness adapters (claude_code, codex, terminus_2, grok) + in-sandbox install scripts |
| `src/boundarybench/daytona/` | Policy axes, hardening config/scripts, runtime policy probes |
| `src/boundarybench/policy_catalog/` | Canonical policy catalog packs, validation, compilation |
| `src/boundarybench/cli.py` | `boundarybench` CLI (`run`, `list`, `export-results`, …) |
| `docs/` | Policy model, NIST level derivations, env vars, snapshots |
| `provenance/` | Frozen manifest of the evaluated model + harness bundles (`bundles.json`, `BUNDLES.md`) |
| `verifier_diffs/` | Unified diffs of the five adapted verifiers vs upstream Terminal-Bench 2.1, with per-assertion notes |
| `data/` | Per-task solvability-evidence CSV |
| `tests/` | Unit and contract tests |

## Development

```bash
uv sync --extra dev --extra harbor --extra daytona
uv run pytest -q
uv run ruff check src tests
```

The test suite is hermetic and needs no live credentials. Daytona
provisioning and model calls happen only in real benchmark runs.

## Citation

```bibtex
@misc{davidovich2026permissiondenied,
  title         = {Permission Denied: Policy-Graded Evaluation of Coding Agents in Hardened Environments},
  author        = {Dotan Davidovich and Yair Amar and Hai Rozencwajg and Or Hiltch},
  year          = {2026},
  eprint        = {2608.02670},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
  url           = {https://arxiv.org/abs/2608.02670}
}
```

## License

MIT, see [LICENSE](LICENSE).

---

<div align="center">

<a href="https://accomplish.ai/"><picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/powered-by-accomplish-dark.svg">
  <img src="docs/assets/powered-by-accomplish-light.svg" height="18" alt="Powered by Accomplish">
</picture></a>

<sub><samp>© 2026 ACCOMPLISH AI, INC. &nbsp;·&nbsp; <a href="https://x.com/accomplish_ai">X</a> &nbsp;·&nbsp; <a href="https://www.linkedin.com/company/accomplish-hq/">LINKEDIN</a></samp></sub>

</div>
