# Task solvability evidence — NIST-derived high

`high-nist-89-task-evidence.csv` is the per-task solvability audit of all 89
Terminal-Bench 2.1 tasks under the strictest published policy tier, `high-nist`
(n5-f2-p2; the *NIST-derived high* tier). One row per task.

## Columns

| Column | Meaning |
| --- | --- |
| `task` | Terminal-Bench 2.1 task id. |
| `status` | `PASS` — a solvability witness reaches the task's official passing state under the policy (82 tasks). `DROP` (6) and `INFEASIBLE` (1) together are the seven *blocked-by-design* tasks: the policy forbids an action the task itself requires, so no policy-compliant solution exists. |
| `reward` | Verifier reward of the witness run (`1.0`), or `n/a` for non-PASS rows. |
| `refsol_type` | How the witness passes: `official/canonical` (50) — Terminal-Bench's own reference solution passes unchanged (the *unaffected* subset); `implemented-witness (static-egress)` (30) and `existing-rootless-witness` (2) — a study-authored, policy-compliant reference solution (together the 32-task *affected* subset); `none (needs domain exception)` (1) — no witness exists. |
| `signpost_fixture` | Audit fixture used by earlier iterations of the audit, if any (`none` for 84 rows); details in `notes`. |
| `adapted_verifier` | `yes` for the five verifier-repaired tasks whose additively broadened checks live in `src/boundarybench/terminalbench/adapted_verifiers/`; `none-needed (verifier already /app-native)` for `caffe-cifar-10`. |
| `eval_evidence_id` | Basename of the Inspect `.eval` log containing the witness trial. Audit runs were batched, so several rows share one log (88 rows map to 33 distinct logs). `count-dataset-tokens` has no id because no reference-solution run exists for it. The logs are retained by the maintainers for audit and are not distributed: they contain full execution transcripts. |
| `median_runtime_s` | Median witness runtime in seconds. |
| `notes` | Free-text audit notes (fix history, drop rationale). |

## Task-set mapping

- 82 `PASS` rows = the solvability-witness pool used for the reduced-pool results.
- 50 `official/canonical` rows = the *unaffected* subset; the 32 witness rows = the *affected* subset.
- 6 `DROP` + 1 `INFEASIBLE` rows = the seven *blocked-by-design* tasks.
- The five `adapted_verifier = yes` rows are the verifier-repaired tasks.
