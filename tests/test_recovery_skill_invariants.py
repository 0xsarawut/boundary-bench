"""Invariant regression guards for the ``recovery_skill`` bundle.

The per-task Phase-1 reviews pinned the renderer's behavior one preset/harness at a
time; two *hard* invariants span the whole suite and need dedicated guards:

1. **Task-blindness.** The rendered guidance BODY is byte-identical across EVERY
   task in the suite (``body_sha256`` constant) and harness-independent, and embeds
   NO task ids, artifact URLs, or version pins. Per-task egress domains live ONLY in
   ``allowed-domains.txt``, never in the body. ``test_recovery_skill`` checks this on
   a single task / a two-task pair; here we sweep the real per-task egress data.

2. **Config-snapshot seam.** The body is harness-independent ONLY because the run
   path renders from the PRE-carveout config snapshot — ``daytona_eval.py`` line ~923
   passes ``config_pre_carveout`` (captured *before* ``_with_harness_home_carveouts``),
   NOT the post-overlay config used for live hardening. A regression that passed the
   post-overlay config would fold the running harness's own home dir into §5's
   writable map, so codex would list ``~/.codex``, its ``body_sha256`` would diverge
   from claude_code's, and the cross-harness body-identity invariant would break. The
   Phase-1 recovery tests are all claude_code, where pre == post (``.claude`` is
   already a default F3 carveout), so they *structurally* cannot catch this. This
   guard renders the codex seam explicitly.
"""

from __future__ import annotations

from boundarybench.daytona.hardening_config import (
    DEFAULT_DOMAIN_EGRESS_ALLOWLIST,
)
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    _load_task_egress_allowlists,
    build_daytona_config_from_axes,
)
from boundarybench.harness.adapter import HarnessAdapter
from boundarybench.harness.claude_code import ClaudeCodeAdapter
from boundarybench.harness.codex import CodexAdapter

from boundarybench.terminalbench.daytona_eval import (
    _with_harness_health_domains,
    _with_harness_home_carveouts,
)
from boundarybench.terminalbench.daytona_constants import (
    REMOTE_ALLOWED_DOMAINS_PATH,
)
from boundarybench.terminalbench.policies import resolve_policy
from boundarybench.terminalbench.recovery_skill import (
    RecoveryBundle,
    render_recovery_bundle,
)

_HEALTH_DOMAIN = "api.anthropic.com"
_INFRA = frozenset((*DEFAULT_DOMAIN_EGRESS_ALLOWLIST, _HEALTH_DOMAIN))
_AGENT_HOME = "/home/daytona"

_PLAIN_TASK_IDS = ("hello-world", "mailman", "git-multibranch")

_LEAK_MARKERS = (
    "models.huggingface.co",
    "raw.githubusercontent.com/",
    "s3.amazonaws.com",
    "build-pov-ray",
    "rust-v0",
    "1.31.3",
)


def _all_task_ids() -> list[str]:
    """Every task that parameterizes the config + a few plain no-egress tasks.

    ``_load_task_egress_allowlists`` is the canonical per-task egress data source —
    the same data ``test_policy_prompt``'s egress cases reach through
    ``task_egress_domains``. Its keys are exactly the task ids for which the task_id
    changes the resolved config, so they are the ids that would EXPOSE a regression
    that made the body task-dependent. Hermetic (reads a packaged JSON; no harbor /
    dataset load), so the sweep stays a fast unit test.
    """

    egress = sorted(_load_task_egress_allowlists())
    plain = [t for t in _PLAIN_TASK_IDS if t not in egress]
    return egress + plain


def _render(
    adapter: HarnessAdapter,
    *,
    preset: str = "high-nist",
    task_id: str = "hello-world",
    config=None,
) -> RecoveryBundle | None:
    return render_recovery_bundle(
        policy=resolve_policy(preset),
        config=(
            config
            if config is not None
            else build_daytona_config_from_axes(AXIS_PRESETS[preset], task_id=task_id)
        ),
        harness_adapter=adapter,
        infra_domains=_INFRA,
        agent_home=_AGENT_HOME,
    )


def _body_text(bundle: RecoveryBundle) -> str:
    """The body-bearing file: SKILL.md (claude_code) or RECOVERY.md (codex/grok).

    Deliberately NOT allowed-domains.txt — per-task domains legitimately live there,
    so it is excluded from the leak scan.
    """

    return next(
        f.content
        for f in bundle.files
        if f.remote_path.endswith(("SKILL.md", "RECOVERY.md"))
    )


def _claude_core_text(bundle: RecoveryBundle) -> str:
    """The always-loaded ``CLAUDE.md`` core (claude_code only).

    Symmetric with codex's ``AGENTS.md``: auto-injected every turn, it is ALSO
    static/task-blind, so the leak scan and the byte-identity check must cover it —
    not just the body-bearing SKILL.md.
    """

    return next(
        f.content
        for f in bundle.files
        if f.remote_path.endswith("/.claude/CLAUDE.md")
    )


def test_body_is_task_blind_and_leak_free() -> None:
    ids = _all_task_ids()
    assert len(ids) >= 36, ids

    per_harness_shas: dict[str, set[str]] = {"claude_code": set(), "codex": set()}
    claude_core_texts: set[str] = set()
    for adapter in (ClaudeCodeAdapter(), CodexAdapter()):
        for tid in ids:
            bundle = _render(adapter, task_id=tid)
            assert bundle is not None, (adapter.name, tid)
            per_harness_shas[adapter.name].add(bundle.body_sha256)
            body = _body_text(bundle)
            for marker in _LEAK_MARKERS:
                assert marker not in body, (marker, adapter.name, tid)
            if adapter.name == "claude_code":
                core = _claude_core_text(bundle)
                claude_core_texts.add(core)
                for marker in _LEAK_MARKERS:
                    assert marker not in core, (marker, "CLAUDE.md", tid)

    assert len(per_harness_shas["claude_code"]) == 1, per_harness_shas["claude_code"]
    assert len(per_harness_shas["codex"]) == 1, per_harness_shas["codex"]
    assert len(claude_core_texts) == 1, claude_core_texts
    assert per_harness_shas["claude_code"] == per_harness_shas["codex"]


def test_per_task_domains_stay_out_of_body_when_injected() -> None:
    tasks_with_markers = {
        "count-dataset-tokens": ("s3.amazonaws.com", "huggingface.co"),
        "hf-model-inference": ("huggingface.co",),
    }
    shas: set[str] = set()
    for tid, markers in tasks_with_markers.items():
        bundle = _render(ClaudeCodeAdapter(), preset="moderate-nist", task_id=tid)
        assert bundle is not None, tid
        shas.add(bundle.body_sha256)
        allowlist = next(
            f.content
            for f in bundle.files
            if f.remote_path == REMOTE_ALLOWED_DOMAINS_PATH
        )
        body = _body_text(bundle)
        for marker in markers:
            assert marker in allowlist, (marker, tid)
            assert marker not in body, (marker, tid)
    assert len(shas) == 1, shas


def test_config_snapshot_seam_keeps_body_harness_independent() -> None:
    preset = AXIS_PRESETS["high-nist"]
    claude, codex = ClaudeCodeAdapter(), CodexAdapter()

    def pre(adapter: HarnessAdapter):
        base = build_daytona_config_from_axes(preset, task_id="hello-world")
        return _with_harness_health_domains(base, adapter)

    def post(adapter: HarnessAdapter):
        return _with_harness_home_carveouts(pre(adapter), adapter)

    pre_claude = _render(claude, config=pre(claude))
    pre_codex = _render(codex, config=pre(codex))
    assert pre_claude is not None and pre_codex is not None
    assert pre_claude.body_sha256 == pre_codex.body_sha256
    pre_codex_body = _body_text(pre_codex)
    assert "~/.codex" not in pre_codex_body

    post_claude = _render(claude, config=post(claude))
    assert post_claude is not None
    assert post_claude.body_sha256 == pre_claude.body_sha256

    post_codex = _render(codex, config=post(codex))
    assert post_codex is not None
    assert post_codex.body_sha256 != pre_codex.body_sha256
    assert "~/.codex" in _body_text(post_codex)
