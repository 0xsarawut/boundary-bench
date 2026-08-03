"""Unit tests for the ``recovery_skill`` policy-error-recovery bundle renderer.

These exercise the renderer against the REAL N×F×P presets (via ``resolve_policy``
+ ``build_daytona_config_from_axes``) and the REAL per-task egress data, so any
drift in the presets, the trusted-domain base, the enforced writable map, or the
task egress allowlists breaks these tests rather than silently changing the
guidance the agent receives.

The load-bearing correctness properties pinned here:
- §5 renders the ENFORCED writable set (never /var/tmp under F2) — the whole
  reason the bundle exists (see ``policy_disclosure.enforced_writable_display``).
- The guidance BODY (§1-§6) is byte-identical across tasks AND across harnesses
  for a given policy (``body_sha256``), so a later task can assert task-blindness
  across all 89 tasks and the A/B can prove which body shipped.
- Sections are conditional on the walls the resolved config actually enforces.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from boundarybench.daytona.hardening_config import (
    DEFAULT_DOMAIN_EGRESS_ALLOWLIST,
)
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    build_daytona_config_from_axes,
)
from boundarybench.harness.claude_code import ClaudeCodeAdapter
from boundarybench.harness.codex import CodexAdapter
from boundarybench.harness.grok import GrokAdapter
from boundarybench.harness.terminus_2 import Terminus2Adapter
from boundarybench.terminalbench.daytona_constants import (
    REMOTE_ALLOWED_DOMAINS_PATH,
)
from boundarybench.terminalbench.policies import resolve_policy
from boundarybench.terminalbench.recovery_skill import (
    RECOVERY_BUNDLE_OFF,
    RECOVERY_BUNDLE_ON,
    RECOVERY_SKILL_NAME,
    RecoveryBundle,
    RecoveryFile,
    _SKILL_FRONTMATTER,
    build_recovery_bundle_provenance,
    render_recovery_bundle,
    validate_recovery_bundle,
)


_HEALTH_DOMAIN = "api.anthropic.com"
_INFRA = frozenset((*DEFAULT_DOMAIN_EGRESS_ALLOWLIST, _HEALTH_DOMAIN))

_AGENT_HOME = "/home/daytona"


def _cfg(name, task_id="hello-world"):
    return build_daytona_config_from_axes(AXIS_PRESETS[name], task_id=task_id)


def _render(name, adapter, *, task_id="hello-world", infra=_INFRA):
    return render_recovery_bundle(
        policy=resolve_policy(name),
        config=_cfg(name, task_id),
        harness_adapter=adapter,
        infra_domains=infra,
        agent_home=_AGENT_HOME,
    )


def _skill(bundle: RecoveryBundle) -> RecoveryFile:
    return next(f for f in bundle.files if f.remote_path.endswith("SKILL.md"))


def test_validate_recovery_bundle_coerces_yaml_booleans() -> None:
    assert validate_recovery_bundle(True) == RECOVERY_BUNDLE_ON
    assert validate_recovery_bundle(False) == RECOVERY_BUNDLE_OFF


def test_validate_recovery_bundle_strict_for_strings() -> None:
    assert validate_recovery_bundle("on") == "on"
    assert validate_recovery_bundle("off") == "off"
    for bad in ("true", "yes", "1", "On", "OFF", "sometimes", ""):
        with pytest.raises(ValueError, match="recovery_bundle must be one of"):
            validate_recovery_bundle(bad)


def test_control_returns_none() -> None:
    assert _render("control", ClaudeCodeAdapter()) is None


def test_legacy_enforcement_mode_renders_none_even_when_hardening() -> None:
    native = resolve_policy("high-nist")
    legacy = replace(
        native, enforcement_mode="legacy", overlays=("blocked-surfaces",)
    )
    assert legacy.applies_hardening
    assert (
        render_recovery_bundle(
            policy=legacy,
            config=_cfg("high-nist"),
            harness_adapter=ClaudeCodeAdapter(),
            infra_domains=_INFRA,
            agent_home=_AGENT_HOME,
        )
        is None
    )
    assert _render("high-nist", ClaudeCodeAdapter()) is not None


def test_non_root_has_privilege_not_network_or_filesystem() -> None:
    bundle = render_recovery_bundle(
        policy=resolve_policy("non-root"),
        config=_cfg("non-root"),
        harness_adapter=ClaudeCodeAdapter(),
        infra_domains=frozenset(),
        agent_home=_AGENT_HOME,
    )
    assert bundle is not None
    body = _skill(bundle).content
    assert "## 3. Privilege wall" in body
    assert "pip install --user" in body
    assert "## 4. Network wall" not in body
    assert "## 5. Filesystem wall" not in body
    assert "→ FILESYSTEM wall" not in body
    assert "not on the egress allowlist" not in body
    assert "/tmp/allowed-domains.txt" not in body
    assert "Matches NONE of the walls above" in body
    assert not any(
        f.remote_path == REMOTE_ALLOWED_DOMAINS_PATH for f in bundle.files
    )
    assert len(bundle.files) == 2
    assert {f.remote_path for f in bundle.files} == {
        f"{_AGENT_HOME}/.claude/CLAUDE.md",
        f"{_AGENT_HOME}/.claude/skills/policy-error-recovery/SKILL.md",
    }


def test_fslock_has_filesystem_and_privilege_not_network() -> None:
    bundle = render_recovery_bundle(
        policy=resolve_policy("fslock"),
        config=_cfg("fslock"),
        harness_adapter=ClaudeCodeAdapter(),
        infra_domains=frozenset(),
        agent_home=_AGENT_HOME,
    )
    assert bundle is not None
    body = _skill(bundle).content
    assert "## 5. Filesystem wall" in body
    assert "## 3. Privilege wall" in body
    assert "## 4. Network wall" not in body
    assert "Writable: /app, /tmp, ~/.claude, ~/.cache, ~/.config, ~/.local." in body
    assert not any(
        f.remote_path == REMOTE_ALLOWED_DOMAINS_PATH for f in bundle.files
    )


def test_high_nist_claude_code_skill_path_frontmatter_and_writable_map() -> None:
    bundle = _render("high-nist", ClaudeCodeAdapter())
    assert bundle is not None
    assert bundle.harness == "claude_code"
    assert bundle.preset_name == "high-nist"

    skill = _skill(bundle)
    assert (
        skill.remote_path
        == "/home/daytona/.claude/skills/policy-error-recovery/SKILL.md"
    )
    assert skill.content.startswith("---\nname: policy-error-recovery")
    assert skill.chmod == "644"

    for heading in (
        "## 1. Identify which wall you hit",
        "## 2. Before any retry",
        "## 3. Privilege wall",
        "## 4. Network wall",
        "## 5. Filesystem wall",
        "## 6. Infeasibility exit",
    ):
        assert heading in skill.content

    assert (
        "Writable: /app, /tmp, ~/.claude, ~/.cache, ~/.config, ~/.local."
        in skill.content
    )
    assert "including /var/tmp and the rest of your home" in skill.content

    assert "you are non-root (`daytona`)" in skill.content

    for dom in _INFRA:
        assert dom not in skill.content


def test_frontmatter_description_sources_representative_taxonomy_markers() -> None:
    desc = " ".join(_SKILL_FRONTMATTER.split()).lower()
    assert "timed out" in desc or "timed-out" in desc
    for phrase in (
        "Failed to connect to bus",
        "Cannot connect to the Docker daemon",
        "Read-only file system",
        "Permission denied",
    ):
        assert phrase.lower() in desc, phrase


def test_claude_code_emits_always_loaded_claude_core() -> None:
    bundle = _render("high-nist", ClaudeCodeAdapter())
    assert bundle is not None

    assert bundle.files[0].remote_path == f"{_AGENT_HOME}/.claude/CLAUDE.md"
    assert bundle.files[1].remote_path == (
        f"{_AGENT_HOME}/.claude/skills/policy-error-recovery/SKILL.md"
    )
    core = bundle.files[0]
    assert core.chmod == "644"

    skill_path = f"{_AGENT_HOME}/.claude/skills/policy-error-recovery/SKILL.md"
    assert RECOVERY_SKILL_NAME in core.content
    assert f"`{RECOVERY_SKILL_NAME}` skill" in core.content
    assert skill_path in core.content
    assert (
        "It MIGHT be the security policy — check the policy before retrying, "
        "rearchitecting, or blaming infrastructure." in core.content
    )
    assert "at most 2 recovery strategies per wall" in core.content
    assert (
        "Never fake, stub, or hardcode a result to satisfy a check" in core.content
    )
    for dom in _INFRA:
        assert dom not in core.content

    codex = _render("high-nist", CodexAdapter())
    assert codex is not None
    assert bundle.body_sha256 == codex.body_sha256


def test_no_stub_guardrail_and_convention_principle() -> None:
    body = _skill(_render("high-nist", ClaudeCodeAdapter())).content
    assert "Make your work count where the check looks." in body
    assert '"Install to <system path>" requirements' not in body
    assert "Expose built binaries by bare name" not in body
    assert "Output files: write them to the exact path the task names" in body
    assert "Tools the task itself will run:" in body
    assert (
        "Already-redirected locations: probe a conventional path with `readlink -f`"
        in body
    )
    assert "Know when you can't reach it:" in body
    assert "This helps ONLY when the check runs in\n    your environment" in body
    assert "Don't drop a binary in `~/.local/bin` and hope" in body
    assert "you CANNOT make it find your artifact" in body
    assert "tool from root's PATH" in body
    assert "treat that requirement as blocked (§6)." in body
    assert (
        "Never fake, stub, or hardcode an expected result to satisfy a check." in body
    )
    assert (
        "Never fake, stub, or hardcode an\nexpected result to make a check pass"
        in body
    )
    assert "a documented partial is worth more than a false pass." in body


def test_f1_workspace_section5_names_only_os_trees_read_only() -> None:
    body = _skill(
        _render("moderate-nist", ClaudeCodeAdapter(), task_id="build-cython-ext")
    ).content
    s5 = body.split("## 5. Filesystem wall")[1].split("## 6.")[0]
    assert "Writable: /app, /tmp, /var/tmp, ~." in s5
    assert (
        "The OS system trees (/usr, /etc, /opt, /var apart from /var/tmp, ...) are "
        "readable but\nREAD-ONLY; writes there fail with EROFS." in s5
    )
    assert "the rest of your home directory" not in s5.replace("\n", " ")
    assert "including /var/tmp" not in s5


def test_f2_read_only_section5_names_var_tmp_read_only() -> None:
    body = _skill(_render("high-nist", ClaudeCodeAdapter())).content
    s5 = body.split("## 5. Filesystem wall")[1].split("## 6.")[0]
    assert "Writable: /app, /tmp, ~/.claude, ~/.cache, ~/.config, ~/.local." in s5
    assert (
        "Everything else — including /var/tmp and the rest of your home directory — "
        "is readable but\nREAD-ONLY; writes fail with EROFS." in s5
    )
    assert "The OS system trees" not in s5


def test_high_nist_allowlist_file_written_and_infra_filtered() -> None:
    bundle = _render("high-nist", ClaudeCodeAdapter())
    assert bundle is not None
    allow = next(
        f for f in bundle.files if f.remote_path == REMOTE_ALLOWED_DOMAINS_PATH
    )
    assert allow.chmod == "644"
    assert allow.content.endswith("\n")
    assert "pypi.org" in allow.content
    for dom in _INFRA:
        assert dom not in allow.content


def test_section1_always_ends_with_no_wall_exit_row() -> None:
    body = _skill(_render("high-nist", ClaudeCodeAdapter())).content
    s1 = body.split("## 1. Identify which wall you hit")[1].split("## 2.")[0]
    assert (
        "- Matches NONE of the walls above (e.g. an error on a path §5 lists as "
        "writable, or a 5xx or\n  timeout on an allowlisted host) → this is an "
        "ordinary error, NOT the policy — debug it normally." in s1
    )
    assert s1.rstrip().endswith("debug it normally.")


def test_egress_gated_but_empty_disclosed_omits_allowlist_pointer() -> None:
    config = replace(_cfg("high-nist"), egress_domain_allowlist=())
    bundle = render_recovery_bundle(
        policy=resolve_policy("high-nist"),
        config=config,
        harness_adapter=ClaudeCodeAdapter(),
        infra_domains=_INFRA,
        agent_home=_AGENT_HOME,
    )
    assert bundle is not None
    body = _skill(bundle).content
    assert "## 4. Network wall — find an allowed source" in body
    assert REMOTE_ALLOWED_DOMAINS_PATH not in body
    assert not any(
        f.remote_path == REMOTE_ALLOWED_DOMAINS_PATH for f in bundle.files
    )


def test_high_nist_body_points_at_allowlist_file_when_written() -> None:
    bundle = _render("high-nist", ClaudeCodeAdapter())
    assert bundle is not None
    body = _skill(bundle).content
    assert (
        f"Check\n  {REMOTE_ALLOWED_DOMAINS_PATH} for the exact allowed hosts" in body
    )
    assert f"Check {REMOTE_ALLOWED_DOMAINS_PATH} for the candidate host" in body
    assert any(f.remote_path == REMOTE_ALLOWED_DOMAINS_PATH for f in bundle.files)


def test_high_nist_codex_agents_and_recovery_files() -> None:
    bundle = _render("high-nist", CodexAdapter())
    assert bundle is not None
    assert bundle.harness == "codex"
    paths = {f.remote_path for f in bundle.files}
    assert "/home/daytona/.codex/AGENTS.md" in paths
    assert "/home/daytona/.codex/recovery/RECOVERY.md" in paths
    assert REMOTE_ALLOWED_DOMAINS_PATH in paths

    agents = next(f for f in bundle.files if f.remote_path.endswith("AGENTS.md"))
    recovery = next(
        f for f in bundle.files if f.remote_path.endswith("RECOVERY.md")
    )
    assert agents.content.startswith("# Security-policy environment")
    assert "/home/daytona/.codex/recovery/RECOVERY.md" in agents.content
    assert len(agents.content.splitlines()) < len(recovery.content.splitlines())
    assert recovery.content.startswith("# Working under this machine's security policy")
    assert (
        hashlib.sha256(recovery.content.encode("utf-8")).hexdigest()
        == bundle.body_sha256
    )


def test_grok_uses_grok_home_subdir() -> None:
    bundle = _render("high-nist", GrokAdapter())
    assert bundle is not None
    assert bundle.harness == "grok"
    paths = {f.remote_path for f in bundle.files}
    assert "/home/daytona/.grok/AGENTS.md" in paths
    assert "/home/daytona/.grok/recovery/RECOVERY.md" in paths
    agents = next(f for f in bundle.files if f.remote_path.endswith("AGENTS.md"))
    assert "/home/daytona/.grok/recovery/RECOVERY.md" in agents.content


def test_body_sha256_identical_across_harnesses() -> None:
    kwargs = dict(
        policy=resolve_policy("high-nist"),
        config=_cfg("high-nist"),
        infra_domains=_INFRA,
        agent_home=_AGENT_HOME,
    )
    claude = render_recovery_bundle(harness_adapter=ClaudeCodeAdapter(), **kwargs)
    codex = render_recovery_bundle(harness_adapter=CodexAdapter(), **kwargs)
    grok = render_recovery_bundle(harness_adapter=GrokAdapter(), **kwargs)
    terminus = render_recovery_bundle(harness_adapter=Terminus2Adapter(), **kwargs)
    assert claude is not None and codex is not None and grok is not None
    assert terminus is not None
    assert (
        claude.body_sha256
        == codex.body_sha256
        == grok.body_sha256
        == terminus.body_sha256
    )
    recovery = next(
        f for f in codex.files if f.remote_path.endswith("RECOVERY.md")
    )
    assert _skill(claude).content.endswith(recovery.content)


def test_body_is_task_blind_but_allowlist_is_not() -> None:
    a = _render("moderate-nist", ClaudeCodeAdapter(), task_id="build-cython-ext")
    b = _render(
        "moderate-nist", ClaudeCodeAdapter(), task_id="count-dataset-tokens"
    )
    assert a is not None and b is not None
    assert a.body_sha256 == b.body_sha256
    allow_a = next(
        f for f in a.files if f.remote_path == REMOTE_ALLOWED_DOMAINS_PATH
    )
    allow_b = next(
        f for f in b.files if f.remote_path == REMOTE_ALLOWED_DOMAINS_PATH
    )
    assert allow_a.content != allow_b.content


def test_bundle_facts_are_self_consistent() -> None:
    bundle = _render("high-nist", CodexAdapter())
    assert bundle is not None
    assert bundle.file_count == len(bundle.files)
    assert bundle.total_bytes == sum(
        len(f.content.encode("utf-8")) for f in bundle.files
    )
    assert bundle.body_bytes == len(
        next(
            f for f in bundle.files if f.remote_path.endswith("RECOVERY.md")
        ).content.encode("utf-8")
    )


def test_provenance_off_mode_has_no_bundle_facts() -> None:
    prov = build_recovery_bundle_provenance(bundle=None, knob="off")
    assert prov["mode"] == RECOVERY_BUNDLE_OFF
    assert prov["knob"] == "off"
    assert "body_sha256" not in prov
    json.dumps(prov)


def test_provenance_on_mode_carries_bundle_facts() -> None:
    bundle = _render("high-nist", ClaudeCodeAdapter())
    assert bundle is not None
    prov = build_recovery_bundle_provenance(bundle=bundle, knob="on")
    assert prov["mode"] == RECOVERY_BUNDLE_ON
    assert prov["knob"] == "on"
    assert prov["body_sha256"] == bundle.body_sha256
    assert prov["body_bytes"] == bundle.body_bytes
    assert prov["file_count"] == bundle.file_count
    assert prov["total_bytes"] == bundle.total_bytes
    assert prov["harness"] == "claude_code"
    assert prov["preset_name"] == "high-nist"
    json.dumps(prov)


def test_render_fails_closed_on_credential_shaped_writable_path() -> None:
    config = _cfg("high-nist")
    poisoned = replace(
        config,
        f3_home_carveout_subdirs=(
            *config.f3_home_carveout_subdirs,
            "ghp_0123456789abcdefghij0123456789",
        ),
    )
    with pytest.raises(ValueError, match="credential-shaped"):
        render_recovery_bundle(
            policy=resolve_policy("high-nist"),
            config=poisoned,
            harness_adapter=ClaudeCodeAdapter(),
            infra_domains=_INFRA,
            agent_home=_AGENT_HOME,
        )


def test_render_fails_closed_on_credential_shaped_domain() -> None:
    config = _cfg("moderate-nist", "build-cython-ext")
    poisoned = replace(
        config,
        egress_domain_allowlist=(
            *config.egress_domain_allowlist,
            "sk-or-abcdef123456",
        ),
    )
    with pytest.raises(ValueError, match="credential-shaped"):
        render_recovery_bundle(
            policy=resolve_policy("moderate-nist"),
            config=poisoned,
            harness_adapter=ClaudeCodeAdapter(),
            infra_domains=frozenset(),
            agent_home=_AGENT_HOME,
        )


def test_terminus_wrapper_is_single_native_skill_file() -> None:
    bundle = _render("high-nist", Terminus2Adapter())
    assert bundle is not None
    skill = _skill(bundle)
    assert skill.remote_path == (
        f"{_AGENT_HOME}/.terminus-2/skills/policy-error-recovery/SKILL.md"
    )
    wrapper_files = [
        f for f in bundle.files if not f.remote_path.endswith("allowed-domains.txt")
    ]
    assert wrapper_files == [skill]
    codex = _render("high-nist", CodexAdapter())
    assert bundle.body_sha256 == codex.body_sha256
    recovery = next(f for f in codex.files if f.remote_path.endswith("RECOVERY.md"))
    assert skill.content.endswith(recovery.content)


def test_terminus_skill_frontmatter_parses_with_harbor() -> None:
    pytest.importorskip("harbor")
    from harbor.agents.terminus_2 import Terminus2

    bundle = _render("high-nist", Terminus2Adapter())
    assert bundle is not None
    parsed = Terminus2._parse_skill_frontmatter(_skill(bundle).content)
    assert parsed is not None
    assert parsed["name"] == "policy-error-recovery"
    assert parsed["description"].strip()
