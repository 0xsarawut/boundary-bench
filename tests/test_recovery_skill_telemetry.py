"""Recovery-skill invocation telemetry: per-harness counting of the tool-calls
that pull up the ``policy-error-recovery`` guidance.

The count is the leading indicator that the agent actually USED the
``recovery_bundle`` guidance rather than ignoring it. Fixtures are grounded in
REAL captured output, not invented: the Claude Code Skill-invocation envelope is
faithful to a captured claude stream-json run (CC 2.1.215 — ``name == "Skill"``,
invoked skill under ``input.skill``, plus the ``caller`` field), and the Codex
``command_execution`` items mirror the real shapes in ``test_harness_codex``.
"""

from __future__ import annotations

import json

from boundarybench.harness.claude_code import ClaudeCodeAdapter
from boundarybench.harness.codex import CodexAdapter
from boundarybench.harness.grok import GrokAdapter
from boundarybench.terminalbench.recovery_skill import (
    RECOVERY_DOC_FILE,
    RECOVERY_SKILL_FILE,
    RECOVERY_SKILL_NAME,
)

_SKILL_MD_PATH = (
    f"/home/daytona/.claude/skills/{RECOVERY_SKILL_NAME}/{RECOVERY_SKILL_FILE}"
)


def _real_skill_event(skill: str, args: str = "EACCES writing /etc/hosts") -> str:
    """A Claude Code Skill-invocation event in the REAL captured stream-json shape.

    Faithful to the empirically captured envelope (CC 2.1.215) at
    scratchpad/skillprobe/probe_out.jsonl line 10 — full assistant-message
    wrapper, ``name == "Skill"``, invoked skill under ``input.skill``,
    ``input.args`` the arg string, and the ``caller`` field — with only the
    probe skill swapped out. This is the shape the counter must match, not an
    invented one.
    """

    return json.dumps(
        {
            "type": "assistant",
            "message": {
                "model": "claude-fable-5",
                "id": "msg_011CdDiQtU1kkxDRN2aHmDvn",
                "type": "message",
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_01RT4WViYFLRMmbZ8WAneEM4",
                        "name": "Skill",
                        "input": {"skill": skill, "args": args},
                        "caller": {"type": "direct"},
                    }
                ],
                "stop_reason": None,
                "usage": {"input_tokens": 2, "output_tokens": 4},
            },
            "parent_tool_use_id": None,
            "session_id": "6547ee34-087a-4a10-b873-4f1e4687f3a3",
            "uuid": "5243aada-50df-4640-a4b3-77f82f95e086",
            "request_id": "req_011CdDiQrGJzCFyjt1DmTn5i",
        }
    )


def _real_tool_use_event(name: str, tool_input: dict) -> str:
    """A non-Skill Claude Code ``tool_use`` event (real assistant envelope)."""

    return json.dumps(
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "t1", "name": name, "input": tool_input}
                ],
            },
        }
    )


def _codex_command_item(command: str, *, completed: bool = True) -> str:
    """One Codex ``--json`` item-wrapped ``command_execution`` event."""

    return json.dumps(
        {
            "type": "item.completed" if completed else "item.started",
            "item": {
                "id": "i1",
                "type": "command_execution",
                "command": command,
                "status": "completed" if completed else "in_progress",
            },
        }
    )


class TestClaudeRecoverySkillCount:
    adapter = ClaudeCodeAdapter()

    def test_real_skill_invocation_naming_recovery_skill_counts(self):
        stdout = _real_skill_event(RECOVERY_SKILL_NAME)
        assert self.adapter.recovery_skill_invocation_count(stdout) == 1

    def test_real_skill_invocation_naming_other_skill_is_zero(self):
        stdout = _real_skill_event("some-other-skill")
        assert self.adapter.recovery_skill_invocation_count(stdout) == 0

    def test_defensive_skill_md_read_arm_counts(self):
        stdout = _real_tool_use_event("Read", {"file_path": _SKILL_MD_PATH})
        assert self.adapter.recovery_skill_invocation_count(stdout) == 1

    def test_skill_plus_defensive_read_sum(self):
        stdout = "\n".join(
            [
                _real_skill_event(RECOVERY_SKILL_NAME),
                _real_tool_use_event("Read", {"file_path": _SKILL_MD_PATH}),
            ]
        )
        assert self.adapter.recovery_skill_invocation_count(stdout) == 2

    def test_unrelated_tool_use_is_zero(self):
        stdout = "\n".join(
            [
                _real_skill_event("superpowers:brainstorming"),
                _real_tool_use_event("Read", {"file_path": "/etc/hosts"}),
                _real_tool_use_event("Bash", {"command": "ls -la"}),
            ]
        )
        assert self.adapter.recovery_skill_invocation_count(stdout) == 0

    def test_empty_stdout_is_zero(self):
        assert self.adapter.recovery_skill_invocation_count("") == 0


class TestCodexRecoverySkillCount:
    adapter = CodexAdapter()

    def test_command_reading_recovery_doc_counts_once(self):
        command = f"cat ~/.codex/recovery/{RECOVERY_DOC_FILE}"
        stdout = "\n".join(
            [
                _codex_command_item(command, completed=False),
                _codex_command_item(command),
            ]
        )
        assert self.adapter.recovery_skill_invocation_count(stdout) == 1

    def test_command_naming_skill_counts(self):
        stdout = _codex_command_item(f"ls ~/.codex/skills/{RECOVERY_SKILL_NAME}")
        assert self.adapter.recovery_skill_invocation_count(stdout) == 1

    def test_unrelated_command_is_zero(self):
        stdout = _codex_command_item("git status")
        assert self.adapter.recovery_skill_invocation_count(stdout) == 0

    def test_legacy_flat_exec_command_shape(self):
        stdout = json.dumps(
            {"type": "exec_command", "command": f"less {RECOVERY_DOC_FILE}"}
        )
        assert self.adapter.recovery_skill_invocation_count(stdout) == 1

    def test_empty_stdout_is_zero(self):
        assert self.adapter.recovery_skill_invocation_count("") == 0


class TestGrokRecoverySkillCount:
    def test_always_zero(self):
        adapter = GrokAdapter()
        stdout = json.dumps({"type": "result", "text": f"I read {RECOVERY_DOC_FILE}"})
        assert adapter.recovery_skill_invocation_count(stdout) == 0
        assert adapter.recovery_skill_invocation_count("") == 0


class TestConstantsReconcileWithRenderer:
    """The counter keys off ``RECOVERY_SKILL_NAME`` / the file basenames; the
    renderer must emit those exact strings or the count silently drifts to 0."""

    @staticmethod
    def _render(adapter):
        from boundarybench.daytona.policy_axes import (
            AXIS_PRESETS,
            build_daytona_config_from_axes,
        )
        from boundarybench.terminalbench.policies import resolve_policy
        from boundarybench.terminalbench.recovery_skill import (
            render_recovery_bundle,
        )

        return render_recovery_bundle(
            policy=resolve_policy("moderate-nist"),
            config=build_daytona_config_from_axes(
                AXIS_PRESETS["moderate-nist"], task_id="hello-world"
            ),
            harness_adapter=adapter,
            infra_domains=frozenset(),
            agent_home="/home/daytona",
        )

    def test_claude_skill_dir_and_frontmatter_match_constants(self):
        bundle = self._render(ClaudeCodeAdapter())
        skill = next(
            f for f in bundle.files if f.remote_path.endswith(RECOVERY_SKILL_FILE)
        )
        assert (
            f"/skills/{RECOVERY_SKILL_NAME}/{RECOVERY_SKILL_FILE}" in skill.remote_path
        )
        assert f"name: {RECOVERY_SKILL_NAME}\n" in skill.content

    def test_codex_recovery_doc_basename_matches_constant(self):
        bundle = self._render(CodexAdapter())
        recovery = next(
            f for f in bundle.files if f.remote_path.endswith(RECOVERY_DOC_FILE)
        )
        assert recovery.remote_path.endswith(f"/recovery/{RECOVERY_DOC_FILE}")
