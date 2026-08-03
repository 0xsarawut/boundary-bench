"""Temporary first-party patches over Harbor's Terminus-2 runtime.

This module runs INSIDE the task sandbox: ``install.sh`` copies it next to the
rendered ``bridge.py`` runner, which imports it from its own directory. It is
not importable in the controller process (``harbor`` is a sandbox-only
dependency).

Patch inventory — keep this list exhaustive so removal stays tractable:

1. ``ResilientTmuxSession`` — bounded recovery when the task shell exits and
   tmux tears the session down mid-run.

   - Provenance: observed once in the 89-task Terminal-Bench campaign
     (task ``git-multibranch``): "tmux server exited unexpectedly" while the
     official verifier still passed. Harbor 0.13.1's ``TmuxSession.send_keys``
     raises and the run would be lost even though the task state was valid.
   - Behavior: at most ``_MAX_SESSION_RESTARTS`` (2) restarts; the initial
     pane log truncates as upstream does, restart output appends so the pane
     transcript keeps pre-crash history; a restart marker line is written to
     the pane log; an unexpected change to Harbor's start-command format fails
     explicitly rather than silently degrading.
   - Upstream-removal path: if a Harbor release makes ``TmuxSession`` recover
     dead sessions itself (or exposes a hook for it), drop this class, switch
     ``bridge.py`` back to ``TmuxSession``, and delete the corresponding
     restart-marker handling asserted in ``tests/test_harness_terminus_2.py``.
"""

from __future__ import annotations

from pathlib import Path

from harbor.agents.terminus_2.tmux_session import TmuxSession


class ResilientTmuxSession(TmuxSession):
    """Recover from a task shell exiting without discarding pane evidence."""

    _MAX_SESSION_RESTARTS = 2

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._restart_count = 0

    @property
    def _tmux_start_session(self) -> str:
        command = super()._tmux_start_session
        if self._restart_count == 0:
            return command

        redirection = "cat > "
        if redirection not in command:
            raise RuntimeError(
                "Harbor tmux start command no longer contains the expected "
                "pane-log redirection"
            )
        return command.replace(redirection, "cat >> ", 1)

    async def send_keys(
        self,
        keys: str | list[str],
        block: bool = False,
        min_timeout_sec: float = 0.0,
        max_timeout_sec: float = 180.0,
    ) -> None:
        try:
            await super().send_keys(
                keys,
                block=block,
                min_timeout_sec=min_timeout_sec,
                max_timeout_sec=max_timeout_sec,
            )
            return
        except RuntimeError as exc:
            if (
                "failed to send " not in str(exc)
                or self._restart_count >= self._MAX_SESSION_RESTARTS
                or await self.is_session_alive()
            ):
                raise

        self._restart_count += 1
        self._logger.warning(
            "Terminus-2 tmux session disappeared; restarting shell (%s/%s)",
            self._restart_count,
            self._MAX_SESSION_RESTARTS,
        )
        try:
            with Path(self._logging_path).open("a", encoding="utf-8") as handle:
                handle.write("\n[boundarybench: tmux session restarted]\n")
        except OSError:
            pass
        self._previous_buffer = None
        await self.start()
        await super().send_keys(
            keys,
            block=block,
            min_timeout_sec=min_timeout_sec,
            max_timeout_sec=max_timeout_sec,
        )
