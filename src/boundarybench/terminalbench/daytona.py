from __future__ import annotations

import io
import json
import math
import os
import re
import shlex
import shutil
import tarfile
import tempfile
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from inspect_ai.dataset import Sample

from boundarybench.daytona.transport import (
    is_transient_daytona_transport_error,
)
from boundarybench.terminalbench.harbor import build_terminalbench_control_task
from boundarybench.terminalbench.task_config import (
    HarborVerifierEnvironmentMode,
    HarborVerifierEnvironmentResolution,
    HarborVerifierEnvironmentSource,
    resolve_harbor_verifier_environment,
    task_toml_agent_timeout,
)


VERIFIER_OBSERVATION_TESTS_UPLOADED_AFTER_AGENT = "tests_uploaded_after_agent"
VERIFIER_OBSERVATION_PROCESS_STARTED = "verifier_process_started"


@dataclass(frozen=True)
class TerminalBenchTaskBundle:
    """Harbor task data needed by the Daytona runner.

    This deliberately keeps Harbor as the task/verifier source of truth while
    avoiding Harbor's Docker/Compose sandbox as the runtime boundary.
    """

    sample_id: str
    input: str
    task_name: str
    task_dir: Path
    tests_dir: Path
    test_path: Path
    verifier_timeout_sec: int
    agent_timeout_sec: int | None = None
    verifier_env: dict[str, str] = field(default_factory=dict)
    verifier_user: str | None = None
    verifier_environment_mode: HarborVerifierEnvironmentMode | None = None
    verifier_environment_mode_source: HarborVerifierEnvironmentSource | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "task_name": self.task_name,
            "task_dir": str(self.task_dir),
            "tests_dir": str(self.tests_dir),
            "test_path": str(self.test_path),
            "verifier_timeout_sec": self.verifier_timeout_sec,
            "agent_timeout_sec": self.agent_timeout_sec,
            "verifier_env": dict(self.verifier_env),
            "verifier_user": self.verifier_user,
            "verifier_environment_mode": self.verifier_environment_mode,
            "verifier_environment_mode_source": self.verifier_environment_mode_source,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class DaytonaVerifierResult:
    value: float
    answer: str
    exit_code: int | None
    stdout: str
    stderr: str
    reward_payload: dict[str, Any] | None = None
    timed_out: bool = False
    verifier_identity: dict[str, Any] | None = None
    session_id: str | None = None

    def to_metadata(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "answer": self.answer,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "reward_payload": self.reward_payload,
            "verifier_identity": self.verifier_identity,
            "session_id": self.session_id,
            "timed_out": self.timed_out,
        }


@dataclass(frozen=True)
class _VerifierCommandResult:
    exit_code: int | None
    stdout: str
    timed_out: bool = False
    session_id: str | None = None


def validate_shared_root_verifier_admission(
    bundle: TerminalBenchTaskBundle,
) -> tuple[str, HarborVerifierEnvironmentSource | None]:
    """Fail closed unless the task supports our shared, root verifier lifecycle."""

    mode = getattr(bundle, "verifier_environment_mode", None)
    source = getattr(bundle, "verifier_environment_mode_source", None)
    if mode is None:
        raise RuntimeError(
            "verifier error: Harbor verifier environment mode is missing"
        )
    if mode == "separate":
        raise RuntimeError(
            "verifier error: Harbor verifier environment mode 'separate' is "
            "not supported by the Daytona runner"
        )
    if mode != "shared":
        raise RuntimeError(f"unsupported Harbor verifier environment mode: {mode!r}")
    verifier_user = getattr(bundle, "verifier_user", None)
    if verifier_user not in (None, "", "root", "0"):
        raise RuntimeError(
            "verifier error: hardened shared verification requires a root verifier, "
            f"got verifier_user={verifier_user!r}"
        )
    return mode, source


_VERIFIER_IDENTITY_MARKER = "__BOUNDARYBENCH_VERIFIER_IDENTITY__"
_VERIFIER_IDENTITY_RE = re.compile(
    rf"^{_VERIFIER_IDENTITY_MARKER} effective_uid=(\d+) effective_user=([^\s]+)$",
    re.MULTILINE,
)

DEFAULT_VERIFIER_MAX_ATTEMPTS = 3
MAX_VERIFIER_MAX_ATTEMPTS = 10
_VERIFIER_MAX_ATTEMPTS_ENV = "BOUNDARYBENCH_VERIFIER_MAX_ATTEMPTS"


def load_terminalbench_daytona_bundle(
    *,
    task_id: str | None,
    harbor_ref: str,
    overwrite_cache: bool = False,
) -> TerminalBenchTaskBundle:
    """Load exactly one Terminal-Bench task through Harbor without running Docker."""

    task = build_terminalbench_control_task(
        task_id=task_id,
        max_samples=1,
        ref=harbor_ref,
        sandbox_env_name="docker",
        overwrite_cache=overwrite_cache,
    )
    samples = list(task.dataset or [])
    if len(samples) != 1:
        raise ValueError(
            f"expected exactly one Terminal-Bench sample, got {len(samples)}"
        )
    return terminalbench_bundle_from_sample(samples[0])


def terminalbench_bundle_from_sample(sample: Sample) -> TerminalBenchTaskBundle:
    metadata = dict(sample.metadata or {})
    required = ("task_name", "task_dir", "tests_dir", "test_path", "harbor_config")
    missing = [key for key in required if not metadata.get(key)]
    if missing:
        raise ValueError(f"Harbor sample metadata missing required fields: {missing}")
    verifier_environment = _verifier_environment_from_metadata(metadata)
    return TerminalBenchTaskBundle(
        sample_id=str(sample.id),
        input=str(sample.input),
        task_name=str(metadata["task_name"]),
        task_dir=Path(str(metadata["task_dir"])),
        tests_dir=Path(str(metadata["tests_dir"])),
        test_path=Path(str(metadata["test_path"])),
        verifier_timeout_sec=int(metadata.get("verifier_timeout_sec") or 600),
        agent_timeout_sec=_agent_timeout_sec(metadata, Path(str(metadata["task_dir"]))),
        verifier_env={
            str(k): str(v) for k, v in dict(metadata.get("verifier_env") or {}).items()
        },
        verifier_user=str(metadata["verifier_user"])
        if metadata.get("verifier_user") is not None
        else None,
        verifier_environment_mode=verifier_environment.mode,
        verifier_environment_mode_source=verifier_environment.source,
        metadata=metadata,
    )


def _verifier_environment_from_metadata(
    metadata: dict[str, Any],
) -> HarborVerifierEnvironmentResolution:
    return resolve_harbor_verifier_environment(metadata["harbor_config"])


def _agent_timeout_sec(metadata: dict[str, Any], task_dir: Path) -> int | None:
    task_name = str(metadata.get("task_name") or "")
    if (task_dir / "task.toml").exists():
        return task_toml_agent_timeout(task_dir, task_name=task_name)
    for key in ("agent_timeout_sec", "max_agent_timeout_sec"):
        parsed = _optional_positive_int(metadata.get(key), field_name=key)
        if parsed is not None:
            return parsed
    return None


def _optional_positive_int(value: Any, *, field_name: str) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(float(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a positive number: {value!r}") from exc
    if parsed <= 0:
        raise ValueError(f"{field_name} must be a positive number: {value!r}")
    return parsed


_ADAPTED_VERIFIERS_DIR = (
    Path(__file__).resolve().parent / "adapted_verifiers"
)


def _adapted_tests_dir(
    bundle: TerminalBenchTaskBundle,
) -> tuple[Path, Callable[[], None]]:
    """Return the tests dir to upload, applying any in-repo verifier override.

    Tasks with no adapted verifier upload their pinned Harbor tests unchanged.
    Tasks with one at ``adapted_verifiers/<task>/`` get a merged temp dir
    (pinned tests + adapted files on top). Applies to EVERY preset, so an
    adapted verifier replaces the official one uniformly. Returns
    ``(dir, cleanup)``; the caller must invoke ``cleanup`` when done.
    """

    short_name = bundle.task_name.split("/")[-1]
    override = _ADAPTED_VERIFIERS_DIR / short_name
    if not override.is_dir():
        return bundle.tests_dir, (lambda: None)
    merged = Path(tempfile.mkdtemp(prefix="adapted-tests-"))
    shutil.copytree(bundle.tests_dir, merged, dirs_exist_ok=True)
    for src in sorted(override.rglob("*")):
        if src.is_file():
            dest = merged / src.relative_to(override)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
    return merged, (lambda: shutil.rmtree(merged, ignore_errors=True))


def upload_tests_dir_to_daytona(
    sandbox: Any,
    bundle: TerminalBenchTaskBundle,
    *,
    remote_tests_dir: str = "/tests",
    staging_dir: str | None = None,
) -> None:
    """Upload Harbor tests to Daytona via a tarball.

    The Daytona SDK supports file uploads consistently; directory upload support
    varies across versions. A tarball keeps the runner version-tolerant. Any
    in-repo adapted-verifier override for the task is merged in first (see
    ``_adapted_tests_dir``).
    """

    tests_dir, cleanup_tests = _adapted_tests_dir(bundle)
    try:
        if not tests_dir.exists():
            raise FileNotFoundError(
                f"Terminal-Bench tests_dir not found: {tests_dir}"
            )
        owns_staging_dir = staging_dir is None
        if staging_dir is None:
            staging_dir = _create_verifier_staging_dir(sandbox)
        try:
            with tempfile.NamedTemporaryFile(suffix=".tar.gz") as archive:
                archive.write(tar_directory_bytes(tests_dir))
                archive.flush()
                remote_archive = f"{staging_dir}/tests.tar.gz"
                _run_verifier_transport_operation(
                    sandbox,
                    lambda: sandbox.fs.upload_file(archive.name, remote_archive),
                    operation_name="test archive upload",
                )
                quoted_remote_tests_dir = shlex.quote(remote_tests_dir)
                quoted_remote_archive = shlex.quote(remote_archive)
                extraction_command = (
                    f"umask 077 && {_secure_staged_file_command(remote_archive)} && "
                    f"rm -rf -- {quoted_remote_tests_dir} && "
                    f"install -d -m 700 -o 0 -g 0 {quoted_remote_tests_dir} && "
                    f"tar -xzf {quoted_remote_archive} -C {quoted_remote_tests_dir} && "
                    f"chown -R 0:0 {quoted_remote_tests_dir} && "
                    f"chmod -R go-rwx {quoted_remote_tests_dir}"
                )
                result = _run_verifier_transport_operation(
                    sandbox,
                    lambda: sandbox.process.exec(extraction_command, timeout=60),
                    operation_name="test upload extraction",
                )
                if getattr(result, "exit_code", 1) != 0:
                    raise RuntimeError(
                        getattr(result, "result", "")
                        or "failed to validate and extract tests tarball"
                    )
        finally:
            if owns_staging_dir:
                _remove_verifier_staging_dir(sandbox, staging_dir)
    finally:
        cleanup_tests()


def run_daytona_harbor_verifier(
    sandbox: Any,
    bundle: TerminalBenchTaskBundle,
    *,
    remote_tests_dir: str = "/tests",
    remote_logs_dir: str = "/logs/verifier",
    remote_workdir: str = "/app",
    observation_callback: Callable[[str], None] | None = None,
) -> DaytonaVerifierResult:
    """Run Harbor's verifier contract inside Daytona and parse reward files.

    Daytona SDK process execution does not accept a separate ``user`` argument
    across supported versions. When Harbor supplies a verifier user, this runner
    drops privileges inside the command with ``setpriv`` instead. The caller
    supplies the task image's exact ``remote_workdir`` so verifier-relative paths
    match Harbor execution semantics. ``observation_callback`` is optional and
    backward-compatible: test upload is reported only after secure extraction
    completes, and process start only after an async launch is acknowledged (or
    after the legacy synchronous exec call returns a command result).
    """

    staging_dir = _create_verifier_staging_dir(sandbox)
    try:
        upload_tests_dir_to_daytona(
            sandbox,
            bundle,
            remote_tests_dir=remote_tests_dir,
            staging_dir=staging_dir,
        )
        if observation_callback is not None:
            observation_callback(VERIFIER_OBSERVATION_TESTS_UPLOADED_AFTER_AGENT)
        relative_test_path = bundle.test_path.relative_to(bundle.tests_dir)
        remote_test_path = f"{remote_tests_dir}/{relative_test_path}".replace("\\", "/")
        _reset_verifier_logs_dir(sandbox, remote_logs_dir)
        env = _with_git_safe_directory(
            {"HOME": "/root", "TEST_DIR": remote_tests_dir, **bundle.verifier_env}
        )
        command_result = _run_verifier_command_with_deadline(
            sandbox,
            command=_verifier_command(
                remote_test_path, bundle.verifier_user, remote_workdir
            ),
            timeout=bundle.verifier_timeout_sec,
            env=env,
            timeout_markers=(remote_test_path, remote_tests_dir, remote_logs_dir),
            staging_dir=staging_dir,
            on_process_started=(
                lambda: (
                    observation_callback(VERIFIER_OBSERVATION_PROCESS_STARTED)
                    if observation_callback is not None
                    else None
                )
            ),
        )
        verifier_identity = _parse_verifier_identity(command_result.stdout)
        if command_result.timed_out:
            stdout = (
                command_result.stdout
                + "\n[boundarybench] verifier timed out after "
                f"{bundle.verifier_timeout_sec}s; recording verifier_timeout"
            ).strip()
            return DaytonaVerifierResult(
                value=0.0,
                answer="ERROR",
                exit_code=command_result.exit_code,
                stdout=stdout,
                stderr="",
                reward_payload=None,
                timed_out=True,
                verifier_identity=verifier_identity,
                session_id=command_result.session_id,
            )
        reward_value, reward_payload = _read_reward(sandbox, remote_logs_dir)
        passed = reward_value > 0
        return DaytonaVerifierResult(
            value=reward_value,
            answer="PASS" if passed else "FAIL",
            exit_code=command_result.exit_code,
            stdout=command_result.stdout,
            stderr="",
            reward_payload=reward_payload,
            timed_out=False,
            verifier_identity=verifier_identity,
            session_id=command_result.session_id,
        )
    finally:
        _remove_verifier_staging_dir(sandbox, staging_dir)


def _create_verifier_staging_dir(sandbox: Any) -> str:
    staging_dir = f"/tmp/boundarybench-verifier-{uuid.uuid4().hex}"
    quoted_staging_dir = shlex.quote(staging_dir)
    result = sandbox.process.exec(
        f"umask 077 && mkdir -- {quoted_staging_dir} && "
        f"chmod 700 {quoted_staging_dir} && chown 0:0 {quoted_staging_dir}",
        timeout=30,
    )
    if getattr(result, "exit_code", 1) != 0:
        raise RuntimeError(
            getattr(result, "result", "")
            or "failed to create private verifier staging directory"
        )
    return staging_dir


def _secure_staged_file_command(remote_path: str) -> str:
    quoted_remote_path = shlex.quote(remote_path)
    return (
        f"test -f {quoted_remote_path} && test ! -L {quoted_remote_path} && "
        f'[ "$(stat -c %u -- {quoted_remote_path})" = "0" ] && '
        f"chmod 600 {quoted_remote_path}"
    )


def _remove_verifier_staging_dir(sandbox: Any, staging_dir: str) -> None:
    try:
        sandbox.process.exec(
            f"rm -rf -- {shlex.quote(staging_dir)}",
            timeout=30,
        )
    except Exception:
        pass


def _reset_verifier_logs_dir(sandbox: Any, remote_logs_dir: str) -> None:
    quoted_remote_logs_dir = shlex.quote(remote_logs_dir)
    result = sandbox.process.exec(
        f"mkdir -p /logs/agent && rm -rf -- {quoted_remote_logs_dir} && "
        f"install -d -m 700 -o 0 -g 0 {quoted_remote_logs_dir}",
        timeout=30,
    )
    if getattr(result, "exit_code", 1) != 0:
        raise RuntimeError(
            getattr(result, "result", "")
            or "failed to securely reset verifier logs directory"
        )


def _with_git_safe_directory(env: dict[str, str]) -> dict[str, str]:
    """Append verifier-only Git ownership trust without mutating caller env."""

    updated = dict(env)
    raw_count = updated.get("GIT_CONFIG_COUNT", "0")
    try:
        count = int(raw_count)
    except ValueError as exc:
        raise ValueError(
            f"verifier GIT_CONFIG_COUNT must be a non-negative integer: {raw_count!r}"
        ) from exc
    if count < 0:
        raise ValueError(
            f"verifier GIT_CONFIG_COUNT must be a non-negative integer: {raw_count!r}"
        )
    updated["GIT_CONFIG_COUNT"] = str(count + 1)
    updated[f"GIT_CONFIG_KEY_{count}"] = "safe.directory"
    updated[f"GIT_CONFIG_VALUE_{count}"] = "*"
    return updated


def _run_verifier_command_with_deadline(
    sandbox: Any,
    *,
    command: str,
    timeout: int,
    env: dict[str, str],
    timeout_markers: tuple[str, ...],
    staging_dir: str,
    on_process_started: Callable[[], None] | None = None,
) -> _VerifierCommandResult:
    process = sandbox.process
    if not hasattr(process, "create_session"):
        result = process.exec(command, timeout=timeout, env=env)
        if on_process_started is not None:
            on_process_started()
        return _VerifierCommandResult(
            exit_code=getattr(result, "exit_code", None),
            stdout=getattr(result, "result", "") or "",
        )

    from daytona_sdk.common.process import SessionExecuteRequest

    session_id = "ia-verifier-" + uuid.uuid4().hex[:12]
    env_remote = f"{staging_dir}/verifier-env.sh"
    setup = ""
    if env:
        lines = "".join(f"export {k}={shlex.quote(v)}\n" for k, v in env.items())
        fh = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False)
        try:
            fh.write(lines)
            fh.close()
            sandbox.fs.upload_file(fh.name, env_remote)
        finally:
            try:
                os.unlink(fh.name)
            except OSError:
                pass
        validation_result = process.exec(
            _secure_staged_file_command(env_remote), timeout=30
        )
        if getattr(validation_result, "exit_code", 1) != 0:
            raise RuntimeError(
                getattr(validation_result, "result", "")
                or "failed to validate verifier environment file"
            )
        setup = f"set -a; . {shlex.quote(env_remote)}; set +a; "

    exit_code: int | None = None
    cmd_id: str | None = None
    stdout = ""
    timed_out = False
    poll_attempt = 0
    max_poll_attempts = verifier_max_attempts()
    process.create_session(session_id)
    try:
        started = time.monotonic()
        deadline = started + timeout
        try:
            resp = process.execute_session_command(
                session_id,
                SessionExecuteRequest(command=setup + command, run_async=True),
                timeout=max(1, min(60, math.ceil(deadline - started))),
            )
        except Exception:
            if time.monotonic() < deadline:
                raise
            timed_out = True
        else:
            if on_process_started is not None:
                on_process_started()
            cmd_id = resp.cmd_id
            while True:
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                poll_attempt += 1
                try:
                    info = process.get_session_command(session_id, cmd_id)
                except Exception as exc:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    if (
                        poll_attempt >= max_poll_attempts
                        or not is_transient_daytona_transport_error(exc)
                    ):
                        raise
                    sandbox_live = _sandbox_is_live(
                        sandbox,
                        timeout_sec=max(1, min(30, math.ceil(remaining))),
                    )
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    if not sandbox_live:
                        raise
                    print(
                        "[terminalbench-daytona] WARN transient verifier poll error "
                        f"({poll_attempt}/{max_poll_attempts}): {exc!r}",
                        flush=True,
                    )
                    time.sleep(min(5, remaining))
                    continue
                poll_attempt = 0
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                if getattr(info, "exit_code", None) is not None:
                    exit_code = int(info.exit_code)
                    break
                time.sleep(min(5, remaining))
        if timed_out:
            _signal_verifier_process_tree(process, "-TERM", timeout_markers)
            time.sleep(5)
            process_still_running = True
            if cmd_id is not None:
                try:
                    info = process.get_session_command(session_id, cmd_id)
                    if getattr(info, "exit_code", None) is not None:
                        exit_code = int(info.exit_code)
                        process_still_running = False
                except Exception:
                    pass
            if process_still_running:
                _signal_verifier_process_tree(process, "-KILL", timeout_markers)
        if cmd_id is not None:
            try:
                logs = process.get_session_command_logs(session_id, cmd_id)
                stdout = (
                    getattr(logs, "stdout", None) or getattr(logs, "output", "") or ""
                )
            except Exception:
                stdout = ""
    finally:
        try:
            process.delete_session(session_id)
        except Exception:
            pass
    return _VerifierCommandResult(
        exit_code=exit_code,
        stdout=stdout,
        timed_out=timed_out,
        session_id=session_id,
    )


def verifier_max_attempts() -> int:
    raw = os.environ.get(_VERIFIER_MAX_ATTEMPTS_ENV)
    if raw is None:
        return DEFAULT_VERIFIER_MAX_ATTEMPTS
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"{_VERIFIER_MAX_ATTEMPTS_ENV} must be an integer between "
            f"1 and {MAX_VERIFIER_MAX_ATTEMPTS}"
        ) from exc
    if not 1 <= parsed <= MAX_VERIFIER_MAX_ATTEMPTS:
        raise ValueError(
            f"{_VERIFIER_MAX_ATTEMPTS_ENV} must be an integer between "
            f"1 and {MAX_VERIFIER_MAX_ATTEMPTS}"
        )
    return parsed


def _sandbox_is_live(sandbox: Any, *, timeout_sec: int = 30) -> bool:
    try:
        result = sandbox.process.exec("true", timeout=timeout_sec)
    except Exception:
        return False
    return getattr(result, "exit_code", 1) == 0


def _run_verifier_transport_operation(
    sandbox: Any,
    operation: Callable[[], Any],
    *,
    operation_name: str,
) -> Any:
    max_attempts = verifier_max_attempts()
    for attempt in range(1, max_attempts + 1):
        try:
            return operation()
        except Exception as exc:
            if (
                attempt >= max_attempts
                or not is_transient_daytona_transport_error(exc)
            ):
                raise
            if not _sandbox_is_live(sandbox):
                raise
            print(
                "[terminalbench-daytona] WARN transient verifier transport error "
                f"operation={operation_name} ({attempt}/{max_attempts}): {exc!r}",
                flush=True,
            )
            time.sleep(5)
    raise AssertionError("unreachable verifier transport retry state")


def _signal_verifier_process_tree(
    process: Any, signal: str, markers: tuple[str, ...]
) -> None:
    marker_lines = "\n".join(marker for marker in markers if marker)
    script = f"""
signal={shlex.quote(signal)}
pids=""
for p in /proc/[0-9]*; do
  pid="${{p#/proc/}}"
  cmdline="$(tr '\\0' ' ' < "$p/cmdline" 2>/dev/null || true)"
  while IFS= read -r marker; do
    [ -n "$marker" ] || continue
    case "$cmdline" in
      *"$marker"*) pids="$pids $pid"; break ;;
    esac
  done <<'EOF'
{marker_lines}
EOF
done
changed=1
while [ "$changed" = 1 ]; do
  changed=0
  for p in /proc/[0-9]*; do
    pid="${{p#/proc/}}"
    stat="$(cat "$p/stat" 2>/dev/null || true)"
    rest="${{stat##*) }}"
    ppid="$(printf '%s\\n' "$rest" | awk '{{print $2}}')"
    [ -n "$ppid" ] || continue
    case " $pids " in
      *" $ppid "*)
        case " $pids " in
          *" $pid "*) ;;
          *) pids="$pids $pid"; changed=1 ;;
        esac
        ;;
    esac
  done
done
for pid in $pids; do
  kill "$signal" "$pid" 2>/dev/null || true
done
"""
    try:
        process.exec(script, timeout=20)
    except Exception:
        pass


def parse_reward_content(
    *,
    reward_txt: str | None = None,
    reward_json: str | None = None,
) -> tuple[float, dict[str, Any] | None]:
    if reward_txt is not None:
        stripped_reward_txt = reward_txt.strip()
        if not stripped_reward_txt:
            return 0.0, None
        try:
            return float(stripped_reward_txt), None
        except ValueError as exc:
            final_line = next(
                (
                    line.strip()
                    for line in reversed(stripped_reward_txt.splitlines())
                    if line.strip()
                ),
                "",
            )
            try:
                return float(final_line), None
            except ValueError:
                raise exc
    if reward_json is not None and reward_json.strip():
        payload = json.loads(reward_json)
        if not isinstance(payload, dict) or not payload:
            raise ValueError("reward.json must contain a non-empty object")
        if "reward" in payload:
            return float(payload["reward"]), payload
        if len(payload) != 1:
            raise ValueError(
                "reward.json fallback must contain exactly one numeric key"
            )
        reward_value = next(iter(payload.values()))
        if isinstance(reward_value, bool) or not isinstance(reward_value, (int, float)):
            raise ValueError("reward.json fallback value must be numeric")
        return float(reward_value), payload
    raise FileNotFoundError("No reward.txt or reward.json content was provided")


def _read_reward(
    sandbox: Any, remote_logs_dir: str
) -> tuple[float, dict[str, Any] | None]:
    for path, kind in (
        (f"{remote_logs_dir}/reward.txt", "txt"),
        (f"{remote_logs_dir}/reward.json", "json"),
    ):
        result = sandbox.process.exec(f"cat {shlex.quote(path)}", timeout=10)
        if getattr(result, "exit_code", 1) != 0:
            continue
        content = getattr(result, "result", "") or ""
        if kind == "txt":
            return parse_reward_content(reward_txt=content)
        return parse_reward_content(reward_json=content)
    raise FileNotFoundError(f"No reward file found under {remote_logs_dir}")


def _verifier_command(
    remote_test_path: str, verifier_user: str | None, remote_workdir: str
) -> str:
    command = f"bash -l {shlex.quote(remote_test_path)}"
    command = f"cd {shlex.quote(remote_workdir)} && {command}"
    command = (
        f"printf '{_VERIFIER_IDENTITY_MARKER} "
        'effective_uid=%s effective_user=%s\\n\' "$(id -u)" "$(id -un)"; '
        f"{command}"
    )
    if not verifier_user:
        return command
    quoted_user = shlex.quote(verifier_user)
    return f"setpriv --reuid {quoted_user} --init-groups -- bash -lc {shlex.quote(command)}"


def _parse_verifier_identity(stdout: str) -> dict[str, Any] | None:
    match = _VERIFIER_IDENTITY_RE.search(stdout)
    if match is None:
        return None
    return {
        "effective_uid": int(match.group(1)),
        "effective_user": match.group(2),
    }


def tar_directory_bytes(root: Path) -> bytes:
    """Build a directory tarball without duplicate members."""

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path in sorted(root.rglob("*")):
            tar.add(path, arcname=path.relative_to(root), recursive=False)
    return buffer.getvalue()
