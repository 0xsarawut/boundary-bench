from __future__ import annotations

import asyncio
from importlib.resources import files
import re
from typing import Any

from inspect_ai.solver import TaskState


_DOCKER_CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


async def _lift_hardening_for_verifier(state: TaskState) -> dict[str, Any]:
    if not _hardening_agent_started(state):
        return {}

    from inspect_ai.util import sandbox

    active_sandbox = sandbox()
    metadata: dict[str, Any] = {
        "status": "running",
        "lifted": [],
        "not_liftable": [],
        "errors": [],
    }

    script = (
        files("boundarybench.enforcement")
        .joinpath("scripts", "lift_hardening_for_verifier.sh")
        .read_text(encoding="utf-8")
    )
    try:
        result = await active_sandbox.exec(["bash", "-s"], input=script, user="root")
    except Exception as exc:
        metadata["errors"].append(
            {
                "operation": "in_container_lift",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        )
    else:
        if result.returncode == 0:
            metadata["lifted"].extend(
                [
                    "command_shims",
                    "agent_workspace_permissions",
                    "verifier_paths",
                    "fixture_permissions",
                ]
            )
        else:
            metadata["errors"].append(
                {
                    "operation": "in_container_lift",
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            )

    try:
        connection = await active_sandbox.connection(user="root")
        container = getattr(connection, "container", None)
    except Exception as exc:
        metadata["errors"].append(
            {
                "operation": "sandbox_connection",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        )
        container = None
    if container:
        try:
            network_result = await _connect_docker_bridge(
                container,
                timeout=30,
            )
        except Exception as exc:
            metadata["errors"].append(
                {
                    "operation": "docker_network_connect_bridge",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )
            metadata["not_liftable"].append("docker_network_mode")
        else:
            already_connected = "already exists" in network_result["stderr"].lower()
            if network_result["returncode"] == 0 or already_connected:
                metadata["lifted"].append("docker_bridge_network")
                metadata["network_reconnect"] = {
                    "container": container,
                    "network": "bridge",
                    "already_connected": already_connected,
                }
            else:
                metadata["errors"].append(
                    {
                        "operation": "docker_network_connect_bridge",
                        **network_result,
                    }
                )
                metadata["not_liftable"].append("docker_network_mode")
    else:
        metadata["not_liftable"].append("docker_network_mode")

    metadata["not_liftable"].append("dropped_linux_capabilities")
    metadata["status"] = "pass" if not metadata["errors"] else "partial"
    return metadata


async def _connect_docker_bridge(container: str, *, timeout: int) -> dict[str, Any]:
    if not _DOCKER_CONTAINER_NAME_RE.fullmatch(container):
        raise ValueError(f"unsupported docker container identifier: {container!r}")

    cmd = ["docker", "network", "connect", "bridge", container]
    process = await asyncio.create_subprocess_exec(
        "docker",
        "network",
        "connect",
        "bridge",
        container,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    return await _communicate_host_process(process, cmd, timeout=timeout)


async def _communicate_host_process(
    process: asyncio.subprocess.Process, cmd: list[str], *, timeout: int
) -> dict[str, Any]:
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        stdout, stderr = await process.communicate()
        return {
            "cmd": cmd,
            "returncode": 124,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "timeout": timeout,
        }
    return {
        "cmd": cmd,
        "returncode": process.returncode,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }


def _hardening_agent_started(state: TaskState) -> bool:
    metadata = dict(getattr(state, "metadata", {}) or {})
    hardening = dict(metadata.get("hardening", {}) or {})
    return hardening.get("agent_started") is True
