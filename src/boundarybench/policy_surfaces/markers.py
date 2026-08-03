from __future__ import annotations


POLICY_BLOCKED_OUTPUT_MARKERS = (
    "boundary_policy_block",
    "blocked by policy",
)

BROAD_BLOCKED_OUTPUT_MARKERS = (
    "blocked",
    "denied",
    "not allowed",
    "permission denied",
    "operation not permitted",
    "cannot create",
    "read-only file system",
    "input/output error",
    "no new privileges",
    "403 forbidden",
    "returned error: 403",
    "from proxy after connect",
    "blocked by policy",
    "timed out after",
    "connection timed out",
    "connection reset by peer",
    "connection refused",
    "not in the sudoers file",
    "failed to connect to bus",
    "cannot connect to the docker daemon",
    "agentsh: command failed",
    "permissionerror",
    "file not found",
    "no such file or directory",
)

BLOCKED_OUTPUT_MARKERS = POLICY_BLOCKED_OUTPUT_MARKERS + BROAD_BLOCKED_OUTPUT_MARKERS


def contains_policy_blocked_output_marker(output: str) -> bool:
    normalized = output.lower()
    return any(marker in normalized for marker in POLICY_BLOCKED_OUTPUT_MARKERS)


def contains_blocked_output_marker(output: str) -> bool:
    normalized = output.lower()
    return any(marker in normalized for marker in BLOCKED_OUTPUT_MARKERS)
