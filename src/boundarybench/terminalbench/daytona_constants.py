"""Shared constants for Terminal-Bench Daytona execution."""

import os
import re

from boundarybench.harness.claude_code import (  # noqa: F401
    DAYTONA_CLAUDE_BIN,
    ROOT_CLAUDE_BIN,
)
from boundarybench.harness.openrouter import OPENROUTER_BASE_URL  # noqa: F401

DEFAULT_OPENROUTER_MODEL = "deepseek/deepseek-v4-flash"

DEFAULT_AGENT_WORKDIR = "/app"
DEFAULT_HARDENING_ASSET_DIR = "/opt/boundarybench-hardening"
REMOTE_PROMPT_PATH = "/tmp/boundarybench-task-prompt.txt"
REMOTE_ALLOWED_DOMAINS_PATH = "/tmp/allowed-domains.txt"
REMOTE_TESTS_DIR = "/tests"

CLAUDE_BIN = DAYTONA_CLAUDE_BIN

DEFAULT_AGENT_TIMEOUT_SEC = 3600
DAYTONA_MAX_PARALLEL = 100

MAX_SESSION_ARTIFACT_FILES = 20
MAX_SESSION_ARTIFACT_FILE_BYTES = 4 * 1024 * 1024
MAX_SESSION_ARTIFACT_TOTAL_BYTES = 16 * 1024 * 1024

SANDBOX_AUTO_STOP_MIN = 90
SANDBOX_AUTO_STOP_BUFFER_SEC = 30 * 60
SANDBOX_AUTO_DELETE_MIN = 30

SANDBOX_MANAGED_BY_LABEL = "managed-by"
SANDBOX_NAMESPACE_LABEL = "boundarybench-sandbox-namespace"
DEFAULT_SANDBOX_MANAGED_BY_VALUE = "boundarybench-terminalbench"
SANDBOX_MANAGED_BY_ENV = "BOUNDARYBENCH_SANDBOX_MANAGED_BY"
_SANDBOX_MANAGED_BY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_ISOLATED_SANDBOX_NAMESPACE_RE = re.compile(
    r"^isolated-[a-z0-9]{1,24}-[0-9a-f]{8,32}$"
)


def _sandbox_managed_by_value() -> str:
    value = os.getenv(
        SANDBOX_MANAGED_BY_ENV,
        DEFAULT_SANDBOX_MANAGED_BY_VALUE,
    ).strip()
    if not _SANDBOX_MANAGED_BY_RE.fullmatch(value):
        raise ValueError(
            f"{SANDBOX_MANAGED_BY_ENV} must match "
            f"{_SANDBOX_MANAGED_BY_RE.pattern}, got {value!r}"
        )
    if (
        value != DEFAULT_SANDBOX_MANAGED_BY_VALUE
        and not _ISOLATED_SANDBOX_NAMESPACE_RE.fullmatch(value)
    ):
        raise ValueError(
            f"{SANDBOX_MANAGED_BY_ENV} must equal "
            f"{DEFAULT_SANDBOX_MANAGED_BY_VALUE!r} or match "
            f"{_ISOLATED_SANDBOX_NAMESPACE_RE.pattern}, got {value!r}"
        )
    return value


SANDBOX_MANAGED_BY_VALUE = _sandbox_managed_by_value()
SANDBOX_LABELS = {
    SANDBOX_MANAGED_BY_LABEL: SANDBOX_MANAGED_BY_VALUE,
    SANDBOX_NAMESPACE_LABEL: SANDBOX_MANAGED_BY_VALUE,
}
SANDBOX_RUN_ID_ENV = "BOUNDARYBENCH_RUN_ID"
SANDBOX_RUN_ID_LABEL = "boundarybench-run-id"
