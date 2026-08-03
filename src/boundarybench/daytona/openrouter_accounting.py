"""Launch + read-back for the in-sandbox OpenRouter accounting proxy.

The proxy (``scripts/openrouter_accounting_proxy.py``) is started during sandbox
provisioning — before the agent runs and regardless of whether policy hardening
is installed — so every agent-exec path (hardened, unhardened, and the split
agent/clean-verifier flow) records OpenRouter's native charged cost. It is
launched by the controller as root, outside the agent's hardening boundary,
exactly like the domain egress proxy, so it can reach ``openrouter.ai`` directly
even when the agent's own egress is restricted.

After the agent phase the harness reads the accounting log back with
``read_openrouter_accounting`` and attaches a ``ModelUsage`` carrying the native
cost + native token counts.
"""

from __future__ import annotations

import base64
import json
import shlex
from typing import Any

from boundarybench.daytona.script_assets import read_daytona_script
from boundarybench.harness.openrouter import (
    ACCOUNTING_PROXY_HOST,
    ACCOUNTING_PROXY_PORT,
    OPENROUTER_ORIGIN,
)

_PROXY_SCRIPT_NAME = "openrouter_accounting_proxy.py"
REMOTE_PROXY_SCRIPT_PATH = "/tmp/boundarybench-openrouter-accounting-proxy.py"
OPENROUTER_ACCOUNTING_LOG = "/tmp/boundarybench-openrouter-accounting.jsonl"
OPENROUTER_ACCOUNTING_PROXY_LOG = "/tmp/boundarybench-openrouter-accounting-proxy.log"


_REQUEST_EFFORT_LEVELS = frozenset(
    {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
)


def start_openrouter_accounting_proxy(
    sandbox: Any, *, effort_level: str = "high"
) -> None:
    """Upload + launch the accounting proxy in the sandbox (best-effort-fatal).

    Raises ``RuntimeError`` if the proxy does not come up: the agent's OpenRouter
    base URL points at this loopback port, so a dead proxy means the agent cannot
    reach OpenRouter at all — we want to fail provisioning loudly, not silently
    strand the run.

    ``effort_level`` is forced onto every upstream inference request by the
    proxy, so auxiliary requests the harness makes internally use the same
    operator-selected effort as the visible agent loop.
    """

    if effort_level not in _REQUEST_EFFORT_LEVELS:
        raise ValueError(f"unsupported effort level: {effort_level!r}")
    script_text = read_daytona_script(_PROXY_SCRIPT_NAME)
    encoded = base64.b64encode(script_text.encode("utf-8")).decode("ascii")
    write_command = (
        f"base64 -d > {shlex.quote(REMOTE_PROXY_SCRIPT_PATH)} <<'ACCT_PROXY_EOF'\n"
        f"{encoded}\n"
        "ACCT_PROXY_EOF"
    )
    write_result = sandbox.process.exec(write_command, timeout=60)
    if getattr(write_result, "exit_code", None) not in (0, None):
        output = getattr(write_result, "result", "") or ""
        raise RuntimeError(f"failed to write OpenRouter accounting proxy: {output}")

    readiness_code = (
        "import socket; "
        f"sock = socket.create_connection(({ACCOUNTING_PROXY_HOST!r}, "
        f"{ACCOUNTING_PROXY_PORT}), timeout=0.2); "
        "sock.close()"
    )
    launch_command = (
        f"rm -f {shlex.quote(OPENROUTER_ACCOUNTING_PROXY_LOG)} "
        f"{shlex.quote(OPENROUTER_ACCOUNTING_LOG)}; "
        f"nohup python3 {shlex.quote(REMOTE_PROXY_SCRIPT_PATH)} "
        f"--host {shlex.quote(ACCOUNTING_PROXY_HOST)} "
        f"--port {ACCOUNTING_PROXY_PORT} "
        f"--upstream {shlex.quote(OPENROUTER_ORIGIN)} "
        f"--accounting-log {shlex.quote(OPENROUTER_ACCOUNTING_LOG)} "
        f"--effort-level {shlex.quote(effort_level)} "
        f">{shlex.quote(OPENROUTER_ACCOUNTING_PROXY_LOG)} 2>&1 & "
        "pid=$!; ready=0; attempt=0; "
        'while [ "$attempt" -lt 50 ]; do '
        f"if ! kill -0 \"$pid\" 2>/dev/null; then "
        f"cat {shlex.quote(OPENROUTER_ACCOUNTING_PROXY_LOG)} >&2 || true; exit 1; fi; "
        f"if python3 -c {shlex.quote(readiness_code)} >/dev/null 2>&1; then "
        "ready=1; break; fi; "
        "attempt=$((attempt + 1)); sleep 0.1; done; "
        'if [ "$ready" -ne 1 ]; then '
        f"cat {shlex.quote(OPENROUTER_ACCOUNTING_PROXY_LOG)} >&2 || true; "
        'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; exit 1; fi; '
        f"rm -f {shlex.quote(REMOTE_PROXY_SCRIPT_PATH)} "
        f"{shlex.quote(OPENROUTER_ACCOUNTING_PROXY_LOG)}"
    )
    launch_result = sandbox.process.exec(launch_command, timeout=60)
    exit_code = getattr(launch_result, "exit_code", None)
    if exit_code not in (0, None):
        output = (
            getattr(launch_result, "result", "")
            or getattr(launch_result, "stderr", "")
            or ""
        )
        raise RuntimeError(f"failed to start OpenRouter accounting proxy: {output}")


def summarize_accounting(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Sum per-response accounting records into one run-level usage summary.

    ``cost`` is the sum of the native per-response costs; ``cost_complete`` is
    True only when every record carried a cost (so a partial capture can be
    surfaced rather than silently under-reported). Token totals follow the
    OpenAI/OpenRouter convention where ``input_tokens`` already includes any
    cached prompt tokens, so ``total_tokens = input + output`` (cache counts are
    reported separately, not re-added).
    """

    input_tokens = output_tokens = cache_read = cache_write = 0
    cost_total = 0.0
    cost_seen = False
    cost_complete = True
    for record in records:
        input_tokens += int(record.get("input_tokens") or 0)
        output_tokens += int(record.get("output_tokens") or 0)
        cache_read += int(record.get("cache_read_tokens") or 0)
        cache_write += int(record.get("cache_write_tokens") or 0)
        cost = record.get("cost")
        if isinstance(cost, (int, float)) and not isinstance(cost, bool):
            cost_total += float(cost)
            cost_seen = True
        else:
            cost_complete = False
    return {
        "records": len(records),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_tokens": cache_read,
        "cache_write_tokens": cache_write,
        "total_tokens": input_tokens + output_tokens,
        "cost": cost_total if cost_seen else None,
        "cost_complete": cost_complete and cost_seen,
    }


def read_openrouter_accounting(sandbox: Any) -> dict[str, Any] | None:
    """Read + summarize the accounting log from the sandbox, or None if empty.

    Best-effort: any read/parse failure yields None so cost accounting never
    breaks a task result.
    """

    try:
        result = sandbox.process.exec(
            f"cat {shlex.quote(OPENROUTER_ACCOUNTING_LOG)} 2>/dev/null || true",
            timeout=15,
        )
    except Exception:  # noqa: BLE001 - accounting is best-effort
        return None
    output = getattr(result, "result", "") or ""
    records: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    if not records:
        return None
    return summarize_accounting(records)
