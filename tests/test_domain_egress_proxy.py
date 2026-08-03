"""Tests for the domain-egress proxy's deny response and per-task allowlist.

Two things are pinned here:

1. **Bare 403.** A blocked CONNECT/HTTP request must return a bare
   ``403 Forbidden`` — the standard reason phrase, no custom reason, and NO
   body (``Content-Length: 0``). This is Claude-Code-web parity: a real proxy
   deny reveals nothing about a policy sandbox. The old
   ``send_error(403, "egress denied by domain policy")`` emitted a custom
   reason phrase AND a stock HTML body repeating it — both steering tells.
2. **Telemetry preserved.** Every deny still writes the ``policy_block`` JSONL
   event via ``DomainPolicy.emit_block`` — only the agent-visible text changed.
3. **Per-task allowlist** resolved by ``build_daytona_config_from_axes(preset,
   task_id)`` reaches the rendered proxy config JSON.

The proxy is a plain ``http.server`` handler, so the deny paths are driven both
against fake in-memory I/O (fast, deterministic) and end-to-end over a real
loopback socket (wire-level proof the agent sees exactly a bare 403).
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import io
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
from email.message import Message
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from boundarybench.daytona.hardening_assets import (
    render_domain_egress_proxy_config,
)
from boundarybench.daytona.policy_axes import (
    AXIS_PRESETS,
    Network,
    build_daytona_config_from_axes,
)

_OLD_POLICY_TEXT = b"egress denied by domain policy"


def _load_domain_proxy_module():
    path = files("boundarybench.daytona").joinpath(
        "scripts", "domain_egress_proxy.py"
    )
    spec = importlib.util.spec_from_file_location(
        "boundarybench_test_domain_egress_proxy", path
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


module = _load_domain_proxy_module()


def _deny_policy(event_log: str) -> Any:
    return module.DomainPolicy(
        {"allowlist": [], "denylist": [], "default_action": "deny"},
        event_log=event_log,
    )


def _make_handler(policy: Any, *, command: str, path: str) -> Any:
    """A DomainProxyHandler wired to fake in-memory I/O (no socket)."""
    handler = module.DomainProxyHandler.__new__(module.DomainProxyHandler)
    handler.policy = policy
    handler.command = command
    handler.path = path
    handler.request_version = "HTTP/1.1"
    handler.rfile = io.BytesIO(b"")
    handler.wfile = io.BytesIO()
    handler.connection = None
    handler.close_connection = False
    handler.headers = Message()
    return handler


def _assert_bare_403(response: bytes) -> None:
    assert response.startswith(b"HTTP/1.1 403 Forbidden\r\n")
    assert _OLD_POLICY_TEXT not in response
    assert b"Content-Length: 0" in response
    assert b"<html" not in response.lower()
    assert b"<body" not in response.lower()
    assert b"Error code" not in response
    assert b"Error response" not in response
    assert response.endswith(b"\r\n\r\n")


def test_send_bare_forbidden_writes_minimal_response(tmp_path) -> None:
    handler = _make_handler(
        _deny_policy(str(tmp_path / "events.jsonl")),
        command="CONNECT",
        path="x:443",
    )

    handler._send_bare_forbidden()

    assert handler.wfile.getvalue() == (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    assert handler.close_connection is True


def test_connect_deny_sends_bare_403_and_preserves_telemetry(tmp_path) -> None:
    event_log = tmp_path / "events.jsonl"
    handler = _make_handler(
        _deny_policy(str(event_log)),
        command="CONNECT",
        path="blocked.example.com:443",
    )

    handler.do_CONNECT()

    _assert_bare_403(handler.wfile.getvalue())
    event = json.loads(event_log.read_text(encoding="utf-8"))
    assert event["event_type"] == "policy_block"
    assert event["surface"] == "network_domain"
    assert event["target"] == "blocked.example.com"
    assert event["reason"] == "domain_default_deny"


def test_connect_resolved_ip_denial_sends_bare_403_without_leaking_reason(
    tmp_path,
) -> None:
    event_log = tmp_path / "events.jsonl"
    policy = module.DomainPolicy(
        {
            "allowlist": [],
            "default_action": "deny",
            "cidr_allowlist": ["127.0.0.0/8"],
            "cidr_default_action": "deny",
        },
        event_log=str(event_log),
    )

    def _raise(host: str, port: int, timeout: float = 10.0):
        raise PermissionError(
            "resolved address denied by CIDR policy: 10.0.0.1"
        )

    policy.connect = _raise
    handler = _make_handler(policy, command="CONNECT", path="127.0.0.1:443")

    handler.do_CONNECT()

    response = handler.wfile.getvalue()
    _assert_bare_403(response)
    assert b"CIDR policy" not in response
    event = json.loads(event_log.read_text(encoding="utf-8"))
    assert event["target"] == "127.0.0.1"
    assert event["reason"] == "resolved address denied by CIDR policy: 10.0.0.1"


def test_http_deny_sends_bare_403_and_preserves_telemetry(tmp_path) -> None:
    event_log = tmp_path / "events.jsonl"
    handler = _make_handler(
        _deny_policy(str(event_log)),
        command="GET",
        path="http://blocked.example.com/secret",
    )

    handler.do_GET()

    _assert_bare_403(handler.wfile.getvalue())
    event = json.loads(event_log.read_text(encoding="utf-8"))
    assert event["event_type"] == "policy_block"
    assert event["target"] == "blocked.example.com"
    assert event["reason"] == "domain_default_deny"


def test_http_resolved_ip_denial_sends_bare_403_without_leaking_reason(
    tmp_path,
) -> None:
    event_log = tmp_path / "events.jsonl"
    policy = module.DomainPolicy(
        {
            "allowlist": [],
            "default_action": "deny",
            "cidr_allowlist": ["127.0.0.0/8"],
            "cidr_default_action": "deny",
        },
        event_log=str(event_log),
    )

    def _raise(host: str, port: int, timeout: float = 10.0):
        raise PermissionError(
            "resolved address denied by CIDR policy: 10.0.0.1"
        )

    policy.connect = _raise
    handler = _make_handler(policy, command="GET", path="http://127.0.0.1/")

    handler.do_GET()

    response = handler.wfile.getvalue()
    _assert_bare_403(response)
    assert b"CIDR policy" not in response
    event = json.loads(event_log.read_text(encoding="utf-8"))
    assert event["target"] == "127.0.0.1"
    assert event["reason"] == "resolved address denied by CIDR policy: 10.0.0.1"


def test_allowed_connect_reaches_upstream_and_sends_no_403(tmp_path) -> None:
    policy = module.DomainPolicy(
        {"allowlist": ["api.openrouter.ai"], "default_action": "deny"},
        event_log=str(tmp_path / "events.jsonl"),
    )
    reached: dict[str, Any] = {}

    class _Reached(Exception):
        pass

    def _fake_connect(host: str, port: int, timeout: float = 10.0):
        reached["hostport"] = (host, port)
        raise _Reached()

    policy.connect = _fake_connect
    handler = _make_handler(
        policy, command="CONNECT", path="api.openrouter.ai:443"
    )

    with pytest.raises(_Reached):
        handler.do_CONNECT()

    assert reached["hostport"] == ("api.openrouter.ai", 443)
    assert b"403" not in handler.wfile.getvalue()


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"upstream-pong"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: Any) -> None:
        return


@contextlib.contextmanager
def _running(server):
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextlib.contextmanager
def _proxy_server(
    payload: dict[str, Any], event_log: str, access_log: str | None = None
):
    module.DomainProxyHandler.policy = module.DomainPolicy(
        payload, event_log, access_log=access_log
    )
    server = module.ReusableThreadingHTTPServer(
        ("127.0.0.1", 0), module.DomainProxyHandler
    )
    with _running(server):
        yield server


def _read_until(sock: socket.socket, marker: bytes, limit: int = 65536) -> bytes:
    data = b""
    sock.settimeout(5)
    with contextlib.suppress(socket.timeout):
        while marker not in data and len(data) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    return data


def _read_to_eof(sock: socket.socket, limit: int = 65536) -> bytes:
    data = b""
    sock.settimeout(5)
    with contextlib.suppress(socket.timeout):
        while len(data) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    return data


def test_integration_allowed_http_request_is_proxied_end_to_end(tmp_path) -> None:
    origin = HTTPServer(("127.0.0.1", 0), _OriginHandler)
    with _running(origin):
        origin_port = origin.server_address[1]
        payload = {
            "allowlist": [],
            "default_action": "deny",
            "cidr_allowlist": [],
            "cidr_default_action": "allow",
        }
        with _proxy_server(payload, str(tmp_path / "events.jsonl")) as proxy:
            with socket.create_connection(
                proxy.server_address, timeout=5
            ) as client:
                request = (
                    f"GET http://127.0.0.1:{origin_port}/ping HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{origin_port}\r\n"
                    f"\r\n"
                ).encode("ascii")
                client.sendall(request)
                data = _read_until(client, b"upstream-pong")

    assert b"200" in data
    assert b"upstream-pong" in data
    assert b"403" not in data


def test_integration_connect_deny_is_bare_403_on_the_wire(tmp_path) -> None:
    event_log = tmp_path / "events.jsonl"
    payload = {"allowlist": [], "denylist": [], "default_action": "deny"}
    with _proxy_server(payload, str(event_log)) as proxy:
        with socket.create_connection(proxy.server_address, timeout=5) as client:
            client.sendall(
                b"CONNECT blocked.example.com:443 HTTP/1.1\r\n"
                b"Host: blocked.example.com:443\r\n"
                b"\r\n"
            )
            data = _read_to_eof(client)

    _assert_bare_403(data)
    event = json.loads(event_log.read_text(encoding="utf-8").splitlines()[0])
    assert event["event_type"] == "policy_block"
    assert event["target"] == "blocked.example.com"


def test_proxy_keeps_enforcing_after_asset_directory_is_removed(tmp_path) -> None:
    asset_dir = tmp_path / "hardening-assets"
    asset_dir.mkdir()
    proxy_source = asset_dir / "domain_egress_proxy.py"
    shutil.copyfile(
        files("boundarybench.daytona").joinpath(
            "scripts", "domain_egress_proxy.py"
        ),
        proxy_source,
    )
    config_path = asset_dir / "domain_egress_policy.json"
    config_path.write_text(
        json.dumps(
            {
                "allowlist": [],
                "default_action": "deny",
                "cidr_allowlist": ["127.0.0.0/8"],
                "cidr_default_action": "deny",
            }
        ),
        encoding="utf-8",
    )
    event_log = tmp_path / "events.jsonl"
    access_log = tmp_path / "access.jsonl"

    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        proxy_port = port_socket.getsockname()[1]

    origin = HTTPServer(("127.0.0.1", 0), _OriginHandler)
    with _running(origin):
        origin_port = origin.server_address[1]
        process = subprocess.Popen(
            [
                sys.executable,
                str(proxy_source),
                "--config",
                str(config_path),
                "--host",
                "127.0.0.1",
                "--port",
                str(proxy_port),
                "--event-log",
                str(event_log),
                "--access-log",
                str(access_log),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    pytest.fail("domain egress proxy exited before becoming ready")
                try:
                    with socket.create_connection(
                        ("127.0.0.1", proxy_port), timeout=0.1
                    ):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        pytest.fail("domain egress proxy did not become ready")
                    time.sleep(0.02)

            shutil.rmtree(asset_dir)
            assert not asset_dir.exists()
            assert process.poll() is None

            with socket.create_connection(
                ("127.0.0.1", proxy_port), timeout=5
            ) as client:
                client.sendall(
                    (
                        f"GET http://127.0.0.1:{origin_port}/ping HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{origin_port}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii")
                )
                allowed_response = _read_to_eof(client)

            assert b"200" in allowed_response
            assert b"upstream-pong" in allowed_response

            with socket.create_connection(
                ("127.0.0.1", proxy_port), timeout=5
            ) as client:
                client.sendall(
                    b"CONNECT blocked.example.com:443 HTTP/1.1\r\n"
                    b"Host: blocked.example.com:443\r\n\r\n"
                )
                blocked_response = _read_to_eof(client)

            _assert_bare_403(blocked_response)
            events = [
                json.loads(line)
                for line in event_log.read_text(encoding="utf-8").splitlines()
            ]
            assert any(
                event["event_type"] == "policy_block"
                and event["target"] == "blocked.example.com"
                for event in events
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def test_emit_block_carries_axis_observer_and_native_error(tmp_path) -> None:
    event_log = tmp_path / "events.jsonl"
    policy = _deny_policy(str(event_log))

    policy.emit_block("blocked.example.com", "domain_default_deny")

    event = json.loads(event_log.read_text(encoding="utf-8").splitlines()[0])
    assert event["event_type"] == "policy_block"
    assert event["surface"] == "network_domain"
    assert event["target"] == "blocked.example.com"
    assert event["reason"] == "domain_default_deny"
    assert event["axis"] == "network"
    assert event["observer"] == "proxy"
    assert event["native_error"] == "403 Forbidden"


def test_record_allow_rolls_up_per_host_in_access_log(tmp_path) -> None:
    access_log = tmp_path / "access.jsonl"
    policy = module.DomainPolicy(
        {"allowlist": ["api.openrouter.ai"], "default_action": "deny"},
        event_log=str(tmp_path / "events.jsonl"),
        access_log=str(access_log),
    )

    policy.record_allow("api.openrouter.ai", 443)
    policy.record_allow("api.openrouter.ai", 443)
    policy.record_allow("registry.npmjs.org", 443)

    lines = [
        line
        for line in access_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 2
    events = {json.loads(line)["target"]: json.loads(line) for line in lines}
    assert events["api.openrouter.ai"]["hit_count"] == 2
    assert events["registry.npmjs.org"]["hit_count"] == 1
    for event in events.values():
        assert event["event_type"] == "policy_allow"
        assert event["surface"] == "network_domain"
        assert event["axis"] == "network"
        assert event["observer"] == "proxy"


def test_record_allow_is_noop_without_access_log(tmp_path) -> None:
    policy = _deny_policy(str(tmp_path / "events.jsonl"))
    policy.record_allow("api.openrouter.ai", 443)
    assert list(tmp_path.iterdir()) == []


def test_integration_allowed_requests_roll_up_in_access_log(tmp_path) -> None:
    origin = HTTPServer(("127.0.0.1", 0), _OriginHandler)
    with _running(origin):
        origin_port = origin.server_address[1]
        payload = {
            "allowlist": [],
            "default_action": "deny",
            "cidr_allowlist": [],
            "cidr_default_action": "allow",
        }
        access_log = tmp_path / "access.jsonl"
        with _proxy_server(
            payload, str(tmp_path / "events.jsonl"), access_log=str(access_log)
        ) as proxy:
            for _ in range(2):
                with socket.create_connection(
                    proxy.server_address, timeout=5
                ) as client:
                    request = (
                        f"GET http://127.0.0.1:{origin_port}/ping HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{origin_port}\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    ).encode("ascii")
                    client.sendall(request)
                    _read_until(client, b"upstream-pong")

    lines = [
        line
        for line in access_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["event_type"] == "policy_allow"
    assert event["target"] == "127.0.0.1"
    assert event["hit_count"] == 2
    assert event["observer"] == "proxy"


def test_per_task_allowlist_reaches_rendered_proxy_config() -> None:
    expected_path = (
        Path(__file__).parent / "fixtures" / "task_egress_allowlists_expected.json"
    )
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    template = AXIS_PRESETS["moderate-nist"]

    for network in (Network.N1, Network.N2, Network.N3, Network.N4):
        preset = dataclasses.replace(
            template,
            name=f"synthetic-{network.value.lower()}",
            tuple_id=f"{network.value.lower()}-f2-p1",
            network=network,
        )
        for task_id, domains in expected.items():
            rendered = json.loads(
                render_domain_egress_proxy_config(
                    build_daytona_config_from_axes(preset, task_id=task_id)
                )
            )
            assert set(domains).issubset(set(rendered["allowlist"])), (
                network.value,
                task_id,
            )
