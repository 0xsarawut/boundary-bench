#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import selectors
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit


DEFAULT_EVENT_LOG = "/tmp/boundarybench-policy-events.jsonl"
DEFAULT_ACCESS_LOG = "/tmp/boundarybench-proxy-access.jsonl"
BUFFER_SIZE = 65536


class DomainPolicy:
    def __init__(
        self,
        payload: dict[str, Any],
        event_log: str,
        access_log: str | None = None,
    ) -> None:
        self.allowlist = tuple(str(item).lower() for item in payload.get("allowlist", ()))
        self.denylist = tuple(str(item).lower() for item in payload.get("denylist", ()))
        self.default_action = str(payload.get("default_action") or "allow")
        self.cidr_allowlist = tuple(
            ipaddress.ip_network(str(item), strict=False)
            for item in payload.get("cidr_allowlist", ())
        )
        self.cidr_denylist = tuple(
            ipaddress.ip_network(str(item), strict=False)
            for item in payload.get("cidr_denylist", ())
        )
        self.cidr_default_action = str(payload.get("cidr_default_action") or "allow")
        self.event_log = event_log
        self.access_log = access_log
        self._allow_counts: dict[str, int] = {}
        self._allow_lock = threading.Lock()

    def decide(self, host: str, port: int) -> tuple[bool, str]:
        normalized = normalize_host(host)
        ip_decision = self._ip_literal_allowed(normalized)
        if ip_decision is not None:
            return ip_decision
        if normalized == "localhost" and any(
            ipaddress.ip_address("127.0.0.1") in network
            for network in self.cidr_allowlist
        ):
            return True, "loopback_allowlist"
        if port not in {80, 443}:
            return False, "port_not_allowed"
        if any(host_matches(pattern, normalized) for pattern in self.denylist):
            return False, "domain_denylist"
        if any(host_matches(pattern, normalized) for pattern in self.allowlist):
            return True, "domain_allowlist"
        if self.default_action == "deny":
            return False, "domain_default_deny"
        return True, "domain_default_allow"

    def connect(self, host: str, port: int, timeout: float = 10.0) -> socket.socket:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        denied_addresses: list[str] = []
        last_error: OSError | None = None
        for family, socktype, proto, _canonname, sockaddr in infos:
            ip = str(sockaddr[0])
            if not self._resolved_ip_allowed(ip):
                denied_addresses.append(ip)
                continue
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            try:
                sock.connect(sockaddr)
                sock.settimeout(None)
                return sock
            except OSError as exc:
                last_error = exc
                sock.close()
        if denied_addresses:
            raise PermissionError(
                "resolved address denied by CIDR policy: " + ", ".join(denied_addresses)
            )
        if last_error is not None:
            raise last_error
        raise OSError(f"no address found for {host}:{port}")

    def emit_block(self, host: str, reason: str) -> None:
        event = {
            "event_type": "policy_block",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "surface": "network_domain",
            "target": normalize_host(host),
            "reason": reason,
            "axis": "network",
            "observer": "proxy",
            "native_error": "403 Forbidden",
            **process_attribution("domain_proxy_process"),
        }
        try:
            with open(self.event_log, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
        except OSError:
            pass

    def record_allow(self, host: str, _port: int) -> None:
        """Roll up an allowed request per host into the access log.

        Best-effort telemetry: never raises. The whole access log is rewritten
        atomically from the in-memory per-host counter on each allowed request,
        so it holds exactly one ``policy_allow`` line per unique host.
        """

        if not self.access_log:
            return
        normalized = normalize_host(host)
        with self._allow_lock:
            self._allow_counts[normalized] = self._allow_counts.get(normalized, 0) + 1
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            payload = "".join(
                json.dumps(
                    {
                        "event_type": "policy_allow",
                        "timestamp": timestamp,
                        "surface": "network_domain",
                        "target": target,
                        "axis": "network",
                        "observer": "proxy",
                        "hit_count": count,
                    },
                    sort_keys=True,
                )
                + "\n"
                for target, count in sorted(self._allow_counts.items())
            )
            try:
                tmp_path = self.access_log + ".tmp"
                with open(tmp_path, "w", encoding="utf-8") as handle:
                    handle.write(payload)
                os.replace(tmp_path, self.access_log)
            except OSError:
                pass

    def _ip_literal_allowed(self, host: str) -> tuple[bool, str] | None:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None
        if any(ip in network for network in self.cidr_allowlist):
            return True, "cidr_allowlist"
        if any(ip in network for network in self.cidr_denylist):
            return False, "cidr_denylist"
        if self.cidr_default_action == "deny":
            return False, "cidr_default_deny"
        return True, "cidr_default_allow"

    def _resolved_ip_allowed(self, ip_value: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_value)
        except ValueError:
            return False
        if any(ip in network for network in self.cidr_allowlist):
            return True
        if any(ip in network for network in self.cidr_denylist):
            return False
        return True


class DomainProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    policy: DomainPolicy

    def do_CONNECT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        try:
            host, port = split_host_port(self.path, default_port=443)
        except ValueError:
            self.send_error(400, "invalid CONNECT target")
            return
        allowed, reason = self.policy.decide(host, port)
        if not allowed:
            self.policy.emit_block(host, reason)
            self._send_bare_forbidden()
            return
        try:
            upstream = self.policy.connect(host, port)
        except PermissionError as exc:
            self.policy.emit_block(host, str(exc))
            self._send_bare_forbidden()
            return
        except OSError as exc:
            self.send_error(502, str(exc))
            return
        self.policy.record_allow(host, port)
        self.send_response(200, "Connection Established")
        self.end_headers()
        tunnel(self.connection, upstream)

    def do_DELETE(self) -> None:  # noqa: N802
        self._proxy_http_request()

    def do_GET(self) -> None:  # noqa: N802
        self._proxy_http_request()

    def do_HEAD(self) -> None:  # noqa: N802
        self._proxy_http_request()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._proxy_http_request()

    def do_PATCH(self) -> None:  # noqa: N802
        self._proxy_http_request()

    def do_POST(self) -> None:  # noqa: N802
        self._proxy_http_request()

    def do_PUT(self) -> None:  # noqa: N802
        self._proxy_http_request()

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _send_bare_forbidden(self) -> None:
        self.send_response_only(403, "Forbidden")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def _proxy_http_request(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.scheme and parsed.netloc:
            host, port = split_host_port(
                parsed.netloc, default_port=443 if parsed.scheme == "https" else 80
            )
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
        else:
            host_header = self.headers.get("Host")
            if not host_header:
                self.send_error(400, "missing Host header")
                return
            host, port = split_host_port(host_header, default_port=80)
            path = self.path or "/"
        allowed, reason = self.policy.decide(host, port)
        if not allowed:
            self.policy.emit_block(host, reason)
            self._send_bare_forbidden()
            return
        try:
            upstream = self.policy.connect(host, port)
        except PermissionError as exc:
            self.policy.emit_block(host, str(exc))
            self._send_bare_forbidden()
            return
        except OSError as exc:
            self.send_error(502, str(exc))
            return
        self.policy.record_allow(host, port)
        with upstream:
            self._send_upstream_request(upstream, path)
            relay_one_way(upstream, self.connection)

    def _send_upstream_request(self, upstream: socket.socket, path: str) -> None:
        request = f"{self.command} {path} {self.request_version}\r\n"
        upstream.sendall(request.encode("ascii"))
        for key, value in self.headers.items():
            if key.lower() in {"proxy-connection", "connection"}:
                continue
            upstream.sendall(f"{key}: {value}\r\n".encode("latin-1"))
        upstream.sendall(b"Connection: close\r\n\r\n")
        length = int(self.headers.get("Content-Length") or "0")
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(BUFFER_SIZE, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            upstream.sendall(chunk)


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def normalize_host(value: str) -> str:
    host = value.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host[:-1] if host.endswith(".") else host


def split_host_port(value: str, *, default_port: int) -> tuple[str, int]:
    raw = value.strip()
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            raise ValueError("invalid IPv6 host")
        host = raw[1:end]
        rest = raw[end + 1 :]
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if ":" in raw and raw.count(":") == 1:
        host, port_text = raw.rsplit(":", 1)
        return host, int(port_text)
    return raw, default_port


def host_matches(pattern: str, host: str) -> bool:
    normalized = normalize_host(host)
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return normalized.endswith("." + suffix)
    return normalized == pattern


def process_attribution(scope: str) -> dict[str, Any]:
    return {
        "attribution_scope": scope,
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "uid": os.getuid() if hasattr(os, "getuid") else 0,
        "cwd": safe_getcwd(),
        "comm": proc_text("/proc/self/comm", default=Path(sys.argv[0]).name or "python"),
        "exe": safe_readlink("/proc/self/exe"),
        "cmdline": proc_cmdline(),
    }


def safe_getcwd() -> str:
    try:
        return os.getcwd()
    except OSError:
        return "unknown"


def proc_text(path: str, *, default: str) -> str:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return default
    return value or default


def safe_readlink(path: str) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return "unknown"


def proc_cmdline() -> str:
    try:
        raw = Path("/proc/self/cmdline").read_bytes()
    except OSError:
        return " ".join(sys.argv)
    parts = [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
    return " ".join(parts) if parts else " ".join(sys.argv)


def tunnel(client: socket.socket, upstream: socket.socket) -> None:
    with upstream:
        selector = selectors.DefaultSelector()
        selector.register(client, selectors.EVENT_READ, upstream)
        selector.register(upstream, selectors.EVENT_READ, client)
        while True:
            for key, _events in selector.select():
                source = key.fileobj
                target = key.data
                try:
                    data = source.recv(BUFFER_SIZE)
                except OSError:
                    return
                if not data:
                    return
                try:
                    target.sendall(data)
                except OSError:
                    return


def relay_one_way(source: socket.socket, target: socket.socket) -> None:
    while True:
        data = source.recv(BUFFER_SIZE)
        if not data:
            return
        target.sendall(data)


def load_policy(
    path: str, event_log: str, access_log: str | None = None
) -> DomainPolicy:
    with open(path, "r", encoding="utf-8") as handle:
        try:
            payload = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ValueError("domain egress policy config must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("domain egress policy config must be a JSON object")
    return DomainPolicy(payload, event_log, access_log)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--event-log", default=DEFAULT_EVENT_LOG)
    parser.add_argument("--access-log", default=DEFAULT_ACCESS_LOG)
    args = parser.parse_args()

    DomainProxyHandler.policy = load_policy(
        args.config, args.event_log, args.access_log
    )
    server = ReusableThreadingHTTPServer((args.host, args.port), DomainProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
