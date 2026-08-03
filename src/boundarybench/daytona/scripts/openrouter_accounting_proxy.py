#!/usr/bin/env python3
"""In-sandbox OpenRouter accounting proxy.

The agent CLIs run inside the Daytona sandbox and call OpenRouter, but none of
them report OpenRouter's *actual* charged cost in their transcripts. This is a
path-preserving reverse proxy the agent's OpenRouter base_url points at
(``http://127.0.0.1:<port>``). It injects ``usage: {"include": true}`` into JSON
request bodies (so OpenRouter returns the real ``usage.cost`` + native tokens on
the ``/chat/completions``, ``/responses`` and ``/v1/messages`` routes, streaming
or not), relays the response back to the agent unchanged, and records each
response's normalized usage as one JSON line the harness reads back afterward.

Runs as root outside the agent's hardening boundary (like
``domain_egress_proxy.py``), so it reaches ``openrouter.ai`` even under egress
restriction. Best-effort: a failure to parse/record usage must never disturb the
proxied request. Standard library only — runs under the sandbox's ``python3``.
"""

from __future__ import annotations

import argparse
import http.client
import json
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

DEFAULT_ACCOUNTING_LOG = "/tmp/boundarybench-openrouter-accounting.jsonl"
DEFAULT_UPSTREAM = "https://openrouter.ai"
UPSTREAM_TIMEOUT_SEC = 600

_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "content-encoding",
    }
)


_ACCOUNTING_ROUTE_SUFFIXES = ("/chat/completions", "/responses", "/messages")

_ORIGINAL_PROVIDER_SLUGS = {
    "amazon": "amazon-bedrock",
    "anthropic": "anthropic",
    "cohere": "cohere",
    "deepseek": "deepseek",
    "google": "google-ai-studio",
    "mistralai": "mistral",
    "nvidia": "nvidia",
    "openai": "openai",
    "perplexity": "perplexity",
    "qwen": "alibaba",
    "x-ai": "xai",
}

_PROVIDER_LOCK_EXEMPT_MODELS = frozenset({"deepseek/deepseek-v4-flash"})

_CLAUDE_FABLE_MODEL = "anthropic/claude-fable-5"
_CLAUDE_FABLE_FALLBACK_MODEL = "anthropic/claude-opus-4.8"


class FirstPartyRoutingError(ValueError):
    """The request cannot be proven to use only a creator-operated endpoint."""


def _is_accounting_route(path: str) -> bool:
    route = urlsplit(path).path.rstrip("/")
    return any(route.endswith(suffix) for suffix in _ACCOUNTING_ROUTE_SUFFIXES)


def _normalized_model_id(model: str) -> str:
    normalized = model.strip().removeprefix("~")
    if normalized.startswith("openrouter/"):
        normalized = normalized.removeprefix("openrouter/")
    return normalized


def _original_provider_slug(model: str) -> str | None:
    """Map an OpenRouter model id to its creator-operated provider slug."""

    normalized = _normalized_model_id(model)
    namespace, separator, _ = normalized.partition("/")
    if not separator or not namespace:
        return None
    return _ORIGINAL_PROVIDER_SLUGS.get(namespace)


def _num(value: object) -> float | int | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _normalize_usage(usage: dict) -> dict | None:
    """Map an OpenRouter usage object (OpenAI- or Anthropic-shaped) to our record.

    Returns ``None`` when the object carries neither a cost nor any token count,
    so purely-structural usage stubs are ignored.
    """

    if not isinstance(usage, dict):
        return None
    prompt_details = usage.get("prompt_tokens_details")
    input_details = usage.get("input_tokens_details")
    prompt_details = prompt_details if isinstance(prompt_details, dict) else {}
    input_details = input_details if isinstance(input_details, dict) else {}

    input_tokens = usage.get("prompt_tokens")
    if input_tokens is None:
        input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("completion_tokens")
    if output_tokens is None:
        output_tokens = usage.get("output_tokens")

    cache_read = prompt_details.get("cached_tokens")
    if cache_read is None:
        cache_read = input_details.get("cached_tokens")
    if cache_read is None:
        cache_read = usage.get("cache_read_input_tokens")
    cache_write = prompt_details.get("cache_write_tokens")
    if cache_write is None:
        cache_write = usage.get("cache_creation_input_tokens")

    cost = _num(usage.get("cost"))
    record = {
        "cost": cost,
        "input_tokens": int(_num(input_tokens) or 0),
        "output_tokens": int(_num(output_tokens) or 0),
        "cache_read_tokens": int(_num(cache_read) or 0),
        "cache_write_tokens": int(_num(cache_write) or 0),
    }
    if cost is None and not any(
        record[key]
        for key in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens")
    ):
        return None
    return record


def _merge_usage(into: dict, obj: dict) -> None:
    """Shallow-merge a usage dict, last non-null value wins.

    Anthropic streaming splits usage across events (``message_start`` carries
    input tokens, ``message_delta`` carries output tokens + cost), so we merge
    every usage object seen in a stream into one before normalizing.
    """

    for key, value in obj.items():
        if value is not None:
            into[key] = value


def _usage_from_obj(obj: object) -> dict | None:
    """Locate the usage object across route shapes.

    OpenAI ``/chat/completions`` and Anthropic ``/v1/messages`` put ``usage`` at
    the top level; the ``/responses`` route (streaming and not) nests it under
    ``response.usage`` (e.g. inside the ``response.completed`` event); Anthropic
    streaming's ``message_start`` nests input-token usage under ``message.usage``.
    """

    if not isinstance(obj, dict):
        return None
    usage = obj.get("usage")
    if isinstance(usage, dict):
        return usage
    for wrapper in ("response", "message"):
        nested = obj.get(wrapper)
        if isinstance(nested, dict) and isinstance(nested.get("usage"), dict):
            return nested["usage"]
    return None


def _extract_usage(content_type: str, body: bytes) -> dict | None:
    """Pull the response's final usage from a buffered body (JSON or SSE)."""

    if not body:
        return None
    if "text/event-stream" in content_type.lower():
        merged: dict = {}
        found = False
        for raw_line in body.split(b"\n"):
            line = raw_line.strip()
            if not line.startswith(b"data:"):
                continue
            payload = line[len(b"data:") :].strip()
            if not payload or payload == b"[DONE]":
                continue
            try:
                obj = json.loads(payload)
            except (ValueError, UnicodeDecodeError):
                continue
            usage = _usage_from_obj(obj)
            if isinstance(usage, dict):
                _merge_usage(merged, usage)
                found = True
        return _normalize_usage(merged) if found else None
    try:
        obj = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    usage = _usage_from_obj(obj)
    return _normalize_usage(usage) if usage is not None else None


def _inject_usage_include(body: bytes) -> bytes:
    """Set ``usage.include = true`` on a JSON request body; pass through on any
    non-JSON / non-object body untouched."""

    if not body:
        return body
    try:
        obj = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return body
    if not isinstance(obj, dict):
        return body
    usage = obj.get("usage")
    if not isinstance(usage, dict):
        usage = {}
    usage["include"] = True
    obj["usage"] = usage
    return json.dumps(obj).encode("utf-8")


_CLAUDE_MESSAGES_ROUTES = frozenset({"/v1/messages", "/api/v1/messages"})
_REQUEST_EFFORT_LEVELS = frozenset(
    {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
)


def _force_request_effort(path: str, obj: dict, effort_level: str | None) -> None:
    """Apply the run's normalized effort to every upstream inference request.

    Agent CLIs can issue auxiliary requests in addition to the visible agent
    loop. Keeping this enforcement at the shared provider boundary guarantees
    that those requests use the same operator-selected effort too.
    """

    if effort_level is None:
        return
    if effort_level not in _REQUEST_EFFORT_LEVELS:
        raise ValueError(f"unsupported effort level: {effort_level!r}")

    output_config = obj.get("output_config")
    reasoning = obj.get("reasoning")

    if isinstance(output_config, dict) and "effort" in output_config:
        output_config["effort"] = effort_level
    if isinstance(reasoning, dict) and "effort" in reasoning:
        reasoning["effort"] = effort_level
    if "reasoning_effort" in obj:
        obj["reasoning_effort"] = effort_level

    route = urlsplit(path).path
    if route in _CLAUDE_MESSAGES_ROUTES:
        if isinstance(output_config, dict):
            output_config["effort"] = effort_level
        else:
            obj["output_config"] = {"effort": effort_level}
    elif isinstance(reasoning, dict):
        reasoning["effort"] = effort_level
    else:
        obj["reasoning"] = {"effort": effort_level}


def _prepare_request_body(
    path: str, body: bytes, *, effort_level: str | None = None
) -> bytes:
    """Add accounting and require the model creator's first-party provider.

    OpenRouter normally load-balances a model across multiple inference hosts.
    Benchmark comparability requires the creator-operated endpoint instead, so
    supported inference requests get a strict provider allowlist and provider
    fallbacks are disabled. DeepSeek V4 Flash remains on OpenRouter routing
    because its creator-operated endpoint is incompatible with the benchmark
    account's data policy. Conflicting caller routing is otherwise overwritten
    while orthogonal constraints such as ZDR remain.
    """

    prepared = _inject_usage_include(body)
    if not _is_accounting_route(path):
        return prepared
    try:
        obj = json.loads(prepared)
    except (ValueError, UnicodeDecodeError):
        raise FirstPartyRoutingError(
            "first-party routing requires a JSON request object"
        ) from None
    if not isinstance(obj, dict):
        raise FirstPartyRoutingError(
            "first-party routing requires a JSON request object"
        )
    _force_request_effort(path, obj, effort_level)
    if "models" in obj:
        raise FirstPartyRoutingError(
            "model fallbacks are disabled by first-party-only routing"
        )
    if "fallbacks" in obj:
        raise FirstPartyRoutingError(
            "caller-supplied model fallbacks are disabled by first-party-only routing"
        )
    model = obj.get("model")
    if not isinstance(model, str) or not model.strip():
        raise FirstPartyRoutingError(
            "first-party routing requires an explicit namespaced model"
        )
    normalized_model = _normalized_model_id(model)
    if (
        normalized_model == _CLAUDE_FABLE_MODEL
        and urlsplit(path).path.rstrip("/").endswith("/messages")
    ):
        obj["fallbacks"] = [{"model": _CLAUDE_FABLE_FALLBACK_MODEL}]
    if normalized_model in _PROVIDER_LOCK_EXEMPT_MODELS:
        return json.dumps(obj).encode("utf-8")
    original_provider = _original_provider_slug(model)
    if original_provider is None:
        raise FirstPartyRoutingError(
            "model creator has no configured first-party provider route"
        )
    provider = obj.get("provider")
    if not isinstance(provider, dict):
        provider = {}
    provider.pop("ignore", None)
    provider["order"] = [original_provider]
    provider["only"] = [original_provider]
    provider["allow_fallbacks"] = False
    obj["provider"] = provider
    return json.dumps(obj).encode("utf-8")


class _Recorder:
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()

    def record(self, record: dict) -> None:
        line = json.dumps(record)
        with self._lock:
            try:
                with open(self._path, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            except OSError:
                pass


def make_handler(
    *, upstream: str, recorder: _Recorder, effort_level: str | None = None
) -> type[BaseHTTPRequestHandler]:
    parsed = urlsplit(upstream)
    upstream_host = parsed.hostname or "openrouter.ai"
    upstream_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme != "http"
    ssl_context = ssl.create_default_context() if use_tls else None

    class AccountingProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "or-accounting-proxy"

        def log_message(self, *args: object) -> None:  # noqa: D401
            return

        def _proxy(self) -> None:
            if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                self.send_error(411, "chunked request bodies not supported")
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            body = self.rfile.read(length) if length > 0 else b""
            try:
                body = _prepare_request_body(
                    self.path, body, effort_level=effort_level
                )
            except FirstPartyRoutingError as exc:
                self._diag(
                    "first_party_routing_rejected "
                    f"method={self.command} path={urlsplit(self.path).path}"
                )
                self.send_error(400, str(exc))
                return

            out_headers = {}
            for key, value in self.headers.items():
                lowered = key.lower()
                if lowered in _HOP_BY_HOP or lowered == "host" or lowered == "accept-encoding":
                    continue
                out_headers[key] = value
            out_headers["Host"] = upstream_host
            out_headers["Accept-Encoding"] = "identity"
            if body:
                out_headers["Content-Length"] = str(len(body))

            if use_tls:
                conn = http.client.HTTPSConnection(
                    upstream_host, upstream_port, timeout=UPSTREAM_TIMEOUT_SEC, context=ssl_context
                )
            else:
                conn = http.client.HTTPConnection(
                    upstream_host, upstream_port, timeout=UPSTREAM_TIMEOUT_SEC
                )
            try:
                conn.request(self.command, self.path, body=body, headers=out_headers)
                resp = conn.getresponse()
            except Exception as exc:  # noqa: BLE001 - surface upstream failure to agent
                conn.close()
                self._diag(
                    f"upstream_error method={self.command} "
                    f"path={urlsplit(self.path).path} detail={type(exc).__name__}"
                )
                self._send_gateway_error(str(exc))
                return

            content_type = resp.getheader("Content-Type") or ""
            self.send_response(resp.status)
            for key, value in resp.getheaders():
                if key.lower() in _HOP_BY_HOP:
                    continue
                self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()

            buffered = bytearray()
            try:
                while True:
                    line = resp.readline()
                    if not line:
                        break
                    self.wfile.write(line)
                    self.wfile.flush()
                    buffered.extend(line)
            except Exception:  # noqa: BLE001 - client hung up mid-stream
                buffered.clear()
            finally:
                conn.close()
                self.close_connection = True

            usage = None
            if buffered:
                try:
                    usage = _extract_usage(content_type, bytes(buffered))
                except Exception:  # noqa: BLE001 - accounting must never crash the proxy
                    usage = None
                if usage is not None:
                    recorder.record(usage)

            self._log_accounting_diagnostics(
                status=resp.status,
                content_type=content_type,
                had_body=bool(buffered),
                usage_recorded=usage is not None,
            )

        def _diag(self, message: str) -> None:
            try:
                print(f"or-accounting-proxy diag {message}", file=sys.stderr, flush=True)
            except Exception:  # noqa: BLE001 - diagnostics are best-effort
                pass

        def _log_accounting_diagnostics(
            self,
            *,
            status: int,
            content_type: str,
            had_body: bool,
            usage_recorded: bool,
        ) -> None:
            path = urlsplit(self.path).path
            if not _is_accounting_route(self.path):
                self._diag(
                    f"unmatched_route method={self.command} path={path} status={status}"
                )
                return
            if usage_recorded:
                return
            reason = "empty_response_body" if not had_body else "no_usage_in_response"
            ct = (content_type or "none").split(";")[0].strip() or "none"
            self._diag(
                f"no_usage_record method={self.command} path={path} "
                f"status={status} content_type={ct} reason={reason}"
            )

        def _send_gateway_error(self, detail: str) -> None:
            payload = json.dumps({"error": {"message": f"accounting proxy upstream error: {detail}"}}).encode()
            try:
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
            except Exception:  # noqa: BLE001
                pass
            self.close_connection = True

        do_GET = _proxy
        do_POST = _proxy

    return AccountingProxyHandler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OpenRouter accounting reverse proxy")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18082)
    parser.add_argument("--upstream", default=DEFAULT_UPSTREAM)
    parser.add_argument("--accounting-log", default=DEFAULT_ACCOUNTING_LOG)
    parser.add_argument(
        "--effort-level",
        choices=sorted(_REQUEST_EFFORT_LEVELS),
        default="high",
    )
    args = parser.parse_args(argv)

    recorder = _Recorder(args.accounting_log)
    handler = make_handler(
        upstream=args.upstream, recorder=recorder, effort_level=args.effort_level
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    server.daemon_threads = True
    print(
        f"openrouter-accounting-proxy: listening on {args.host}:{args.port} "
        f"-> {args.upstream} (log {args.accounting_log})",
        file=sys.stderr,
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
