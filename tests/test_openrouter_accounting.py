"""Tests for the OpenRouter accounting proxy + read-back helpers."""

from __future__ import annotations

import http.client
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from boundarybench.daytona.openrouter_accounting import (
    OPENROUTER_ACCOUNTING_LOG,
    OPENROUTER_ACCOUNTING_PROXY_LOG,
    REMOTE_PROXY_SCRIPT_PATH,
    read_openrouter_accounting,
    start_openrouter_accounting_proxy,
    summarize_accounting,
)

_PROXY_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "boundarybench"
    / "daytona"
    / "scripts"
    / "openrouter_accounting_proxy.py"
)
_spec = importlib.util.spec_from_file_location("_or_accounting_proxy", _PROXY_PATH)
proxy = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(proxy)


class TestUsageInclusionInjection:
    def test_injects_usage_include_on_json_object(self):
        body = b'{"model":"m","messages":[]}'
        out = proxy._inject_usage_include(body)
        import json

        assert json.loads(out)["usage"] == {"include": True}

    def test_preserves_existing_usage_keys(self):
        body = b'{"model":"m","usage":{"foo":1}}'
        import json

        out = json.loads(proxy._inject_usage_include(body))
        assert out["usage"] == {"foo": 1, "include": True}

    def test_passes_through_non_json(self):
        assert proxy._inject_usage_include(b"not json") == b"not json"

    def test_passes_through_json_array(self):
        assert proxy._inject_usage_include(b"[1,2,3]") == b"[1,2,3]"

    def test_empty_body_unchanged(self):
        assert proxy._inject_usage_include(b"") == b""

    def test_anthropic_messages_override_cross_provider_routing(self):
        body = json.dumps(
            {
                "model": "anthropic/claude-fable-5",
                "messages": [],
                "provider": {
                    "order": ["google-vertex"],
                    "only": ["google-vertex"],
                    "ignore": ["anthropic"],
                    "allow_fallbacks": True,
                    "zdr": True,
                    "require_parameters": True,
                },
            }
        ).encode()

        out = json.loads(proxy._prepare_request_body("/api/v1/messages", body))

        assert out["provider"] == {
            "order": ["anthropic"],
            "only": ["anthropic"],
            "allow_fallbacks": False,
            "zdr": True,
            "require_parameters": True,
        }

    def test_claude_code_fable_configures_exact_opus_fallback(self):
        body = b'{"model":"anthropic/claude-fable-5","messages":[]}'

        out = json.loads(proxy._prepare_request_body("/api/v1/messages", body))

        assert out["fallbacks"] == [{"model": "anthropic/claude-opus-4.8"}]
        assert out["provider"] == {
            "order": ["anthropic"],
            "only": ["anthropic"],
            "allow_fallbacks": False,
        }

    def test_fable_fallback_is_only_added_to_claude_code_messages(self):
        body = b'{"model":"anthropic/claude-fable-5","messages":[]}'

        out = json.loads(proxy._prepare_request_body("/api/v1/chat/completions", body))

        assert "fallbacks" not in out

    def test_caller_cannot_override_fable_fallback(self):
        body = json.dumps(
            {
                "model": "anthropic/claude-fable-5",
                "messages": [],
                "fallbacks": [{"model": "openai/gpt-5.6-sol"}],
            }
        ).encode()

        with pytest.raises(
            proxy.FirstPartyRoutingError, match="caller-supplied model fallbacks"
        ):
            proxy._prepare_request_body("/api/v1/messages", body)

    @pytest.mark.parametrize(
        ("path", "model", "provider_slug"),
        [
            pytest.param(
                "/api/v1/messages",
                "anthropic/claude-sonnet-4.5",
                "anthropic",
                id="claude-code-anthropic",
            ),
            pytest.param(
                "/api/v1/responses",
                "openai/gpt-5.6-sol",
                "openai",
                id="codex-openai",
            ),
            pytest.param(
                "/api/v1/responses",
                "x-ai/grok-4.20",
                "xai",
                id="grok-xai",
            ),
        ],
    )
    def test_harness_model_provider_lock_matrix(
        self, path: str, model: str, provider_slug: str
    ):
        body = json.dumps({"model": model, "messages": []}).encode()

        out = json.loads(proxy._prepare_request_body(path, body))

        assert out["provider"] == {
            "order": [provider_slug],
            "only": [provider_slug],
            "allow_fallbacks": False,
        }

    @pytest.mark.parametrize(
        "path",
        [
            pytest.param("/api/v1/messages", id="claude-code"),
            pytest.param("/api/v1/responses", id="codex"),
            pytest.param("/api/v1/responses", id="grok"),
        ],
    )
    def test_deepseek_v4_flash_preserves_openrouter_routing(self, path: str):
        body = json.dumps(
            {
                "model": "deepseek/deepseek-v4-flash",
                "messages": [],
                "provider": {"zdr": True},
            }
        ).encode()

        out = json.loads(proxy._prepare_request_body(path, body))

        assert out["provider"] == {"zdr": True}
        assert out["usage"] == {"include": True}

    def test_non_inference_route_does_not_change_provider_routing(self):
        body = b'{"model":"anthropic/claude-fable-5","messages":[]}'

        out = json.loads(proxy._prepare_request_body("/api/v1/models", body))

        assert "provider" not in out
        assert out["usage"] == {"include": True}

    @pytest.mark.parametrize(
        ("body", "message"),
        [
            (b"{}", "explicit namespaced model"),
            (b'{"model":"gpt-5.2"}', "no configured first-party provider"),
            (
                b'{"model":"meta-llama/llama-3.3-70b"}',
                "no configured first-party provider",
            ),
            (
                b'{"model":"openai/gpt-5.2","models":["anthropic/claude-sonnet-4.5"]}',
                "model fallbacks are disabled",
            ),
            (
                b'{"model":"anthropic/claude-sonnet-4.5","fallbacks":[]}',
                "model fallbacks are disabled",
            ),
        ],
    )
    def test_inference_routes_reject_ambiguous_or_unsupported_models(
        self, body: bytes, message: str
    ):
        with pytest.raises(proxy.FirstPartyRoutingError, match=message):
            proxy._prepare_request_body("/api/v1/chat/completions", body)


class TestUsageExtraction:
    def test_openai_non_stream(self):
        body = b'{"id":"gen-x","usage":{"prompt_tokens":7,"completion_tokens":6,"cost":2.66e-06}}'
        rec = proxy._extract_usage("application/json", body)
        assert rec == {
            "cost": 2.66e-06,
            "input_tokens": 7,
            "output_tokens": 6,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
        }

    def test_openai_cached_tokens(self):
        body = (
            b'{"usage":{"prompt_tokens":100,"completion_tokens":5,"cost":1e-05,'
            b'"prompt_tokens_details":{"cached_tokens":40}}}'
        )
        rec = proxy._extract_usage("application/json", body)
        assert rec["cache_read_tokens"] == 40
        assert rec["input_tokens"] == 100

    def test_anthropic_messages(self):
        body = (
            b'{"usage":{"input_tokens":11,"output_tokens":6,"cost":4.1e-05,'
            b'"cache_read_input_tokens":0,"cache_creation_input_tokens":3}}'
        )
        rec = proxy._extract_usage("application/json", body)
        assert rec["input_tokens"] == 11
        assert rec["output_tokens"] == 6
        assert rec["cache_write_tokens"] == 3
        assert rec["cost"] == 4.1e-05

    def test_responses_route_nested_usage(self):
        body = b'{"id":"gen-x","status":"completed","usage":{"input_tokens":7,"output_tokens":3,"cost":1.8e-06}}'
        rec = proxy._extract_usage("application/json", body)
        assert rec["cost"] == 1.8e-06
        assert rec["input_tokens"] == 7

    def test_chat_stream_final_chunk(self):
        body = (
            b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
            b'data: {"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":4,"cost":1.4e-06}}\n\n'
            b"data: [DONE]\n\n"
        )
        rec = proxy._extract_usage("text/event-stream", body)
        assert rec["cost"] == 1.4e-06
        assert rec["input_tokens"] == 5
        assert rec["output_tokens"] == 4

    def test_responses_stream_completed_event(self):
        body = (
            b'data: {"type":"response.in_progress","response":{"status":"in_progress"}}\n\n'
            b'data: {"type":"response.completed","response":{"status":"completed",'
            b'"usage":{"input_tokens":5,"output_tokens":17,"cost":5.2e-06}}}\n\n'
        )
        rec = proxy._extract_usage("text/event-stream", body)
        assert rec["cost"] == 5.2e-06
        assert rec["input_tokens"] == 5
        assert rec["output_tokens"] == 17

    def test_anthropic_stream_split_usage_is_merged(self):
        body = (
            b'data: {"type":"message_start","message":{"usage":{"input_tokens":11}}}\n\n'
            b'data: {"type":"message_delta","usage":{"output_tokens":6,"cost":3.3e-05}}\n\n'
        )
        rec = proxy._extract_usage("text/event-stream", body)
        assert rec["input_tokens"] == 11
        assert rec["output_tokens"] == 6
        assert rec["cost"] == 3.3e-05

    def test_no_usage_returns_none(self):
        assert proxy._extract_usage("application/json", b'{"id":"x"}') is None
        assert proxy._extract_usage("text/event-stream", b"data: {}\n\n") is None

    def test_structural_usage_without_cost_or_tokens_ignored(self):
        body = b'{"usage":{"prompt_tokens":0,"completion_tokens":0}}'
        assert proxy._extract_usage("application/json", body) is None

    def test_malformed_json_returns_none(self):
        assert proxy._extract_usage("application/json", b"{not json") is None


class TestSummarize:
    def test_sums_cost_and_tokens(self):
        summary = summarize_accounting(
            [
                {"cost": 1e-06, "input_tokens": 5, "output_tokens": 2, "cache_read_tokens": 1},
                {"cost": 2e-06, "input_tokens": 3, "output_tokens": 1},
            ]
        )
        assert summary["records"] == 2
        assert summary["input_tokens"] == 8
        assert summary["output_tokens"] == 3
        assert summary["cache_read_tokens"] == 1
        assert summary["total_tokens"] == 11
        assert summary["cost"] == pytest.approx(3e-06)
        assert summary["cost_complete"] is True

    def test_partial_cost_marks_incomplete(self):
        summary = summarize_accounting(
            [
                {"cost": 1e-06, "input_tokens": 5, "output_tokens": 2},
                {"cost": None, "input_tokens": 3, "output_tokens": 1},
            ]
        )
        assert summary["cost"] == pytest.approx(1e-06)
        assert summary["cost_complete"] is False

    def test_no_cost_yields_none(self):
        summary = summarize_accounting([{"input_tokens": 5, "output_tokens": 2}])
        assert summary["cost"] is None
        assert summary["cost_complete"] is False


class _FakeExecResult:
    def __init__(self, result: str) -> None:
        self.result = result
        self.exit_code = 0


class _FakeSandbox:
    def __init__(self, log_text: str) -> None:
        self._log_text = log_text
        self.commands: list[str] = []

    class _Process:
        def __init__(self, outer: "_FakeSandbox") -> None:
            self._outer = outer

        def exec(self, command: str, timeout: int = 0):
            self._outer.commands.append(command)
            return _FakeExecResult(self._outer._log_text)

    @property
    def process(self):
        return _FakeSandbox._Process(self)


class TestReadBack:
    def test_reads_and_summarizes(self):
        log = (
            '{"cost": 1e-06, "input_tokens": 5, "output_tokens": 2}\n'
            '{"cost": 2e-06, "input_tokens": 3, "output_tokens": 1}\n'
        )
        sandbox = _FakeSandbox(log)
        summary = read_openrouter_accounting(sandbox)
        assert summary is not None
        assert summary["records"] == 2
        assert summary["cost"] == pytest.approx(3e-06)
        assert OPENROUTER_ACCOUNTING_LOG in sandbox.commands[0]

    def test_empty_log_returns_none(self):
        assert read_openrouter_accounting(_FakeSandbox("")) is None

    def test_skips_malformed_lines(self):
        sandbox = _FakeSandbox('garbage\n{"cost": 1e-06, "input_tokens": 1, "output_tokens": 1}\n')
        summary = read_openrouter_accounting(sandbox)
        assert summary is not None
        assert summary["records"] == 1


class _FakeUpstreamHandler(BaseHTTPRequestHandler):
    """Fixed-response upstream that records the request it received."""

    received: dict = {}

    def log_message(self, *args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        type(self).received = {
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body,
        }
        payload = json.dumps(
            {"id": "x", "usage": {"prompt_tokens": 5, "completion_tokens": 3, "cost": 1.5e-06}}
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


class TestProxyEndToEnd:
    def test_rejects_unroutable_inference_before_contacting_upstream(self, tmp_path):
        _FakeUpstreamHandler.received = {}
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _FakeUpstreamHandler)
        upstream_port = upstream.server_address[1]
        handler = proxy.make_handler(
            upstream=f"http://127.0.0.1:{upstream_port}",
            recorder=proxy._Recorder(str(tmp_path / "accounting.jsonl")),
        )
        proxy_server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        proxy_port = proxy_server.server_address[1]
        proxy_thread = threading.Thread(target=proxy_server.handle_request)
        proxy_thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
            conn.request(
                "POST",
                "/api/v1/responses",
                body=b"{}",
                headers={"Content-Type": "application/json"},
            )
            response = conn.getresponse()
            response.read()
            conn.close()
        finally:
            proxy_thread.join(timeout=5)
            proxy_server.server_close()
            upstream.server_close()

        assert response.status == 400
        assert _FakeUpstreamHandler.received == {}

    def test_forwards_injects_usage_and_records(self, tmp_path):
        _FakeUpstreamHandler.received = {}
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _FakeUpstreamHandler)
        upstream.timeout = 5
        upstream_port = upstream.server_address[1]

        log_path = tmp_path / "accounting.jsonl"
        recorder = proxy._Recorder(str(log_path))
        handler = proxy.make_handler(
            upstream=f"http://127.0.0.1:{upstream_port}", recorder=recorder
        )
        proxy_server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        proxy_server.timeout = 5
        proxy_host, proxy_port = proxy_server.server_address

        upstream_thread = threading.Thread(target=upstream.handle_request)
        proxy_thread = threading.Thread(target=proxy_server.handle_request)
        upstream_thread.start()
        proxy_thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
            request_body = json.dumps(
                {"model": "openai/gpt-5.2", "messages": []}
            ).encode("utf-8")
            conn.request(
                "POST",
                "/api/v1/chat/completions",
                body=request_body,
                headers={"Content-Type": "application/json"},
            )
            response = conn.getresponse()
            client_body = response.read()
            conn.close()
        finally:
            proxy_thread.join(timeout=5)
            upstream_thread.join(timeout=5)
            proxy_server.server_close()
            upstream.server_close()

        received = _FakeUpstreamHandler.received
        upstream_json = json.loads(received["body"])
        assert upstream_json["usage"]["include"] is True
        assert upstream_json["provider"] == {
            "order": ["openai"],
            "only": ["openai"],
            "allow_fallbacks": False,
        }
        assert received["headers"]["host"] == "127.0.0.1"
        assert received["headers"]["host"] != f"{proxy_host}:{proxy_port}"
        assert received["headers"]["accept-encoding"] == "identity"
        client_json = json.loads(client_body)
        assert client_json["id"] == "x"
        lines = [ln for ln in log_path.read_text().splitlines() if ln.strip()]
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["cost"] == pytest.approx(1.5e-06)
        assert record["input_tokens"] == 5
        assert record["output_tokens"] == 3


class TestAccountingRouteClassification:
    def test_accounting_routes_match(self):
        assert proxy._is_accounting_route("/api/v1/chat/completions")
        assert proxy._is_accounting_route("/api/v1/responses")
        assert proxy._is_accounting_route("/api/v1/messages")
        assert proxy._is_accounting_route("/api/v1/responses/")
        assert proxy._is_accounting_route("/api/v1/responses?stream=true")

    def test_non_accounting_routes_do_not_match(self):
        assert not proxy._is_accounting_route("/api/v1/models")
        assert not proxy._is_accounting_route("/api/v1/key")
        assert not proxy._is_accounting_route("/")


class _NoUsageUpstreamHandler(BaseHTTPRequestHandler):
    """Upstream that returns a 200 body WITHOUT any usage object."""

    def log_message(self, *args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            self.rfile.read(length)
        payload = json.dumps({"id": "x"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


class TestAccountingDiagnostics:
    def _exchange(self, path: str, capsys) -> str:
        """Drive one proxied POST and return the proxy's captured stderr."""

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _NoUsageUpstreamHandler)
        upstream.timeout = 5
        upstream_port = upstream.server_address[1]
        recorder = proxy._Recorder("/dev/null")
        handler = proxy.make_handler(
            upstream=f"http://127.0.0.1:{upstream_port}", recorder=recorder
        )
        proxy_server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        proxy_server.timeout = 5
        proxy_port = proxy_server.server_address[1]

        upstream_thread = threading.Thread(target=upstream.handle_request)
        proxy_thread = threading.Thread(target=proxy_server.handle_request)
        upstream_thread.start()
        proxy_thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
            conn.request(
                "POST",
                path,
                body=b'{"model":"openai/gpt-5.2"}',
                headers={"Content-Type": "application/json"},
            )
            conn.getresponse().read()
            conn.close()
        finally:
            proxy_thread.join(timeout=5)
            upstream_thread.join(timeout=5)
            proxy_server.server_close()
            upstream.server_close()
        return capsys.readouterr().err

    def test_accounting_route_without_usage_logs_reason(self, capsys):
        err = self._exchange("/api/v1/responses", capsys)
        assert "or-accounting-proxy diag no_usage_record" in err
        assert "path=/api/v1/responses" in err
        assert "reason=no_usage_in_response" in err
        assert "status=200" in err

    def test_non_accounting_route_is_logged(self, capsys):
        err = self._exchange("/api/v1/models", capsys)
        assert "or-accounting-proxy diag unmatched_route" in err
        assert "path=/api/v1/models" in err


class TestNativeModelUsage:
    def test_none_or_empty_returns_none(self):
        from boundarybench.terminalbench.daytona_eval import _native_model_usage

        assert _native_model_usage(None) is None
        assert _native_model_usage({}) is None
        assert _native_model_usage({"records": 0}) is None

    def test_complete_record_sets_cost_and_tokens(self):
        from boundarybench.terminalbench.daytona_eval import _native_model_usage

        usage = _native_model_usage(
            {
                "records": 2,
                "input_tokens": 8,
                "output_tokens": 3,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "total_tokens": 11,
                "cost": 3e-06,
                "cost_complete": True,
            }
        )
        assert usage is not None
        assert usage.total_cost == pytest.approx(3e-06)
        assert usage.input_tokens == 8
        assert usage.output_tokens == 3
        assert usage.total_tokens == 11
        assert usage.input_tokens_cache_read is None

    def test_incomplete_record_drops_cost_keeps_tokens(self):
        from boundarybench.terminalbench.daytona_eval import _native_model_usage

        usage = _native_model_usage(
            {
                "records": 2,
                "input_tokens": 8,
                "output_tokens": 3,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
                "total_tokens": 11,
                "cost": 1e-06,
                "cost_complete": False,
            }
        )
        assert usage is not None
        assert usage.total_cost is None
        assert usage.input_tokens == 8
        assert usage.output_tokens == 3


class _FakeExecResultWithCode:
    def __init__(self, exit_code: int, result: str = "") -> None:
        self.exit_code = exit_code
        self.result = result


class _FakeLaunchSandbox:
    """Records exec commands; returns a chosen exit code for the launch call.

    The write command is the first exec, the launch command the second, so we
    can hand back different exit codes per call to exercise the failure path.
    """

    def __init__(self, exit_codes: list[int]) -> None:
        self._exit_codes = exit_codes
        self.commands: list[str] = []

    class _Process:
        def __init__(self, outer: "_FakeLaunchSandbox") -> None:
            self._outer = outer

        def exec(self, command: str, timeout: int = 0):
            outer = self._outer
            index = len(outer.commands)
            outer.commands.append(command)
            code = outer._exit_codes[index] if index < len(outer._exit_codes) else 0
            return _FakeExecResultWithCode(code, result="boom")

    @property
    def process(self):
        return _FakeLaunchSandbox._Process(self)


class TestStartProxy:
    def test_writes_and_launches(self):
        sandbox = _FakeLaunchSandbox([0, 0])
        start_openrouter_accounting_proxy(sandbox)
        write_command, launch_command = sandbox.commands[0], sandbox.commands[1]
        assert "base64 -d" in write_command
        assert REMOTE_PROXY_SCRIPT_PATH in write_command
        assert "--port 18082" in launch_command
        assert OPENROUTER_ACCOUNTING_LOG in launch_command
        assert "nohup python3" in launch_command

    def test_removes_setup_source_and_startup_log_after_readiness(self):
        sandbox = _FakeLaunchSandbox([0, 0])

        start_openrouter_accounting_proxy(sandbox)

        launch_command = sandbox.commands[1]
        cleanup = (
            f"rm -f {REMOTE_PROXY_SCRIPT_PATH} {OPENROUTER_ACCOUNTING_PROXY_LOG}"
        )
        cleanup_index = launch_command.index(cleanup)
        readiness_probe_index = launch_command.index("socket.create_connection")
        readiness_guard_index = launch_command.index('if [ "$ready" -ne 1 ]')
        assert "sleep 0.3" not in launch_command
        assert 'while [ "$attempt" -lt ' in launch_command
        assert launch_command.index('kill -0 "$pid"') < readiness_probe_index
        assert readiness_probe_index < readiness_guard_index < cleanup_index
        assert launch_command.endswith(cleanup)
        assert OPENROUTER_ACCOUNTING_LOG not in launch_command[cleanup_index:]

    def test_nonzero_launch_exit_raises(self):
        sandbox = _FakeLaunchSandbox([0, 1])
        with pytest.raises(RuntimeError):
            start_openrouter_accounting_proxy(sandbox)


class TestRecorder:
    def test_records_two_json_lines(self, tmp_path):
        log_path = tmp_path / "rec.jsonl"
        recorder = proxy._Recorder(str(log_path))
        first = {"cost": 1e-06, "input_tokens": 5, "output_tokens": 2}
        second = {"cost": 2e-06, "input_tokens": 3, "output_tokens": 1}
        recorder.record(first)
        recorder.record(second)
        lines = [ln for ln in log_path.read_text().splitlines() if ln.strip()]
        assert len(lines) == 2
        assert json.loads(lines[0]) == first
        assert json.loads(lines[1]) == second


class TestProxyEffortEnforcement:
    """The proxy forces the run's effort on every upstream inference request,
    including auxiliary requests a harness makes outside its visible loop."""

    def test_forces_effort_on_claude_messages_route(self):
        body = b'{"model":"anthropic/claude-fable-5","messages":[]}'
        out = json.loads(
            proxy._prepare_request_body(
                "/api/v1/messages", body, effort_level="low"
            )
        )
        assert out["output_config"] == {"effort": "low"}

    def test_forces_effort_on_completions_route(self):
        body = b'{"model":"deepseek/deepseek-v4-flash","messages":[]}'
        out = json.loads(
            proxy._prepare_request_body(
                "/api/v1/chat/completions", body, effort_level="high"
            )
        )
        assert out["reasoning"] == {"effort": "high"}

    def test_overrides_a_conflicting_caller_effort(self):
        body = b'{"model":"deepseek/deepseek-v4-flash","reasoning":{"effort":"high"}}'
        out = json.loads(
            proxy._prepare_request_body(
                "/api/v1/chat/completions", body, effort_level="low"
            )
        )
        assert out["reasoning"]["effort"] == "low"

    def test_none_effort_leaves_request_untouched(self):
        body = b'{"model":"deepseek/deepseek-v4-flash","messages":[]}'
        out = json.loads(
            proxy._prepare_request_body(
                "/api/v1/chat/completions", body, effort_level=None
            )
        )
        assert "reasoning" not in out and "output_config" not in out

    def test_rejects_unsupported_effort(self):
        with pytest.raises(ValueError, match="unsupported effort level"):
            proxy._force_request_effort("/api/v1/messages", {}, "turbo")


class TestProxyEffortPreservation:
    """Forcing effort must merge into the route-appropriate object and
    canonicalize conflicting efforts, never destroy other request config."""

    def test_preserves_reasoning_summary_when_adding_effort(self):
        obj = {"reasoning": {"summary": "auto"}}
        proxy._force_request_effort("/api/v1/chat/completions", obj, "high")
        assert obj["reasoning"] == {"summary": "auto", "effort": "high"}

    def test_preserves_output_config_format_when_adding_effort(self):
        obj = {"output_config": {"format": {"type": "json"}}}
        proxy._force_request_effort("/api/v1/messages", obj, "high")
        assert obj["output_config"] == {"format": {"type": "json"}, "effort": "high"}

    def test_canonicalizes_conflicting_effort_fields(self):
        obj = {
            "output_config": {"effort": "low", "format": "json"},
            "reasoning": {"effort": "medium", "summary": "auto"},
            "reasoning_effort": "max",
        }
        proxy._force_request_effort("/api/v1/messages", obj, "high")
        assert obj["output_config"] == {"effort": "high", "format": "json"}
        assert obj["reasoning"] == {"effort": "high", "summary": "auto"}
        assert obj["reasoning_effort"] == "high"


def _proxy_roundtrip(tmp_path, *, route, body_obj, effort_level):
    """Send one request through the proxy to a fake upstream and return the
    JSON body the upstream actually received on the wire."""
    _FakeUpstreamHandler.received = {}
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _FakeUpstreamHandler)
    upstream.timeout = 5
    up_port = upstream.server_address[1]
    handler = proxy.make_handler(
        upstream=f"http://127.0.0.1:{up_port}",
        recorder=proxy._Recorder(str(tmp_path / "acct.jsonl")),
        effort_level=effort_level,
    )
    proxy_server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    proxy_server.timeout = 5
    proxy_port = proxy_server.server_address[1]
    up_thread = threading.Thread(target=upstream.handle_request)
    px_thread = threading.Thread(target=proxy_server.handle_request)
    up_thread.start()
    px_thread.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
        conn.request(
            "POST",
            route,
            body=json.dumps(body_obj).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        resp.read()
        conn.close()
    finally:
        up_thread.join(timeout=5)
        px_thread.join(timeout=5)
        proxy_server.server_close()
        upstream.server_close()
    assert resp.status == 200, f"proxy returned {resp.status}"
    return json.loads(_FakeUpstreamHandler.received["body"])


class TestProxyEffortWireEvidence:
    """End-to-end: verify the effort the UPSTREAM actually receives on the wire,
    across every route shape, for the default and an explicit override."""

    def test_default_high_reaches_claude_messages_upstream(self, tmp_path):
        got = _proxy_roundtrip(
            tmp_path,
            route="/api/v1/messages",
            body_obj={"model": "anthropic/claude-opus-4.8", "messages": []},
            effort_level="high",
        )
        assert got["output_config"]["effort"] == "high"

    def test_override_low_reaches_chat_completions_upstream(self, tmp_path):
        got = _proxy_roundtrip(
            tmp_path,
            route="/api/v1/chat/completions",
            body_obj={"model": "openai/gpt-5.2", "messages": []},
            effort_level="low",
        )
        assert got["reasoning"]["effort"] == "low"

    def test_effort_reaches_responses_upstream(self, tmp_path):
        got = _proxy_roundtrip(
            tmp_path,
            route="/api/v1/responses",
            body_obj={"model": "openai/gpt-5.2", "input": []},
            effort_level="high",
        )
        assert got["reasoning"]["effort"] == "high"

    def test_preserves_caller_fields_on_the_wire(self, tmp_path):
        got = _proxy_roundtrip(
            tmp_path,
            route="/api/v1/chat/completions",
            body_obj={
                "model": "openai/gpt-5.2",
                "messages": [],
                "reasoning": {"summary": "auto"},
            },
            effort_level="low",
        )
        assert got["reasoning"] == {"summary": "auto", "effort": "low"}


class TestProxyEffortWrongRouteAlias:
    """A stray effort on the wrong-route object must NOT satisfy enforcement:
    the field the provider actually reads for the route must still be set."""

    def test_messages_route_adds_output_config_despite_stray_reasoning_effort(self):
        obj = {"reasoning": {"effort": "low"}}
        proxy._force_request_effort("/api/v1/messages", obj, "high")
        assert obj["output_config"]["effort"] == "high"
        assert obj["reasoning"]["effort"] == "high"

    def test_responses_route_adds_reasoning_despite_stray_output_config(self):
        obj = {"output_config": {"effort": "low"}}
        proxy._force_request_effort("/api/v1/responses", obj, "high")
        assert obj["reasoning"]["effort"] == "high"
        assert obj["output_config"]["effort"] == "high"

    def test_wrong_route_alias_reaches_upstream_with_route_field(self, tmp_path):
        got = _proxy_roundtrip(
            tmp_path,
            route="/api/v1/messages",
            body_obj={
                "model": "anthropic/claude-opus-4.8",
                "messages": [],
                "reasoning": {"effort": "low"},
            },
            effort_level="high",
        )
        assert got["output_config"]["effort"] == "high"
        assert got["reasoning"]["effort"] == "high"
