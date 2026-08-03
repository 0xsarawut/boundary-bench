from __future__ import annotations

from types import SimpleNamespace

from boundarybench.daytona.apparmor_capability import (
    DEFAULT_APPARMOR_PROFILE_NAME,
    run_apparmor_capability_probe,
)


class _FakeProcess:
    def __init__(self, responses: list[tuple[str, SimpleNamespace]]) -> None:
        self.commands: list[str] = []
        self._responses = responses

    def exec(self, command: str, *, timeout: int, env=None):
        self.commands.append(command)
        for needle, response in self._responses:
            if needle in command:
                return response
        raise AssertionError(f"unexpected AppArmor probe command: {command}")


class _FakeSandbox:
    def __init__(self, responses: list[tuple[str, SimpleNamespace]]) -> None:
        self.process = _FakeProcess(responses)


def _result(exit_code: int, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(exit_code=exit_code, result=stdout, stderr=stderr)


def test_apparmor_probe_reports_unsupported_when_required_tools_are_missing():
    sandbox = _FakeSandbox(
        [
            (
                "APPARMOR_PARSER=",
                _result(
                    0,
                    "\n".join(
                        [
                            "LSM=",
                            "APPARMOR_ENABLED=N",
                            "PROFILES_READABLE=no",
                            "CURRENT=unconfined",
                            "APPARMOR_PARSER=",
                            "AA_EXEC=",
                            "AA_STATUS=",
                        ]
                    ),
                ),
            )
        ]
    )

    report = run_apparmor_capability_probe(sandbox)

    assert report.status == "unsupported"
    assert report.supported is False
    assert report.profile_loaded is False
    assert "apparmor_parser" in report.unsupported_reason
    metadata = report.to_metadata()
    assert metadata["engine"] == "apparmor"
    assert metadata["supported"] is False
    assert metadata["command_evidence"][0]["command_id"] == "substrate"


def test_apparmor_probe_requires_load_attach_deny_and_allowed_write_evidence():
    sandbox = _FakeSandbox(
        [
            (
                "APPARMOR_PARSER=",
                _result(
                    0,
                    "\n".join(
                        [
                            "LSM=lockdown,yama,integrity,apparmor",
                            "APPARMOR_ENABLED=Y",
                            "PROFILES_READABLE=yes",
                            "CURRENT=unconfined",
                            "APPARMOR_PARSER=/usr/sbin/apparmor_parser",
                            "AA_EXEC=/usr/bin/aa-exec",
                            "AA_STATUS=/usr/sbin/aa-status",
                        ]
                    ),
                ),
            ),
            ("cat > /tmp/boundarybench-apparmor-probe", _result(0)),
            ("apparmor_parser -r", _result(0)),
            (
                "/sys/kernel/security/apparmor/profiles",
                _result(0, f"{DEFAULT_APPARMOR_PROFILE_NAME} (enforce)\n"),
            ),
            (
                "cat /proc/self/attr/current",
                _result(0, f"{DEFAULT_APPARMOR_PROFILE_NAME} (enforce)\n"),
            ),
            (
                "CHILD_APPARMOR_CURRENT",
                _result(0, f"CHILD_APPARMOR_CURRENT={DEFAULT_APPARMOR_PROFILE_NAME} (enforce)\n"),
            ),
            (
                "boundarybench-apparmor-denied",
                _result(1, "", "Permission denied\n"),
            ),
            ("apparmor-allowed", _result(0, "ok\n")),
            ("apparmor_parser -R", _result(0)),
        ]
    )

    report = run_apparmor_capability_probe(sandbox)

    assert report.status == "enforced"
    assert report.supported is True
    assert report.profile_loaded is True
    assert report.profile_attached is True
    assert report.child_inherits_profile is True
    assert report.denied_action_blocked is True
    assert report.workspace_write_allowed is True
    metadata = report.to_metadata()
    assert metadata["profile_name"] == DEFAULT_APPARMOR_PROFILE_NAME
    assert metadata["denied_action"]["path"].endswith("/secret.txt")
    assert {item["command_id"] for item in metadata["command_evidence"]} >= {
        "load_profile",
        "attached_profile",
        "denied_file_read",
        "workspace_allowed_write",
        "cleanup_profile",
    }
    assert any(
        f"aa-exec -p {DEFAULT_APPARMOR_PROFILE_NAME}" in command
        for command in sandbox.process.commands
    )
