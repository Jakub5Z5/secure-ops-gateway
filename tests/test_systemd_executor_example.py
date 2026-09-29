import os
import subprocess
import threading
from types import SimpleNamespace

import pytest

from examples.systemd_executor import (
    SystemdServiceExecutor,
    load_executor_key,
    load_services,
    validate_services,
)
from secure_ops_gateway import ExecutorInvocation, UnixSocketExecutorClient, UnixSocketExecutorServer
from secure_ops_gateway.executor import ExecutorError


def invocation(*, capability="service.status", permission="service.read", risk="read", service="api", action="status", resource=None, request_extra=None):
    request = {"action": action, "service": service}
    if request_extra:
        request.update(request_extra)
    return ExecutorInvocation(
        request_id="req-1",
        principal_id="alice",
        source_provider="test",
        source_subject="alice-source",
        capability=capability,
        permission=permission,
        risk=risk,
        resource=f"service:{service}" if resource is None else resource,
        request=request,
    )


def test_status_uses_fixed_argv_and_parses_bounded_properties():
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout="LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n",
            stderr="",
        )

    executor = SystemdServiceExecutor({"api": "my-api.service"}, runner=runner)
    result = executor.status(invocation())

    assert result == {
        "ok": True,
        "service": "api",
        "unit": "my-api.service",
        "load_state": "loaded",
        "active_state": "active",
        "sub_state": "running",
        "unit_file_state": "enabled",
    }
    argv, kwargs = calls[0]
    assert argv == [
        "/usr/bin/systemctl",
        "--no-ask-password",
        "show",
        "--no-pager",
        "--property=LoadState",
        "--property=ActiveState",
        "--property=SubState",
        "--property=UnitFileState",
        "--",
        "my-api.service",
    ]
    assert "shell" not in kwargs
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["env"] == {"LANG": "C", "LC_ALL": "C"}


def test_restart_uses_exact_allowlisted_unit_without_shell():
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    executor = SystemdServiceExecutor({"worker": "my-worker.service"}, runner=runner)
    result = executor.restart(
        invocation(
            capability="service.restart",
            permission="service.restart",
            risk="write",
            service="worker",
            action="restart",
        )
    )

    assert result == {
        "ok": True,
        "service": "worker",
        "unit": "my-worker.service",
        "action": "restart",
    }
    argv, kwargs = calls[0]
    assert argv == [
        "/usr/bin/systemctl",
        "--no-ask-password",
        "restart",
        "--",
        "my-worker.service",
    ]
    assert "shell" not in kwargs


def test_service_alias_and_authorized_resource_must_match_before_execution():
    calls = []
    executor = SystemdServiceExecutor(
        {"api": "my-api.service"},
        runner=lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    with pytest.raises(ExecutorError, match="not allowlisted"):
        executor.status(invocation(service="api;shutdown"))
    with pytest.raises(ExecutorError, match="authorized resource"):
        executor.status(invocation(resource="service:worker"))
    with pytest.raises(ExecutorError, match="invalid systemd executor request"):
        executor.status(invocation(request_extra={"unit": "ssh.service"}))
    assert calls == []


def test_handler_requires_expected_capability_permission_risk_and_action():
    executor = SystemdServiceExecutor({"api": "my-api.service"}, runner=lambda *a, **k: None)
    with pytest.raises(ExecutorError, match="unexpected capability"):
        executor.status(invocation(capability="service.restart"))
    with pytest.raises(ExecutorError, match="permission or risk"):
        executor.status(invocation(permission="service.restart"))
    with pytest.raises(ExecutorError, match="unexpected systemd executor action"):
        executor.status(invocation(action="restart"))


def test_systemctl_failure_and_incomplete_status_fail_closed():
    failed = SystemdServiceExecutor(
        {"api": "my-api.service"},
        runner=lambda *a, **k: SimpleNamespace(returncode=5, stdout="", stderr="secret detail"),
    )
    with pytest.raises(ExecutorError, match="exit code 5") as exc:
        failed.status(invocation())
    assert "secret detail" not in str(exc.value)

    incomplete = SystemdServiceExecutor(
        {"api": "my-api.service"},
        runner=lambda *a, **k: SimpleNamespace(returncode=0, stdout="ActiveState=active\n", stderr=""),
    )
    with pytest.raises(ExecutorError, match="incomplete status"):
        incomplete.status(invocation())


def test_systemctl_os_error_and_timeout_fail_closed():
    def missing(*_args, **_kwargs):
        raise FileNotFoundError("systemctl")

    executor = SystemdServiceExecutor({"api": "my-api.service"}, runner=missing)
    with pytest.raises(ExecutorError, match="execution failed"):
        executor.status(invocation())

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="systemctl", timeout=1)

    executor = SystemdServiceExecutor({"api": "my-api.service"}, runner=timeout)
    with pytest.raises(ExecutorError, match="execution failed"):
        executor.status(invocation())


def test_service_configuration_validation_is_narrow():
    assert validate_services({"api": "my-api.service"}) == {"api": "my-api.service"}
    for services in [
        {},
        {"../api": "my-api.service"},
        {"api": "ssh.service;reboot"},
        {"api": "/etc/passwd"},
    ]:
        with pytest.raises(ExecutorError):
            validate_services(services)
    with pytest.raises(ExecutorError, match="too many"):
        validate_services({f"s{i}": f"s{i}.service" for i in range(65)})


def test_constructor_rejects_ambient_or_invalid_execution_settings():
    with pytest.raises(ValueError, match="absolute"):
        SystemdServiceExecutor({"api": "api.service"}, systemctl_path="systemctl")
    with pytest.raises(ValueError, match="positive"):
        SystemdServiceExecutor({"api": "api.service"}, timeout_seconds=0)
    with pytest.raises(TypeError, match="callable"):
        SystemdServiceExecutor({"api": "api.service"}, runner=None)


@pytest.mark.skipif(os.name != "posix", reason="trusted file permissions are POSIX-specific")
def test_load_services_rejects_symlink_writable_and_duplicate_configuration(tmp_path):
    config = tmp_path / "services.json"
    config.write_text('{"api":"my-api.service"}', encoding="utf-8")
    os.chmod(config, 0o600)
    assert load_services(config) == {"api": "my-api.service"}

    os.chmod(config, 0o666)
    with pytest.raises(ExecutorError, match="writable"):
        load_services(config)
    os.chmod(config, 0o600)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"api":"one.service","api":"two.service"}', encoding="utf-8")
    os.chmod(duplicate, 0o600)
    with pytest.raises(ExecutorError, match="duplicate JSON key"):
        load_services(duplicate)

    link = tmp_path / "services-link.json"
    link.symlink_to(config)
    with pytest.raises(ExecutorError, match="cannot open trusted file"):
        load_services(link)


@pytest.mark.skipif(os.name != "posix", reason="trusted file permissions are POSIX-specific")
def test_executor_key_requires_private_owner_file_and_exact_32_byte_hex(tmp_path):
    key_file = tmp_path / "executor.key"
    key_file.write_text("ab" * 32 + "\n", encoding="ascii")
    os.chmod(key_file, 0o600)
    assert load_executor_key(key_file) == bytes.fromhex("ab" * 32)

    os.chmod(key_file, 0o640)
    with pytest.raises(ExecutorError, match="0600"):
        load_executor_key(key_file)
    os.chmod(key_file, 0o600)

    key_file.write_text("ab" * 31, encoding="ascii")
    with pytest.raises(ExecutorError, match="exactly 32 bytes"):
        load_executor_key(key_file)


def test_handlers_expose_only_two_exact_capabilities():
    executor = SystemdServiceExecutor({"api": "api.service"}, runner=lambda *a, **k: None)
    assert set(executor.handlers()) == {"service.status", "service.restart"}


@pytest.mark.skipif(os.name != "posix", reason="Unix socket executor is POSIX-specific")
def test_real_executor_server_round_trip_uses_systemd_handler(tmp_path):
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout="LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n",
            stderr="",
        )

    controller = SystemdServiceExecutor({"api": "my-api.service"}, runner=runner)
    socket_path = tmp_path / "private" / "systemd.sock"
    key = b"k" * 32
    server = UnixSocketExecutorServer(socket_path, key, controller.handlers())
    ready = threading.Event()
    thread = threading.Thread(
        target=server.serve_once,
        kwargs={"ready_event": ready},
        daemon=True,
    )
    thread.start()
    assert ready.wait(2)

    client = UnixSocketExecutorClient(key_loader=lambda _credential: key)
    response = client.call(
        {"endpoint": f"unix:{socket_path}", "credential": "systemd.key"},
        {
            "schema": 1,
            "request_id": "systemd-example-1",
            "principal_id": "operator-a",
            "source": {"provider": "test", "subject": "operator-source"},
            "capability": "service.status",
            "permission": "service.read",
            "risk": "read",
            "resource": "service:api",
            "request": {"action": "status", "service": "api"},
        },
    )
    thread.join(2)

    assert response["active_state"] == "active"
    assert response["service"] == "api"
    assert calls[0][0][-1] == "my-api.service"
    assert not socket_path.exists()
