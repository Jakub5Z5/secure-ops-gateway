import json
import os
import socket
import stat
import threading
import time

import pytest

from secure_ops_gateway.executor import (
    CapabilityRouter,
    ExecutorError,
    ExecutorInvocation,
    ReplayCache,
    UnixSocketExecutorClient,
    UnixSocketExecutorServer,
    canonical_json,
    sign_envelope,
    verify_response_envelope,
)

KEY = b"s" * 32


def payload(*, capability="demo.status", request_id="req-1", request=None):
    return {
        "schema": 1,
        "request_id": request_id,
        "principal_id": "alice",
        "source": {"provider": "mcp", "subject": "client:alice"},
        "capability": capability,
        "permission": "demo.read",
        "risk": "read",
        "resource": "demo:api",
        "request": {"action": "status"} if request is None else request,
    }


def wait_for_path(path, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError("executor socket did not become ready")


def private_socket_path(tmp_path):
    return tmp_path / "private" / "executor.sock"


def assert_connection_closed(sock):
    try:
        assert sock.recv(1024) == b""
    except ConnectionResetError:
        pass


def test_invocation_validates_common_authenticated_payload():
    invocation = ExecutorInvocation.from_payload(payload())
    assert invocation.request_id == "req-1"
    assert invocation.principal_id == "alice"
    assert invocation.source_provider == "mcp"
    assert invocation.source_subject == "client:alice"
    assert invocation.capability == "demo.status"
    assert invocation.request == {"action": "status"}

    broken = payload()
    broken["extra"] = True
    with pytest.raises(ExecutorError, match="request payload"):
        ExecutorInvocation.from_payload(broken)

    broken = payload()
    broken["source"] = {"provider": "mcp", "subject": "alice", "extra": "x"}
    with pytest.raises(ExecutorError, match="source metadata"):
        ExecutorInvocation.from_payload(broken)

    broken = payload(capability="bad capability")
    with pytest.raises(ExecutorError, match="capability"):
        ExecutorInvocation.from_payload(broken)

    broken = payload()
    broken["risk"] = "root"
    with pytest.raises(ExecutorError, match="risk"):
        ExecutorInvocation.from_payload(broken)


def test_capability_router_is_an_exact_allowlist():
    seen = []
    router = CapabilityRouter({"demo.status": lambda item: seen.append(item) or {"ok": True}})
    invocation = ExecutorInvocation.from_payload(payload())
    assert router.capabilities == ("demo.status",)
    assert router.dispatch(invocation) == {"ok": True}
    assert seen == [invocation]

    denied = ExecutorInvocation.from_payload(payload(capability="demo.restart"))
    with pytest.raises(ExecutorError, match="unsupported executor capability"):
        router.dispatch(denied)

    with pytest.raises(ValueError, match="non-empty mapping"):
        CapabilityRouter({})
    with pytest.raises(ValueError, match="capability name"):
        CapabilityRouter({"bad capability": lambda _item: {}})
    with pytest.raises(TypeError, match="must be callable"):
        CapabilityRouter({"demo.status": None})


def test_router_rejects_non_object_handler_response():
    router = CapabilityRouter({"demo.status": lambda _item: "ok"})
    with pytest.raises(ExecutorError, match="return an object"):
        router.dispatch(ExecutorInvocation.from_payload(payload()))


def test_server_handle_envelope_authenticates_replay_and_binds_response(tmp_path):
    seen = []
    server = UnixSocketExecutorServer(
        private_socket_path(tmp_path),
        KEY,
        {"demo.status": lambda item: seen.append(item) or {"ok": True}},
    )
    now = int(time.time())
    envelope = sign_envelope(payload(), KEY, timestamp=now, nonce="a" * 32)
    response = server.handle_envelope(envelope)
    assert verify_response_envelope(
        response,
        KEY,
        request_id="req-1",
        replay_protector=ReplayCache(),
        now=now,
    ) == {"ok": True}
    assert seen[0].capability == "demo.status"

    with pytest.raises(ExecutorError, match="replayed"):
        server.handle_envelope(envelope)


def test_server_handle_envelope_rejects_tampering_before_dispatch(tmp_path):
    calls = []
    server = UnixSocketExecutorServer(
        private_socket_path(tmp_path),
        KEY,
        {"demo.status": lambda item: calls.append(item) or {"ok": True}},
    )
    envelope = sign_envelope(payload(), KEY)
    envelope["payload"]["resource"] = "demo:other"
    with pytest.raises(ExecutorError, match="authentication failed"):
        server.handle_envelope(envelope)
    assert calls == []


def test_unix_server_round_trip_with_builtin_client(tmp_path):
    path = private_socket_path(tmp_path)
    seen = []
    errors = []
    server = UnixSocketExecutorServer(
        path,
        KEY,
        {
            "demo.status": lambda item: seen.append(item) or {
                "ok": True,
                "principal": item.principal_id,
                "action": item.request["action"],
            }
        },
        error_handler=errors.append,
    )
    thread = threading.Thread(target=server.serve_once, daemon=True)
    thread.start()
    wait_for_path(path)

    client = UnixSocketExecutorClient(key_loader=lambda _credential: KEY)
    result = client.call(
        {"endpoint": f"unix:{path}", "credential": "demo.key"},
        payload(),
    )
    thread.join(2)

    assert result == {"ok": True, "principal": "alice", "action": "status"}
    assert seen[0].source_subject == "client:alice"
    assert errors == []
    assert not path.exists()


def test_server_socket_permissions_are_private_and_cleanup_is_identity_safe(tmp_path):
    path = private_socket_path(tmp_path)
    server = UnixSocketExecutorServer(
        path,
        KEY,
        {"demo.status": lambda _item: {"ok": True}},
    )
    with server._listener():
        metadata = os.lstat(path)
        assert stat.S_ISSOCK(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        os.unlink(path)
        path.write_text("replacement")
    assert path.read_text() == "replacement"


def test_server_refuses_existing_socket_path_without_unlinking(tmp_path):
    path = private_socket_path(tmp_path)
    path.parent.mkdir(mode=0o700)
    path.write_text("do not remove")
    server = UnixSocketExecutorServer(
        path,
        KEY,
        {"demo.status": lambda _item: {"ok": True}},
    )
    with pytest.raises(ExecutorError, match="already exists"):
        with server._listener():
            pass
    assert path.read_text() == "do not remove"


def test_server_rejects_parent_replacement_after_initialization(tmp_path):
    path = private_socket_path(tmp_path)
    server = UnixSocketExecutorServer(
        path,
        KEY,
        {"demo.status": lambda _item: {"ok": True}},
    )
    original = path.parent
    moved = tmp_path / "moved"
    original.rename(moved)
    original.mkdir(mode=0o700)
    with pytest.raises(ExecutorError, match="parent was replaced"):
        with server._listener():
            pass


def test_serve_forever_isolates_bad_connection_and_continues(tmp_path):
    path = private_socket_path(tmp_path)
    errors = []
    stop = threading.Event()
    server = UnixSocketExecutorServer(
        path,
        KEY,
        {"demo.status": lambda _item: {"ok": True}},
        error_handler=errors.append,
        accept_poll_seconds=0.02,
    )
    thread = threading.Thread(target=server.serve_forever, kwargs={"stop_event": stop}, daemon=True)
    thread.start()
    wait_for_path(path)

    bad = sign_envelope(payload(capability="demo.forbidden", request_id="bad"), KEY)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(str(path))
        client_socket.sendall(canonical_json(bad) + b"\n")
        assert_connection_closed(client_socket)

    client = UnixSocketExecutorClient(key_loader=lambda _credential: KEY)
    assert client.call(
        {"endpoint": f"unix:{path}", "credential": "demo.key"},
        payload(request_id="good"),
    ) == {"ok": True}

    stop.set()
    thread.join(2)
    assert not thread.is_alive()
    assert any("unsupported executor capability" in str(exc) for exc in errors)
    assert not path.exists()


def test_server_rejects_oversized_or_malformed_frames_without_signed_response(tmp_path):
    path = private_socket_path(tmp_path)
    errors = []
    server = UnixSocketExecutorServer(
        path,
        KEY,
        {"demo.status": lambda _item: {"ok": True}},
        max_request_bytes=128,
        error_handler=errors.append,
    )
    thread = threading.Thread(target=server.serve_once, daemon=True)
    thread.start()
    wait_for_path(path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(str(path))
        client_socket.sendall(b"x" * 129 + b"\n")
        assert_connection_closed(client_socket)
    thread.join(2)
    assert any("too large" in str(exc) for exc in errors)

    path2 = tmp_path / "private2" / "executor.sock"
    errors2 = []
    server2 = UnixSocketExecutorServer(
        path2,
        KEY,
        {"demo.status": lambda _item: {"ok": True}},
        error_handler=errors2.append,
    )
    thread2 = threading.Thread(target=server2.serve_once, daemon=True)
    thread2.start()
    wait_for_path(path2)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(str(path2))
        client_socket.sendall(b"not-json\n")
        assert_connection_closed(client_socket)
    thread2.join(2)
    assert any("invalid JSON" in str(exc) for exc in errors2)


def test_server_response_size_limit_fails_closed(tmp_path):
    path = private_socket_path(tmp_path)
    errors = []
    server = UnixSocketExecutorServer(
        path,
        KEY,
        {"demo.status": lambda _item: {"data": "x" * 1000}},
        max_response_bytes=128,
        error_handler=errors.append,
    )
    thread = threading.Thread(target=server.serve_once, daemon=True)
    thread.start()
    wait_for_path(path)

    client = UnixSocketExecutorClient(key_loader=lambda _credential: KEY)
    with pytest.raises(ExecutorError, match="invalid JSON"):
        client.call(
            {"endpoint": f"unix:{path}", "credential": "demo.key"},
            payload(),
        )
    thread.join(2)
    assert any("response too large" in str(exc) for exc in errors)


def test_server_constructor_validation(tmp_path, monkeypatch):
    path = private_socket_path(tmp_path)
    handlers = {"demo.status": lambda _item: {"ok": True}}

    with pytest.raises(ExecutorError, match="32 bytes"):
        UnixSocketExecutorServer(path, b"short", handlers)
    with pytest.raises(ValueError, match="max_request_bytes"):
        UnixSocketExecutorServer(path, KEY, handlers, max_request_bytes=0)
    with pytest.raises(ValueError, match="max_response_bytes"):
        UnixSocketExecutorServer(path, KEY, handlers, max_response_bytes=0)
    with pytest.raises(ValueError, match="backlog"):
        UnixSocketExecutorServer(path, KEY, handlers, backlog=0)
    with pytest.raises(ValueError, match="connection_timeout_seconds"):
        UnixSocketExecutorServer(path, KEY, handlers, connection_timeout_seconds=0)
    with pytest.raises(ValueError, match="accept_poll_seconds"):
        UnixSocketExecutorServer(path, KEY, handlers, accept_poll_seconds=0)
    with pytest.raises(TypeError, match="error_handler"):
        UnixSocketExecutorServer(path, KEY, handlers, error_handler=1)

    server = UnixSocketExecutorServer(path, KEY, handlers)
    with pytest.raises(TypeError, match="stop_event"):
        server.serve_forever(stop_event=object())

    monkeypatch.setattr("secure_ops_gateway.executor.os.name", "nt")
    with pytest.raises(ExecutorError, match="POSIX"):
        UnixSocketExecutorServer(path, KEY, handlers)


def test_gateway_to_executor_server_end_to_end(tmp_path):
    from secure_ops_gateway.gateway import Gateway
    from secure_ops_gateway.identity import SourceContext, StaticIdentityResolver

    path = private_socket_path(tmp_path)
    server = UnixSocketExecutorServer(
        path,
        KEY,
        {
            "demo.status": lambda item: {
                "ok": True,
                "principal": item.principal_id,
                "resource": item.resource,
            }
        },
    )
    thread = threading.Thread(target=server.serve_once, daemon=True)
    thread.start()
    wait_for_path(path)

    client = UnixSocketExecutorClient(key_loader=lambda _credential: KEY)
    gateway = Gateway(
        tools={
            "schema": 1,
            "tools": {
                "demo.status": {
                    "capability": "demo.status",
                    "permission": "demo.read",
                    "resource": "demo:api",
                    "risk": "read",
                    "confirmation": "none",
                    "arguments": {},
                    "request": {"action": "status"},
                }
            },
        },
        executors={
            "schema": 1,
            "executors": {
                "demo": {
                    "endpoint": f"unix:{path}",
                    "credential": "demo.key",
                    "capabilities": ["demo.status"],
                }
            },
        },
        policy={
            "schema": 1,
            "roles": {
                "reader": {
                    "permissions": ["demo.read"],
                    "max_risk": "read",
                }
            },
            "bindings": {
                "alice": [{"role": "reader", "resources": ["demo:*"]}],
            },
        },
        identity_resolver=StaticIdentityResolver(
            {
                "schema": 1,
                "bindings": [
                    {
                        "provider": "test",
                        "subject": "alice-source",
                        "principal": "alice",
                    }
                ],
            }
        ),
        executor_call=client.call,
    )

    result = gateway.invoke(
        SourceContext("test", "alice-source", "gateway-e2e"),
        "demo.status",
    )
    thread.join(2)
    assert result == {"ok": True, "principal": "alice", "resource": "demo:api"}


def test_confirmed_gateway_marks_real_executor_handler_failure_uncertain(tmp_path):
    from secure_ops_gateway.gateway import ConfirmationRequired, Gateway
    from secure_ops_gateway.identity import SourceContext, StaticIdentityResolver
    from secure_ops_gateway.operation_guard import SQLiteOperationGuard

    path = private_socket_path(tmp_path)
    errors = []

    def fail(_invocation):
        raise RuntimeError("simulated target failure")

    server = UnixSocketExecutorServer(
        path,
        KEY,
        {"demo.restart": fail},
        error_handler=errors.append,
    )
    client = UnixSocketExecutorClient(key_loader=lambda _credential: KEY)
    guard = SQLiteOperationGuard(tmp_path / "state" / "operations.sqlite3")
    identities = StaticIdentityResolver(
        {
            "schema": 1,
            "bindings": [
                {
                    "provider": "test",
                    "subject": "alice-source",
                    "principal": "alice",
                }
            ],
        }
    )
    gateway = Gateway(
        tools={
            "schema": 1,
            "tools": {
                "demo.restart": {
                    "capability": "demo.restart",
                    "permission": "demo.restart",
                    "resource": "demo:api",
                    "risk": "write",
                    "confirmation": "explicit",
                    "arguments": {},
                    "request": {"action": "restart"},
                }
            },
        },
        executors={
            "schema": 1,
            "executors": {
                "demo": {
                    "endpoint": f"unix:{path}",
                    "credential": "demo.key",
                    "capabilities": ["demo.restart"],
                }
            },
        },
        policy={
            "schema": 1,
            "roles": {
                "operator": {
                    "permissions": ["demo.restart"],
                    "max_risk": "write",
                }
            },
            "bindings": {
                "alice": [{"role": "operator", "resources": ["demo:*"]}],
            },
        },
        identity_resolver=identities,
        executor_call=client.call,
        operation_guard=guard,
    )
    source = SourceContext("test", "alice-source", "mutation-1")
    with pytest.raises(ConfirmationRequired) as challenge:
        gateway.invoke(source, "demo.restart")
    token = challenge.value.challenge["confirmation_token"]

    thread = threading.Thread(target=server.serve_once, daemon=True)
    thread.start()
    wait_for_path(path)
    with pytest.raises(ExecutorError, match="invalid JSON"):
        gateway.invoke(
            source,
            "demo.restart",
            confirmed=True,
            confirmation_token=token,
        )
    thread.join(2)

    context = gateway._resolve_context(source)
    assert guard.status(token, context)["status"] == "uncertain"
    assert any("simulated target failure" in str(exc) for exc in errors)
