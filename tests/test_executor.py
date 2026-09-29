import pytest
from secure_ops_gateway.executor import (
    ExecutorError,
    ReplayCache,
    sign_envelope,
    sign_response,
    verify_envelope,
    verify_response_envelope,
)

KEY = b"k" * 32


def test_hmac_envelope_round_trip_requires_replay_protection():
    envelope = sign_envelope({"action": "status"}, KEY, timestamp=100, nonce="a" * 32)
    cache = ReplayCache(max_age_seconds=60)
    assert verify_envelope(envelope, KEY, now=100, replay_protector=cache) == {"action": "status"}


def test_hmac_envelope_detects_tampering():
    envelope = sign_envelope({"action": "status"}, KEY, timestamp=100, nonce="a" * 32)
    envelope["payload"] = {"action": "restart"}
    with pytest.raises(ExecutorError):
        verify_envelope(envelope, KEY, now=100, replay_protector=ReplayCache())


def test_replay_cache_rejects_reused_nonce():
    envelope = sign_envelope({"action": "status"}, KEY, timestamp=100, nonce="b" * 32)
    cache = ReplayCache(max_age_seconds=60)
    assert verify_envelope(envelope, KEY, now=100, replay_protector=cache) == {"action": "status"}
    with pytest.raises(ExecutorError):
        verify_envelope(envelope, KEY, now=100, replay_protector=cache)


def test_verification_rejects_missing_replay_protection():
    envelope = sign_envelope({"action": "status"}, KEY, timestamp=100, nonce="c" * 32)
    with pytest.raises(ExecutorError, match="replay protection is required"):
        verify_envelope(envelope, KEY, now=100, replay_protector=None)


def test_nonce_format_is_strict():
    with pytest.raises(ExecutorError):
        sign_envelope({"action": "status"}, KEY, timestamp=100, nonce="Z" * 32)


def test_replay_cache_retention_must_cover_authentication_window():
    envelope = sign_envelope({"action": "status"}, KEY, timestamp=100, nonce="d" * 32)
    with pytest.raises(ExecutorError, match="retention"):
        verify_envelope(
            envelope,
            KEY,
            now=100,
            max_skew_seconds=30,
            replay_protector=ReplayCache(max_age_seconds=10),
        )



def test_response_envelope_is_authenticated_and_bound_to_request_id():
    envelope = sign_response(
        "request-1",
        {"ok": True},
        KEY,
        timestamp=100,
        nonce="e" * 32,
    )
    assert verify_response_envelope(
        envelope,
        KEY,
        request_id="request-1",
        replay_protector=ReplayCache(),
        now=100,
    ) == {"ok": True}


def test_response_envelope_rejects_wrong_request_id_and_request_reflection():
    envelope = sign_response(
        "request-1",
        {"ok": True},
        KEY,
        timestamp=100,
        nonce="f" * 32,
    )
    with pytest.raises(ExecutorError, match="does not match"):
        verify_response_envelope(
            envelope,
            KEY,
            request_id="request-2",
            replay_protector=ReplayCache(),
            now=100,
        )

    request = sign_envelope(
        {"request_id": "request-1"},
        KEY,
        purpose="request",
        timestamp=100,
        nonce="1" * 32,
    )
    with pytest.raises(ExecutorError, match="purpose"):
        verify_response_envelope(
            request,
            KEY,
            request_id="request-1",
            replay_protector=ReplayCache(),
            now=100,
        )


def test_unix_socket_client_requires_authenticated_bound_response(tmp_path):
    import json
    import socket
    import threading

    from secure_ops_gateway.executor import UnixSocketExecutorClient

    path = tmp_path / "executor.sock"
    ready = threading.Event()

    def server():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            listener.listen(1)
            ready.set()
            conn, _ = listener.accept()
            with conn:
                line = b""
                while b"\n" not in line:
                    line += conn.recv(65536)
                request_envelope = json.loads(line.split(b"\n", 1)[0])
                request = verify_envelope(
                    request_envelope,
                    KEY,
                    replay_protector=ReplayCache(),
                    expected_purpose="request",
                )
                response = sign_response(
                    request["request_id"],
                    {"ok": True},
                    KEY,
                )
                conn.sendall(json.dumps(response).encode() + b"\n")

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(2)
    client = UnixSocketExecutorClient(key_loader=lambda _name: KEY)
    result = client.call(
        {
            "endpoint": f"unix:{path}",
            "credential": "executor.key",
        },
        {"request_id": "socket-1", "action": "status"},
    )
    thread.join(2)
    assert result == {"ok": True}


def test_unix_socket_client_rejects_unsigned_response(tmp_path):
    import json
    import socket
    import threading

    from secure_ops_gateway.executor import UnixSocketExecutorClient

    path = tmp_path / "executor.sock"
    ready = threading.Event()

    def server():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            listener.listen(1)
            ready.set()
            conn, _ = listener.accept()
            with conn:
                while b"\n" not in conn.recv(65536):
                    pass
                conn.sendall(json.dumps({"ok": True}).encode() + b"\n")

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(2)
    client = UnixSocketExecutorClient(key_loader=lambda _name: KEY)
    with pytest.raises(ExecutorError, match="authenticated envelope"):
        client.call(
            {
                "endpoint": f"unix:{path}",
                "credential": "executor.key",
            },
            {"request_id": "socket-2", "action": "status"},
        )
    thread.join(2)
