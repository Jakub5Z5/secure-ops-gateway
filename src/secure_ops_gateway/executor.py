from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
import threading
from typing import Callable, Mapping, Protocol

from .paths import (
    SecurePathError,
    prepare_private_parent,
    private_parent_identity,
    reject_symlink_leaf,
    verify_private_parent_identity,
)


class ExecutorError(RuntimeError):
    pass


_NONCE = re.compile(r"^[0-9a-f]{32}$")
_PURPOSES = {"request", "response"}
_CAPABILITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def canonical_json(value: dict) -> bytes:
    if not isinstance(value, dict):
        raise ExecutorError("executor payload must be an object")
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def sign_envelope(
    payload: dict,
    key: bytes,
    *,
    purpose: str = "request",
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict:
    if not isinstance(key, (bytes, bytearray)) or len(key) < 32:
        raise ExecutorError("executor key must contain at least 32 bytes")
    if purpose not in _PURPOSES:
        raise ExecutorError("invalid executor envelope purpose")
    ts = int(time.time()) if timestamp is None else int(timestamp)
    token = secrets.token_hex(16) if nonce is None else nonce
    if not isinstance(token, str) or not _NONCE.fullmatch(token):
        raise ExecutorError(
            "executor nonce must be 32 lowercase hexadecimal characters"
        )
    message = (
        b"secure-ops-gateway-envelope-v1\n"
        + purpose.encode("ascii")
        + b"\n"
        + str(ts).encode("ascii")
        + b"\n"
        + token.encode("ascii")
        + b"\n"
        + canonical_json(payload)
    )
    mac = hmac.new(bytes(key), message, hashlib.sha256).hexdigest()
    return {
        "schema": 1,
        "purpose": purpose,
        "timestamp": ts,
        "nonce": token,
        "payload": payload,
        "mac": mac,
    }


class ReplayProtector(Protocol):
    def accept(
        self,
        nonce: str,
        timestamp: int,
        *,
        now: int | None = None,
    ) -> None: ...


@dataclass
class ReplayCache:
    """Single-process replay cache.

    Multi-process or restart-resistant deployments should supply a
    durable/shared ReplayProtector implementation instead.
    """

    max_age_seconds: int = 60
    _seen: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_age_seconds, bool)
            or not isinstance(self.max_age_seconds, int)
            or self.max_age_seconds < 1
        ):
            raise ValueError("max_age_seconds must be a positive integer")

    def accept(
        self,
        nonce: str,
        timestamp: int,
        *,
        now: int | None = None,
    ) -> None:
        current = int(time.time()) if now is None else int(now)
        with self._lock:
            cutoff = current - self.max_age_seconds
            self._seen = {
                key: value
                for key, value in self._seen.items()
                if value >= cutoff
            }
            if nonce in self._seen:
                raise ExecutorError("authenticated envelope replayed")
            self._seen[nonce] = timestamp


class SQLiteReplayProtector:
    """Durable same-host replay protection backed by SQLite.

    The database may be shared by multiple executor processes using the same
    authenticated channel. Nonce admission is serialized with ``BEGIN
    IMMEDIATE`` and a unique primary key, so concurrent attempts to accept the
    same nonce cannot both succeed. The state file uses the same private-path
    ownership and replacement checks as other security-sensitive gateway state.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        max_age_seconds: int = 60,
        timeout_seconds: float = 5.0,
    ) -> None:
        if (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, int)
            or max_age_seconds < 1
        ):
            raise ValueError("max_age_seconds must be a positive integer")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")
        try:
            self.path = prepare_private_parent(path)
            self._parent_identity = private_parent_identity(self.path)
        except SecurePathError as exc:
            raise ExecutorError("replay database parent is unsafe") from exc
        self.max_age_seconds = max_age_seconds
        self.timeout_seconds = float(timeout_seconds)
        self._ensure_private_database_file()
        with self._database() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS replay_nonces (
                    nonce TEXT PRIMARY KEY,
                    envelope_timestamp INTEGER NOT NULL
                )"""
            )
            db.execute(
                """CREATE INDEX IF NOT EXISTS replay_nonces_timestamp_idx
                   ON replay_nonces(envelope_timestamp)"""
            )
        self._enforce_private_permissions()
        self.cleanup()

    def _ensure_private_database_file(self) -> None:
        try:
            prepare_private_parent(self.path)
            verify_private_parent_identity(self.path, self._parent_identity)
            reject_symlink_leaf(self.path)
        except SecurePathError as exc:
            raise ExecutorError("replay database path is unsafe") from exc
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags, 0o600)
        except FileExistsError:
            try:
                reject_symlink_leaf(self.path)
                self._enforce_private_permissions()
            except SecurePathError as exc:
                raise ExecutorError("replay database path is unsafe") from exc
        except OSError as exc:
            raise ExecutorError("cannot create replay database safely") from exc
        else:
            os.close(fd)

    def _enforce_private_permissions(self) -> None:
        try:
            prepare_private_parent(self.path)
            verify_private_parent_identity(self.path, self._parent_identity)
            reject_symlink_leaf(self.path)
            os.chmod(self.path, 0o600, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except (OSError, SecurePathError) as exc:
            raise ExecutorError("replay database path is unsafe") from exc

    def _connect(self):
        try:
            prepare_private_parent(self.path)
            verify_private_parent_identity(self.path, self._parent_identity)
            reject_symlink_leaf(self.path)
        except SecurePathError as exc:
            raise ExecutorError("replay database path is unsafe") from exc
        self._enforce_private_permissions()
        connection = sqlite3.connect(self.path, timeout=self.timeout_seconds)
        try:
            reject_symlink_leaf(self.path)
            self._enforce_private_permissions()
        except Exception:
            connection.close()
            raise
        return connection

    @contextmanager
    def _database(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def cleanup(self, *, now: int | None = None) -> int:
        current = int(time.time()) if now is None else int(now)
        cutoff = current - self.max_age_seconds
        with self._database() as db:
            cursor = db.execute(
                "DELETE FROM replay_nonces WHERE envelope_timestamp < ?",
                (cutoff,),
            )
            return cursor.rowcount

    def accept(
        self,
        nonce: str,
        timestamp: int,
        *,
        now: int | None = None,
    ) -> None:
        if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
            raise ExecutorError(
                "executor nonce must be 32 lowercase hexadecimal characters"
            )
        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            raise ExecutorError("executor timestamp must be an integer")
        current = int(time.time()) if now is None else int(now)
        cutoff = current - self.max_age_seconds
        with self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "DELETE FROM replay_nonces WHERE envelope_timestamp < ?",
                (cutoff,),
            )
            try:
                db.execute(
                    "INSERT INTO replay_nonces(nonce, envelope_timestamp) VALUES (?, ?)",
                    (nonce, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise ExecutorError("authenticated envelope replayed") from exc
        self._enforce_private_permissions()


def verify_envelope(
    envelope: dict,
    key: bytes,
    *,
    replay_protector: ReplayProtector,
    expected_purpose: str = "request",
    max_skew_seconds: int = 30,
    now: int | None = None,
) -> dict:
    if replay_protector is None:
        raise ExecutorError("replay protection is required")
    if expected_purpose not in _PURPOSES:
        raise ExecutorError("invalid expected envelope purpose")
    if (
        isinstance(max_skew_seconds, bool)
        or not isinstance(max_skew_seconds, int)
        or max_skew_seconds < 0
    ):
        raise ExecutorError("max_skew_seconds must be a non-negative integer")
    retention = getattr(replay_protector, "max_age_seconds", None)
    if isinstance(retention, int) and retention < max_skew_seconds:
        raise ExecutorError(
            "replay protection retention is shorter than the authentication window"
        )
    if not isinstance(envelope, dict) or set(envelope) != {
        "schema",
        "purpose",
        "timestamp",
        "nonce",
        "payload",
        "mac",
    }:
        raise ExecutorError("invalid authenticated envelope")
    if envelope.get("schema") != 1:
        raise ExecutorError("unsupported authenticated envelope")
    purpose = envelope["purpose"]
    ts = envelope["timestamp"]
    nonce = envelope["nonce"]
    payload = envelope["payload"]
    mac = envelope["mac"]
    if purpose != expected_purpose:
        raise ExecutorError("unexpected authenticated envelope purpose")
    if (
        isinstance(ts, bool)
        or not isinstance(ts, int)
        or not isinstance(nonce, str)
        or not _NONCE.fullmatch(nonce)
    ):
        raise ExecutorError("invalid authenticated envelope metadata")
    if not isinstance(payload, dict):
        raise ExecutorError("authenticated envelope payload must be an object")
    current = int(time.time()) if now is None else int(now)
    if abs(current - ts) > max_skew_seconds:
        raise ExecutorError("authenticated envelope expired")
    expected = sign_envelope(
        payload,
        key,
        purpose=purpose,
        timestamp=ts,
        nonce=nonce,
    )["mac"]
    if not isinstance(mac, str) or not hmac.compare_digest(expected, mac):
        raise ExecutorError("executor authentication failed")
    replay_protector.accept(nonce, ts, now=current)
    return payload


def sign_response(
    request_id: str,
    response: dict,
    key: bytes,
    *,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict:
    if not isinstance(request_id, str) or not request_id:
        raise ExecutorError("response request_id must be a non-empty string")
    if not isinstance(response, dict):
        raise ExecutorError("executor response must be an object")
    return sign_envelope(
        {
            "schema": 1,
            "request_id": request_id,
            "response": response,
        },
        key,
        purpose="response",
        timestamp=timestamp,
        nonce=nonce,
    )


def verify_response_envelope(
    envelope: dict,
    key: bytes,
    *,
    request_id: str,
    replay_protector: ReplayProtector,
    max_skew_seconds: int = 30,
    now: int | None = None,
) -> dict:
    payload = verify_envelope(
        envelope,
        key,
        replay_protector=replay_protector,
        expected_purpose="response",
        max_skew_seconds=max_skew_seconds,
        now=now,
    )
    if set(payload) != {"schema", "request_id", "response"} or payload.get("schema") != 1:
        raise ExecutorError("invalid authenticated executor response")
    if payload.get("request_id") != request_id:
        raise ExecutorError("executor response does not match request")
    response = payload.get("response")
    if not isinstance(response, dict):
        raise ExecutorError("executor response payload must be an object")
    return response


@dataclass(frozen=True)
class ExecutorInvocation:
    """Validated request passed to an executor capability handler.

    Every field in this object came from an authenticated gateway envelope.
    The executor still treats the nested service-specific ``request`` object as
    untrusted application input and should validate it according to the
    capability's own contract.
    """

    request_id: str
    principal_id: str
    source_provider: str
    source_subject: str
    capability: str
    permission: str
    risk: str
    resource: str
    request: dict

    @classmethod
    def from_payload(cls, payload: dict) -> "ExecutorInvocation":
        expected = {
            "schema",
            "request_id",
            "principal_id",
            "source",
            "capability",
            "permission",
            "risk",
            "resource",
            "request",
        }
        if not isinstance(payload, dict) or set(payload) != expected:
            raise ExecutorError("invalid executor request payload")
        if payload.get("schema") != 1:
            raise ExecutorError("unsupported executor request payload")

        source = payload.get("source")
        if not isinstance(source, dict) or set(source) != {"provider", "subject"}:
            raise ExecutorError("invalid executor source metadata")

        values = {
            "request_id": payload.get("request_id"),
            "principal_id": payload.get("principal_id"),
            "source_provider": source.get("provider"),
            "source_subject": source.get("subject"),
            "capability": payload.get("capability"),
            "permission": payload.get("permission"),
            "risk": payload.get("risk"),
            "resource": payload.get("resource"),
        }
        if not all(isinstance(value, str) and value for value in values.values()):
            raise ExecutorError("invalid executor request metadata")
        if not _CAPABILITY.fullmatch(values["capability"]):
            raise ExecutorError("invalid executor capability")
        if values["risk"] not in {"read", "write", "privileged"}:
            raise ExecutorError("invalid executor risk")
        request = payload.get("request")
        if not isinstance(request, dict):
            raise ExecutorError("executor request body must be an object")

        return cls(request=request, **values)


class CapabilityRouter:
    """Exact-match allowlist from capability names to executor handlers."""

    def __init__(self, handlers: Mapping[str, Callable[[ExecutorInvocation], dict]]):
        if not isinstance(handlers, Mapping) or not handlers:
            raise ValueError("executor handlers must be a non-empty mapping")
        validated: dict[str, Callable[[ExecutorInvocation], dict]] = {}
        for capability, handler in handlers.items():
            if not isinstance(capability, str) or not _CAPABILITY.fullmatch(capability):
                raise ValueError("invalid executor capability name")
            if not callable(handler):
                raise TypeError(f"handler for {capability!r} must be callable")
            validated[capability] = handler
        self._handlers = validated

    @property
    def capabilities(self) -> tuple[str, ...]:
        return tuple(sorted(self._handlers))

    def dispatch(self, invocation: ExecutorInvocation) -> dict:
        if not isinstance(invocation, ExecutorInvocation):
            raise TypeError("invocation must be ExecutorInvocation")
        try:
            handler = self._handlers[invocation.capability]
        except KeyError as exc:
            raise ExecutorError("unsupported executor capability") from exc
        response = handler(invocation)
        if not isinstance(response, dict):
            raise ExecutorError("executor handler must return an object")
        return response


class UnixSocketExecutorServer:
    """Authenticated single-request-per-connection Unix socket executor.

    The server owns only an exact capability allowlist. It verifies the
    gateway's HMAC-authenticated request envelope with replay protection,
    validates the common executor payload, dispatches one handler, and returns
    a response envelope cryptographically bound to the request ID.

    A failed or unauthenticated request receives no signed response. This is
    deliberate: for a mutating operation the gateway must treat transport or
    handler failure as an uncertain outcome rather than as a successful
    operation with an error-looking response body.
    """

    def __init__(
        self,
        path: str | Path,
        key: bytes,
        handlers: Mapping[str, Callable[[ExecutorInvocation], dict]],
        *,
        replay_protector: ReplayProtector | None = None,
        max_skew_seconds: int = 30,
        max_request_bytes: int = 1024 * 1024,
        max_response_bytes: int = 1024 * 1024,
        connection_timeout_seconds: float = 10.0,
        accept_poll_seconds: float = 0.25,
        backlog: int = 16,
        error_handler: Callable[[Exception], None] | None = None,
    ):
        if os.name != "posix":
            raise ExecutorError("Unix socket executor server requires a POSIX platform")
        if not isinstance(key, (bytes, bytearray)) or len(key) < 32:
            raise ExecutorError("executor key must contain at least 32 bytes")
        if (
            isinstance(max_skew_seconds, bool)
            or not isinstance(max_skew_seconds, int)
            or max_skew_seconds < 0
        ):
            raise ValueError("max_skew_seconds must be a non-negative integer")
        for name, value in {
            "max_request_bytes": max_request_bytes,
            "max_response_bytes": max_response_bytes,
            "backlog": backlog,
        }.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name, value in {
            "connection_timeout_seconds": connection_timeout_seconds,
            "accept_poll_seconds": accept_poll_seconds,
        }.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or value <= 0
            ):
                raise ValueError(f"{name} must be positive")
        if error_handler is not None and not callable(error_handler):
            raise TypeError("error_handler must be callable")

        try:
            self.path = prepare_private_parent(path)
            self._parent_identity = private_parent_identity(self.path)
        except SecurePathError as exc:
            raise ExecutorError("executor socket parent is unsafe") from exc
        self.key = bytes(key)
        self.router = CapabilityRouter(handlers)
        self.replay_protector = (
            ReplayCache() if replay_protector is None else replay_protector
        )
        self.max_skew_seconds = max_skew_seconds
        self.max_request_bytes = max_request_bytes
        self.max_response_bytes = max_response_bytes
        self.connection_timeout_seconds = float(connection_timeout_seconds)
        self.accept_poll_seconds = float(accept_poll_seconds)
        self.backlog = backlog
        self.error_handler = error_handler
        self._serve_lock = threading.Lock()

    @property
    def capabilities(self) -> tuple[str, ...]:
        return self.router.capabilities

    def handle_envelope(self, envelope: dict) -> dict:
        payload = verify_envelope(
            envelope,
            self.key,
            replay_protector=self.replay_protector,
            expected_purpose="request",
            max_skew_seconds=self.max_skew_seconds,
        )
        invocation = ExecutorInvocation.from_payload(payload)
        response = self.router.dispatch(invocation)
        return sign_response(invocation.request_id, response, self.key)

    def _report_error(self, exc: Exception) -> None:
        if self.error_handler is None:
            return
        try:
            self.error_handler(exc)
        except Exception:
            pass

    def _read_request(self, connection: socket.socket) -> dict:
        chunks = bytearray()
        while True:
            chunk = connection.recv(min(65536, self.max_request_bytes + 1))
            if not chunk:
                raise ExecutorError("executor request was not newline terminated")
            chunks.extend(chunk)
            newline = chunks.find(b"\n")
            if newline >= 0:
                if newline > self.max_request_bytes:
                    raise ExecutorError("executor request too large")
                line = bytes(chunks[:newline])
                break
            if len(chunks) > self.max_request_bytes:
                raise ExecutorError("executor request too large")
        try:
            message = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExecutorError("executor request is invalid JSON") from exc
        if not isinstance(message, dict):
            raise ExecutorError("executor request envelope must be an object")
        return message

    def _serve_connection(self, connection: socket.socket) -> None:
        connection.settimeout(self.connection_timeout_seconds)
        envelope = self._read_request(connection)
        response = self.handle_envelope(envelope)
        raw = canonical_json(response) + b"\n"
        if len(raw) > self.max_response_bytes:
            raise ExecutorError("executor response too large")
        connection.sendall(raw)

    @contextmanager
    def _listener(self):
        try:
            verify_private_parent_identity(self.path, self._parent_identity)
        except SecurePathError as exc:
            raise ExecutorError("executor socket parent was replaced") from exc
        try:
            metadata = os.lstat(self.path)
        except FileNotFoundError:
            metadata = None
        if metadata is not None:
            raise ExecutorError("executor socket path already exists")

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        socket_identity = None
        try:
            listener.bind(str(self.path))
            metadata = os.lstat(self.path)
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise ExecutorError("executor socket path is unsafe")
            socket_identity = (metadata.st_dev, metadata.st_ino, metadata.st_uid)
            os.chmod(self.path, 0o600, follow_symlinks=False)
            metadata = os.lstat(self.path)
            if (
                not stat.S_ISSOCK(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino, metadata.st_uid) != socket_identity
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise ExecutorError("executor socket path is unsafe")
            listener.listen(self.backlog)
            listener.settimeout(self.accept_poll_seconds)
            yield listener
        finally:
            listener.close()
            if socket_identity is not None:
                try:
                    verify_private_parent_identity(self.path, self._parent_identity)
                    current = os.lstat(self.path)
                except (FileNotFoundError, SecurePathError):
                    current = None
                if (
                    current is not None
                    and stat.S_ISSOCK(current.st_mode)
                    and (current.st_dev, current.st_ino, current.st_uid) == socket_identity
                ):
                    os.unlink(self.path)

    @staticmethod
    def _validate_ready_event(ready_event) -> None:
        if ready_event is not None and not callable(getattr(ready_event, "set", None)):
            raise TypeError("ready_event must expose set()")

    def serve_once(self, *, ready_event=None) -> None:
        """Bind the socket, signal readiness, process one connection, and clean up."""

        self._validate_ready_event(ready_event)
        if not self._serve_lock.acquire(blocking=False):
            raise ExecutorError("executor server is already running")
        try:
            with self._listener() as listener:
                if ready_event is not None:
                    ready_event.set()
                listener.settimeout(self.connection_timeout_seconds)
                connection, _ = listener.accept()
                with connection:
                    try:
                        self._serve_connection(connection)
                    except Exception as exc:
                        self._report_error(exc)
        finally:
            self._serve_lock.release()

    def serve_forever(self, *, stop_event=None, ready_event=None) -> None:
        """Serve connections until ``stop_event`` is set.

        ``stop_event`` may be any object exposing ``is_set()``. ``ready_event``
        may expose ``set()`` and is signalled only after the Unix socket is
        listening, so supervisors and tests do not need to infer readiness from
        the socket path alone. When ``stop_event`` is omitted, the server runs
        until interrupted. Per-connection errors are isolated and reported
        through ``error_handler`` without stopping the listener.
        """

        if stop_event is not None and not callable(getattr(stop_event, "is_set", None)):
            raise TypeError("stop_event must expose is_set()")
        self._validate_ready_event(ready_event)
        if not self._serve_lock.acquire(blocking=False):
            raise ExecutorError("executor server is already running")
        try:
            with self._listener() as listener:
                if ready_event is not None:
                    ready_event.set()
                while stop_event is None or not stop_event.is_set():
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        try:
                            self._serve_connection(connection)
                        except Exception as exc:
                            self._report_error(exc)
        finally:
            self._serve_lock.release()


@dataclass(frozen=True)
class UnixSocketExecutorClient:
    key_loader: Callable[[str], bytes]
    timeout_seconds: float = 10.0
    max_response_bytes: int = 1024 * 1024
    response_replay_protector: ReplayProtector = field(
        default_factory=ReplayCache,
        compare=False,
    )

    def call(self, route: dict, payload: dict) -> dict:
        credential = route.get("credential")
        if not isinstance(credential, str) or not credential:
            raise ExecutorError("executor credential is not configured")
        key = self.key_loader(credential)
        envelope = sign_envelope(payload, key, purpose="request")
        raw = canonical_json(envelope) + b"\n"

        endpoint = route.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint.startswith("unix:"):
            raise ExecutorError(
                "only unix: endpoints are supported by the built-in client"
            )
        path = endpoint[5:]

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(self.timeout_seconds)
            client.connect(path)
            client.sendall(raw)
            chunks = bytearray()
            while b"\n" not in chunks:
                chunk = client.recv(65536)
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > self.max_response_bytes:
                    raise ExecutorError("executor response too large")

        line = bytes(chunks).split(b"\n", 1)[0]
        try:
            response_envelope = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExecutorError("executor returned invalid JSON") from exc
        request_id = payload.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            raise ExecutorError("executor request is missing request_id")
        return verify_response_envelope(
            response_envelope,
            key,
            request_id=request_id,
            replay_protector=self.response_replay_protector,
        )
