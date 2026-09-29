from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import socket
import time
from dataclasses import dataclass, field
import threading
from typing import Callable, Protocol


class ExecutorError(RuntimeError):
    pass


_NONCE = re.compile(r"^[0-9a-f]{32}$")
_PURPOSES = {"request", "response"}


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
