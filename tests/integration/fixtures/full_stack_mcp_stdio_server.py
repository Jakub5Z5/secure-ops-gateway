from __future__ import annotations

import sys
import tempfile
import threading
from pathlib import Path

from secure_ops_gateway import (
    Gateway,
    MCPAdapter,
    MCPStdioServer,
    MCPTrustedSource,
    SQLiteReplayProtector,
    StaticIdentityResolver,
    UnixSocketExecutorClient,
    UnixSocketExecutorServer,
)
from secure_ops_gateway.executor import ExecutorError, ExecutorInvocation
from secure_ops_gateway.operation_guard import SQLiteOperationGuard

KEY = b"full-stack-integration-key-material!!"

TOOLS = {
    "schema": 1,
    "tools": {
        "demo.status": {
            "capability": "demo.status",
            "permission": "demo.read",
            "resource": "demo:api",
            "risk": "read",
            "confirmation": "none",
            "description": "Read the demo service status through the real executor channel.",
            "arguments": {},
            "request": {"action": "status", "service": "api"},
        },
        "demo.restart": {
            "capability": "demo.restart",
            "permission": "demo.restart",
            "resource": "demo:{service}",
            "risk": "write",
            "confirmation": "explicit",
            "description": "Restart an allowlisted demo service through the real executor channel.",
            "arguments": {
                "service": {
                    "type": "string",
                    "required": True,
                    "enum": ["api"],
                }
            },
            "request": {"action": "restart", "service": "$arg:service"},
        },
    },
}

POLICY = {
    "schema": 1,
    "roles": {
        "operator": {
            "permissions": ["demo.read", "demo.restart"],
            "max_risk": "write",
        }
    },
    "bindings": {
        "full-stack-user": [
            {"role": "operator", "resources": ["demo:*"]},
        ]
    },
}

IDENTITIES = StaticIdentityResolver(
    {
        "schema": 1,
        "bindings": [
            {
                "provider": "stdio",
                "subject": "official-sdk-full-stack",
                "principal": "full-stack-user",
            }
        ],
    }
)

_restart_count = 0


def _validate(invocation: ExecutorInvocation, *, action: str) -> None:
    expected = {"action": action, "service": "api"}
    if invocation.request != expected:
        raise ExecutorError("unexpected integration request")
    if invocation.resource != "demo:api":
        raise ExecutorError("unexpected integration resource")


def status(invocation: ExecutorInvocation) -> dict:
    _validate(invocation, action="status")
    return {
        "ok": True,
        "action": "status",
        "resource": invocation.resource,
        "capability": invocation.capability,
        "principal": invocation.principal_id,
        "source_provider": invocation.source_provider,
        "source_subject": invocation.source_subject,
    }


def restart(invocation: ExecutorInvocation) -> dict:
    global _restart_count
    _validate(invocation, action="restart")
    _restart_count += 1
    return {
        "ok": True,
        "action": "restart",
        "resource": invocation.resource,
        "capability": invocation.capability,
        "principal": invocation.principal_id,
        "source_provider": invocation.source_provider,
        "source_subject": invocation.source_subject,
        "restart_count": _restart_count,
    }


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="secure-ops-gateway-full-stack-") as temp:
        root = Path(temp)
        socket_path = root / "executor" / "executor.sock"
        stop_event = threading.Event()
        ready_event = threading.Event()
        executor = UnixSocketExecutorServer(
            socket_path,
            KEY,
            {
                "demo.status": status,
                "demo.restart": restart,
            },
            replay_protector=SQLiteReplayProtector(
                root / "executor-state" / "replay.sqlite3"
            ),
            accept_poll_seconds=0.02,
        )
        executor_thread = threading.Thread(
            target=executor.serve_forever,
            kwargs={"stop_event": stop_event, "ready_event": ready_event},
            daemon=True,
        )
        executor_thread.start()
        if not ready_event.wait(2):
            raise RuntimeError("executor did not become ready")

        executors = {
            "schema": 1,
            "executors": {
                "demo": {
                    "endpoint": f"unix:{socket_path}",
                    "credential": "integration.key",
                    "capabilities": ["demo.status", "demo.restart"],
                }
            },
        }
        def key_loader(credential: str) -> bytes:
            if credential != "integration.key":
                raise ExecutorError("unexpected credential")
            return KEY

        client = UnixSocketExecutorClient(key_loader=key_loader)
        guard = SQLiteOperationGuard(root / "state" / "operations.sqlite3")
        gateway = Gateway(
            tools=TOOLS,
            executors=executors,
            policy=POLICY,
            identity_resolver=IDENTITIES,
            executor_call=client.call,
            operation_guard=guard,
        )
        adapter = MCPAdapter(
            gateway,
            server_name="secure-ops-gateway-full-stack",
            server_version="0.2.0-dev",
        )
        server = MCPStdioServer(
            adapter,
            trusted_source=MCPTrustedSource(
                "stdio",
                "official-sdk-full-stack",
            ),
        )
        try:
            server.serve(sys.stdin.buffer, sys.stdout.buffer)
        finally:
            stop_event.set()
            executor_thread.join(2)
            if executor_thread.is_alive():
                raise RuntimeError("executor thread did not stop")


if __name__ == "__main__":
    main()
