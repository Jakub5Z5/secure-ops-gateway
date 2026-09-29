from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from secure_ops_gateway import (
    Gateway,
    MCPAdapter,
    MCPStdioServer,
    MCPTrustedSource,
    StaticIdentityResolver,
)
from secure_ops_gateway.operation_guard import SQLiteOperationGuard

TOOLS = {
    "schema": 1,
    "tools": {
        "demo.status": {
            "capability": "demo.status",
            "permission": "demo.read",
            "resource": "demo:api",
            "risk": "read",
            "confirmation": "none",
            "description": "Read the demo service status.",
            "arguments": {},
            "request": {"action": "status", "service": "api"},
        },
        "demo.restart": {
            "capability": "demo.restart",
            "permission": "demo.restart",
            "resource": "demo:{service}",
            "risk": "write",
            "confirmation": "explicit",
            "description": "Restart an allowed demo service.",
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

EXECUTORS = {
    "schema": 1,
    "executors": {
        "demo": {
            "endpoint": "unix:/unused/official-sdk-compat.sock",
            "credential": "unused.key",
            "capabilities": ["demo.status", "demo.restart"],
        }
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
        "official-sdk-user": [
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
                "subject": "official-sdk",
                "principal": "official-sdk-user",
            }
        ],
    }
)


def executor_call(_route: dict, payload: dict) -> dict:
    return {
        "ok": True,
        "action": payload["request"]["action"],
        "resource": payload["resource"],
    }


def main() -> None:
    state_dir = tempfile.TemporaryDirectory(prefix="secure-ops-gateway-mcp-")
    guard = SQLiteOperationGuard(Path(state_dir.name) / "operations.sqlite3")
    gateway = Gateway(
        tools=TOOLS,
        executors=EXECUTORS,
        policy=POLICY,
        identity_resolver=IDENTITIES,
        executor_call=executor_call,
        operation_guard=guard,
    )
    adapter = MCPAdapter(
        gateway,
        server_name="secure-ops-gateway-compat",
        server_version="0.2.0-dev",
    )
    server = MCPStdioServer(
        adapter,
        trusted_source=MCPTrustedSource("stdio", "official-sdk"),
    )
    try:
        server.serve(sys.stdin.buffer, sys.stdout.buffer)
    finally:
        state_dir.cleanup()


if __name__ == "__main__":
    main()
