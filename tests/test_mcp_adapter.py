import json

import pytest

from secure_ops_gateway.gateway import ConfirmationRequired, GatewayError
from secure_ops_gateway.identity import SourceContext
from secure_ops_gateway.mcp_adapter import (
    LEGACY_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
    MCPAdapter,
    MCPAdapterError,
    MCPConnectionState,
    MCPStdioServer,
    MCPTransportError,
    MCPTrustedSource,
)
from secure_ops_gateway.operation_guard import ConfirmationError
from secure_ops_gateway.registry import RegistryError


class FakeGateway:
    def __init__(self):
        self.tools = {
            "schema": 1,
            "tools": {
                "demo.status": {
                    "capability": "demo.status",
                    "permission": "demo.read",
                    "resource": "demo:status",
                    "risk": "read",
                    "confirmation": "none",
                    "arguments": {},
                    "request": {"action": "status"},
                },
                "demo.restart": {
                    "capability": "demo.restart",
                    "permission": "demo.restart",
                    "resource": "demo:{service}",
                    "risk": "write",
                    "confirmation": "explicit",
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
        self.catalog_sources = []
        self.invoke_calls = []
        self.next_error = None

    def catalog(self, source):
        self.catalog_sources.append(source)
        return [
            {
                "name": "demo.status",
                "description": "Read status",
                "risk": "read",
                "confirmation": "none",
                "arguments": {},
            },
            {
                "name": "demo.restart",
                "description": "Restart service",
                "risk": "write",
                "confirmation": "explicit",
                "arguments": {
                    "service": {
                        "type": "string",
                        "required": True,
                        "enum": ["api"],
                    }
                },
            },
        ]

    def invoke(self, source, name, arguments, *, confirmed=False, confirmation_token=None):
        self.invoke_calls.append(
            (source, name, arguments, confirmed, confirmation_token)
        )
        if self.next_error is not None:
            error = self.next_error
            self.next_error = None
            raise error
        return {"ok": True, "name": name}


@pytest.fixture
def trusted():
    return MCPTrustedSource("stdio", "host:test")


@pytest.fixture
def adapter(monkeypatch):
    gateway = FakeGateway()
    monkeypatch.setattr(
        "secure_ops_gateway.mcp_adapter.Gateway",
        FakeGateway,
    )
    return MCPAdapter(
        gateway,
        server_name="test-gateway",
        server_version="0.2-test",
        instructions="Use bounded tools only.",
        request_id_factory=lambda: "server-generated-request-id",
    )


def modern_meta():
    return {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": "test-client",
                "version": "1",
            },
        }
    }


def test_modern_discover(adapter, trusted):
    response = adapter.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": modern_meta(),
        },
        trusted_source=trusted,
    )
    assert response["result"]["supportedVersions"] == [
        MODERN_PROTOCOL_VERSION,
        LEGACY_PROTOCOL_VERSION,
    ]
    assert response["result"]["resultType"] == "complete"
    assert response["result"]["capabilities"] == {"tools": {}}
    assert response["result"]["cacheScope"] == "public"
    assert response["result"]["_meta"]["io.modelcontextprotocol/serverInfo"] == {
        "name": "test-gateway",
        "version": "0.2-test",
    }


def test_modern_rejects_unsupported_and_missing_metadata(adapter, trusted):
    wrong = modern_meta()
    wrong["_meta"]["io.modelcontextprotocol/protocolVersion"] = "1900-01-01"
    response = adapter.handle(
        {"jsonrpc": "2.0", "id": "x", "method": "tools/list", "params": wrong},
        trusted_source=trusted,
    )
    assert response["error"]["code"] == -32022
    assert response["error"]["data"]["requested"] == "1900-01-01"

    response = adapter.handle(
        {
            "jsonrpc": "2.0",
            "id": "x",
            "method": "server/discover",
            "params": {"_meta": {}},
        },
        trusted_source=trusted,
    )
    assert response["error"]["code"] == -32602


def test_modern_tools_list_uses_only_trusted_transport_identity(adapter, trusted):
    params = modern_meta()
    params["principal"] = "attacker-chosen"
    response = adapter.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": params},
        trusted_source=trusted,
    )
    assert response["error"]["code"] == -32602

    response = adapter.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": modern_meta(),
        },
        trusted_source=trusted,
    )
    assert response["result"]["cacheScope"] == "private"
    assert response["result"]["ttlMs"] == 0
    assert [tool["name"] for tool in response["result"]["tools"]] == [
        "demo.status",
        "demo.restart",
    ]
    source = adapter.gateway.catalog_sources[-1]
    assert source == SourceContext(
        "stdio",
        "host:test",
        "server-generated-request-id",
    )
    restart = response["result"]["tools"][1]
    assert restart["inputSchema"]["properties"]["confirmed"]["type"] == "boolean"
    assert "confirmation_token" in restart["inputSchema"]["properties"]


def test_modern_tool_call_returns_structured_and_text_content(adapter, trusted):
    params = modern_meta()
    params.update({"name": "demo.status", "arguments": {}})
    response = adapter.handle(
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": params},
        trusted_source=trusted,
    )
    assert response["result"]["resultType"] == "complete"
    assert response["result"]["structuredContent"] == {
        "ok": True,
        "name": "demo.status",
    }
    assert json.loads(response["result"]["content"][0]["text"])["ok"] is True


def test_confirmation_controls_are_stripped_before_gateway_invoke(adapter, trusted):
    params = modern_meta()
    params.update(
        {
            "name": "demo.restart",
            "arguments": {
                "service": "api",
                "confirmed": True,
                "confirmation_token": "token-123",
            },
        }
    )
    response = adapter.handle(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params},
        trusted_source=trusted,
    )
    assert response["result"].get("isError") is None
    source, name, arguments, confirmed, token = adapter.gateway.invoke_calls[-1]
    assert source.source_provider == "stdio"
    assert source.source_subject == "host:test"
    assert name == "demo.restart"
    assert arguments == {"service": "api"}
    assert confirmed is True
    assert token == "token-123"


def test_confirmation_required_is_returned_as_tool_result(adapter, trusted):
    adapter.gateway.next_error = ConfirmationRequired(
        {
            "confirmation_token": "abc",
            "expires_at_unix": 123,
            "tool": "demo.restart",
            "resource": "demo:api",
            "risk": "write",
        }
    )
    params = modern_meta()
    params.update({"name": "demo.restart", "arguments": {"service": "api"}})
    response = adapter.handle(
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": params},
        trusted_source=trusted,
    )
    result = response["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["status"] == "confirmation_required"
    assert result["structuredContent"]["confirmation_token"] == "abc"


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({"confirmed": "yes"}, "confirmed must be boolean"),
        ({"confirmation_token": 3}, "confirmation_token must be a string"),
        ({"confirmation_token": "abc"}, "confirmation_token requires confirmed=true"),
    ],
)
def test_invalid_confirmation_controls_return_tool_errors(adapter, trusted, arguments, message):
    params = modern_meta()
    params.update(
        {
            "name": "demo.restart",
            "arguments": {"service": "api", **arguments},
        }
    )
    response = adapter.handle(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params},
        trusted_source=trusted,
    )
    assert response["result"]["isError"] is True
    assert response["result"]["content"][0]["text"] == message


def test_confirmation_controls_rejected_for_non_confirming_tool(adapter, trusted):
    params = modern_meta()
    params.update(
        {
            "name": "demo.status",
            "arguments": {"confirmed": True, "confirmation_token": "abc"},
        }
    )
    response = adapter.handle(
        {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": params},
        trusted_source=trusted,
    )
    assert response["result"]["isError"] is True
    assert "not valid" in response["result"]["content"][0]["text"]


def test_unknown_tool_is_protocol_error(adapter, trusted):
    params = modern_meta()
    params.update({"name": "missing", "arguments": {}})
    response = adapter.handle(
        {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": params},
        trusted_source=trusted,
    )
    assert response["error"]["code"] == -32602
    assert response["error"]["message"] == "Unknown tool"


def test_gateway_errors_do_not_leak_authorization_details(adapter, trusted):
    from secure_ops_gateway.authorization import AuthorizationDenied

    adapter.gateway.next_error = AuthorizationDenied("secret policy detail")
    params = modern_meta()
    params.update({"name": "demo.status", "arguments": {}})
    response = adapter.handle(
        {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": params},
        trusted_source=trusted,
    )
    assert response["result"]["isError"] is True
    assert response["result"]["content"][0]["text"] == "Tool call denied"


def test_confirmation_registry_and_gateway_errors_are_tool_results(adapter, trusted):
    for error in (
        ConfirmationError("operation outcome is uncertain"),
        RegistryError("argument bad"),
        GatewayError("confirmation token is required"),
    ):
        adapter.gateway.next_error = error
        params = modern_meta()
        params.update({"name": "demo.status", "arguments": {}})
        response = adapter.handle(
            {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": params},
            trusted_source=trusted,
        )
        assert response["result"]["isError"] is True


def test_unexpected_exception_is_internal_error(adapter, trusted):
    adapter.gateway.next_error = RuntimeError("do not leak me")
    params = modern_meta()
    params.update({"name": "demo.status", "arguments": {}})
    response = adapter.handle(
        {"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": params},
        trusted_source=trusted,
    )
    assert response["error"] == {"code": -32603, "message": "Internal error"}


def test_legacy_handshake_tools_and_ping(adapter, trusted):
    state = MCPConnectionState()
    before = adapter.handle(
        {"jsonrpc": "2.0", "id": "a", "method": "tools/list", "params": {}},
        trusted_source=trusted,
        connection_state=state,
    )
    assert before["error"]["code"] == -32000

    initialized = adapter.handle(
        {
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize",
            "params": {
                "protocolVersion": LEGACY_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "legacy-client", "version": "1"},
            },
        },
        trusted_source=trusted,
        connection_state=state,
    )
    assert initialized["result"]["protocolVersion"] == LEGACY_PROTOCOL_VERSION
    assert initialized["result"]["serverInfo"]["name"] == "test-gateway"
    assert adapter.handle(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        trusted_source=trusted,
        connection_state=state,
    ) is None

    listed = adapter.handle(
        {"jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {}},
        trusted_source=trusted,
        connection_state=state,
    )
    assert "resultType" not in listed["result"]
    assert listed["result"]["tools"]

    pong = adapter.handle(
        {"jsonrpc": "2.0", "id": "ping", "method": "ping", "params": {}},
        trusted_source=trusted,
        connection_state=state,
    )
    assert pong["result"] == {}


def test_second_initialize_is_rejected(adapter, trusted):
    state = MCPConnectionState()
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2099-01-01",
            "capabilities": {},
            "clientInfo": {"name": "client", "version": "1"},
        },
    }
    assert adapter.handle(init, trusted_source=trusted, connection_state=state)["result"]["protocolVersion"] == LEGACY_PROTOCOL_VERSION
    init["id"] = 2
    assert adapter.handle(init, trusted_source=trusted, connection_state=state)["error"]["code"] == -32600



def test_legacy_connection_state_is_isolated_between_clients(adapter, trusted):
    state_a = MCPConnectionState()
    state_b = MCPConnectionState()
    initialize = {
        "jsonrpc": "2.0",
        "id": "init-a",
        "method": "initialize",
        "params": {
            "protocolVersion": LEGACY_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "client-a", "version": "1"},
        },
    }

    assert adapter.handle(
        initialize,
        trusted_source=trusted,
        connection_state=state_a,
    )["result"]["protocolVersion"] == LEGACY_PROTOCOL_VERSION

    assert adapter.handle(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        trusted_source=trusted,
        connection_state=state_a,
    ) is None

    assert adapter.handle(
        {
            "jsonrpc": "2.0",
            "id": "list-a",
            "method": "tools/list",
            "params": {},
        },
        trusted_source=trusted,
        connection_state=state_a,
    )["result"]["tools"]

    assert adapter.handle(
        {
            "jsonrpc": "2.0",
            "id": "list-b",
            "method": "tools/list",
            "params": {},
        },
        trusted_source=trusted,
        connection_state=state_b,
    )["error"]["code"] == -32000


def test_legacy_initialize_requires_connection_state(adapter, trusted):
    with pytest.raises(MCPAdapterError, match="MCPConnectionState"):
        adapter.handle(
            {
                "jsonrpc": "2.0",
                "id": "init",
                "method": "initialize",
                "params": {
                    "protocolVersion": LEGACY_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "client", "version": "1"},
                },
            },
            trusted_source=trusted,
        )

def test_invalid_requests_notifications_and_methods(adapter, trusted):
    assert adapter.handle([], trusted_source=trusted)["error"]["code"] == -32600
    assert adapter.handle({"jsonrpc": "1.0"}, trusted_source=trusted)["error"]["code"] == -32600
    assert adapter.handle(
        {"jsonrpc": "2.0", "id": True, "method": "tools/list"},
        trusted_source=trusted,
    )["error"]["code"] == -32600
    assert adapter.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "unknown", "params": modern_meta()},
        trusted_source=trusted,
    )["error"]["code"] == -32601
    assert adapter.handle(
        {"jsonrpc": "2.0", "method": "notifications/unknown"},
        trusted_source=trusted,
    ) is None


def test_bad_request_id_factory_fails_closed(monkeypatch, trusted):
    gateway = FakeGateway()
    monkeypatch.setattr("secure_ops_gateway.mcp_adapter.Gateway", FakeGateway)
    adapter = MCPAdapter(gateway, request_id_factory=lambda: "")
    response = adapter.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": modern_meta(),
        },
        trusted_source=trusted,
    )
    assert response["error"]["code"] == -32603


def test_stdio_transport_frames_requests(adapter, trusted):
    server = MCPStdioServer(adapter, trusted_source=trusted, max_line_bytes=4096)
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": modern_meta(),
    }
    raw = json.dumps(request).encode() + b"\n"
    response = json.loads(server.transact_bytes(raw))
    assert response["id"] == 1
    assert response["result"]["resultType"] == "complete"


def test_stdio_legacy_state_is_scoped_to_one_serve(adapter, trusted):
    server = MCPStdioServer(adapter, trusted_source=trusted, max_line_bytes=4096)
    initialize = {
        "jsonrpc": "2.0",
        "id": "init",
        "method": "initialize",
        "params": {
            "protocolVersion": LEGACY_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "legacy-client", "version": "1"},
        },
    }
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    listed = {
        "jsonrpc": "2.0",
        "id": "list",
        "method": "tools/list",
        "params": {},
    }

    payload = b"".join(
        json.dumps(item).encode() + b"\n"
        for item in (initialize, initialized, listed)
    )
    responses = [
        json.loads(line)
        for line in server.transact_bytes(payload).splitlines()
    ]
    assert len(responses) == 2
    assert responses[0]["result"]["protocolVersion"] == LEGACY_PROTOCOL_VERSION
    assert responses[1]["result"]["tools"]

    fresh = json.loads(
        server.transact_bytes(json.dumps(listed).encode() + b"\n")
    )
    assert fresh["error"]["code"] == -32000


def test_stdio_transport_parse_error_and_frame_limits(adapter, trusted):
    server = MCPStdioServer(adapter, trusted_source=trusted, max_line_bytes=1024)
    response = json.loads(server.transact_bytes(b"not-json\n"))
    assert response["error"]["code"] == -32700

    with pytest.raises(MCPTransportError, match="newline terminated"):
        server.transact_bytes(b"{}")
    with pytest.raises(MCPTransportError, match="exceeds"):
        server.transact_bytes(b"x" * 1025)


def test_constructor_validation(monkeypatch):
    with pytest.raises(ValueError):
        MCPTrustedSource("", "subject")
    with pytest.raises(ValueError):
        MCPTrustedSource("provider", "")

    gateway = FakeGateway()
    monkeypatch.setattr("secure_ops_gateway.mcp_adapter.Gateway", FakeGateway)
    with pytest.raises(ValueError):
        MCPAdapter(gateway, server_name="")
    with pytest.raises(ValueError):
        MCPAdapter(gateway, server_version="")
    with pytest.raises(ValueError):
        MCPAdapter(gateway, instructions="")
    with pytest.raises(TypeError):
        MCPAdapter(gateway, request_id_factory=1)

    adapter = MCPAdapter(gateway)
    trusted = MCPTrustedSource("stdio", "subject")
    with pytest.raises(ValueError):
        MCPStdioServer(adapter, trusted_source=trusted, max_line_bytes=1)
