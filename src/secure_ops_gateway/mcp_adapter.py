from __future__ import annotations

import io
import json
import secrets
from importlib.metadata import PackageNotFoundError, version as package_version
from dataclasses import dataclass
from typing import BinaryIO, Callable

from .admission import AdmissionError
from .authorization import AuthorizationDenied
from .gateway import ConfirmationRequired, Gateway, GatewayError
from .identity import IdentityDenied, SourceContext
from .mcp_schema import tool_input_schema
from .operation_guard import ConfirmationError
from .registry import RegistryError, get_tool

MODERN_PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = (
    MODERN_PROTOCOL_VERSION,
    LEGACY_PROTOCOL_VERSION,
)

_JSONRPC_VERSION = "2.0"
_SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo"
_PROTOCOL_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
_CLIENT_CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities"


class MCPAdapterError(RuntimeError):
    pass


class MCPTransportError(MCPAdapterError):
    pass


@dataclass(frozen=True)
class MCPTrustedSource:
    """Authenticated transport identity supplied outside the MCP request body."""

    provider: str
    subject: str

    def __post_init__(self) -> None:
        if not isinstance(self.provider, str) or not self.provider:
            raise ValueError("provider must be a non-empty string")
        if not isinstance(self.subject, str) or not self.subject:
            raise ValueError("subject must be a non-empty string")


class MCPAdapter:
    """Translate MCP JSON-RPC requests into Secure Ops Gateway operations.

    Authentication is intentionally out of scope for this class. The caller must
    provide a trusted transport identity separately from the untrusted MCP JSON.
    That identity is the only source used to build ``SourceContext`` objects.

    The adapter supports the current stateless MCP revision (2026-07-28) and the
    latest handshake-era revision (2025-11-25) for stdio compatibility.
    """

    def __init__(
        self,
        gateway: Gateway,
        *,
        server_name: str = "secure-ops-gateway",
        server_version: str | None = None,
        instructions: str | None = None,
        request_id_factory: Callable[[], str] | None = None,
    ):
        if not isinstance(gateway, Gateway):
            raise TypeError("gateway must be a Gateway")
        if not isinstance(server_name, str) or not server_name:
            raise ValueError("server_name must be a non-empty string")
        if server_version is None:
            try:
                server_version = package_version("secure-ops-gateway")
            except PackageNotFoundError:
                server_version = "unknown"
        if not isinstance(server_version, str) or not server_version:
            raise ValueError("server_version must be a non-empty string or None")
        if instructions is not None and (
            not isinstance(instructions, str) or not instructions
        ):
            raise ValueError("instructions must be a non-empty string or None")
        if request_id_factory is not None and not callable(request_id_factory):
            raise TypeError("request_id_factory must be callable")

        self.gateway = gateway
        self.server_name = server_name
        self.server_version = server_version
        self.instructions = instructions
        self.request_id_factory = (
            request_id_factory
            if request_id_factory is not None
            else lambda: secrets.token_urlsafe(18)
        )
        self._legacy_initialize_seen = False
        self._legacy_initialized = False

    @property
    def server_info(self) -> dict:
        return {"name": self.server_name, "version": self.server_version}

    @property
    def capabilities(self) -> dict:
        return {"tools": {}}

    @staticmethod
    def _error(
        request_id: object,
        code: int,
        message: str,
        *,
        data: dict | None = None,
    ) -> dict:
        error = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {
            "jsonrpc": _JSONRPC_VERSION,
            "id": request_id,
            "error": error,
        }

    @staticmethod
    def _success(request_id: object, result: dict) -> dict:
        return {
            "jsonrpc": _JSONRPC_VERSION,
            "id": request_id,
            "result": result,
        }

    def _modern_result(self, result: dict) -> dict:
        return {
            "resultType": "complete",
            **result,
            "_meta": {_SERVER_INFO_KEY: self.server_info},
        }

    def _source(self, trusted_source: MCPTrustedSource) -> SourceContext:
        request_id = self.request_id_factory()
        if not isinstance(request_id, str) or not request_id:
            raise MCPAdapterError("request_id_factory returned an invalid request id")
        return SourceContext(
            trusted_source.provider,
            trusted_source.subject,
            request_id,
        )

    @staticmethod
    def _request_id(message: dict) -> object:
        request_id = message.get("id")
        if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
            raise ValueError("invalid JSON-RPC request id")
        return request_id

    @staticmethod
    def _params(message: dict) -> dict:
        params = message.get("params", {})
        if not isinstance(params, dict):
            raise ValueError("params must be an object")
        return params

    def _modern_version(self, params: dict) -> str | None:
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            return None
        version = meta.get(_PROTOCOL_VERSION_KEY)
        return version if isinstance(version, str) else None

    def _validate_modern_meta(self, params: dict, request_id: object) -> dict | None:
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            return self._error(request_id, -32602, "Invalid params")

        version = meta.get(_PROTOCOL_VERSION_KEY)
        if not isinstance(version, str) or not version:
            return self._error(request_id, -32602, "Invalid params")
        if version != MODERN_PROTOCOL_VERSION:
            return self._error(
                request_id,
                -32022,
                "Unsupported protocol version",
                data={
                    "supported": list(SUPPORTED_PROTOCOL_VERSIONS),
                    "requested": version,
                },
            )

        capabilities = meta.get(_CLIENT_CAPABILITIES_KEY)
        if not isinstance(capabilities, dict):
            return self._error(request_id, -32602, "Invalid params")
        return None

    def _initialize(self, request_id: object, params: dict) -> dict:
        if self._legacy_initialize_seen:
            return self._error(request_id, -32600, "Already initialized")

        requested = params.get("protocolVersion")
        capabilities = params.get("capabilities")
        client_info = params.get("clientInfo")
        if (
            not isinstance(requested, str)
            or not requested
            or not isinstance(capabilities, dict)
            or not isinstance(client_info, dict)
            or not isinstance(client_info.get("name"), str)
            or not client_info.get("name")
            or not isinstance(client_info.get("version"), str)
            or not client_info.get("version")
        ):
            return self._error(request_id, -32602, "Invalid params")

        self._legacy_initialize_seen = True
        result = {
            "protocolVersion": LEGACY_PROTOCOL_VERSION,
            "capabilities": self.capabilities,
            "serverInfo": self.server_info,
        }
        if self.instructions is not None:
            result["instructions"] = self.instructions
        return self._success(request_id, result)

    def _discover(self, request_id: object, params: dict) -> dict:
        invalid = self._validate_modern_meta(params, request_id)
        if invalid is not None:
            return invalid
        result = self._modern_result(
            {
                "supportedVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
                "capabilities": self.capabilities,
                "ttlMs": 3600000,
                "cacheScope": "public",
            }
        )
        if self.instructions is not None:
            result["instructions"] = self.instructions
        return self._success(request_id, result)

    def _list_tools(
        self,
        request_id: object,
        params: dict,
        trusted_source: MCPTrustedSource,
        *,
        modern: bool,
    ) -> dict:
        if modern:
            invalid = self._validate_modern_meta(params, request_id)
            if invalid is not None:
                return invalid
        elif not self._legacy_initialized:
            return self._error(request_id, -32000, "Server not initialized")

        allowed_keys = {"_meta", "cursor"} if modern else {"cursor", "_meta"}
        if set(params) - allowed_keys:
            return self._error(request_id, -32602, "Invalid params")
        if "cursor" in params:
            return self._error(request_id, -32602, "Pagination is not supported")

        try:
            catalog = self.gateway.catalog(self._source(trusted_source))
        except (IdentityDenied, AuthorizationDenied):
            return self._error(request_id, -32001, "Access denied")
        except AdmissionError:
            return self._error(request_id, -32003, "Gateway admission limit exceeded")
        except Exception:
            return self._error(request_id, -32603, "Internal error")

        tools = [
            {
                "name": item["name"],
                "description": item.get("description", ""),
                "inputSchema": tool_input_schema(item),
            }
            for item in catalog
        ]
        result = {"tools": tools}
        if modern:
            result = self._modern_result(
                {
                    **result,
                    "ttlMs": 0,
                    "cacheScope": "private",
                }
            )
        return self._success(request_id, result)

    @staticmethod
    def _tool_error(message: str, *, structured: dict | None = None) -> dict:
        result = {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        }
        if structured is not None:
            result["structuredContent"] = structured
        return result

    @staticmethod
    def _tool_success(response: dict) -> dict:
        text = json.dumps(
            response,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": response,
        }

    def _call_tool(
        self,
        request_id: object,
        params: dict,
        trusted_source: MCPTrustedSource,
        *,
        modern: bool,
    ) -> dict:
        if modern:
            invalid = self._validate_modern_meta(params, request_id)
            if invalid is not None:
                return invalid
        elif not self._legacy_initialized:
            return self._error(request_id, -32000, "Server not initialized")

        allowed = {"name", "arguments", "_meta"}
        if set(params) - allowed:
            return self._error(request_id, -32602, "Invalid params")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not name or not isinstance(arguments, dict):
            return self._error(request_id, -32602, "Invalid params")

        try:
            raw_tool = get_tool(name, registry=self.gateway.tools)
        except RegistryError:
            return self._error(request_id, -32602, "Unknown tool")

        call_arguments = dict(arguments)
        has_confirmed = "confirmed" in call_arguments
        has_token = "confirmation_token" in call_arguments
        confirmed = call_arguments.pop("confirmed", False)
        confirmation_token = call_arguments.pop("confirmation_token", None)
        explicit = raw_tool.get("confirmation", "none") == "explicit"

        if has_confirmed and not isinstance(confirmed, bool):
            return self._call_result(
                request_id,
                self._tool_error("confirmed must be boolean"),
                modern=modern,
            )
        if has_token and not isinstance(confirmation_token, str):
            return self._call_result(
                request_id,
                self._tool_error("confirmation_token must be a string"),
                modern=modern,
            )
        if (has_confirmed or has_token) and not explicit:
            return self._call_result(
                request_id,
                self._tool_error("confirmation controls are not valid for this tool"),
                modern=modern,
            )
        if confirmation_token is not None and not confirmed:
            return self._call_result(
                request_id,
                self._tool_error("confirmation_token requires confirmed=true"),
                modern=modern,
            )

        try:
            response = self.gateway.invoke(
                self._source(trusted_source),
                name,
                call_arguments,
                confirmed=confirmed,
                confirmation_token=confirmation_token,
            )
            result = self._tool_success(response)
        except ConfirmationRequired as exc:
            challenge = {
                "status": "confirmation_required",
                **exc.challenge,
            }
            result = self._tool_error(
                "Explicit confirmation is required before this operation can run.",
                structured=challenge,
            )
        except ConfirmationError as exc:
            result = self._tool_error(str(exc))
        except RegistryError as exc:
            result = self._tool_error(str(exc))
        except (IdentityDenied, AuthorizationDenied):
            result = self._tool_error("Tool call denied")
        except AdmissionError:
            result = self._tool_error("Gateway admission limit exceeded")
        except GatewayError as exc:
            result = self._tool_error(str(exc))
        except Exception:
            return self._error(request_id, -32603, "Internal error")

        return self._call_result(request_id, result, modern=modern)

    def _call_result(self, request_id: object, result: dict, *, modern: bool) -> dict:
        if modern:
            result = self._modern_result(result)
        return self._success(request_id, result)

    def handle(
        self,
        message: object,
        *,
        trusted_source: MCPTrustedSource,
    ) -> dict | None:
        """Handle one decoded MCP JSON-RPC message.

        Returns a response object for requests and ``None`` for notifications.
        Batch messages are intentionally rejected because MCP no longer permits
        JSON-RPC batching.
        """

        if not isinstance(trusted_source, MCPTrustedSource):
            raise TypeError("trusted_source must be MCPTrustedSource")
        if not isinstance(message, dict):
            return self._error(None, -32600, "Invalid Request")
        if message.get("jsonrpc") != _JSONRPC_VERSION:
            return self._error(message.get("id"), -32600, "Invalid Request")

        method = message.get("method")
        if not isinstance(method, str) or not method:
            return self._error(message.get("id"), -32600, "Invalid Request")

        is_notification = "id" not in message
        if is_notification:
            if method == "notifications/initialized":
                if self._legacy_initialize_seen:
                    self._legacy_initialized = True
                return None
            return None

        try:
            request_id = self._request_id(message)
            params = self._params(message)
        except ValueError:
            return self._error(message.get("id"), -32600, "Invalid Request")

        if method == "initialize":
            return self._initialize(request_id, params)
        if method == "server/discover":
            return self._discover(request_id, params)

        modern_version = self._modern_version(params)
        modern = modern_version is not None
        if modern:
            invalid = self._validate_modern_meta(params, request_id)
            if invalid is not None:
                return invalid
        elif "_meta" in params and not self._legacy_initialized:
            return self._error(request_id, -32602, "Invalid params")

        if method == "tools/list":
            return self._list_tools(
                request_id,
                params,
                trusted_source,
                modern=modern,
            )
        if method == "tools/call":
            return self._call_tool(
                request_id,
                params,
                trusted_source,
                modern=modern,
            )
        if method == "ping" and not modern:
            if not self._legacy_initialized:
                return self._error(request_id, -32000, "Server not initialized")
            return self._success(request_id, {})
        return self._error(request_id, -32601, "Method not found")


class MCPStdioServer:
    """Newline-delimited JSON-RPC stdio transport for ``MCPAdapter``."""

    def __init__(
        self,
        adapter: MCPAdapter,
        *,
        trusted_source: MCPTrustedSource,
        max_line_bytes: int = 4 * 1024 * 1024,
    ):
        if not isinstance(adapter, MCPAdapter):
            raise TypeError("adapter must be MCPAdapter")
        if not isinstance(trusted_source, MCPTrustedSource):
            raise TypeError("trusted_source must be MCPTrustedSource")
        if (
            isinstance(max_line_bytes, bool)
            or not isinstance(max_line_bytes, int)
            or max_line_bytes < 1024
        ):
            raise ValueError("max_line_bytes must be an integer >= 1024")
        self.adapter = adapter
        self.trusted_source = trusted_source
        self.max_line_bytes = max_line_bytes

    @staticmethod
    def _write(output_stream: BinaryIO, message: dict) -> None:
        raw = json.dumps(
            message,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        output_stream.write(raw)
        output_stream.flush()

    def serve(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
    ) -> None:
        while True:
            line = input_stream.readline(self.max_line_bytes + 1)
            if not line:
                return
            if len(line) > self.max_line_bytes:
                raise MCPTransportError("MCP stdio request exceeds max_line_bytes")
            if not line.endswith(b"\n"):
                raise MCPTransportError("MCP stdio request frame is not newline terminated")

            try:
                message = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._write(
                    output_stream,
                    MCPAdapter._error(None, -32700, "Parse error"),
                )
                continue

            response = self.adapter.handle(
                message,
                trusted_source=self.trusted_source,
            )
            if response is not None:
                self._write(output_stream, response)

    def transact_bytes(self, payload: bytes) -> bytes:
        """Small in-memory helper useful for embedding tests and diagnostics."""

        source = io.BytesIO(payload)
        destination = io.BytesIO()
        self.serve(source, destination)
        return destination.getvalue()
