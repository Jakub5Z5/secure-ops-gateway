"""Secure Ops Gateway public API."""

from .admission import SQLiteAdmissionController

from .executor import (
    CapabilityRouter,
    ExecutorInvocation,
    ReplayCache,
    SQLiteReplayProtector,
    UnixSocketExecutorClient,
    UnixSocketExecutorServer,
)
from .gateway import Gateway
from .identity import SourceContext, StaticIdentityResolver
from .mcp_adapter import (
    MCPAdapter,
    MCPConnectionState,
    MCPStdioServer,
    MCPTrustedSource,
)
from .observability import GatewayMetrics

__all__ = [
    "CapabilityRouter",
    "ExecutorInvocation",
    "Gateway",
    "GatewayMetrics",
    "MCPAdapter",
    "MCPConnectionState",
    "MCPStdioServer",
    "MCPTrustedSource",
    "SourceContext",
    "ReplayCache",
    "SQLiteAdmissionController",
    "SQLiteReplayProtector",
    "StaticIdentityResolver",
    "UnixSocketExecutorClient",
    "UnixSocketExecutorServer",
]
__version__ = "0.2.0"
