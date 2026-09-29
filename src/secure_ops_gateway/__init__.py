"""Secure Ops Gateway public API."""

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
from .mcp_adapter import MCPAdapter, MCPStdioServer, MCPTrustedSource

__all__ = [
    "CapabilityRouter",
    "ExecutorInvocation",
    "Gateway",
    "MCPAdapter",
    "MCPStdioServer",
    "MCPTrustedSource",
    "SourceContext",
    "ReplayCache",
    "SQLiteReplayProtector",
    "StaticIdentityResolver",
    "UnixSocketExecutorClient",
    "UnixSocketExecutorServer",
]
__version__ = "0.1.1"
