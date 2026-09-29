"""Secure Ops Gateway public API."""

from .gateway import Gateway
from .identity import SourceContext, StaticIdentityResolver
from .mcp_adapter import MCPAdapter, MCPStdioServer, MCPTrustedSource

__all__ = [
    "Gateway",
    "MCPAdapter",
    "MCPStdioServer",
    "MCPTrustedSource",
    "SourceContext",
    "StaticIdentityResolver",
]
__version__ = "0.1.1"
