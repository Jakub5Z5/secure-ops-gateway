"""Secure Ops Gateway public API."""

from .gateway import Gateway
from .identity import SourceContext, StaticIdentityResolver

__all__ = ["Gateway", "SourceContext", "StaticIdentityResolver"]
__version__ = "0.1.0"
