from __future__ import annotations

from dataclasses import dataclass


class IdentityError(RuntimeError):
    pass


class IdentityDenied(IdentityError):
    pass


@dataclass(frozen=True)
class SourceContext:
    """Identity metadata supplied by an authenticated transport.

    `source_provider` and `source_subject` must be derived from the transport's
    authenticated identity, never copied from untrusted request-body fields.
    """

    source_provider: str
    source_subject: str
    request_id: str


class StaticIdentityResolver:
    """Resolve authenticated transport identities to gateway principals."""

    def __init__(self, document: dict):
        if not isinstance(document, dict) or document.get("schema") != 1:
            raise IdentityError("unsupported identity registry")
        bindings = document.get("bindings")
        if not isinstance(bindings, list):
            raise IdentityError("identity registry must contain bindings")

        resolved: dict[tuple[str, str], str] = {}
        for item in bindings:
            if not isinstance(item, dict):
                raise IdentityError("invalid identity binding")
            provider = item.get("provider")
            subject = item.get("subject")
            principal = item.get("principal")
            if not all(isinstance(value, str) and value for value in (provider, subject, principal)):
                raise IdentityError("invalid identity binding")
            key = (provider, subject)
            if key in resolved:
                raise IdentityError("duplicate identity binding")
            resolved[key] = principal
        self._bindings = resolved

    def __call__(self, source_provider: str, source_subject: str) -> str:
        try:
            return self._bindings[(source_provider, source_subject)]
        except KeyError as exc:
            raise IdentityDenied("authenticated source is not bound to a principal") from exc
