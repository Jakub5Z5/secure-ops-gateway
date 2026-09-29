import pytest

from secure_ops_gateway.identity import IdentityDenied, SourceContext, StaticIdentityResolver


def test_static_identity_resolver_maps_authenticated_source():
    resolver = StaticIdentityResolver({
        "schema": 1,
        "bindings": [{"provider": "test", "subject": "alice-device", "principal": "alice"}],
    })
    assert resolver("test", "alice-device") == "alice"


def test_static_identity_resolver_denies_unknown_source():
    resolver = StaticIdentityResolver({"schema": 1, "bindings": []})
    with pytest.raises(IdentityDenied):
        resolver("test", "unknown")


def test_source_context_does_not_accept_principal_id():
    with pytest.raises(TypeError):
        SourceContext("test", "subject", "request", "admin")


def test_identity_registry_rejects_invalid_documents():
    from secure_ops_gateway.identity import IdentityError

    with pytest.raises(IdentityError):
        StaticIdentityResolver({"schema": 2, "bindings": []})
    with pytest.raises(IdentityError):
        StaticIdentityResolver({"schema": 1, "bindings": {}})
    with pytest.raises(IdentityError):
        StaticIdentityResolver({"schema": 1, "bindings": ["bad"]})
    with pytest.raises(IdentityError):
        StaticIdentityResolver(
            {
                "schema": 1,
                "bindings": [
                    {"provider": "p", "subject": "s", "principal": "a"},
                    {"provider": "p", "subject": "s", "principal": "b"},
                ],
            }
        )
