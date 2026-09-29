import pytest
from secure_ops_gateway.authorization import AuthorizationDenied, authorize

POLICY = {
    "schema": 1,
    "roles": {"operator": {"permissions": ["service.read", "service.restart"], "max_risk": "write"}},
    "bindings": {"alice": [{"role": "operator", "resources": ["service:api", "service:worker-*"]}]},
}


def test_authorization_accepts_matching_permission_resource_and_risk():
    assert authorize("alice", "service.restart", "service:api", "write", policy=POLICY)["role"] == "operator"


def test_authorization_denies_resource_outside_binding():
    with pytest.raises(AuthorizationDenied):
        authorize("alice", "service.restart", "service:db", "write", policy=POLICY)


def test_authorization_rejects_invalid_policy_shapes_and_risk():
    from secure_ops_gateway.authorization import AuthorizationError

    with pytest.raises(AuthorizationError):
        authorize("alice", "x", "x", "read", policy={"schema": 2})
    with pytest.raises(AuthorizationDenied, match="unknown risk"):
        authorize("alice", "service.read", "service:api", "unknown", policy=POLICY)


def test_authorization_denies_permission_and_risk_above_role():
    with pytest.raises(AuthorizationDenied):
        authorize("alice", "service.delete", "service:api", "write", policy=POLICY)
    with pytest.raises(AuthorizationDenied):
        authorize("alice", "service.restart", "service:api", "privileged", policy=POLICY)


def test_authorization_wildcard_permission_is_supported():
    policy = {
        "schema": 1,
        "roles": {"admin": {"permissions": ["*"], "max_risk": "privileged"}},
        "bindings": {"root": [{"role": "admin", "resources": ["*"]}]},
    }
    assert authorize("root", "anything", "any:resource", "privileged", policy=policy)["role"] == "admin"
