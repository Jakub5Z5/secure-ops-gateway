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
