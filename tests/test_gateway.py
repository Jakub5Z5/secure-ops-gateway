import pytest

from secure_ops_gateway.authorization import AuthorizationDenied
from secure_ops_gateway.gateway import ConfirmationRequired, Gateway
from secure_ops_gateway.identity import IdentityDenied, SourceContext, StaticIdentityResolver
from secure_ops_gateway.operation_guard import SQLiteOperationGuard

TOOLS = {
    "schema": 1,
    "tools": {
        "demo.status": {
            "capability": "demo.status",
            "permission": "demo.read",
            "resource": "demo:service",
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
            "arguments": {"service": {"type": "string", "required": True, "enum": ["api", "worker"]}},
            "request": {"action": "restart", "service": "$arg:service"},
        },
    },
}
EXECUTORS = {
    "schema": 1,
    "executors": {
        "demo": {
            "endpoint": "unix:/tmp/demo.sock",
            "credential": "demo.key",
            "capabilities": ["demo.status", "demo.restart"],
        }
    },
}
POLICY = {
    "schema": 1,
    "roles": {
        "operator": {"permissions": ["demo.read", "demo.restart"], "max_risk": "write"},
        "limited": {"permissions": ["demo.restart"], "max_risk": "write"},
    },
    "bindings": {
        "alice": [{"role": "operator", "resources": ["demo:*"]}],
        "limited-user": [{"role": "limited", "resources": ["demo:api"]}],
    },
}
IDENTITIES = StaticIdentityResolver({
    "schema": 1,
    "bindings": [
        {"provider": "test", "subject": "alice-source", "principal": "alice"},
        {"provider": "test", "subject": "limited-source", "principal": "limited-user"},
    ],
})


def gateway_for(executor_call, **kwargs):
    return Gateway(
        tools=TOOLS,
        executors=EXECUTORS,
        policy=POLICY,
        identity_resolver=IDENTITIES,
        executor_call=executor_call,
        **kwargs,
    )


def test_gateway_routes_authorized_read():
    calls = []
    gateway = gateway_for(lambda route, payload: calls.append((route, payload)) or {"ok": True})
    response = gateway.invoke(SourceContext("test", "alice-source", "r1"), "demo.status")
    assert response == {"ok": True}
    assert calls[0][1]["capability"] == "demo.status"
    assert calls[0][1]["principal_id"] == "alice"


def test_unknown_authenticated_source_is_denied():
    gateway = gateway_for(lambda _route, _payload: {"ok": True})
    with pytest.raises(IdentityDenied):
        gateway.invoke(SourceContext("test", "unknown", "r1"), "demo.status")


def test_catalog_filters_unauthorized_enum_values():
    gateway = gateway_for(lambda _route, _payload: {"ok": True})
    catalog = gateway.catalog(SourceContext("test", "limited-source", "catalog-1"))
    assert [item["name"] for item in catalog] == ["demo.restart"]
    assert catalog[0]["arguments"]["service"]["enum"] == ["api"]


def test_authorization_denial_is_audited():
    records = []
    gateway = gateway_for(lambda _route, _payload: {"ok": True}, audit_sink=records.append)
    with pytest.raises(AuthorizationDenied):
        gateway.invoke(SourceContext("test", "limited-source", "r-denied"), "demo.restart", {"service": "worker"})
    assert records[-1]["event"] == "authorization_denied"
    assert records[-1]["principal_id"] == "limited-user"


def test_explicit_confirmation_is_bound_and_idempotent(tmp_path):
    calls = []
    records = []
    gateway = gateway_for(
        lambda route, payload: calls.append(payload) or {"ok": True, "count": len(calls)},
        audit_sink=records.append,
        operation_guard=SQLiteOperationGuard(tmp_path / "operations.sqlite3"),
    )
    source = SourceContext("test", "alice-source", "r2")
    with pytest.raises(ConfirmationRequired) as required:
        gateway.invoke(source, "demo.restart", {"service": "api"})
    token = required.value.challenge["confirmation_token"]
    first = gateway.invoke(source, "demo.restart", {"service": "api"}, confirmed=True, confirmation_token=token)
    second = gateway.invoke(source, "demo.restart", {"service": "api"}, confirmed=True, confirmation_token=token)
    assert first == second == {"ok": True, "count": 1}
    assert len(calls) == 1
    assert "invoke_succeeded" in [record["event"] for record in records]
    assert "invoke_replayed" in [record["event"] for record in records]


def test_confirmed_executor_failure_is_marked_uncertain_and_audited(tmp_path):
    records = []
    guard = SQLiteOperationGuard(tmp_path / "operations.sqlite3")
    gateway = gateway_for(
        lambda _route, _payload: (_ for _ in ()).throw(RuntimeError("executor failed")),
        audit_sink=records.append,
        operation_guard=guard,
    )
    source = SourceContext("test", "alice-source", "r3")
    with pytest.raises(ConfirmationRequired) as required:
        gateway.invoke(source, "demo.restart", {"service": "api"})
    token = required.value.challenge["confirmation_token"]
    with pytest.raises(RuntimeError, match="executor failed"):
        gateway.invoke(source, "demo.restart", {"service": "api"}, confirmed=True, confirmation_token=token)
    assert records[-1]["event"] == "invoke_uncertain"


def test_catalog_does_not_require_non_resource_arguments():
    tools = {
        "schema": 1,
        "tools": {
            "demo.send": {
                "capability": "demo.status",
                "permission": "demo.restart",
                "resource": "demo:{service}",
                "risk": "write",
                "confirmation": "none",
                "allow_unconfirmed_mutation": True,
                "arguments": {
                    "service": {"type": "string", "required": True, "enum": ["api", "worker"]},
                    "message": {"type": "string", "required": True, "max_length": 100},
                },
                "request": {"action": "send", "service": "$arg:service", "message": "$arg:message"},
            }
        },
    }
    gateway = Gateway(
        tools=tools,
        executors=EXECUTORS,
        policy=POLICY,
        identity_resolver=IDENTITIES,
        executor_call=lambda _route, _payload: {"ok": True},
    )
    catalog = gateway.catalog(SourceContext("test", "limited-source", "catalog-2"))
    assert catalog[0]["arguments"]["service"]["enum"] == ["api"]



def test_post_execution_audit_failure_does_not_turn_success_into_failure():
    calls = []
    audit_calls = []

    def executor(_route, _payload):
        calls.append(1)
        return {"ok": True}

    def audit(record):
        audit_calls.append(record["event"])
        if record["event"] == "invoke_succeeded":
            raise OSError("audit disk full")

    gateway = gateway_for(executor, audit_sink=audit)
    assert gateway.invoke(SourceContext("test", "alice-source", "audit-success"), "demo.status") == {"ok": True}
    assert len(calls) == 1
    assert audit_calls[-1] == "invoke_succeeded"


def test_post_execution_audit_failure_handler_is_called():
    failures = []

    def audit(record):
        if record["event"] == "invoke_succeeded":
            raise OSError("audit disk full")

    gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        audit_sink=audit,
        audit_failure_handler=lambda exc, record: failures.append((type(exc).__name__, record["event"])),
    )
    assert gateway.invoke(SourceContext("test", "alice-source", "audit-handler"), "demo.status") == {"ok": True}
    assert failures == [("OSError", "invoke_succeeded")]


def test_gateway_rate_limit_is_enforced():
    from secure_ops_gateway.admission import GatewayAdmissionController, RateLimitExceeded

    gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        admission_controller=GatewayAdmissionController(
            max_calls_per_window=1,
            window_seconds=60,
            max_inflight_global=2,
            max_inflight_per_source=1,
        ),
    )
    source = SourceContext("test", "alice-source", "rate-1")
    assert gateway.invoke(source, "demo.status") == {"ok": True}
    with pytest.raises(RateLimitExceeded):
        gateway.invoke(SourceContext("test", "alice-source", "rate-2"), "demo.status")



def test_pre_execution_audit_failure_releases_confirmation_reservation(tmp_path):
    calls = []
    guard = SQLiteOperationGuard(tmp_path / "operations.sqlite3")
    source = SourceContext("test", "alice-source", "audit-pre")
    initial = gateway_for(
        lambda _route, _payload: calls.append(1) or {"ok": True},
        operation_guard=guard,
    )
    with pytest.raises(ConfirmationRequired) as required:
        initial.invoke(source, "demo.restart", {"service": "api"})
    token = required.value.challenge["confirmation_token"]

    def broken_audit(record):
        if record["event"] == "invoke_started":
            raise OSError("audit unavailable")

    blocked = gateway_for(
        lambda _route, _payload: calls.append(1) or {"ok": True},
        operation_guard=guard,
        audit_sink=broken_audit,
    )
    with pytest.raises(OSError, match="audit unavailable"):
        blocked.invoke(
            source,
            "demo.restart",
            {"service": "api"},
            confirmed=True,
            confirmation_token=token,
        )
    assert calls == []
    assert guard.status(token, initial._resolve_context(source))["status"] == "pending"


def test_identity_denied_calls_are_rate_limited_before_resolution():
    from secure_ops_gateway.admission import GatewayAdmissionController, RateLimitExceeded

    gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        admission_controller=GatewayAdmissionController(
            max_calls_per_window=1,
            window_seconds=60,
            max_inflight_global=2,
            max_inflight_per_source=1,
        ),
    )
    with pytest.raises(IdentityDenied):
        gateway.invoke(SourceContext("test", "unknown-source", "deny-1"), "demo.status")
    with pytest.raises(RateLimitExceeded):
        gateway.invoke(SourceContext("test", "unknown-source", "deny-2"), "demo.status")
