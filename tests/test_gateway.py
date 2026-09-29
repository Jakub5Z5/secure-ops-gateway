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


def test_catalog_hides_correlated_enum_combinations_it_cannot_represent():
    tools = {
        "schema": 1,
        "tools": {
            "demo.deploy": {
                "capability": "demo.status",
                "permission": "demo.restart",
                "resource": "demo:{region}:{service}",
                "risk": "write",
                "confirmation": "none",
                "allow_unconfirmed_mutation": True,
                "arguments": {
                    "region": {
                        "type": "string",
                        "required": True,
                        "enum": ["eu", "us"],
                    },
                    "service": {
                        "type": "string",
                        "required": True,
                        "enum": ["api", "db"],
                    },
                },
                "request": {
                    "action": "deploy",
                    "region": "$arg:region",
                    "service": "$arg:service",
                },
            }
        },
    }
    policy = {
        "schema": 1,
        "roles": {
            "limited": {
                "permissions": ["demo.restart"],
                "max_risk": "write",
            }
        },
        "bindings": {
            "limited-user": [
                {
                    "role": "limited",
                    "resources": ["demo:eu:api", "demo:us:db"],
                }
            ]
        },
    }
    gateway = Gateway(
        tools=tools,
        executors=EXECUTORS,
        policy=policy,
        identity_resolver=IDENTITIES,
        executor_call=lambda _route, _payload: {"ok": True},
    )
    source = SourceContext("test", "limited-source", "catalog-correlated")

    # Independent enum filtering would incorrectly advertise all four
    # region/service combinations. The current schema cannot express only the
    # two diagonal pairs, so the tool must be omitted from discovery.
    assert gateway.catalog(source) == []

    assert gateway.invoke(
        SourceContext("test", "limited-source", "invoke-correlated-ok"),
        "demo.deploy",
        {"region": "eu", "service": "api"},
    ) == {"ok": True}

    with pytest.raises(AuthorizationDenied):
        gateway.invoke(
            SourceContext("test", "limited-source", "invoke-correlated-denied"),
            "demo.deploy",
            {"region": "eu", "service": "db"},
        )


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


def test_rate_limited_identity_denials_do_not_amplify_audit_logs():
    from secure_ops_gateway.admission import GatewayAdmissionController, RateLimitExceeded

    events = []
    gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        audit_sink=lambda record: events.append(record["event"]),
        admission_controller=GatewayAdmissionController(
            max_calls_per_window=1,
            window_seconds=60,
            max_inflight_global=2,
            max_inflight_per_source=1,
        ),
    )
    source = SourceContext("test", "unknown-source", "deny-audit-1")
    with pytest.raises(IdentityDenied):
        gateway.invoke(source, "demo.status")
    assert events == ["identity_denied"]

    for request_id in ("deny-audit-2", "deny-audit-3"):
        with pytest.raises(RateLimitExceeded):
            gateway.invoke(SourceContext("test", "unknown-source", request_id), "demo.status")
    assert events == ["identity_denied"]


def test_gateway_metrics_capture_success_security_and_admission_outcomes(tmp_path):
    from secure_ops_gateway.admission import GatewayAdmissionController, RateLimitExceeded
    from secure_ops_gateway.observability import GatewayMetrics

    metrics = GatewayMetrics()
    guard = SQLiteOperationGuard(tmp_path / "metrics-operations.sqlite3")
    gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        operation_guard=guard,
        metrics=metrics,
    )

    assert gateway.catalog(SourceContext("test", "alice-source", "metrics-catalog"))
    assert gateway.invoke(
        SourceContext("test", "alice-source", "metrics-read"),
        "demo.status",
    ) == {"ok": True}

    with pytest.raises(IdentityDenied):
        gateway.invoke(
            SourceContext("test", "unknown-source", "metrics-identity"),
            "demo.status",
        )
    with pytest.raises(AuthorizationDenied):
        gateway.invoke(
            SourceContext("test", "limited-source", "metrics-auth"),
            "demo.restart",
            {"service": "worker"},
        )

    source = SourceContext("test", "alice-source", "metrics-confirm")
    with pytest.raises(ConfirmationRequired) as required:
        gateway.invoke(source, "demo.restart", {"service": "api"})
    token = required.value.challenge["confirmation_token"]
    assert gateway.invoke(
        source,
        "demo.restart",
        {"service": "api"},
        confirmed=True,
        confirmation_token=token,
    ) == {"ok": True}
    assert gateway.invoke(
        source,
        "demo.restart",
        {"service": "api"},
        confirmed=True,
        confirmation_token=token,
    ) == {"ok": True}

    limited_metrics = GatewayMetrics()
    limited_gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        metrics=limited_metrics,
        admission_controller=GatewayAdmissionController(
            max_calls_per_window=1,
            window_seconds=60,
            max_inflight_global=2,
            max_inflight_per_source=1,
        ),
    )
    assert limited_gateway.invoke(
        SourceContext("test", "alice-source", "metrics-rate-1"),
        "demo.status",
    ) == {"ok": True}
    with pytest.raises(RateLimitExceeded):
        limited_gateway.invoke(
            SourceContext("test", "alice-source", "metrics-rate-2"),
            "demo.status",
        )

    snapshot = metrics.snapshot()
    assert snapshot["requests"]["catalog"]["success"] == 1
    assert snapshot["requests"]["invoke"]["success"] == 3
    assert snapshot["requests"]["invoke"]["identity_denied"] == 1
    assert snapshot["requests"]["invoke"]["authorization_denied"] == 1
    assert snapshot["requests"]["invoke"]["confirmation_required"] == 1
    assert snapshot["events"]["identity_denied"] == 1
    assert snapshot["events"]["authorization_denied"] == 1
    assert snapshot["events"]["confirmation_required"] == 1
    assert snapshot["events"]["invoke_replayed"] == 1
    assert limited_metrics.snapshot()["events"]["admission_rate_limited"] == 1
    assert limited_metrics.snapshot()["requests"]["invoke"]["admission_denied"] == 1


def test_gateway_metrics_capture_executor_uncertainty_and_audit_degradation(tmp_path):
    from secure_ops_gateway.observability import GatewayMetrics

    metrics = GatewayMetrics()
    guard = SQLiteOperationGuard(tmp_path / "metrics-failure-operations.sqlite3")
    source = SourceContext("test", "alice-source", "metrics-failure")
    gateway = gateway_for(
        lambda _route, _payload: (_ for _ in ()).throw(RuntimeError("executor failed")),
        operation_guard=guard,
        metrics=metrics,
    )
    with pytest.raises(ConfirmationRequired) as required:
        gateway.invoke(source, "demo.restart", {"service": "api"})
    with pytest.raises(RuntimeError, match="executor failed"):
        gateway.invoke(
            source,
            "demo.restart",
            {"service": "api"},
            confirmed=True,
            confirmation_token=required.value.challenge["confirmation_token"],
        )

    audit_metrics = GatewayMetrics()

    def broken_audit(record):
        if record["event"] == "invoke_succeeded":
            raise OSError("audit unavailable")

    audit_gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        audit_sink=broken_audit,
        metrics=audit_metrics,
    )
    assert audit_gateway.invoke(
        SourceContext("test", "alice-source", "metrics-audit"),
        "demo.status",
    ) == {"ok": True}

    snapshot = metrics.snapshot()
    assert snapshot["events"]["executor_failure"] == 1
    assert snapshot["events"]["invoke_uncertain"] == 1
    assert snapshot["requests"]["invoke"]["failed"] == 1
    assert audit_metrics.snapshot()["events"]["audit_best_effort_failure"] == 1


def test_gateway_metrics_are_best_effort_and_type_checked():
    from secure_ops_gateway.observability import GatewayMetrics

    with pytest.raises(TypeError, match="metrics"):
        gateway_for(lambda _route, _payload: {"ok": True}, metrics=object())

    class BrokenMetrics(GatewayMetrics):
        def record_event(self, _event):
            raise RuntimeError("metrics backend failed")

        def finish_request(self, _operation, _outcome, _started_at):
            raise RuntimeError("metrics backend failed")

    metrics = BrokenMetrics()
    gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        metrics=metrics,
    )
    assert gateway.invoke(
        SourceContext("test", "alice-source", "metrics-best-effort"),
        "demo.status",
    ) == {"ok": True}


def test_gateway_metrics_capture_admission_concurrency_and_state_failures():
    from secure_ops_gateway.admission import (
        AdmissionStateError,
        ConcurrencyLimitExceeded,
    )
    from secure_ops_gateway.observability import GatewayMetrics

    class RejectingAdmission:
        def __init__(self, error):
            self.error = error

        def acquire(self, _source):
            raise self.error

        def release(self, _lease):
            raise AssertionError("release must not run without a lease")

    concurrency_metrics = GatewayMetrics()
    concurrency_gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        metrics=concurrency_metrics,
        admission_controller=RejectingAdmission(
            ConcurrencyLimitExceeded("gateway global concurrency limit exceeded")
        ),
    )
    with pytest.raises(ConcurrencyLimitExceeded):
        concurrency_gateway.invoke(
            SourceContext("test", "alice-source", "metrics-concurrency"),
            "demo.status",
        )
    concurrency_snapshot = concurrency_metrics.snapshot()
    assert concurrency_snapshot["events"]["admission_concurrency_limited"] == 1
    assert concurrency_snapshot["requests"]["invoke"]["admission_denied"] == 1

    state_metrics = GatewayMetrics()
    state_gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        metrics=state_metrics,
        admission_controller=RejectingAdmission(
            AdmissionStateError("admission database unavailable")
        ),
    )
    with pytest.raises(AdmissionStateError):
        state_gateway.invoke(
            SourceContext("test", "alice-source", "metrics-state"),
            "demo.status",
        )
    state_snapshot = state_metrics.snapshot()
    assert state_snapshot["events"]["admission_state_error"] == 1
    assert state_snapshot["requests"]["invoke"]["failed"] == 1


def test_gateway_metrics_capture_confirmation_denial_and_required_audit_failure(tmp_path):
    from secure_ops_gateway.observability import GatewayMetrics
    from secure_ops_gateway.operation_guard import ConfirmationError

    confirmation_metrics = GatewayMetrics()
    confirmation_gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        operation_guard=SQLiteOperationGuard(tmp_path / "metrics-denial.sqlite3"),
        metrics=confirmation_metrics,
    )
    with pytest.raises(ConfirmationError):
        confirmation_gateway.invoke(
            SourceContext("test", "alice-source", "metrics-denied-confirmation"),
            "demo.restart",
            {"service": "api"},
            confirmed=True,
            confirmation_token="not-a-real-token",
        )
    snapshot = confirmation_metrics.snapshot()
    assert snapshot["events"]["confirmation_denied"] == 1
    assert snapshot["requests"]["invoke"]["confirmation_denied"] == 1

    audit_metrics = GatewayMetrics()

    def broken_required_audit(record):
        if record["event"] == "invoke_started":
            raise OSError("audit unavailable")

    audit_gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        audit_sink=broken_required_audit,
        metrics=audit_metrics,
    )
    with pytest.raises(OSError, match="audit unavailable"):
        audit_gateway.invoke(
            SourceContext("test", "alice-source", "metrics-required-audit"),
            "demo.status",
        )
    audit_snapshot = audit_metrics.snapshot()
    assert audit_snapshot["events"]["audit_required_failure"] == 1
    assert audit_snapshot["requests"]["invoke"]["failed"] == 1


def test_gateway_metrics_failures_and_admission_release_error_do_not_break_accounting():
    from secure_ops_gateway.admission import AdmissionLease
    from secure_ops_gateway.observability import GatewayMetrics

    class BeginBrokenMetrics(GatewayMetrics):
        def begin_request(self, _operation):
            raise RuntimeError("metrics start failed")

    gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        metrics=BeginBrokenMetrics(),
    )
    assert gateway.invoke(
        SourceContext("test", "alice-source", "metrics-begin-failure"),
        "demo.status",
    ) == {"ok": True}

    class ReleaseBrokenAdmission:
        def acquire(self, _source):
            return AdmissionLease(("test", "alice-source"))

        def release(self, _lease):
            raise RuntimeError("release failed")

    metrics = GatewayMetrics()
    release_gateway = gateway_for(
        lambda _route, _payload: {"ok": True},
        metrics=metrics,
        admission_controller=ReleaseBrokenAdmission(),
    )
    with pytest.raises(RuntimeError, match="release failed"):
        release_gateway.invoke(
            SourceContext("test", "alice-source", "metrics-release-failure"),
            "demo.status",
        )
    assert metrics.snapshot()["requests"]["invoke"]["failed"] == 1
