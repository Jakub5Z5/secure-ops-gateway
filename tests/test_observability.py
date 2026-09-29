import pytest

from secure_ops_gateway.observability import GatewayMetrics, MetricsError


def test_gateway_metrics_records_bounded_snapshot_and_durations():
    clock = {"now": 10.0}
    metrics = GatewayMetrics(clock=lambda: clock["now"])

    invoke_started = metrics.begin_request("invoke")
    catalog_started = metrics.begin_request("catalog")
    clock["now"] = 10.25
    metrics.finish_request("catalog", "success", catalog_started)
    clock["now"] = 10.75
    metrics.finish_request("invoke", "failed", invoke_started)
    metrics.record_event("executor_failure")
    metrics.record_event("executor_failure")

    snapshot = metrics.snapshot()
    assert snapshot["schema"] == 1
    assert snapshot["uptime_seconds"] == pytest.approx(0.75)
    assert snapshot["inflight"] == {"catalog": 0, "invoke": 0}
    assert snapshot["requests"]["catalog"]["success"] == 1
    assert snapshot["requests"]["invoke"]["failed"] == 1
    assert snapshot["duration_seconds"]["catalog"] == {
        "count": 1,
        "sum": pytest.approx(0.25),
        "max": pytest.approx(0.25),
    }
    assert snapshot["duration_seconds"]["invoke"] == {
        "count": 1,
        "sum": pytest.approx(0.75),
        "max": pytest.approx(0.75),
    }
    assert snapshot["events"]["executor_failure"] == 2


def test_gateway_metrics_clamps_clock_regression_and_returns_copies():
    clock = {"now": 5.0}
    metrics = GatewayMetrics(clock=lambda: clock["now"])
    started = metrics.begin_request("invoke")
    clock["now"] = 4.0
    metrics.finish_request("invoke", "success", started)

    first = metrics.snapshot()
    assert first["uptime_seconds"] == 0.0
    assert first["duration_seconds"]["invoke"]["sum"] == 0.0
    first["requests"]["invoke"]["success"] = 999
    assert metrics.snapshot()["requests"]["invoke"]["success"] == 1


def test_gateway_metrics_rejects_unbounded_or_invalid_dimensions():
    with pytest.raises(TypeError, match="clock"):
        GatewayMetrics(clock=object())

    metrics = GatewayMetrics(clock=lambda: 1.0)
    with pytest.raises(MetricsError, match="operation"):
        metrics.begin_request("user-controlled-operation")
    started = metrics.begin_request("invoke")
    with pytest.raises(MetricsError, match="outcome"):
        metrics.finish_request("invoke", "principal-alice", started)
    with pytest.raises(MetricsError, match="numeric"):
        metrics.finish_request("invoke", "success", object())
    metrics.finish_request("invoke", "success", started)
    with pytest.raises(MetricsError, match="not started"):
        metrics.finish_request("invoke", "success", started)
    with pytest.raises(MetricsError, match="event"):
        metrics.record_event("resource:secret")


def test_gateway_metrics_prometheus_is_bounded_and_contains_no_dynamic_identity():
    metrics = GatewayMetrics(clock=lambda: 10.0)
    started = metrics.begin_request("invoke")
    metrics.finish_request("invoke", "identity_denied", started)
    metrics.record_event("identity_denied")

    rendered = metrics.render_prometheus()
    assert "secure_ops_gateway_requests_total" in rendered
    assert 'operation="invoke",outcome="identity_denied"' in rendered
    assert 'event="identity_denied"' in rendered
    assert "principal" not in rendered
    assert "subject" not in rendered
    assert "resource" not in rendered
    assert rendered.endswith("\n")


def test_gateway_metrics_release_failure_handler_is_low_cardinality():
    metrics = GatewayMetrics(clock=lambda: 1.0)
    metrics.admission_release_failure(RuntimeError("secret path"), object())
    snapshot = metrics.snapshot()
    assert snapshot["events"]["admission_release_failure"] == 1
