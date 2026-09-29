import pytest

from secure_ops_gateway.admission import (
    ConcurrencyLimitExceeded,
    GatewayAdmissionController,
    RateLimitExceeded,
)
from secure_ops_gateway.identity import SourceContext


def test_admission_constructor_validates_limits():
    for kwargs in (
        {"max_inflight_global": 0},
        {"max_inflight_per_source": 0},
        {"max_calls_per_window": 0},
        {"max_tracked_sources": 0},
        {"window_seconds": 0},
    ):
        with pytest.raises(ValueError):
            GatewayAdmissionController(**kwargs)
    with pytest.raises(ValueError, match="per-source"):
        GatewayAdmissionController(max_inflight_global=1, max_inflight_per_source=2)


def test_admission_enforces_global_and_source_concurrency():
    controller = GatewayAdmissionController(
        max_inflight_global=2,
        max_inflight_per_source=1,
        max_calls_per_window=10,
    )
    a = SourceContext("test", "a", "1")
    b = SourceContext("test", "b", "2")
    lease_a = controller.acquire(a)
    with pytest.raises(ConcurrencyLimitExceeded, match="source"):
        controller.acquire(a)
    lease_b = controller.acquire(b)
    with pytest.raises(ConcurrencyLimitExceeded, match="global"):
        controller.acquire(SourceContext("test", "c", "3"))
    controller.release(lease_a)
    controller.release(lease_b)


def test_admission_prunes_old_events_and_caps_tracked_sources():
    clock = {"now": 0.0}
    controller = GatewayAdmissionController(
        max_inflight_global=2,
        max_inflight_per_source=1,
        max_calls_per_window=1,
        window_seconds=10,
        max_tracked_sources=1,
        clock=lambda: clock["now"],
    )
    a = SourceContext("test", "a", "1")
    lease = controller.acquire(a)
    controller.release(lease)
    with pytest.raises(RateLimitExceeded, match="tracking"):
        controller.acquire(SourceContext("test", "b", "2"))
    clock["now"] = 11
    lease_b = controller.acquire(SourceContext("test", "b", "3"))
    controller.release(lease_b)
