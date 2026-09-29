from __future__ import annotations

from copy import deepcopy
import threading
import time
from typing import Callable


class MetricsError(ValueError):
    pass


class GatewayMetrics:
    """Bounded, process-local gateway metrics with no identity/resource labels.

    The collector intentionally exposes only fixed operation, outcome and event
    names. Caller-controlled principal, source, tool, capability and resource
    values are never accepted as metric labels, keeping cardinality bounded and
    avoiding accidental disclosure through metrics backends.
    """

    OPERATIONS = ("catalog", "invoke")
    OUTCOMES = (
        "success",
        "admission_denied",
        "identity_denied",
        "authorization_denied",
        "confirmation_required",
        "confirmation_denied",
        "failed",
    )
    EVENTS = (
        "admission_rate_limited",
        "admission_concurrency_limited",
        "admission_state_error",
        "admission_release_failure",
        "identity_denied",
        "authorization_denied",
        "confirmation_required",
        "confirmation_denied",
        "invoke_replayed",
        "invoke_uncertain",
        "executor_failure",
        "audit_required_failure",
        "audit_best_effort_failure",
    )

    def __init__(self, *, clock: Callable[[], float] | None = None) -> None:
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._clock = time.monotonic if clock is None else clock
        self._lock = threading.Lock()
        self._started_at = float(self._clock())
        self._inflight = {operation: 0 for operation in self.OPERATIONS}
        self._requests = {
            operation: {outcome: 0 for outcome in self.OUTCOMES}
            for operation in self.OPERATIONS
        }
        self._durations = {
            operation: {"count": 0, "sum": 0.0, "max": 0.0}
            for operation in self.OPERATIONS
        }
        self._events = {event: 0 for event in self.EVENTS}

    @classmethod
    def _operation(cls, operation: str) -> str:
        if operation not in cls.OPERATIONS:
            raise MetricsError("unsupported metrics operation")
        return operation

    @classmethod
    def _outcome(cls, outcome: str) -> str:
        if outcome not in cls.OUTCOMES:
            raise MetricsError("unsupported metrics outcome")
        return outcome

    @classmethod
    def _event(cls, event: str) -> str:
        if event not in cls.EVENTS:
            raise MetricsError("unsupported metrics event")
        return event

    def begin_request(self, operation: str) -> float:
        operation = self._operation(operation)
        started = float(self._clock())
        with self._lock:
            self._inflight[operation] += 1
        return started

    def finish_request(
        self,
        operation: str,
        outcome: str,
        started_at: float,
    ) -> None:
        operation = self._operation(operation)
        outcome = self._outcome(outcome)
        try:
            started = float(started_at)
        except (TypeError, ValueError) as exc:
            raise MetricsError("started_at must be numeric") from exc
        duration = max(0.0, float(self._clock()) - started)
        with self._lock:
            if self._inflight[operation] <= 0:
                raise MetricsError("metrics request was not started")
            self._inflight[operation] -= 1
            self._requests[operation][outcome] += 1
            aggregate = self._durations[operation]
            aggregate["count"] += 1
            aggregate["sum"] += duration
            aggregate["max"] = max(aggregate["max"], duration)

    def record_event(self, event: str) -> None:
        event = self._event(event)
        with self._lock:
            self._events[event] += 1

    def admission_release_failure(self, _exc, _lease) -> None:
        """Compatible handler for SQLiteAdmissionController release failures."""

        self.record_event("admission_release_failure")

    def snapshot(self) -> dict:
        now = float(self._clock())
        with self._lock:
            return {
                "schema": 1,
                "uptime_seconds": max(0.0, now - self._started_at),
                "inflight": dict(self._inflight),
                "requests": deepcopy(self._requests),
                "duration_seconds": deepcopy(self._durations),
                "events": dict(self._events),
            }

    def render_prometheus(self) -> str:
        """Render a bounded Prometheus text snapshot without user labels."""

        snapshot = self.snapshot()
        lines = [
            "# TYPE secure_ops_gateway_uptime_seconds gauge",
            f"secure_ops_gateway_uptime_seconds {snapshot['uptime_seconds']:.9f}",
            "# TYPE secure_ops_gateway_inflight_requests gauge",
        ]
        for operation in self.OPERATIONS:
            lines.append(
                "secure_ops_gateway_inflight_requests"
                f'{{operation="{operation}"}} {snapshot["inflight"][operation]}'
            )
        lines.append("# TYPE secure_ops_gateway_requests_total counter")
        for operation in self.OPERATIONS:
            for outcome in self.OUTCOMES:
                value = snapshot["requests"][operation][outcome]
                lines.append(
                    "secure_ops_gateway_requests_total"
                    f'{{operation="{operation}",outcome="{outcome}"}} {value}'
                )
        lines.extend(
            [
                "# TYPE secure_ops_gateway_request_duration_seconds_count counter",
                "# TYPE secure_ops_gateway_request_duration_seconds_sum counter",
                "# TYPE secure_ops_gateway_request_duration_seconds_max gauge",
            ]
        )
        for operation in self.OPERATIONS:
            aggregate = snapshot["duration_seconds"][operation]
            lines.append(
                "secure_ops_gateway_request_duration_seconds_count"
                f'{{operation="{operation}"}} {aggregate["count"]}'
            )
            lines.append(
                "secure_ops_gateway_request_duration_seconds_sum"
                f'{{operation="{operation}"}} {aggregate["sum"]:.9f}'
            )
            lines.append(
                "secure_ops_gateway_request_duration_seconds_max"
                f'{{operation="{operation}"}} {aggregate["max"]:.9f}'
            )
        lines.append("# TYPE secure_ops_gateway_events_total counter")
        for event in self.EVENTS:
            lines.append(
                "secure_ops_gateway_events_total"
                f'{{event="{event}"}} {snapshot["events"][event]}'
            )
        return "\n".join(lines) + "\n"
