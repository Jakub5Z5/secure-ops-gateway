from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import threading
import time


class AdmissionError(RuntimeError):
    pass


class RateLimitExceeded(AdmissionError):
    pass


class ConcurrencyLimitExceeded(AdmissionError):
    pass


@dataclass(frozen=True)
class AdmissionLease:
    source_key: tuple[str, str]


class GatewayAdmissionController:
    """Small in-process admission controller for gateway calls.

    Admission is keyed by the authenticated transport identity, not by the
    resolved principal. This lets the limiter protect identity resolution and
    identity-denied audit paths as well as authorized calls.

    Distributed deployments should replace this with a shared limiter if they
    need a global limit across gateway replicas.
    """

    def __init__(
        self,
        *,
        max_inflight_global: int = 16,
        max_inflight_per_source: int = 4,
        max_calls_per_window: int = 120,
        window_seconds: float = 60.0,
        max_tracked_sources: int = 4096,
        clock=None,
    ):
        for name, value in {
            "max_inflight_global": max_inflight_global,
            "max_inflight_per_source": max_inflight_per_source,
            "max_calls_per_window": max_calls_per_window,
            "max_tracked_sources": max_tracked_sources,
        }.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if max_inflight_per_source > max_inflight_global:
            raise ValueError("per-source inflight limit exceeds global limit")
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or window_seconds <= 0
        ):
            raise ValueError("window_seconds must be positive")
        self.max_inflight_global = max_inflight_global
        self.max_inflight_per_source = max_inflight_per_source
        self.max_calls_per_window = max_calls_per_window
        self.window_seconds = float(window_seconds)
        self.max_tracked_sources = max_tracked_sources
        self.clock = time.monotonic if clock is None else clock
        self._lock = threading.Lock()
        self._global_inflight = 0
        self._source_inflight: dict[tuple[str, str], int] = {}
        self._events: dict[tuple[str, str], deque[float]] = {}

    @staticmethod
    def source_key(context) -> tuple[str, str]:
        return (
            context.source_provider,
            context.source_subject,
        )

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        stale = []
        for key, events in self._events.items():
            while events and events[0] <= cutoff:
                events.popleft()
            if not events and self._source_inflight.get(key, 0) == 0:
                stale.append(key)
        for key in stale:
            self._events.pop(key, None)

    def acquire(self, context) -> AdmissionLease:
        now = float(self.clock())
        key = self.source_key(context)
        with self._lock:
            self._prune(now)
            events = self._events.get(key)
            if events is None:
                if len(self._events) >= self.max_tracked_sources:
                    raise RateLimitExceeded("gateway source tracking limit exceeded")
                events = deque()
                self._events[key] = events
            if len(events) >= self.max_calls_per_window:
                raise RateLimitExceeded("gateway rate limit exceeded")
            if self._global_inflight >= self.max_inflight_global:
                raise ConcurrencyLimitExceeded("gateway global concurrency limit exceeded")
            inflight = self._source_inflight.get(key, 0)
            if inflight >= self.max_inflight_per_source:
                raise ConcurrencyLimitExceeded("gateway source concurrency limit exceeded")
            events.append(now)
            self._global_inflight += 1
            self._source_inflight[key] = inflight + 1
        return AdmissionLease(key)

    def release(self, lease: AdmissionLease) -> None:
        key = lease.source_key
        with self._lock:
            inflight = self._source_inflight.get(key, 0)
            if inflight <= 1:
                self._source_inflight.pop(key, None)
            else:
                self._source_inflight[key] = inflight - 1
            if self._global_inflight > 0:
                self._global_inflight -= 1
