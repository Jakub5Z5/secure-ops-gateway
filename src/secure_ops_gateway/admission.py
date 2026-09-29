from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from typing import Callable

from .paths import (
    SecurePathError,
    prepare_private_parent,
    private_parent_identity,
    reject_symlink_leaf,
    verify_private_parent_identity,
)


class AdmissionError(RuntimeError):
    pass


class RateLimitExceeded(AdmissionError):
    pass


class ConcurrencyLimitExceeded(AdmissionError):
    pass


class AdmissionStateError(AdmissionError):
    pass


@dataclass(frozen=True)
class AdmissionLease:
    source_key: tuple[str, str]
    lease_id: str | None = None


def _validate_limits(
    *,
    max_inflight_global: int,
    max_inflight_per_source: int,
    max_calls_per_window: int,
    window_seconds: float,
    max_tracked_sources: int,
) -> None:
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


def _source_hash(key: tuple[str, str]) -> str:
    raw = json.dumps(
        list(key),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _linux_process_start_ticks(pid: int) -> str | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError:
        return "unknown"
    try:
        tail = raw.rsplit(")", 1)[1].strip().split()
        return tail[19]
    except (IndexError, ValueError):
        return "unknown"


def _linux_boot_id() -> str | None:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="utf-8"
        ).strip()
    except OSError:
        return None
    return value or None


def _process_marker(pid: int) -> str:
    boot_id = _linux_boot_id()
    start_ticks = _linux_process_start_ticks(pid)
    if boot_id is not None and start_ticks not in {None, "unknown"}:
        return f"linux:{boot_id}:{pid}:{start_ticks}"
    return f"pid:{pid}"


def _process_marker_alive(pid: int, marker: str) -> bool:
    if marker.startswith("linux:"):
        boot_id = _linux_boot_id()
        start_ticks = _linux_process_start_ticks(pid)
        if boot_id is None or start_ticks == "unknown":
            return True
        if start_ticks is None:
            return False
        return marker == f"linux:{boot_id}:{pid}:{start_ticks}"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


class GatewayAdmissionController:
    """Small in-process admission controller for gateway calls.

    Admission is keyed by the authenticated transport identity, not by the
    resolved principal. This lets the limiter protect identity resolution and
    identity-denied audit paths as well as authorized calls.

    Multi-process deployments should use ``SQLiteAdmissionController`` when
    they need one same-host rate/concurrency boundary across gateway workers.
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
        _validate_limits(
            max_inflight_global=max_inflight_global,
            max_inflight_per_source=max_inflight_per_source,
            max_calls_per_window=max_calls_per_window,
            window_seconds=window_seconds,
            max_tracked_sources=max_tracked_sources,
        )
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


class SQLiteAdmissionController:
    """Durable same-host gateway admission control backed by SQLite.

    Rate-window events survive worker restarts and are shared by all gateway
    processes using the same database. In-flight leases are transactionally
    counted across processes. Each lease records its owning process identity;
    on Linux, the kernel boot ID plus ``/proc/<pid>/stat`` start ticks protect
    cleanup against PID reuse and host reboot.
    Dead-process leases are removed before every admission attempt, so a crashed
    worker does not permanently consume concurrency capacity.

    Source provider/subject strings are not stored in the database. A SHA-256
    digest of the authenticated source tuple is used as the shared key.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        max_inflight_global: int = 16,
        max_inflight_per_source: int = 4,
        max_calls_per_window: int = 120,
        window_seconds: float = 60.0,
        max_tracked_sources: int = 4096,
        timeout_seconds: float = 5.0,
        clock=None,
        release_failure_handler: Callable[[Exception, AdmissionLease], None] | None = None,
    ) -> None:
        _validate_limits(
            max_inflight_global=max_inflight_global,
            max_inflight_per_source=max_inflight_per_source,
            max_calls_per_window=max_calls_per_window,
            window_seconds=window_seconds,
            max_tracked_sources=max_tracked_sources,
        )
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")
        if release_failure_handler is not None and not callable(release_failure_handler):
            raise TypeError("release_failure_handler must be callable")
        try:
            self.path = prepare_private_parent(path)
            self._parent_identity = private_parent_identity(self.path)
        except SecurePathError as exc:
            raise AdmissionStateError("admission database parent is unsafe") from exc
        self.max_inflight_global = max_inflight_global
        self.max_inflight_per_source = max_inflight_per_source
        self.max_calls_per_window = max_calls_per_window
        self.window_seconds = float(window_seconds)
        self.max_tracked_sources = max_tracked_sources
        self.timeout_seconds = float(timeout_seconds)
        self.clock = time.time if clock is None else clock
        self.release_failure_handler = release_failure_handler
        self._ensure_private_database_file()
        try:
            with self._database() as db:
                db.execute(
                    """CREATE TABLE IF NOT EXISTS admission_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source_hash TEXT NOT NULL,
                        occurred_at REAL NOT NULL
                    )"""
                )
                db.execute(
                    """CREATE INDEX IF NOT EXISTS admission_events_source_time_idx
                       ON admission_events(source_hash, occurred_at)"""
                )
                db.execute(
                    """CREATE INDEX IF NOT EXISTS admission_events_time_idx
                       ON admission_events(occurred_at)"""
                )
                db.execute(
                    """CREATE TABLE IF NOT EXISTS admission_leases (
                        lease_id TEXT PRIMARY KEY,
                        source_hash TEXT NOT NULL,
                        owner_pid INTEGER NOT NULL,
                        owner_marker TEXT NOT NULL,
                        acquired_at REAL NOT NULL
                    )"""
                )
                db.execute(
                    """CREATE INDEX IF NOT EXISTS admission_leases_source_idx
                       ON admission_leases(source_hash)"""
                )
        except sqlite3.Error as exc:
            raise AdmissionStateError("cannot initialize admission database") from exc
        self._enforce_private_permissions()
        self.cleanup()

    @staticmethod
    def source_key(context) -> tuple[str, str]:
        return GatewayAdmissionController.source_key(context)

    def _ensure_private_database_file(self) -> None:
        try:
            prepare_private_parent(self.path)
            verify_private_parent_identity(self.path, self._parent_identity)
            reject_symlink_leaf(self.path)
        except SecurePathError as exc:
            raise AdmissionStateError("admission database path is unsafe") from exc
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags, 0o600)
        except FileExistsError:
            try:
                reject_symlink_leaf(self.path)
                self._enforce_private_permissions()
            except SecurePathError as exc:
                raise AdmissionStateError("admission database path is unsafe") from exc
        except OSError as exc:
            raise AdmissionStateError("cannot create admission database safely") from exc
        else:
            os.close(fd)

    def _enforce_private_permissions(self) -> None:
        try:
            prepare_private_parent(self.path)
            verify_private_parent_identity(self.path, self._parent_identity)
            reject_symlink_leaf(self.path)
            os.chmod(self.path, 0o600, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except (OSError, SecurePathError) as exc:
            raise AdmissionStateError("admission database path is unsafe") from exc

    def _connect(self):
        try:
            prepare_private_parent(self.path)
            verify_private_parent_identity(self.path, self._parent_identity)
            reject_symlink_leaf(self.path)
        except SecurePathError as exc:
            raise AdmissionStateError("admission database path is unsafe") from exc
        self._enforce_private_permissions()
        try:
            connection = sqlite3.connect(self.path, timeout=self.timeout_seconds)
        except sqlite3.Error as exc:
            raise AdmissionStateError("cannot open admission database") from exc
        try:
            reject_symlink_leaf(self.path)
            self._enforce_private_permissions()
        except Exception:
            connection.close()
            raise
        return connection

    @contextmanager
    def _database(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _dead_owner_rows(db) -> list[tuple[int, str]]:
        owners = db.execute(
            "SELECT DISTINCT owner_pid, owner_marker FROM admission_leases"
        ).fetchall()
        return [
            (int(pid), str(marker))
            for pid, marker in owners
            if not _process_marker_alive(int(pid), str(marker))
        ]

    def _prune_locked(self, db, now: float) -> int:
        cutoff = now - self.window_seconds
        removed = db.execute(
            "DELETE FROM admission_events WHERE occurred_at <= ?",
            (cutoff,),
        ).rowcount
        for pid, marker in self._dead_owner_rows(db):
            removed += db.execute(
                "DELETE FROM admission_leases WHERE owner_pid=? AND owner_marker=?",
                (pid, marker),
            ).rowcount
        return removed

    def cleanup(self, *, now: float | None = None) -> int:
        current = float(self.clock()) if now is None else float(now)
        try:
            with self._database() as db:
                db.execute("BEGIN IMMEDIATE")
                return self._prune_locked(db, current)
        except AdmissionStateError:
            raise
        except sqlite3.Error as exc:
            raise AdmissionStateError("admission database cleanup failed") from exc

    @staticmethod
    def _tracked_source_count(db) -> int:
        row = db.execute(
            """SELECT COUNT(*) FROM (
                   SELECT source_hash FROM admission_events
                   UNION
                   SELECT source_hash FROM admission_leases
               )"""
        ).fetchone()
        return int(row[0])

    @staticmethod
    def _source_is_tracked(db, source_hash: str) -> bool:
        return (
            db.execute(
                "SELECT 1 FROM admission_events WHERE source_hash=? LIMIT 1",
                (source_hash,),
            ).fetchone()
            is not None
            or db.execute(
                "SELECT 1 FROM admission_leases WHERE source_hash=? LIMIT 1",
                (source_hash,),
            ).fetchone()
            is not None
        )

    def acquire(self, context) -> AdmissionLease:
        now = float(self.clock())
        key = self.source_key(context)
        source_hash = _source_hash(key)
        owner_pid = os.getpid()
        owner_marker = _process_marker(owner_pid)
        lease_id = secrets.token_urlsafe(24)
        try:
            with self._database() as db:
                db.execute("BEGIN IMMEDIATE")
                self._prune_locked(db, now)
                if not self._source_is_tracked(db, source_hash):
                    if self._tracked_source_count(db) >= self.max_tracked_sources:
                        raise RateLimitExceeded("gateway source tracking limit exceeded")
                rate_count = db.execute(
                    "SELECT COUNT(*) FROM admission_events WHERE source_hash=?",
                    (source_hash,),
                ).fetchone()[0]
                if int(rate_count) >= self.max_calls_per_window:
                    raise RateLimitExceeded("gateway rate limit exceeded")
                global_inflight = db.execute(
                    "SELECT COUNT(*) FROM admission_leases"
                ).fetchone()[0]
                if int(global_inflight) >= self.max_inflight_global:
                    raise ConcurrencyLimitExceeded(
                        "gateway global concurrency limit exceeded"
                    )
                source_inflight = db.execute(
                    "SELECT COUNT(*) FROM admission_leases WHERE source_hash=?",
                    (source_hash,),
                ).fetchone()[0]
                if int(source_inflight) >= self.max_inflight_per_source:
                    raise ConcurrencyLimitExceeded(
                        "gateway source concurrency limit exceeded"
                    )
                db.execute(
                    "INSERT INTO admission_events(source_hash, occurred_at) VALUES (?, ?)",
                    (source_hash, now),
                )
                db.execute(
                    """INSERT INTO admission_leases(
                           lease_id, source_hash, owner_pid, owner_marker, acquired_at
                       ) VALUES (?, ?, ?, ?, ?)""",
                    (lease_id, source_hash, owner_pid, owner_marker, now),
                )
        except AdmissionError:
            raise
        except sqlite3.Error as exc:
            raise AdmissionStateError("admission database operation failed") from exc
        self._enforce_private_permissions()
        return AdmissionLease(key, lease_id)

    def _report_release_failure(self, exc: Exception, lease: AdmissionLease) -> None:
        handler = self.release_failure_handler
        if handler is None:
            return
        try:
            handler(exc, lease)
        except Exception:
            pass

    def release(self, lease: AdmissionLease) -> None:
        if not isinstance(lease, AdmissionLease):
            raise TypeError("lease must be AdmissionLease")
        if not isinstance(lease.lease_id, str) or not lease.lease_id:
            raise ValueError("lease does not belong to SQLiteAdmissionController")
        try:
            source_hash = _source_hash(lease.source_key)
            with self._database() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "DELETE FROM admission_leases WHERE lease_id=? AND source_hash=?",
                    (lease.lease_id, source_hash),
                )
            self._enforce_private_permissions()
        except Exception as exc:
            # Failure to release can only make admission stricter because the
            # lease remains counted. Do not turn a completed mutation into a
            # client-visible failure that could encourage a duplicate retry.
            if isinstance(exc, AdmissionStateError):
                wrapped = exc
            elif isinstance(exc, sqlite3.Error):
                wrapped = AdmissionStateError("admission database release failed")
                wrapped.__cause__ = exc
            else:
                wrapped = exc
            self._report_release_failure(wrapped, lease)
