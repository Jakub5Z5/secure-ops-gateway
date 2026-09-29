import multiprocessing
from contextlib import closing
import os
import sqlite3
import stat

import pytest

from secure_ops_gateway import SQLiteAdmissionController
from secure_ops_gateway.admission import (
    AdmissionLease,
    AdmissionStateError,
    ConcurrencyLimitExceeded,
    GatewayAdmissionController,
    RateLimitExceeded,
)
from secure_ops_gateway.identity import SourceContext


def _hold_admission(path: str, subject: str, release_event, queue) -> None:
    controller = SQLiteAdmissionController(
        path,
        max_inflight_global=2,
        max_inflight_per_source=1,
        max_calls_per_window=20,
    )
    try:
        lease = controller.acquire(SourceContext("spawn", subject, f"req-{subject}"))
    except ConcurrencyLimitExceeded as exc:
        queue.put(("limited", str(exc)))
        return
    queue.put(("accepted", subject))
    release_event.wait(5)
    controller.release(lease)


def _acquire_without_release(path: str, queue) -> None:
    controller = SQLiteAdmissionController(
        path,
        max_inflight_global=1,
        max_inflight_per_source=1,
        max_calls_per_window=20,
    )
    controller.acquire(SourceContext("spawn", "crashed", "req-crashed"))
    queue.put("acquired")


def test_sqlite_admission_constructor_validates_limits(tmp_path):
    path = tmp_path / "private" / "admission.sqlite3"
    for kwargs in (
        {"max_inflight_global": 0},
        {"max_inflight_per_source": 0},
        {"max_calls_per_window": 0},
        {"max_tracked_sources": 0},
        {"window_seconds": 0},
    ):
        with pytest.raises(ValueError):
            SQLiteAdmissionController(path, **kwargs)
    with pytest.raises(ValueError, match="per-source"):
        SQLiteAdmissionController(
            path,
            max_inflight_global=1,
            max_inflight_per_source=2,
        )
    with pytest.raises(ValueError, match="timeout_seconds"):
        SQLiteAdmissionController(path, timeout_seconds=0)
    with pytest.raises(TypeError, match="release_failure_handler"):
        SQLiteAdmissionController(path, release_failure_handler="nope")


def test_sqlite_admission_rate_window_persists_across_instances(tmp_path):
    path = tmp_path / "private" / "admission.sqlite3"
    clock = {"now": 1000.0}
    kwargs = {
        "max_inflight_global": 2,
        "max_inflight_per_source": 1,
        "max_calls_per_window": 1,
        "window_seconds": 10,
        "clock": lambda: clock["now"],
    }
    context = SourceContext("transport", "alice", "req-1")
    first = SQLiteAdmissionController(path, **kwargs)
    first.release(first.acquire(context))

    restarted = SQLiteAdmissionController(path, **kwargs)
    with pytest.raises(RateLimitExceeded, match="rate"):
        restarted.acquire(SourceContext("transport", "alice", "req-2"))

    clock["now"] = 1011.0
    lease = restarted.acquire(SourceContext("transport", "alice", "req-3"))
    restarted.release(lease)


def test_sqlite_admission_shares_global_and_source_concurrency(tmp_path):
    path = tmp_path / "private" / "admission.sqlite3"
    kwargs = {
        "max_inflight_global": 2,
        "max_inflight_per_source": 1,
        "max_calls_per_window": 20,
    }
    first = SQLiteAdmissionController(path, **kwargs)
    second = SQLiteAdmissionController(path, **kwargs)
    a = SourceContext("transport", "a", "req-a")
    b = SourceContext("transport", "b", "req-b")
    c = SourceContext("transport", "c", "req-c")

    lease_a = first.acquire(a)
    with pytest.raises(ConcurrencyLimitExceeded, match="source"):
        second.acquire(a)
    lease_b = second.acquire(b)
    with pytest.raises(ConcurrencyLimitExceeded, match="global"):
        first.acquire(c)

    first.release(lease_a)
    second.release(lease_b)


def test_sqlite_admission_caps_shared_tracked_sources(tmp_path):
    path = tmp_path / "private" / "admission.sqlite3"
    clock = {"now": 100.0}
    controller = SQLiteAdmissionController(
        path,
        max_inflight_global=2,
        max_inflight_per_source=1,
        max_calls_per_window=5,
        max_tracked_sources=1,
        window_seconds=10,
        clock=lambda: clock["now"],
    )
    lease = controller.acquire(SourceContext("transport", "a", "req-a"))
    controller.release(lease)
    with pytest.raises(RateLimitExceeded, match="tracking"):
        SQLiteAdmissionController(
            path,
            max_inflight_global=2,
            max_inflight_per_source=1,
            max_calls_per_window=5,
            max_tracked_sources=1,
            window_seconds=10,
            clock=lambda: clock["now"],
        ).acquire(SourceContext("transport", "b", "req-b"))

    clock["now"] = 111.0
    restarted = SQLiteAdmissionController(
        path,
        max_inflight_global=2,
        max_inflight_per_source=1,
        max_calls_per_window=5,
        max_tracked_sources=1,
        window_seconds=10,
        clock=lambda: clock["now"],
    )
    lease_b = restarted.acquire(SourceContext("transport", "b", "req-b2"))
    restarted.release(lease_b)


def test_sqlite_admission_database_hashes_source_identity(tmp_path):
    path = tmp_path / "private" / "admission.sqlite3"
    controller = SQLiteAdmissionController(path)
    lease = controller.acquire(
        SourceContext("sensitive-provider", "sensitive-subject", "req")
    )
    controller.release(lease)

    with closing(sqlite3.connect(path)) as db:
        events = db.execute(
            "SELECT source_hash FROM admission_events"
        ).fetchall()
        leases = db.execute("SELECT lease_id FROM admission_leases").fetchall()
    assert len(events) == 1
    assert len(events[0][0]) == 64
    assert "sensitive" not in events[0][0]
    assert leases == []


@pytest.mark.skipif(os.name != "posix", reason="secure admission state paths are POSIX-specific")
def test_sqlite_admission_database_is_private_and_rejects_symlink(tmp_path):
    path = tmp_path / "private" / "admission.sqlite3"
    SQLiteAdmissionController(path)
    metadata = os.stat(path, follow_symlinks=False)
    assert stat.S_IMODE(metadata.st_mode) == 0o600

    other = tmp_path / "other.sqlite3"
    other.write_bytes(b"")
    link = tmp_path / "private-link" / "admission.sqlite3"
    link.parent.mkdir(mode=0o700)
    link.symlink_to(other)
    with pytest.raises(AdmissionStateError, match="unsafe"):
        SQLiteAdmissionController(link)


@pytest.mark.skipif(os.name != "posix", reason="secure admission state paths are POSIX-specific")
def test_sqlite_admission_rejects_parent_replacement_after_initialization(tmp_path):
    path = tmp_path / "private" / "admission.sqlite3"
    failures = []
    controller = SQLiteAdmissionController(
        path,
        release_failure_handler=lambda exc, lease: failures.append((exc, lease)),
    )
    lease = controller.acquire(SourceContext("transport", "a", "req-a"))
    original = path.parent
    moved = tmp_path / "moved"
    original.rename(moved)
    original.mkdir(mode=0o700)

    with pytest.raises(AdmissionStateError, match="unsafe"):
        controller.acquire(SourceContext("transport", "b", "req-b"))

    # Release failures are deliberately fail-closed and out-of-band: the old
    # lease remains counted rather than turning a completed mutation into a
    # client-visible failure that could encourage a duplicate retry.
    controller.release(lease)
    assert len(failures) == 1
    assert isinstance(failures[0][0], AdmissionStateError)
    assert failures[0][1] == lease


def test_sqlite_admission_release_validates_lease(tmp_path):
    controller = SQLiteAdmissionController(tmp_path / "private" / "admission.sqlite3")
    with pytest.raises(TypeError, match="AdmissionLease"):
        controller.release(object())
    with pytest.raises(ValueError, match="does not belong"):
        controller.release(AdmissionLease(("transport", "a")))


def test_sqlite_admission_recovers_lease_from_dead_process(tmp_path):
    if os.name != "posix":
        pytest.skip("dead-process admission recovery requires POSIX process semantics")
    path = tmp_path / "private" / "admission.sqlite3"
    SQLiteAdmissionController(
        path,
        max_inflight_global=1,
        max_inflight_per_source=1,
        max_calls_per_window=20,
    )
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    process = context.Process(
        target=_acquire_without_release,
        args=(str(path), queue),
    )
    process.start()
    assert queue.get(timeout=5) == "acquired"
    process.join(5)
    assert process.exitcode == 0

    recovered = SQLiteAdmissionController(
        path,
        max_inflight_global=1,
        max_inflight_per_source=1,
        max_calls_per_window=20,
    )
    lease = recovered.acquire(SourceContext("spawn", "crashed", "req-after"))
    recovered.release(lease)


def test_sqlite_admission_serializes_concurrent_processes(tmp_path):
    if os.name != "posix":
        pytest.skip("multiprocess admission test requires POSIX process semantics")
    path = tmp_path / "private" / "admission.sqlite3"
    SQLiteAdmissionController(
        path,
        max_inflight_global=2,
        max_inflight_per_source=1,
        max_calls_per_window=20,
    )
    context = multiprocessing.get_context("spawn")
    release_event = context.Event()
    queue = context.Queue()
    processes = [
        context.Process(
            target=_hold_admission,
            args=(str(path), f"source-{index}", release_event, queue),
        )
        for index in range(4)
    ]
    for process in processes:
        process.start()

    outcomes = [queue.get(timeout=8) for _ in processes]
    assert [status for status, _detail in outcomes].count("accepted") == 2
    assert [status for status, _detail in outcomes].count("limited") == 2
    assert all(
        "global" in detail
        for status, detail in outcomes
        if status == "limited"
    )

    release_event.set()
    for process in processes:
        process.join(5)
        assert process.exitcode == 0


def test_existing_in_memory_admission_controller_remains_available():
    controller = GatewayAdmissionController(
        max_inflight_global=1,
        max_inflight_per_source=1,
        max_calls_per_window=2,
    )
    context = SourceContext("transport", "a", "req")
    lease = controller.acquire(context)
    controller.release(lease)
