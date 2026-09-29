import multiprocessing
from contextlib import closing
import os
import sqlite3
import stat
import time

import pytest

from secure_ops_gateway import SQLiteReplayProtector
from secure_ops_gateway.executor import ExecutorError, ReplayCache, sign_envelope, verify_envelope


NONCE = "a" * 32
KEY = b"k" * 32


def _accept_once(path: str, nonce: str, timestamp: int, queue) -> None:
    try:
        protector = SQLiteReplayProtector(path, max_age_seconds=60)
        protector.accept(nonce, timestamp, now=timestamp)
    except ExecutorError as exc:
        queue.put(str(exc))
    else:
        queue.put("accepted")


def test_sqlite_replay_persists_across_instances(tmp_path):
    path = tmp_path / "private" / "replay.sqlite3"
    now = int(time.time())
    first = SQLiteReplayProtector(path, max_age_seconds=60)
    first.accept(NONCE, now, now=now)

    second = SQLiteReplayProtector(path, max_age_seconds=60)
    with pytest.raises(ExecutorError, match="replayed"):
        second.accept(NONCE, now, now=now + 1)


def test_sqlite_replay_integrates_with_authenticated_envelope_across_restart(tmp_path):
    path = tmp_path / "private" / "replay.sqlite3"
    now = int(time.time())
    envelope = sign_envelope(
        {"request_id": "req-1"},
        KEY,
        timestamp=now,
        nonce=NONCE,
    )
    first = SQLiteReplayProtector(path, max_age_seconds=60)
    assert verify_envelope(
        envelope,
        KEY,
        replay_protector=first,
        max_skew_seconds=30,
        now=now,
    ) == {"request_id": "req-1"}

    restarted = SQLiteReplayProtector(path, max_age_seconds=60)
    with pytest.raises(ExecutorError, match="replayed"):
        verify_envelope(
            envelope,
            KEY,
            replay_protector=restarted,
            max_skew_seconds=30,
            now=now + 1,
        )


def test_sqlite_replay_prunes_entries_outside_retention(tmp_path):
    path = tmp_path / "private" / "replay.sqlite3"
    protector = SQLiteReplayProtector(path, max_age_seconds=60)
    protector.accept("1" * 32, 100, now=100)
    protector.accept("2" * 32, 160, now=160)

    assert protector.cleanup(now=161) == 1
    protector.accept("1" * 32, 161, now=161)
    with pytest.raises(ExecutorError, match="replayed"):
        protector.accept("2" * 32, 160, now=161)


def test_sqlite_replay_rejects_retention_shorter_than_auth_window(tmp_path):
    path = tmp_path / "private" / "replay.sqlite3"
    protector = SQLiteReplayProtector(path, max_age_seconds=10)
    envelope = sign_envelope(
        {"request_id": "req-1"},
        KEY,
        timestamp=1000,
        nonce=NONCE,
    )
    with pytest.raises(ExecutorError, match="retention is shorter"):
        verify_envelope(
            envelope,
            KEY,
            replay_protector=protector,
            max_skew_seconds=30,
            now=1000,
        )


@pytest.mark.skipif(os.name != "posix", reason="secure replay state paths are POSIX-specific")
def test_sqlite_replay_database_is_private_and_rejects_symlink(tmp_path):
    path = tmp_path / "private" / "replay.sqlite3"
    SQLiteReplayProtector(path)
    metadata = os.stat(path, follow_symlinks=False)
    assert stat.S_IMODE(metadata.st_mode) == 0o600

    other = tmp_path / "other.sqlite3"
    other.write_bytes(b"")
    link = tmp_path / "private-link" / "replay.sqlite3"
    link.parent.mkdir(mode=0o700)
    link.symlink_to(other)
    with pytest.raises(ExecutorError, match="unsafe"):
        SQLiteReplayProtector(link)


@pytest.mark.skipif(os.name != "posix", reason="secure replay state paths are POSIX-specific")
def test_sqlite_replay_rejects_parent_replacement_after_initialization(tmp_path):
    path = tmp_path / "private" / "replay.sqlite3"
    protector = SQLiteReplayProtector(path)
    original = path.parent
    moved = tmp_path / "moved"
    original.rename(moved)
    original.mkdir(mode=0o700)

    with pytest.raises(ExecutorError, match="unsafe"):
        protector.accept(NONCE, 1000, now=1000)


def test_sqlite_replay_serializes_concurrent_processes(tmp_path):
    if os.name != "posix":
        pytest.skip("multiprocess replay test requires POSIX fork")
    path = tmp_path / "private" / "replay.sqlite3"
    SQLiteReplayProtector(path, max_age_seconds=60)

    now = int(time.time())
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(
            target=_accept_once,
            args=(str(path), NONCE, now, queue),
        )
        for _ in range(4)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(5)
        assert process.exitcode == 0

    outcomes = [queue.get(timeout=2) for _ in processes]
    assert outcomes.count("accepted") == 1
    assert outcomes.count("authenticated envelope replayed") == 3


def test_sqlite_replay_constructor_and_direct_input_validation(tmp_path):
    path = tmp_path / "private" / "replay.sqlite3"
    with pytest.raises(ValueError, match="max_age_seconds"):
        SQLiteReplayProtector(path, max_age_seconds=0)
    with pytest.raises(ValueError, match="timeout_seconds"):
        SQLiteReplayProtector(path, timeout_seconds=0)

    protector = SQLiteReplayProtector(path)
    with pytest.raises(ExecutorError, match="nonce"):
        protector.accept("not-a-nonce", 1, now=1)
    with pytest.raises(ExecutorError, match="timestamp"):
        protector.accept(NONCE, True, now=1)


def test_sqlite_replay_shared_database_contains_only_bounded_nonce_state(tmp_path):
    path = tmp_path / "private" / "replay.sqlite3"
    protector = SQLiteReplayProtector(path, max_age_seconds=60)
    protector.accept(NONCE, 1000, now=1000)

    with closing(sqlite3.connect(path)) as db:
        rows = db.execute(
            "SELECT nonce, envelope_timestamp FROM replay_nonces"
        ).fetchall()
    assert rows == [(NONCE, 1000)]


def test_existing_in_memory_replay_cache_remains_available():
    cache = ReplayCache(max_age_seconds=60)
    cache.accept(NONCE, 1000, now=1000)
    with pytest.raises(ExecutorError, match="replayed"):
        cache.accept(NONCE, 1000, now=1000)
