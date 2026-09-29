import os
from contextlib import closing
import sqlite3

import pytest

from secure_ops_gateway.gateway import InvocationContext
from secure_ops_gateway.operation_guard import ConfirmationError, SQLiteOperationGuard


BASE_TOOL = {
    "name": "service.restart",
    "capability": "service.restart",
    "permission": "service.restart",
    "resource": "service:api",
    "risk": "write",
    "confirmation": "explicit",
    "arguments": {"service": "api"},
    "request": {"action": "restart", "service": "api"},
}
CONTEXT = InvocationContext("alice", "test", "subject", "request-1")


def test_sqlite_confirmation_database_is_private(tmp_path):
    path = tmp_path / "operations.sqlite3"
    SQLiteOperationGuard(path)
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_confirmation_token_binds_capability_permission_and_risk(tmp_path):
    guard = SQLiteOperationGuard(tmp_path / "operations.sqlite3")
    token = guard.issue(CONTEXT, BASE_TOOL)["confirmation_token"]
    for field, changed in (
        ("capability", "service.delete"),
        ("permission", "service.admin"),
        ("risk", "privileged"),
    ):
        modified = {**BASE_TOOL, field: changed}
        with pytest.raises(ConfirmationError, match="does not match"):
            guard.begin(token, CONTEXT, modified)


def test_uncertain_confirmation_cannot_be_retried(tmp_path):
    guard = SQLiteOperationGuard(tmp_path / "operations.sqlite3")
    token = guard.issue(CONTEXT, BASE_TOOL)["confirmation_token"]
    assert guard.begin(token, CONTEXT, BASE_TOOL)["execute"] is True
    guard.mark_uncertain(token)
    with pytest.raises(ConfirmationError, match="uncertain"):
        guard.begin(token, CONTEXT, BASE_TOOL)
    assert guard.status(token, CONTEXT)["status"] == "uncertain"



def test_confirmation_database_rejects_symlink(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("do-not-touch")
    link = tmp_path / "operations.sqlite3"
    link.symlink_to(victim)
    with pytest.raises(ConfirmationError, match="unsafe"):
        SQLiteOperationGuard(link)
    assert victim.read_text() == "do-not-touch"


def test_stale_executing_confirmation_becomes_uncertain(tmp_path, monkeypatch):
    clock = {"now": 1000}
    monkeypatch.setattr("secure_ops_gateway.operation_guard.time.time", lambda: clock["now"])
    guard = SQLiteOperationGuard(
        tmp_path / "operations.sqlite3",
        execution_stale_seconds=10,
    )
    token = guard.issue(CONTEXT, BASE_TOOL)["confirmation_token"]
    assert guard.begin(token, CONTEXT, BASE_TOOL)["execute"] is True
    clock["now"] = 1011
    assert guard.status(token, CONTEXT)["status"] == "uncertain"
    with pytest.raises(ConfirmationError, match="uncertain"):
        guard.begin(token, CONTEXT, BASE_TOOL)


def test_cleanup_removes_old_terminal_records(tmp_path, monkeypatch):
    clock = {"now": 1000}
    monkeypatch.setattr("secure_ops_gateway.operation_guard.time.time", lambda: clock["now"])
    path = tmp_path / "operations.sqlite3"
    guard = SQLiteOperationGuard(path, retention_seconds=10)
    token = guard.issue(CONTEXT, BASE_TOOL)["confirmation_token"]
    guard.begin(token, CONTEXT, BASE_TOOL)
    guard.complete(token, {"ok": True})
    clock["now"] = 1011
    assert guard.cleanup() == 1
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("SELECT COUNT(*) FROM confirmations").fetchone()[0] == 0



def test_begin_itself_persists_stale_execution_as_uncertain(tmp_path, monkeypatch):
    clock = {"now": 2000}
    monkeypatch.setattr("secure_ops_gateway.operation_guard.time.time", lambda: clock["now"])
    guard = SQLiteOperationGuard(
        tmp_path / "operations.sqlite3",
        execution_stale_seconds=5,
    )
    token = guard.issue(CONTEXT, BASE_TOOL)["confirmation_token"]
    guard.begin(token, CONTEXT, BASE_TOOL)
    clock["now"] = 2006
    with pytest.raises(ConfirmationError, match="uncertain"):
        guard.begin(token, CONTEXT, BASE_TOOL)
    assert guard.status(token, CONTEXT)["status"] == "uncertain"


def test_confirmation_database_rejects_parent_owned_by_unrelated_user(tmp_path, monkeypatch):
    actual_uid = os.geteuid()
    fake_uid = actual_uid + 10000 if actual_uid != 0 else 10000
    monkeypatch.setattr("secure_ops_gateway.paths.os.geteuid", lambda: fake_uid)
    with pytest.raises(ConfirmationError, match="parent is unsafe"):
        SQLiteOperationGuard(tmp_path / "operations.sqlite3")


def test_confirmation_database_detects_parent_replacement(tmp_path):
    parent = tmp_path / "state"
    parent.mkdir(mode=0o700)
    guard = SQLiteOperationGuard(parent / "operations.sqlite3")

    moved = tmp_path / "state-old"
    parent.rename(moved)
    parent.mkdir(mode=0o700)

    with pytest.raises(ConfirmationError, match="unsafe"):
        guard.issue(CONTEXT, BASE_TOOL)
    assert not (parent / "operations.sqlite3").exists()


def test_confirmation_guard_validates_constructor_and_unknown_token(tmp_path):
    with pytest.raises(ValueError):
        SQLiteOperationGuard(tmp_path / "bad.sqlite3", ttl_seconds=0)
    guard = SQLiteOperationGuard(tmp_path / "operations.sqlite3")
    with pytest.raises(ConfirmationError, match="unknown"):
        guard.begin("missing", CONTEXT, BASE_TOOL)
    with pytest.raises(ConfirmationError, match="unknown"):
        guard.status("missing", CONTEXT)


def test_confirmation_completed_response_is_idempotent(tmp_path):
    guard = SQLiteOperationGuard(tmp_path / "operations.sqlite3")
    token = guard.issue(CONTEXT, BASE_TOOL)["confirmation_token"]
    assert guard.begin(token, CONTEXT, BASE_TOOL)["execute"] is True
    guard.complete(token, {"ok": True})
    assert guard.begin(token, CONTEXT, BASE_TOOL) == {
        "execute": False,
        "response": {"ok": True},
    }


def test_confirmation_token_cannot_cross_source(tmp_path):
    guard = SQLiteOperationGuard(tmp_path / "operations.sqlite3")
    token = guard.issue(CONTEXT, BASE_TOOL)["confirmation_token"]
    other = InvocationContext("bob", "test", "other", "request-2")
    with pytest.raises(ConfirmationError, match="another source"):
        guard.begin(token, other, BASE_TOOL)
    with pytest.raises(ConfirmationError, match="unknown"):
        guard.status(token, other)


def test_confirmation_guard_closes_all_internal_database_connections(tmp_path, monkeypatch):
    original_connect = sqlite3.connect
    opened = []

    class TrackingConnection(sqlite3.Connection):
        was_closed = False

        def close(self):
            self.was_closed = True
            return super().close()

    def tracked_connect(*args, **kwargs):
        kwargs["factory"] = TrackingConnection
        connection = original_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr("secure_ops_gateway.operation_guard.sqlite3.connect", tracked_connect)
    guard = SQLiteOperationGuard(tmp_path / "operations.sqlite3")
    token = guard.issue(CONTEXT, BASE_TOOL)["confirmation_token"]
    assert guard.begin(token, CONTEXT, BASE_TOOL)["execute"] is True
    guard.complete(token, {"ok": True})
    assert guard.status(token, CONTEXT)["status"] == "completed"
    guard.cleanup()

    assert opened
    assert all(connection.was_closed for connection in opened)


def test_confirmation_guard_rejects_invalid_and_conflicting_states(tmp_path, monkeypatch):
    clock = {"now": 1000}
    monkeypatch.setattr("secure_ops_gateway.operation_guard.time.time", lambda: clock["now"])
    guard = SQLiteOperationGuard(tmp_path / "operations.sqlite3", ttl_seconds=5)

    with pytest.raises(ConfirmationError, match="invalid confirmation token"):
        guard.begin("", CONTEXT, BASE_TOOL)

    token = guard.issue(CONTEXT, BASE_TOOL)["confirmation_token"]
    assert guard.begin(token, CONTEXT, BASE_TOOL)["execute"] is True
    with pytest.raises(ConfirmationError, match="already in use"):
        guard.begin(token, CONTEXT, BASE_TOOL)
    with pytest.raises(ConfirmationError, match="cannot be released"):
        guard.abort_before_execution("missing")

    guard.complete(token, {"ok": True})
    with pytest.raises(ConfirmationError, match="not executing"):
        guard.complete(token, {"ok": True})

    expired = guard.issue(CONTEXT, BASE_TOOL)["confirmation_token"]
    clock["now"] = 1006
    with pytest.raises(ConfirmationError, match="not usable"):
        guard.begin(expired, CONTEXT, BASE_TOOL)
