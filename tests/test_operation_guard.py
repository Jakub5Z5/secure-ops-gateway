import os
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
    with sqlite3.connect(path) as db:
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
