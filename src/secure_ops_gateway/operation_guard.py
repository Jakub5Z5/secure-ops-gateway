from __future__ import annotations

import hashlib
from contextlib import contextmanager
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

from .paths import (
    SecurePathError,
    prepare_private_parent,
    private_parent_identity,
    reject_symlink_leaf,
    verify_private_parent_identity,
)


class ConfirmationError(RuntimeError):
    pass


class SQLiteOperationGuard:
    def __init__(
        self,
        path: str | Path,
        *,
        ttl_seconds: int = 120,
        execution_stale_seconds: int = 300,
        retention_seconds: int = 86400,
    ):
        for name, value in {
            "ttl_seconds": ttl_seconds,
            "execution_stale_seconds": execution_stale_seconds,
            "retention_seconds": retention_seconds,
        }.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        try:
            self.path = prepare_private_parent(path)
            self._parent_identity = private_parent_identity(self.path)
        except SecurePathError as exc:
            raise ConfirmationError("confirmation database parent is unsafe") from exc
        self.ttl_seconds = ttl_seconds
        self.execution_stale_seconds = execution_stale_seconds
        self.retention_seconds = retention_seconds
        self._ensure_private_database_file()
        with self._database() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS confirmations (
                    token TEXT PRIMARY KEY,
                    operation_hash TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    source_provider TEXT NOT NULL,
                    source_subject TEXT NOT NULL,
                    status TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    response_json TEXT,
                    started_at INTEGER,
                    completed_at INTEGER
                )"""
            )
            columns = {
                row[1] for row in db.execute("PRAGMA table_info(confirmations)").fetchall()
            }
            if "started_at" not in columns:
                db.execute("ALTER TABLE confirmations ADD COLUMN started_at INTEGER")
            if "completed_at" not in columns:
                db.execute("ALTER TABLE confirmations ADD COLUMN completed_at INTEGER")
        self._enforce_private_permissions()
        self.cleanup()

    def _ensure_private_database_file(self) -> None:
        try:
            prepare_private_parent(self.path)
            verify_private_parent_identity(self.path, self._parent_identity)
            reject_symlink_leaf(self.path)
        except SecurePathError as exc:
            raise ConfirmationError("confirmation database path is unsafe") from exc
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags, 0o600)
        except FileExistsError:
            reject_symlink_leaf(self.path)
            self._enforce_private_permissions()
        except OSError as exc:
            raise ConfirmationError("cannot create confirmation database safely") from exc
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
            raise ConfirmationError("confirmation database path is unsafe") from exc

    def _connect(self):
        try:
            prepare_private_parent(self.path)
            verify_private_parent_identity(self.path, self._parent_identity)
            reject_symlink_leaf(self.path)
        except SecurePathError as exc:
            raise ConfirmationError("confirmation database path is unsafe") from exc
        self._enforce_private_permissions()
        connection = sqlite3.connect(self.path)
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
    def operation_hash(context, tool: dict) -> str:
        document = {
            "principal_id": context.principal_id,
            "source_provider": context.source_provider,
            "source_subject": context.source_subject,
            "tool": tool["name"],
            "capability": tool["capability"],
            "permission": tool["permission"],
            "resource": tool["resource"],
            "risk": tool["risk"],
            "confirmation": tool.get("confirmation", "none"),
            "arguments": tool.get("arguments", {}),
            "request": tool["request"],
        }
        raw = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(raw).hexdigest()

    def cleanup(self, *, now: int | None = None) -> int:
        current = int(time.time()) if now is None else int(now)
        cutoff = current - self.retention_seconds
        with self._database() as db:
            cursor = db.execute(
                """DELETE FROM confirmations
                   WHERE
                     (status='pending' AND expires_at < ?)
                     OR
                     (status IN ('completed','uncertain')
                      AND COALESCE(completed_at, expires_at) < ?)""",
                (cutoff, cutoff),
            )
            return cursor.rowcount

    def _mark_stale_if_needed(self, db, token: str, status: str, started_at: int | None, now: int) -> str:
        if (
            status == "executing"
            and isinstance(started_at, int)
            and now - started_at > self.execution_stale_seconds
        ):
            db.execute(
                """UPDATE confirmations
                   SET status='uncertain', completed_at=?
                   WHERE token=? AND status='executing'""",
                (now, token),
            )
            return "uncertain"
        return status

    def issue(self, context, tool: dict) -> dict:
        self.cleanup()
        token = secrets.token_urlsafe(32)
        expires = int(time.time()) + self.ttl_seconds
        op_hash = self.operation_hash(context, tool)
        with self._database() as db:
            db.execute(
                """INSERT INTO confirmations (
                       token, operation_hash, principal_id, source_provider,
                       source_subject, status, expires_at, response_json,
                       started_at, completed_at
                   ) VALUES (?, ?, ?, ?, ?, 'pending', ?, NULL, NULL, NULL)""",
                (
                    token,
                    op_hash,
                    context.principal_id,
                    context.source_provider,
                    context.source_subject,
                    expires,
                ),
            )
        self._enforce_private_permissions()
        return {
            "confirmation_token": token,
            "expires_at_unix": expires,
            "tool": tool["name"],
            "resource": tool["resource"],
            "risk": tool["risk"],
        }

    def begin(self, token: str, context, tool: dict) -> dict:
        if not isinstance(token, str) or not token:
            raise ConfirmationError("invalid confirmation token")
        now = int(time.time())
        with self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT operation_hash, principal_id, source_provider,
                          source_subject, status, expires_at, response_json,
                          started_at
                   FROM confirmations WHERE token = ?""",
                (token,),
            ).fetchone()
            if row is None:
                raise ConfirmationError("unknown confirmation token")
            (
                op_hash,
                principal,
                provider,
                subject,
                status,
                expires,
                response_json,
                started_at,
            ) = row
            if (principal, provider, subject) != (
                context.principal_id,
                context.source_provider,
                context.source_subject,
            ):
                raise ConfirmationError("confirmation token belongs to another source")
            if op_hash != self.operation_hash(context, tool):
                raise ConfirmationError("confirmation token does not match this operation")
            status = self._mark_stale_if_needed(db, token, status, started_at, now)
            if status == "completed":
                return {"execute": False, "response": json.loads(response_json)}
            if status == "uncertain":
                # Persist stale-execution recovery before surfacing the error.
                # Otherwise the context manager would roll the UPDATE back.
                db.commit()
                raise ConfirmationError(
                    "operation outcome is uncertain; verify state before retrying"
                )
            if status == "executing":
                raise ConfirmationError("confirmation token is already in use")
            if status != "pending" or expires < now:
                raise ConfirmationError("confirmation token is not usable")
            updated = db.execute(
                """UPDATE confirmations
                   SET status='executing', started_at=?
                   WHERE token=? AND status='pending'""",
                (now, token),
            )
            if updated.rowcount != 1:
                raise ConfirmationError("confirmation token is already in use")
        return {"execute": True}

    def abort_before_execution(self, token: str) -> None:
        """Release a reservation when the executor was definitely not called."""
        now = int(time.time())
        with self._database() as db:
            updated = db.execute(
                """UPDATE confirmations
                   SET status='pending', started_at=NULL
                   WHERE token=? AND status='executing' AND expires_at>=?""",
                (token, now),
            )
            if updated.rowcount != 1:
                raise ConfirmationError("operation reservation cannot be released")

    def mark_uncertain(self, token: str) -> None:
        now = int(time.time())
        with self._database() as db:
            db.execute(
                """UPDATE confirmations
                   SET status='uncertain', completed_at=?
                   WHERE token=? AND status='executing'""",
                (now, token),
            )

    def complete(self, token: str, response: dict) -> None:
        encoded = json.dumps(
            response,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        now = int(time.time())
        with self._database() as db:
            updated = db.execute(
                """UPDATE confirmations
                   SET status='completed', response_json=?, completed_at=?
                   WHERE token=? AND status='executing'""",
                (encoded, now, token),
            )
            if updated.rowcount != 1:
                raise ConfirmationError("operation is not executing")

    def status(self, token: str, context) -> dict:
        now = int(time.time())
        with self._database() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT principal_id, source_provider, source_subject,
                          status, expires_at, started_at
                   FROM confirmations WHERE token = ?""",
                (token,),
            ).fetchone()
            if row is None:
                raise ConfirmationError("unknown confirmation token")
            principal, provider, subject, status, expires, started_at = row
            if (principal, provider, subject) != (
                context.principal_id,
                context.source_provider,
                context.source_subject,
            ):
                raise ConfirmationError("unknown confirmation token")
            status = self._mark_stale_if_needed(db, token, status, started_at, now)
        effective = "expired" if status == "pending" and expires < now else status
        return {"status": effective, "expires_at_unix": expires}
