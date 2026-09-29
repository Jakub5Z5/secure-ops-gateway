from __future__ import annotations

import json
import os
import stat
import threading
import time
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - Unix is the supported secure file-sink target.
    fcntl = None

from .paths import (
    SecurePathError,
    prepare_private_parent,
    private_parent_identity,
    reject_symlink_leaf,
    verify_private_parent_identity,
)


class AuditError(RuntimeError):
    pass


class JSONLAuditSink:
    def __init__(self, path: str | Path):
        if fcntl is None:
            raise AuditError("cross-process audit locking is unavailable on this platform")
        try:
            self.path = prepare_private_parent(path)
            self._parent_identity = private_parent_identity(self.path)
            reject_symlink_leaf(self.path)
        except SecurePathError as exc:
            raise AuditError("audit path is unsafe") from exc
        self._lock = threading.Lock()

    def __call__(self, record: dict) -> None:
        if not isinstance(record, dict):
            raise TypeError("audit record must be an object")
        payload = dict(record)
        payload.setdefault("timestamp_unix", time.time())
        encoded = (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        with self._lock:
            try:
                # Re-check the full parent chain for every append. This catches
                # directory replacement after sink construction.
                prepare_private_parent(self.path)
                verify_private_parent_identity(self.path, self._parent_identity)
                reject_symlink_leaf(self.path)
                fd = os.open(self.path, flags, 0o600)
            except (OSError, SecurePathError) as exc:
                raise AuditError("cannot open audit destination safely") from exc
            try:
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode):
                    raise AuditError("audit destination is not a regular file")
                os.fchmod(fd, 0o600)

                # flock coordinates independent sink instances and processes.
                # Keep it across the complete partial-write loop so one JSONL
                # record cannot interleave with another writer.
                fcntl.flock(fd, fcntl.LOCK_EX)
                view = memoryview(encoded)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise AuditError("audit write made no progress")
                    view = view[written:]
                os.fsync(fd)
            except OSError as exc:
                raise AuditError("cannot append audit record") from exc
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(fd)
