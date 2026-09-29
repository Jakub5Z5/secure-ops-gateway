from __future__ import annotations

import json
import os
import stat
import threading
import time
from pathlib import Path

from .paths import SecurePathError, prepare_private_parent, reject_symlink_leaf


class AuditError(RuntimeError):
    pass


class JSONLAuditSink:
    def __init__(self, path: str | Path):
        try:
            self.path = prepare_private_parent(path)
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
                reject_symlink_leaf(self.path)
                fd = os.open(self.path, flags, 0o600)
            except (OSError, SecurePathError) as exc:
                raise AuditError("cannot open audit destination safely") from exc
            try:
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode):
                    raise AuditError("audit destination is not a regular file")
                os.fchmod(fd, 0o600)
                view = memoryview(encoded)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            except OSError as exc:
                raise AuditError("cannot append audit record") from exc
            finally:
                os.close(fd)
