from __future__ import annotations

import os
import stat
from pathlib import Path


class SecurePathError(RuntimeError):
    pass


def _reject_unsafe_components(path: Path) -> None:
    """Reject symlinks and replaceable non-sticky directory ancestors.

    A world/group-writable sticky directory such as `/tmp` is allowed because
    the sticky bit prevents unrelated users from replacing another user's
    private child directory. Writable ancestors without the sticky bit are
    rejected.
    """

    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise SecurePathError(f"symlink path component is not allowed: {current}")
        if stat.S_ISDIR(metadata.st_mode):
            writable_by_others = bool(metadata.st_mode & 0o022)
            sticky = bool(metadata.st_mode & stat.S_ISVTX)
            if writable_by_others and not sticky:
                raise SecurePathError(
                    f"writable non-sticky directory component is not allowed: {current}"
                )


def prepare_private_parent(path: str | Path) -> Path:
    target = Path(path)
    parent = target.parent
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    _reject_unsafe_components(parent)
    metadata = os.stat(parent, follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode):
        raise SecurePathError("state parent is not a directory")
    if metadata.st_mode & 0o022:
        raise SecurePathError(
            "state parent must not be writable by group or other users"
        )
    return target


def reject_symlink_leaf(path: str | Path) -> None:
    target = Path(path)
    try:
        metadata = os.lstat(target)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise SecurePathError("state file must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise SecurePathError("state path must be a regular file")
