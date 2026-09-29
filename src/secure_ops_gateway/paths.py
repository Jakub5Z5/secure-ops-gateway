from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import NamedTuple


class SecurePathError(RuntimeError):
    pass


def _absolute_path(path: str | Path) -> Path:
    """Return an absolute lexical path without resolving symlinks."""

    return Path(os.path.abspath(os.fspath(path)))


def _trusted_directory_owner(uid: int, effective_uid: int) -> bool:
    """System-root directories and directories owned by this process are trusted.

    Root-owned ancestors are required for normal system paths such as /var and
    /run. A service-owned final state directory is also trusted. Directories
    owned by an unrelated account are rejected even when their mode is 0700,
    because their owner can rename or replace entries beneath them.
    """

    return uid in {0, effective_uid}


def _reject_unsafe_components(path: Path, *, effective_uid: int | None = None) -> None:
    """Reject replaceable or attacker-controlled directory ancestors.

    A world/group-writable sticky directory such as /tmp is allowed when it is
    root-owned. Other existing directory components must be owned by root or by
    the effective process user and must not be writable by unrelated users.
    """

    effective_uid = os.geteuid() if effective_uid is None else effective_uid
    absolute = _absolute_path(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise SecurePathError(f"symlink path component is not allowed: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise SecurePathError(f"non-directory path component is not allowed: {current}")

        writable_by_others = bool(metadata.st_mode & 0o022)
        sticky = bool(metadata.st_mode & stat.S_ISVTX)
        root_owned_sticky = sticky and metadata.st_uid == 0
        if writable_by_others and not root_owned_sticky:
            raise SecurePathError(
                f"writable non-sticky directory component is not allowed: {current}"
            )
        if not _trusted_directory_owner(metadata.st_uid, effective_uid):
            raise SecurePathError(
                f"directory component is owned by an unrelated user: {current}"
            )


def prepare_private_parent(path: str | Path) -> Path:
    """Create and validate the parent directory for security-sensitive state.

    The final parent must be owned by the effective process user. Ancestors may
    additionally be root-owned, which supports conventional system layouts.
    This ownership rule is important even for mode-0700 directories: a
    directory's owner can rename or replace its contents regardless of whether
    group/other write bits are clear.
    """

    target = _absolute_path(path)
    parent = target.parent
    effective_uid = os.geteuid()

    # Validate every existing ancestor before creating anything. Otherwise a
    # privileged process could create directories through an attacker-owned or
    # symlinked prefix and only discover the unsafe ownership afterwards.
    _reject_unsafe_components(parent, effective_uid=effective_uid)
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    _reject_unsafe_components(parent, effective_uid=effective_uid)
    metadata = os.stat(parent, follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode):
        raise SecurePathError("state parent is not a directory")
    if metadata.st_uid != effective_uid:
        raise SecurePathError("state parent must be owned by the effective process user")
    if metadata.st_mode & 0o022:
        raise SecurePathError(
            "state parent must not be writable by group or other users"
        )
    return target



class ParentIdentity(NamedTuple):
    device: int
    inode: int
    owner_uid: int


def private_parent_identity(path: str | Path) -> ParentIdentity:
    parent = _absolute_path(path).parent
    metadata = os.stat(parent, follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode):
        raise SecurePathError("state parent is not a directory")
    return ParentIdentity(metadata.st_dev, metadata.st_ino, metadata.st_uid)


def verify_private_parent_identity(
    path: str | Path,
    expected: ParentIdentity,
) -> None:
    current = private_parent_identity(path)
    if current != expected:
        raise SecurePathError("state parent was replaced after initialization")

def reject_symlink_leaf(path: str | Path) -> None:
    target = _absolute_path(path)
    try:
        metadata = os.lstat(target)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise SecurePathError("state file must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise SecurePathError("state path must be a regular file")
