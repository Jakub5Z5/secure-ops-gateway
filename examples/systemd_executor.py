"""Bounded systemd service executor example.

This example deliberately exposes only two exact capabilities:
``service.status`` and ``service.restart``.  Public service aliases are mapped
through a trusted local allowlist to fixed ``.service`` unit names.  Caller
input is never appended to a shell command and ``shell=True`` is never used.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Callable, Mapping

from secure_ops_gateway import ExecutorInvocation, UnixSocketExecutorServer
from secure_ops_gateway.executor import ExecutorError

_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.service$")
_MAX_CONFIG_BYTES = 64 * 1024
_MAX_KEY_BYTES = 4096


def _read_trusted_file(path: str | Path, *, max_bytes: int, secret: bool) -> bytes:
    """Read one trusted regular file without following a final symlink."""

    if os.name != "posix":
        raise ExecutorError("systemd executor example requires a POSIX platform")
    target = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags)
    except OSError as exc:
        raise ExecutorError(f"cannot open trusted file: {target}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ExecutorError(f"trusted file is not regular: {target}")
        euid = os.geteuid()
        if metadata.st_uid not in {0, euid}:
            raise ExecutorError(f"trusted file has an unexpected owner: {target}")
        mode = stat.S_IMODE(metadata.st_mode)
        if mode & 0o022:
            raise ExecutorError(f"trusted file is group/world writable: {target}")
        if secret and (metadata.st_uid != euid or mode & 0o077):
            raise ExecutorError(
                f"executor key file must be owned by the executor user and mode 0600 or stricter: {target}"
            )
        data = bytearray()
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > max_bytes:
                raise ExecutorError(f"trusted file is too large: {target}")
        return bytes(data)
    finally:
        os.close(fd)


def load_executor_key(path: str | Path) -> bytes:
    """Load a 32-byte executor key encoded as exactly 64 hexadecimal characters."""

    raw = _read_trusted_file(path, max_bytes=_MAX_KEY_BYTES, secret=True)
    try:
        text = raw.decode("ascii").strip()
        key = bytes.fromhex(text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ExecutorError("executor key file must contain hexadecimal data") from exc
    if len(text) != 64 or len(key) != 32:
        raise ExecutorError("executor key file must contain exactly 32 bytes as 64 hexadecimal characters")
    return key


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ExecutorError(f"duplicate JSON key in services configuration: {key}")
        value[key] = item
    return value


def load_services(path: str | Path) -> dict[str, str]:
    """Load and validate the public-alias to systemd-unit allowlist."""

    raw = _read_trusted_file(path, max_bytes=_MAX_CONFIG_BYTES, secret=False)
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutorError("services configuration is not valid JSON") from exc
    return validate_services(data)


def validate_services(services: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(services, Mapping) or not services:
        raise ExecutorError("services configuration must be a non-empty object")
    if len(services) > 64:
        raise ExecutorError("services configuration contains too many entries")
    validated: dict[str, str] = {}
    for alias, unit in services.items():
        if not isinstance(alias, str) or not _ALIAS.fullmatch(alias):
            raise ExecutorError("invalid public service alias")
        if not isinstance(unit, str) or not _UNIT.fullmatch(unit):
            raise ExecutorError("invalid systemd service unit")
        validated[alias] = unit
    return validated


class SystemdServiceExecutor:
    """Capability handlers for an exact allowlist of systemd services."""

    def __init__(
        self,
        services: Mapping[str, str],
        *,
        systemctl_path: str = "/usr/bin/systemctl",
        timeout_seconds: float = 10.0,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ):
        self.services = validate_services(services)
        path = Path(systemctl_path)
        if not path.is_absolute():
            raise ValueError("systemctl_path must be absolute")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not callable(runner):
            raise TypeError("runner must be callable")
        self.systemctl_path = str(path)
        self.timeout_seconds = float(timeout_seconds)
        self._runner = runner

    def handlers(self):
        return {
            "service.status": self.status,
            "service.restart": self.restart,
        }

    def _resolve(self, invocation: ExecutorInvocation, *, capability: str, permission: str, risk: str, action: str):
        if invocation.capability != capability:
            raise ExecutorError("unexpected capability for systemd handler")
        if invocation.permission != permission or invocation.risk != risk:
            raise ExecutorError("unexpected permission or risk for systemd handler")
        request = invocation.request
        if not isinstance(request, dict) or set(request) != {"action", "service"}:
            raise ExecutorError("invalid systemd executor request")
        if request.get("action") != action:
            raise ExecutorError("unexpected systemd executor action")
        alias = request.get("service")
        if not isinstance(alias, str) or alias not in self.services:
            raise ExecutorError("service is not allowlisted")
        if invocation.resource != f"service:{alias}":
            raise ExecutorError("systemd request does not match authorized resource")
        return alias, self.services[alias]

    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        try:
            result = self._runner(
                [self.systemctl_path, *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
                env={"LANG": "C", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ExecutorError("systemctl execution failed") from exc
        if result.returncode != 0:
            raise ExecutorError(f"systemctl failed with exit code {result.returncode}")
        return result

    def status(self, invocation: ExecutorInvocation) -> dict:
        alias, unit = self._resolve(
            invocation,
            capability="service.status",
            permission="service.read",
            risk="read",
            action="status",
        )
        result = self._run(
            "--no-ask-password",
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=UnitFileState",
            "--",
            unit,
        )
        properties = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                properties[key] = value
        required = {"LoadState", "ActiveState", "SubState"}
        if not required.issubset(properties):
            raise ExecutorError("systemctl returned incomplete status data")
        return {
            "ok": True,
            "service": alias,
            "unit": unit,
            "load_state": properties["LoadState"],
            "active_state": properties["ActiveState"],
            "sub_state": properties["SubState"],
            "unit_file_state": properties.get("UnitFileState", ""),
        }

    def restart(self, invocation: ExecutorInvocation) -> dict:
        alias, unit = self._resolve(
            invocation,
            capability="service.restart",
            permission="service.restart",
            risk="write",
            action="restart",
        )
        self._run("--no-ask-password", "restart", "--", unit)
        return {"ok": True, "service": alias, "unit": unit, "action": "restart"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded systemd executor for Secure Ops Gateway")
    parser.add_argument("--socket", required=True, help="Unix socket path owned by this executor")
    parser.add_argument("--key-file", required=True, help="0600 file containing a 32-byte key as 64 hex characters")
    parser.add_argument("--services-file", required=True, help="trusted JSON alias-to-.service allowlist")
    parser.add_argument("--systemctl", default="/usr/bin/systemctl", help="absolute systemctl binary path")
    parser.add_argument("--timeout", type=float, default=10.0, help="systemctl timeout in seconds")
    args = parser.parse_args()

    key = load_executor_key(args.key_file)
    controller = SystemdServiceExecutor(
        load_services(args.services_file),
        systemctl_path=args.systemctl,
        timeout_seconds=args.timeout,
    )
    server = UnixSocketExecutorServer(args.socket, key, controller.handlers())
    server.serve_forever()


if __name__ == "__main__":
    main()
