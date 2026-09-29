from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys

import pytest

pytest.importorskip("mcp")

from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "tests" / "integration" / "fixtures" / "full_stack_mcp_stdio_server.py"


def server_parameters() -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER)],
        cwd=str(ROOT),
        env={
            "PYTHONPATH": str(ROOT / "src")
            + os.pathsep
            + os.environ.get("PYTHONPATH", "")
        },
    )


def expected_common(*, action: str, capability: str) -> dict:
    return {
        "ok": True,
        "action": action,
        "resource": "demo:api",
        "capability": capability,
        "principal": "full-stack-user",
        "source_provider": "stdio",
        "source_subject": "official-sdk-full-stack",
    }


async def exercise_modern_full_stack() -> None:
    async with Client(server_parameters(), mode="auto", cache=None) as client:
        assert client.protocol_version == "2026-07-28"
        assert client.server_info is not None
        assert client.server_info.name == "secure-ops-gateway-full-stack"

        listed = await client.list_tools()
        assert [tool.name for tool in listed.tools] == ["demo.restart", "demo.status"]

        status = await client.call_tool("demo.status", {})
        assert status.is_error is False
        assert status.structured_content == expected_common(
            action="status",
            capability="demo.status",
        )

        challenge = await client.call_tool("demo.restart", {"service": "api"})
        assert challenge.is_error is True
        assert challenge.structured_content["status"] == "confirmation_required"
        token = challenge.structured_content["confirmation_token"]

        restarted = await client.call_tool(
            "demo.restart",
            {
                "service": "api",
                "confirmed": True,
                "confirmation_token": token,
            },
        )
        assert restarted.is_error is False
        assert restarted.structured_content == {
            **expected_common(action="restart", capability="demo.restart"),
            "restart_count": 1,
        }


async def exercise_legacy_full_stack() -> None:
    async with Client(server_parameters(), mode="legacy", cache=None) as client:
        assert client.protocol_version == "2025-11-25"
        status = await client.call_tool("demo.status", {})
        assert status.is_error is False
        assert status.structured_content == expected_common(
            action="status",
            capability="demo.status",
        )


def test_official_mcp_sdk_reaches_real_unix_executor() -> None:
    asyncio.run(exercise_modern_full_stack())
    asyncio.run(exercise_legacy_full_stack())
