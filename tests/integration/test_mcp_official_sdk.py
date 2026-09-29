from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys

import pytest

pytest.importorskip("mcp")

from mcp import Client, StdioServerParameters

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "tests" / "integration" / "fixtures" / "official_mcp_stdio_server.py"


def server_parameters() -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER)],
        cwd=str(ROOT),
        env={"PYTHONPATH": str(ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")},
    )


async def exercise_modern_client() -> None:
    async with Client(server_parameters(), mode="auto", cache=None) as client:
        assert client.protocol_version == "2026-07-28"
        assert client.server_info is not None
        assert client.server_info.name == "secure-ops-gateway-compat"

        listed = await client.list_tools()
        assert [tool.name for tool in listed.tools] == ["demo.restart", "demo.status"]

        status = await client.call_tool("demo.status", {})
        assert status.is_error is False
        assert status.structured_content == {
            "ok": True,
            "action": "status",
            "resource": "demo:api",
        }

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
            "ok": True,
            "action": "restart",
            "resource": "demo:api",
        }


async def exercise_legacy_client() -> None:
    async with Client(server_parameters(), mode="legacy", cache=None) as client:
        assert client.protocol_version == "2025-11-25"
        assert client.server_info is not None
        assert client.server_info.name == "secure-ops-gateway-compat"

        listed = await client.list_tools()
        assert [tool.name for tool in listed.tools] == ["demo.restart", "demo.status"]

        status = await client.call_tool("demo.status", {})
        assert status.is_error is False
        assert status.structured_content == {
            "ok": True,
            "action": "status",
            "resource": "demo:api",
        }


def test_official_mcp_python_sdk_stdio_auto_and_legacy() -> None:
    asyncio.run(exercise_modern_client())
    asyncio.run(exercise_legacy_client())
