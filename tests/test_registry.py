import pytest

from secure_ops_gateway.registry import RegistryError, materialize_tool, resolve_capability, validate_tool_registry

TOOLS = {
    "schema": 1,
    "tools": {
        "service.restart": {
            "capability": "service.restart",
            "permission": "service.restart",
            "resource": "service:{name}",
            "risk": "write",
            "confirmation": "explicit",
            "arguments": {"name": {"type": "string", "required": True, "enum": ["api"]}},
            "request": {"action": "restart", "name": "$arg:name"},
        }
    },
}
EXECUTORS = {"schema": 1, "executors": {"host": {"endpoint": "unix:/tmp/host.sock", "credential": "host.key", "capabilities": ["service.restart"]}}}


def test_materialization_is_bounded_and_declarative():
    tool = materialize_tool("service.restart", {"name": "api"}, registry=TOOLS)
    assert tool["resource"] == "service:api"
    assert tool["request"] == {"action": "restart", "name": "api"}


def test_capability_resolves_to_single_executor():
    assert resolve_capability("service.restart", registry=EXECUTORS)["executor_id"] == "host"


def test_resource_template_cannot_reference_unknown_argument():
    bad = {
        "schema": 1,
        "tools": {
            "bad": {
                "capability": "bad.run",
                "permission": "bad.run",
                "resource": "service:{missing}",
                "risk": "read",
                "arguments": {},
                "request": {"action": "run"},
            }
        },
    }
    with pytest.raises(RegistryError):
        validate_tool_registry(bad)



def test_state_changing_tools_require_confirmation_by_default():
    for risk in ("write", "privileged"):
        bad = {
            "schema": 1,
            "tools": {
                "danger": {
                    "capability": "danger.run",
                    "permission": "danger.run",
                    "resource": "danger:one",
                    "risk": risk,
                    "confirmation": "none",
                    "arguments": {},
                    "request": {"action": "run"},
                }
            },
        }
        with pytest.raises(RegistryError, match="requires explicit confirmation"):
            validate_tool_registry(bad)


def test_unconfirmed_mutation_requires_explicit_escape_hatch():
    document = {
        "schema": 1,
        "tools": {
            "automation.tick": {
                "capability": "automation.tick",
                "permission": "automation.tick",
                "resource": "automation:one",
                "risk": "write",
                "confirmation": "none",
                "allow_unconfirmed_mutation": True,
                "arguments": {},
                "request": {"action": "tick"},
            }
        },
    }
    validate_tool_registry(document)
