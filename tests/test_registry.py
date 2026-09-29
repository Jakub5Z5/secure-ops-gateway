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


def _tool_with_argument(spec, *, argument_name="value", request=None, resource="demo:one"):
    return {
        "schema": 1,
        "tools": {
            "demo.run": {
                "capability": "demo.run",
                "permission": "demo.run",
                "resource": resource,
                "risk": "read",
                "arguments": {argument_name: spec},
                "request": {"value": "$arg:value"} if request is None else request,
            }
        },
    }


@pytest.mark.parametrize(
    "spec",
    [
        {"type": "string", "required": True, "min_length": "1"},
        {"type": "string", "required": True, "min_length": 5, "max_length": 2},
        {"type": "integer", "required": True, "minimum": "0"},
        {"type": "integer", "required": True, "minimum": 5, "maximum": 2},
        {"type": "boolean", "required": True, "minimum": 0},
    ],
)
def test_registry_rejects_invalid_argument_constraints(spec):
    with pytest.raises(RegistryError):
        validate_tool_registry(_tool_with_argument(spec))


def test_registry_rejects_unknown_request_template_argument():
    document = _tool_with_argument(
        {"type": "string", "required": True},
        request={"value": "$arg:missing"},
    )
    with pytest.raises(RegistryError, match="request template references unknown"):
        validate_tool_registry(document)


def test_registry_rejects_optional_template_argument_without_default():
    document = _tool_with_argument(
        {"type": "string"},
        resource="demo:{value}",
    )
    with pytest.raises(RegistryError, match="required or have a default"):
        validate_tool_registry(document)


@pytest.mark.parametrize("reserved", ["confirmed", "confirmation_token"])
def test_registry_reserves_gateway_confirmation_argument_names(reserved):
    document = _tool_with_argument(
        {"type": "string", "required": True},
        argument_name=reserved,
        request={"action": "status"},
    )
    with pytest.raises(RegistryError, match="reserved argument name"):
        validate_tool_registry(document)


def test_registry_accepts_and_materializes_defaults_and_nested_lists():
    document = {
        "schema": 1,
        "tools": {
            "demo.run": {
                "capability": "demo.run",
                "permission": "demo.run",
                "resource": "demo:{name}",
                "risk": "read",
                "arguments": {
                    "name": {"type": "string", "default": "api", "min_length": 2, "max_length": 8},
                    "count": {"type": "integer", "default": 2, "minimum": 1, "maximum": 3},
                    "enabled": {"type": "boolean", "default": True},
                },
                "request": {
                    "action": "run",
                    "items": ["$arg:name", {"count": "$arg:count"}],
                    "enabled": "$arg:enabled",
                },
            }
        },
    }
    validate_tool_registry(document)
    tool = materialize_tool("demo.run", None, registry=document)
    assert tool["resource"] == "demo:api"
    assert tool["request"] == {
        "action": "run",
        "items": ["api", {"count": 2}],
        "enabled": True,
    }


@pytest.mark.parametrize(
    "value, spec, expected",
    [
        (3, {"type": "string", "required": True}, "must be a string"),
        ("db", {"type": "string", "required": True, "enum": ["api", "worker"]}, "is not allowed"),
        ("", {"type": "string", "required": True, "min_length": 2}, "too short"),
        ("toolong", {"type": "string", "required": True, "max_length": 6}, "too long"),
    ],
)
def test_materialize_rejects_invalid_string_values(value, spec, expected):
    document = _tool_with_argument(spec)
    with pytest.raises(RegistryError, match=expected):
        materialize_tool("demo.run", {"value": value}, registry=document)


def test_materialize_rejects_unknown_and_missing_arguments():
    document = _tool_with_argument({"type": "string", "required": True})
    with pytest.raises(RegistryError, match="unknown arguments"):
        materialize_tool("demo.run", {"value": "x", "extra": "y"}, registry=document)
    with pytest.raises(RegistryError, match="missing argument"):
        materialize_tool("demo.run", {}, registry=document)


def test_integer_and_boolean_materialization_validation():
    integer_doc = _tool_with_argument(
        {"type": "integer", "required": True, "minimum": 1, "maximum": 3}
    )
    with pytest.raises(RegistryError, match="must be an integer"):
        materialize_tool("demo.run", {"value": True}, registry=integer_doc)
    with pytest.raises(RegistryError, match="out of range"):
        materialize_tool("demo.run", {"value": 9}, registry=integer_doc)

    boolean_doc = _tool_with_argument({"type": "boolean", "required": True})
    with pytest.raises(RegistryError, match="must be boolean"):
        materialize_tool("demo.run", {"value": 1}, registry=boolean_doc)


def test_executor_registry_rejects_duplicate_capability_and_missing_route():
    from secure_ops_gateway.registry import validate_executor_registry

    duplicate = {
        "schema": 1,
        "executors": {
            "a": {"endpoint": "unix:/a", "capabilities": ["demo.run"]},
            "b": {"endpoint": "unix:/b", "capabilities": ["demo.run"]},
        },
    }
    with pytest.raises(RegistryError, match="multiple executors"):
        validate_executor_registry(duplicate)

    valid = {
        "schema": 1,
        "executors": {
            "a": {"endpoint": "unix:/a", "capabilities": ["demo.run"]},
        },
    }
    with pytest.raises(RegistryError, match="no executor"):
        resolve_capability("demo.missing", registry=valid)


def test_catalog_returns_public_tool_metadata():
    from secure_ops_gateway.registry import catalog

    items = catalog(registry=TOOLS)
    assert items == [
        {
            "name": "service.restart",
            "description": "",
            "risk": "write",
            "confirmation": "explicit",
            "arguments": {"name": {"type": "string", "required": True, "enum": ["api"]}},
        }
    ]


def test_registry_rejects_malformed_top_level_and_executor_documents():
    from secure_ops_gateway.registry import validate_executor_registry

    with pytest.raises(RegistryError):
        validate_tool_registry({"schema": 2, "tools": {}})
    with pytest.raises(RegistryError):
        validate_tool_registry({"schema": 1, "tools": []})
    with pytest.raises(RegistryError):
        validate_executor_registry({"schema": 2, "executors": {}})
    with pytest.raises(RegistryError):
        validate_executor_registry({"schema": 1, "executors": []})


def test_registry_rejects_bad_resource_format_and_invalid_request_argument_name():
    bad_format = _tool_with_argument(
        {"type": "string", "required": True},
        resource="demo:{value!r}",
    )
    with pytest.raises(RegistryError, match="formatting directives"):
        validate_tool_registry(bad_format)

    bad_request = _tool_with_argument(
        {"type": "string", "required": True},
        request={"value": "$arg:not-valid!"},
    )
    with pytest.raises(RegistryError, match="invalid request template"):
        validate_tool_registry(bad_request)


def test_registry_rejects_unknown_tool_and_invalid_materialize_arguments():
    from secure_ops_gateway.registry import get_tool

    with pytest.raises(RegistryError, match="unknown tool"):
        get_tool("missing", registry=TOOLS)
    with pytest.raises(RegistryError, match="arguments must be an object"):
        materialize_tool("service.restart", "bad", registry=TOOLS)
