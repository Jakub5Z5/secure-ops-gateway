import pytest

from secure_ops_gateway.mcp_schema import tool_input_schema


def test_mcp_schema_includes_constraints_and_confirmation_controls():
    schema = tool_input_schema(
        {
            "confirmation": "explicit",
            "arguments": {
                "service": {
                    "type": "string",
                    "required": True,
                    "enum": ["api", "worker"],
                    "min_length": 2,
                    "max_length": 16,
                },
                "retries": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 3,
                    "default": 1,
                },
            },
        }
    )
    assert schema["required"] == ["service"]
    assert schema["properties"]["service"]["enum"] == ["api", "worker"]
    assert schema["properties"]["retries"]["maximum"] == 3
    assert schema["properties"]["confirmed"] == {"type": "boolean", "default": False}
    assert schema["properties"]["confirmation_token"]["minLength"] == 32
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize("reserved", ["confirmed", "confirmation_token"])
def test_mcp_schema_defensively_rejects_control_field_collision(reserved):
    with pytest.raises(ValueError, match="reserved gateway control argument"):
        tool_input_schema(
            {
                "confirmation": "explicit",
                "arguments": {reserved: {"type": "string"}},
            }
        )
