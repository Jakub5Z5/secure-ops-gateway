from __future__ import annotations


def tool_input_schema(tool: dict) -> dict:
    properties = {}
    required = []
    for name, spec in tool.get("arguments", {}).items():
        kind = spec["type"]
        if kind == "string":
            item = {"type": "string"}
            if "enum" in spec:
                item["enum"] = list(spec["enum"])
            if "min_length" in spec:
                item["minLength"] = spec["min_length"]
            if "max_length" in spec:
                item["maxLength"] = spec["max_length"]
        elif kind == "integer":
            item = {"type": "integer"}
            if "minimum" in spec:
                item["minimum"] = spec["minimum"]
            if "maximum" in spec:
                item["maximum"] = spec["maximum"]
        elif kind == "boolean":
            item = {"type": "boolean"}
        else:
            raise ValueError(f"unsupported argument type: {kind}")
        if "default" in spec:
            item["default"] = spec["default"]
        properties[name] = item
        if spec.get("required"):
            required.append(name)

    if tool.get("confirmation", "none") == "explicit":
        properties["confirmed"] = {"type": "boolean", "default": False}
        properties["confirmation_token"] = {"type": "string", "minLength": 32, "maxLength": 128, "pattern": "^[A-Za-z0-9_-]+$"}

    result = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        result["required"] = required
    return result
