from __future__ import annotations

import copy
import re
from string import Formatter

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ARGUMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class RegistryError(RuntimeError):
    pass


def _name(value: object, label: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise RegistryError(f"invalid {label}")
    return value


def resource_argument_names(resource: str) -> tuple[str, ...]:
    if not isinstance(resource, str) or not resource:
        raise RegistryError("invalid resource")
    fields = []
    try:
        parts = Formatter().parse(resource)
        for _literal, field_name, format_spec, conversion in parts:
            if field_name is None:
                continue
            if format_spec or conversion:
                raise RegistryError("resource templates do not support formatting directives")
            if not _ARGUMENT_NAME.fullmatch(field_name):
                raise RegistryError("invalid resource template argument")
            fields.append(field_name)
    except ValueError as exc:
        raise RegistryError("invalid resource template") from exc
    return tuple(dict.fromkeys(fields))


def _validate_argument_spec(name: str, spec: object) -> None:
    if not isinstance(name, str) or not _ARGUMENT_NAME.fullmatch(name):
        raise RegistryError("invalid argument name")
    if not isinstance(spec, dict):
        raise RegistryError(f"invalid argument definition: {name}")
    kind = spec.get("type")
    if kind not in {"string", "integer", "boolean"}:
        raise RegistryError(f"unsupported argument type for {name}")
    if "required" in spec and not isinstance(spec["required"], bool):
        raise RegistryError(f"invalid required flag for {name}")
    if kind == "string":
        enum = spec.get("enum")
        if enum is not None and (
            not isinstance(enum, list)
            or not enum
            or not all(isinstance(value, str) for value in enum)
            or len(set(enum)) != len(enum)
        ):
            raise RegistryError(f"invalid enum for {name}")
    if "default" in spec:
        _validate_argument(name, spec["default"], spec)


def validate_tool_registry(document: dict) -> None:
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise RegistryError("unsupported tool registry")
    tools = document.get("tools")
    if not isinstance(tools, dict):
        raise RegistryError("tool registry must contain tools")
    for name, tool in tools.items():
        _name(name, "tool name")
        if not isinstance(tool, dict):
            raise RegistryError(f"invalid tool: {name}")
        _name(tool.get("capability"), "capability")
        _name(tool.get("permission"), "permission")
        risk = tool.get("risk")
        if risk not in {"read", "write", "privileged"}:
            raise RegistryError(f"invalid risk for {name}")
        confirmation = tool.get("confirmation", "none")
        if confirmation not in {"none", "explicit"}:
            raise RegistryError(f"invalid confirmation mode for {name}")
        allow_unconfirmed = tool.get("allow_unconfirmed_mutation", False)
        if not isinstance(allow_unconfirmed, bool):
            raise RegistryError(f"invalid allow_unconfirmed_mutation for {name}")
        if risk in {"write", "privileged"} and confirmation != "explicit" and not allow_unconfirmed:
            raise RegistryError(
                f"state-changing tool {name} requires explicit confirmation; "
                "set allow_unconfirmed_mutation=true only after an explicit risk decision"
            )
        if risk == "read" and allow_unconfirmed:
            raise RegistryError(
                f"allow_unconfirmed_mutation is only valid for write or privileged tools: {name}"
            )
        resource = tool.get("resource")
        placeholders = resource_argument_names(resource)
        if not isinstance(tool.get("request"), dict):
            raise RegistryError(f"invalid request template for {name}")
        arguments = tool.get("arguments", {})
        if not isinstance(arguments, dict):
            raise RegistryError(f"invalid arguments for {name}")
        for arg_name, spec in arguments.items():
            _validate_argument_spec(arg_name, spec)
        unknown_placeholders = set(placeholders) - set(arguments)
        if unknown_placeholders:
            raise RegistryError(f"resource template references unknown arguments for {name}")


def validate_executor_registry(document: dict) -> None:
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise RegistryError("unsupported executor registry")
    executors = document.get("executors")
    if not isinstance(executors, dict):
        raise RegistryError("executor registry must contain executors")
    owners: dict[str, str] = {}
    for executor_id, item in executors.items():
        _name(executor_id, "executor id")
        if not isinstance(item, dict):
            raise RegistryError(f"invalid executor: {executor_id}")
        endpoint = item.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint:
            raise RegistryError(f"invalid endpoint for {executor_id}")
        capabilities = item.get("capabilities")
        if not isinstance(capabilities, list) or not capabilities:
            raise RegistryError(f"invalid capabilities for {executor_id}")
        for capability in capabilities:
            _name(capability, "capability")
            if capability in owners:
                raise RegistryError(f"capability owned by multiple executors: {capability}")
            owners[capability] = executor_id


def get_tool(name: str, *, registry: dict) -> dict:
    validate_tool_registry(registry)
    try:
        return registry["tools"][name]
    except KeyError as exc:
        raise RegistryError(f"unknown tool: {name}") from exc


def resolve_capability(capability: str, *, registry: dict) -> dict:
    validate_executor_registry(registry)
    for executor_id, item in registry["executors"].items():
        if capability in item["capabilities"]:
            return {"executor_id": executor_id, **item}
    raise RegistryError(f"no executor for capability: {capability}")


def _validate_argument(name: str, value: object, spec: dict) -> object:
    kind = spec.get("type")
    if kind == "string":
        if not isinstance(value, str):
            raise RegistryError(f"argument {name} must be a string")
        if "enum" in spec and value not in spec["enum"]:
            raise RegistryError(f"argument {name} is not allowed")
        if len(value) < spec.get("min_length", 0):
            raise RegistryError(f"argument {name} is too short")
        if len(value) > spec.get("max_length", 4096):
            raise RegistryError(f"argument {name} is too long")
        return value
    if kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise RegistryError(f"argument {name} must be an integer")
        if value < spec.get("minimum", -(2**63)) or value > spec.get("maximum", 2**63 - 1):
            raise RegistryError(f"argument {name} is out of range")
        return value
    if kind == "boolean":
        if not isinstance(value, bool):
            raise RegistryError(f"argument {name} must be boolean")
        return value
    raise RegistryError(f"unsupported argument type for {name}")


def materialize_tool(name: str, arguments: dict | None, *, registry: dict) -> dict:
    tool = copy.deepcopy(get_tool(name, registry=registry))
    if arguments is not None and not isinstance(arguments, dict):
        raise RegistryError("arguments must be an object")
    provided = {} if arguments is None else dict(arguments)
    specs = tool.get("arguments", {})
    unknown = set(provided) - set(specs)
    if unknown:
        raise RegistryError(f"unknown arguments: {', '.join(sorted(unknown))}")

    values: dict[str, object] = {}
    for arg_name, spec in specs.items():
        if arg_name in provided:
            value = provided[arg_name]
        elif "default" in spec:
            value = copy.deepcopy(spec["default"])
        elif spec.get("required"):
            raise RegistryError(f"missing argument: {arg_name}")
        else:
            continue
        values[arg_name] = _validate_argument(arg_name, value, spec)

    def expand(value: object) -> object:
        if isinstance(value, str) and value.startswith("$arg:"):
            key = value[5:]
            if key not in values:
                raise RegistryError(f"missing template argument: {key}")
            return values[key]
        if isinstance(value, dict):
            return {k: expand(v) for k, v in value.items()}
        if isinstance(value, list):
            return [expand(v) for v in value]
        return value

    try:
        resource = tool["resource"].format(**values)
    except KeyError as exc:
        raise RegistryError(f"missing resource template argument: {exc.args[0]}") from exc
    request = expand(tool["request"])
    return {**tool, "name": name, "arguments": values, "resource": resource, "request": request}


def catalog(*, registry: dict) -> list[dict]:
    validate_tool_registry(registry)
    result = []
    for name, item in sorted(registry["tools"].items()):
        result.append(
            {
                "name": name,
                "description": item.get("description", ""),
                "risk": item["risk"],
                "confirmation": item.get("confirmation", "none"),
                "arguments": copy.deepcopy(item.get("arguments", {})),
            }
        )
    return result
