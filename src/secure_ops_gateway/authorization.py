from __future__ import annotations

from fnmatch import fnmatchcase

RISK_ORDER = {"read": 0, "write": 1, "privileged": 2}


class AuthorizationError(RuntimeError):
    pass


class AuthorizationDenied(AuthorizationError):
    pass


def _valid_risk(value: str) -> bool:
    return isinstance(value, str) and value in RISK_ORDER


def validate_policy(policy: dict) -> None:
    if not isinstance(policy, dict) or policy.get("schema") != 1:
        raise AuthorizationError("unsupported authorization policy")
    roles = policy.get("roles")
    bindings = policy.get("bindings")
    if not isinstance(roles, dict) or not isinstance(bindings, dict):
        raise AuthorizationError("invalid authorization policy")

    for role_id, role in roles.items():
        if not isinstance(role_id, str) or not isinstance(role, dict):
            raise AuthorizationError("invalid role")
        permissions = role.get("permissions")
        max_risk = role.get("max_risk")
        if (
            not isinstance(permissions, list)
            or not all(isinstance(x, str) and x for x in permissions)
            or not _valid_risk(max_risk)
        ):
            raise AuthorizationError(f"invalid role: {role_id}")

    for principal, entries in bindings.items():
        if not isinstance(principal, str) or not isinstance(entries, list):
            raise AuthorizationError("invalid binding")
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("role") not in roles:
                raise AuthorizationError(f"invalid binding for {principal}")
            resources = entry.get("resources")
            if not isinstance(resources, list) or not all(
                isinstance(x, str) and x for x in resources
            ):
                raise AuthorizationError(f"invalid resources for {principal}")


def authorize(
    principal_id: str,
    permission: str,
    resource: str,
    risk: str,
    *,
    policy: dict,
) -> dict:
    validate_policy(policy)
    if not _valid_risk(risk):
        raise AuthorizationDenied("unknown risk level")

    for binding in policy["bindings"].get(principal_id, []):
        role = policy["roles"][binding["role"]]
        if permission not in role["permissions"] and "*" not in role["permissions"]:
            continue
        if RISK_ORDER[risk] > RISK_ORDER[role["max_risk"]]:
            continue
        if not any(fnmatchcase(resource, pattern) for pattern in binding["resources"]):
            continue
        return {"role": binding["role"], "resource": resource}

    raise AuthorizationDenied(
        f"principal {principal_id!r} is not authorized for {permission!r} on {resource!r}"
    )
