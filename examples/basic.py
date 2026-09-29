import json
import tempfile
from pathlib import Path

from secure_ops_gateway import Gateway, SourceContext, StaticIdentityResolver
from secure_ops_gateway.gateway import ConfirmationRequired
from secure_ops_gateway.operation_guard import SQLiteOperationGuard

ROOT = Path(__file__).parent / "config"


def load(name):
    return json.loads((ROOT / name).read_text())


def local_executor(_route, payload):
    return {"ok": True, "handled": payload["request"]}


def main():
    # A private state directory is required. Do not place the SQLite file
    # directly in a shared-writable directory such as /tmp.
    with tempfile.TemporaryDirectory(prefix="secure-ops-gateway-") as state_dir:
        gateway = Gateway(
            tools=load("tools.json"),
            executors=load("executors.json"),
            policy=load("authorization.json"),
            identity_resolver=StaticIdentityResolver(load("identities.json")),
            executor_call=local_executor,
            operation_guard=SQLiteOperationGuard(
                Path(state_dir) / "operations.sqlite3"
            ),
        )
        source = SourceContext("example", "local-user", "request-1")
        print(gateway.invoke(source, "demo.status"))

        try:
            gateway.invoke(source, "demo.restart", {"service": "api"})
        except ConfirmationRequired as exc:
            challenge = exc.challenge
            print("confirmation required:", challenge)
            print(
                gateway.invoke(
                    source,
                    "demo.restart",
                    {"service": "api"},
                    confirmed=True,
                    confirmation_token=challenge["confirmation_token"],
                )
            )


if __name__ == "__main__":
    main()
