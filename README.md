# Secure Ops Gateway

Secure Ops Gateway is a small, policy-driven control backend for safely exposing bounded operational capabilities to AI agents, MCP clients, APIs and command-line tools.

It separates **authenticated identity, authorization and intent** from **execution**:

```text
authenticated client / agent / API
        |
        v
transport adapter
  derives trusted provider + subject
        |
        v
Secure Ops Gateway
  identity resolution
  authorization
  tool registry
  capability routing
  confirmation guard
  audit
        |
        v
isolated executors
        |
        v
services / hosts / applications
```

The gateway does not need to know how a specific service is implemented. A tool maps a user-facing operation to a capability, permission, resource and bounded request. The executor registry maps that capability to one isolated executor.

## Why

Operational automation often ends up exposing a generic shell, SSH session or highly privileged API to an automation client. Secure Ops Gateway takes the opposite approach: expose only explicit operations and evaluate authorization against the concrete resource before execution.

## v0.1 scope

The initial public core contains:

- authenticated-source-to-principal identity resolution;
- role- and resource-based authorization;
- risk levels (`read`, `write`, `privileged`);
- declarative tool and executor registries;
- argument validation and bounded request templates;
- capability-to-executor routing;
- bidirectional HMAC-SHA256 authenticated executor envelopes with mandatory replay protection and request/response binding;
- SQLite-backed explicit confirmation with idempotent replay, stale-execution recovery, bounded retention and ownership/symlink/replacement-safe state paths;
- authorization-filtered tool discovery;
- structured JSONL audit events with fail-closed pre-execution logging and non-duplicating post-execution failure semantics;
- in-process rate and concurrency admission controls;
- JSON Schema generation helpers for MCP-style tool definitions;
- example configuration and tests.

The Python core has no runtime dependencies outside the standard library.

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e . pytest
python -m pytest
python examples/basic.py
```

## Identity boundary

A remote client must **never** be allowed to send its own principal identifier. The transport authenticates the caller and constructs a `SourceContext` from trusted transport metadata. An identity resolver maps that authenticated source to a gateway principal.

```python
from secure_ops_gateway import SourceContext, StaticIdentityResolver

resolver = StaticIdentityResolver({
    "schema": 1,
    "bindings": [
        {"provider": "ssh", "subject": "uid:1001", "principal": "operator-a"}
    ],
})

source = SourceContext("ssh", "uid:1001", "request-123")
```

For a real deployment, `source_provider` and `source_subject` should come from verified OAuth claims, mutual-TLS identity, SSH/local peer credentials, or equivalent authenticated transport state—not from request JSON supplied by the caller.

## Configuration model

A tool declares a bounded public operation:

```json
{
  "capability": "demo.restart",
  "permission": "demo.restart",
  "resource": "demo:{service}",
  "risk": "write",
  "confirmation": "explicit",
  "arguments": {
    "service": {
      "type": "string",
      "required": true,
      "enum": ["api", "worker"]
    }
  },
  "request": {
    "action": "restart",
    "service": "$arg:service"
  }
}
```

The executor registry independently decides which isolated component owns the capability. Authorization independently decides which principals may use a permission against which resources and maximum risk level.

Tool discovery filters enumerated resource arguments through authorization. Values a principal cannot access are not returned in the catalog. Dynamic resource templates that cannot be safely enumerated are hidden from discovery and remain callable only if the concrete invocation passes authorization.

See [`examples/config`](examples/config) for a complete minimal configuration.

## MCP transport adapter

The development branch includes a stdio MCP adapter that serves the current stateless `2026-07-28` protocol and the latest handshake-era `2025-11-25` protocol. It implements `server/discover`, `initialize`, `tools/list`, `tools/call` and legacy `ping` without adding runtime dependencies.

Transport identity remains outside the MCP request body. An embedding transport supplies an `MCPTrustedSource` containing the authenticated provider and subject; the adapter creates `SourceContext` objects from that trusted metadata and generates gateway request IDs server-side. Client-supplied `principal` fields are never used for gateway identity.

`tools/list` is authorization-filtered through `Gateway.catalog()`. `tools/call` delegates authorization, routing, confirmation and audit semantics to the existing gateway core. For tools requiring explicit confirmation, the adapter exposes the existing `confirmed` and `confirmation_token` controls in the MCP input schema and returns a structured confirmation challenge when approval is required. The MCP host is responsible for collecting the intended approval before retrying the operation.

The built-in stdio transport uses newline-delimited JSON-RPC and enforces a bounded request-frame size. It writes protocol messages only to stdout; embedding applications should send diagnostics to stderr.

## Executor verification

Executor servers must verify every request envelope with replay protection and return a signed response envelope bound to the same request ID:

```python
from secure_ops_gateway.executor import ReplayCache, sign_response, verify_envelope

replay = ReplayCache(max_age_seconds=60)
payload = verify_envelope(
    envelope,
    key,
    replay_protector=replay,
    expected_purpose="request",
)

result = {"ok": True}
response_envelope = sign_response(payload["request_id"], result, key)
```

The built-in Unix-socket client rejects unsigned responses, wrong request IDs, reflected request envelopes and replayed responses. The built-in cache is process-local. Use a shared/durable replay protector when executors are replicated or must retain replay state across restarts.

## State-path safety

Security-sensitive state such as the confirmation database and JSONL audit log must live in a directory owned by the effective gateway user and not writable by group or other users. Existing ancestors must be owned by root or the gateway user. Final state files and existing path components may not be symlinks, and the gateway pins the parent directory identity so replacement after initialization is rejected. A file directly under shared `/tmp` is intentionally rejected; create a private `0700` subdirectory instead.

## Admission limits

`Gateway` enables an in-process rate/concurrency controller by default: 120 calls per authenticated source per 60 seconds, at most 4 concurrent calls per source and 16 globally. Admission happens before identity resolution, so unknown-but-authenticated sources are limited too. Multi-process or replicated deployments should provide a shared admission controller if they require fleet-wide limits.

## Audit failure semantics

The `invoke_started` audit event is fail-closed: if it cannot be written, the executor is not called. Once an executor has returned success, failure to append `invoke_succeeded` is treated as an audit-channel degradation rather than an operation failure, avoiding a misleading client error that could trigger a duplicate mutation. Use `audit_failure_handler` to surface that degradation through an independent monitoring path.

## Design principles

1. **No generic shell in the gateway.** Add explicit executor capabilities instead.
2. **Authorization is resource-aware.** Permission alone is insufficient.
3. **Executor presence does not grant access.** Routing and authorization are separate concerns.
4. **Mutations require explicit confirmation by default.** `write` and `privileged` tools are rejected unless they use explicit confirmation or deliberately declare `allow_unconfirmed_mutation: true`. Confirmation tokens bind the full security-relevant operation.
5. **Credentials stay behind the gateway.** Executor authentication material is not part of client requests.
6. **Identity comes from authenticated transport metadata.** Clients do not choose principals.
7. **Service-specific logic stays out of the core.** Integrations belong in isolated executors.

## Project status

`0.1.1` is a security-hardening alpha release of the standalone public project. The API and configuration schemas may change before `1.0`.

Near-term work includes a reusable executor SDK, packaging of example executors, durable replay backends, structured observability, deployment documentation and richer MCP confirmation/elicitation integration. See `CHANGELOG.md` for security changes since 0.1.0.

## Security

Read [`SECURITY.md`](SECURITY.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md) before using this software for privileged operations. Treat the example policies as demonstrations, not production defaults.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
