# Security Policy

Secure Ops Gateway is security-sensitive infrastructure software.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability that could enable unauthorized execution, privilege escalation, authentication bypass, secret disclosure, or replay of privileged operations.

Use GitHub's private vulnerability reporting feature when it is enabled for this repository. If private reporting is unavailable, contact the repository owner privately before publishing technical details.

## Trust boundaries

The gateway does **not** authenticate an end user by reading identity fields from a request body. A transport adapter must first authenticate the connection or token and derive a trusted `(source_provider, source_subject)` pair. `SourceContext` must contain only those transport-derived values. `StaticIdentityResolver` or another resolver then maps that authenticated source to a gateway principal.

Never let a remote caller directly choose `source_provider`, `source_subject`, or a principal identifier. For OAuth, SSH, mutual TLS, local peer credentials, or another transport, bind these fields from verified transport metadata.

## Executor authentication and replay protection

Executor requests and responses use purpose-separated HMAC-SHA256 envelopes. Verification requires a replay protector; verification without replay protection is rejected. Responses are bound to the originating `request_id`, and the built-in Unix-socket client rejects unsigned, reflected, mismatched or replayed responses. `ReplayCache` is suitable only for a single long-running process. `SQLiteReplayProtector` persists nonce state across restarts and coordinates multiple processes on one host. Multi-host deployments still require a distributed replay-protector implementation.

Use a distinct random key for each trust boundary and keep executor sockets inaccessible to untrusted local users. The built-in `UnixSocketExecutorServer` requires a private owner-controlled parent directory, refuses any pre-existing socket path, creates the socket with mode `0600`, pins the parent directory identity, and performs inode-checked cleanup so it does not unlink a replacement path. Its handler map is an exact capability allowlist; do not register a generic shell or command-execution capability.

## Confirmation state

Explicit-confirmation tokens are bound to the principal, authenticated source, tool, capability, permission, concrete resource, risk level, materialized arguments, and bounded executor request. `write` and `privileged` tools require explicit confirmation by default; bypassing it requires the deliberately named `allow_unconfirmed_mutation: true` escape hatch. Confirmation state is stored with mode `0600` when using `SQLiteOperationGuard`.

An executor error after a confirmed operation starts is recorded as an `uncertain` outcome. An operation left in `executing` past the configured stale interval is also converted to `uncertain`. Do not automatically retry an uncertain mutation; verify the target state first. Old terminal confirmation records are removed after the configured retention period.

## Audit

The gateway emits structured events for identity denial, authorization denial, confirmation requirements/denials, invocation start, success, failure, uncertain outcomes, and idempotent replays. Audit records intentionally exclude executor credentials and confirmation tokens.

Protect the audit destination from modification and deletion by the workload being audited whenever possible. The built-in file sinks reject symlink leaves, shared-writable state directories, directories owned by unrelated operating-system users, and parent-directory replacement after initialization. JSONL file writes use cross-process `flock` serialization so partial writes from independent gateway processes cannot interleave. Pre-execution audit failure prevents execution. Post-execution audit failure never changes a successful executor result into a client-visible operation failure; route `audit_failure_handler` to an independent alerting channel.

## Observability

`GatewayMetrics` intentionally uses a fixed, low-cardinality schema and does not accept principal IDs, transport subjects, request IDs, tool names, capabilities or resources as metric labels. Keep that property when exporting or transforming metrics: do not add user-controlled or security-sensitive values as labels. Metrics are best-effort and are not a substitute for the durable audit trail.

Treat monitoring endpoints as a separate authenticated surface. Even aggregate operational counters can reveal workload timing, failure rates or service health. The built-in collector is process-local; multi-worker deployments should aggregate snapshots externally rather than weakening the gateway trust boundary to share metrics state.

## General deployment guidance

The project intentionally exposes bounded capabilities rather than arbitrary shell commands. Deployments are expected to keep executors isolated, use separate credentials per trust boundary, authorize every concrete resource, and require explicit confirmation for state-changing operations.

The example configuration is not a production security policy.

## Local state paths

Do not place security-sensitive state files directly in `/tmp` or another directory writable by unrelated users. Use a dedicated directory owned by the gateway account and not writable by group or others. Existing ancestors must be owned by root or the gateway account; the final state directory must be owned by the effective gateway user. The built-in state components validate ownership, permissions, symlinks and parent identity, but deployment permissions remain part of the trust boundary.

## Resource exhaustion

The default gateway admission controller limits per-authenticated-source call rate and concurrent work before identity resolution, so unknown-but-authenticated sources are covered as well. Requests rejected by admission are not written to the normal per-request audit sink, preventing an attacker from turning rate-limit denials into unbounded audit-log growth; expose aggregate admission metrics through a separate bounded monitoring path if required.

The default controller is process-local. `SQLiteAdmissionController` provides one same-host boundary across multiple gateway workers: rate events are durable, concurrency leases are counted transactionally, authenticated source identifiers are stored only as SHA-256 digests, and dead-worker leases are reclaimed before admission. On Linux, the kernel boot ID and process start ticks are stored with the PID so PID reuse or a host reboot does not release a live process's capacity accidentally. A release-state failure is deliberately fail-closed and should be surfaced through `release_failure_handler`. Multi-host replicas still require a distributed limiter, and transports should enforce request-size and connection limits independently.
