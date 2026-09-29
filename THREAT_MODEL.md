# Threat Model

Secure Ops Gateway is a policy and execution boundary for operational automation. The core assumes that transport authentication happens before a request reaches `Gateway`.

## Assets

The primary assets are:

- authorization policy and identity bindings;
- executor credentials and authenticated request/response integrity;
- bounded operational capabilities;
- confirmation tokens and operation state;
- audit integrity and availability;
- the target services reached through executors.

## Trust boundaries

1. **Client -> transport adapter**: the transport authenticates the caller. Request-body identity fields are not trusted.
2. **Transport adapter -> gateway**: `SourceContext` contains only authenticated provider/subject metadata and a request identifier.
3. **Gateway -> executor**: requests and responses are authenticated with purpose-separated HMAC-SHA256 envelopes and replay protection.
4. **Gateway -> local state**: audit and confirmation state must be stored below a directory owned by the effective gateway user, with only root- or gateway-owned ancestors.
5. **Executor -> managed service**: each executor is responsible for translating one or more explicit capabilities into service-specific actions without exposing a generic command surface.

## Adversaries considered

The design considers:

- a remote authenticated client attempting to select another principal;
- an authenticated source attempting unauthorized resources or risk levels;
- replay or modification of gateway/executor messages;
- reuse or cross-binding of confirmation tokens;
- malicious or compromised local users attempting symlink/path-redirection attacks against gateway state or executor socket paths;
- concurrent local gateway processes attempting to append audit records;
- clients attempting resource exhaustion through repeated or concurrent requests;
- executor failures where the final mutation outcome cannot be known safely.

## Security assumptions

- The transport authenticator is correct and does not copy identity from untrusted payload fields.
- Executor HMAC keys are random, secret and separated between trust boundaries.
- The operating system enforces user ownership, Unix socket permissions and file permissions.
- Processes running under the same operating-system UID are within one local trust domain. A hostile process with the same UID can generally inspect or modify that user's state and is not isolated by file ownership alone.
- A process with root-level control over the host is outside the protection boundary.
- Multi-process same-host executor deployments may use the built-in SQLite replay backend; multi-host deployments provide distributed replay/rate-limit backends when local controls are insufficient.

## Fail-closed behavior

The gateway fails closed when:

- identity cannot be resolved;
- authorization fails;
- a state-changing tool lacks required explicit confirmation;
- confirmation state is mismatched, expired, already executing or uncertain;
- pre-execution audit cannot be persisted;
- authenticated executor request or response verification fails;
- an executor request names a capability not explicitly registered by that executor;
- security-sensitive state paths fail ownership, permission, symlink or parent-identity checks.

Once an executor has returned success, a later audit append failure is reported out-of-band rather than converted into a client-visible operation failure, because returning failure could encourage a duplicate mutation.

## Out of scope for the core

The core does not currently provide:

- end-user authentication transports;
- host sandboxing for executors;
- distributed multi-host replay protection;
- fleet-wide distributed rate limiting;
- secret storage or key rotation;
- tamper-evident remote audit storage.

Deployments must supply those controls where required.
