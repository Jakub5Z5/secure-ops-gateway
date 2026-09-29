# Changelog

## 0.2.0 - unreleased

### Added

- Added a reusable authenticated Unix-socket executor server SDK with exact capability allowlisting, typed invocation metadata, HMAC-SHA256 request verification, replay protection and request-bound signed responses.
- Added bounded executor request/response framing, per-connection timeouts, isolated connection failures and secure `0600` Unix-socket lifecycle management below a private owner-controlled directory.
- Added a dual-era MCP stdio adapter supporting the current stateless `2026-07-28` protocol and the latest handshake-era `2025-11-25` protocol.
- Added `server/discover`, `initialize`, `tools/list`, `tools/call` and legacy `ping` handling over newline-delimited JSON-RPC.
- Added MCP tool-result translation with structured JSON output and explicit confirmation challenge propagation.
- Added bounded stdio framing with a 4 MiB default maximum request line size.
- Added an end-to-end compatibility test against the official MCP Python SDK 2.2.0 over a real stdio subprocess, covering modern auto-negotiation, legacy initialization, tool discovery, tool calls and confirmation retry.

### Security

- Executor servers refuse pre-existing socket paths, pin the private parent directory identity and remove their socket only when the path still refers to the exact socket inode they created.
- Unauthenticated, malformed, replayed, unsupported-capability and handler-failure requests receive no signed success response, preserving the gateway's uncertain-outcome semantics for mutations.
- MCP requests cannot choose a gateway principal. The adapter requires a separately supplied trusted transport provider/subject and mints gateway request IDs server-side.
- Authorization-filtered gateway catalogs are exposed as private, immediately stale MCP tool lists to avoid cross-identity caching.
- Unknown/internal failures are mapped without leaking authorization policy details or arbitrary exception text.

## 0.1.1 - 2026-09-29

Security hardening release prepared after the public 0.1.0 audit.

### Security

- Reject state directories controlled by an unrelated operating-system user, even when their mode is `0700`.
- Validate existing path ancestors before creating state directories, preventing privileged directory creation through an untrusted or symlinked prefix.
- Pin the state parent identity (device, inode and owner) and reject parent replacement after initialization.
- Serialize JSONL audit writes across independent processes/instances with `flock`, including partial-write loops.
- Apply admission limits before identity resolution so unknown authenticated sources cannot bypass rate/concurrency controls; over-limit attempts are rejected without per-request audit writes to avoid log-amplification denial of service.
- Reserve gateway confirmation field names to prevent MCP schema/control collisions.
- Validate argument constraints and `$arg:` request templates at startup instead of failing during invocation.
- Close every SQLite operation-guard connection deterministically and fail CI on leaked `ResourceWarning` handles.

### Quality

- Added adversarial regression tests for parent replacement, ownership, audit interleaving, invalid registry constraints and pre-identity rate limiting.
- Added direct MCP schema tests.
- CI now compiles sources, enforces at least 90% coverage, builds a wheel and verifies installation from that wheel on Python 3.11-3.13.
