# Changelog

## 0.1.1 - unreleased

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
