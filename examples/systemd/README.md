# Bounded systemd executor example

`../systemd_executor.py` is a real executor example for two capabilities only:

- `service.status` — read status for an allowlisted service;
- `service.restart` — restart an allowlisted service after the gateway's normal explicit-confirmation flow.

The public name sent through the gateway is an alias such as `api`. The executor independently maps that alias to one fixed `.service` unit through `services.json`. Arbitrary unit names are rejected.

The example invokes an absolute `systemctl` path with an argument vector. It never invokes a shell and never concatenates caller data into a command string.

## Files

- `services.json` — security-sensitive alias-to-unit allowlist;
- `tools.json` — gateway tool definitions;
- `executors.json` — capability routing to the Unix socket;
- `authorization.json` — demonstration resource-aware policy.

Keep the executor key in a separate file owned by the executor operating-system user with mode `0600`. The file contains exactly 32 random bytes encoded as 64 hexadecimal characters. The services configuration must be owned by root or the executor user and must not be group/world writable.

Example invocation:

```bash
python examples/systemd_executor.py \
  --socket /run/secure-ops-gateway/systemd/executor.sock \
  --key-file /etc/secure-ops-gateway/systemd-executor.key \
  --services-file /etc/secure-ops-gateway/systemd-services.json
```

Do not run this example with broader operating-system privileges than necessary. A dedicated service account plus a narrowly scoped systemd/PolicyKit policy for the exact units is preferable to running the executor as unrestricted root. `service.restart` will fail closed if the executor account is not authorized to restart the selected unit.
