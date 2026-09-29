# Contributing

Contributions are welcome.

1. Keep the gateway generic. Service-specific behavior belongs in executors or integrations.
2. Do not introduce arbitrary shell, SSH, Docker exec, or unrestricted file-operation surfaces into the core gateway.
3. New state-changing capabilities should be explicit, bounded and covered by authorization tests.
4. Security-sensitive changes require tests for both the allowed and denied paths.
5. Never commit credentials, real infrastructure addresses, production principal mappings or private deployment configuration.

Run the validation suite with:

```bash
python -m compileall -q src tests examples
python -m coverage run -m pytest -q
python -m coverage report --fail-under=90
```

Security regressions should include an adversarial test that reproduces the previous failure mode.
