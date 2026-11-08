# Demonstration fixture

`demo-project/` contains **invented, deliberately insecure assignments** for validating the local credential-indicator rules. **No real credentials, production systems, or network hosts are used.** Do not deploy this fixture.

```sh
go run ./cmd/secubrain scan --path ./examples/demo-project --out ./secubrain-reports
```

The scanner should report medium-severity *potential hardcoded credential* indicators. Values themselves are redacted in report evidence. `.env.example` is a documentation template, not a secret file. The test suite separately creates a temporary `.env` file to validate ignore checks.

This fixture provides reproducible local results and does **not** demonstrate exploitation or proof of a genuine vulnerability.
