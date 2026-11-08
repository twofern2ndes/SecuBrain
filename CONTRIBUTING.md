# Contributing to SecuBrain

Thank you for helping improve a minimal, deterministic security-auditing tool.

## Before contributing

- Read the [security boundaries](docs/security-model.md); default behavior must remain non-destructive and explicitly scoped.
- Search existing issues and describe the problem or planned change before a large PR.
- Never commit real credentials, private infrastructure details, production audit output, or exploit payloads.
- Keep user-facing documentation and issue reports in English for international collaboration.

## Development loop

```bash
go fmt ./...
go test -count=1 ./...
go vet ./...
go build ./cmd/secubrain
```

Please include: a clear problem statement, affected command/check, synthetic reproduction, automated tests, and documentation changes where appropriate.

### Rule quality

New rules should state what is observed (not assert active compromise), redact matched secret strings, explain false positives and false negatives, use bounded resources, and provide practical remediation guidance.

### Network integrations

Any new network action must require explicit opt-in, clear scope boundaries, measured timeouts, and non-destructive defaults. Do not add automated password guessing, exploit chains, stealth, or broad indiscriminate scanning to the default pipeline.

## Pull requests

Use focused commits and descriptive messages; tests must pass on the supported Go version. Maintainers may request revisions to limit collection of private data or avoid misleading severity claims.
