# Development and testing

## Requirements

- Go 1.23 or later
- Standard Go tools; no third-party module dependency for the current core
- Nmap is optional and not needed for local test runs

## Build

```sh
go mod tidy
go build -o secubrain ./cmd/secubrain
go vet ./...
```

Windows:

```powershell
go build -o secubrain.exe ./cmd/secubrain
```

Cross-compile Windows x64 on a Unix-like shell:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o secubrain-windows-amd64.exe ./cmd/secubrain
```

## Tests

```sh
go test -count=1 -v ./...
go test -race ./...    # supported platforms only
```

The v0.1 test suite covers redacting credential values across every report format, respecting authorization for network calls, HEAD request semantics, preventing redirect traversal, URL validation, Nmap XML parsing, HTML escaping, and CLI quoting / Windows path handling.

`go test ./...` does not send traffic to public sites. HTTP tests use `httptest.NewServer` on localhost. The Nmap test parses a literal fixture; it does not run Nmap or scan a network.

## Reproduce documentation visuals

1. Run the local sample fixture: `go run ./cmd/secubrain scan --path ./examples/demo-project --out ./secubrain-reports`.
2. Run tests: `go test -count=1 -v ./...`.
3. Compare the results to the documented captures in `docs/assets/`. The illustrations are manually formatted SVG renders of the observed test output; they are **not** pixel screenshots of a user's desktop.
4. Use synthetic credentials only. Never submit actual secrets or private network names to public screenshots or reports.

## Suggested PR standards

Keep the command interface backward compatible when possible, add unit tests for each new detector and each safety boundary, avoid network requests in standard unit tests, and document new findings as *indicators* rather than proof of compromise. Update README tables and relevant documentation when shipping a new feature.
