# Architecture and data flow

SecuBrain is a **Go 1.23 standard-library** application. Its audit engine deliberately does not delegate execution decisions to an LLM or a shell.

## Component map

| Area | Location | Responsibility |
|:--|:--|:--|
| Entrypoint | `cmd/secubrain/main.go` | Map arguments to exit code |
| CLI and REPL | `internal/cli/cli.go` | Parse flags, accept basic terminal commands, show progress |
| Pipeline/model | `internal/audit/types.go` | Validate scope, execute stages, collect and sort findings |
| Local analysis | `internal/audit/detectors.go` | Traverse bounded project files and evaluate patterns |
| HTTP adapter | `internal/audit/web.go` | One HEAD request, no redirects, configuration advisories |
| Nmap adapter | `internal/audit/nmap.go` | Optional subprocess with fixed arguments, parse XML |
| Report engine | `internal/audit/reports.go` | Generate HTML, Markdown, and JSON |

## Execution order

1. `cli.Run` interprets the user's command. Running with no arguments starts a simple interactive REPL.
2. `audit.Run` validates configuration: at least a directory, URL, or Nmap target, existing local directory, output destination, count/time limits, URL syntax, and authorization assertion for remote checks.
3. If a directory is provided, `scanFiles` walks supported files while skipping common build folders and symbolic links. It applies deterministic line-based expressions, records *redacted* evidence, and checks root `.env` ignore coverage.
4. If a URL is provided, `scanWeb` sends one HEAD request. It records header observations and warnings without following redirect destinations.
5. If and only if `--nmap` was enabled, `scanNmap` runs an installed Nmap with a profile-selected TCP connect scan for the exact explicitly authorized --target (or URL hostname). The adapter parses XML; no shell is involved.
6. `summarize` sorts findings by priority and location and computes counts.
7. `WriteReports` writes self-contained HTML plus Markdown and JSON representations.

## Data model

A `Report` contains version, input scope, UTC timestamps, statistics, findings, checks, and warnings. A `Finding` contains stable ID, severity, category, title, description, generic redacted evidence, location, optional line number, and a recommendation. IDs are deterministic within a given location/rule and are not cryptographic proof of uniqueness.

## Resource bounds

- Local project: one file up to **1 MiB**, at most **30 MiB** inspected content, at most **250** findings, default **5000** source files (configurable to 50,000).
- Web check: a single HEAD request, default **8s** timeout, maximum **60s**, no redirect traversal.
- Nmap adapter: per-host timeout defaults to 100s (quick), 5m (standard), 20m (full), configurable between 15s and 30m; XML bounded to 24 MiB; one explicit target. HTML/Markdown cap port previews; JSON retains parsed inventory.
- Remote targets are not inferred from local source. Only explicitly supplied URL or --target values are considered and require --authorized.

## Trust and limitations

Parsing a directory or a remote response does not guarantee correctness. Static signatures can trigger on innocuous examples or miss obfuscated or runtime-derived credentials. The scanner neither validates active tokens nor determines exploitability. `--authorized` is an operator assertion only. Network requests and Nmap operations must be approved within the target owner's scope.

Reports suppress matched credential values but can include file locations and endpoint names. Review the generated reports before sharing them externally.

## 0.3.0 components

- `internal/ui` handles the TTY-aware CLI presentation, plain fallback and Windows console virtual terminal setup.
- `internal/audit/nmap.go` locates Nmap separately, queries its version, runs a controlled profile-specific command through `exec.CommandContext` and parses detailed Nmap XML, including host/port/service/version/NSE/OS metadata. No raw command flags are passed through.
- `internal/audit/testdata/fakenmap` is a test-double executable. It does not send packets; the fixed argv and interpretation are verified in integration tests.
- `installer/SecuBrain.iss` builds the guided Windows installer from the Windows CLI binary and project documentation, with an explicit user-acceptance page. Nmap/Npcap are never packed. Nmap real-loopback CI gates the Windows installer workflow.
- `.github/workflows/windows-installer.yml` builds the installer on a Windows runner, performs a sandboxed install/uninstall smoke test, and publishes a prerelease only after validation.

The installer and program are independent: running `secubrain.exe` from a source build does not trigger installation, and installing SecuBrain does not perform network scans automatically.
