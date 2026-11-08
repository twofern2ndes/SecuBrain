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
2. `audit.Run` validates configuration: at least a directory or URL, existing local directory, output destination, count/time limits, URL syntax, and authorization assertion for remote checks.
3. If a directory is provided, `scanFiles` walks supported files while skipping common build folders and symbolic links. It applies deterministic line-based expressions, records *redacted* evidence, and checks root `.env` ignore coverage.
4. If a URL is provided, `scanWeb` sends one HEAD request. It records header observations and warnings without following redirect destinations.
5. If and only if `--nmap` was enabled, `scanNmap` runs an installed Nmap with a fixed bounded TCP connect scan for the exact hostname extracted from the URL. The adapter parses XML; no shell is involved.
6. `summarize` sorts findings by priority and location and computes counts.
7. `WriteReports` writes self-contained HTML plus Markdown and JSON representations.

## Data model

A `Report` contains version, input scope, UTC timestamps, statistics, findings, checks, and warnings. A `Finding` contains stable ID, severity, category, title, description, generic redacted evidence, location, optional line number, and a recommendation. IDs are deterministic within a given location/rule and are not cryptographic proof of uniqueness.

## Resource bounds

- Local project: one file up to **1 MiB**, at most **30 MiB** inspected content, at most **250** findings, default **5000** source files (configurable to 50,000).
- Web check: a single HEAD request, default **8s** timeout, maximum **60s**, no redirect traversal.
- Nmap adapter: maximum **40s** context lifetime and `--host-timeout 30s` in the command.
- Remote targets are not inferred from local source; only explicit URL input is considered.

## Trust and limitations

Parsing a directory or a remote response does not guarantee correctness. Static signatures can trigger on innocuous examples or miss obfuscated or runtime-derived credentials. The scanner neither validates active tokens nor determines exploitability. `--authorized` is an operator assertion only. Network requests and Nmap operations must be approved within the target owner's scope.

Reports suppress matched credential values but can include file locations and endpoint names. Review the generated reports before sharing them externally.
