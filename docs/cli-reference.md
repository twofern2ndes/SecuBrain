# Command-line reference

The CLI is intentionally small. It accepts commands directly or through a basic interactive prompt.

## Entrypoints

```sh
secubrain                 # interactive prompt
secubrain help            # complete usage
secubrain version         # version string
secubrain scan --path .   # inspect a local directory
```

The interactive prompt accepts `scan`, `status`, `help`, `version`, `exit` / `quit`. It supports quoted paths, including backslashes in Windows file paths. The interactive `status` command remembers the last successful report path in the current process only. It is not a multi-session database.

## Scan flags

| Flag | Input | Default | Notes |
|---|---|---|---|
| `--path` | Folder path | None | Required unless `--url` supplied; accepts a positional path as an alternative |
| `--url` | `http://` or `https://` endpoint | None | No username/password, query or fragment |
| `--authorized` | Boolean | Off | Must be set for any URL-based check; operator asserts permission |
| `--nmap` | Boolean | Off | Requires URL; Nmap must be on PATH |
| `--out` | Output folder | `secubrain-reports` | Created if absent; reports may include sensitive locations |
| `--max-files` | Integer | 5000 | Maximum 50,000; a nonpositive value is reset to default |
| `--timeout` | Go duration | `8s` | Maximum `60s`; applies to web request |

## Tested usage

```powershell
# Windows, source inspection only
.\secubrain.exe scan --path "C:\Projects\my-api" --out "C:\Audits\my-api"
```

```bash
# Linux/macOS, local sample fixture
go run ./cmd/secubrain scan --path ./examples/demo-project --out ./secubrain-reports

# Web header check (only your own/approved system)
go run ./cmd/secubrain scan --url https://your-owned-host.example --authorized

# Optional bounded Nmap adapter
go run ./cmd/secubrain scan --url https://your-owned-host.example --authorized --nmap
```

## Output

A successful scan prints file count, counts by severity, warnings, and paths to three reports. Validation or report-writing errors yield nonzero exit status. Some optional network failures become warnings so that a partial report remains available; check warnings rather than treating an exit code of 0 as proof that every adapter ran successfully.

## Explicit non-features

No arbitrary-command chat, shell passthrough, automatic exploit execution, password attacks, stealth scanning, port-range input, crawling, vulnerability confirmation, cloud-agent connection, or AI-based decisions are implemented.

## New in 0.2.0 — Nmap health and explicit executable path

`secubrain doctor` (or `tools`) checks available runtime tools without scanning any network target. It returns the detected user-installed Nmap binary, version, and discovery method when present, or the official independent download page when absent. A missing optional tool is not fatal for local project auditing.

`secubrain scan --url https://authorized.example --authorized --nmap` enables bounded Nmap TCP connect / light service inspection. `--nmap-bin PATH` overrides Nmap discovery. `SECUBRAIN_NMAP_PATH` is another optional override. A provided explicit path that does not exist fails clearly instead of silently falling back.

The CLI uses ANSI colors and a brief banner animation only on an interactive supported terminal. `NO_COLOR=1` or `SECUBRAIN_PLAIN=1` disables ANSI. `SECUBRAIN_NO_ANIM=1` disables animation. Non-interactive runs fall back to plain output.

For Nmap parameters, safety bounds and XML semantics, read [Nmap integration](nmap-integration.md).
