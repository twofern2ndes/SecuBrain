# Command-line reference — v0.3.0

SecuBrain is a local-first deterministic Go executable. It supports non-interactive commands and a small built-in interactive prompt. No AI, cloud account, or custom shell-command execution is required.

## Commands

| Command | Action |
|---|---|
| `secubrain` | Open interactive command prompt |
| `secubrain help` | Display all available flags |
| `secubrain version` | Display running version |
| `secubrain doctor [--nmap-bin PATH]` | Identify the installed Nmap executable and version |
| `secubrain scan [options]` | Run local file, HTTP header, and/or Nmap checks |
| `secubrain nmap --target HOST --authorized [options]` | Convenient equivalent of `scan --nmap --target HOST --authorized` |

## Arguments and behavior

| Flag | Description | Default |
|---|---|---|
| `--path FOLDER` | Audit a local directory (or one positional path) | None |
| `--url URL` | Single authorized HTTP(S) endpoint (HEAD only, no redirects) | None |
| `--target HOST` | Exactly one IP address or DNS hostname for Nmap | None |
| `--authorized` | Operator asserts explicit permission for all remote checks | Required for URL/Nmap |
| `--nmap` | Enable Nmap subprocess from `scan` | Off |
| `--nmap-profile quick\|standard\|full` | ~100 / ~1000 / all 65535 TCP ports | Standard |
| `--nmap-udp` | Add UDP service inventory | Off |
| `--nmap-os` | Enable OS estimation (often requires elevated privileges) | Off |
| `--nmap-scripts` | Run default NSE scripts (can increase traffic) | Off |
| `--nmap-bin PATH` | Explicit executable path; overrides search | PATH / standard Windows paths |
| `--nmap-timeout DURATION` | Per-host timeout, `15s`–`30m` | Profile dependent |
| `--out FOLDER` | Local output folder | `./secubrain-reports` |
| `--max-files N` | Maximum files inspected | 5000 |
| `--timeout DURATION` | HTTP HEAD timeout, up to 60s | 8s |

### Examples

```powershell
secubrain doctor
secubrain scan --path C:\\Projects\\my-app --out C:\\Audits\\app
secubrain nmap --target 192.0.2.10 --authorized --nmap-profile standard
secubrain nmap --target 192.0.2.10 --authorized --nmap-profile full --nmap-timeout 25m
secubrain scan --url https://approved.example --nmap --authorized
secubrain nmap --target 192.0.2.10 --authorized --nmap-bin "C:\\Program Files (x86)\\Nmap\\nmap.exe"
```

A `scan` command with both `--url` and `--target` must refer to the **same** hostname. For standalone network audits, use `nmap --target` without a URL; this avoids an unnecessary HTTP request. No wildcard targets, address ranges, CIDRs, or raw Nmap argument injection are supported.

On success, reports are created at `<out>/report.json`, `<out>/report.html`, and `<out>/report.md`. On Nmap failure or absence, the tool returns a **nonzero exit status** and preserves any available report data and diagnostics. Treat a clean scan as the absence of observed indicators within the selected profile, **not** proof of security.

The interactive prompt retains `scan`, `nmap`, `doctor`, `status`, `help`, `version`, `exit` and `quit`. Presentation changes are **not** the focus of v0.3.

Read [Nmap integration](nmap-integration.md), [report format](report-format.md), and [installation](windows-installer.md) for details.
