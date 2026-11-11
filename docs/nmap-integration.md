# Nmap integration — SecuBrain v0.3.0

SecuBrain invokes the **real, separately installed Nmap executable** to inventory an explicitly authorized host. The adapter uses Go `os/exec` (no shell), reads bounded XML (`-oX -`), normalizes service metadata, and writes results into the same local JSON, HTML, and Markdown reports as the file/HTTP checks. Nmap is authored and licensed by the Nmap Project, **not** by SecuBrain.

## Requirements

1. Install Nmap independently from [nmap.org/download.html](https://nmap.org/download.html). On Windows, Npcap may be required for privileged features; install it using the official installer as appropriate.
2. Run `secubrain doctor` to check the executable and version. If installed outside standard locations, pass `--nmap-bin "C:\\Nmap\\nmap.exe"` or set `SECUBRAIN_NMAP_PATH`.
3. Obtain explicit written authorization from the host owner and select **one** approved IP address or DNS name. `--authorized` records the operator's assertion but cannot independently verify it.

```powershell
# Non-privileged TCP scan of ~100 common ports
secubrain nmap --target 192.0.2.10 --authorized --nmap-profile quick

# Default profile, ~1000 common TCP ports and richer service probes
secubrain nmap --target 192.0.2.10 --authorized --nmap-profile standard --out C:\\Audits\\host

# All TCP ports 1..65535, with version discovery
secubrain nmap --target 192.0.2.10 --authorized --nmap-profile full --out C:\\Audits\\host-full

# Optional additional probes (may require administrator/root + Npcap)
secubrain nmap --target 192.0.2.10 --authorized --nmap-profile standard --nmap-udp --nmap-os --nmap-scripts

# Combined local source + URL header + Nmap inventory (URL host must match target if specified)
secubrain scan --path ./project --url https://approved.example --nmap --authorized
```

## Profiles and optional features

| Profile | TCP ports | Version intensity | Default execution timeout | Additional options |
|---|---|---|---|---|
| `quick` | Nmap `-F`: ~100 common TCP ports | 2 | 100 seconds | UDP, OS, scripts if enabled |
| `standard` (default) | Nmap default: ~1000 common TCP ports | 5 | 5 minutes | UDP, OS, scripts if enabled |
| `full` | **all 65,535 TCP ports** (`-p-`) | 7 | 20 minutes | UDP, OS, scripts if enabled |

All modes use TCP connect (`-sT`), service/version probing (`-sV`), IPv6 mode (`-6`) when necessary, and a single specified target. They avoid initiating multi-target, CIDR, or file-list scans. Nmap scan rate and retry limits are selected by the adapter, not accepted as raw command flags.

- `--nmap-udp`: requests UDP scanning (`-sU`). For the `full` profile, UDP is limited to **ports 1..1024** while the TCP scan covers ports 1..65535. UDP service identification can be slow or ambiguous (`open|filtered`). Nmap may require elevated privileges.
- `--nmap-os`: requests OS fingerprinting (`-O --osscan-limit --max-os-tries 1`); results are **estimates**, and raw-packet privileges are often necessary.
- `--nmap-scripts`: requests Nmap's **default NSE** script category only (`--script default`). These scripts can generate extra requests and reveal sensitive banners or metadata. This is **off by default**; verify permission and change windows. No arbitrary script or executable content is accepted via the SecuBrain CLI.
- `--nmap-timeout 120s`: overrides the per-host execution timeout, from `15s` up to `30m`. Timeouts do **not** guarantee all ports completed scanning; check warnings/status.

A full TCP scan is **not** equivalent to all features of Nmap or a penetration test. Scripts, UDP, OS detection, network appliances and target behavior can affect what is discovered.

## Output schema and data handling

The `nmap` object in `report.json` contains: status (`completed`, `partial`, `skipped`, `failed`), exact target, profile, mode, Nmap version/source, duration, host count, open TCP/UDP counts, and a `hosts` array. Each host includes status, addresses, DNS names, OS matches, uptime, aggregated closed/filtered counts, and sorted port entries. Individual ports record TCP/UDP, port number, state/reason, service name/product/version/extra information, confidence and method, CPE identifiers, and optionally NSE script IDs and bounded outputs.

Only confirmed `open` ports create **informational** findings. `open|filtered` is retained in the inventory but is **not** counted as open. A port banner or CPE is not a vulnerability assertion; no CVE confirmation or exploitation is performed. At most 1,000 informational port findings are generated; full parsed inventory remains in JSON (within the XML size bound). HTML and Markdown show a smaller operational preview of open/open|filtered ports and refer to JSON for all parsed data.

- Output XML is capped at **24 MiB** to prevent unbounded memory use.
- Data derived from remote services is sanitized and HTML-escaped; arbitrary raw XML is not kept in the reports.
- Privileged scans may fail without adequate permissions or Npcap. Unavailable/failed scans return **nonzero exit status** while preserving a partial report for investigation.
- The application does not stream the target system's collected data to a cloud AI service. Protect local reports as potentially confidential.

## Licensing and installation boundary

The SecuBrain installer includes **SecuBrain only**. Neither Nmap nor Npcap is included or auto-installed. Nmap's [public source license](https://nmap.org/npsl/) and the [Windows/Npcap redistribution restrictions](https://nmap.org/book/man-legal.html) make bundling or repackaging without appropriate rights unsuitable. Official [OEM terms](https://nmap.org/oem/) describe commercial redistribution rights. Users may obtain Nmap separately and use it in accordance with its terms.

## Tests

The Go test suite builds a deterministic **test-only Nmap process double** to validate subprocess execution, argv construction, XML parsing, large-output handling, metadata escaping, report writing, and error states without sending packets.

The `Windows installer / CI and prerelease` GitHub Actions workflow additionally installs a real distribution Nmap **inside its Ubuntu CI runner**, starts a temporary HTTP server bound to **127.0.0.1:80**, runs `secubrain nmap --target 127.0.0.1 --authorized`, and asserts the resulting JSON contains the open port. A separate Windows runner compiles the CLI and Inno Setup installer and smoke-tests installation, `doctor`, and uninstall. These checks are meaningful but not certification across every supported Windows/Nmap/Npcap combination.
