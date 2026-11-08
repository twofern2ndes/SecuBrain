# Nmap adapter / technical design

SecuBrain v0.2.0 can invoke a **separately installed** Nmap executable. The integration performs a bounded TCP connect scan and low-intensity service identification on **one hostname** extracted from an explicitly authorized HTTP(S) URL.

## Preconditions

1. The operator has permission to assess the exact target.
2. The `--url` input is a clean HTTP(S) URL without credentials, query parameters, or fragments.
3. `--authorized` is provided explicitly.
4. `--nmap` opts in to network discovery.
5. An Nmap executable is available on PATH, in a standard Windows folder, or via `--nmap-bin` / `SECUBRAIN_NMAP_PATH`.

## Fixed argument allowlist

SecuBrain invokes Nmap through Go's `exec.CommandContext` with **separate arguments**, never through a shell:

```text
-sT -sV --version-light -Pn -F -T2 --max-rate 25 --max-retries 1 --host-timeout 80s --open -oX - <exact-hostname>
```

| Argument | Meaning |
| :--- | :--- |
| `-sT` | TCP connect scan (does not require raw SYN packet privileges) |
| `-sV --version-light` | Limited version probing on discovered ports |
| `-Pn` | Do not use separate host discovery before port checks |
| `-F` | Fast set of Nmap's common ports (not all 65,535 ports) |
| `-T2 --max-rate 25` | Conservative timing and rate cap |
| `--max-retries 1` | Lower probe retry count |
| `--host-timeout 80s` | Upper Nmap per-host time bound |
| `--open` | Show only open port results |
| `-oX -` | XML output through stdout (not untrusted text parsing) |

The outer Go process also has a 95-second deadline. Neither these options nor the operator's authorization guarantee zero operational impact. Nmap probing may still affect sensitive systems; obtain approval and schedule a suitable maintenance window.

## Parsing and results

SecuBrain parses the Nmap XML response using `encoding/xml`, recognizes open **TCP** ports, and adds informational findings containing service names and best-effort product/version labels. Output is sanitized and limited in length, and HTML reports escape target-supplied strings.

The JSON report also contains a `nmap` object with the status (`completed`, `skipped`, or `failed`), target, scan mode, version, duration, observed open TCP count, and binary discovery method. It does not include raw XML or claim open ports are exploitable vulnerabilities.

## Error behavior

- Missing Nmap or bad `--nmap-bin`: warning plus `nmap.status=skipped`; local and HTTP checks continue.
- Missing authorization or invalid URL: input validation error **before** executing checks.
- Nmap failure or timeout: warning plus `nmap.status=failed`; no fabricated findings.
- Malformed XML: warning plus `nmap.status=failed`.
- Valid XML with no open TCP ports: completed scan with zero findings; **not a safety certification**.

## What's intentionally out of scope

No NSE scripts, OS fingerprinting, UDP sweeps, large target lists, wildcard CIDRs, stealth scanning, exploit execution, brute force, credential tests or escalation. The adapter does not offer arbitrary Nmap flags.

## Third-party rights

SecuBrain ships **no Nmap/Npcap binary** and is not endorsed by their maintainers. For redistribution requirements, read [Nmap licensing](https://nmap.org/npsl/) and [Npcap redistribution limitations](https://nmap.org/book/man-legal.html).

## Tests

`internal/audit/nmap_integration_test.go` builds a small test-only Go executable that mimics Nmap's `--version` and XML response. It validates the exact argv allowlist, parsing, discovery metadata, report output escaping, missing-binary behavior and safe error reporting. This deterministic fixture sends **no network packets**; it is not a replacement for an authorized real-world compatibility test.
