# SecuBrain report format — v0.3.0

Every completed audit writes three related representations to the requested local output directory:

- `report.json` — **canonical machine-readable record**, including all parsed Nmap hosts/ports within resource limits.
- `report.html` — self-contained, HTML-escaped human-readable summary of findings and Nmap service inventory.
- `report.md` — concise text report with port table and discoveries for review or versioned internal records.

The JSON document has top-level `tool`, `version`, `started_at`, `finished_at`, optional `path`, `url`, and `target`, `stats`, `findings`, `warnings`, `checks`, and optional `nmap`.

`findings[]` entries contain a stable reference `id`, `severity` (`high`, `medium`, `low`, `info`), `category`, `title`, `description`, `evidence`, optional `location`/`line`, and `recommendation`. Potential secrets are represented as redacted indicators, not matched credential strings.

## Nmap inventory

`nmap` contains:

```json
{
  "status": "completed",
  "target": "127.0.0.1",
  "profile": "standard",
  "mode": "TCP connect + service/version detection",
  "version": "Nmap fixture 0.3.0 (test executable)",
  "duration_ms": 15,
  "open_tcp_ports": 1,
  "open_udp_ports": 0,
  "hosts_up": 1,
  "binary_source": "explicit override",
  "hosts": [
    {
      "status": "up", "addresses": ["127.0.0.1"],
      "ports": [
        {"protocol":"tcp", "number":443, "state":"open", "service":"https", "product":"Fixture Web", "version":"1.2.3"}
      ],
      "extra_port_states":{"filtered":98}
    }
  ]
}
```

This is an **illustrative synthetic fixture**, not a real network result. The complete schema may also contain host reason, hostnames, `os_matches` (name/accuracy), `uptime_seconds`, port reason, `extra_info`, `tunnel`, `method`, `confidence`, `cpe` and `scripts` (NSE ID and sanitized output). Port list includes all Nmap-explicitly-reported states; `extra_port_states` reflects aggregated Nmap XML counts, not enumerated port detail.

A completed scan can return zero open ports. `partial` means Nmap exited unsuccessfully but returned parseable XML. `skipped` means the requested tool could not be located; `failed` means no trustworthy complete result was obtained. **Any status other than completed yields a nonzero CLI exit code**, although partial reports are saved.

Informational findings are emitted only for explicitly reported `open` ports, not for closed, filtered or ambiguous `open|filtered` states. The finding count is capped at 1,000 even when structured inventory contains more. HTML/Markdown may cap port previews at 500; use JSON for complete normalized parsed data.

## Data security and compatibility

Potentially confidential paths, hostnames, service versions, OS guesses and script output are stored locally. Review and sanitize before sharing. HTML uses Go `html/template`; Markdown normalizes control characters, line breaks and table separators. Output values are evidence/observations, **not** CVE validation, regulatory compliance assurance or proof of exploitability.

The schema may evolve until a stable release. JSON consumers should tolerate additional fields and partial/empty nested data.
