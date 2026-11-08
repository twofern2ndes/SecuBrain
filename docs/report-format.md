# Report data format (prototype)

Each successful run creates `report.html`, `report.md`, and `report.json` in the configured report directory. The files represent the same audit; Markdown and HTML are intended for review, JSON for downstream tools.

## JSON top-level fields

| Property | Type | Description |
|---|---|---|
| `tool` | string | `SecuBrain` |
| `version` | string | Tool version (`0.1.0`) |
| `started_at`, `finished_at` | RFC3339 timestamps | UTC execution window |
| `path` | string, optional | Local absolute project directory |
| `url` | string, optional | User-supplied endpoint |
| `stats` | object | Counts and inspected file/byte totals |
| `findings` | array | Sorted detected indicators |
| `warnings` | array of strings | Partial/incomplete check information |
| `checks` | array of strings | Enabled checks performed or attempted |

## Finding properties

- `id`: short deterministic identifier, for example `SB-9645B30E`.
- `severity`: `high`, `medium`, `low`, or `info`.
- `category`: rule family, e.g. `credentials`, `repository`, `web-hardening`, or `network-discovery`.
- `title` and `description`: explanation of the indicator.
- `evidence`: a generic statement, **not** a secret string or raw source line.
- `location`: file-relative path or endpoint/host indicator.
- `line`: optional line number for local source findings.
- `recommendation`: review or mitigation suggestion.

See [`samples/demo-report.json`](samples/demo-report.json) for a sanitized fixture result generated from the local demo. The sample is not evidence of a breach or a production vulnerability.

## Reading result severity correctly

`high` means the scanner treats the matched pattern as potentially significant, not that exploitation is confirmed. Header omissions are often deployment-specific. An observed TCP port is informational. Missing findings means no triggered rule within scan limits, **not** security validation.

## Privacy and stable use

Do not publish reports about confidential project paths, hosts, or internal topology. The output folder is ignored by the repository's `.gitignore`; keep the same hygiene in downstream CI logs. The JSON structure is a prototype interface and may change before a stable release. Downstream consumers should tolerate unknown fields and missing optional properties.
