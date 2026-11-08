# Security policy

SecuBrain is an early prototype. It is **not** certified, independently audited, or guaranteed to find vulnerabilities.

## Supported versions

| Version | Status |
|---|---|
| 0.1.x | Prototype; best-effort fixes |
| Earlier versions | Not supported |

## Responsible disclosure

If you find a security issue **in SecuBrain**, prefer GitHub's private vulnerability reporting when it is enabled for this repository (repository **Security → Advisories → Report a vulnerability**). If unavailable, contact the maintainer privately through an appropriate channel listed on their GitHub profile. Do **not** post exploit steps, keys, target details, or sensitive reports in a public issue.

Please include an impact summary, affected version/commit, minimal synthetic reproduction, and suggested mitigation. There is no guaranteed response SLA.

For feature requests or ordinary bugs that do not expose sensitive security details, use GitHub Issues.

## Operator responsibility

Run remote audits only with authorization; the `--authorized` flag expresses user confirmation and does not independently validate ownership. Audit reports may contain confidential paths and domains and should be stored and shared accordingly.
