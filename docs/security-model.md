# Threat model, operator obligations, and boundaries

SecuBrain is designed for **bounded, explicitly authorized assessment**. It does not establish permission to test an endpoint and does not independently verify who owns a hostname.

## Security boundaries

1. **Local project scope:** a user-selected directory. The tool does not discover external targets from source or silently expand to related domains.
2. **Remote scope:** an explicitly supplied HTTP(S) endpoint, with an explicit `--authorized` assertion. Remote inspection is opt-in, not a default consequence of local scanning.
3. **HTTP check:** single HEAD request. No redirect following, login, content crawling, request body, exploitation payloads, certificate-validation bypass, or brute force.
4. **Nmap:** opt-in only; single hostname, fixed bounded arguments, no shell interpolation. Reports open TCP ports as observations rather than exploitable findings.
5. **Secrets:** pattern evidence is redacted rather than quoting source values. Report paths, hosts, and timing metadata can nevertheless be sensitive.
6. **Execution:** deterministic Go rules. No LLM, external model provider, arbitrary user-supplied shell command, or remote code execution feature.

## Assumptions & caveats

- A local folder could include sensitive credentials. Run SecuBrain in an environment you trust, then protect reports as you would logs.
- Files and network responses can be adversarial inputs; the test suite covers some escaping and bounds, but a prototype is **not** formally security-reviewed.
- Some requests can be affected by user-controlled proxy environment variables or DNS resolution. Ensure the environment and network route conform to the approved scope.
- A target can change between the review and the scan. Authorization must remain valid at execution time.
- Flags may produce a partial report if an optional adapter fails. Read `warnings` and `checks`.
- Source findings and policy recommendations are not substitutes for a professional security assessment.

## Reporting security vulnerabilities in SecuBrain

Do not publish working exploit details or private tokens in public issues. Read [`../SECURITY.md`](../SECURITY.md). Report a concise impact summary, affected version, controlled reproduction, and remediation ideas through a private channel when available.

## Windows installer security boundary

The SecuBrain installer does not bundle Nmap or Npcap. The installer presents project terms, explicit acceptance and an optional external Nmap download link. The setup uses per-user installation by default; it does not require administrator privileges. Source license selection is separate from the installation terms. The project does not claim its liability limitations can override mandatory applicable law.

## Optional Nmap adapter (v0.2)

The operator must provide an authorized URL and opt in via `--authorized --nmap`; no scanning begins automatically. The argument set is a fixed allowlist: TCP connect, 100 common ports, light version detection, conservative timing, a rate ceiling, and a host timeout. No command shell, arbitrary flags or NSE scripts are invoked. Results are parsed from XML and encoded/escaped into reports. A best-effort service version may be wrong and is not proof of a vulnerability.
