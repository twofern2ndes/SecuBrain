# Windows installation / v0.4.0

This page describes the **official SecuBrain installer build** (Windows x64, unprivileged per-user installation). It does **not** install Nmap or Npcap: these tools are under separate licenses and must be obtained independently.

## Obtain the installer

1. Open [SecuBrain releases](https://github.com/twofern2ndes/SecuBrain/releases/tag/v0.4.0).
2. Download the asset named `SecuBrain-Setup-v0.4.0-windows-x64.exe` from the prerelease, if published.
3. Download `SHA256SUMS.txt` and compare the SHA-256 value against your downloaded executable.
4. Launch the installer and follow the guided setup.

The installer is currently **not code-signed**. Windows SmartScreen may display an unknown publisher warning. That is not proof the binary is safe; validate its hash, inspect the published code and CI provenance, and use only downloads you trust. Never suppress security features just to run an unfamiliar installer.

## Installer wizard — screens and effects

| Page | Purpose | Required? |
| :--- | :--- | :---: |
| Welcome | Shows package name/version and publisher | Automatic |
| Installation notes | Explains audit operation, limitations and optional Nmap | Read |
| License and acceptable use | Full scrollable agreement, `I accept` / `I do not accept` | **Accept** |
| Destination | Choose per-user install directory | Select |
| Tasks | Optional user PATH entry and desktop shortcut | Optional |
| Nmap integration | Explanation and official external download button | Optional |
| Ready to install | Final summary of selected options | Review |
| Installing | Native installer progress bar for extracting/copying files | Automatic |
| Finish | Optional launch CLI and Nmap official download page | Optional |

**Default install directory:** `%LOCALAPPDATA%\Programs\SecuBrain` (no elevation requested). The installer creates shortcuts and, when selected, adds only its own directory to the **current user's** PATH. Uninstall removes the installed files and matching PATH entry. The installer does not remove independently installed Nmap or user-created reports.

The `.exe` contains the SecuBrain executable, legal notices, README, and selected documentation. It contains **no Nmap/Npcap binaries or embedded installation packages**.

## Nmap detection on Windows

After installing Nmap separately through its official installer:

```powershell
secubrain doctor
secubrain scan --url https://your-authorized-host.example --authorized --nmap
```

The application checks `PATH`, then common Nmap locations under `%ProgramFiles%`, `%ProgramFiles(x86)%`, and `%LOCALAPPDATA%`. Override if you installed to another location:

```powershell
secubrain doctor --nmap-bin "C:\Tools\Nmap\nmap.exe"
secubrain scan --url https://your-authorized-host.example --authorized --nmap --nmap-bin "C:\Tools\Nmap\nmap.exe"
```

### Why doesn't setup install Nmap automatically?

Nmap's free license and the separate Npcap license impose redistribution restrictions, including restrictions relevant to some installers that fetch third-party packages. The SecuBrain project has not acquired Nmap OEM redistribution rights. See [Nmap's legal notice](https://nmap.org/book/man-legal.html), [NPSL](https://nmap.org/npsl/), and [Nmap OEM](https://nmap.org/oem/). Installing Nmap independently is the transparent, license-respecting path.

## For maintainers: building the installer

Requirements:

- Windows x64
- Go >= 1.23
- Inno Setup 6 (ISCC compiler)

```powershell
# Run from repository root
New-Item -ItemType Directory -Force dist | Out-Null
go test -count=1 ./...
go vet ./...
go build -trimpath -ldflags "-s -w" -o dist\secubrain.exe ./cmd/secubrain
& "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" installer\SecuBrain.iss
```

The output is written to `dist/SecuBrain-Setup-v0.4.0-windows-x64.exe`.

A GitHub Actions Windows runner executes the test suite, compiles the CLI, invokes Inno Setup, performs an unattended **CI-only** installation smoke test, calculates a SHA-256 checksum and uploads the installer artifact. Silent CI installation is for automated verification; interactive installation normally displays the full acceptance page.

### Limitations

- Windows 10/11 x64 only; other operating systems can build the CLI from Go source.
- Code signing and independent security review are not included in v0.4.0.
- Application tests use a fake Nmap executable with verified fixed arguments; this does not prove network scan reliability in every environment.
- SecuBrain cannot verify that you legally own or administer a target. Authorization is the operator's responsibility.

## Troubleshooting

**Command not found after install:** open a new PowerShell window and run `secubrain doctor`. Existing shells may not see updated user PATH immediately. Alternatively run the Start Menu shortcut.

**Nmap unavailable:** install from https://nmap.org/download.html and check `secubrain doctor`. Specify `--nmap-bin` for a nonstandard installation.

**Endpoint detection returns no findings:** no open TCP ports were observed in the bounded common-port scan. This is not proof that the system is secure.

**Third-party anti-malware alert:** do not disable security software automatically. Verify the downloaded artifact and review the source; report potential issues to project maintainers.

## Terminal changes in v0.4

The same installed `secubrain.exe` now presents the animated neural dashboard when launched in a supported Windows console with interactive input. It falls back to the regular prompt for redirected input or incompatible consoles. No extra GUI runtime, browser, cloud account or AI model is required. See [terminal experience](terminal-experience.md).

## Changes in v0.3

The Nmap wizard page now detects typical local Nmap installation paths and
explains the available scan modes. It does not silently install third-party
software. User PATH modifications are tracked in the installer registry so
uninstallation does not remove a pre-existing entry owned by another program.
Use `secubrain doctor` after installing Nmap to check the actual binary.

For a full TCP scan on a host you own:

```powershell
secubrain nmap --target 192.0.2.10 --authorized --nmap-profile full --out C:\Audits\host
```
