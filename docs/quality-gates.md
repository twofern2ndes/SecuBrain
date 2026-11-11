# SecuBrain v0.4.0 / release verification

The release process uses five reproducible technical checks, each with an
objective passing criterion. These checks apply to the behaviors and environments
covered by the tests; they are not a guarantee of defect-free operation.

| Gate | Purpose | Verification |
|---|---|---|
| 1. Animation and layout | Frames vary over time, remain deterministic for the same tick, show a command prompt at narrow and wide dimensions, and never emit ANSI when disabled | `go test ./internal/ui -run 'TestNeural|TestDashboardLayouts'` |
| 2. Keyboard and safety | History, cursor editing, UTF-8/wide text, paste limit, logs cap, control-character filtering and cancellation shortcuts | `go test ./internal/ui -run 'TestDashboardKeyboard|TestDashboardUnicode|TestDashboardInput|TestWideUnicode'` |
| 3. Engine compatibility | Real local audit invoked through the dashboard bridge writes HTML, Markdown and JSON; unauthorized network arguments still fail | `go test ./internal/cli -run 'TestAnimatedShell'` and existing audit suite |
| 4. Live terminal and responsiveness | Real PTY opens alternate screen, processes multiple commands, executes a local audit, survives resize and restores terminal; render benchmark quantifies cost | `python3 docs/pty_smoke.py`; `go test -run '^$' -bench '^BenchmarkDashboard' -benchmem ./internal/ui` |
| 5. Cross-platform and packaging | Go race/vet, Windows amd64 cross-compilation, Linux/Windows tests, Windows Inno Setup build/install/uninstall smoke | `go test -race ./...`, `go vet ./...`, `GOOS=windows GOARCH=amd64 go build ./cmd/secubrain`, GitHub Actions CI and Windows installer workflow |

A release is considered verified only for the environments and operations
actually covered by passing tests. CI does not test every physical Windows
terminal, font, antivirus product, privilege level or Npcap installation.
