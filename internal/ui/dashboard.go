package ui

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// CommandHandler is intentionally an adapter: the UI has no knowledge of
// network scanning, external tools, or privilege requirements.
type CommandHandler func(ctx context.Context, command string, emit func(string)) int

type logEntry struct{ kind, text string }
type dashboardEvent struct {
	kind, text string
	code       int
}

type Dashboard struct {
	Version       string
	Color         bool
	Motion        bool
	Width, Height int
	Tick          uint64
	Input         []rune
	Cursor        int
	Logs          []logEntry
	History       []string
	historyAt     int
	Busy          bool
	ActiveCommand string
	Status        string
	lastCode      int
	escState      int
	utf8Pending   []byte
	lastFrame     string
}

func NewDashboard(version string, color, motion bool, width, height int) *Dashboard {
	d := &Dashboard{Version: version, Color: color, Motion: motion, Width: width, Height: height, Status: "READY", historyAt: 0}
	d.addLog("ok", "Engine ready · offline-first · no AI dependency")
	d.addLog("info", "Enter help to see commands, or try doctor")
	return d
}

func (d *Dashboard) addLog(kind, message string) {
	for _, line := range strings.Split(message, "\n") {
		line = sanitizeTerminalLine(line)
		if line == "" {
			continue
		}
		d.Logs = append(d.Logs, logEntry{kind: kind, text: line})
	}
	if len(d.Logs) > 160 {
		d.Logs = append([]logEntry(nil), d.Logs[len(d.Logs)-160:]...)
	}
}

func sanitizeTerminalLine(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r < 32 || r == 127) && r != '\t' {
			continue
		}
		if r == '\t' {
			b.WriteString("  ")
			continue
		}
		if !unicode.IsPrint(r) {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 800 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func (d *Dashboard) setInput(s string)   { d.Input = []rune(s); d.Cursor = len(d.Input) }
func (d *Dashboard) inputString() string { return string(d.Input) }

// ApplyByte is a small, bounded keyboard parser. Arrow keys and Delete are
// interpreted only as input editing, never as shell escape sequences.
// Returns one of: "", "submit", "exit", "cancel", "clear".
func (d *Dashboard) ApplyByte(c byte) string {
	if d.escState == 1 {
		if c == '[' || c == 'O' {
			d.escState = 2
			return ""
		}
		d.escState = 0
		if c == 27 {
			return ""
		}
		return d.ApplyByte(c)
	}
	if d.escState == 2 {
		d.escState = 0
		switch c {
		case 'A':
			d.historyUp()
		case 'B':
			d.historyDown()
		case 'C':
			if d.Cursor < len(d.Input) {
				d.Cursor++
			}
		case 'D':
			if d.Cursor > 0 {
				d.Cursor--
			}
		case 'H':
			d.Cursor = 0
		case 'F':
			d.Cursor = len(d.Input)
		case '3':
			d.escState = 3
		}
		return ""
	}
	if d.escState == 3 {
		d.escState = 0
		if c == '~' && d.Cursor < len(d.Input) {
			d.Input = append(d.Input[:d.Cursor], d.Input[d.Cursor+1:]...)
		}
		return ""
	}
	if c == 27 {
		d.escState = 1
		return ""
	}
	switch c {
	case 3:
		return "cancel"
	case 4:
		if len(d.Input) == 0 {
			return "exit"
		}
		return ""
	case 12:
		return "clear"
	case '\r', '\n':
		return "submit"
	case 127, 8:
		if d.Cursor > 0 {
			d.Input = append(d.Input[:d.Cursor-1], d.Input[d.Cursor:]...)
			d.Cursor--
		}
		return ""
	case 1:
		d.Cursor = 0
		return ""
	case 5:
		d.Cursor = len(d.Input)
		return ""
	case 21:
		d.setInput("")
		return ""
	case 9:
		d.autoComplete()
		return ""
	}
	if c < 32 {
		return ""
	}
	d.utf8Pending = append(d.utf8Pending, c)
	if len(d.utf8Pending) > 4 {
		d.utf8Pending = nil
		return ""
	}
	if !utf8.FullRune(d.utf8Pending) {
		return ""
	}
	r, sz := utf8.DecodeRune(d.utf8Pending)
	d.utf8Pending = d.utf8Pending[sz:]
	if r == utf8.RuneError || !unicode.IsPrint(r) || len(d.Input) >= 2048 {
		return ""
	}
	d.Input = append(d.Input, 0)
	copy(d.Input[d.Cursor+1:], d.Input[d.Cursor:])
	d.Input[d.Cursor] = r
	d.Cursor++
	return ""
}

func (d *Dashboard) historyUp() {
	if len(d.History) == 0 {
		return
	}
	if d.historyAt > 0 {
		d.historyAt--
	}
	d.setInput(d.History[d.historyAt])
}
func (d *Dashboard) historyDown() {
	if d.historyAt < len(d.History) {
		d.historyAt++
	}
	if d.historyAt == len(d.History) {
		d.setInput("")
	} else {
		d.setInput(d.History[d.historyAt])
	}
}
func (d *Dashboard) autoComplete() {
	if strings.ContainsAny(d.inputString(), " \t") {
		return
	}
	choices := []string{"scan", "nmap", "doctor", "status", "history", "help", "version", "clear", "exit"}
	prefix := d.inputString()
	for _, choice := range choices {
		if strings.HasPrefix(choice, prefix) && prefix != "" {
			d.setInput(choice + " ")
			return
		}
	}
}

func (d *Dashboard) Submit() string {
	cmd := strings.TrimSpace(d.inputString())
	d.setInput("")
	if cmd == "" {
		return ""
	}
	if len(d.History) == 0 || d.History[len(d.History)-1] != cmd {
		d.History = append(d.History, cmd)
	}
	if len(d.History) > 60 {
		d.History = d.History[len(d.History)-60:]
	}
	d.historyAt = len(d.History)
	d.addLog("command", "❯ "+cmd)
	return cmd
}

func (d *Dashboard) emitColor(code, txt string) string {
	if !d.Color {
		return txt
	}
	return "\x1b[" + code + "m" + txt + "\x1b[0m"
}

// runeColumns estimates terminal cell width for common Unicode characters.
// It avoids terminal overflow when users paste Hangul, CJK, or emoji commands.
func runeColumns(r rune) int {
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
		return 0
	}
	if r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
		(r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0xfe10 && r <= 0xfe19) ||
		(r >= 0xfe30 && r <= 0xfe6f) ||
		(r >= 0xff00 && r <= 0xff60) ||
		(r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x1f300 && r <= 0x1faff) ||
		(r >= 0x20000 && r <= 0x3fffd)) {
		return 2
	}
	return 1
}
func displayColumns(s string) int {
	n := 0
	for _, r := range s {
		n += runeColumns(r)
	}
	return n
}
func dashboardFit(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if displayColumns(s) <= width {
		return s
	}
	var b strings.Builder
	columns := 0
	for _, r := range s {
		rw := runeColumns(r)
		if columns+rw > width-1 {
			break
		}
		b.WriteRune(r)
		columns += rw
	}
	b.WriteRune('…')
	return b.String()
}
func (d *Dashboard) renderLog(row logEntry, width int) string {
	sym, code := "·", "38;5;247"
	switch row.kind {
	case "ok":
		sym, code = "✓", "38;5;120"
	case "error":
		sym, code = "×", "38;5;203"
	case "warn":
		sym, code = "!", "38;5;221"
	case "command":
		sym, code = "❯", "38;5;81"
	case "progress":
		sym, code = "↳", "38;5;110"
	}
	s := dashboardFit(row.text, width-4)
	return "  " + d.emitColor(code, sym) + " " + s
}

// RenderFrame renders an entire terminal frame without side effects. It can be
// snapshot-tested without a TTY, animations, sockets, or sleeping.
func (d *Dashboard) RenderFrame() string {
	w, h := d.Width, d.Height
	if w < 34 {
		w = 34
	}
	if w > 200 {
		w = 200
	}
	if h < 10 {
		h = 10
	}
	if h > 80 {
		h = 80
	}
	inner := w - 4
	top := "  ╭" + strings.Repeat("─", inner) + "╮"
	bottom := "  ╰" + strings.Repeat("─", inner) + "╯"

	c := d.emitColor
	lines := make([]string, 0, h)
	lines = append(lines, c("38;5;67", top))
	header := fmt.Sprintf("  ◈ SECUBRAIN / v%s", d.Version)
	if w < 65 {
		header = " ◈ SECUBRAIN"
	}
	tail := "  ◉ " + d.Status
	if d.Busy {
		tail = "  ◉ RUNNING"
	}
	padding := inner - len([]rune(header)) - len([]rune(tail))
	if padding < 1 {
		padding = 1
	}
	lines = append(lines, "  │"+c("1;38;5;159", header)+strings.Repeat(" ", padding)+c("38;5;120", tail)+"│")
	lines = append(lines, c("38;5;67", bottom))
	compact := w < 65 || h < 23
	if h >= 14 && !compact {
		neurons := NeuralFrame(d.Tick, d.Color)
		for _, line := range neurons {
			lines = append(lines, strings.Repeat(" ", maxInt(0, (w-42)/2))+line)
		}
		lines = append(lines, c("38;5;110", strings.Repeat(" ", maxInt(0, (w-29)/2))+neuralCaption(d.Tick, d.Busy)))
	} else if h >= 14 {
		lines = append(lines, c("1;38;5;81", "    ◈  NEURAL ENGINE"), c("38;5;244", dashboardFit("    Local-first  ·  Deterministic  ·  No AI", w)))
	}
	if h >= 17 {
		title := "  ── WORKSPACE " + strings.Repeat("─", maxInt(0, w-18))
		lines = append(lines, c("38;5;67", dashboardFit(title, w)))
		if w >= 82 && h >= 28 {
			lines = append(lines, c("38;5;110", "  SCAN / scan --path ./project     NETWORK / nmap --target HOST --authorized"))
			lines = append(lines, c("38;5;110", "  TOOLS / doctor                 GUIDE / help             EXIT / exit"))
		} else {
			lines = append(lines, c("38;5;110", dashboardFit("  scan   ·   nmap   ·   doctor   ·   help   ·   exit", w)))
		}
	}
	activity := "  ── ACTIVITY " + strings.Repeat("─", maxInt(0, w-17))
	lines = append(lines, c("38;5;67", dashboardFit(activity, w)))
	// Activity shrinks to accommodate small terminals. Reserve four rows for
	// the command prompt and help footer.
	avail := h - len(lines) - 3
	if avail < 1 {
		avail = 1
	}
	if avail > 12 {
		avail = 12
	}
	start := len(d.Logs) - avail
	if start < 0 {
		start = 0
	}
	for _, entry := range d.Logs[start:] {
		lines = append(lines, d.renderLog(entry, w))
	}
	for len(lines) < h-3 {
		lines = append(lines, "")
	}
	lines = append(lines, c("38;5;67", "  ╭─ COMMAND "+strings.Repeat("─", maxInt(0, w-15))))
	visibleInput := d.Input
	commandWidth := w - 10
	if commandWidth < 2 {
		commandWidth = 2
	}
	offset := d.Cursor
	cells := 0
	for offset > 0 {
		width := runeColumns(visibleInput[offset-1])
		if cells+width >= commandWidth {
			break
		}
		cells += width
		offset--
	}
	end := offset
	used := 0
	for end < len(visibleInput) {
		width := runeColumns(visibleInput[end])
		if used+width > commandWidth {
			break
		}
		used += width
		end++
	}
	cursor := d.Cursor - offset
	if cursor < 0 {
		cursor = 0
	}
	shown := visibleInput[offset:end]
	if cursor > len(shown) {
		cursor = len(shown)
	}
	caret := " "
	if cursor < len(shown) {
		caret = string(shown[cursor])
	}
	endCursor := cursor
	if cursor < len(shown) {
		endCursor++
	}
	inputDisplay := string(shown[:cursor]) + c("7", caret) + string(shown[endCursor:])
	lines = append(lines, "  "+c("1;38;5;81", "❯")+"  "+inputDisplay)
	footer := "  Enter: run   ↑↓: history   Tab: complete   Ctrl+C: cancel   Ctrl+D: exit"
	lines = append(lines, c("38;5;244", dashboardFit(footer, w)))
	if len(lines) > h {
		lines = lines[:h]
	}
	return strings.Join(lines, "\r\n")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// StartDashboard enters a dedicated alternate screen only for real interactive
// terminals. Piped use and CI remain plain and deterministic.
func StartDashboard(ctx context.Context, input, output *os.File, version string, handler CommandHandler) (int, bool) {
	if input == nil || output == nil || os.Getenv("SECUBRAIN_PLAIN") != "" || os.Getenv("TERM") == "dumb" || os.Getenv("CI") != "" {
		return 0, false
	}
	stat, err := output.Stat()
	if err != nil || stat.Mode()&os.ModeCharDevice == 0 {
		return 0, false
	}
	terminal := New(output)
	if !terminal.Color {
		return 0, false
	}
	restore, ok := enterRawInput(input)
	if !ok {
		return 0, false
	}
	defer restore()
	w, h := terminalDimensions(output)
	d := NewDashboard(version, os.Getenv("NO_COLOR") == "", os.Getenv("SECUBRAIN_NO_ANIM") == "" && os.Getenv("SECUBRAIN_REDUCED_MOTION") == "", w, h)
	fmt.Fprint(output, "\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J")
	defer fmt.Fprint(output, "\x1b[0m\x1b[?25h\x1b[?1049l")
	inputCh := make(chan []byte, 16)
	events := make(chan dashboardEvent, 128)
	stopInput := make(chan struct{})
	defer close(stopInput)
	go func() {
		buf := make([]byte, 128)
		for {
			n, e := input.Read(buf)
			if n > 0 {
				chunk := append([]byte(nil), buf[:n]...)
				select {
				case inputCh <- chunk:
				case <-stopInput:
					return
				}
			}
			if e != nil {
				select {
				case inputCh <- nil:
				case <-stopInput:
				}
				return
			}
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	if !d.Motion {
		ticker.Reset(time.Hour)
	}
	defer ticker.Stop()
	var cancel context.CancelFunc
	var lastScan string
	redraw := func() error {
		width, height := terminalDimensions(output)
		if width != d.Width || height != d.Height {
			d.Width, d.Height = width, height
		}
		frame := d.RenderFrame()
		if frame == d.lastFrame {
			return nil
		}
		d.lastFrame = frame
		_, e := io.WriteString(output, "\x1b[H\x1b[0J"+frame)
		return e
	}
	if err := redraw(); err != nil {
		return 1, true
	}
	launch := func(command string) {
		switch command {
		case "exit", "quit":
			d.Status = "EXIT"
			return
		case "clear":
			d.Logs = nil
			d.addLog("info", "Activity cleared")
			return
		case "history":
			for _, h := range d.History {
				d.addLog("info", h)
			}
			return
		case "status":
			if lastScan == "" {
				d.addLog("info", "No scan completed in this session")
			} else {
				d.addLog("ok", "Last successful scan: "+lastScan)
			}
			return
		}
		if d.Busy {
			d.addLog("warn", "A command is running. Ctrl+C cancels it.")
			return
		}
		runCtx, c := context.WithCancel(ctx)
		cancel = c
		d.Busy = true
		d.Status = "RUNNING"
		d.ActiveCommand = command
		go func() {
			code := handler(runCtx, command, func(msg string) {
				select {
				case events <- dashboardEvent{kind: "progress", text: msg}:
				default:
				}
			})
			// Always deliver completion, even if several progress events were
			// dropped under pressure. Cancellation comes from UI only.
			select {
			case events <- dashboardEvent{kind: "done", text: command, code: code}:
			case <-ctx.Done():
			}
		}()
	}
	for {
		select {
		case <-ctx.Done():
			if cancel != nil {
				cancel()
			}
			return 0, true
		case <-ticker.C:
			d.Tick++
		case bytes, ok := <-inputCh:
			if !ok || bytes == nil {
				if cancel != nil {
					cancel()
				}
				return 0, true
			}
			for _, b := range bytes {
				action := d.ApplyByte(b)
				switch action {
				case "cancel":
					if cancel != nil && d.Busy {
						cancel()
						d.addLog("warn", "Cancellation requested")
					} else {
						d.setInput("")
					}
				case "clear":
					d.Logs = nil
				case "exit":
					if !d.Busy {
						return 0, true
					} else {
						d.addLog("warn", "Cancel running command first")
					}
				case "submit":
					cmd := d.Submit()
					if cmd == "" {
						break
					}
					if cmd == "exit" || cmd == "quit" {
						if !d.Busy {
							return 0, true
						}
						d.addLog("warn", "Cancel running command first")
						break
					}
					launch(cmd)
				}
			}
		case event := <-events:
			switch event.kind {
			case "progress":
				d.addLog("progress", event.text)
			case "done":
				if cancel != nil {
					cancel()
					cancel = nil
				}
				d.Busy = false
				d.lastCode = event.code
				if event.code == 0 {
					d.Status = "READY"
					if strings.HasPrefix(event.text, "scan ") || strings.HasPrefix(event.text, "nmap ") {
						lastScan = event.text
					}
					d.addLog("ok", "Command finished successfully")
				} else {
					d.Status = "ATTENTION"
					d.addLog("error", fmt.Sprintf("Command exited with status %d", event.code))
				}
			}
		}
		if err := redraw(); err != nil {
			if cancel != nil {
				cancel()
			}
			return 1, true
		}
	}
}
