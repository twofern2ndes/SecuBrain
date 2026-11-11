package ui

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)

func stripANSI(s string) string { return ansiPattern.ReplaceAllString(s, "") }

func TestNeuralFrameDeterminismAndMotion(t *testing.T) {
	a, b := NeuralFrame(0, false), NeuralFrame(0, false)
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Fatal("same tick must have identical neural visual")
	}
	if len(a) < 9 {
		t.Fatalf("neural frame too small: %d", len(a))
	}
	for tick := uint64(0); tick < 200; tick++ {
		frame := NeuralFrame(tick, false)
		if len(frame) != len(a) {
			t.Fatal("canvas height changed")
		}
		for _, line := range frame {
			if strings.Contains(line, "\x1b") || len([]rune(line)) > 42 {
				t.Fatalf("bad plain neural frame: %q", line)
			}
		}
	}
	if strings.Join(a, "\n") == strings.Join(NeuralFrame(30, false), "\n") {
		t.Fatal("neural pulses never move")
	}
	colored := strings.Join(NeuralFrame(18, true), "\n")
	if !strings.Contains(colored, "\x1b[38;5;") || stripANSI(colored) != strings.Join(NeuralFrame(18, false), "\n") {
		// Colored frames preserve visible symbols, but use ANSI around them.
		t.Fatal("colored and plain neural frames diverged")
	}
}

func TestDashboardKeyboardHistoryEditingAndCompletion(t *testing.T) {
	d := NewDashboard("0.4.0", false, true, 100, 38)
	for _, c := range []byte("sc") {
		d.ApplyByte(c)
	}
	d.ApplyByte('\t')
	if d.inputString() != "scan " {
		t.Fatalf("tab completion: %q", d.inputString())
	}
	for _, c := range []byte("abc") {
		d.ApplyByte(c)
	}
	d.ApplyByte(27)
	d.ApplyByte('[')
	d.ApplyByte('D')
	d.ApplyByte('Z')
	if d.inputString() != "scan abZc" {
		t.Fatalf("cursor insertion: %q", d.inputString())
	}
	d.ApplyByte(127)
	if d.inputString() != "scan abc" {
		t.Fatalf("backspace: %q", d.inputString())
	}
	if d.ApplyByte('\r') != "submit" {
		t.Fatal("Enter did not submit")
	}
	if cmd := d.Submit(); cmd != "scan abc" {
		t.Fatalf("submission: %q", cmd)
	}
	d.ApplyByte(27)
	d.ApplyByte('[')
	d.ApplyByte('A')
	if d.inputString() != "scan abc" {
		t.Fatalf("history up: %q", d.inputString())
	}
	d.ApplyByte(27)
	d.ApplyByte('[')
	d.ApplyByte('B')
	if d.inputString() != "" {
		t.Fatal("history down should clear")
	}
	if d.ApplyByte(4) != "exit" {
		t.Fatal("ctrl+d must request exit")
	}
	if d.ApplyByte(3) != "cancel" {
		t.Fatal("ctrl+c must request cancellation")
	}
}

func TestDashboardUnicodeInputAndBoundedPaste(t *testing.T) {
	d := NewDashboard("0.4.0", false, true, 85, 28)
	for _, b := range []byte("coração") {
		d.ApplyByte(b)
	}
	if d.inputString() != "coração" {
		t.Fatalf("UTF-8 input: %q", d.inputString())
	}
	for i := 0; i < 10000; i++ {
		d.ApplyByte('x')
	}
	if len(d.Input) != 2048 {
		t.Fatalf("input length not capped: %d", len(d.Input))
	}
	if !strings.Contains(d.RenderFrame(), "COMMAND") {
		t.Fatal("prompt missing")
	}
}

func TestDashboardLayoutsAndNoColor(t *testing.T) {
	dims := [][2]int{{34, 10}, {40, 14}, {55, 20}, {64, 23}, {80, 24}, {100, 30}, {120, 40}, {190, 70}}
	for _, dim := range dims {
		t.Run(fmt.Sprintf("%dx%d", dim[0], dim[1]), func(t *testing.T) {
			d := NewDashboard("0.4.0", false, true, dim[0], dim[1])
			d.addLog("progress", "100% ready · 127.0.0.1/32")
			rendered := d.RenderFrame()
			if strings.Contains(rendered, "\x1b") {
				t.Fatal("ANSI output in no-color mode")
			}
			lines := strings.Split(rendered, "\r\n")
			if len(lines) > dim[1] {
				t.Fatalf("overflowed terminal height: %d > %d", len(lines), dim[1])
			}
			if !strings.Contains(rendered, "SECUBRAIN") || !strings.Contains(rendered, "COMMAND") {
				t.Fatalf("header or prompt cut off: %q", rendered)
			}
			for n, line := range lines {
				if len([]rune(line)) > dim[0] {
					t.Fatalf("line %d too wide (%d>%d): %q", n, len([]rune(line)), dim[0], line)
				}
			}
		})
	}
}

func TestDashboardInputSanitizationAndLogsBounded(t *testing.T) {
	d := NewDashboard("0.4.0", false, true, 80, 30)
	d.addLog("error", "unsafe\x1b[2J\r\nnext\tpart")
	for i := 0; i < 500; i++ {
		d.addLog("info", fmt.Sprintf("message %d", i))
	}
	if len(d.Logs) > 160 {
		t.Fatalf("logs unbounded: %d", len(d.Logs))
	}
	for _, row := range d.Logs {
		if strings.ContainsAny(row.text, "\x1b\r\n") {
			t.Fatal("unsafe control sequence")
		}
	}
}

func BenchmarkDashboardRender100x30(b *testing.B) {
	d := NewDashboard("0.4.0", true, true, 100, 30)
	for i := 0; i < 50; i++ {
		d.addLog("progress", fmt.Sprintf("Scanning item %d", i))
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d.Tick = uint64(i)
		_ = d.RenderFrame()
	}
}

func TestWideUnicodeOutputWidth(t *testing.T) {
	for _, example := range []struct {
		source string
		limit  int
	}{
		{"안녕하세요", 8}, {"漢字 hello", 7}, {"🧠⚡ Security", 8}, {"àbcd", 3},
	} {
		truncated := dashboardFit(example.source, example.limit)
		if width := displayColumns(truncated); width > example.limit {
			t.Fatalf("wide output overflow %q = %d columns", truncated, width)
		}
	}
	d := NewDashboard("0.4.0", false, true, 50, 21)
	for _, b := range []byte(strings.Repeat("네", 70)) {
		d.ApplyByte(b)
	}
	if displayColumns(d.RenderFrame()) == 0 {
		t.Fatal("empty screen")
	}
	line := strings.Split(d.RenderFrame(), "\r\n")
	for n, row := range line {
		if width := displayColumns(row); width > 50 {
			t.Fatalf("wide command overflow on line %d: %d columns", n, width)
		}
	}
}
