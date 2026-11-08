package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	reset  = "\x1b[0m"
	white  = "\x1b[97m"
	silver = "\x1b[38;5;250m"
	gray   = "\x1b[38;5;244m"
	blue   = "\x1b[38;5;110m"
	green  = "\x1b[38;5;114m"
	yellow = "\x1b[38;5;221m"
	red    = "\x1b[38;5;203m"
)

type Terminal struct {
	Out     io.Writer
	Color   bool
	Animate bool
}

func New(out io.Writer) Terminal {
	tty := false
	if f, ok := out.(*os.File); ok {
		if stat, err := f.Stat(); err == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
			tty = enableColors(f)
		}
	}
	if os.Getenv("TERM") == "dumb" || os.Getenv("NO_COLOR") != "" || os.Getenv("SECUBRAIN_PLAIN") != "" {
		tty = false
	}
	return Terminal{Out: out, Color: tty, Animate: tty && os.Getenv("SECUBRAIN_NO_ANIM") == "" && os.Getenv("CI") == ""}
}

func (t Terminal) color(colorName, content string) string {
	if !t.Color {
		return content
	}
	return colorName + content + reset
}

func (t Terminal) Banner(version string) {
	lines := []string{
		"",
		"   ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓",
		"   ┃                                                    ┃",
		fmt.Sprintf("   ┃  %-43s v%-5s ┃", "S E C U B R A I N", version),
		"   ┃  SECURITY ENGINEERING / DETERMINISTIC AUDITING     ┃",
		"   ┃                                                    ┃",
		"   ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛",
		"",
	}
	for i, line := range lines {
		if i == 3 {
			line = t.color(white, line)
		} else {
			line = t.color(blue, line)
		}
		fmt.Fprintln(t.Out, line)
		if t.Animate {
			time.Sleep(35 * time.Millisecond)
		}
	}
	fmt.Fprintln(t.Out, t.color(gray, "   Local-first  ·  No AI  ·  Authorized assessments only"))
	fmt.Fprintln(t.Out, t.color(gray, "   Type help for commands, doctor to inspect dependencies."))
	fmt.Fprintln(t.Out)
}

func (t Terminal) Prompt() {
	fmt.Fprint(t.Out, t.color(blue, "  secubrain")+t.color(gray, " / ")+t.color(silver, "› "))
}

func (t Terminal) Step(s string)    { fmt.Fprintln(t.Out, "  "+t.color(blue, "·")+" "+s) }
func (t Terminal) Success(s string) { fmt.Fprintln(t.Out, "  "+t.color(green, "✓")+" "+s) }
func (t Terminal) Warn(s string)    { fmt.Fprintln(t.Out, "  "+t.color(yellow, "!")+" "+s) }
func (t Terminal) Error(s string)   { fmt.Fprintln(t.Out, "  "+t.color(red, "×")+" "+s) }
func (t Terminal) Heading(s string) {
	fmt.Fprintln(t.Out, "\n  "+t.color(white, s)+"\n  "+t.color(gray, strings.Repeat("─", 48)))
}
func (t Terminal) KeyValue(k, v string) {
	fmt.Fprintln(t.Out, "  "+t.color(gray, fmt.Sprintf("%-18s", k))+t.color(silver, v))
}
