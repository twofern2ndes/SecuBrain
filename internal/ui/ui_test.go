package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestPlainBannerWithNonTTYWriter(t *testing.T) {
	var out bytes.Buffer
	term := New(&out)
	if term.Color || term.Animate {
		t.Fatalf("unexpected styling for pipe: %+v", term)
	}
	term.Banner("0.2.0")
	term.Prompt()
	s := out.String()
	if !strings.Contains(s, "SECURITY ENGINEERING") || !strings.Contains(s, "v0.2.0") || strings.Contains(s, "\x1b[") {
		t.Fatalf("bad output: %q", s)
	}
}
