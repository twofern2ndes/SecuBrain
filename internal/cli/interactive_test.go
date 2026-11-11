package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnimatedShellUsesRealLocalScanner(t *testing.T) {
	project := t.TempDir()
	report := filepath.Join(t.TempDir(), "reports")
	if err := os.WriteFile(filepath.Join(project, "app.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var messages []string
	code := interactiveCommand(context.Background(), `scan --path "`+project+`" --out "`+report+`"`, func(s string) { messages = append(messages, s) })
	if code != 0 {
		t.Fatalf("scan returned %d: %q", code, messages)
	}
	for _, filename := range []string{"report.json", "report.md", "report.html"} {
		if _, err := os.Stat(filepath.Join(report, filename)); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(strings.Join(messages, "\n"), "Reports written") {
		t.Fatalf("scan summary missing: %q", messages)
	}
}

func TestAnimatedShellHelpAndInvalidCommand(t *testing.T) {
	var received []string
	emit := func(s string) { received = append(received, s) }
	if rc := interactiveCommand(context.Background(), "help", emit); rc != 0 || !strings.Contains(strings.Join(received, " "), "nmap") {
		t.Fatal("interactive help failed")
	}
	if rc := interactiveCommand(context.Background(), "nonsense", emit); rc != 2 {
		t.Fatalf("unknown command code %d", rc)
	}
	if rc := interactiveCommand(context.Background(), `scan --path "unfinished`, emit); rc != 2 {
		t.Fatalf("invalid quote code %d", rc)
	}
	// No remote command without explicit authorization.
	if rc := interactiveCommand(context.Background(), "nmap --target 192.0.2.1", emit); rc == 0 {
		t.Fatal("network scan without authorization passed")
	}
}
